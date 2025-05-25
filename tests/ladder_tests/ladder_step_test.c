#include "../../curve25519.h"
#include "../tests.h"

int32_t curve25519_ladder_step_test(void) {
	printf("Montgomery Ladder Step Test\n");
	int steps = 64;
	curve25519_key_t X1 = {.key64 = {
		0x98EC88F84138EDC0ULL,
		0x532FB1C473CF652BULL,
		0xC97473587A2BE3DDULL,
		0x4590F1C0EAAE474FULL
		}
	};
	curve25519_proj_point_t XZ2 = {
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	curve25519_proj_point_t XZ3 = {
		.X = {.key64 = {
			0x98EC88F84138EDC0ULL,
			0x532FB1C473CF652BULL,
			0xC97473587A2BE3DDULL,
			0x4590F1C0EAAE474FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	curve25519_proj_point_t XZ3n = {
		.X = {.key64 = {
			0x203DE65EA7C6271BULL,
			0xE495472B83364BE6ULL,
			0x652636D655CF961FULL,
			0x3E9456244B967FC3ULL}
		},
		.Z = {.key64 = {
			0x5838BB013AA8EE92ULL,
			0x1E78A670E5E94D4BULL,
			0xF4DFAF7E38A5AA1EULL,
			0x0508D84D26B4DC05ULL}
		}
	};
	printf("Test Case 1\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	int res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 1 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
	} else {
		printf("Test Case 1 PASSED\n");
	}

	steps = 50;
	X1 = (curve25519_key_t){.key64 = {
		0xD3A2D7BC45F77150ULL,
		0xEA4C27B8656798DCULL,
		0xD4983CC8CFC35404ULL,
		0x77C6D2DED5885C7DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD3A2D7BC45F77150ULL,
			0xEA4C27B8656798DCULL,
			0xD4983CC8CFC35404ULL,
			0x77C6D2DED5885C7DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFBFF15C0EEAC62D3ULL,
			0x29D27A8DEC215B30ULL,
			0xEBB427B0F8E2D265ULL,
			0x63AFF61796F2679FULL}
		},
		.Z = {.key64 = {
			0x7A0C689126448C25ULL,
			0x80F13BCA31BEF272ULL,
			0x881F89D76DF6D9B4ULL,
			0x5846B0B64A2D82C1ULL}
		}
	};
	printf("Test Case 1\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 1 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}

	steps = 36;
	X1 = (curve25519_key_t){.key64 = {
		0xAE2BE8877DC5D208ULL,
		0x3F1BE970150969D1ULL,
		0x8C7CBBD6C4394AAAULL,
		0x4191E0EA85599471ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAE2BE8877DC5D208ULL,
			0x3F1BE970150969D1ULL,
			0x8C7CBBD6C4394AAAULL,
			0x4191E0EA85599471ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3E0E2DFFB1C2ADF2ULL,
			0x751199D613F593EAULL,
			0xD071D3FDF95BA9C8ULL,
			0x0C278A42DB6DBC54ULL}
		},
		.Z = {.key64 = {
			0xA50348C66E82CB52ULL,
			0x0536CBAD0E45185AULL,
			0x05171667046FC722ULL,
			0x2C54223B18D294ECULL}
		}
	};
	printf("Test Case 2\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 2 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}

	steps = 49;
	X1 = (curve25519_key_t){.key64 = {
		0x16237DE341366520ULL,
		0x442AFFAB608F5B74ULL,
		0xBACC4E7FF9B87FDDULL,
		0x7377BCC0608ADC81ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x16237DE341366520ULL,
			0x442AFFAB608F5B74ULL,
			0xBACC4E7FF9B87FDDULL,
			0x7377BCC0608ADC81ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6716A108F7DD1A31ULL,
			0x87AEA4B0F62FE774ULL,
			0x16257EC3446F1E39ULL,
			0x2466957D88621ECFULL}
		},
		.Z = {.key64 = {
			0x0F174074306E8607ULL,
			0xC1F04981F6B3CB05ULL,
			0x77BA8FB7780B4F2BULL,
			0x160E1D94FCE68EA7ULL}
		}
	};
	printf("Test Case 3\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 3 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}

	steps = 63;
	X1 = (curve25519_key_t){.key64 = {
		0xC7CFBF614C0348D0ULL,
		0x29CD4F91C67A3226ULL,
		0xDF4E23EF614023A3ULL,
		0x44B19A392EDADAAEULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC7CFBF614C0348D0ULL,
			0x29CD4F91C67A3226ULL,
			0xDF4E23EF614023A3ULL,
			0x44B19A392EDADAAEULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x319175F0B558E935ULL,
			0xDE61DD75DCA09DD5ULL,
			0xFB1F37BFFF1FB4A9ULL,
			0x5CFA18745B873BB9ULL}
		},
		.Z = {.key64 = {
			0x1B8E82C674DA08F3ULL,
			0xCB93BD298D23B0A5ULL,
			0x3A1CA71D0FFA945CULL,
			0x360659799158BA10ULL}
		}
	};
	printf("Test Case 4\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 4 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}

	steps = 5;
	X1 = (curve25519_key_t){.key64 = {
		0x1C49D10D951F62E8ULL,
		0xA70DC5C0CB53D724ULL,
		0x49E9FE833B3614C0ULL,
		0x48749AEE1B89075CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1C49D10D951F62E8ULL,
			0xA70DC5C0CB53D724ULL,
			0x49E9FE833B3614C0ULL,
			0x48749AEE1B89075CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x558667FC77CA347BULL,
			0x1F16C102F73A9F51ULL,
			0xBE2D4E61BC39EF50ULL,
			0x14F43F6B485A7F49ULL}
		},
		.Z = {.key64 = {
			0x67E5B0340D9744DFULL,
			0x8EC8B9F8DB360673ULL,
			0x64558FEE69F50E2BULL,
			0x0A0A599B7AA3CB92ULL}
		}
	};
	printf("Test Case 5\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 5 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}

	steps = 45;
	X1 = (curve25519_key_t){.key64 = {
		0x4FB1E52AB8B04360ULL,
		0x6D26A1AFE009565DULL,
		0xDB264CF4064D439CULL,
		0x4B47DCF3875C9FBDULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4FB1E52AB8B04360ULL,
			0x6D26A1AFE009565DULL,
			0xDB264CF4064D439CULL,
			0x4B47DCF3875C9FBDULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x39780D325CC8774DULL,
			0x4F7494389614E650ULL,
			0xCC15BCDC5B6D667AULL,
			0x775F721EF2FB859DULL}
		},
		.Z = {.key64 = {
			0xF3172673B7E8FB73ULL,
			0x84E00C0BDB85EE04ULL,
			0x94C24359094BF302ULL,
			0x239C73746502C738ULL}
		}
	};
	printf("Test Case 6\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 6 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}

	steps = 43;
	X1 = (curve25519_key_t){.key64 = {
		0xD5E67456BD0BEE98ULL,
		0xDB37581AD07DAB9FULL,
		0x8110150AC1AD1DF9ULL,
		0x5E9C4FEDEBA70060ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD5E67456BD0BEE98ULL,
			0xDB37581AD07DAB9FULL,
			0x8110150AC1AD1DF9ULL,
			0x5E9C4FEDEBA70060ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x03A844E39C4FF67BULL,
			0x31A2CF0A7C51ECBCULL,
			0x9ED2A5E77E409746ULL,
			0x269A20C7106AA4B6ULL}
		},
		.Z = {.key64 = {
			0xA29B567AE89E3A50ULL,
			0x16A99F6D1DB0D7FCULL,
			0x03AB73A09C63C829ULL,
			0x511BB746D2DBD7EBULL}
		}
	};
	printf("Test Case 7\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 7 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}

	steps = 17;
	X1 = (curve25519_key_t){.key64 = {
		0x57732229D6F7B3A0ULL,
		0x0FC77BDF2AE89AFAULL,
		0x60C3DBEEA9565FBFULL,
		0x56876C9AA925E07CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x57732229D6F7B3A0ULL,
			0x0FC77BDF2AE89AFAULL,
			0x60C3DBEEA9565FBFULL,
			0x56876C9AA925E07CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x62D48DEF91C8D773ULL,
			0xD5036D4322F3238FULL,
			0xDA8F914B3409E7A6ULL,
			0x7177A9CFCADD4371ULL}
		},
		.Z = {.key64 = {
			0xC5406336A9D30374ULL,
			0x2B2BF5AA58C8E3FAULL,
			0x3016244F6B52168AULL,
			0x28EC484B8841DA29ULL}
		}
	};
	printf("Test Case 8\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 8 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}

	steps = 49;
	X1 = (curve25519_key_t){.key64 = {
		0x267AA3EC6EBF7358ULL,
		0x27D5515D2B539094ULL,
		0x738B3173388C7932ULL,
		0x64830B2902F8DB3AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x267AA3EC6EBF7358ULL,
			0x27D5515D2B539094ULL,
			0x738B3173388C7932ULL,
			0x64830B2902F8DB3AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x423279E6AEF4C095ULL,
			0xA38867AEFDA7E43EULL,
			0x01F139CD9E3AAFC6ULL,
			0x73BEE4AAF70369ACULL}
		},
		.Z = {.key64 = {
			0x00C5EA4663BBEB06ULL,
			0x244B99205F4EB0F9ULL,
			0x7A26C1E3351C723AULL,
			0x2F6341B2ED1FCF7FULL}
		}
	};
	printf("Test Case 9\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 9 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}

	steps = 42;
	X1 = (curve25519_key_t){.key64 = {
		0x6F58A6F8CE5E2FE0ULL,
		0xBF86359F26E670F1ULL,
		0x165F54BC28285705ULL,
		0x543110EDB171F1D7ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6F58A6F8CE5E2FE0ULL,
			0xBF86359F26E670F1ULL,
			0x165F54BC28285705ULL,
			0x543110EDB171F1D7ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3F6F8A98D59A3304ULL,
			0x2C4548CB59EEA2BDULL,
			0x610434B48C75A351ULL,
			0x68753A98F0EDDC91ULL}
		},
		.Z = {.key64 = {
			0x69ECFCAA83507A94ULL,
			0x3045C4A8981A0C7EULL,
			0x4DB6174C252825D6ULL,
			0x4A53A8EFFEB85A3AULL}
		}
	};
	printf("Test Case 10\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 10 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}

	steps = 40;
	X1 = (curve25519_key_t){.key64 = {
		0x819E097A901EBA60ULL,
		0x08F7EBCDA21BECD4ULL,
		0x85E9AE351DF1F52FULL,
		0x6695107897F4FEB5ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x819E097A901EBA60ULL,
			0x08F7EBCDA21BECD4ULL,
			0x85E9AE351DF1F52FULL,
			0x6695107897F4FEB5ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF72FE2AEA8024447ULL,
			0xAAA20DFC005BFDBBULL,
			0x2D74247EFF2EF852ULL,
			0x1AC3918D969C3B5DULL}
		},
		.Z = {.key64 = {
			0x2D1F2B166FEF88DEULL,
			0x6BCE0AD0C88E919DULL,
			0xB3124E93AE622096ULL,
			0x61D25005A1046ABEULL}
		}
	};
	printf("Test Case 11\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 11 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}

	steps = 17;
	X1 = (curve25519_key_t){.key64 = {
		0x09BF132BFEAD73A0ULL,
		0x9F344D03EC8EBECCULL,
		0x3563D25AA3E2E045ULL,
		0x63BC168E74D1AEFBULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x09BF132BFEAD73A0ULL,
			0x9F344D03EC8EBECCULL,
			0x3563D25AA3E2E045ULL,
			0x63BC168E74D1AEFBULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFCFD30CCA4F310B7ULL,
			0x7841C0F0943E04C3ULL,
			0xBB22DFFE008AD9DBULL,
			0x21A9EDBFAEDBE703ULL}
		},
		.Z = {.key64 = {
			0xF2DB813AC979C458ULL,
			0xCBBA45CCAA7EDDA0ULL,
			0x94EBDFB1AAF4FCACULL,
			0x6B3B0D6101C042EEULL}
		}
	};
	printf("Test Case 12\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 12 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}

	steps = 64;
	X1 = (curve25519_key_t){.key64 = {
		0x76DFF09F61C9A4E8ULL,
		0x4BCF2A2FBA2BB396ULL,
		0x6ECB6E35F01426D4ULL,
		0x40C4EC12E61B8BE1ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x76DFF09F61C9A4E8ULL,
			0x4BCF2A2FBA2BB396ULL,
			0x6ECB6E35F01426D4ULL,
			0x40C4EC12E61B8BE1ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1A3AE12801E3A3D4ULL,
			0xC1819628C9A7140DULL,
			0x66590F2D45DC3B2CULL,
			0x3DF9F524AE1FE6BAULL}
		},
		.Z = {.key64 = {
			0x3DF00B09A30DAFA6ULL,
			0x1D95E6B01AC875F1ULL,
			0x9ACB21DEFC7B1C17ULL,
			0x14E0369488E1E46AULL}
		}
	};
	printf("Test Case 13\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 13 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}

	steps = 57;
	X1 = (curve25519_key_t){.key64 = {
		0xC0E0D992EAEEDB10ULL,
		0x413852D40741BF76ULL,
		0xAEF680A8726FC9A8ULL,
		0x7BC8B381CF4E9C65ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC0E0D992EAEEDB10ULL,
			0x413852D40741BF76ULL,
			0xAEF680A8726FC9A8ULL,
			0x7BC8B381CF4E9C65ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x48A524474B69DA3CULL,
			0x98750651A5CD347CULL,
			0xF3C3F0CF0A3B0A23ULL,
			0x103C5A6A8E1CA7CDULL}
		},
		.Z = {.key64 = {
			0x459EF586F27B356DULL,
			0x858A2FA200F8D1ABULL,
			0x4429952CC8C67A34ULL,
			0x5336F40995AF1322ULL}
		}
	};
	printf("Test Case 14\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 14 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}

	steps = 64;
	X1 = (curve25519_key_t){.key64 = {
		0x57174CCFDA0EA2F8ULL,
		0xDAC99271A2E4CA74ULL,
		0xD4BE97F4FE07E13AULL,
		0x62DB56F19F5AD244ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x57174CCFDA0EA2F8ULL,
			0xDAC99271A2E4CA74ULL,
			0xD4BE97F4FE07E13AULL,
			0x62DB56F19F5AD244ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB89BABEDA63785C4ULL,
			0x12F4E8F7EC53B340ULL,
			0x3CE0E89B2DCD3A4AULL,
			0x7B6266A140E625FDULL}
		},
		.Z = {.key64 = {
			0x323794F9CF7A7447ULL,
			0x42438CDF2BA8E223ULL,
			0xB4A9563A5AEA4D17ULL,
			0x4CB740E760F4F3ECULL}
		}
	};
	printf("Test Case 15\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 15 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}

	steps = 42;
	X1 = (curve25519_key_t){.key64 = {
		0xFFB6091CBF220098ULL,
		0x280EF1E5082C0011ULL,
		0xCE0A3A2F4CEE1787ULL,
		0x5A9261D81DE7BC6CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFFB6091CBF220098ULL,
			0x280EF1E5082C0011ULL,
			0xCE0A3A2F4CEE1787ULL,
			0x5A9261D81DE7BC6CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1EE4615C1CFFAA55ULL,
			0x8F2DC5B8F3C5AEDCULL,
			0x346460CB3536E6B5ULL,
			0x26A66E398ED21B26ULL}
		},
		.Z = {.key64 = {
			0x97257B89254D3ECCULL,
			0x34D215AAB4212B65ULL,
			0xDA9984D8B88A7E2DULL,
			0x00184286CD46D790ULL}
		}
	};
	printf("Test Case 16\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 16 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}

	steps = 5;
	X1 = (curve25519_key_t){.key64 = {
		0x51855DA67F1CC8F0ULL,
		0xC99BB4E74FB4E2B1ULL,
		0x9464834F1BF29ED8ULL,
		0x4283FA7872CFEE3EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x51855DA67F1CC8F0ULL,
			0xC99BB4E74FB4E2B1ULL,
			0x9464834F1BF29ED8ULL,
			0x4283FA7872CFEE3EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7D7B505C3AFF5F6EULL,
			0xDEFDA7D2B2DCA86FULL,
			0x4FDFE5A0D4663784ULL,
			0x133BA00CCA74E548ULL}
		},
		.Z = {.key64 = {
			0x9D665D44F2F70F61ULL,
			0x5816781C7BD4ECF0ULL,
			0x91882A46FE850BB5ULL,
			0x381AFCB18844DCA8ULL}
		}
	};
	printf("Test Case 17\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 17 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}

	steps = 40;
	X1 = (curve25519_key_t){.key64 = {
		0x883F48C7067B4FD8ULL,
		0xCE94E343083F888CULL,
		0x0A169B142FE07598ULL,
		0x5F1219CF98E3B1B8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x883F48C7067B4FD8ULL,
			0xCE94E343083F888CULL,
			0x0A169B142FE07598ULL,
			0x5F1219CF98E3B1B8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8DF5535B29FADE8EULL,
			0x94B78F65F69480A5ULL,
			0x97BA7D5705E5C33EULL,
			0x5598E0C0443FF0AEULL}
		},
		.Z = {.key64 = {
			0x7B7E771A6641D6BFULL,
			0x597CA385BF94EF5FULL,
			0xDE7562E614ADC84AULL,
			0x01329A38E25006E6ULL}
		}
	};
	printf("Test Case 18\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 18 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}

	steps = 20;
	X1 = (curve25519_key_t){.key64 = {
		0x9F50ACB4DA9B3448ULL,
		0x0564A697A9A6365CULL,
		0x1498C1B93B6E0DCDULL,
		0x70D8BE45AA3F1CA0ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9F50ACB4DA9B3448ULL,
			0x0564A697A9A6365CULL,
			0x1498C1B93B6E0DCDULL,
			0x70D8BE45AA3F1CA0ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8F6BFE097F8D7CB8ULL,
			0xA1511624E0D874A5ULL,
			0xD261413DCB4BDF73ULL,
			0x281B69EE0A0B59AFULL}
		},
		.Z = {.key64 = {
			0x662AA757108E5F59ULL,
			0x204455CD945363E1ULL,
			0x222FFB0A1A50C919ULL,
			0x75FAA73B3260B183ULL}
		}
	};
	printf("Test Case 19\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 19 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}

	steps = 19;
	X1 = (curve25519_key_t){.key64 = {
		0x275EB9D409F499A0ULL,
		0x56689023E7661910ULL,
		0x4EC959BB051F8A12ULL,
		0x7281E3230EE62DECULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x275EB9D409F499A0ULL,
			0x56689023E7661910ULL,
			0x4EC959BB051F8A12ULL,
			0x7281E3230EE62DECULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x59703D71AFCD9DFDULL,
			0x4AABABA95A1EE511ULL,
			0x8A728D8CC3C9FE61ULL,
			0x0A25364040CE28CDULL}
		},
		.Z = {.key64 = {
			0xE3FFCDBF24B29998ULL,
			0x4303EECAA9218370ULL,
			0x7A0FEB657D2C9705ULL,
			0x6832869DF04FA4D2ULL}
		}
	};
	printf("Test Case 20\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 20 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}

	steps = 20;
	X1 = (curve25519_key_t){.key64 = {
		0xCF21525FEAA50718ULL,
		0x29177033AE2E7542ULL,
		0x374B1819A72128F6ULL,
		0x643D89EA9A020364ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCF21525FEAA50718ULL,
			0x29177033AE2E7542ULL,
			0x374B1819A72128F6ULL,
			0x643D89EA9A020364ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x17617FB3551D7EE8ULL,
			0xEF3EE98D60C1DD10ULL,
			0x6C22D34CCC3B8E3DULL,
			0x60F2037009D0CF78ULL}
		},
		.Z = {.key64 = {
			0xC1D1A652A0D379CCULL,
			0x84BAEB02DE7BB41EULL,
			0x27B6C963DB0A1A4AULL,
			0x2D2D3CA8722E7996ULL}
		}
	};
	printf("Test Case 21\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 21 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}

	steps = 20;
	X1 = (curve25519_key_t){.key64 = {
		0xA0D2059D38F80B78ULL,
		0x0A34C1E2223DAF43ULL,
		0x3DF3F3C5665246FFULL,
		0x498B9AA3955647A7ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA0D2059D38F80B78ULL,
			0x0A34C1E2223DAF43ULL,
			0x3DF3F3C5665246FFULL,
			0x498B9AA3955647A7ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9F8B86670D7CC519ULL,
			0x6387DD3DDDBB3F35ULL,
			0xC8D03832305A8A48ULL,
			0x16DE9278AAC9D73EULL}
		},
		.Z = {.key64 = {
			0x75CAD6E454EC4077ULL,
			0x3FB676BBC81E0EA5ULL,
			0x60527691932F1238ULL,
			0x6CF78B8DDC192086ULL}
		}
	};
	printf("Test Case 22\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 22 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}

	steps = 4;
	X1 = (curve25519_key_t){.key64 = {
		0xADE152B72D9C36D0ULL,
		0x3DB0D7C9D066EA7EULL,
		0xE8EAD7547167D8C3ULL,
		0x53BFCB76A4F79141ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xADE152B72D9C36D0ULL,
			0x3DB0D7C9D066EA7EULL,
			0xE8EAD7547167D8C3ULL,
			0x53BFCB76A4F79141ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA0C23AA0135F3E0EULL,
			0xCEDB750477AF0AA1ULL,
			0xB84C52C9A6BE4377ULL,
			0x63237371E896D776ULL}
		},
		.Z = {.key64 = {
			0x37CBBBD0191F5D81ULL,
			0x2E024D8398D0A486ULL,
			0x954C5975D6D13AE2ULL,
			0x0892B370F3FE2E35ULL}
		}
	};
	printf("Test Case 23\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 23 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}

	steps = 21;
	X1 = (curve25519_key_t){.key64 = {
		0xDE14028D195FC938ULL,
		0xB9043153B063719AULL,
		0xD7E0E38398E156A2ULL,
		0x73654B4D3A172731ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDE14028D195FC938ULL,
			0xB9043153B063719AULL,
			0xD7E0E38398E156A2ULL,
			0x73654B4D3A172731ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x16A96D5F1F90BB2AULL,
			0xC79E907B4A714D25ULL,
			0x8592EF6720486501ULL,
			0x6943738E2A595934ULL}
		},
		.Z = {.key64 = {
			0xD1173C3C0C0C80B7ULL,
			0x2D63EF0A10EA6C43ULL,
			0xB25F6C0347E3EA10ULL,
			0x6B346FF51ACDF77BULL}
		}
	};
	printf("Test Case 24\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 24 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}

	steps = 11;
	X1 = (curve25519_key_t){.key64 = {
		0xD75F50EBA3746388ULL,
		0x4EF0FABE2B06491FULL,
		0x87C02B64FFE86E92ULL,
		0x5407A3AB3348AA0DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD75F50EBA3746388ULL,
			0x4EF0FABE2B06491FULL,
			0x87C02B64FFE86E92ULL,
			0x5407A3AB3348AA0DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7597AB2241DAA91DULL,
			0x9568F7EF49322B52ULL,
			0x9871BABC73D15376ULL,
			0x19CA2ACFB1333EA3ULL}
		},
		.Z = {.key64 = {
			0x570A35E6B4F5B8BAULL,
			0x5FD2DAD9037F40DFULL,
			0xF8B38A73AD5AEBBCULL,
			0x6C746C2E073DE839ULL}
		}
	};
	printf("Test Case 25\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 25 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}

	steps = 32;
	X1 = (curve25519_key_t){.key64 = {
		0xA714EBDFDB3EFF30ULL,
		0x6F644D972AE5176CULL,
		0x145B8DAD260A45EFULL,
		0x596E2229F9EC0A0CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA714EBDFDB3EFF30ULL,
			0x6F644D972AE5176CULL,
			0x145B8DAD260A45EFULL,
			0x596E2229F9EC0A0CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7908BD8C7D7DD9CAULL,
			0x59D4D77F33A00CF4ULL,
			0x4423F456091DDEC4ULL,
			0x60190A13ED140B16ULL}
		},
		.Z = {.key64 = {
			0xAC72A4D0550D8C3CULL,
			0x946B547D68337491ULL,
			0x989FE0BD3D537981ULL,
			0x3222F4B33E2BE1B5ULL}
		}
	};
	printf("Test Case 26\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 26 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}

	steps = 46;
	X1 = (curve25519_key_t){.key64 = {
		0x13F861A32E7FF4A8ULL,
		0x3AC2A9CD361F2872ULL,
		0xD1726354E59A43FEULL,
		0x6DAB3B8D9E494255ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x13F861A32E7FF4A8ULL,
			0x3AC2A9CD361F2872ULL,
			0xD1726354E59A43FEULL,
			0x6DAB3B8D9E494255ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0BACB5BE3A2900B1ULL,
			0x8699C35201AE290AULL,
			0xA025AB5C1BA29814ULL,
			0x6D5401AFFED9074EULL}
		},
		.Z = {.key64 = {
			0x81B24449B1C2E510ULL,
			0x1AA4E7BDACEBFEBAULL,
			0xFA65940E64372A00ULL,
			0x5926226003DDE6FEULL}
		}
	};
	printf("Test Case 27\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 27 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}

	steps = 4;
	X1 = (curve25519_key_t){.key64 = {
		0x599C0DF14290AA80ULL,
		0x5CBD97C914540452ULL,
		0xDDF998F44C9E8675ULL,
		0x6A61725FE0A4BB51ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x599C0DF14290AA80ULL,
			0x5CBD97C914540452ULL,
			0xDDF998F44C9E8675ULL,
			0x6A61725FE0A4BB51ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF8AF175EBCD3CDCEULL,
			0xB91EFF81C891F4F1ULL,
			0xC51F4803D5058796ULL,
			0x03360A6172948B20ULL}
		},
		.Z = {.key64 = {
			0x9FEB1333ECDB61B3ULL,
			0xA7E520137DA77E55ULL,
			0x47F887FC3A0EB605ULL,
			0x3ADDDE4E821F1D32ULL}
		}
	};
	printf("Test Case 28\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 28 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}

	steps = 10;
	X1 = (curve25519_key_t){.key64 = {
		0x7EF895CC2FEF5878ULL,
		0x1F8F4B5F4E0B90E6ULL,
		0xC357B5518C8BA7EFULL,
		0x78FF549752334633ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7EF895CC2FEF5878ULL,
			0x1F8F4B5F4E0B90E6ULL,
			0xC357B5518C8BA7EFULL,
			0x78FF549752334633ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAFDA5162101E8C24ULL,
			0x39C8BBD234D1F11BULL,
			0x2C0443AD3CDF95B3ULL,
			0x29E5C8A3869FFD79ULL}
		},
		.Z = {.key64 = {
			0x3BB0A499CDC98A2BULL,
			0x9ECDE5135AC4C75EULL,
			0xF19635A601F34F58ULL,
			0x6A999E64B292CAC7ULL}
		}
	};
	printf("Test Case 29\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 29 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}

	steps = 33;
	X1 = (curve25519_key_t){.key64 = {
		0x68E6B1DCED2A0900ULL,
		0x1CBAEBDD88BF18B8ULL,
		0x26E2CB0260F2CA65ULL,
		0x7CC23D2BB5F47B0EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x68E6B1DCED2A0900ULL,
			0x1CBAEBDD88BF18B8ULL,
			0x26E2CB0260F2CA65ULL,
			0x7CC23D2BB5F47B0EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x143245D7DAC35425ULL,
			0x97806524BBB9766DULL,
			0x33D5998762EC8198ULL,
			0x3761BF9B682E9E4DULL}
		},
		.Z = {.key64 = {
			0x93E24107D7A3398AULL,
			0x2F87A1E4E91D2CF9ULL,
			0x367E90B42DD2124BULL,
			0x6BD7952F5DEE794BULL}
		}
	};
	printf("Test Case 30\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 30 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}

	steps = 46;
	X1 = (curve25519_key_t){.key64 = {
		0xE4F8C1085EDF8FB8ULL,
		0xCD4FD5CF5BA8D59FULL,
		0x036CABB6390F64F9ULL,
		0x49BA9F73E1F9CE4AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE4F8C1085EDF8FB8ULL,
			0xCD4FD5CF5BA8D59FULL,
			0x036CABB6390F64F9ULL,
			0x49BA9F73E1F9CE4AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7566E6CFB0C64095ULL,
			0xD1E53FDC3AF6D720ULL,
			0xD55AFF8CB8C89153ULL,
			0x75127E5421278F33ULL}
		},
		.Z = {.key64 = {
			0x2DA81EEED2BC0081ULL,
			0x9EB4AE756CDD5F80ULL,
			0x0D6C3DE3CA437461ULL,
			0x6B272622E5C0FC64ULL}
		}
	};
	printf("Test Case 31\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 31 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}

	steps = 23;
	X1 = (curve25519_key_t){.key64 = {
		0x9FA883A830CFEB00ULL,
		0xB86E971E191AB1A5ULL,
		0x5215CE1E1A18D0F4ULL,
		0x5B6FCD1B13C96BAAULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9FA883A830CFEB00ULL,
			0xB86E971E191AB1A5ULL,
			0x5215CE1E1A18D0F4ULL,
			0x5B6FCD1B13C96BAAULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD5A3D8DA736E95F4ULL,
			0x0B4036FF20A55D54ULL,
			0x1C16F9526EECA741ULL,
			0x59D48C4948DC218DULL}
		},
		.Z = {.key64 = {
			0x43CD73C4018E1E5FULL,
			0x5242FFED56B13CC7ULL,
			0x4945AFD776BAD952ULL,
			0x43332F79E83801A5ULL}
		}
	};
	printf("Test Case 32\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 32 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}

	steps = 14;
	X1 = (curve25519_key_t){.key64 = {
		0xD2F19DC58689A988ULL,
		0x29B37316FEC97B36ULL,
		0x17E6372F182074F4ULL,
		0x7DB1D84BE5F236B1ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD2F19DC58689A988ULL,
			0x29B37316FEC97B36ULL,
			0x17E6372F182074F4ULL,
			0x7DB1D84BE5F236B1ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1AD0AA1F49FBA44AULL,
			0x4FEAA43960F66C5EULL,
			0x074E0E6BEA246FF4ULL,
			0x11FC3203C8D01BB7ULL}
		},
		.Z = {.key64 = {
			0xEEA134B9D7EC101AULL,
			0xEB685797B89FCA87ULL,
			0x90CA5E87ADBA9515ULL,
			0x7A726548740C2DE8ULL}
		}
	};
	printf("Test Case 33\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 33 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}

	steps = 38;
	X1 = (curve25519_key_t){.key64 = {
		0x5948A062DDE84E10ULL,
		0x83CFD63DC6367756ULL,
		0x0003B01003C0B67FULL,
		0x51D5F30E9E5E9A03ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5948A062DDE84E10ULL,
			0x83CFD63DC6367756ULL,
			0x0003B01003C0B67FULL,
			0x51D5F30E9E5E9A03ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0BC2BBA648F34FDDULL,
			0x5832B856124D1FD9ULL,
			0x7356B41BF4C7C16EULL,
			0x37D0861C5AE8D2D6ULL}
		},
		.Z = {.key64 = {
			0xB50FCBA79568CC15ULL,
			0x025D208C66F28718ULL,
			0x1B0CC95071CEF810ULL,
			0x1B9A089F855F1BC4ULL}
		}
	};
	printf("Test Case 34\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 34 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}

	steps = 50;
	X1 = (curve25519_key_t){.key64 = {
		0xA97DE1268953A5C0ULL,
		0x51119F165D990D7CULL,
		0xE10B881DC7599F51ULL,
		0x661572671C94D0EEULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA97DE1268953A5C0ULL,
			0x51119F165D990D7CULL,
			0xE10B881DC7599F51ULL,
			0x661572671C94D0EEULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA38C9E68144F4A00ULL,
			0xD8ACA3566E9D4DD8ULL,
			0x677CFB1AAA8CEFEBULL,
			0x32FFC88885B9693EULL}
		},
		.Z = {.key64 = {
			0x1A9DCD9260730E1CULL,
			0x1B5EC7A353367DA9ULL,
			0xFE6850D285971650ULL,
			0x0BC3D00095570022ULL}
		}
	};
	printf("Test Case 35\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 35 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}

	steps = 34;
	X1 = (curve25519_key_t){.key64 = {
		0x036964A1380A9518ULL,
		0xAA98427CEA8DE09EULL,
		0x0C8773861643787BULL,
		0x73354F74573F06E5ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x036964A1380A9518ULL,
			0xAA98427CEA8DE09EULL,
			0x0C8773861643787BULL,
			0x73354F74573F06E5ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4B807C63C7F57F0DULL,
			0x222CFAE0906C03BBULL,
			0xE20E88CDBBE4A96EULL,
			0x59A9BFB430A0EFF9ULL}
		},
		.Z = {.key64 = {
			0x2F1748EE10239AF7ULL,
			0x63A35E75B5734987ULL,
			0x04D56E38D513CAB9ULL,
			0x2746EC46DC00A007ULL}
		}
	};
	printf("Test Case 36\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 36 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}

	steps = 40;
	X1 = (curve25519_key_t){.key64 = {
		0x3B17BC4D9FE59C18ULL,
		0x012A45BDD710210AULL,
		0x51A9495C7AEED74FULL,
		0x46A1630AD7DA2D49ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3B17BC4D9FE59C18ULL,
			0x012A45BDD710210AULL,
			0x51A9495C7AEED74FULL,
			0x46A1630AD7DA2D49ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCF0D08AF053AB08DULL,
			0x9F5838EB40B0732BULL,
			0x87FBA722ADD2944CULL,
			0x20361A07CF10F41DULL}
		},
		.Z = {.key64 = {
			0x63FE680E684DE3DEULL,
			0xD4C7739B91E742DFULL,
			0x78C5CCDC25D74B6CULL,
			0x61DBE320D8EB3395ULL}
		}
	};
	printf("Test Case 37\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 37 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}

	steps = 5;
	X1 = (curve25519_key_t){.key64 = {
		0xE7560A59A716C540ULL,
		0x536B0266D9E7CB81ULL,
		0xE1E48B99F6D066BFULL,
		0x76F403BD3B92A09AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE7560A59A716C540ULL,
			0x536B0266D9E7CB81ULL,
			0xE1E48B99F6D066BFULL,
			0x76F403BD3B92A09AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0E126A48F193561FULL,
			0x39F6DB67B93E6E36ULL,
			0x1ACA8804326B2B94ULL,
			0x11E2614B696838D6ULL}
		},
		.Z = {.key64 = {
			0x9768EBB9643A198FULL,
			0x3CE54347E304995AULL,
			0x35E139EF1E532C44ULL,
			0x55B5FEFAFFA6E4BFULL}
		}
	};
	printf("Test Case 38\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 38 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}

	steps = 54;
	X1 = (curve25519_key_t){.key64 = {
		0x2C65900438BAC3F0ULL,
		0x1830789774DC34BCULL,
		0x2446ABE4719D756CULL,
		0x5DF686E799D5D322ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2C65900438BAC3F0ULL,
			0x1830789774DC34BCULL,
			0x2446ABE4719D756CULL,
			0x5DF686E799D5D322ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x878F8BC0F3818C7EULL,
			0x1638959A4F39BD5FULL,
			0xB819441B6543CDD4ULL,
			0x66BE4135A3228849ULL}
		},
		.Z = {.key64 = {
			0x5A0ACD4033FF3B8EULL,
			0x99809276D7C18331ULL,
			0xC60D28AEEA39BF5DULL,
			0x4ADBD7A780349B39ULL}
		}
	};
	printf("Test Case 39\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 39 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}

	steps = 20;
	X1 = (curve25519_key_t){.key64 = {
		0x7A7EC02E2E722930ULL,
		0x19443D2D04EDA042ULL,
		0x64C6E142737F7194ULL,
		0x6C480382631040B6ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7A7EC02E2E722930ULL,
			0x19443D2D04EDA042ULL,
			0x64C6E142737F7194ULL,
			0x6C480382631040B6ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x588B309386C1A5DCULL,
			0xB9D199893B42DFA6ULL,
			0x6B95396A944637B0ULL,
			0x708FB5B13F5416DDULL}
		},
		.Z = {.key64 = {
			0x6C2F489F97CD409BULL,
			0x8BF134C335FF1E4CULL,
			0x4892A1E2B5095FEDULL,
			0x28BF9A582E414DBDULL}
		}
	};
	printf("Test Case 40\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 40 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}

	steps = 10;
	X1 = (curve25519_key_t){.key64 = {
		0x33AAB7AB98AE10E0ULL,
		0x2620721D0F568810ULL,
		0x8F46AF3E42D78786ULL,
		0x5D21FF77286E303EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x33AAB7AB98AE10E0ULL,
			0x2620721D0F568810ULL,
			0x8F46AF3E42D78786ULL,
			0x5D21FF77286E303EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3C127C72C335D9D4ULL,
			0xB8B7D470722CB120ULL,
			0xD3F6E8F1B94ED34AULL,
			0x49146ABEA5166B52ULL}
		},
		.Z = {.key64 = {
			0x7A412587811CA1F1ULL,
			0xA17DA57074947F8CULL,
			0x92623CF5483C7B35ULL,
			0x272184A513324B02ULL}
		}
	};
	printf("Test Case 41\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 41 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}

	steps = 3;
	X1 = (curve25519_key_t){.key64 = {
		0xE70877021650AB80ULL,
		0xF8E5EBFDA47B0484ULL,
		0xB221951AE0FCEA11ULL,
		0x7FB458BB74402051ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE70877021650AB80ULL,
			0xF8E5EBFDA47B0484ULL,
			0xB221951AE0FCEA11ULL,
			0x7FB458BB74402051ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x67D2F3953F129E27ULL,
			0xB54E957FF7BCA0A2ULL,
			0x05D3044FD6CDCDE2ULL,
			0x14669C8880ABE337ULL}
		},
		.Z = {.key64 = {
			0xADCE906D4370CB15ULL,
			0xED0E3CE64DEA628FULL,
			0x6C0E4AB801D2F1C8ULL,
			0x09F2BFF8B4420090ULL}
		}
	};
	printf("Test Case 42\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 42 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}

	steps = 16;
	X1 = (curve25519_key_t){.key64 = {
		0x70BF69F43532BD08ULL,
		0x4ADCE2189B246F9EULL,
		0x1B3AC6062E20CB7FULL,
		0x49EBB8BDF98E2D6CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x70BF69F43532BD08ULL,
			0x4ADCE2189B246F9EULL,
			0x1B3AC6062E20CB7FULL,
			0x49EBB8BDF98E2D6CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x861D70BA98C0E193ULL,
			0x2EFA92DD587FB5E8ULL,
			0xB66510D8D5DEA080ULL,
			0x0086E4581D945C5AULL}
		},
		.Z = {.key64 = {
			0x28757F4AEB456B0FULL,
			0x0F465F048E1EC6FAULL,
			0x09D30ED3053D462CULL,
			0x3500BB33C63C4204ULL}
		}
	};
	printf("Test Case 43\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 43 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}

	steps = 18;
	X1 = (curve25519_key_t){.key64 = {
		0xD9CC711852C98468ULL,
		0x708719592FB01C4AULL,
		0xAEC764C756C0AF5AULL,
		0x79310E33CFA9EAD1ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD9CC711852C98468ULL,
			0x708719592FB01C4AULL,
			0xAEC764C756C0AF5AULL,
			0x79310E33CFA9EAD1ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAEE119279E80B49EULL,
			0xC425B53AA973CBC7ULL,
			0x4509C8DFF7D30080ULL,
			0x2F9B78A7996B40BCULL}
		},
		.Z = {.key64 = {
			0x5FDFEC8477B45D73ULL,
			0x2C4801E711287E08ULL,
			0x11813A7A22F64546ULL,
			0x54592E90D27E9AF4ULL}
		}
	};
	printf("Test Case 44\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 44 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}

	steps = 62;
	X1 = (curve25519_key_t){.key64 = {
		0x52A37F9440479140ULL,
		0x84BFA570A7D7A727ULL,
		0x4A2DEE90525B3436ULL,
		0x44EBE4DCEF4B819AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x52A37F9440479140ULL,
			0x84BFA570A7D7A727ULL,
			0x4A2DEE90525B3436ULL,
			0x44EBE4DCEF4B819AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x469101566A1E0AADULL,
			0x843F32FE965F7A9BULL,
			0x18094E5066016600ULL,
			0x03C3EF7E05DDB3BEULL}
		},
		.Z = {.key64 = {
			0x4D3442FB7862CF83ULL,
			0x91AC92CCDF502E88ULL,
			0xC921CFD9B8B1C4A4ULL,
			0x4385D40DCDD48B8CULL}
		}
	};
	printf("Test Case 45\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 45 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}

	steps = 43;
	X1 = (curve25519_key_t){.key64 = {
		0x0E0CF22D46C2DFA0ULL,
		0x606F021CED92EB38ULL,
		0x84E3C1B2471EF4E1ULL,
		0x500F38E46A52F1FFULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0E0CF22D46C2DFA0ULL,
			0x606F021CED92EB38ULL,
			0x84E3C1B2471EF4E1ULL,
			0x500F38E46A52F1FFULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x557DB8A802AD879DULL,
			0x96ECD3A06EF2BBAEULL,
			0x5AC5D9EA13848CA5ULL,
			0x73411BC0AF478912ULL}
		},
		.Z = {.key64 = {
			0x418B14ACBC8A96B1ULL,
			0xADA0D9D18532DC2CULL,
			0x51E0F5F4459FB039ULL,
			0x400A1976920C5061ULL}
		}
	};
	printf("Test Case 46\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 46 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}

	steps = 43;
	X1 = (curve25519_key_t){.key64 = {
		0x81B1F6A1D8435620ULL,
		0x615E305664A66BAEULL,
		0x9D6C22A990A81D0CULL,
		0x7268C088D83FB0AFULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x81B1F6A1D8435620ULL,
			0x615E305664A66BAEULL,
			0x9D6C22A990A81D0CULL,
			0x7268C088D83FB0AFULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC97CCA120CB2683FULL,
			0x0BB2DBC07414744BULL,
			0x241148CDF3ACA10DULL,
			0x346E66A63DC70E01ULL}
		},
		.Z = {.key64 = {
			0x7507EEB9B8166A71ULL,
			0x32681495793DE1DFULL,
			0x0E8BC5AB32ED2B0EULL,
			0x5D78128F4C38D790ULL}
		}
	};
	printf("Test Case 47\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 47 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}

	steps = 43;
	X1 = (curve25519_key_t){.key64 = {
		0xF7666252011A0D88ULL,
		0xDCC802D97345D5FCULL,
		0x6534966E3AD33C2AULL,
		0x746516FB88E3F9E4ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF7666252011A0D88ULL,
			0xDCC802D97345D5FCULL,
			0x6534966E3AD33C2AULL,
			0x746516FB88E3F9E4ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4E1009962C6C1858ULL,
			0xA6471F76B3004A7BULL,
			0xF58E601D7385EBDAULL,
			0x6053EC01E7E97AD5ULL}
		},
		.Z = {.key64 = {
			0xA12C7D5D6087274CULL,
			0xC34EC6CDB3CE6F7DULL,
			0xFE14CACFC232FD67ULL,
			0x18693694ABF4AE4AULL}
		}
	};
	printf("Test Case 48\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 48 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}

	steps = 27;
	X1 = (curve25519_key_t){.key64 = {
		0x04882C604B081598ULL,
		0xC65743041C0C24CEULL,
		0xEF7543E68A231D9CULL,
		0x7666D23D2AE74C94ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x04882C604B081598ULL,
			0xC65743041C0C24CEULL,
			0xEF7543E68A231D9CULL,
			0x7666D23D2AE74C94ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6DDD8968A72E6DCBULL,
			0xE51D6CD67A76B3A6ULL,
			0x7DB82F3623B05DF7ULL,
			0x677D1B231C6DD066ULL}
		},
		.Z = {.key64 = {
			0xBA04AAE286DD860FULL,
			0xC6A31074608090A8ULL,
			0x9F48A876D1D2005AULL,
			0x13C72F92C596219AULL}
		}
	};
	printf("Test Case 49\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 49 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}

	steps = 43;
	X1 = (curve25519_key_t){.key64 = {
		0x50B6CE3E57E9A968ULL,
		0xE3F591CDDF51431FULL,
		0x561DD1E1A71C400BULL,
		0x5363D2C1C7B45F77ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x50B6CE3E57E9A968ULL,
			0xE3F591CDDF51431FULL,
			0x561DD1E1A71C400BULL,
			0x5363D2C1C7B45F77ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x20DA9FB5BFE6C0D3ULL,
			0xD0AC34AE10433756ULL,
			0x686D7B8D2B3D81CDULL,
			0x26106866E1540BC8ULL}
		},
		.Z = {.key64 = {
			0x223E147E2E5A9A94ULL,
			0x15294426570B1D25ULL,
			0x70DE104E71EC86DDULL,
			0x585D2C0103A28D90ULL}
		}
	};
	printf("Test Case 50\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 50 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}

	steps = 64;
	X1 = (curve25519_key_t){.key64 = {
		0x77A855C1FC9FC300ULL,
		0x1E07B2D20EDB97D8ULL,
		0xCCF0FE4D12168BE3ULL,
		0x4688D2D82239D50FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x77A855C1FC9FC300ULL,
			0x1E07B2D20EDB97D8ULL,
			0xCCF0FE4D12168BE3ULL,
			0x4688D2D82239D50FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFC99F9925571882EULL,
			0xD293F6B15DF4465DULL,
			0x7D9118BF61861BD7ULL,
			0x501C88F9EE7D1694ULL}
		},
		.Z = {.key64 = {
			0x2F54988896DEBCB4ULL,
			0xF2EDB7542A270270ULL,
			0x4943EC14E8361E3CULL,
			0x2BC9518C97F0834AULL}
		}
	};
	printf("Test Case 51\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 51 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -51;
	} else {
		printf("Test Case 51 PASSED\n");
	}

	steps = 14;
	X1 = (curve25519_key_t){.key64 = {
		0xBB9723E2FC3EAB98ULL,
		0xB5EFF6903FBD727DULL,
		0x5A7DB8CFAD3B39E2ULL,
		0x70E74E21A87DBB6FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBB9723E2FC3EAB98ULL,
			0xB5EFF6903FBD727DULL,
			0x5A7DB8CFAD3B39E2ULL,
			0x70E74E21A87DBB6FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFCD96FBC4EE9B674ULL,
			0xE72BC0D1759A7806ULL,
			0xE4D04ACB7C189E40ULL,
			0x1F0AA2DCF81CF353ULL}
		},
		.Z = {.key64 = {
			0x2050241A85B5C420ULL,
			0x91847EC1E65F452AULL,
			0x574D79E8ED2B3497ULL,
			0x07B8D71FD464E5E0ULL}
		}
	};
	printf("Test Case 52\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 52 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -52;
	} else {
		printf("Test Case 52 PASSED\n");
	}

	steps = 55;
	X1 = (curve25519_key_t){.key64 = {
		0xC00688DB5BEFE8F0ULL,
		0x254C759AC069562DULL,
		0x4005291CAA086A0BULL,
		0x6918A30E38485754ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC00688DB5BEFE8F0ULL,
			0x254C759AC069562DULL,
			0x4005291CAA086A0BULL,
			0x6918A30E38485754ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE3FA6851009C27ECULL,
			0xB67179EA6B9C129DULL,
			0xD8A9D99E29633308ULL,
			0x01541075D22C775FULL}
		},
		.Z = {.key64 = {
			0x28B8151658FBA2ADULL,
			0x6EEA1872BD81F9EBULL,
			0xA372762FCDF66FCDULL,
			0x162DD639A9C549A1ULL}
		}
	};
	printf("Test Case 53\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 53 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -53;
	} else {
		printf("Test Case 53 PASSED\n");
	}

	steps = 21;
	X1 = (curve25519_key_t){.key64 = {
		0x5FBE5CF33C4C5690ULL,
		0x586982A1E3407FE7ULL,
		0x3DD39266106ED77CULL,
		0x50EFF7024D655A1FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5FBE5CF33C4C5690ULL,
			0x586982A1E3407FE7ULL,
			0x3DD39266106ED77CULL,
			0x50EFF7024D655A1FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB7CCDD821C4CEAF0ULL,
			0xE7037651E58CDC6EULL,
			0x92D94201A924DBC0ULL,
			0x7361B4E774CB2C40ULL}
		},
		.Z = {.key64 = {
			0x10A66949F0A8BC59ULL,
			0x02B9D01106E26055ULL,
			0xD871E0F34EB7F092ULL,
			0x77A9D8CF594950D9ULL}
		}
	};
	printf("Test Case 54\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 54 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -54;
	} else {
		printf("Test Case 54 PASSED\n");
	}

	steps = 5;
	X1 = (curve25519_key_t){.key64 = {
		0x4FAA826824F223A8ULL,
		0x54F97B6B44048D53ULL,
		0xC869F55F915A0F4DULL,
		0x4C83068F543104DBULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4FAA826824F223A8ULL,
			0x54F97B6B44048D53ULL,
			0xC869F55F915A0F4DULL,
			0x4C83068F543104DBULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6445BAFAFFD85B89ULL,
			0x22BB5F7F8641A60DULL,
			0x770CC0FF80F98D62ULL,
			0x2BB63CD331770D8FULL}
		},
		.Z = {.key64 = {
			0x9F66EE39A31B09A1ULL,
			0x45FB9042913C6CA1ULL,
			0xC3E194F57FF8A0E7ULL,
			0x21BFD3BD7C38C8C5ULL}
		}
	};
	printf("Test Case 55\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 55 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -55;
	} else {
		printf("Test Case 55 PASSED\n");
	}

	steps = 63;
	X1 = (curve25519_key_t){.key64 = {
		0xF5B69EFA4F6B6FC0ULL,
		0x46B4A1AFCF3CD091ULL,
		0xCCA85BC27DDB70E6ULL,
		0x60A529734F2D7861ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF5B69EFA4F6B6FC0ULL,
			0x46B4A1AFCF3CD091ULL,
			0xCCA85BC27DDB70E6ULL,
			0x60A529734F2D7861ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFE0ECF45D8EEEC2CULL,
			0xFDD6C0744397D15DULL,
			0xB48EE60C13599B5DULL,
			0x12E980D7E2F022F0ULL}
		},
		.Z = {.key64 = {
			0x43BBEAB264A5E1DDULL,
			0x0B3EC5407605D5AFULL,
			0xCBD8F9EE53C26CC6ULL,
			0x2BDB1266C1BC40C7ULL}
		}
	};
	printf("Test Case 56\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 56 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -56;
	} else {
		printf("Test Case 56 PASSED\n");
	}

	steps = 45;
	X1 = (curve25519_key_t){.key64 = {
		0x61CA50DAD9CE5A30ULL,
		0x29B37F69A44A7B50ULL,
		0x7D4AB6CF8BF99532ULL,
		0x4D07F5B312C7F3EAULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x61CA50DAD9CE5A30ULL,
			0x29B37F69A44A7B50ULL,
			0x7D4AB6CF8BF99532ULL,
			0x4D07F5B312C7F3EAULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBE0DBE41C2BBDCA4ULL,
			0xAC35B0CFCD6C33ACULL,
			0x264A170CE9C732CAULL,
			0x52E2242C89E4E6D0ULL}
		},
		.Z = {.key64 = {
			0x1D3C9610CC6830ACULL,
			0x7421591875F6A1F2ULL,
			0x81C26C79C3282A45ULL,
			0x0B5CF2ADB3212BCCULL}
		}
	};
	printf("Test Case 57\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 57 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -57;
	} else {
		printf("Test Case 57 PASSED\n");
	}

	steps = 37;
	X1 = (curve25519_key_t){.key64 = {
		0x26A6D81E8E3C9D60ULL,
		0x8AF5D23C389E1357ULL,
		0x652655D33020D39BULL,
		0x526E5955FAE59833ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x26A6D81E8E3C9D60ULL,
			0x8AF5D23C389E1357ULL,
			0x652655D33020D39BULL,
			0x526E5955FAE59833ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x59E8A596C2A7C1C8ULL,
			0xBA9B21E9CDE97CC5ULL,
			0x8CAC93659842B388ULL,
			0x4B314A75C6EDA64AULL}
		},
		.Z = {.key64 = {
			0x11874E30C2CA305DULL,
			0xFCE8D0D4AD216BA8ULL,
			0x4D8588DE2BF30285ULL,
			0x19C761A6924613B0ULL}
		}
	};
	printf("Test Case 58\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 58 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -58;
	} else {
		printf("Test Case 58 PASSED\n");
	}

	steps = 54;
	X1 = (curve25519_key_t){.key64 = {
		0xE351F67795B8BA40ULL,
		0x30566BFEBA1A16EBULL,
		0x39CF9B0BB89A7431ULL,
		0x6F718E5083AA2327ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE351F67795B8BA40ULL,
			0x30566BFEBA1A16EBULL,
			0x39CF9B0BB89A7431ULL,
			0x6F718E5083AA2327ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA9A842692CFB133BULL,
			0x6BEA4D787142B49FULL,
			0x91157CD02B26D7F4ULL,
			0x17CEE35C11C360C6ULL}
		},
		.Z = {.key64 = {
			0xB34D3D47FF09B0F5ULL,
			0xFD86347E6C63E34FULL,
			0xD0CFE3E7A6A47030ULL,
			0x36BE42EF57B6DAA7ULL}
		}
	};
	printf("Test Case 59\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 59 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -59;
	} else {
		printf("Test Case 59 PASSED\n");
	}

	steps = 12;
	X1 = (curve25519_key_t){.key64 = {
		0x5E93F2F83501B648ULL,
		0x3A97C3980B504DD7ULL,
		0xBDA85D063C03DD2FULL,
		0x6B88C18AD3EA576BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5E93F2F83501B648ULL,
			0x3A97C3980B504DD7ULL,
			0xBDA85D063C03DD2FULL,
			0x6B88C18AD3EA576BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x078C7E564285A942ULL,
			0x5575765AE46E8274ULL,
			0xFBDEC16E14641A97ULL,
			0x789FEA1CC9F827C1ULL}
		},
		.Z = {.key64 = {
			0x895543215F217A7BULL,
			0x1DD4275D531A9281ULL,
			0x41CADAABCDD46E74ULL,
			0x3BA044EBCD33384DULL}
		}
	};
	printf("Test Case 60\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 60 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -60;
	} else {
		printf("Test Case 60 PASSED\n");
	}

	steps = 17;
	X1 = (curve25519_key_t){.key64 = {
		0xDEDA280E35262B48ULL,
		0x6D74817D3B9533BCULL,
		0x8782212BC131F800ULL,
		0x57803BC96D22B06CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDEDA280E35262B48ULL,
			0x6D74817D3B9533BCULL,
			0x8782212BC131F800ULL,
			0x57803BC96D22B06CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x06974F58DB1BE4ADULL,
			0xBD52E88BC2F00DC5ULL,
			0x391CAC4583663B4EULL,
			0x77A2B9F2CB1EBECEULL}
		},
		.Z = {.key64 = {
			0x0BE19AC69D66B143ULL,
			0x4DDCC99D6DBFADC7ULL,
			0x8BF3E74CC6C55657ULL,
			0x32B4C77EE47BDB63ULL}
		}
	};
	printf("Test Case 61\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 61 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -61;
	} else {
		printf("Test Case 61 PASSED\n");
	}

	steps = 8;
	X1 = (curve25519_key_t){.key64 = {
		0x336B161319999BB0ULL,
		0x2DCC2916B218D894ULL,
		0xE17CA721B220C55AULL,
		0x45C8FEA4E3D6D184ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x336B161319999BB0ULL,
			0x2DCC2916B218D894ULL,
			0xE17CA721B220C55AULL,
			0x45C8FEA4E3D6D184ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7715C4BC8397C106ULL,
			0x2F49C97E3E7C04D1ULL,
			0xCA02A1FC2303D685ULL,
			0x06BC317ADB30136AULL}
		},
		.Z = {.key64 = {
			0x1E35A23D0A2EA543ULL,
			0x7654805C4DC92C6FULL,
			0x50444385F3801BF8ULL,
			0x7E1D7D871C2757E0ULL}
		}
	};
	printf("Test Case 62\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 62 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -62;
	} else {
		printf("Test Case 62 PASSED\n");
	}

	steps = 23;
	X1 = (curve25519_key_t){.key64 = {
		0xB2C5DF0BE7A22D90ULL,
		0x61D0AAAB334A329BULL,
		0xAEFFB9C006CFCDBAULL,
		0x52123276675D0D3BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB2C5DF0BE7A22D90ULL,
			0x61D0AAAB334A329BULL,
			0xAEFFB9C006CFCDBAULL,
			0x52123276675D0D3BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x20F65BF3934347D7ULL,
			0x38F429A2A4C615CAULL,
			0xB9665F9B278B5598ULL,
			0x05B574E401F72715ULL}
		},
		.Z = {.key64 = {
			0xF197394C2A36D3A7ULL,
			0x71D5F346B90FD598ULL,
			0x30A44CD6E2361DE4ULL,
			0x3B0575C15D5F07C0ULL}
		}
	};
	printf("Test Case 63\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 63 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -63;
	} else {
		printf("Test Case 63 PASSED\n");
	}

	steps = 19;
	X1 = (curve25519_key_t){.key64 = {
		0x91FB933FE87B7F38ULL,
		0xA651CDBB41CD7601ULL,
		0xE204FDF35C54DEC1ULL,
		0x7BB2FE1F7C03311AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x91FB933FE87B7F38ULL,
			0xA651CDBB41CD7601ULL,
			0xE204FDF35C54DEC1ULL,
			0x7BB2FE1F7C03311AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCCB2F5E8EB5A5839ULL,
			0x8EFFCA3E73C9AADEULL,
			0xEB5F2CE8C24DF3BCULL,
			0x386E6FD79CEB4F42ULL}
		},
		.Z = {.key64 = {
			0xCD32C8E1B3B5E55FULL,
			0x1285C2AD6BB2B08DULL,
			0x739EE7C96EB0281EULL,
			0x1DDE67F3D7C06336ULL}
		}
	};
	printf("Test Case 64\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 64 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -64;
	} else {
		printf("Test Case 64 PASSED\n");
	}

	steps = 50;
	X1 = (curve25519_key_t){.key64 = {
		0xD615A19EA151C6A0ULL,
		0x294EB0CE2BAFFEC1ULL,
		0xB0786330517A7AC6ULL,
		0x57E9C6F6A73E78FEULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD615A19EA151C6A0ULL,
			0x294EB0CE2BAFFEC1ULL,
			0xB0786330517A7AC6ULL,
			0x57E9C6F6A73E78FEULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8DFC2349AF9E6541ULL,
			0x5AA8558FD03A42A7ULL,
			0x15BB66D5C26C444EULL,
			0x549B5344BDF1344DULL}
		},
		.Z = {.key64 = {
			0x5CF49828A688D0F1ULL,
			0xB00986C0EC076ECCULL,
			0x657E4BBEBFB6BEDFULL,
			0x57577101845FC7D8ULL}
		}
	};
	printf("Test Case 65\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 65 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -65;
	} else {
		printf("Test Case 65 PASSED\n");
	}

	steps = 48;
	X1 = (curve25519_key_t){.key64 = {
		0xB0FB5A0E6EE84AE0ULL,
		0xBC3C720134E5BB1BULL,
		0x1E02E0C06478F76CULL,
		0x778EFB94FBFDE3B3ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB0FB5A0E6EE84AE0ULL,
			0xBC3C720134E5BB1BULL,
			0x1E02E0C06478F76CULL,
			0x778EFB94FBFDE3B3ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDDF3AB6E4EAF6B57ULL,
			0x4C46AFF4B2FBD6E4ULL,
			0xF147B73C0070BBCBULL,
			0x4AD72097811A63D4ULL}
		},
		.Z = {.key64 = {
			0x6923F94B5CCD04E5ULL,
			0x6D90CF536F690AE4ULL,
			0xFBB021C45EF4EF55ULL,
			0x2F9DC6C7A839A13DULL}
		}
	};
	printf("Test Case 66\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 66 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -66;
	} else {
		printf("Test Case 66 PASSED\n");
	}

	steps = 30;
	X1 = (curve25519_key_t){.key64 = {
		0x5E25FC775400DC78ULL,
		0x9C8F4E3ADA0021CCULL,
		0x9FAF416554A3E289ULL,
		0x5B8162C51AB0E840ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5E25FC775400DC78ULL,
			0x9C8F4E3ADA0021CCULL,
			0x9FAF416554A3E289ULL,
			0x5B8162C51AB0E840ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD01E57FE5F74E19BULL,
			0x9750FC1614CC515EULL,
			0x43A7A233EA04C577ULL,
			0x7CCE43314071D7A5ULL}
		},
		.Z = {.key64 = {
			0x94F820E66F90A8A9ULL,
			0x1C9CE220F19DC467ULL,
			0xB2D4FFFFCFEF3CD0ULL,
			0x1A5B935970214CC5ULL}
		}
	};
	printf("Test Case 67\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 67 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -67;
	} else {
		printf("Test Case 67 PASSED\n");
	}

	steps = 3;
	X1 = (curve25519_key_t){.key64 = {
		0xE33114F5824D2F68ULL,
		0x5D9D205573F81800ULL,
		0xF0A42C8C8B9A423DULL,
		0x632C01EACFBAA35BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE33114F5824D2F68ULL,
			0x5D9D205573F81800ULL,
			0xF0A42C8C8B9A423DULL,
			0x632C01EACFBAA35BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFF4436BF55875744ULL,
			0x4BA7C91AA928AA5AULL,
			0xD92989C0DCA4D949ULL,
			0x2B10BD10A8EDD48FULL}
		},
		.Z = {.key64 = {
			0x944776456B361805ULL,
			0xE76F2108BA1EC801ULL,
			0x1FF8766C7673D305ULL,
			0x46450168F801B81EULL}
		}
	};
	printf("Test Case 68\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 68 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -68;
	} else {
		printf("Test Case 68 PASSED\n");
	}

	steps = 33;
	X1 = (curve25519_key_t){.key64 = {
		0xE4F43F8DF8D9AF48ULL,
		0x0F427F0C70135857ULL,
		0x102FB6581D57AD43ULL,
		0x5909781ED139C3C2ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE4F43F8DF8D9AF48ULL,
			0x0F427F0C70135857ULL,
			0x102FB6581D57AD43ULL,
			0x5909781ED139C3C2ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x79A29830889678A0ULL,
			0xC41FBB0098BF2178ULL,
			0x41A639EC20705F8DULL,
			0x4919581ED8E0EC86ULL}
		},
		.Z = {.key64 = {
			0x8B896340816AFD7BULL,
			0x1A1312CA58B732E6ULL,
			0x83181746CA4D23CBULL,
			0x0A5CD9B4981335CDULL}
		}
	};
	printf("Test Case 69\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 69 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -69;
	} else {
		printf("Test Case 69 PASSED\n");
	}

	steps = 10;
	X1 = (curve25519_key_t){.key64 = {
		0xCAC197B0278CA9A0ULL,
		0x58E187DACCD99AEBULL,
		0x77F2AC84C5F47A78ULL,
		0x48AD2A5437116A32ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCAC197B0278CA9A0ULL,
			0x58E187DACCD99AEBULL,
			0x77F2AC84C5F47A78ULL,
			0x48AD2A5437116A32ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0F3AF9F1811DD1DBULL,
			0x48F85E32847AF0F3ULL,
			0xEE3C09F900D8CBF5ULL,
			0x103EC49BA825BA46ULL}
		},
		.Z = {.key64 = {
			0x4840102BFA69DB90ULL,
			0x03DFAA92C805A60BULL,
			0x722245E215E9C09CULL,
			0x28C926FD3CA35BFDULL}
		}
	};
	printf("Test Case 70\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 70 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -70;
	} else {
		printf("Test Case 70 PASSED\n");
	}

	steps = 56;
	X1 = (curve25519_key_t){.key64 = {
		0xEFF430346EEF0DB8ULL,
		0x712A7C1DB8504791ULL,
		0x33DB9B270EB69A08ULL,
		0x475978BA4DC01200ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEFF430346EEF0DB8ULL,
			0x712A7C1DB8504791ULL,
			0x33DB9B270EB69A08ULL,
			0x475978BA4DC01200ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0F2E3018799D5D01ULL,
			0x351E2FCCC6022997ULL,
			0xB1161521A51F2A3AULL,
			0x56CB12E080B4E30AULL}
		},
		.Z = {.key64 = {
			0x12CBAA4C515743CBULL,
			0xBFD35DCB2E202736ULL,
			0xC56A75AC5F04A8CDULL,
			0x0ECDD8369326890CULL}
		}
	};
	printf("Test Case 71\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 71 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -71;
	} else {
		printf("Test Case 71 PASSED\n");
	}

	steps = 35;
	X1 = (curve25519_key_t){.key64 = {
		0x7A6ED859C838A068ULL,
		0x16DD886E6D8679CCULL,
		0x96ECDFFD7A74341EULL,
		0x444C5D88CD193DDAULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7A6ED859C838A068ULL,
			0x16DD886E6D8679CCULL,
			0x96ECDFFD7A74341EULL,
			0x444C5D88CD193DDAULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA28C1129B7C767A2ULL,
			0x599EA564445EE010ULL,
			0xD534B70B8EBCC713ULL,
			0x093DF2A0F5154B5AULL}
		},
		.Z = {.key64 = {
			0x39CBDB3DB413C290ULL,
			0xC0AFE8682E8475FCULL,
			0x49FE1B5612919FDCULL,
			0x1123B1A851D538C7ULL}
		}
	};
	printf("Test Case 72\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 72 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -72;
	} else {
		printf("Test Case 72 PASSED\n");
	}

	steps = 20;
	X1 = (curve25519_key_t){.key64 = {
		0x7BA9F659AFC88BE8ULL,
		0x797A673B005A63F3ULL,
		0xF6B6893334E1986CULL,
		0x7F24ACB50D170470ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7BA9F659AFC88BE8ULL,
			0x797A673B005A63F3ULL,
			0xF6B6893334E1986CULL,
			0x7F24ACB50D170470ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x68C33F9A05325A16ULL,
			0x3C04F2CAA1C4ED23ULL,
			0xF6E0D2E83EC40D90ULL,
			0x75D6CABA2501BC5BULL}
		},
		.Z = {.key64 = {
			0x6BFAA2EE9686635EULL,
			0xFDCDA15C16595E8DULL,
			0xFE0660DFCAC53674ULL,
			0x146BC4CDE427A73CULL}
		}
	};
	printf("Test Case 73\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 73 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -73;
	} else {
		printf("Test Case 73 PASSED\n");
	}

	steps = 15;
	X1 = (curve25519_key_t){.key64 = {
		0xBA33A95B05401938ULL,
		0x1E83C4407D92561CULL,
		0xB1B8076BB6031C4AULL,
		0x42F59909EE13924EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBA33A95B05401938ULL,
			0x1E83C4407D92561CULL,
			0xB1B8076BB6031C4AULL,
			0x42F59909EE13924EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7F740EAF3EE55DB5ULL,
			0x662A56D6974B5B42ULL,
			0x207AA4FF4178EB0DULL,
			0x4F11F38B269F47FFULL}
		},
		.Z = {.key64 = {
			0x75EF3832270A44F1ULL,
			0x1C93C8BE9860D232ULL,
			0xC898DC550DF9A42AULL,
			0x7364A3691E602E51ULL}
		}
	};
	printf("Test Case 74\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 74 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -74;
	} else {
		printf("Test Case 74 PASSED\n");
	}

	steps = 57;
	X1 = (curve25519_key_t){.key64 = {
		0x2BD6102DB0EA82F0ULL,
		0xB6C7BDC2F0B3FE71ULL,
		0x46FEC32C3EF16BA5ULL,
		0x76FF18639651A311ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2BD6102DB0EA82F0ULL,
			0xB6C7BDC2F0B3FE71ULL,
			0x46FEC32C3EF16BA5ULL,
			0x76FF18639651A311ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD6FDDE0964BB2738ULL,
			0x6F76AA9CAF92CAFBULL,
			0x735930B00C9535DFULL,
			0x42C88E9BF4E72293ULL}
		},
		.Z = {.key64 = {
			0x2E02ED2D33BCBE53ULL,
			0x1884585CB86E862BULL,
			0x06B0E557AA097D2FULL,
			0x6CF0517DE463969BULL}
		}
	};
	printf("Test Case 75\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 75 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -75;
	} else {
		printf("Test Case 75 PASSED\n");
	}

	steps = 7;
	X1 = (curve25519_key_t){.key64 = {
		0x2632C50016DF4E48ULL,
		0x024E7BFB75C4C782ULL,
		0x75058BD18554133EULL,
		0x7FDBE0A78B0A714FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2632C50016DF4E48ULL,
			0x024E7BFB75C4C782ULL,
			0x75058BD18554133EULL,
			0x7FDBE0A78B0A714FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE58830C2F8B8F1C4ULL,
			0xBAD8C2DAAA5AB136ULL,
			0x91A7739FE689712DULL,
			0x45C0985580175373ULL}
		},
		.Z = {.key64 = {
			0x0753E8AB12CB5398ULL,
			0x54CFF80F183C9C8AULL,
			0x7A9844DC689018DDULL,
			0x4196B37B79A8CD97ULL}
		}
	};
	printf("Test Case 76\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 76 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -76;
	} else {
		printf("Test Case 76 PASSED\n");
	}

	steps = 36;
	X1 = (curve25519_key_t){.key64 = {
		0xDD7C9D8DDCEDA760ULL,
		0xB0926BA5237A1997ULL,
		0xAC598F186F1FA7C4ULL,
		0x60F978445B4DBED4ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDD7C9D8DDCEDA760ULL,
			0xB0926BA5237A1997ULL,
			0xAC598F186F1FA7C4ULL,
			0x60F978445B4DBED4ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6F30D5A01C74E7CBULL,
			0xE184201C40D24BB9ULL,
			0xAF5BBB6A5D59A39DULL,
			0x4CC692A173E98850ULL}
		},
		.Z = {.key64 = {
			0x617E5DAA2B005D83ULL,
			0xF0156C3F49CE9F4DULL,
			0x105114E2D1FF1A17ULL,
			0x64365FE066B712FBULL}
		}
	};
	printf("Test Case 77\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 77 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -77;
	} else {
		printf("Test Case 77 PASSED\n");
	}

	steps = 17;
	X1 = (curve25519_key_t){.key64 = {
		0xB229E6FFA88E35D8ULL,
		0xF141012F972798DDULL,
		0xFA9FE75849E8B52CULL,
		0x736B7C6BA198587AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB229E6FFA88E35D8ULL,
			0xF141012F972798DDULL,
			0xFA9FE75849E8B52CULL,
			0x736B7C6BA198587AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2D16F93100C12D53ULL,
			0xA1111D00C4893BD0ULL,
			0x86E30C5C7DFB2602ULL,
			0x534095B2F18BEA89ULL}
		},
		.Z = {.key64 = {
			0x76F37B2B61A42B2BULL,
			0xDB27EBAF781D094EULL,
			0xFE522DF388E94439ULL,
			0x110C2B92FECFDE64ULL}
		}
	};
	printf("Test Case 78\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 78 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -78;
	} else {
		printf("Test Case 78 PASSED\n");
	}

	steps = 38;
	X1 = (curve25519_key_t){.key64 = {
		0xE4F42BAA52F19308ULL,
		0xDFD8C429EC7A7C98ULL,
		0x2652ED56EDC1B28DULL,
		0x7BE8B31A3D6DC14FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE4F42BAA52F19308ULL,
			0xDFD8C429EC7A7C98ULL,
			0x2652ED56EDC1B28DULL,
			0x7BE8B31A3D6DC14FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x65E60317F342CA17ULL,
			0xEF9C72298C8348A5ULL,
			0x86071C1B5A4AC7E6ULL,
			0x27B7CDFB5255F539ULL}
		},
		.Z = {.key64 = {
			0x96D888090CAF8784ULL,
			0x9AB7B001A22F2551ULL,
			0x61E27FFD52053A49ULL,
			0x42C258FA72EE2DFCULL}
		}
	};
	printf("Test Case 79\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 79 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -79;
	} else {
		printf("Test Case 79 PASSED\n");
	}

	steps = 58;
	X1 = (curve25519_key_t){.key64 = {
		0x2AF29AF7319CDDA0ULL,
		0xDA8B0792019F4C55ULL,
		0xAB8B85A42E1E98DBULL,
		0x4382C140B99023DEULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2AF29AF7319CDDA0ULL,
			0xDA8B0792019F4C55ULL,
			0xAB8B85A42E1E98DBULL,
			0x4382C140B99023DEULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE7E400A400EDAE42ULL,
			0x22B3B98E6625E313ULL,
			0x53A0CF8CEB5D93A3ULL,
			0x6A692726B4B334E4ULL}
		},
		.Z = {.key64 = {
			0xA9E6BA9EE5AF4A3FULL,
			0xC5310CC349144ED0ULL,
			0xAD92EA3282D878F3ULL,
			0x560B446E15AEB85DULL}
		}
	};
	printf("Test Case 80\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 80 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -80;
	} else {
		printf("Test Case 80 PASSED\n");
	}

	steps = 60;
	X1 = (curve25519_key_t){.key64 = {
		0x7C724BCCCE3E4D28ULL,
		0x7AD6C605C3E7DA92ULL,
		0x0AA37035BF990777ULL,
		0x7B23B6DCAE494D84ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7C724BCCCE3E4D28ULL,
			0x7AD6C605C3E7DA92ULL,
			0x0AA37035BF990777ULL,
			0x7B23B6DCAE494D84ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x92EB9E817A1E94F6ULL,
			0xF866DABF4F3234CFULL,
			0x9985679083622664ULL,
			0x5C4200F2CECBBF6AULL}
		},
		.Z = {.key64 = {
			0x31F161F3DD49AD46ULL,
			0x28A9933A2B50A30BULL,
			0xF066C43FFA3E7F11ULL,
			0x59F129438BE20DF0ULL}
		}
	};
	printf("Test Case 81\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 81 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -81;
	} else {
		printf("Test Case 81 PASSED\n");
	}

	steps = 20;
	X1 = (curve25519_key_t){.key64 = {
		0x7887F82F35F77630ULL,
		0x2435086B3F49079CULL,
		0x83653BF6FAF0E7D5ULL,
		0x751DE0BE213A8AD6ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7887F82F35F77630ULL,
			0x2435086B3F49079CULL,
			0x83653BF6FAF0E7D5ULL,
			0x751DE0BE213A8AD6ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9BC306FDA84E0C21ULL,
			0xCC56A3D26098C392ULL,
			0x788EE208C2C3253DULL,
			0x090804A702C1E84AULL}
		},
		.Z = {.key64 = {
			0x5452F48B74DC903EULL,
			0x5A8901A8E54DED1DULL,
			0xE6E8F98A9B61EE2CULL,
			0x1AA7BD0C7C694FA2ULL}
		}
	};
	printf("Test Case 82\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 82 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -82;
	} else {
		printf("Test Case 82 PASSED\n");
	}

	steps = 42;
	X1 = (curve25519_key_t){.key64 = {
		0xDC9EC5C1B78B1078ULL,
		0x8E715373C3BA46DAULL,
		0x263B5FA7DB84072BULL,
		0x42D4AADB10CC99AEULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDC9EC5C1B78B1078ULL,
			0x8E715373C3BA46DAULL,
			0x263B5FA7DB84072BULL,
			0x42D4AADB10CC99AEULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD460F39D8B2DFF72ULL,
			0x9219235E53D1EA61ULL,
			0x47DF8FE6B0B934FCULL,
			0x4340CB1A080E94B6ULL}
		},
		.Z = {.key64 = {
			0x48D71708FECBED64ULL,
			0xE80F2B360A16B36FULL,
			0xFA53AAFA8175C34BULL,
			0x2ECB4F7F04E1928EULL}
		}
	};
	printf("Test Case 83\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 83 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -83;
	} else {
		printf("Test Case 83 PASSED\n");
	}

	steps = 19;
	X1 = (curve25519_key_t){.key64 = {
		0x3C999B94E2511AF0ULL,
		0xD27E24462D0D8263ULL,
		0xD73FDF7CBE0BFADDULL,
		0x51B7CBBF5FAFC0DFULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3C999B94E2511AF0ULL,
			0xD27E24462D0D8263ULL,
			0xD73FDF7CBE0BFADDULL,
			0x51B7CBBF5FAFC0DFULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5A1BB3B84FF27D7BULL,
			0x8B9EE50BB63DFED9ULL,
			0x69BCE465874D458CULL,
			0x3A6C44E38AFE48D3ULL}
		},
		.Z = {.key64 = {
			0x795C1E34AEA5D234ULL,
			0x062E9666EE945879ULL,
			0x69CAC0506A7C8213ULL,
			0x4322939B65ED18ABULL}
		}
	};
	printf("Test Case 84\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 84 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -84;
	} else {
		printf("Test Case 84 PASSED\n");
	}

	steps = 29;
	X1 = (curve25519_key_t){.key64 = {
		0x8CDB89B095074D68ULL,
		0x33C4281D345458DFULL,
		0xA7B9328380003D42ULL,
		0x67EFAA051E87C58EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8CDB89B095074D68ULL,
			0x33C4281D345458DFULL,
			0xA7B9328380003D42ULL,
			0x67EFAA051E87C58EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEF5AFB85FD036E8BULL,
			0x855EE4C1A4AAE66FULL,
			0xCE31B212AE61E879ULL,
			0x3F3F08C95BE58BC2ULL}
		},
		.Z = {.key64 = {
			0x9ECD7B9CB56E4E4DULL,
			0x3F55415AC3FA77FFULL,
			0xC34E7A1FFCA060DAULL,
			0x384137C26B368A32ULL}
		}
	};
	printf("Test Case 85\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 85 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -85;
	} else {
		printf("Test Case 85 PASSED\n");
	}

	steps = 43;
	X1 = (curve25519_key_t){.key64 = {
		0xC1FF5106E80972A0ULL,
		0x710FC7FEDB63616BULL,
		0xDED1758849CAD9EEULL,
		0x4189F37B6012AAC4ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC1FF5106E80972A0ULL,
			0x710FC7FEDB63616BULL,
			0xDED1758849CAD9EEULL,
			0x4189F37B6012AAC4ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD486A024D9335082ULL,
			0xC6992BA4D914335AULL,
			0x5A64846A6F49377EULL,
			0x3FDD231C2BD49959ULL}
		},
		.Z = {.key64 = {
			0x674C4B96DBB24CF0ULL,
			0x5EA57EEA46296825ULL,
			0xB670727A18E14FD4ULL,
			0x0652F54DFFD25AA6ULL}
		}
	};
	printf("Test Case 86\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 86 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -86;
	} else {
		printf("Test Case 86 PASSED\n");
	}

	steps = 64;
	X1 = (curve25519_key_t){.key64 = {
		0x8D27D633761694C0ULL,
		0x91436D15FF844E6DULL,
		0x688AAD33A78D0CF2ULL,
		0x5957B6786DEFA9DCULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8D27D633761694C0ULL,
			0x91436D15FF844E6DULL,
			0x688AAD33A78D0CF2ULL,
			0x5957B6786DEFA9DCULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1B2538F5DBEF6B9CULL,
			0xC89F0A423886BB51ULL,
			0xF143BC15FBCF839BULL,
			0x03E9DBC01EEF5634ULL}
		},
		.Z = {.key64 = {
			0x46019B610CB3D69DULL,
			0x7FF0985668626AF4ULL,
			0x78B3F9F266F61495ULL,
			0x5E11515DA910D561ULL}
		}
	};
	printf("Test Case 87\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 87 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -87;
	} else {
		printf("Test Case 87 PASSED\n");
	}

	steps = 39;
	X1 = (curve25519_key_t){.key64 = {
		0xA3025877F1DDA000ULL,
		0x0B33A11BC7013916ULL,
		0xDDE5972B88FA6179ULL,
		0x614F60FFE8C7F2FFULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA3025877F1DDA000ULL,
			0x0B33A11BC7013916ULL,
			0xDDE5972B88FA6179ULL,
			0x614F60FFE8C7F2FFULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x30D7A5689D387870ULL,
			0xF436A1E90F7DCF62ULL,
			0x39AD386222AA162DULL,
			0x7A78FE919EBCF618ULL}
		},
		.Z = {.key64 = {
			0x6463869F88430A86ULL,
			0xB1934F3DC15FAE2FULL,
			0x9D179054E083F8E7ULL,
			0x0BA5952D5687E175ULL}
		}
	};
	printf("Test Case 88\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 88 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -88;
	} else {
		printf("Test Case 88 PASSED\n");
	}

	steps = 40;
	X1 = (curve25519_key_t){.key64 = {
		0x4B5E4E306B83CF98ULL,
		0x323E6580311C3B43ULL,
		0xE0422A530A0B490DULL,
		0x73C2FC1B998B68C8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4B5E4E306B83CF98ULL,
			0x323E6580311C3B43ULL,
			0xE0422A530A0B490DULL,
			0x73C2FC1B998B68C8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x358D8E225F3AE8C0ULL,
			0x59D8BA64C20E3F1EULL,
			0xA26AFF5AD513C610ULL,
			0x02FABAEB1B209FA5ULL}
		},
		.Z = {.key64 = {
			0xE7910D916BCC1B22ULL,
			0x9521ECB6B69915D3ULL,
			0xF071E8E005042F5FULL,
			0x6B4C20E3D8127373ULL}
		}
	};
	printf("Test Case 89\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 89 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -89;
	} else {
		printf("Test Case 89 PASSED\n");
	}

	steps = 55;
	X1 = (curve25519_key_t){.key64 = {
		0xA148DB074DD00E90ULL,
		0xD155A679E010BDEAULL,
		0x5DCC167126F2B498ULL,
		0x770134D3100F6F50ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA148DB074DD00E90ULL,
			0xD155A679E010BDEAULL,
			0x5DCC167126F2B498ULL,
			0x770134D3100F6F50ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4D9967A79BB2995DULL,
			0xB84EE1F79F0500CAULL,
			0x94C9687067F39547ULL,
			0x7D71733C9AAF7764ULL}
		},
		.Z = {.key64 = {
			0x423F2A83F20AD9BDULL,
			0xC11056EBAF9CD6EBULL,
			0x4D50859D00A8E37BULL,
			0x6B6CF82E79C96EA4ULL}
		}
	};
	printf("Test Case 90\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 90 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -90;
	} else {
		printf("Test Case 90 PASSED\n");
	}

	steps = 7;
	X1 = (curve25519_key_t){.key64 = {
		0xD87EA4DEE104ABD8ULL,
		0xB5A27B5CCE84E1E7ULL,
		0x4B86D47A2343DF8BULL,
		0x7815FF98EFC31FD9ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD87EA4DEE104ABD8ULL,
			0xB5A27B5CCE84E1E7ULL,
			0x4B86D47A2343DF8BULL,
			0x7815FF98EFC31FD9ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x77FB6A1900DDA3F2ULL,
			0x404842142D2DB6EEULL,
			0xA10F46435AD1E1E8ULL,
			0x36F6C073D1EE7E46ULL}
		},
		.Z = {.key64 = {
			0x9F6075DE5A5A35B0ULL,
			0xD58138803A27729FULL,
			0x67D09CB016086F80ULL,
			0x3214E994FCB8C7C6ULL}
		}
	};
	printf("Test Case 91\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 91 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -91;
	} else {
		printf("Test Case 91 PASSED\n");
	}

	steps = 37;
	X1 = (curve25519_key_t){.key64 = {
		0x7827CBE9E3360810ULL,
		0x15CD2D02B4D99827ULL,
		0x0F809C2702DA32BCULL,
		0x6D4F5B482A7235A3ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7827CBE9E3360810ULL,
			0x15CD2D02B4D99827ULL,
			0x0F809C2702DA32BCULL,
			0x6D4F5B482A7235A3ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x68430FA8EF5C6D4BULL,
			0x8B732AFFBC7736A1ULL,
			0xF8E8ACC6301447EEULL,
			0x628E8B65757D6490ULL}
		},
		.Z = {.key64 = {
			0xC99FD170AE7C7340ULL,
			0x6E7D06E0A6259F19ULL,
			0xB9F5855DDF0405D6ULL,
			0x056FC971E4D11265ULL}
		}
	};
	printf("Test Case 92\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 92 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -92;
	} else {
		printf("Test Case 92 PASSED\n");
	}

	steps = 58;
	X1 = (curve25519_key_t){.key64 = {
		0xD6B78D1159B5D420ULL,
		0xD07795248A9226DAULL,
		0x97E8CD3B63A29B2FULL,
		0x40CDB312B8BDD16BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD6B78D1159B5D420ULL,
			0xD07795248A9226DAULL,
			0x97E8CD3B63A29B2FULL,
			0x40CDB312B8BDD16BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5EF7EEB31066C491ULL,
			0xCD9F8BF04A4425AAULL,
			0x1D0B54C087DFF09EULL,
			0x10F713589DE47DFFULL}
		},
		.Z = {.key64 = {
			0x2DC6B948C188CDF6ULL,
			0xE3247F76F767F34DULL,
			0x42F13C14DD0621D3ULL,
			0x4428152B8C54557EULL}
		}
	};
	printf("Test Case 93\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 93 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -93;
	} else {
		printf("Test Case 93 PASSED\n");
	}

	steps = 38;
	X1 = (curve25519_key_t){.key64 = {
		0x74B277439566FEA8ULL,
		0x8DD9C4522EEB6147ULL,
		0xAEA04E9FA66EDE7FULL,
		0x79A2083D910D09D6ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x74B277439566FEA8ULL,
			0x8DD9C4522EEB6147ULL,
			0xAEA04E9FA66EDE7FULL,
			0x79A2083D910D09D6ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3B39486EE9A58465ULL,
			0x5D22009CE305061BULL,
			0x4A09A5E8593B3B82ULL,
			0x37512A05B5B80C98ULL}
		},
		.Z = {.key64 = {
			0x90DD404234621279ULL,
			0x929FCFA5A772CD9BULL,
			0x45D51B5AD6991DFDULL,
			0x40FCF6B5103E432CULL}
		}
	};
	printf("Test Case 94\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 94 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -94;
	} else {
		printf("Test Case 94 PASSED\n");
	}

	steps = 45;
	X1 = (curve25519_key_t){.key64 = {
		0x70EDC29416EF4B28ULL,
		0xF2BD624F5ABD2D9DULL,
		0x84E88A24C56D8602ULL,
		0x691D9919ACFF70A8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x70EDC29416EF4B28ULL,
			0xF2BD624F5ABD2D9DULL,
			0x84E88A24C56D8602ULL,
			0x691D9919ACFF70A8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x82A4AA35AAA231CCULL,
			0xA6728E3730B004A8ULL,
			0x6B99DE3408B379AEULL,
			0x5A2FC2AB25CBB1A0ULL}
		},
		.Z = {.key64 = {
			0xC0E45012FD6AACC0ULL,
			0x07CDC55711E77814ULL,
			0x0710C0A9B984D319ULL,
			0x15791F349D9805BDULL}
		}
	};
	printf("Test Case 95\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 95 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -95;
	} else {
		printf("Test Case 95 PASSED\n");
	}

	steps = 49;
	X1 = (curve25519_key_t){.key64 = {
		0x00264F5C0F4F2E18ULL,
		0xA6C5E2FD19CD6665ULL,
		0x3E176F517615B797ULL,
		0x6599FB8BE361A936ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x00264F5C0F4F2E18ULL,
			0xA6C5E2FD19CD6665ULL,
			0x3E176F517615B797ULL,
			0x6599FB8BE361A936ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB15CBED88EBE21C5ULL,
			0xCE8FE247FF086CE7ULL,
			0x06A8337EE80A2B6BULL,
			0x6135037E023A988CULL}
		},
		.Z = {.key64 = {
			0x83C0E6D60D09F938ULL,
			0x2B44C1EB91617BB6ULL,
			0x4A2500EC7253E0C0ULL,
			0x3DCD36B397611D1AULL}
		}
	};
	printf("Test Case 96\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 96 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -96;
	} else {
		printf("Test Case 96 PASSED\n");
	}

	steps = 51;
	X1 = (curve25519_key_t){.key64 = {
		0xFB9C9EE3D08EDFF0ULL,
		0x43C38F78091F4918ULL,
		0xF7CE7D511A4B325FULL,
		0x401ADA34EA933E1AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFB9C9EE3D08EDFF0ULL,
			0x43C38F78091F4918ULL,
			0xF7CE7D511A4B325FULL,
			0x401ADA34EA933E1AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF5041C93ED748D1EULL,
			0xB22EF8F85A9F0CA9ULL,
			0x8574B6AB5ED0C554ULL,
			0x24BAA27ACDA1E175ULL}
		},
		.Z = {.key64 = {
			0x35D1C7078DCFAD3FULL,
			0xD5B4137FAAC87717ULL,
			0xDFE93E50A087854AULL,
			0x6C66658C7116AFD4ULL}
		}
	};
	printf("Test Case 97\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 97 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -97;
	} else {
		printf("Test Case 97 PASSED\n");
	}

	steps = 37;
	X1 = (curve25519_key_t){.key64 = {
		0x5AB548375CA7E838ULL,
		0x46832ED13E9AB5DDULL,
		0x5D54E2A565C981FBULL,
		0x4EC7F866A3E1726CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5AB548375CA7E838ULL,
			0x46832ED13E9AB5DDULL,
			0x5D54E2A565C981FBULL,
			0x4EC7F866A3E1726CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF2F9246BAA85B946ULL,
			0x81FF3373879D2A14ULL,
			0xEED799923D39CC3BULL,
			0x2E11CDEAC2C6DDE7ULL}
		},
		.Z = {.key64 = {
			0x1DE9BDC08A651076ULL,
			0x86B0C2EB1EE7D29FULL,
			0xB40C8CD7C705B0FAULL,
			0x6B7E475B6E0209CBULL}
		}
	};
	printf("Test Case 98\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 98 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -98;
	} else {
		printf("Test Case 98 PASSED\n");
	}

	steps = 56;
	X1 = (curve25519_key_t){.key64 = {
		0xA7137AF25479A7B8ULL,
		0xE735B9F4CE652AA5ULL,
		0xFF3700C5E3D1BEC3ULL,
		0x78EA800C2DB3EF84ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA7137AF25479A7B8ULL,
			0xE735B9F4CE652AA5ULL,
			0xFF3700C5E3D1BEC3ULL,
			0x78EA800C2DB3EF84ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x51221E54BA3116A0ULL,
			0xA1DEC22DB83ED176ULL,
			0x1EF985BB140EF4CAULL,
			0x32C7186AC16B4C70ULL}
		},
		.Z = {.key64 = {
			0x7AE4A3B7852DC380ULL,
			0x00825E06AB4B112CULL,
			0x61B7BCCC9767EC06ULL,
			0x120FB23E2FE75F05ULL}
		}
	};
	printf("Test Case 99\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 99 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -99;
	} else {
		printf("Test Case 99 PASSED\n");
	}

	steps = 9;
	X1 = (curve25519_key_t){.key64 = {
		0x6EC60CC7AEB30988ULL,
		0x9A153822F74935D7ULL,
		0xB2503D30BD1D45CBULL,
		0x60AD05BB0B41A364ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6EC60CC7AEB30988ULL,
			0x9A153822F74935D7ULL,
			0xB2503D30BD1D45CBULL,
			0x60AD05BB0B41A364ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB5BB1D0B2D1591B6ULL,
			0xBC2938B76764E650ULL,
			0xA7847CDAF377C2B4ULL,
			0x487F4FA69096F579ULL}
		},
		.Z = {.key64 = {
			0x5E6CFD378C0217DFULL,
			0xCAD8B690E3DD4286ULL,
			0xE987E08834D9B607ULL,
			0x383FEAFDDD771DD0ULL}
		}
	};
	printf("Test Case 100\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 100 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -100;
	} else {
		printf("Test Case 100 PASSED\n");
	}

	steps = 45;
	X1 = (curve25519_key_t){.key64 = {
		0xE2E8C9EFFE5C0418ULL,
		0xAE485A355C49A25CULL,
		0xA2EA8E73565D1EBAULL,
		0x654E56CFE730B4ABULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE2E8C9EFFE5C0418ULL,
			0xAE485A355C49A25CULL,
			0xA2EA8E73565D1EBAULL,
			0x654E56CFE730B4ABULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x614C35E737C015DBULL,
			0xEEAD42F368D8BA62ULL,
			0x0D2AA3FB5AEEBAABULL,
			0x36B25A6F9FEA9328ULL}
		},
		.Z = {.key64 = {
			0x4A5DD42A81445B0AULL,
			0x746673F451C3D38CULL,
			0x5641DEDE16733DECULL,
			0x74BEA0717F403CECULL}
		}
	};
	printf("Test Case 101\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 101 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -101;
	} else {
		printf("Test Case 101 PASSED\n");
	}

	steps = 13;
	X1 = (curve25519_key_t){.key64 = {
		0xF22095F8456137A0ULL,
		0x71602318457BA182ULL,
		0x85C90ED13E3AABE4ULL,
		0x6C8FE4C705E77DB7ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF22095F8456137A0ULL,
			0x71602318457BA182ULL,
			0x85C90ED13E3AABE4ULL,
			0x6C8FE4C705E77DB7ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD8CD9FC40B90B147ULL,
			0xDBBC86CD3D57689DULL,
			0xF8B3AACEED562D72ULL,
			0x54CEE306589E6394ULL}
		},
		.Z = {.key64 = {
			0xD0AA715C3B41123FULL,
			0x2EF2C2BFF6B68DECULL,
			0xFAAA5C94EEB7DAB3ULL,
			0x148F0539A6DC8DE7ULL}
		}
	};
	printf("Test Case 102\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 102 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -102;
	} else {
		printf("Test Case 102 PASSED\n");
	}

	steps = 22;
	X1 = (curve25519_key_t){.key64 = {
		0x53DF0E256B91D1E8ULL,
		0x580D27B6E4E64E16ULL,
		0x50E769A18F8746D4ULL,
		0x54A181E1AC075002ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x53DF0E256B91D1E8ULL,
			0x580D27B6E4E64E16ULL,
			0x50E769A18F8746D4ULL,
			0x54A181E1AC075002ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9E265B879F054C13ULL,
			0x1FB0A2ED7AF50A8DULL,
			0xFC1F7065AD42BB60ULL,
			0x1058B15944F4C9ECULL}
		},
		.Z = {.key64 = {
			0x3CEAD35F6BDC9A75ULL,
			0x3EDE441C0C2BFA0AULL,
			0x40133245A168355EULL,
			0x6BBCDF086F55F58FULL}
		}
	};
	printf("Test Case 103\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 103 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -103;
	} else {
		printf("Test Case 103 PASSED\n");
	}

	steps = 21;
	X1 = (curve25519_key_t){.key64 = {
		0x01590D99D2FD58B8ULL,
		0x2E4682E2A4B2452BULL,
		0x443479220A9476E9ULL,
		0x6453DAB26E417A21ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x01590D99D2FD58B8ULL,
			0x2E4682E2A4B2452BULL,
			0x443479220A9476E9ULL,
			0x6453DAB26E417A21ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDEAA59BCCBA17D31ULL,
			0x6536D656C7FC9A36ULL,
			0xDE3E8605797E3E6AULL,
			0x56C1DA9B383E0482ULL}
		},
		.Z = {.key64 = {
			0x808E81642731A68EULL,
			0x44A2A566EC55E06AULL,
			0x964AD9F3F1D97881ULL,
			0x53E921315184CAA8ULL}
		}
	};
	printf("Test Case 104\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 104 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -104;
	} else {
		printf("Test Case 104 PASSED\n");
	}

	steps = 26;
	X1 = (curve25519_key_t){.key64 = {
		0xD5F4A07BB11973B0ULL,
		0x93A7D6454D9845CDULL,
		0xF6A29B97FBF19B71ULL,
		0x7356E6E1B698AB78ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD5F4A07BB11973B0ULL,
			0x93A7D6454D9845CDULL,
			0xF6A29B97FBF19B71ULL,
			0x7356E6E1B698AB78ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x472DA68AEF8A71FEULL,
			0xDC64218F320D968DULL,
			0x34D81299CF0EA113ULL,
			0x5B9F3E7A77547026ULL}
		},
		.Z = {.key64 = {
			0x7C1B776503856D70ULL,
			0x377C992858218403ULL,
			0x3AF1FB50403C14C2ULL,
			0x24B91BCD584DF97CULL}
		}
	};
	printf("Test Case 105\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 105 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -105;
	} else {
		printf("Test Case 105 PASSED\n");
	}

	steps = 46;
	X1 = (curve25519_key_t){.key64 = {
		0x73DF066B5E1DF648ULL,
		0xCB22F122DBED5FFFULL,
		0xAC29A1692A37C22BULL,
		0x47A6DEED88BC1A2DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x73DF066B5E1DF648ULL,
			0xCB22F122DBED5FFFULL,
			0xAC29A1692A37C22BULL,
			0x47A6DEED88BC1A2DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4F0028229DF48791ULL,
			0xE8F709C62CD91961ULL,
			0x36A5396BABB9ED71ULL,
			0x3AE58E5BF45CA783ULL}
		},
		.Z = {.key64 = {
			0x73EB968146406D0EULL,
			0xD42F9750BFED7D62ULL,
			0x436BC3D4E41396CAULL,
			0x0871F3B0FA916852ULL}
		}
	};
	printf("Test Case 106\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 106 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -106;
	} else {
		printf("Test Case 106 PASSED\n");
	}

	steps = 31;
	X1 = (curve25519_key_t){.key64 = {
		0x61EE2BD5D69BCD60ULL,
		0x67DCF0FE67F19F43ULL,
		0x34F7A0EA918F286EULL,
		0x501EBDB0993537B1ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x61EE2BD5D69BCD60ULL,
			0x67DCF0FE67F19F43ULL,
			0x34F7A0EA918F286EULL,
			0x501EBDB0993537B1ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7BFE8D077861F13CULL,
			0xDC92686B90971B02ULL,
			0x54DCEE346DCA371BULL,
			0x606AB28F1413660BULL}
		},
		.Z = {.key64 = {
			0x9CB53A478DAA900EULL,
			0x185EB3236B085F56ULL,
			0x2BF5F367B3B3E6A6ULL,
			0x3F1A5768E0DC90BAULL}
		}
	};
	printf("Test Case 107\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 107 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -107;
	} else {
		printf("Test Case 107 PASSED\n");
	}

	steps = 62;
	X1 = (curve25519_key_t){.key64 = {
		0xEED289FD1519B1E0ULL,
		0xBDA88A499F97F6FEULL,
		0x34E34800E72334E8ULL,
		0x504C1BDB4A71B99AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEED289FD1519B1E0ULL,
			0xBDA88A499F97F6FEULL,
			0x34E34800E72334E8ULL,
			0x504C1BDB4A71B99AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD56B74AF349DC3FCULL,
			0xD6BBD59EE6D64096ULL,
			0x08CE6A3513D9DBBCULL,
			0x08969F3BB9D1C3F5ULL}
		},
		.Z = {.key64 = {
			0x0CD2DACF36A58414ULL,
			0xF4D9A6A11D39518FULL,
			0xBD930DEC5FD70389ULL,
			0x1A79CB41DFA18E5EULL}
		}
	};
	printf("Test Case 108\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 108 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -108;
	} else {
		printf("Test Case 108 PASSED\n");
	}

	steps = 44;
	X1 = (curve25519_key_t){.key64 = {
		0x47FA3300A175D060ULL,
		0x7F9F9C29EFC0B00AULL,
		0x1BD39FE88CB68D04ULL,
		0x646AF033983C4C0AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x47FA3300A175D060ULL,
			0x7F9F9C29EFC0B00AULL,
			0x1BD39FE88CB68D04ULL,
			0x646AF033983C4C0AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x05D212AC09F3C119ULL,
			0x48872A1EF1E47CBFULL,
			0xCC5DDE8B77AD893EULL,
			0x217DA8EA4FC06E5BULL}
		},
		.Z = {.key64 = {
			0xFC23D8C1E040EC9FULL,
			0x12BABE7B6CECCB05ULL,
			0xB8D8ED7AEF370620ULL,
			0x488BB9305C4BA8CDULL}
		}
	};
	printf("Test Case 109\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 109 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -109;
	} else {
		printf("Test Case 109 PASSED\n");
	}

	steps = 44;
	X1 = (curve25519_key_t){.key64 = {
		0x4F61A5E3DD767FB0ULL,
		0xD25903917A0A3AC2ULL,
		0xCB74285BDED6D2D1ULL,
		0x569E20186C68A948ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4F61A5E3DD767FB0ULL,
			0xD25903917A0A3AC2ULL,
			0xCB74285BDED6D2D1ULL,
			0x569E20186C68A948ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF9913A4D41903FA0ULL,
			0xF99ABCCC942C3B63ULL,
			0x2D8AFB3A85FC7E4DULL,
			0x76A9C55F89D52861ULL}
		},
		.Z = {.key64 = {
			0x0BD59FA9BC5C4578ULL,
			0xDD5E77EEAA77EE48ULL,
			0xE085F5CC2F6512DCULL,
			0x42273A7D155B5D56ULL}
		}
	};
	printf("Test Case 110\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 110 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -110;
	} else {
		printf("Test Case 110 PASSED\n");
	}

	steps = 52;
	X1 = (curve25519_key_t){.key64 = {
		0xD2A85C63B53036F0ULL,
		0x778DC694C1CC854AULL,
		0x071A9332929E4EACULL,
		0x7A8ACE4FE1774521ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD2A85C63B53036F0ULL,
			0x778DC694C1CC854AULL,
			0x071A9332929E4EACULL,
			0x7A8ACE4FE1774521ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8E6B6867463BA5FDULL,
			0xE9635427745A68B4ULL,
			0xB150136C9AD4749EULL,
			0x7F46C51B08270AFDULL}
		},
		.Z = {.key64 = {
			0xB7859FB990C36A0FULL,
			0x5A24B92CED7CECB1ULL,
			0x978AFAB1D342D1EDULL,
			0x24E4D276A9E24E39ULL}
		}
	};
	printf("Test Case 111\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 111 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -111;
	} else {
		printf("Test Case 111 PASSED\n");
	}

	steps = 37;
	X1 = (curve25519_key_t){.key64 = {
		0xB2B805608C2BBEC0ULL,
		0x96B09B075382F86AULL,
		0x0AA328CF690E2DEAULL,
		0x7B1F57707ACBC5B5ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB2B805608C2BBEC0ULL,
			0x96B09B075382F86AULL,
			0x0AA328CF690E2DEAULL,
			0x7B1F57707ACBC5B5ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5B1BADC08848EEEBULL,
			0xBB03FCFF2F21EFB0ULL,
			0xED78FF811D797DD3ULL,
			0x51D728FA7E6A1DACULL}
		},
		.Z = {.key64 = {
			0x2065A991F898EA8DULL,
			0xDA182F534D67C6F1ULL,
			0x0A601DBCA4E89F0DULL,
			0x0A0C568E0D9394FFULL}
		}
	};
	printf("Test Case 112\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 112 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -112;
	} else {
		printf("Test Case 112 PASSED\n");
	}

	steps = 2;
	X1 = (curve25519_key_t){.key64 = {
		0xC612EC46A8CA6FD8ULL,
		0x65EBF3384FED93B6ULL,
		0x0BB35A9DD8BB6CEDULL,
		0x793F483AB6B254AFULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC612EC46A8CA6FD8ULL,
			0x65EBF3384FED93B6ULL,
			0x0BB35A9DD8BB6CEDULL,
			0x793F483AB6B254AFULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFB36A8ECE0920705ULL,
			0xE1791CE3A72C50ADULL,
			0x4685E61959DCECE2ULL,
			0x7A2343B3607C2FFCULL}
		},
		.Z = {.key64 = {
			0xB9BABF4CCCFE7F62ULL,
			0xB00F67E62BADCE18ULL,
			0xB327C193CC8EBF89ULL,
			0x7D36108AD8907924ULL}
		}
	};
	printf("Test Case 113\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 113 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -113;
	} else {
		printf("Test Case 113 PASSED\n");
	}

	steps = 36;
	X1 = (curve25519_key_t){.key64 = {
		0x9640312FE5717190ULL,
		0xDF4B5A357AD58F3EULL,
		0xCDB8B33ADEA223D2ULL,
		0x7333652258635B95ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9640312FE5717190ULL,
			0xDF4B5A357AD58F3EULL,
			0xCDB8B33ADEA223D2ULL,
			0x7333652258635B95ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9535C06722325CABULL,
			0xC6FE4431B3DA0F96ULL,
			0x2805DFB9DB22914BULL,
			0x42077B56C2605C4FULL}
		},
		.Z = {.key64 = {
			0xCAFF360DA70C579EULL,
			0x75BC52599647516BULL,
			0x90400FCD27D91D20ULL,
			0x62C4E5339DB1D48CULL}
		}
	};
	printf("Test Case 114\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 114 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -114;
	} else {
		printf("Test Case 114 PASSED\n");
	}

	steps = 9;
	X1 = (curve25519_key_t){.key64 = {
		0x09D820A1A410E348ULL,
		0xD010D0CBAC7591A0ULL,
		0xB6BE8386D6FFCAD4ULL,
		0x6B3653C068E99216ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x09D820A1A410E348ULL,
			0xD010D0CBAC7591A0ULL,
			0xB6BE8386D6FFCAD4ULL,
			0x6B3653C068E99216ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x705927F9B569250CULL,
			0x8E26AF3B41B854B8ULL,
			0x7A7AE11D1FD938C2ULL,
			0x0198802396EF1DEFULL}
		},
		.Z = {.key64 = {
			0x42E5AD915A272E9DULL,
			0x63F63666D770F041ULL,
			0x19A95CF824D6F834ULL,
			0x61FB0DE372E22555ULL}
		}
	};
	printf("Test Case 115\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 115 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -115;
	} else {
		printf("Test Case 115 PASSED\n");
	}

	steps = 29;
	X1 = (curve25519_key_t){.key64 = {
		0x1BCAE38432987420ULL,
		0xB2E4B0314C62D636ULL,
		0x413AE90324A50849ULL,
		0x44BDAA4584EA4D01ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1BCAE38432987420ULL,
			0xB2E4B0314C62D636ULL,
			0x413AE90324A50849ULL,
			0x44BDAA4584EA4D01ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xED2F2E832488ACBAULL,
			0x13A47B68331B3D9EULL,
			0x132FE0D93845F23FULL,
			0x6F06624178598A4DULL}
		},
		.Z = {.key64 = {
			0xDE96CD9F388EBDEEULL,
			0xAF351A20062CA85CULL,
			0x58D72045DA13FB91ULL,
			0x401BAE7E4F04F422ULL}
		}
	};
	printf("Test Case 116\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 116 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -116;
	} else {
		printf("Test Case 116 PASSED\n");
	}

	steps = 59;
	X1 = (curve25519_key_t){.key64 = {
		0x096095F137ED1AB8ULL,
		0xF562F77B2EB43657ULL,
		0xF9A7ADC84352EB20ULL,
		0x49E824B39F94303BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x096095F137ED1AB8ULL,
			0xF562F77B2EB43657ULL,
			0xF9A7ADC84352EB20ULL,
			0x49E824B39F94303BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3A3892DAE4C81ABBULL,
			0x4294E79073BE4B33ULL,
			0x4716F0A93CC00210ULL,
			0x2E20E3006781E227ULL}
		},
		.Z = {.key64 = {
			0x9C28564DAE8CE6D8ULL,
			0x41337DA7005A8F24ULL,
			0x8A1381C86CD46F6BULL,
			0x76365A3D9033FF2DULL}
		}
	};
	printf("Test Case 117\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 117 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -117;
	} else {
		printf("Test Case 117 PASSED\n");
	}

	steps = 44;
	X1 = (curve25519_key_t){.key64 = {
		0x0596B579A384D938ULL,
		0x5BEB921CD97DA5CDULL,
		0x713942A8589A495FULL,
		0x545CFB065FE2435EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0596B579A384D938ULL,
			0x5BEB921CD97DA5CDULL,
			0x713942A8589A495FULL,
			0x545CFB065FE2435EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x88DB773B0FCE1BFBULL,
			0x244DFE54F2541DCAULL,
			0x0649840C940651B3ULL,
			0x1956DD5C411D7D77ULL}
		},
		.Z = {.key64 = {
			0x3BB10F6152F16DA1ULL,
			0x94EAF1C7D934FAE0ULL,
			0x9B7145AD4024AFFFULL,
			0x202B4B975D4653A0ULL}
		}
	};
	printf("Test Case 118\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 118 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -118;
	} else {
		printf("Test Case 118 PASSED\n");
	}

	steps = 57;
	X1 = (curve25519_key_t){.key64 = {
		0x99769DC8B549F7B8ULL,
		0xFDEE03C50165A6C6ULL,
		0x05A388A3C912669EULL,
		0x4BB08FD14E33CE3BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x99769DC8B549F7B8ULL,
			0xFDEE03C50165A6C6ULL,
			0x05A388A3C912669EULL,
			0x4BB08FD14E33CE3BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE841A5D01A031A58ULL,
			0x49C08914D799BD4CULL,
			0xD2CE3D97FEB3150EULL,
			0x705957C2241BA7A4ULL}
		},
		.Z = {.key64 = {
			0x99EB7C9F27F4D988ULL,
			0xFDA6C41EE82B4356ULL,
			0x3D1506E114524D6CULL,
			0x730667B8C121A3F4ULL}
		}
	};
	printf("Test Case 119\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 119 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -119;
	} else {
		printf("Test Case 119 PASSED\n");
	}

	steps = 24;
	X1 = (curve25519_key_t){.key64 = {
		0xFA0399CBEBDA4468ULL,
		0xF6349167BB2C64B4ULL,
		0x330ECC75A16BB40BULL,
		0x4248B61778BCAD7BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFA0399CBEBDA4468ULL,
			0xF6349167BB2C64B4ULL,
			0x330ECC75A16BB40BULL,
			0x4248B61778BCAD7BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8AC84D82AED454D0ULL,
			0x6B75F21529C55223ULL,
			0xE5C64C02C3BF4E7AULL,
			0x768A3E866F88FEC7ULL}
		},
		.Z = {.key64 = {
			0x6F4272FB0C5D6B11ULL,
			0x911D55D33920982DULL,
			0x370BB2C7AD0EE7B2ULL,
			0x37D9D5E97F86EB99ULL}
		}
	};
	printf("Test Case 120\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 120 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -120;
	} else {
		printf("Test Case 120 PASSED\n");
	}

	steps = 53;
	X1 = (curve25519_key_t){.key64 = {
		0x0655E975C93F7090ULL,
		0x00A72334F4F74B2FULL,
		0x047768D4DACA159DULL,
		0x7A58DAEA0868F383ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0655E975C93F7090ULL,
			0x00A72334F4F74B2FULL,
			0x047768D4DACA159DULL,
			0x7A58DAEA0868F383ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x443C7253611A6F78ULL,
			0x302DB24ADF380B18ULL,
			0x1DCDE4A608F7D6F0ULL,
			0x7AF6C6B87EF9EA89ULL}
		},
		.Z = {.key64 = {
			0x3F3DD9AD06AC38A9ULL,
			0x47555DE4137C6EE0ULL,
			0xCF836BD68462C468ULL,
			0x1745797132FF991DULL}
		}
	};
	printf("Test Case 121\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 121 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -121;
	} else {
		printf("Test Case 121 PASSED\n");
	}

	steps = 40;
	X1 = (curve25519_key_t){.key64 = {
		0xB019BE3FEF0C8BD8ULL,
		0xC92BFB203EB9A86EULL,
		0x000D8969BE49E15EULL,
		0x57A049092D834E2FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB019BE3FEF0C8BD8ULL,
			0xC92BFB203EB9A86EULL,
			0x000D8969BE49E15EULL,
			0x57A049092D834E2FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x77F10F4D3F2604F2ULL,
			0x35B79EE5EA988B12ULL,
			0x414CA02CFF5563ACULL,
			0x3B79FE655C0768F8ULL}
		},
		.Z = {.key64 = {
			0x16251A13E9B24EF2ULL,
			0x9D965D2E971A8195ULL,
			0x6C1B5F9150E12A35ULL,
			0x10BBB2647B71C482ULL}
		}
	};
	printf("Test Case 122\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 122 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -122;
	} else {
		printf("Test Case 122 PASSED\n");
	}

	steps = 20;
	X1 = (curve25519_key_t){.key64 = {
		0x2F2F419F29A90E10ULL,
		0xE5B5685278E10239ULL,
		0x8C41EEA13971B429ULL,
		0x6305AEB8F1580E56ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2F2F419F29A90E10ULL,
			0xE5B5685278E10239ULL,
			0x8C41EEA13971B429ULL,
			0x6305AEB8F1580E56ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x93CC4CDA974F7405ULL,
			0xE2CFE2B94DB8A178ULL,
			0xFB863F5837F11BEEULL,
			0x44E131BB7E7BEEB8ULL}
		},
		.Z = {.key64 = {
			0x486B0F4C51C9B369ULL,
			0x0C88562449B72BA4ULL,
			0x72B6F562420F4D51ULL,
			0x0B2052B2780847E2ULL}
		}
	};
	printf("Test Case 123\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 123 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -123;
	} else {
		printf("Test Case 123 PASSED\n");
	}

	steps = 54;
	X1 = (curve25519_key_t){.key64 = {
		0x9FE82D8848245308ULL,
		0x11FDDD23A39883CCULL,
		0x1893A712F617CFB0ULL,
		0x4F232DDC7D1DA276ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9FE82D8848245308ULL,
			0x11FDDD23A39883CCULL,
			0x1893A712F617CFB0ULL,
			0x4F232DDC7D1DA276ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9E5A03CC6959AF2AULL,
			0x0D92B3DD0DE6A136ULL,
			0xC53384F2AAA9CE6BULL,
			0x14250509E758B224ULL}
		},
		.Z = {.key64 = {
			0xF016D1B4F30FF147ULL,
			0x2EACF167DEF4B550ULL,
			0xE24F0FF3E2FB3E4AULL,
			0x00D77CB591437800ULL}
		}
	};
	printf("Test Case 124\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 124 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -124;
	} else {
		printf("Test Case 124 PASSED\n");
	}

	steps = 43;
	X1 = (curve25519_key_t){.key64 = {
		0xD729B490B3973968ULL,
		0x75F8A9B5D63D860FULL,
		0x5D92B21496741E6FULL,
		0x435D16447B8159BAULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD729B490B3973968ULL,
			0x75F8A9B5D63D860FULL,
			0x5D92B21496741E6FULL,
			0x435D16447B8159BAULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8BB1C34412BABAD3ULL,
			0x4551DA1C6A33FB0EULL,
			0x9B85939BBBED186DULL,
			0x6AFD29D5BA29DD18ULL}
		},
		.Z = {.key64 = {
			0xC0722FDB48139F4BULL,
			0x004DF4F31C1474B7ULL,
			0x89ED5201919FB341ULL,
			0x6603851AF561364AULL}
		}
	};
	printf("Test Case 125\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 125 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -125;
	} else {
		printf("Test Case 125 PASSED\n");
	}

	steps = 18;
	X1 = (curve25519_key_t){.key64 = {
		0x4CD572F414EE9128ULL,
		0x2BF79B9010F8E5D4ULL,
		0x91CFEF10DBAE1C8FULL,
		0x4B3CA8511A0E0E6EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4CD572F414EE9128ULL,
			0x2BF79B9010F8E5D4ULL,
			0x91CFEF10DBAE1C8FULL,
			0x4B3CA8511A0E0E6EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2A095B5153EED01AULL,
			0x15035A7095E46E84ULL,
			0x841F70D7E1189576ULL,
			0x72EEE5D72C92FE8CULL}
		},
		.Z = {.key64 = {
			0x6375AC1316B690B7ULL,
			0x9B2066C67E180F1BULL,
			0x7847A56FF1DBAE5BULL,
			0x19296AA53295238AULL}
		}
	};
	printf("Test Case 126\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 126 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -126;
	} else {
		printf("Test Case 126 PASSED\n");
	}

	steps = 24;
	X1 = (curve25519_key_t){.key64 = {
		0xD45B592B82653D70ULL,
		0x1DA5B38FB7872C75ULL,
		0x7B030002DDCFC292ULL,
		0x53D91EF36B308234ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD45B592B82653D70ULL,
			0x1DA5B38FB7872C75ULL,
			0x7B030002DDCFC292ULL,
			0x53D91EF36B308234ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5A76C434C9BD6B7AULL,
			0x5EB13ACB0FFB6FE0ULL,
			0x3063918D69A9C023ULL,
			0x2660C9798B269CAFULL}
		},
		.Z = {.key64 = {
			0x66B5621454F6B404ULL,
			0x547908342AA4BB3AULL,
			0xFF2BA9B73B908D01ULL,
			0x26E50F3D9EE048DAULL}
		}
	};
	printf("Test Case 127\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 127 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -127;
	} else {
		printf("Test Case 127 PASSED\n");
	}

	steps = 25;
	X1 = (curve25519_key_t){.key64 = {
		0xB3F52299341BF4E0ULL,
		0xFFDF88C3BA15449EULL,
		0xE8341F0F117FB2F7ULL,
		0x67228BC049B55CBCULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB3F52299341BF4E0ULL,
			0xFFDF88C3BA15449EULL,
			0xE8341F0F117FB2F7ULL,
			0x67228BC049B55CBCULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1A82F909DA4ADE12ULL,
			0x4107425825525AAEULL,
			0x33DBE7AE1BDF2F89ULL,
			0x3E2348BC8AE2C04BULL}
		},
		.Z = {.key64 = {
			0x9110E6CE935BE30FULL,
			0x1D91936FBDF356A9ULL,
			0x8E005D33AFD6564FULL,
			0x6E49974D0C9F76D7ULL}
		}
	};
	printf("Test Case 128\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 128 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -128;
	} else {
		printf("Test Case 128 PASSED\n");
	}

	steps = 34;
	X1 = (curve25519_key_t){.key64 = {
		0x317EE136A9AFE8E8ULL,
		0x4E24634A76A10D27ULL,
		0x6918FEC25A0F5613ULL,
		0x4FB07767949102E8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x317EE136A9AFE8E8ULL,
			0x4E24634A76A10D27ULL,
			0x6918FEC25A0F5613ULL,
			0x4FB07767949102E8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x35FCF412D6E60AACULL,
			0x3F7730FEA9C4A9D7ULL,
			0x584A2F725FCEEF16ULL,
			0x760CA7E4FD8D861BULL}
		},
		.Z = {.key64 = {
			0x0716ECB064401FBCULL,
			0x2CB159C33738E022ULL,
			0xCF831F2B00741E00ULL,
			0x7046D3C54BF5DC2AULL}
		}
	};
	printf("Test Case 129\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 129 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -129;
	} else {
		printf("Test Case 129 PASSED\n");
	}

	steps = 22;
	X1 = (curve25519_key_t){.key64 = {
		0xE6C328333B78B0F8ULL,
		0x22CA52E18AD60133ULL,
		0x8B3F4ACFBE2BD656ULL,
		0x5A5F369967D18A88ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE6C328333B78B0F8ULL,
			0x22CA52E18AD60133ULL,
			0x8B3F4ACFBE2BD656ULL,
			0x5A5F369967D18A88ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC84EECBD26CF1908ULL,
			0x179945299816C17DULL,
			0x1EE261CB9C89B9B0ULL,
			0x1F2772B31E48F602ULL}
		},
		.Z = {.key64 = {
			0xB0B2DED95519804DULL,
			0xFC50ED85D5147BA4ULL,
			0x70550B5F0A3C3D7CULL,
			0x047E4A14F07B28CBULL}
		}
	};
	printf("Test Case 130\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 130 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -130;
	} else {
		printf("Test Case 130 PASSED\n");
	}

	steps = 5;
	X1 = (curve25519_key_t){.key64 = {
		0x9368BD59581F57A0ULL,
		0x8A17D813D61FD696ULL,
		0x1173F19B13D003C3ULL,
		0x76FECE8714C49A5CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9368BD59581F57A0ULL,
			0x8A17D813D61FD696ULL,
			0x1173F19B13D003C3ULL,
			0x76FECE8714C49A5CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x36DF83390E0989FDULL,
			0x93D428C098AC8CE1ULL,
			0xAF61CDFBA054B38DULL,
			0x23FC1978E6611BF3ULL}
		},
		.Z = {.key64 = {
			0xA0FD5310B8AF0EBFULL,
			0x78916FC70B4E76C4ULL,
			0xBF2B9F83E1111760ULL,
			0x3ACF58A972C2365EULL}
		}
	};
	printf("Test Case 131\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 131 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -131;
	} else {
		printf("Test Case 131 PASSED\n");
	}

	steps = 16;
	X1 = (curve25519_key_t){.key64 = {
		0x77F70CA7E4245200ULL,
		0x7C9C796322CD1884ULL,
		0x480EEB2F3FC5AB6EULL,
		0x5E4CF0B9F4A25ACCULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x77F70CA7E4245200ULL,
			0x7C9C796322CD1884ULL,
			0x480EEB2F3FC5AB6EULL,
			0x5E4CF0B9F4A25ACCULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6BA4073E9C1EF8E3ULL,
			0x45E073740C00E3A4ULL,
			0xFA636CD83C31B022ULL,
			0x770577A37AB74386ULL}
		},
		.Z = {.key64 = {
			0x01A657E2E63442FCULL,
			0xC15786EF2A3C2384ULL,
			0x27152B33DA79E6CFULL,
			0x4DA5D11DF4B382A7ULL}
		}
	};
	printf("Test Case 132\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 132 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -132;
	} else {
		printf("Test Case 132 PASSED\n");
	}

	steps = 44;
	X1 = (curve25519_key_t){.key64 = {
		0xE004E0E81017D200ULL,
		0x383094852F724E81ULL,
		0x4244D6834C824079ULL,
		0x7063D5ACA80A5A4DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE004E0E81017D200ULL,
			0x383094852F724E81ULL,
			0x4244D6834C824079ULL,
			0x7063D5ACA80A5A4DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB638A791DB5427D8ULL,
			0xD645AFC2B90A23BDULL,
			0xA7479A8306D13F39ULL,
			0x30071B03B492A0B0ULL}
		},
		.Z = {.key64 = {
			0x8697020D4E3E8B91ULL,
			0xB529C3F30128174BULL,
			0x8E102C98C8047E75ULL,
			0x0B29C6D6C38A931DULL}
		}
	};
	printf("Test Case 133\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 133 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -133;
	} else {
		printf("Test Case 133 PASSED\n");
	}

	steps = 42;
	X1 = (curve25519_key_t){.key64 = {
		0x206AB1268D56A960ULL,
		0xB4845FA9C0BE9E24ULL,
		0x21EEAA16D708F950ULL,
		0x66644404A845D95CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x206AB1268D56A960ULL,
			0xB4845FA9C0BE9E24ULL,
			0x21EEAA16D708F950ULL,
			0x66644404A845D95CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE4EAA774935CBA92ULL,
			0x3AC38CDE26F2FF7BULL,
			0x2D710A3388E73C2DULL,
			0x2180E5A869E9AF32ULL}
		},
		.Z = {.key64 = {
			0x075A52AC14398711ULL,
			0x59E2D5097AA59DFAULL,
			0xE2E6C8E18F427CCFULL,
			0x46FAC48DB71D83D7ULL}
		}
	};
	printf("Test Case 134\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 134 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -134;
	} else {
		printf("Test Case 134 PASSED\n");
	}

	steps = 15;
	X1 = (curve25519_key_t){.key64 = {
		0x81451C7953A348A0ULL,
		0x64F064749FF7498DULL,
		0x537C3A6EEAD89920ULL,
		0x74B80679D6C17936ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x81451C7953A348A0ULL,
			0x64F064749FF7498DULL,
			0x537C3A6EEAD89920ULL,
			0x74B80679D6C17936ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2365F086FBB6EDBBULL,
			0xD4D75DD170746704ULL,
			0xF4383691906DA0F6ULL,
			0x39EB35F954855585ULL}
		},
		.Z = {.key64 = {
			0x1286A6FFC9FD235BULL,
			0xA8C72B45B068264BULL,
			0xC5FE485EB01F108AULL,
			0x5886F34E2AAD6A42ULL}
		}
	};
	printf("Test Case 135\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 135 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -135;
	} else {
		printf("Test Case 135 PASSED\n");
	}

	steps = 57;
	X1 = (curve25519_key_t){.key64 = {
		0xCEAAE4E970A99A68ULL,
		0x04E0EDD63342C493ULL,
		0x23E360B653505CD8ULL,
		0x46ACF86E6F404DD5ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCEAAE4E970A99A68ULL,
			0x04E0EDD63342C493ULL,
			0x23E360B653505CD8ULL,
			0x46ACF86E6F404DD5ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD7061679CBF73B04ULL,
			0x381E48EF00F2DFF4ULL,
			0x3887B434AA619BC4ULL,
			0x4F6B95D47A5617EDULL}
		},
		.Z = {.key64 = {
			0x2B73607043DA3ADAULL,
			0x5E4ADAF5D09EC3C1ULL,
			0x60D22EB2F256BD7BULL,
			0x544EE3E26C073254ULL}
		}
	};
	printf("Test Case 136\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 136 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -136;
	} else {
		printf("Test Case 136 PASSED\n");
	}

	steps = 64;
	X1 = (curve25519_key_t){.key64 = {
		0xA7E1DEEE6A99C290ULL,
		0x4F59ADEF3DBB0D46ULL,
		0xA4F44864275CA3CFULL,
		0x6D9D7A0E4AD38986ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA7E1DEEE6A99C290ULL,
			0x4F59ADEF3DBB0D46ULL,
			0xA4F44864275CA3CFULL,
			0x6D9D7A0E4AD38986ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x219943C2FE2FFFF3ULL,
			0x2ED4779D676AFE54ULL,
			0xF42EC1B35F1D4445ULL,
			0x441C980BC66F2657ULL}
		},
		.Z = {.key64 = {
			0xC0573D347767F04EULL,
			0x45AEDD5B64CFD81FULL,
			0x9282779CC85E3BCFULL,
			0x6AFE25C459F13A42ULL}
		}
	};
	printf("Test Case 137\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 137 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -137;
	} else {
		printf("Test Case 137 PASSED\n");
	}

	steps = 11;
	X1 = (curve25519_key_t){.key64 = {
		0x21293CE6CBF3C6E0ULL,
		0x53DFAA7B918018C6ULL,
		0x5F87C1CF4A039432ULL,
		0x4C490180E4EB3935ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x21293CE6CBF3C6E0ULL,
			0x53DFAA7B918018C6ULL,
			0x5F87C1CF4A039432ULL,
			0x4C490180E4EB3935ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB0B7D309CF924063ULL,
			0x17AC1862C1EE85D9ULL,
			0x88B34965DAE1D137ULL,
			0x560C179E7D77EFD0ULL}
		},
		.Z = {.key64 = {
			0x3F7CE854FD781AD5ULL,
			0x10458DCC5BF09AB3ULL,
			0xCD4FEC82C2133CD3ULL,
			0x7E37815DE9D78C9EULL}
		}
	};
	printf("Test Case 138\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 138 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -138;
	} else {
		printf("Test Case 138 PASSED\n");
	}

	steps = 16;
	X1 = (curve25519_key_t){.key64 = {
		0x91FE79C926ECE770ULL,
		0xE926412F79DCCC12ULL,
		0xF1EA3D8949A4D039ULL,
		0x6009D2D197700EA1ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x91FE79C926ECE770ULL,
			0xE926412F79DCCC12ULL,
			0xF1EA3D8949A4D039ULL,
			0x6009D2D197700EA1ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x28CD0A2304CD0A66ULL,
			0x8A17B1D073DC8B57ULL,
			0x9AA8EC620723113FULL,
			0x48F6E08AF1ED51C1ULL}
		},
		.Z = {.key64 = {
			0x8ABB2E05BB6BCF2CULL,
			0x5B59547DFAC5C84DULL,
			0x7E8BB502C5342675ULL,
			0x3737D965B2A6C357ULL}
		}
	};
	printf("Test Case 139\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 139 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -139;
	} else {
		printf("Test Case 139 PASSED\n");
	}

	steps = 13;
	X1 = (curve25519_key_t){.key64 = {
		0x5C61BAB025173FF0ULL,
		0xB1BEB0EDCA8067DCULL,
		0xA0612E544356B1BAULL,
		0x5D97A50C15111B7EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5C61BAB025173FF0ULL,
			0xB1BEB0EDCA8067DCULL,
			0xA0612E544356B1BAULL,
			0x5D97A50C15111B7EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFEE3A4FA0B8E34E1ULL,
			0x6A0D9FDFA273828BULL,
			0x51B9240E96B6E8CDULL,
			0x30A7B0C728386839ULL}
		},
		.Z = {.key64 = {
			0x548028334F2DF921ULL,
			0x4C0E7D0B9FBCBA96ULL,
			0xDDB1CC35B1D73ED5ULL,
			0x4EB0E7678BE3ED84ULL}
		}
	};
	printf("Test Case 140\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 140 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -140;
	} else {
		printf("Test Case 140 PASSED\n");
	}

	steps = 43;
	X1 = (curve25519_key_t){.key64 = {
		0xBAE364659F75B580ULL,
		0x92A180C42AAF9FF7ULL,
		0x694CE8DAB32D0246ULL,
		0x436A58BF26F0C250ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBAE364659F75B580ULL,
			0x92A180C42AAF9FF7ULL,
			0x694CE8DAB32D0246ULL,
			0x436A58BF26F0C250ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4FFA6F9C32E1F7C5ULL,
			0x91E82B9F29DB3C6CULL,
			0xD9C61CF03F76B51AULL,
			0x499DF047F1708BAFULL}
		},
		.Z = {.key64 = {
			0x5FB5EF195C67F100ULL,
			0xA7EBB6FD181D3B2EULL,
			0x9C402950DCC165E6ULL,
			0x6AE7D5D2CC37D29AULL}
		}
	};
	printf("Test Case 141\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 141 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -141;
	} else {
		printf("Test Case 141 PASSED\n");
	}

	steps = 63;
	X1 = (curve25519_key_t){.key64 = {
		0x6D1696E62CEA9F10ULL,
		0x97E97D32EF634E25ULL,
		0xDC3DD79546CB7866ULL,
		0x781AC86906D6C3B5ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6D1696E62CEA9F10ULL,
			0x97E97D32EF634E25ULL,
			0xDC3DD79546CB7866ULL,
			0x781AC86906D6C3B5ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC8BCF68C95729C26ULL,
			0x8B33ACA9EA3E04AFULL,
			0x9C1D934ADBD81698ULL,
			0x2D804D820E0056E9ULL}
		},
		.Z = {.key64 = {
			0x9CB65ADA27A3F949ULL,
			0x32B83EC483DC4C97ULL,
			0x6E9F6F3693B5E663ULL,
			0x2F7EC48B8D4DE9F0ULL}
		}
	};
	printf("Test Case 142\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 142 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -142;
	} else {
		printf("Test Case 142 PASSED\n");
	}

	steps = 19;
	X1 = (curve25519_key_t){.key64 = {
		0x182558242B0E3618ULL,
		0x71DDF27C61CBCBB3ULL,
		0xFF7F1CD0BBE250A3ULL,
		0x77DFB251E423B590ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x182558242B0E3618ULL,
			0x71DDF27C61CBCBB3ULL,
			0xFF7F1CD0BBE250A3ULL,
			0x77DFB251E423B590ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7EB9CF1AABD41268ULL,
			0xF0C5E6C7DF786A13ULL,
			0x9BF9EDEA0F781C29ULL,
			0x34AEAD21BC22463EULL}
		},
		.Z = {.key64 = {
			0xCB4D4173EE836CF3ULL,
			0xFEB6A5DAA12623B1ULL,
			0x957E42F6A43B4493ULL,
			0x122B51D90B109824ULL}
		}
	};
	printf("Test Case 143\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 143 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -143;
	} else {
		printf("Test Case 143 PASSED\n");
	}

	steps = 8;
	X1 = (curve25519_key_t){.key64 = {
		0x079C3D9F21B13560ULL,
		0xCC164372095D68EBULL,
		0xDDA18338727455EFULL,
		0x53EDF7D73FDBC2CAULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x079C3D9F21B13560ULL,
			0xCC164372095D68EBULL,
			0xDDA18338727455EFULL,
			0x53EDF7D73FDBC2CAULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x13CC9889FAC5C24EULL,
			0x0284606C78BFA498ULL,
			0xBEC7D7025DCFCABFULL,
			0x049BA408E0AE4940ULL}
		},
		.Z = {.key64 = {
			0xA6156C015C5FB323ULL,
			0xA0A33DF3D70023E8ULL,
			0xF3D09BE1B5928ABCULL,
			0x2253A0467221C288ULL}
		}
	};
	printf("Test Case 144\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 144 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -144;
	} else {
		printf("Test Case 144 PASSED\n");
	}

	steps = 53;
	X1 = (curve25519_key_t){.key64 = {
		0x25630E703782A540ULL,
		0x41CF651746CCF332ULL,
		0x26A49C809FA78AE7ULL,
		0x76F01489D0E7645BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x25630E703782A540ULL,
			0x41CF651746CCF332ULL,
			0x26A49C809FA78AE7ULL,
			0x76F01489D0E7645BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2ED505A40AF5CD77ULL,
			0xF437BD829A8DEFB5ULL,
			0x0753B59DC6322F19ULL,
			0x35FD7A5ACEFE2948ULL}
		},
		.Z = {.key64 = {
			0xA7DBA94458C733BBULL,
			0xAE11AC50EDA67A98ULL,
			0x656854D1E58354F6ULL,
			0x30AADC0975FDDA04ULL}
		}
	};
	printf("Test Case 145\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 145 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -145;
	} else {
		printf("Test Case 145 PASSED\n");
	}

	steps = 57;
	X1 = (curve25519_key_t){.key64 = {
		0x1324D975967CB6F8ULL,
		0x06EF0BCB2FC36BD1ULL,
		0xAB6E955ECB4E8097ULL,
		0x70ECE09BFFC07A9DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1324D975967CB6F8ULL,
			0x06EF0BCB2FC36BD1ULL,
			0xAB6E955ECB4E8097ULL,
			0x70ECE09BFFC07A9DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3754B66079151DD5ULL,
			0x8C29C7E5B5078B2FULL,
			0x10E725A5E32F6FFAULL,
			0x54993E642E5AF2E9ULL}
		},
		.Z = {.key64 = {
			0x74BEF53115ABD7ADULL,
			0xFE40CAF39D80DE9EULL,
			0x93EBBD7DEAB29D11ULL,
			0x0B2056962BC17601ULL}
		}
	};
	printf("Test Case 146\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 146 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -146;
	} else {
		printf("Test Case 146 PASSED\n");
	}

	steps = 16;
	X1 = (curve25519_key_t){.key64 = {
		0x86BD37A9733E6240ULL,
		0x9D76DEE62FFF84BEULL,
		0x5EAE4CA7649AECA7ULL,
		0x481D5A14E683B796ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x86BD37A9733E6240ULL,
			0x9D76DEE62FFF84BEULL,
			0x5EAE4CA7649AECA7ULL,
			0x481D5A14E683B796ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x37DE9534B3297D0BULL,
			0xA1405F2B3E4BE705ULL,
			0x22C4D8393DCF408EULL,
			0x4860692F9CBE9289ULL}
		},
		.Z = {.key64 = {
			0xBBF39DC7439DE8BBULL,
			0x92165B487FA169BEULL,
			0x605A4531D74B432AULL,
			0x26214D845E3C53C2ULL}
		}
	};
	printf("Test Case 147\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 147 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -147;
	} else {
		printf("Test Case 147 PASSED\n");
	}

	steps = 36;
	X1 = (curve25519_key_t){.key64 = {
		0xEF8FC50E0B317828ULL,
		0x47F0121609AA1548ULL,
		0x07F771075194D056ULL,
		0x64B59F254EC6E477ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEF8FC50E0B317828ULL,
			0x47F0121609AA1548ULL,
			0x07F771075194D056ULL,
			0x64B59F254EC6E477ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x858BF89E923727ADULL,
			0xDF42F455FA3ED12EULL,
			0x48B8FD10EA4BBDA4ULL,
			0x3187D09B0ECB571DULL}
		},
		.Z = {.key64 = {
			0x58BB1A7FC5153E8CULL,
			0x1F5AFC0E70F54063ULL,
			0xF23A3561E2BCB2D4ULL,
			0x7EE249405DF38060ULL}
		}
	};
	printf("Test Case 148\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 148 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -148;
	} else {
		printf("Test Case 148 PASSED\n");
	}

	steps = 6;
	X1 = (curve25519_key_t){.key64 = {
		0x9CDE97D0C5F14CC0ULL,
		0x0E14E3903FEC7FFAULL,
		0x36F353D44BD39171ULL,
		0x5EE6F3319A0CCD8AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9CDE97D0C5F14CC0ULL,
			0x0E14E3903FEC7FFAULL,
			0x36F353D44BD39171ULL,
			0x5EE6F3319A0CCD8AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7D859852F2EDADD3ULL,
			0xCD83B3D276CF29ABULL,
			0x1E8E52781600B9DDULL,
			0x2570010E494525E2ULL}
		},
		.Z = {.key64 = {
			0xF92F2051F05A62C3ULL,
			0x49EE5B3A2C6B9577ULL,
			0x18AE69B30C2A296EULL,
			0x2BDFF5AC5C586B78ULL}
		}
	};
	printf("Test Case 149\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 149 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -149;
	} else {
		printf("Test Case 149 PASSED\n");
	}

	steps = 14;
	X1 = (curve25519_key_t){.key64 = {
		0x71F4D1151FB21208ULL,
		0x3E488FA43C7F89A9ULL,
		0xFFDADE59D5FEFE3AULL,
		0x6E89E5DBCFDFB5DBULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x71F4D1151FB21208ULL,
			0x3E488FA43C7F89A9ULL,
			0xFFDADE59D5FEFE3AULL,
			0x6E89E5DBCFDFB5DBULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3E123B8A27E0368CULL,
			0xCA09827CE0B1C77BULL,
			0x2B6A7A6A602DF3A5ULL,
			0x5F9172523455EDF9ULL}
		},
		.Z = {.key64 = {
			0x4A830FF7503ADD74ULL,
			0xB15D97159FEC4B68ULL,
			0x1596D2D063C11A0AULL,
			0x76AB91C5DF95BE54ULL}
		}
	};
	printf("Test Case 150\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 150 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -150;
	} else {
		printf("Test Case 150 PASSED\n");
	}

	steps = 21;
	X1 = (curve25519_key_t){.key64 = {
		0xE9AC6490A1EFD698ULL,
		0xFE0B05A5CBB823E7ULL,
		0x8DF84E2E37812849ULL,
		0x5C70DE53C3444858ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE9AC6490A1EFD698ULL,
			0xFE0B05A5CBB823E7ULL,
			0x8DF84E2E37812849ULL,
			0x5C70DE53C3444858ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x33DE7C691A64DB06ULL,
			0xE4BD0996870D3F56ULL,
			0xAA2265ECD0BC1277ULL,
			0x63433CD05E76CA44ULL}
		},
		.Z = {.key64 = {
			0x732DEABA4A9C22FDULL,
			0xB20A5DD40CFC1EE2ULL,
			0xCFC72A9E5338CA1CULL,
			0x26791F8EAC72545EULL}
		}
	};
	printf("Test Case 151\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 151 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -151;
	} else {
		printf("Test Case 151 PASSED\n");
	}

	steps = 44;
	X1 = (curve25519_key_t){.key64 = {
		0xAB30E196D7809F98ULL,
		0x36D3CC9CE9DD1F63ULL,
		0x03ACB40CA953EEEFULL,
		0x588F4206139032C8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAB30E196D7809F98ULL,
			0x36D3CC9CE9DD1F63ULL,
			0x03ACB40CA953EEEFULL,
			0x588F4206139032C8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBBC7B43B2E1E98B3ULL,
			0xB419C789EEFD0A79ULL,
			0x03206234DFF90EE5ULL,
			0x08D207C9188BB32DULL}
		},
		.Z = {.key64 = {
			0x92BE308841F3B060ULL,
			0x1ACD767542F3824DULL,
			0x71256EDAB4D180B0ULL,
			0x10C7348850E88155ULL}
		}
	};
	printf("Test Case 152\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 152 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -152;
	} else {
		printf("Test Case 152 PASSED\n");
	}

	steps = 8;
	X1 = (curve25519_key_t){.key64 = {
		0x00A39512F2BAE298ULL,
		0xCFAC90B559967B85ULL,
		0x7EB0BD9E6DE3263FULL,
		0x7B1B980A34A624C6ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x00A39512F2BAE298ULL,
			0xCFAC90B559967B85ULL,
			0x7EB0BD9E6DE3263FULL,
			0x7B1B980A34A624C6ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x12F73A2846A2148EULL,
			0xEACD27220BCEFA90ULL,
			0xCCCAC8AB0B943023ULL,
			0x792F99E276EB4A7DULL}
		},
		.Z = {.key64 = {
			0x321B1B79C595EDDDULL,
			0x70340557C7703A5EULL,
			0xB3FDA676E383EDCEULL,
			0x3DEE0F65F303CE17ULL}
		}
	};
	printf("Test Case 153\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 153 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -153;
	} else {
		printf("Test Case 153 PASSED\n");
	}

	steps = 8;
	X1 = (curve25519_key_t){.key64 = {
		0x8FD208D5896B8950ULL,
		0x6496F6DEDCABF91BULL,
		0x15C417197BD90A5EULL,
		0x73FD36DA7BA9FCBFULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8FD208D5896B8950ULL,
			0x6496F6DEDCABF91BULL,
			0x15C417197BD90A5EULL,
			0x73FD36DA7BA9FCBFULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6FB4B6601362F915ULL,
			0xE0B0AE85C522FB5AULL,
			0xB1705BEAEEDB0BE3ULL,
			0x6F65BCAD41732193ULL}
		},
		.Z = {.key64 = {
			0x579736B3FBFAD9A3ULL,
			0x88F4D107497568FFULL,
			0xE4612BD2ABECD0F9ULL,
			0x763AC41537192E1CULL}
		}
	};
	printf("Test Case 154\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 154 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -154;
	} else {
		printf("Test Case 154 PASSED\n");
	}

	steps = 38;
	X1 = (curve25519_key_t){.key64 = {
		0x57DE9FF291C1C858ULL,
		0x2643142BF48F8BDDULL,
		0x43F6CCC167B4F3C0ULL,
		0x48EFEAB2844AFE24ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x57DE9FF291C1C858ULL,
			0x2643142BF48F8BDDULL,
			0x43F6CCC167B4F3C0ULL,
			0x48EFEAB2844AFE24ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDB321362FFD0FC22ULL,
			0xD1D9A778482BFBCAULL,
			0xD6847C0A79A18980ULL,
			0x66B51ACDE0500A51ULL}
		},
		.Z = {.key64 = {
			0x2EB5D3CB794AC798ULL,
			0xD3E7E7D42468050FULL,
			0x53019656C45CE1F8ULL,
			0x1B1537C5FEF8FAA2ULL}
		}
	};
	printf("Test Case 155\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 155 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -155;
	} else {
		printf("Test Case 155 PASSED\n");
	}

	steps = 64;
	X1 = (curve25519_key_t){.key64 = {
		0xD33CE9FFB08290D8ULL,
		0xE02B8329ACD2C6A5ULL,
		0xF67F0F414E38AF0DULL,
		0x6EE71663257FED6EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD33CE9FFB08290D8ULL,
			0xE02B8329ACD2C6A5ULL,
			0xF67F0F414E38AF0DULL,
			0x6EE71663257FED6EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4E623766876DF2D2ULL,
			0x601D1097B290BE5CULL,
			0x29D1501C29E35B41ULL,
			0x1A4AC76E84B5A460ULL}
		},
		.Z = {.key64 = {
			0xC25E301624D2D9DAULL,
			0xF3D9A5BDF4445E13ULL,
			0xFEF518C5DA5768E4ULL,
			0x09AAF2F7CB46088DULL}
		}
	};
	printf("Test Case 156\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 156 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -156;
	} else {
		printf("Test Case 156 PASSED\n");
	}

	steps = 41;
	X1 = (curve25519_key_t){.key64 = {
		0xC27F9582D8718DB0ULL,
		0xB884F33D404E8A04ULL,
		0xE9DAF12E524CC173ULL,
		0x6B4C7C0FE79AA6B7ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC27F9582D8718DB0ULL,
			0xB884F33D404E8A04ULL,
			0xE9DAF12E524CC173ULL,
			0x6B4C7C0FE79AA6B7ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x98404510ED06767AULL,
			0x9D0D2B20AEE2B165ULL,
			0xA8B3FD1F90F317ADULL,
			0x0F6BF813A92455B0ULL}
		},
		.Z = {.key64 = {
			0x298E379D869AB9C4ULL,
			0x78C10279959783B3ULL,
			0x7B98DAB84EECB251ULL,
			0x4AE58B0AFAE268BBULL}
		}
	};
	printf("Test Case 157\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 157 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -157;
	} else {
		printf("Test Case 157 PASSED\n");
	}

	steps = 40;
	X1 = (curve25519_key_t){.key64 = {
		0x0629D7D43245C608ULL,
		0xFB24A39A0F7B3935ULL,
		0x1C590B967EFFDFA0ULL,
		0x7DEC856A4CB49F96ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0629D7D43245C608ULL,
			0xFB24A39A0F7B3935ULL,
			0x1C590B967EFFDFA0ULL,
			0x7DEC856A4CB49F96ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE473B6E6DEA918B2ULL,
			0xEB33A668776F5159ULL,
			0x772619B8F6A46B63ULL,
			0x4332B0EC5C0C0541ULL}
		},
		.Z = {.key64 = {
			0xD9C359A3DA0E7C37ULL,
			0x10CB0F69967B38C5ULL,
			0x7940C26A597E2FD9ULL,
			0x68A1170ED9B493A3ULL}
		}
	};
	printf("Test Case 158\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 158 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -158;
	} else {
		printf("Test Case 158 PASSED\n");
	}

	steps = 11;
	X1 = (curve25519_key_t){.key64 = {
		0x889C971DD0BB7CC0ULL,
		0xEA2205C0CEBAA5E0ULL,
		0x3CA46B3285A16504ULL,
		0x5D7F1DFB371C82ECULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x889C971DD0BB7CC0ULL,
			0xEA2205C0CEBAA5E0ULL,
			0x3CA46B3285A16504ULL,
			0x5D7F1DFB371C82ECULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9629D839FD520791ULL,
			0x9475527A080B9E2FULL,
			0x5D5779E715CBA86EULL,
			0x482AE5224EAAF870ULL}
		},
		.Z = {.key64 = {
			0x46B78206F4D4397AULL,
			0x0FAB65C0D044CD98ULL,
			0x1F04D7A0A9CB2A5BULL,
			0x0B44AB9848410AEBULL}
		}
	};
	printf("Test Case 159\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 159 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -159;
	} else {
		printf("Test Case 159 PASSED\n");
	}

	steps = 61;
	X1 = (curve25519_key_t){.key64 = {
		0x7ED970D338F54358ULL,
		0xBF0869A34CA09B3CULL,
		0x06056F15CA6ED885ULL,
		0x56B3911637AD84B6ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7ED970D338F54358ULL,
			0xBF0869A34CA09B3CULL,
			0x06056F15CA6ED885ULL,
			0x56B3911637AD84B6ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0A86DB806970A48FULL,
			0x9D75F9BED47C7985ULL,
			0x77C5546BCBAAC106ULL,
			0x286287CB5168DAF8ULL}
		},
		.Z = {.key64 = {
			0x3F179204B2AB4C86ULL,
			0x04E98A7C6E464E20ULL,
			0x0A857AA3E86FED98ULL,
			0x71A300B8174BE773ULL}
		}
	};
	printf("Test Case 160\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 160 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -160;
	} else {
		printf("Test Case 160 PASSED\n");
	}

	steps = 10;
	X1 = (curve25519_key_t){.key64 = {
		0x0653A0BF50D5A530ULL,
		0x4F2E2FB67DE0B50CULL,
		0x34B317704BA354D8ULL,
		0x77BD958123AAF1C1ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0653A0BF50D5A530ULL,
			0x4F2E2FB67DE0B50CULL,
			0x34B317704BA354D8ULL,
			0x77BD958123AAF1C1ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA28AFCD420915CB2ULL,
			0x4A09732FA1029257ULL,
			0x3E1B79E2A320B8DCULL,
			0x5F2E7C3DED913D66ULL}
		},
		.Z = {.key64 = {
			0x5BA0ED34BFBF44C5ULL,
			0x3573EBF29659A48CULL,
			0x293D96285A45D622ULL,
			0x4D13B97EA7B23166ULL}
		}
	};
	printf("Test Case 161\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 161 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -161;
	} else {
		printf("Test Case 161 PASSED\n");
	}

	steps = 59;
	X1 = (curve25519_key_t){.key64 = {
		0x2BF3442EB8C58638ULL,
		0xB7586335EB101B37ULL,
		0x53B0F30A7435C336ULL,
		0x6CF80D75378D72DCULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2BF3442EB8C58638ULL,
			0xB7586335EB101B37ULL,
			0x53B0F30A7435C336ULL,
			0x6CF80D75378D72DCULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2F9919D7399F0DF1ULL,
			0x0E3CED094E70BC88ULL,
			0x13D4F1C23E2B3459ULL,
			0x12DF7C7D0097330AULL}
		},
		.Z = {.key64 = {
			0xECF6A65FB38019B1ULL,
			0x94D95D5AB185096CULL,
			0x08F68E2258A612BDULL,
			0x3AD84CA5E263A2D5ULL}
		}
	};
	printf("Test Case 162\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 162 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -162;
	} else {
		printf("Test Case 162 PASSED\n");
	}

	steps = 49;
	X1 = (curve25519_key_t){.key64 = {
		0x9BF3D1CFCAD11B38ULL,
		0xAC672E8B772A54E2ULL,
		0x72496AD5B16F0E46ULL,
		0x4C3A052132EF415BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9BF3D1CFCAD11B38ULL,
			0xAC672E8B772A54E2ULL,
			0x72496AD5B16F0E46ULL,
			0x4C3A052132EF415BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9A467175CBF9BFD9ULL,
			0x7EF576ADAB722BF0ULL,
			0xAC9E80FB61607D62ULL,
			0x59E86C442FDFB45DULL}
		},
		.Z = {.key64 = {
			0x0BB41070EE673F8DULL,
			0x37D8B8EB14C764EDULL,
			0x3CDD597D70B1CE76ULL,
			0x40EA25D2E75DFC23ULL}
		}
	};
	printf("Test Case 163\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 163 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -163;
	} else {
		printf("Test Case 163 PASSED\n");
	}

	steps = 38;
	X1 = (curve25519_key_t){.key64 = {
		0x1A83AEB5F2C01330ULL,
		0xC8B7AD05BE7339C4ULL,
		0xD84E9364B40C82D8ULL,
		0x503351834E33706CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1A83AEB5F2C01330ULL,
			0xC8B7AD05BE7339C4ULL,
			0xD84E9364B40C82D8ULL,
			0x503351834E33706CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x44A94E1FE236BCC3ULL,
			0x8006419E6080486FULL,
			0x080CD07718CF89D9ULL,
			0x300EB60FBA705AB4ULL}
		},
		.Z = {.key64 = {
			0xAA8063F742EADD14ULL,
			0x6BB139270B1DAF02ULL,
			0xF0E4B154E5902079ULL,
			0x7C685A44F856FE57ULL}
		}
	};
	printf("Test Case 164\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 164 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -164;
	} else {
		printf("Test Case 164 PASSED\n");
	}

	steps = 48;
	X1 = (curve25519_key_t){.key64 = {
		0xBFF95EC17F54E180ULL,
		0xDEBB0C302553652AULL,
		0xA0B45B5059CD2A84ULL,
		0x4A4D3E4386D8352EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBFF95EC17F54E180ULL,
			0xDEBB0C302553652AULL,
			0xA0B45B5059CD2A84ULL,
			0x4A4D3E4386D8352EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2048D766139A2AF4ULL,
			0xC2D60F0366664B25ULL,
			0xD8EEA25C3808BBBCULL,
			0x61A4866C82F7AB99ULL}
		},
		.Z = {.key64 = {
			0x64136278959FF042ULL,
			0x254D0C787ED56CF6ULL,
			0xC3468BC41750B331ULL,
			0x2CF7823723591ED9ULL}
		}
	};
	printf("Test Case 165\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 165 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -165;
	} else {
		printf("Test Case 165 PASSED\n");
	}

	steps = 17;
	X1 = (curve25519_key_t){.key64 = {
		0xDB8D442E492EE2E0ULL,
		0x6E59E8909F0EDB17ULL,
		0xF09AD4B1BB52434DULL,
		0x621F5DBE874D1738ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDB8D442E492EE2E0ULL,
			0x6E59E8909F0EDB17ULL,
			0xF09AD4B1BB52434DULL,
			0x621F5DBE874D1738ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDF39A8A87C25EF1DULL,
			0xF19AEB7C59D8B2D9ULL,
			0x9FD59232D9A6373EULL,
			0x243549F5A08E5764ULL}
		},
		.Z = {.key64 = {
			0x89A545D76583B62EULL,
			0xBF141BB14547DAEDULL,
			0x8A941738D4CE5698ULL,
			0x2E93B5B4C4D14B3CULL}
		}
	};
	printf("Test Case 166\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 166 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -166;
	} else {
		printf("Test Case 166 PASSED\n");
	}

	steps = 27;
	X1 = (curve25519_key_t){.key64 = {
		0x394AD8EE872CB298ULL,
		0x79222A432671862AULL,
		0xA2C06D20C5BF9331ULL,
		0x7B9DD1B1F2301082ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x394AD8EE872CB298ULL,
			0x79222A432671862AULL,
			0xA2C06D20C5BF9331ULL,
			0x7B9DD1B1F2301082ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x92CD03F38DBC71C0ULL,
			0xEE801D042022C17CULL,
			0xB9BBCE0322D08829ULL,
			0x0B6709988F4D0D31ULL}
		},
		.Z = {.key64 = {
			0x643E531B045361CAULL,
			0xDF9EAB4756A615DBULL,
			0xEE89206E3D9CCAD1ULL,
			0x6BCAB124D9933115ULL}
		}
	};
	printf("Test Case 167\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 167 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -167;
	} else {
		printf("Test Case 167 PASSED\n");
	}

	steps = 48;
	X1 = (curve25519_key_t){.key64 = {
		0xBE25281BB1471108ULL,
		0x831AFA8A126FDF14ULL,
		0x5D55C615497115F1ULL,
		0x4220C79B9009D18DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBE25281BB1471108ULL,
			0x831AFA8A126FDF14ULL,
			0x5D55C615497115F1ULL,
			0x4220C79B9009D18DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x640AEEAD12DAED8CULL,
			0x78C45A033B94DD61ULL,
			0x83398C957A81FE7BULL,
			0x7F77236EB73746C5ULL}
		},
		.Z = {.key64 = {
			0x18A51A1D224C5C2BULL,
			0x0F2C4E76FC75919FULL,
			0x2037B97FA44E1496ULL,
			0x683F6CF2A572A552ULL}
		}
	};
	printf("Test Case 168\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 168 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -168;
	} else {
		printf("Test Case 168 PASSED\n");
	}

	steps = 14;
	X1 = (curve25519_key_t){.key64 = {
		0xDCDF270C6BA264F0ULL,
		0xF37C23909BD12DAEULL,
		0x36DEE87EAA28EBCAULL,
		0x7335758C74238CAFULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDCDF270C6BA264F0ULL,
			0xF37C23909BD12DAEULL,
			0x36DEE87EAA28EBCAULL,
			0x7335758C74238CAFULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1E20A8CFCCE5CD11ULL,
			0x09EA6D5AB8FDB5D6ULL,
			0xAAC3F9EA7E1018E5ULL,
			0x20DE6F24D3430A6DULL}
		},
		.Z = {.key64 = {
			0xBD4D398424BB1EF4ULL,
			0x0EF40394D2A1755AULL,
			0xB009B4EA15B29447ULL,
			0x446BF6DCF230E512ULL}
		}
	};
	printf("Test Case 169\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 169 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -169;
	} else {
		printf("Test Case 169 PASSED\n");
	}

	steps = 35;
	X1 = (curve25519_key_t){.key64 = {
		0x0EE760DEBD0EF728ULL,
		0x803743C8F88DC042ULL,
		0x94465AD4A543CEC2ULL,
		0x67BFF7B5B385D52FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0EE760DEBD0EF728ULL,
			0x803743C8F88DC042ULL,
			0x94465AD4A543CEC2ULL,
			0x67BFF7B5B385D52FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFF7CE76D7DDEC5F9ULL,
			0x47FBA7796FB7BE6DULL,
			0x8A988ED1EBA16976ULL,
			0x2AD8011467CF4931ULL}
		},
		.Z = {.key64 = {
			0xDB055F3861764178ULL,
			0x9EC770256A09DDE2ULL,
			0x792D78424DEF0F95ULL,
			0x3D914BD6F7B2489DULL}
		}
	};
	printf("Test Case 170\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 170 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -170;
	} else {
		printf("Test Case 170 PASSED\n");
	}

	steps = 55;
	X1 = (curve25519_key_t){.key64 = {
		0x8B768C1F63260150ULL,
		0x92067548E88E6333ULL,
		0x1E08AAD168152E33ULL,
		0x5F7F7F9FF472F20FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8B768C1F63260150ULL,
			0x92067548E88E6333ULL,
			0x1E08AAD168152E33ULL,
			0x5F7F7F9FF472F20FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1E56D1E9CFDD1315ULL,
			0xAB22C136BEA4589EULL,
			0x8DE32C5919984B2CULL,
			0x4DA53C3E45B715EEULL}
		},
		.Z = {.key64 = {
			0xC3DED115FB3F4057ULL,
			0x190F4941775F7D08ULL,
			0xF28CD68B1EE3A26EULL,
			0x3C9DB0D868D888C9ULL}
		}
	};
	printf("Test Case 171\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 171 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -171;
	} else {
		printf("Test Case 171 PASSED\n");
	}

	steps = 30;
	X1 = (curve25519_key_t){.key64 = {
		0xEFD3948E95D934F8ULL,
		0xE185B64657DAA7AAULL,
		0xB39BDF1797079E1DULL,
		0x7FFC030A8DAF22CCULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEFD3948E95D934F8ULL,
			0xE185B64657DAA7AAULL,
			0xB39BDF1797079E1DULL,
			0x7FFC030A8DAF22CCULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xABCED0A231EB31A9ULL,
			0x34D8D2A290BD6BA6ULL,
			0x15CEC525DA0218F0ULL,
			0x367961C0148BA555ULL}
		},
		.Z = {.key64 = {
			0x716DAA41363DADA9ULL,
			0x1CE6E8F4DC81EFA5ULL,
			0xD0B4DD8CF01A8897ULL,
			0x422ADDDCFF726CBEULL}
		}
	};
	printf("Test Case 172\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 172 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -172;
	} else {
		printf("Test Case 172 PASSED\n");
	}

	steps = 51;
	X1 = (curve25519_key_t){.key64 = {
		0xA0BEDEDD446C9E20ULL,
		0x30528818831E36B5ULL,
		0xE8F2B4CC3BF43AC7ULL,
		0x776BCBC13CB90846ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA0BEDEDD446C9E20ULL,
			0x30528818831E36B5ULL,
			0xE8F2B4CC3BF43AC7ULL,
			0x776BCBC13CB90846ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDEEE47AF4F22ADDFULL,
			0x1E8616D0697B5925ULL,
			0x5FFC8B43B2E1143AULL,
			0x11D68E63499C3741ULL}
		},
		.Z = {.key64 = {
			0x4655AC1D53D241F6ULL,
			0xF324C5E4C1D9781AULL,
			0x505B309B347D2FDAULL,
			0x0C94A788364659B4ULL}
		}
	};
	printf("Test Case 173\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 173 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -173;
	} else {
		printf("Test Case 173 PASSED\n");
	}

	steps = 44;
	X1 = (curve25519_key_t){.key64 = {
		0x1B9648B0DC09AB38ULL,
		0x3F3E18151BD15FC0ULL,
		0x781C36E3F20737CFULL,
		0x62D49E43130140E2ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1B9648B0DC09AB38ULL,
			0x3F3E18151BD15FC0ULL,
			0x781C36E3F20737CFULL,
			0x62D49E43130140E2ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF2759E8A9DB333F5ULL,
			0xF47307CC3E7B0C9CULL,
			0x093DBDCC2C056C5FULL,
			0x5C1C1D6A24AE06EAULL}
		},
		.Z = {.key64 = {
			0xF6BB03C6476138DCULL,
			0xE8E2BF10105045BDULL,
			0x37B849B445C106CBULL,
			0x7B2477A9E25C0E48ULL}
		}
	};
	printf("Test Case 174\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 174 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -174;
	} else {
		printf("Test Case 174 PASSED\n");
	}

	steps = 39;
	X1 = (curve25519_key_t){.key64 = {
		0xB29B4C4F288BDBA0ULL,
		0xD0DDCF29310AFABBULL,
		0xD0ABB317D01F76E4ULL,
		0x6737F53F294CB33BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB29B4C4F288BDBA0ULL,
			0xD0DDCF29310AFABBULL,
			0xD0ABB317D01F76E4ULL,
			0x6737F53F294CB33BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE9B301DFDA1B85A1ULL,
			0x67C0731168D31439ULL,
			0x993A1C0325420A0CULL,
			0x4BACD38916E489B6ULL}
		},
		.Z = {.key64 = {
			0x0493B5FCD96E7D78ULL,
			0xA3AABB58D06379DEULL,
			0x34BF5117F2FE178AULL,
			0x0C003583F29BF68AULL}
		}
	};
	printf("Test Case 175\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 175 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -175;
	} else {
		printf("Test Case 175 PASSED\n");
	}

	steps = 1;
	X1 = (curve25519_key_t){.key64 = {
		0x31B991FECD4B1200ULL,
		0x77D8B55B67AD9E7AULL,
		0x3C6C41B576083BA3ULL,
		0x42FC7EF694EA66F3ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x31B991FECD4B1200ULL,
			0x77D8B55B67AD9E7AULL,
			0x3C6C41B576083BA3ULL,
			0x42FC7EF694EA66F3ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7C77225425588D0EULL,
			0x710B3C6D03BAF646ULL,
			0xE1B5ED733033588BULL,
			0x74E46B3C054FFF00ULL}
		},
		.Z = {.key64 = {
			0xC6E647FB352C4826ULL,
			0xDF62D56D9EB679E8ULL,
			0xF1B106D5D820EE8DULL,
			0x0BF1FBDA53A99BCCULL}
		}
	};
	printf("Test Case 176\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 176 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -176;
	} else {
		printf("Test Case 176 PASSED\n");
	}

	steps = 37;
	X1 = (curve25519_key_t){.key64 = {
		0x18B382EB425C4F08ULL,
		0x9D3F99CF7F2F5241ULL,
		0xB4749C7F38EDFEBCULL,
		0x5012A4474D807656ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x18B382EB425C4F08ULL,
			0x9D3F99CF7F2F5241ULL,
			0xB4749C7F38EDFEBCULL,
			0x5012A4474D807656ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xECEF53AC9933A400ULL,
			0xAF79C3A31E8D7AB1ULL,
			0xBBDBBB78CDBBBAE2ULL,
			0x30EB266BD9CDC564ULL}
		},
		.Z = {.key64 = {
			0x8F9DE1B3E6DE3CEBULL,
			0xCFB747C51927F809ULL,
			0x23F6DFEE93DFB8F1ULL,
			0x71A09367049DD7ECULL}
		}
	};
	printf("Test Case 177\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 177 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -177;
	} else {
		printf("Test Case 177 PASSED\n");
	}

	steps = 21;
	X1 = (curve25519_key_t){.key64 = {
		0x880F8F998DB70220ULL,
		0x63497906573DB65EULL,
		0x41D1B2108280CE65ULL,
		0x603BE6EB088D22A4ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x880F8F998DB70220ULL,
			0x63497906573DB65EULL,
			0x41D1B2108280CE65ULL,
			0x603BE6EB088D22A4ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7B2542BE766FFABEULL,
			0x0885A63ACCF7B409ULL,
			0x15FC42D2706B628EULL,
			0x29273EEDD82D1A51ULL}
		},
		.Z = {.key64 = {
			0xB6377AB6DF08B62AULL,
			0xA242E3915E3474D5ULL,
			0xF3706B01BEA5AF72ULL,
			0x44787BB614AA3A42ULL}
		}
	};
	printf("Test Case 178\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 178 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -178;
	} else {
		printf("Test Case 178 PASSED\n");
	}

	steps = 7;
	X1 = (curve25519_key_t){.key64 = {
		0xB0F0327FA6180618ULL,
		0x3A62F7A555B8E6EAULL,
		0x2F4D02F0962B57BAULL,
		0x79DCEB166E556FAFULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB0F0327FA6180618ULL,
			0x3A62F7A555B8E6EAULL,
			0x2F4D02F0962B57BAULL,
			0x79DCEB166E556FAFULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC3BDF5C013203F97ULL,
			0x49E8452FBD2D10F0ULL,
			0x4B8FDD22511B02D6ULL,
			0x2E863CA06EAC4165ULL}
		},
		.Z = {.key64 = {
			0x42EB7703338B9A6DULL,
			0x72914EDE0BDFDE68ULL,
			0x1CA5CF6E9E32CB17ULL,
			0x2CC8A9B1AC34CC95ULL}
		}
	};
	printf("Test Case 179\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 179 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -179;
	} else {
		printf("Test Case 179 PASSED\n");
	}

	steps = 16;
	X1 = (curve25519_key_t){.key64 = {
		0xA45E2EDEC9FE9B58ULL,
		0x4D846D4B03FDB390ULL,
		0x29256E10EE866524ULL,
		0x77B7D79E3DBCA31FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA45E2EDEC9FE9B58ULL,
			0x4D846D4B03FDB390ULL,
			0x29256E10EE866524ULL,
			0x77B7D79E3DBCA31FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE683A21E4EADE50DULL,
			0xA98501F9DD908056ULL,
			0xFF921429D8926B60ULL,
			0x4D6135C219F6AFB4ULL}
		},
		.Z = {.key64 = {
			0x9E9D1E99BCCFE5FAULL,
			0x6443586D476DB2EEULL,
			0xFD7954084A17EE06ULL,
			0x0FB1A9ECC8E3C2FCULL}
		}
	};
	printf("Test Case 180\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 180 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -180;
	} else {
		printf("Test Case 180 PASSED\n");
	}

	steps = 58;
	X1 = (curve25519_key_t){.key64 = {
		0x3B4B149A0C925C58ULL,
		0x5FA08EEE82F4897FULL,
		0x0C2B42065A3776FBULL,
		0x5A423A1EAA8EA467ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3B4B149A0C925C58ULL,
			0x5FA08EEE82F4897FULL,
			0x0C2B42065A3776FBULL,
			0x5A423A1EAA8EA467ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5CFBAD33E5FA8210ULL,
			0x182ECD2A638A4BC3ULL,
			0xD3579AA26C415C47ULL,
			0x7260C76211052810ULL}
		},
		.Z = {.key64 = {
			0x9550EDCD8B17642DULL,
			0xDF5A718807C0D026ULL,
			0x98BC4A6FA4D87F92ULL,
			0x4E73EF4D8A796F87ULL}
		}
	};
	printf("Test Case 181\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 181 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -181;
	} else {
		printf("Test Case 181 PASSED\n");
	}

	steps = 42;
	X1 = (curve25519_key_t){.key64 = {
		0xDF8B32FB63265438ULL,
		0xAB448A32E38A1025ULL,
		0xBDD971E82AC6F489ULL,
		0x77997C53E226BC62ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDF8B32FB63265438ULL,
			0xAB448A32E38A1025ULL,
			0xBDD971E82AC6F489ULL,
			0x77997C53E226BC62ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x46AE4227F3C3E377ULL,
			0xFF81E66740C2A86CULL,
			0xCBB14031943EE1E8ULL,
			0x7962E1C5E34A3286ULL}
		},
		.Z = {.key64 = {
			0x37AD5C395B715684ULL,
			0xC72C4E53F1208BE9ULL,
			0xA6EEE66C69998688ULL,
			0x74EE8261E14C37ABULL}
		}
	};
	printf("Test Case 182\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 182 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -182;
	} else {
		printf("Test Case 182 PASSED\n");
	}

	steps = 60;
	X1 = (curve25519_key_t){.key64 = {
		0x2D86461ACDC8AB60ULL,
		0x2E711E99262973D9ULL,
		0x86167738525FA7DAULL,
		0x640F4B08DFFA5049ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2D86461ACDC8AB60ULL,
			0x2E711E99262973D9ULL,
			0x86167738525FA7DAULL,
			0x640F4B08DFFA5049ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDA8404F927E6F8EAULL,
			0x2CC5941AC3B9E7BCULL,
			0xB35DFA3D63221676ULL,
			0x34DEAE813746CA2AULL}
		},
		.Z = {.key64 = {
			0x5E44EB3296D78C1DULL,
			0xC7CA2706C61A7F7EULL,
			0x93F32549A8AF5DC2ULL,
			0x38E1C1015A379323ULL}
		}
	};
	printf("Test Case 183\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 183 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -183;
	} else {
		printf("Test Case 183 PASSED\n");
	}

	steps = 4;
	X1 = (curve25519_key_t){.key64 = {
		0xA83AA492AA591320ULL,
		0x5B6A8EC22BB3A91CULL,
		0xCDE07BF7FC280771ULL,
		0x63CEAFB48CE86EF6ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA83AA492AA591320ULL,
			0x5B6A8EC22BB3A91CULL,
			0xCDE07BF7FC280771ULL,
			0x63CEAFB48CE86EF6ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC785020E3CBDDCB2ULL,
			0x710F93C236D58BEFULL,
			0x3BB54AFC9EF5A2D7ULL,
			0x557B2CF5680EDF0FULL}
		},
		.Z = {.key64 = {
			0xBAE84F79DDC2AC15ULL,
			0x041A0FD0FC78347CULL,
			0x454A8B15AAA86D7BULL,
			0x6E6D4413D08CB2FFULL}
		}
	};
	printf("Test Case 184\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 184 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -184;
	} else {
		printf("Test Case 184 PASSED\n");
	}

	steps = 34;
	X1 = (curve25519_key_t){.key64 = {
		0x03A487D6C9F0A638ULL,
		0x2C2B3DA9EBE213A9ULL,
		0x4080BED3E083779CULL,
		0x65F3DE599B24744CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x03A487D6C9F0A638ULL,
			0x2C2B3DA9EBE213A9ULL,
			0x4080BED3E083779CULL,
			0x65F3DE599B24744CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x162368B8E85A89BCULL,
			0x3ECD6968A5B9BDA3ULL,
			0x2AF35F29BA83B4DDULL,
			0x2B068639461EF997ULL}
		},
		.Z = {.key64 = {
			0x492D50B9861A90CBULL,
			0x13478CC9318D3639ULL,
			0x0B00091FD3D2AF0DULL,
			0x23E322ABCC960A1FULL}
		}
	};
	printf("Test Case 185\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 185 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -185;
	} else {
		printf("Test Case 185 PASSED\n");
	}

	steps = 15;
	X1 = (curve25519_key_t){.key64 = {
		0x6B54F4815F51B8D8ULL,
		0xB2A9F37CBB606AAAULL,
		0x740B227715533ECEULL,
		0x59B26625667A2FA6ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6B54F4815F51B8D8ULL,
			0xB2A9F37CBB606AAAULL,
			0x740B227715533ECEULL,
			0x59B26625667A2FA6ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x054593C53389F90AULL,
			0x006222389A859BADULL,
			0x5355C380DC56040FULL,
			0x5C6AE98943E2DA61ULL}
		},
		.Z = {.key64 = {
			0x143C3447A8246241ULL,
			0xCAD15C531C5B6710ULL,
			0x90C56F902730E4A5ULL,
			0x418701BB309514F7ULL}
		}
	};
	printf("Test Case 186\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 186 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -186;
	} else {
		printf("Test Case 186 PASSED\n");
	}

	steps = 47;
	X1 = (curve25519_key_t){.key64 = {
		0x94A817EA9286BA98ULL,
		0xF8B21A8F4EF60412ULL,
		0x9AA5A086225E0820ULL,
		0x6525F1FC79D0BA2DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x94A817EA9286BA98ULL,
			0xF8B21A8F4EF60412ULL,
			0x9AA5A086225E0820ULL,
			0x6525F1FC79D0BA2DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6EEE8555E95CAD62ULL,
			0x6C8980CC607F9126ULL,
			0x81CE8D56179836D3ULL,
			0x5B27988475D7EA17ULL}
		},
		.Z = {.key64 = {
			0x529CE2F8B67ABB2DULL,
			0x4D9AF2FFE67E8FCDULL,
			0x729221C464DC2E64ULL,
			0x13A75258255F33E2ULL}
		}
	};
	printf("Test Case 187\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 187 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -187;
	} else {
		printf("Test Case 187 PASSED\n");
	}

	steps = 20;
	X1 = (curve25519_key_t){.key64 = {
		0xFD65B94B7531EDA0ULL,
		0xA5274E34FB0E007DULL,
		0xCE6445EE7CFEABC2ULL,
		0x638831DB9B135C14ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFD65B94B7531EDA0ULL,
			0xA5274E34FB0E007DULL,
			0xCE6445EE7CFEABC2ULL,
			0x638831DB9B135C14ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEA649F64405C47F4ULL,
			0x754EA65F4A9B3AABULL,
			0x8359ECDE7788D68BULL,
			0x198C51ABC0E021D5ULL}
		},
		.Z = {.key64 = {
			0x92DF3636FA047D45ULL,
			0x4E0C89B51CB0C76DULL,
			0x193554D7C802DED2ULL,
			0x4C5C284458160BDBULL}
		}
	};
	printf("Test Case 188\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 188 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -188;
	} else {
		printf("Test Case 188 PASSED\n");
	}

	steps = 30;
	X1 = (curve25519_key_t){.key64 = {
		0x884E89A5A0646940ULL,
		0x44622A61C59C858BULL,
		0xC45F270BA39B35B0ULL,
		0x70885AA6C4D82666ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x884E89A5A0646940ULL,
			0x44622A61C59C858BULL,
			0xC45F270BA39B35B0ULL,
			0x70885AA6C4D82666ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF7BE8E7D944B7049ULL,
			0xBB8DCC006366772FULL,
			0x75DB87FDCCBADA61ULL,
			0x134C23A9B6FE9526ULL}
		},
		.Z = {.key64 = {
			0x772B2FA52F0D1F93ULL,
			0xED8A62DB83D50B16ULL,
			0x7752A87C42EF317AULL,
			0x5240EF92E7A67725ULL}
		}
	};
	printf("Test Case 189\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 189 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -189;
	} else {
		printf("Test Case 189 PASSED\n");
	}

	steps = 28;
	X1 = (curve25519_key_t){.key64 = {
		0xDC56D71395C586A0ULL,
		0x9F51AC3EC591C92BULL,
		0x4CA03FB36A39C8ACULL,
		0x7CD48019AF5279A4ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDC56D71395C586A0ULL,
			0x9F51AC3EC591C92BULL,
			0x4CA03FB36A39C8ACULL,
			0x7CD48019AF5279A4ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x397614697FE4D81EULL,
			0xADD69754278563EDULL,
			0xB84F66B667898922ULL,
			0x2CBD7E2A1B5D249EULL}
		},
		.Z = {.key64 = {
			0x27761970FB8DB159ULL,
			0x2C0A35D842049CE6ULL,
			0x76FF9766E10C95D4ULL,
			0x2CAA8912F92F144AULL}
		}
	};
	printf("Test Case 190\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 190 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -190;
	} else {
		printf("Test Case 190 PASSED\n");
	}

	steps = 32;
	X1 = (curve25519_key_t){.key64 = {
		0x54483DC946F855F8ULL,
		0x190A678E1A408EDDULL,
		0x28FE1CBA2D64931DULL,
		0x73CE0188D343B76EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x54483DC946F855F8ULL,
			0x190A678E1A408EDDULL,
			0x28FE1CBA2D64931DULL,
			0x73CE0188D343B76EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x915FC8CA7CAD9EDDULL,
			0x59F7CF2DB1AC0DD6ULL,
			0x723567B9F5BEF0D9ULL,
			0x2CE95C224CB28861ULL}
		},
		.Z = {.key64 = {
			0x619E51F419AC5BFBULL,
			0xC8ED823D4D618F38ULL,
			0x8E932839854F9847ULL,
			0x375A3DBA13664102ULL}
		}
	};
	printf("Test Case 191\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 191 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -191;
	} else {
		printf("Test Case 191 PASSED\n");
	}

	steps = 61;
	X1 = (curve25519_key_t){.key64 = {
		0x6A3A5DC561485618ULL,
		0x7C8BB400B338FEA8ULL,
		0xB9BA3651CB9A82ADULL,
		0x754186E44BF8BCE9ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6A3A5DC561485618ULL,
			0x7C8BB400B338FEA8ULL,
			0xB9BA3651CB9A82ADULL,
			0x754186E44BF8BCE9ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCE47B75DD8145C32ULL,
			0x2739615060AB5BF8ULL,
			0x7B637F5EBCE660F3ULL,
			0x292E18371A64C48BULL}
		},
		.Z = {.key64 = {
			0xB8E0A631B6CE83DDULL,
			0xBA87FD7412BBC570ULL,
			0xB43FCC6FC3795532ULL,
			0x57A2CEFBB86A7A14ULL}
		}
	};
	printf("Test Case 192\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 192 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -192;
	} else {
		printf("Test Case 192 PASSED\n");
	}

	steps = 8;
	X1 = (curve25519_key_t){.key64 = {
		0x1C9CBE01E713A258ULL,
		0xDBF49452BCBD0DBFULL,
		0x708D4A2C32B717A4ULL,
		0x7A3A0FD0E485874AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1C9CBE01E713A258ULL,
			0xDBF49452BCBD0DBFULL,
			0x708D4A2C32B717A4ULL,
			0x7A3A0FD0E485874AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x997F833A34641636ULL,
			0x66D34AD88F14A608ULL,
			0x1EAA35E383E23C23ULL,
			0x07F9CA5A48B0C50FULL}
		},
		.Z = {.key64 = {
			0x56B255114A8276CCULL,
			0xED5A45E303798C67ULL,
			0x8AE084EB28640FF1ULL,
			0x161B659E79A4AD4AULL}
		}
	};
	printf("Test Case 193\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 193 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -193;
	} else {
		printf("Test Case 193 PASSED\n");
	}

	steps = 34;
	X1 = (curve25519_key_t){.key64 = {
		0x0515DBC96FC98800ULL,
		0x23D96F02B8EC57C0ULL,
		0x27D2B83142B05DD1ULL,
		0x598393991C56E92FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0515DBC96FC98800ULL,
			0x23D96F02B8EC57C0ULL,
			0x27D2B83142B05DD1ULL,
			0x598393991C56E92FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x78DBAC939A3EA164ULL,
			0x5FBFBB470C6CB6DCULL,
			0x4248B410806248CBULL,
			0x4D6B02189E486C64ULL}
		},
		.Z = {.key64 = {
			0xD0CCC003DB8F2097ULL,
			0x2CDD878AD116C9DCULL,
			0x75A6FC07733AD835ULL,
			0x541AE8B8C7F8B552ULL}
		}
	};
	printf("Test Case 194\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 194 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -194;
	} else {
		printf("Test Case 194 PASSED\n");
	}

	steps = 16;
	X1 = (curve25519_key_t){.key64 = {
		0x8DBC13AE34FAFC68ULL,
		0xD11F053FAE1B7786ULL,
		0x301C5E8B3633A859ULL,
		0x4F71B764F1936A2DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8DBC13AE34FAFC68ULL,
			0xD11F053FAE1B7786ULL,
			0x301C5E8B3633A859ULL,
			0x4F71B764F1936A2DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x12F68FEBD7AEA2DCULL,
			0x221CEE31256F34A4ULL,
			0xD03FA131C36A5516ULL,
			0x1FD0789FBD9270B6ULL}
		},
		.Z = {.key64 = {
			0x7C16D9ECD505116AULL,
			0xB8F93D9C0B32FA32ULL,
			0xE33A4B2B0486A626ULL,
			0x360AB8778DAFFD4CULL}
		}
	};
	printf("Test Case 195\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 195 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -195;
	} else {
		printf("Test Case 195 PASSED\n");
	}

	steps = 38;
	X1 = (curve25519_key_t){.key64 = {
		0x1BE52CA59CA51AD0ULL,
		0xE30321D65E3F456EULL,
		0x83E23B55DF54FBEDULL,
		0x786C460DB2DFEF0DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1BE52CA59CA51AD0ULL,
			0xE30321D65E3F456EULL,
			0x83E23B55DF54FBEDULL,
			0x786C460DB2DFEF0DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x78D43ACD722D66E1ULL,
			0x10AAA8A2C0C64365ULL,
			0xD855E847BEAA08ACULL,
			0x54EC9B2F3D92DB54ULL}
		},
		.Z = {.key64 = {
			0xF00C8929D35E7853ULL,
			0xD3C13ECB202FD471ULL,
			0x6638D96AECBB30CAULL,
			0x6380604999C77603ULL}
		}
	};
	printf("Test Case 196\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 196 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -196;
	} else {
		printf("Test Case 196 PASSED\n");
	}

	steps = 43;
	X1 = (curve25519_key_t){.key64 = {
		0x73EDE41E06B08AB8ULL,
		0x343B349EB49BA085ULL,
		0x15FC506CB124B970ULL,
		0x4E178387F6495EAAULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x73EDE41E06B08AB8ULL,
			0x343B349EB49BA085ULL,
			0x15FC506CB124B970ULL,
			0x4E178387F6495EAAULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD53027F8B94AD5E2ULL,
			0x472307482B00F2C3ULL,
			0x381A49B0D58CFFCBULL,
			0x42B4886222CAF7BFULL}
		},
		.Z = {.key64 = {
			0xFE288108C53C5A4CULL,
			0x7DFBF3E143C41295ULL,
			0x2C74BF73E42BEF52ULL,
			0x73902441A7D4737FULL}
		}
	};
	printf("Test Case 197\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 197 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -197;
	} else {
		printf("Test Case 197 PASSED\n");
	}

	steps = 43;
	X1 = (curve25519_key_t){.key64 = {
		0xA55E92B8301E8B68ULL,
		0xBA6F735A6B3BEC33ULL,
		0xC92644E104B79497ULL,
		0x69D0E196B333B0E9ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA55E92B8301E8B68ULL,
			0xBA6F735A6B3BEC33ULL,
			0xC92644E104B79497ULL,
			0x69D0E196B333B0E9ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD21A5C0C08500152ULL,
			0x65169168645AE48AULL,
			0x9FE8AB31EDB5BF0CULL,
			0x0435EB6181A4894EULL}
		},
		.Z = {.key64 = {
			0xD85C27488A4C9523ULL,
			0xAA676B0E7C457887ULL,
			0x6D061BB4C627939FULL,
			0x6A7CF7514D99DDABULL}
		}
	};
	printf("Test Case 198\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 198 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -198;
	} else {
		printf("Test Case 198 PASSED\n");
	}

	steps = 61;
	X1 = (curve25519_key_t){.key64 = {
		0x7942A5E999B33FD0ULL,
		0xDD041E4402874918ULL,
		0x51DF7FDF98AC9AB4ULL,
		0x735558DE45C0F71EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7942A5E999B33FD0ULL,
			0xDD041E4402874918ULL,
			0x51DF7FDF98AC9AB4ULL,
			0x735558DE45C0F71EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA2A1B3E4CECE354CULL,
			0x6D600463FF32B899ULL,
			0xB83CC8312F28F69AULL,
			0x0211885C67693B98ULL}
		},
		.Z = {.key64 = {
			0xD2AD8B9CE8A2320AULL,
			0x70A93C8BB18AACD3ULL,
			0x785C73C0DE3BA2D5ULL,
			0x62180D3A731608D1ULL}
		}
	};
	printf("Test Case 199\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 199 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -199;
	} else {
		printf("Test Case 199 PASSED\n");
	}

	steps = 64;
	X1 = (curve25519_key_t){.key64 = {
		0x026A370E7E3D3940ULL,
		0x7AFCFED1B9E0F8EAULL,
		0x029D21FD79FE3FA5ULL,
		0x6622807074EB4816ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x026A370E7E3D3940ULL,
			0x7AFCFED1B9E0F8EAULL,
			0x029D21FD79FE3FA5ULL,
			0x6622807074EB4816ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x177E0D24EA09DE35ULL,
			0xB77BF0D5C0E0F5DBULL,
			0x9697CEB1B771F439ULL,
			0x6717D91DABCDF04FULL}
		},
		.Z = {.key64 = {
			0x82828AA0355C96F4ULL,
			0x4C54AF6EA814BDA1ULL,
			0x8738FB86A27F13AFULL,
			0x026F20260F07720BULL}
		}
	};
	printf("Test Case 200\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 200 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -200;
	} else {
		printf("Test Case 200 PASSED\n");
	}

	steps = 24;
	X1 = (curve25519_key_t){.key64 = {
		0x1C53A80B5E53E2B8ULL,
		0xC74DA6D953541E93ULL,
		0x46E5D1AA6C0F5A05ULL,
		0x5E797AF9EAD069B8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1C53A80B5E53E2B8ULL,
			0xC74DA6D953541E93ULL,
			0x46E5D1AA6C0F5A05ULL,
			0x5E797AF9EAD069B8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x06078D7CDA20AD51ULL,
			0x7B0217432E9FD48DULL,
			0x72289A2390584373ULL,
			0x741BD0C1570FD248ULL}
		},
		.Z = {.key64 = {
			0x673A5F406F8BE506ULL,
			0xEEC5BBBE16A3BFECULL,
			0x4CB81DB9078018E8ULL,
			0x1EF28CE62316FA14ULL}
		}
	};
	printf("Test Case 201\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 201 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -201;
	} else {
		printf("Test Case 201 PASSED\n");
	}

	steps = 34;
	X1 = (curve25519_key_t){.key64 = {
		0x4EE74906FA4F6CE0ULL,
		0xB677A5CC18F3BB8DULL,
		0x84BD6968E27F9B69ULL,
		0x43C390A3EDC53C69ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4EE74906FA4F6CE0ULL,
			0xB677A5CC18F3BB8DULL,
			0x84BD6968E27F9B69ULL,
			0x43C390A3EDC53C69ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4CB922C689897043ULL,
			0x56F5C29DE26FC4B4ULL,
			0x5D4B2B3A86F0AAA5ULL,
			0x2CCA75A40FC1AB0AULL}
		},
		.Z = {.key64 = {
			0x717D048A2277FE47ULL,
			0x54D1B12A7B94D521ULL,
			0x2490631511BC6CB2ULL,
			0x3CC8E1E67D2A80E8ULL}
		}
	};
	printf("Test Case 202\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 202 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -202;
	} else {
		printf("Test Case 202 PASSED\n");
	}

	steps = 49;
	X1 = (curve25519_key_t){.key64 = {
		0x37DE6557E9C37F98ULL,
		0xA85B431E17A3DB73ULL,
		0xBE2A16CFD4AFAF33ULL,
		0x75C95D16D8D73E64ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x37DE6557E9C37F98ULL,
			0xA85B431E17A3DB73ULL,
			0xBE2A16CFD4AFAF33ULL,
			0x75C95D16D8D73E64ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5E9FFB65283A5EBDULL,
			0x894A92A81E0ABE85ULL,
			0x3E71864DEE9F0A3BULL,
			0x4640134A631F0116ULL}
		},
		.Z = {.key64 = {
			0xD1D408F4F8EFBA43ULL,
			0x004E038D827C5D49ULL,
			0x1E8984E74645FDC8ULL,
			0x6F69FAD5A76571BCULL}
		}
	};
	printf("Test Case 203\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 203 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -203;
	} else {
		printf("Test Case 203 PASSED\n");
	}

	steps = 28;
	X1 = (curve25519_key_t){.key64 = {
		0xCF349C7942DBC578ULL,
		0x70B8001D91A2D4B2ULL,
		0x5118743BAD6A9D5FULL,
		0x77CF60EF0909537FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCF349C7942DBC578ULL,
			0x70B8001D91A2D4B2ULL,
			0x5118743BAD6A9D5FULL,
			0x77CF60EF0909537FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1E4C75C04D92EBB7ULL,
			0x75254041F5EF54AEULL,
			0xF423B79B4048C216ULL,
			0x005E090F9F4F9A82ULL}
		},
		.Z = {.key64 = {
			0x9E6F525EAC8E5E89ULL,
			0x2CA03289C1FD32F3ULL,
			0xBE9390B1D34841A9ULL,
			0x7101231921FA7586ULL}
		}
	};
	printf("Test Case 204\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 204 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -204;
	} else {
		printf("Test Case 204 PASSED\n");
	}

	steps = 10;
	X1 = (curve25519_key_t){.key64 = {
		0xA0D1264D54504088ULL,
		0x870B9ADEA57FC288ULL,
		0x9F6ADF65AF55E416ULL,
		0x577344DEA8F8B099ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA0D1264D54504088ULL,
			0x870B9ADEA57FC288ULL,
			0x9F6ADF65AF55E416ULL,
			0x577344DEA8F8B099ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0B6D28ACC05D8AC6ULL,
			0x858152BED6310780ULL,
			0xC0ED75B5C2BDDBFBULL,
			0x3C035D74EC3CD14FULL}
		},
		.Z = {.key64 = {
			0x67DA9D7C0DF47C12ULL,
			0x4AAFE403FAD885FBULL,
			0xE2C486F4786978AAULL,
			0x1EDF62C8919CA5E0ULL}
		}
	};
	printf("Test Case 205\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 205 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -205;
	} else {
		printf("Test Case 205 PASSED\n");
	}

	steps = 11;
	X1 = (curve25519_key_t){.key64 = {
		0xCF3301BB33D77498ULL,
		0xD039AB1FEB3DBCA8ULL,
		0xA947500D9616C40DULL,
		0x6E39FAF3EA2504E8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCF3301BB33D77498ULL,
			0xD039AB1FEB3DBCA8ULL,
			0xA947500D9616C40DULL,
			0x6E39FAF3EA2504E8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3957909B57F9D671ULL,
			0x84A61D1B2363A64AULL,
			0xA10EC76756908260ULL,
			0x14B6435B5782B171ULL}
		},
		.Z = {.key64 = {
			0xF1C096DA8A82D146ULL,
			0xBFE5AEE05E4CABBAULL,
			0x37DCC4ED88F16C25ULL,
			0x5718878225FE31D2ULL}
		}
	};
	printf("Test Case 206\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 206 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -206;
	} else {
		printf("Test Case 206 PASSED\n");
	}

	steps = 24;
	X1 = (curve25519_key_t){.key64 = {
		0xE7082268EA085EB8ULL,
		0x756B076814A3B22DULL,
		0x4B50E8E13ADFDD10ULL,
		0x5521045A1101502AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE7082268EA085EB8ULL,
			0x756B076814A3B22DULL,
			0x4B50E8E13ADFDD10ULL,
			0x5521045A1101502AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA48FA2A0FC26EE08ULL,
			0x611587A35F793B5EULL,
			0xE435FCD233EC911AULL,
			0x4759499F94B4FC10ULL}
		},
		.Z = {.key64 = {
			0x591270A6DEB4CADFULL,
			0xBDE49C1A19696F6EULL,
			0x2350E9160FEBFBD8ULL,
			0x695C71A09131481FULL}
		}
	};
	printf("Test Case 207\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 207 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -207;
	} else {
		printf("Test Case 207 PASSED\n");
	}

	steps = 57;
	X1 = (curve25519_key_t){.key64 = {
		0xBEC9B380C0CCB6F0ULL,
		0x104F0B91B0015274ULL,
		0x191382746E337B56ULL,
		0x6ACD38BF79083697ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBEC9B380C0CCB6F0ULL,
			0x104F0B91B0015274ULL,
			0x191382746E337B56ULL,
			0x6ACD38BF79083697ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5340A6EEF8193EA3ULL,
			0x76E36EBC6BEF41AEULL,
			0x2453548F4E367C2FULL,
			0x402385EFC2AE0740ULL}
		},
		.Z = {.key64 = {
			0xF701AFC119E04857ULL,
			0xBF3266B35ACD92B7ULL,
			0x3151A2054EF3A3A5ULL,
			0x26132611B9D1FF2FULL}
		}
	};
	printf("Test Case 208\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 208 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -208;
	} else {
		printf("Test Case 208 PASSED\n");
	}

	steps = 47;
	X1 = (curve25519_key_t){.key64 = {
		0xB892515171B94D30ULL,
		0x55C827135FCBF2D1ULL,
		0x6B8105641668F54CULL,
		0x6A795FA58C4A77DDULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB892515171B94D30ULL,
			0x55C827135FCBF2D1ULL,
			0x6B8105641668F54CULL,
			0x6A795FA58C4A77DDULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6644853A736F50C0ULL,
			0x548A1A0F220CD361ULL,
			0x28DD5CBA5F6DD6F1ULL,
			0x691B441BAC3728FAULL}
		},
		.Z = {.key64 = {
			0x2D0E373302631961ULL,
			0xB0A7AC1C766335BFULL,
			0x0C4A001319FF19FBULL,
			0x5DDB5A0DE0A2A9F8ULL}
		}
	};
	printf("Test Case 209\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 209 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -209;
	} else {
		printf("Test Case 209 PASSED\n");
	}

	steps = 14;
	X1 = (curve25519_key_t){.key64 = {
		0xDBADDC21564E3DE8ULL,
		0x27EBA7DC0E60CEC7ULL,
		0x6EA5B5C9CE7D3BDFULL,
		0x7816967B30833751ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDBADDC21564E3DE8ULL,
			0x27EBA7DC0E60CEC7ULL,
			0x6EA5B5C9CE7D3BDFULL,
			0x7816967B30833751ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB71897EDD5625058ULL,
			0xD464461CAE05560BULL,
			0x1774A0CC70DF2203ULL,
			0x754B2F72E79D07EBULL}
		},
		.Z = {.key64 = {
			0x0E4622DC58791C8BULL,
			0x6768377D3C78FD0EULL,
			0x5D51D3030F1A8338ULL,
			0x208D53C3DD16CF0BULL}
		}
	};
	printf("Test Case 210\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 210 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -210;
	} else {
		printf("Test Case 210 PASSED\n");
	}

	steps = 27;
	X1 = (curve25519_key_t){.key64 = {
		0x7AC48E2B48E15D38ULL,
		0xBA543317BDB1A6F2ULL,
		0xF18D517DEE1981C5ULL,
		0x7F24BDFFE48C56DAULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7AC48E2B48E15D38ULL,
			0xBA543317BDB1A6F2ULL,
			0xF18D517DEE1981C5ULL,
			0x7F24BDFFE48C56DAULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0E0B0DF70871A07CULL,
			0xBFC2EF94F9BAC61DULL,
			0xE3F6D0AF1B236C77ULL,
			0x22FA93FD349D49B1ULL}
		},
		.Z = {.key64 = {
			0x4371CF3101192991ULL,
			0xCA5929419BF4D531ULL,
			0xA9EF36114B4F1B8EULL,
			0x33D9BECFCAE1D159ULL}
		}
	};
	printf("Test Case 211\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 211 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -211;
	} else {
		printf("Test Case 211 PASSED\n");
	}

	steps = 37;
	X1 = (curve25519_key_t){.key64 = {
		0x535DC172856E9B98ULL,
		0x672C2D245EB0A45AULL,
		0x3470A77E3F9D6155ULL,
		0x7B2B4BDE367B0E46ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x535DC172856E9B98ULL,
			0x672C2D245EB0A45AULL,
			0x3470A77E3F9D6155ULL,
			0x7B2B4BDE367B0E46ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x930513C1B05CD4CAULL,
			0x1952121C34A4A016ULL,
			0x47102F6CD9A1E28BULL,
			0x4A010B673D9D1BD3ULL}
		},
		.Z = {.key64 = {
			0xDACA342D25D040CBULL,
			0x1C53E242ECDEB759ULL,
			0x2F8B7D832738555DULL,
			0x69861AE8AD6AB752ULL}
		}
	};
	printf("Test Case 212\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 212 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -212;
	} else {
		printf("Test Case 212 PASSED\n");
	}

	steps = 8;
	X1 = (curve25519_key_t){.key64 = {
		0x41B41EB0420D8DE0ULL,
		0x219A4227364F6D0EULL,
		0xC179039A52922AD8ULL,
		0x53DCF657E238B182ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x41B41EB0420D8DE0ULL,
			0x219A4227364F6D0EULL,
			0xC179039A52922AD8ULL,
			0x53DCF657E238B182ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6E8C766F6A05B19AULL,
			0xAE6F73E6714C1488ULL,
			0x23FBE416A3BE53EBULL,
			0x223A50A13505E59DULL}
		},
		.Z = {.key64 = {
			0xC6A92AA71CB6D2C6ULL,
			0x4695AB66235D4FFAULL,
			0x1C6666C8D2042C17ULL,
			0x39A7249C8C8B26C6ULL}
		}
	};
	printf("Test Case 213\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 213 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -213;
	} else {
		printf("Test Case 213 PASSED\n");
	}

	steps = 34;
	X1 = (curve25519_key_t){.key64 = {
		0x78ABE7E630344668ULL,
		0x3AA05C71A09EB42FULL,
		0x97FC81BFBEE82CDEULL,
		0x7AD8FC8E543AC3A5ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x78ABE7E630344668ULL,
			0x3AA05C71A09EB42FULL,
			0x97FC81BFBEE82CDEULL,
			0x7AD8FC8E543AC3A5ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x802A65242E09B823ULL,
			0xE950B3420ED8E3EAULL,
			0x51F56AEAF36C840FULL,
			0x2E6D9A956C1D435FULL}
		},
		.Z = {.key64 = {
			0x8FD5C03799D3328FULL,
			0x93BFE498918658D8ULL,
			0x326E94E7C6DAED67ULL,
			0x2126597B28BF083CULL}
		}
	};
	printf("Test Case 214\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 214 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -214;
	} else {
		printf("Test Case 214 PASSED\n");
	}

	steps = 10;
	X1 = (curve25519_key_t){.key64 = {
		0xDEA24232BDF57158ULL,
		0x33F1CC8CFCA53BD1ULL,
		0x10AA15ED35DAE04FULL,
		0x6742F51C345D3369ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDEA24232BDF57158ULL,
			0x33F1CC8CFCA53BD1ULL,
			0x10AA15ED35DAE04FULL,
			0x6742F51C345D3369ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2E8655CA314E4E41ULL,
			0x889B0BA0E76B0FFAULL,
			0xC38D79647BC80952ULL,
			0x302ACE1F1D50F2F2ULL}
		},
		.Z = {.key64 = {
			0xB555E966A8CC7B1CULL,
			0x3D4468B1820BD1C7ULL,
			0x89E3EF150F17444BULL,
			0x07760C89780B030DULL}
		}
	};
	printf("Test Case 215\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 215 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -215;
	} else {
		printf("Test Case 215 PASSED\n");
	}

	steps = 60;
	X1 = (curve25519_key_t){.key64 = {
		0xE0A8A79B7329D810ULL,
		0x0B817DE927218AC4ULL,
		0x8034042B4CD329E5ULL,
		0x6054D7701887CA4DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE0A8A79B7329D810ULL,
			0x0B817DE927218AC4ULL,
			0x8034042B4CD329E5ULL,
			0x6054D7701887CA4DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x46E63F1A8CF4BE52ULL,
			0xA210B22696C4C965ULL,
			0x24FFA45199A499F6ULL,
			0x28D5A25CEAA7849DULL}
		},
		.Z = {.key64 = {
			0xB07E250AF7AA581EULL,
			0xBCF217CFA4140B4AULL,
			0xE176737C8B33CD4AULL,
			0x5104B4D47704368CULL}
		}
	};
	printf("Test Case 216\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 216 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -216;
	} else {
		printf("Test Case 216 PASSED\n");
	}

	steps = 35;
	X1 = (curve25519_key_t){.key64 = {
		0x7FC9672A86CB4C30ULL,
		0xB0B75AFA5099A9A0ULL,
		0xDDC2F694D5C20116ULL,
		0x5E4833601EC5161CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7FC9672A86CB4C30ULL,
			0xB0B75AFA5099A9A0ULL,
			0xDDC2F694D5C20116ULL,
			0x5E4833601EC5161CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFCD1B36783D58C3FULL,
			0xE12B6BB3D8954D6EULL,
			0x451A7570C4C6AA17ULL,
			0x335B72BA32D52550ULL}
		},
		.Z = {.key64 = {
			0x3137E060E4F7790BULL,
			0x0645F557BFE45B9AULL,
			0x0BB8D4CCEBEBF820ULL,
			0x6A5F0B8EC0104FE1ULL}
		}
	};
	printf("Test Case 217\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 217 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -217;
	} else {
		printf("Test Case 217 PASSED\n");
	}

	steps = 35;
	X1 = (curve25519_key_t){.key64 = {
		0x2491812DDAD10080ULL,
		0x7051D0D1D720E686ULL,
		0x26924FA92CEC4BE1ULL,
		0x65D3B3483C42D2C2ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2491812DDAD10080ULL,
			0x7051D0D1D720E686ULL,
			0x26924FA92CEC4BE1ULL,
			0x65D3B3483C42D2C2ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x56AF18C4C85ABD21ULL,
			0x97D975B414C090DAULL,
			0x5ED3F6F1B1142543ULL,
			0x37F1A3A9989C174AULL}
		},
		.Z = {.key64 = {
			0x386BB6E0B92C75AFULL,
			0xD68FE2835C513638ULL,
			0x7F6A9CA92AACE355ULL,
			0x5BD6BD7C5E9455C9ULL}
		}
	};
	printf("Test Case 218\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 218 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -218;
	} else {
		printf("Test Case 218 PASSED\n");
	}

	steps = 58;
	X1 = (curve25519_key_t){.key64 = {
		0x32237E652C4E7878ULL,
		0xDB24975D434A9879ULL,
		0xFE10F8CAA3F5D6F3ULL,
		0x7DB0A9D9B94EC54FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x32237E652C4E7878ULL,
			0xDB24975D434A9879ULL,
			0xFE10F8CAA3F5D6F3ULL,
			0x7DB0A9D9B94EC54FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD09C77D0507369CCULL,
			0x7124508EF072D62CULL,
			0x78CE2F724EC187A2ULL,
			0x6741A41D29C6D4D0ULL}
		},
		.Z = {.key64 = {
			0x0F3351E69CB7514AULL,
			0xC727B565FFE8011DULL,
			0xCD85F4110EF598D0ULL,
			0x1E890EFB22FFF6C3ULL}
		}
	};
	printf("Test Case 219\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 219 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -219;
	} else {
		printf("Test Case 219 PASSED\n");
	}

	steps = 37;
	X1 = (curve25519_key_t){.key64 = {
		0x5F322B1475A0C428ULL,
		0x23717BB8BBA26B8FULL,
		0x2D7FAFCA221D23E7ULL,
		0x57CA70A48D874D9AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5F322B1475A0C428ULL,
			0x23717BB8BBA26B8FULL,
			0x2D7FAFCA221D23E7ULL,
			0x57CA70A48D874D9AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF339B40A46A391A3ULL,
			0xD337F637D895C48EULL,
			0x74073E1F6C9F9832ULL,
			0x028E51DC94EB1ABCULL}
		},
		.Z = {.key64 = {
			0xA7A4337E96FA5E18ULL,
			0xD566215DA09D9558ULL,
			0xFE0F011A65104842ULL,
			0x223B51638D4472BAULL}
		}
	};
	printf("Test Case 220\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 220 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -220;
	} else {
		printf("Test Case 220 PASSED\n");
	}

	steps = 57;
	X1 = (curve25519_key_t){.key64 = {
		0xDE07F25A0D0F1EF8ULL,
		0x79375B0D40A58345ULL,
		0xAF8B4C4A6E6468D1ULL,
		0x7AAF2B0AFF256FBCULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDE07F25A0D0F1EF8ULL,
			0x79375B0D40A58345ULL,
			0xAF8B4C4A6E6468D1ULL,
			0x7AAF2B0AFF256FBCULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x231853708A22F319ULL,
			0x04081BDAA60BB32FULL,
			0xB44D5E8AEFED26A5ULL,
			0x581D7E5D67B1CE0EULL}
		},
		.Z = {.key64 = {
			0xF1DEE1BF2566AC8EULL,
			0xB28DD0FF826D2565ULL,
			0x3BD1078577CE68C0ULL,
			0x490F978B384EC257ULL}
		}
	};
	printf("Test Case 221\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 221 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -221;
	} else {
		printf("Test Case 221 PASSED\n");
	}

	steps = 50;
	X1 = (curve25519_key_t){.key64 = {
		0x6F83C8B413F6E5E0ULL,
		0xE2254792C4CDA300ULL,
		0xFB53B9A16F235F35ULL,
		0x55706535C69DBA46ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6F83C8B413F6E5E0ULL,
			0xE2254792C4CDA300ULL,
			0xFB53B9A16F235F35ULL,
			0x55706535C69DBA46ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x080BCA6138E6BCCAULL,
			0x631623094CEBF149ULL,
			0x000D57C55543B7D9ULL,
			0x479692C79BCBA02BULL}
		},
		.Z = {.key64 = {
			0x466417C4B83231FAULL,
			0x40F4E856AFA4A1FDULL,
			0x33CB3EFD26440802ULL,
			0x0B451ABC67884AF6ULL}
		}
	};
	printf("Test Case 222\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 222 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -222;
	} else {
		printf("Test Case 222 PASSED\n");
	}

	steps = 31;
	X1 = (curve25519_key_t){.key64 = {
		0xEAAA7DB1C32ED838ULL,
		0x481D438774C559E9ULL,
		0xD22AA9811FEC15B5ULL,
		0x5AF327111D771E3BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEAAA7DB1C32ED838ULL,
			0x481D438774C559E9ULL,
			0xD22AA9811FEC15B5ULL,
			0x5AF327111D771E3BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA972AF362CA03216ULL,
			0x3B2B1EDCDB2153B5ULL,
			0x84AE3F8B85E80D7FULL,
			0x707182573188BA4CULL}
		},
		.Z = {.key64 = {
			0xA9942CD6E31AB289ULL,
			0x4D639C832B438A3EULL,
			0xC495E4CA6155625DULL,
			0x0880179783762887ULL}
		}
	};
	printf("Test Case 223\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 223 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -223;
	} else {
		printf("Test Case 223 PASSED\n");
	}

	steps = 14;
	X1 = (curve25519_key_t){.key64 = {
		0xFF1D78E6A91E2A40ULL,
		0xCE2D6273E872B943ULL,
		0x6AE419C274CFBD08ULL,
		0x514943D795360AD5ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFF1D78E6A91E2A40ULL,
			0xCE2D6273E872B943ULL,
			0x6AE419C274CFBD08ULL,
			0x514943D795360AD5ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x03A40C39B408D15CULL,
			0x82284EEE953D7E4EULL,
			0x5DECE9CEBC4E84ECULL,
			0x56F28BAB4DBDB8B5ULL}
		},
		.Z = {.key64 = {
			0xE6047E0D9FD04370ULL,
			0xA5B499849A5AB1E2ULL,
			0x8E2EEE64A84650E5ULL,
			0x040CDAB5C6E3F3C1ULL}
		}
	};
	printf("Test Case 224\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 224 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -224;
	} else {
		printf("Test Case 224 PASSED\n");
	}

	steps = 48;
	X1 = (curve25519_key_t){.key64 = {
		0x977159101F034C48ULL,
		0x68E13EC5263C9397ULL,
		0xA5DEA4871B815FC5ULL,
		0x58A3376410D3C7B1ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x977159101F034C48ULL,
			0x68E13EC5263C9397ULL,
			0xA5DEA4871B815FC5ULL,
			0x58A3376410D3C7B1ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE72333A76A94A2F4ULL,
			0x1BE19F68EA73E0BAULL,
			0xCA01DC63B347431DULL,
			0x67B2FFC14132F78BULL}
		},
		.Z = {.key64 = {
			0xAC91288DDE7A624AULL,
			0x07D5F35241292272ULL,
			0x3DC8B0C7123B95C3ULL,
			0x3CCF961E3C1BE2DFULL}
		}
	};
	printf("Test Case 225\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 225 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -225;
	} else {
		printf("Test Case 225 PASSED\n");
	}

	steps = 57;
	X1 = (curve25519_key_t){.key64 = {
		0xA23B4FC894CBDAC8ULL,
		0xD08D1A75D994B924ULL,
		0x879D220F434FA375ULL,
		0x5DCF9A230C9ABCDCULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA23B4FC894CBDAC8ULL,
			0xD08D1A75D994B924ULL,
			0x879D220F434FA375ULL,
			0x5DCF9A230C9ABCDCULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x782A5F89A4A3AE2FULL,
			0xDF0AF01CE2D47E92ULL,
			0x70A2E0E5BFDA698BULL,
			0x5AF71075B9A90EE2ULL}
		},
		.Z = {.key64 = {
			0xD6F3C8D5CFEE5043ULL,
			0x01197170E0C935AFULL,
			0x4D6FFB7F076E3AC2ULL,
			0x4A5560A4206B112EULL}
		}
	};
	printf("Test Case 226\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 226 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -226;
	} else {
		printf("Test Case 226 PASSED\n");
	}

	steps = 5;
	X1 = (curve25519_key_t){.key64 = {
		0xB316C914802D0488ULL,
		0x2567C30E2ECCA9B4ULL,
		0xAE3E574B32B895D0ULL,
		0x400166C180E19202ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB316C914802D0488ULL,
			0x2567C30E2ECCA9B4ULL,
			0xAE3E574B32B895D0ULL,
			0x400166C180E19202ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x76E9478F20DD2FE9ULL,
			0x4F4F9A03312840C9ULL,
			0x7DDDEC9BFCAD2CB3ULL,
			0x339D3A28D585B318ULL}
		},
		.Z = {.key64 = {
			0x5D9BC63F2E0B5D70ULL,
			0xD26D0B6B36F1245DULL,
			0xC9906FFFB57B2A29ULL,
			0x6A892167CD20B175ULL}
		}
	};
	printf("Test Case 227\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 227 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -227;
	} else {
		printf("Test Case 227 PASSED\n");
	}

	steps = 6;
	X1 = (curve25519_key_t){.key64 = {
		0xD3C67A093EA70D28ULL,
		0x02502528290A9E88ULL,
		0x491C4147DDE42DE5ULL,
		0x7FFACD4779527CBCULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD3C67A093EA70D28ULL,
			0x02502528290A9E88ULL,
			0x491C4147DDE42DE5ULL,
			0x7FFACD4779527CBCULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2FAB7FB801E9DF67ULL,
			0xC758826DF6337373ULL,
			0x81A59282A306F0D1ULL,
			0x747A0BA7BF6020CAULL}
		},
		.Z = {.key64 = {
			0x3519C16D7C80B1AFULL,
			0x5300D727C97F2605ULL,
			0x8BA3BAE22B1D8D5BULL,
			0x69FCD8953A00D8D4ULL}
		}
	};
	printf("Test Case 228\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 228 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -228;
	} else {
		printf("Test Case 228 PASSED\n");
	}

	steps = 11;
	X1 = (curve25519_key_t){.key64 = {
		0x18BC5379738F4AC0ULL,
		0x7A36F188360A0DBEULL,
		0xE0470927FFE17656ULL,
		0x492EB1BA4FEF40D0ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x18BC5379738F4AC0ULL,
			0x7A36F188360A0DBEULL,
			0xE0470927FFE17656ULL,
			0x492EB1BA4FEF40D0ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7844580BF79A4956ULL,
			0xDF45BE3AC89AE96FULL,
			0xC192C2501CAEAD2DULL,
			0x38652B0324B2DB97ULL}
		},
		.Z = {.key64 = {
			0x3F057E5DFC0C9F41ULL,
			0x41F31145AAC6C9BBULL,
			0xB0F2716D6A622C84ULL,
			0x2B005B73F286E213ULL}
		}
	};
	printf("Test Case 229\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 229 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -229;
	} else {
		printf("Test Case 229 PASSED\n");
	}

	steps = 36;
	X1 = (curve25519_key_t){.key64 = {
		0xBA230296D21424B8ULL,
		0xB3FFB9061990007DULL,
		0x9CD79CD347A094CFULL,
		0x48A49B413713D879ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBA230296D21424B8ULL,
			0xB3FFB9061990007DULL,
			0x9CD79CD347A094CFULL,
			0x48A49B413713D879ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCF46A52F2DB7884DULL,
			0xD898207A1D8D2C74ULL,
			0x86F668BA0C0133D4ULL,
			0x48A4A6F23C474BA9ULL}
		},
		.Z = {.key64 = {
			0xFCEF0051FF23F4D7ULL,
			0xA17951DF69C47BBFULL,
			0xBE425B7DB8B2858AULL,
			0x1BDD96C7D4FC1C41ULL}
		}
	};
	printf("Test Case 230\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 230 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -230;
	} else {
		printf("Test Case 230 PASSED\n");
	}

	steps = 20;
	X1 = (curve25519_key_t){.key64 = {
		0xA5FF0148BCC27DE8ULL,
		0xD3CB19211AA98710ULL,
		0xC590E088261D745CULL,
		0x5D4209E853D6BCA7ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA5FF0148BCC27DE8ULL,
			0xD3CB19211AA98710ULL,
			0xC590E088261D745CULL,
			0x5D4209E853D6BCA7ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x59B0A48497724A14ULL,
			0xF9A829A21233D522ULL,
			0xE5ADD669E0E353F7ULL,
			0x13DB2674D4441EA2ULL}
		},
		.Z = {.key64 = {
			0x087CE978A8C9CDC0ULL,
			0x04D942403F2E912CULL,
			0xA6F505815C2B3A4AULL,
			0x4953B337DBFDE7EEULL}
		}
	};
	printf("Test Case 231\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 231 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -231;
	} else {
		printf("Test Case 231 PASSED\n");
	}

	steps = 26;
	X1 = (curve25519_key_t){.key64 = {
		0xEC6D0F150229DB20ULL,
		0xBD44EF272BB293A3ULL,
		0x829AF57A7CE1F751ULL,
		0x4FD7679E2BE1AB23ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEC6D0F150229DB20ULL,
			0xBD44EF272BB293A3ULL,
			0x829AF57A7CE1F751ULL,
			0x4FD7679E2BE1AB23ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDF8FE761E126EA06ULL,
			0xB4F5EECBB78206EAULL,
			0xE1A187DF92F81969ULL,
			0x1449818C28394394ULL}
		},
		.Z = {.key64 = {
			0xBED3FBB7A6079C87ULL,
			0x95E1D6063BB85B56ULL,
			0x8F50CEA24D2CE22AULL,
			0x167A9E258C1BD465ULL}
		}
	};
	printf("Test Case 232\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 232 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -232;
	} else {
		printf("Test Case 232 PASSED\n");
	}

	steps = 60;
	X1 = (curve25519_key_t){.key64 = {
		0x6871210EA29F6A50ULL,
		0xCF196E71A2A313B6ULL,
		0xDEE7CBB88E1F4594ULL,
		0x668ECB4319B47EB1ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6871210EA29F6A50ULL,
			0xCF196E71A2A313B6ULL,
			0xDEE7CBB88E1F4594ULL,
			0x668ECB4319B47EB1ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x197AD47E36ED8244ULL,
			0xD7269E0D3D9D1F7EULL,
			0x8767993A43E1AC24ULL,
			0x350C35EA669BD640ULL}
		},
		.Z = {.key64 = {
			0x1D7BC5FE60743622ULL,
			0x100DE0239B3B72BBULL,
			0x9B7B61F5AAE8541BULL,
			0x3DDF46CA6DB93990ULL}
		}
	};
	printf("Test Case 233\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 233 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -233;
	} else {
		printf("Test Case 233 PASSED\n");
	}

	steps = 14;
	X1 = (curve25519_key_t){.key64 = {
		0x7A577F7261983CC8ULL,
		0x418C291E0C91F34FULL,
		0x2E7DD89378C4E063ULL,
		0x5CCAF50ACE73EC2AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7A577F7261983CC8ULL,
			0x418C291E0C91F34FULL,
			0x2E7DD89378C4E063ULL,
			0x5CCAF50ACE73EC2AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1E1ABDE211BA01B7ULL,
			0xAF522C0BFFFFA8FEULL,
			0x1DAA0C9F8CD32CC8ULL,
			0x18DBCD31ADB3DF5EULL}
		},
		.Z = {.key64 = {
			0x5BC4B2705A157F95ULL,
			0xAC4E1BA8FB0D17E4ULL,
			0x6DC7B0E60386B827ULL,
			0x3EF1D5134979F6D5ULL}
		}
	};
	printf("Test Case 234\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 234 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -234;
	} else {
		printf("Test Case 234 PASSED\n");
	}

	steps = 62;
	X1 = (curve25519_key_t){.key64 = {
		0x72787D1B662E7548ULL,
		0x08B8DE8418581548ULL,
		0x36AF3EAEBC9ACAA9ULL,
		0x453FCCB544C2FC3BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x72787D1B662E7548ULL,
			0x08B8DE8418581548ULL,
			0x36AF3EAEBC9ACAA9ULL,
			0x453FCCB544C2FC3BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x01D97BF35D9C7DCFULL,
			0x9154EF98C46FC89EULL,
			0xEB54F0DD96D8DDD2ULL,
			0x379971925746964AULL}
		},
		.Z = {.key64 = {
			0xF57641D6507FEAC1ULL,
			0x0D5750480602D22CULL,
			0x5A2DC6C2B42802A2ULL,
			0x639DB0D3B23BF4BFULL}
		}
	};
	printf("Test Case 235\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 235 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -235;
	} else {
		printf("Test Case 235 PASSED\n");
	}

	steps = 12;
	X1 = (curve25519_key_t){.key64 = {
		0x52794E23B5DCA328ULL,
		0x8A9EFA56E31F5347ULL,
		0xB66688129AD10F71ULL,
		0x54A479B81B114C1CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x52794E23B5DCA328ULL,
			0x8A9EFA56E31F5347ULL,
			0xB66688129AD10F71ULL,
			0x54A479B81B114C1CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x81A902088F68426FULL,
			0x1F9D55899293E5F9ULL,
			0xF0C202F1977D6843ULL,
			0x4D25EB508D172DA6ULL}
		},
		.Z = {.key64 = {
			0x004737482587A34BULL,
			0x08FABD8D65292C19ULL,
			0xF96ED6A471222314ULL,
			0x0E6CB5525F9E3F7FULL}
		}
	};
	printf("Test Case 236\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 236 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -236;
	} else {
		printf("Test Case 236 PASSED\n");
	}

	steps = 7;
	X1 = (curve25519_key_t){.key64 = {
		0x94DBC50C37864FC8ULL,
		0x3ACD3982C4B88704ULL,
		0xB66E69F021245055ULL,
		0x584A27FC156469E8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x94DBC50C37864FC8ULL,
			0x3ACD3982C4B88704ULL,
			0xB66E69F021245055ULL,
			0x584A27FC156469E8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x657DF04AD32D34B3ULL,
			0x78C1F6766611C1CFULL,
			0x63A88D588C321F20ULL,
			0x1D8C15D28316459FULL}
		},
		.Z = {.key64 = {
			0x89CC7E63A48DF576ULL,
			0x98DED66B855CB65CULL,
			0x7966F20642B589EAULL,
			0x24F9773F9A05BBA0ULL}
		}
	};
	printf("Test Case 237\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 237 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -237;
	} else {
		printf("Test Case 237 PASSED\n");
	}

	steps = 60;
	X1 = (curve25519_key_t){.key64 = {
		0xF6F764CCD04F8960ULL,
		0x68C390356B0C7287ULL,
		0xD1A2B3A797B38C24ULL,
		0x71780543523D83D4ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF6F764CCD04F8960ULL,
			0x68C390356B0C7287ULL,
			0xD1A2B3A797B38C24ULL,
			0x71780543523D83D4ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x76659C548503081DULL,
			0x5720025A3AB5213AULL,
			0x0A3E70EE477BF607ULL,
			0x53677C240CFEA7ADULL}
		},
		.Z = {.key64 = {
			0xC8735137A4FDD58CULL,
			0x0E6648F5466C19ADULL,
			0x9EDAD22F52773A41ULL,
			0x4B23E27503DCBC1EULL}
		}
	};
	printf("Test Case 238\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 238 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -238;
	} else {
		printf("Test Case 238 PASSED\n");
	}

	steps = 3;
	X1 = (curve25519_key_t){.key64 = {
		0xA443FCD175117BA0ULL,
		0xF3DB45C60A09BFDBULL,
		0x919E209CD5041734ULL,
		0x4459E238F78420CBULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA443FCD175117BA0ULL,
			0xF3DB45C60A09BFDBULL,
			0x919E209CD5041734ULL,
			0x4459E238F78420CBULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDEB1C2BD76D65B85ULL,
			0xC2C24B855012DCBEULL,
			0xE22997A99FB0C073ULL,
			0x127BA6EB5582B11FULL}
		},
		.Z = {.key64 = {
			0xB76DF63FAEE98EDCULL,
			0x81350BB57F063C21ULL,
			0x0668844E59C6CBE7ULL,
			0x22CEB79F83A02BC2ULL}
		}
	};
	printf("Test Case 239\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 239 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -239;
	} else {
		printf("Test Case 239 PASSED\n");
	}

	steps = 62;
	X1 = (curve25519_key_t){.key64 = {
		0xC4015F25699909B0ULL,
		0xC3C7FBD72CC2BBA2ULL,
		0xCB08F617A272C5B2ULL,
		0x45CB035B00DD5BDEULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC4015F25699909B0ULL,
			0xC3C7FBD72CC2BBA2ULL,
			0xCB08F617A272C5B2ULL,
			0x45CB035B00DD5BDEULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF67DFA0BD3FBB939ULL,
			0xD70D19B9547CA715ULL,
			0xE058EFA22114160FULL,
			0x04A559EAFB8159FEULL}
		},
		.Z = {.key64 = {
			0xD67B6FE7C6AD1AA8ULL,
			0x60500AA5664F6774ULL,
			0xDDE31589C2533E81ULL,
			0x0831D0314D03AD7BULL}
		}
	};
	printf("Test Case 240\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 240 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -240;
	} else {
		printf("Test Case 240 PASSED\n");
	}

	steps = 62;
	X1 = (curve25519_key_t){.key64 = {
		0xE485C54DAA3787E0ULL,
		0x66297D60D4A542BDULL,
		0x5F43E39034387879ULL,
		0x645A76C0AED063EEULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE485C54DAA3787E0ULL,
			0x66297D60D4A542BDULL,
			0x5F43E39034387879ULL,
			0x645A76C0AED063EEULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9A3DE161EE5937B8ULL,
			0xAADCFE7A28316BFBULL,
			0xDC61EA768E3ADDA6ULL,
			0x3252520F880A36BEULL}
		},
		.Z = {.key64 = {
			0x76DBAA98FA4382B3ULL,
			0xA2F83022C6EAC693ULL,
			0x6B2797A59F6DE142ULL,
			0x1E9DAC2F68AD5EFAULL}
		}
	};
	printf("Test Case 241\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 241 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -241;
	} else {
		printf("Test Case 241 PASSED\n");
	}

	steps = 56;
	X1 = (curve25519_key_t){.key64 = {
		0xED0CD82D60107610ULL,
		0x9697763F4A5BA946ULL,
		0xC7A51C0F48C69EF1ULL,
		0x74B16F0EC10416D6ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xED0CD82D60107610ULL,
			0x9697763F4A5BA946ULL,
			0xC7A51C0F48C69EF1ULL,
			0x74B16F0EC10416D6ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA064FA837DC02D11ULL,
			0xE035C5B10F248B1DULL,
			0x81540217B30432BAULL,
			0x4AE3CD3A6FCD7437ULL}
		},
		.Z = {.key64 = {
			0xC0323D8A0CEF3515ULL,
			0x9BC4EF4BD59EA9DCULL,
			0x34CEC42A8580E004ULL,
			0x709CA8BE1ED0FE44ULL}
		}
	};
	printf("Test Case 242\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 242 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -242;
	} else {
		printf("Test Case 242 PASSED\n");
	}

	steps = 7;
	X1 = (curve25519_key_t){.key64 = {
		0x84F41F15F6498700ULL,
		0x30C5DEA75BAC135DULL,
		0x8FA46FE7133DC371ULL,
		0x6445DC304F97FBF3ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x84F41F15F6498700ULL,
			0x30C5DEA75BAC135DULL,
			0x8FA46FE7133DC371ULL,
			0x6445DC304F97FBF3ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0E72D937845E09C7ULL,
			0x4A04E4F284DC577DULL,
			0xFDF2E9889CEDBD4EULL,
			0x363F776C2241B1D6ULL}
		},
		.Z = {.key64 = {
			0x294D49CEF25757FBULL,
			0xC23BF4A6B87F52C5ULL,
			0xF2472E7F5F0F1E77ULL,
			0x6D64CE2C59FEC0D7ULL}
		}
	};
	printf("Test Case 243\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 243 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -243;
	} else {
		printf("Test Case 243 PASSED\n");
	}

	steps = 17;
	X1 = (curve25519_key_t){.key64 = {
		0xE60EAF7DC668D768ULL,
		0x740299B922CA04AFULL,
		0xF1B392004DDF8B8DULL,
		0x7CE68D6FECEC5AF1ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE60EAF7DC668D768ULL,
			0x740299B922CA04AFULL,
			0xF1B392004DDF8B8DULL,
			0x7CE68D6FECEC5AF1ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x70B1336892B288DEULL,
			0xFF71586148FFBFFAULL,
			0x660A91027853364EULL,
			0x41ACAA1998AA7BDEULL}
		},
		.Z = {.key64 = {
			0xB6CA11AE322F2004ULL,
			0xC80AB46FEC1D0CBDULL,
			0x48C685BC1CADD0B4ULL,
			0x7AE7CDB8AAAAE68FULL}
		}
	};
	printf("Test Case 244\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 244 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -244;
	} else {
		printf("Test Case 244 PASSED\n");
	}

	steps = 59;
	X1 = (curve25519_key_t){.key64 = {
		0x4415FF200CAB7AA8ULL,
		0x96CE1C69582A8176ULL,
		0xBA414B948C9109A3ULL,
		0x4627BD078D8C317DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4415FF200CAB7AA8ULL,
			0x96CE1C69582A8176ULL,
			0xBA414B948C9109A3ULL,
			0x4627BD078D8C317DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x18D4C24BD4124605ULL,
			0x7AE94ADA681B6AE8ULL,
			0x69020FB753B24C3EULL,
			0x7E4D4395C2E0E1FBULL}
		},
		.Z = {.key64 = {
			0xBA36B5042840AF1FULL,
			0x34DD6FD0874A7888ULL,
			0x58EF51207A009959ULL,
			0x1302E118AE78D204ULL}
		}
	};
	printf("Test Case 245\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 245 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -245;
	} else {
		printf("Test Case 245 PASSED\n");
	}

	steps = 29;
	X1 = (curve25519_key_t){.key64 = {
		0x293CA30D01711DF0ULL,
		0x2A2E50CDB453F0FAULL,
		0xDD2DA7C4F92FF93DULL,
		0x48D0356EBFDAF599ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x293CA30D01711DF0ULL,
			0x2A2E50CDB453F0FAULL,
			0xDD2DA7C4F92FF93DULL,
			0x48D0356EBFDAF599ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDA7C4EB1F1C07A0DULL,
			0x0DDC740C70F45ED3ULL,
			0x255163E5539EB8C3ULL,
			0x09BF9A04844C05FAULL}
		},
		.Z = {.key64 = {
			0x6C1E73207D597B68ULL,
			0x4A7A46AA1E81CF1BULL,
			0xD5A64B58738988BAULL,
			0x476F7C69FBE2C0B6ULL}
		}
	};
	printf("Test Case 246\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 246 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -246;
	} else {
		printf("Test Case 246 PASSED\n");
	}

	steps = 29;
	X1 = (curve25519_key_t){.key64 = {
		0x8D4D20FE4281BBF0ULL,
		0xD4D404D8CE13AA95ULL,
		0xAA664BAC4CCC6292ULL,
		0x6E5A041F0AE45590ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8D4D20FE4281BBF0ULL,
			0xD4D404D8CE13AA95ULL,
			0xAA664BAC4CCC6292ULL,
			0x6E5A041F0AE45590ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x92757D516BDB712CULL,
			0xFEF80151D9FCC38CULL,
			0x2D7CF7FB210EAF45ULL,
			0x42159F0F55260536ULL}
		},
		.Z = {.key64 = {
			0x3DE269692C619E85ULL,
			0x14AB25CD2A10F066ULL,
			0x22093C7177C22B0BULL,
			0x30ED2E3AA93898E1ULL}
		}
	};
	printf("Test Case 247\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 247 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -247;
	} else {
		printf("Test Case 247 PASSED\n");
	}

	steps = 11;
	X1 = (curve25519_key_t){.key64 = {
		0x131D75289CED2790ULL,
		0xE23A2C7C4C713A7DULL,
		0xA379C45A73D1C31FULL,
		0x44352856AD233529ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x131D75289CED2790ULL,
			0xE23A2C7C4C713A7DULL,
			0xA379C45A73D1C31FULL,
			0x44352856AD233529ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD6028DB505B43829ULL,
			0xA03C0864F162EB28ULL,
			0x6FE437BC5BBEC70CULL,
			0x79610D471863213AULL}
		},
		.Z = {.key64 = {
			0x7539292755960329ULL,
			0x35B6EFD8EEC73034ULL,
			0x19A355A44B64205AULL,
			0x75FBB05C98E08700ULL}
		}
	};
	printf("Test Case 248\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 248 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -248;
	} else {
		printf("Test Case 248 PASSED\n");
	}

	steps = 17;
	X1 = (curve25519_key_t){.key64 = {
		0x1DE07AF3489B7708ULL,
		0x271845BACE562BD1ULL,
		0x758E84E0E834625BULL,
		0x42554F3F105A97E8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1DE07AF3489B7708ULL,
			0x271845BACE562BD1ULL,
			0x758E84E0E834625BULL,
			0x42554F3F105A97E8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA7A0FFAC4BEEADE1ULL,
			0x43167A7554AE37CEULL,
			0x6F4AB9FEC4C6F99DULL,
			0x5FF8C240E5718A1BULL}
		},
		.Z = {.key64 = {
			0x4086848CD248AFDEULL,
			0x8C0D22A372FB3FEDULL,
			0xB0A45763E17BAEFDULL,
			0x7689143111AFA6F2ULL}
		}
	};
	printf("Test Case 249\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 249 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -249;
	} else {
		printf("Test Case 249 PASSED\n");
	}

	steps = 41;
	X1 = (curve25519_key_t){.key64 = {
		0x0A14CD2FE3EBC950ULL,
		0x8594171BA471E8C6ULL,
		0xC8875474CBBD3CCFULL,
		0x75B55432E8BC50C7ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0A14CD2FE3EBC950ULL,
			0x8594171BA471E8C6ULL,
			0xC8875474CBBD3CCFULL,
			0x75B55432E8BC50C7ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA204AD315550F649ULL,
			0xE8C15215FF11A033ULL,
			0xA1B9AFCABA73C17AULL,
			0x17EEB4BC629097F6ULL}
		},
		.Z = {.key64 = {
			0xDD1F16D1D880D005ULL,
			0x955CE38C114974FEULL,
			0x454A066516176DDAULL,
			0x7C40356832F2CF4AULL}
		}
	};
	printf("Test Case 250\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 250 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -250;
	} else {
		printf("Test Case 250 PASSED\n");
	}

	steps = 64;
	X1 = (curve25519_key_t){.key64 = {
		0xCCA9DBAC1ED3BF38ULL,
		0xCEA53BF57D90DA6DULL,
		0x25D3702B6D6C7A84ULL,
		0x6F4CC21B3B9F4E29ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCCA9DBAC1ED3BF38ULL,
			0xCEA53BF57D90DA6DULL,
			0x25D3702B6D6C7A84ULL,
			0x6F4CC21B3B9F4E29ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF16CA6F4EC1F86C0ULL,
			0x8428BE3217C52FE3ULL,
			0x3F0A726808025EA0ULL,
			0x2CE06233C8CB5B9AULL}
		},
		.Z = {.key64 = {
			0xBE130557C18222DBULL,
			0x7A9F9BE0DB4C9CACULL,
			0x0F7F04806831EB8CULL,
			0x56FD08681F40AE78ULL}
		}
	};
	printf("Test Case 251\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 251 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -251;
	} else {
		printf("Test Case 251 PASSED\n");
	}

	steps = 28;
	X1 = (curve25519_key_t){.key64 = {
		0x1DBCB872E5661CD0ULL,
		0x2B8EAE5FC0418A7AULL,
		0x61DFFFE92E0F8C8AULL,
		0x558A202489BB9FFDULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1DBCB872E5661CD0ULL,
			0x2B8EAE5FC0418A7AULL,
			0x61DFFFE92E0F8C8AULL,
			0x558A202489BB9FFDULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x30E150DF2D6C4377ULL,
			0xFF6A9D56AFB61B8DULL,
			0x2829EA9F63DB2CDDULL,
			0x0AEAA952F0EF4CB0ULL}
		},
		.Z = {.key64 = {
			0xE3C82B7A6FD16A1DULL,
			0xC596673CC0BBB031ULL,
			0xB871937A30FA14C5ULL,
			0x341D1474E73BE093ULL}
		}
	};
	printf("Test Case 252\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 252 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -252;
	} else {
		printf("Test Case 252 PASSED\n");
	}

	steps = 23;
	X1 = (curve25519_key_t){.key64 = {
		0x8BFE173116E6C288ULL,
		0x2ABA3B9D0AE05542ULL,
		0x83BAF334F30B7402ULL,
		0x4A0D4C2FD47F0133ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8BFE173116E6C288ULL,
			0x2ABA3B9D0AE05542ULL,
			0x83BAF334F30B7402ULL,
			0x4A0D4C2FD47F0133ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD57655E4A47FF360ULL,
			0x0B62427C4498D3E9ULL,
			0x44484F9E445E2009ULL,
			0x376889C9CB5635A4ULL}
		},
		.Z = {.key64 = {
			0xDF68CD3E0FD45476ULL,
			0xCAF6B0A25543AA3EULL,
			0x4BB6345ACE4D6B29ULL,
			0x16792BA882296553ULL}
		}
	};
	printf("Test Case 253\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 253 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -253;
	} else {
		printf("Test Case 253 PASSED\n");
	}

	steps = 5;
	X1 = (curve25519_key_t){.key64 = {
		0xA293954982AECD68ULL,
		0xD1B674D7C7FBF293ULL,
		0xF5251CDC8FB50B77ULL,
		0x6E841B584270A9E0ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA293954982AECD68ULL,
			0xD1B674D7C7FBF293ULL,
			0xF5251CDC8FB50B77ULL,
			0x6E841B584270A9E0ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9DB7F08E74CA4865ULL,
			0xD7EE86CE77FA888BULL,
			0xAE6F66EF79783FDAULL,
			0x4B68B76738C02AABULL}
		},
		.Z = {.key64 = {
			0x862CA1D4AB682FE4ULL,
			0x5057845EAD809690ULL,
			0x01C770542F9E9CBFULL,
			0x7ABCC8B5C8E8D5E2ULL}
		}
	};
	printf("Test Case 254\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 254 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -254;
	} else {
		printf("Test Case 254 PASSED\n");
	}

	steps = 59;
	X1 = (curve25519_key_t){.key64 = {
		0xC7561EEA4878B690ULL,
		0x154DAABBC054C926ULL,
		0x7B0C86198906641BULL,
		0x71433027ABAAB76EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC7561EEA4878B690ULL,
			0x154DAABBC054C926ULL,
			0x7B0C86198906641BULL,
			0x71433027ABAAB76EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2DE55DF272A127C3ULL,
			0x78C4C311D9D57CA0ULL,
			0x45D4315F828A5F6CULL,
			0x0961C92D0DDB5B15ULL}
		},
		.Z = {.key64 = {
			0xF06C4F7912A43058ULL,
			0x5420719EE6CAA7AAULL,
			0xD5A9341953E047B3ULL,
			0x1FE22418BD6B5401ULL}
		}
	};
	printf("Test Case 255\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 255 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -255;
	} else {
		printf("Test Case 255 PASSED\n");
	}

	steps = 53;
	X1 = (curve25519_key_t){.key64 = {
		0xBE70AC93C5B70608ULL,
		0x95A3B88561FD8B2EULL,
		0x47CB602D77EA1BE8ULL,
		0x701EA16967758CC5ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBE70AC93C5B70608ULL,
			0x95A3B88561FD8B2EULL,
			0x47CB602D77EA1BE8ULL,
			0x701EA16967758CC5ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD510DFA7388741D6ULL,
			0xF1C64FB9157B357EULL,
			0xF709698225411EA4ULL,
			0x0FB554FC7C9BA7CCULL}
		},
		.Z = {.key64 = {
			0x0BED990A930ABEE1ULL,
			0x216216E3DEA56F6DULL,
			0x5D9C5E86008F82B4ULL,
			0x7AAF6168C9C3A361ULL}
		}
	};
	printf("Test Case 256\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 256 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -256;
	} else {
		printf("Test Case 256 PASSED\n");
	}

	steps = 51;
	X1 = (curve25519_key_t){.key64 = {
		0x55C48B1EC40DC438ULL,
		0x572491818DB43E9BULL,
		0x9B4AA7DD933D2A1CULL,
		0x58677F738D488794ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x55C48B1EC40DC438ULL,
			0x572491818DB43E9BULL,
			0x9B4AA7DD933D2A1CULL,
			0x58677F738D488794ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6A3A10D1C434AF7EULL,
			0x71C26CA07CD62DD9ULL,
			0x9AEDF7BCD194B205ULL,
			0x2CA7C9F94068A21CULL}
		},
		.Z = {.key64 = {
			0xB12B50468A9F17EDULL,
			0xD81EC80D6DBA039CULL,
			0xFE390063882BBF61ULL,
			0x589E7031A6A7E481ULL}
		}
	};
	printf("Test Case 257\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 257 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -257;
	} else {
		printf("Test Case 257 PASSED\n");
	}

	steps = 12;
	X1 = (curve25519_key_t){.key64 = {
		0x7460CC58ABC67CA8ULL,
		0x0AAF4AE7AB6CC774ULL,
		0xA8A35078CCC91A85ULL,
		0x63720F7191DF4FF2ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7460CC58ABC67CA8ULL,
			0x0AAF4AE7AB6CC774ULL,
			0xA8A35078CCC91A85ULL,
			0x63720F7191DF4FF2ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD327F7AFEDD52C26ULL,
			0x112C8F5124485A1AULL,
			0x76AB5A83705C0E97ULL,
			0x3E62662CD29BA228ULL}
		},
		.Z = {.key64 = {
			0x23DBC0118D42D148ULL,
			0xD1DC8B79E0BA001DULL,
			0x6D7DCA85FE56D7EAULL,
			0x0DD3F6585DFAD4C5ULL}
		}
	};
	printf("Test Case 258\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 258 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -258;
	} else {
		printf("Test Case 258 PASSED\n");
	}

	steps = 47;
	X1 = (curve25519_key_t){.key64 = {
		0xD4636DC71A338F70ULL,
		0xD8B78FE4FE76A768ULL,
		0xF5FE157875853DA5ULL,
		0x5C0CA32193E8A22CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD4636DC71A338F70ULL,
			0xD8B78FE4FE76A768ULL,
			0xF5FE157875853DA5ULL,
			0x5C0CA32193E8A22CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x38B4918C60EEFDBDULL,
			0xA9314DF4331822E1ULL,
			0x77DD95B0EFE6D729ULL,
			0x72D49EDB037B0FC2ULL}
		},
		.Z = {.key64 = {
			0xF080F960D4A1A898ULL,
			0xBDFB9B65EC2B0294ULL,
			0x8273BFA92D6510F7ULL,
			0x3F466926094A14F3ULL}
		}
	};
	printf("Test Case 259\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 259 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -259;
	} else {
		printf("Test Case 259 PASSED\n");
	}

	steps = 14;
	X1 = (curve25519_key_t){.key64 = {
		0x611356A645C3AA10ULL,
		0x8C9635707AFCDA1BULL,
		0x1B87BAD1DCC15B8EULL,
		0x5A78D14E2BFF45C7ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x611356A645C3AA10ULL,
			0x8C9635707AFCDA1BULL,
			0x1B87BAD1DCC15B8EULL,
			0x5A78D14E2BFF45C7ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x30308B43EC68170FULL,
			0x6A5680AE2B40E01DULL,
			0xE65003DD0FD314FEULL,
			0x350D105C9FDE55C3ULL}
		},
		.Z = {.key64 = {
			0x5E9019772F115C4DULL,
			0x92D793D4C09367F3ULL,
			0xB764C81C26775C56ULL,
			0x563C539D1F55D971ULL}
		}
	};
	printf("Test Case 260\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 260 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -260;
	} else {
		printf("Test Case 260 PASSED\n");
	}

	steps = 61;
	X1 = (curve25519_key_t){.key64 = {
		0x5B0C98B9C79B6CA0ULL,
		0x59A3CCB4CD4647F4ULL,
		0x0A1F728E070E4011ULL,
		0x67FFB89AE845FB34ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5B0C98B9C79B6CA0ULL,
			0x59A3CCB4CD4647F4ULL,
			0x0A1F728E070E4011ULL,
			0x67FFB89AE845FB34ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x23FE8A5F3EF2A0A0ULL,
			0x2942597CFA4E1261ULL,
			0xDEE8F4F8659F6456ULL,
			0x4D8776A94E0A58DBULL}
		},
		.Z = {.key64 = {
			0xF26107D325D742D1ULL,
			0x3DF8AB2C75570924ULL,
			0x0AD86335D54F03A8ULL,
			0x0B8C276DEE9BA9BEULL}
		}
	};
	printf("Test Case 261\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 261 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -261;
	} else {
		printf("Test Case 261 PASSED\n");
	}

	steps = 14;
	X1 = (curve25519_key_t){.key64 = {
		0x766CD9C64F3F9470ULL,
		0x714A10A0D463B594ULL,
		0xBA4C22F57882B293ULL,
		0x5BBB6F052882A8F4ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x766CD9C64F3F9470ULL,
			0x714A10A0D463B594ULL,
			0xBA4C22F57882B293ULL,
			0x5BBB6F052882A8F4ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB4EC74BA3E412185ULL,
			0x7BE45D6A81434F34ULL,
			0x214FCE805B78A7C8ULL,
			0x30BFDA68BD190858ULL}
		},
		.Z = {.key64 = {
			0x5A2C199DC58CFDDDULL,
			0x3047022B4339145BULL,
			0x5E048F08F2113D69ULL,
			0x09174767FAC7FC1CULL}
		}
	};
	printf("Test Case 262\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 262 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -262;
	} else {
		printf("Test Case 262 PASSED\n");
	}

	steps = 13;
	X1 = (curve25519_key_t){.key64 = {
		0xCD503AFF24C82488ULL,
		0xEC478EFDFB7BF861ULL,
		0x4C986B0D6EC6B956ULL,
		0x60C1FE34D8D609B1ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCD503AFF24C82488ULL,
			0xEC478EFDFB7BF861ULL,
			0x4C986B0D6EC6B956ULL,
			0x60C1FE34D8D609B1ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x10082E0C55842B38ULL,
			0xF38E52DFEBB0BE06ULL,
			0x82E06D0F25464569ULL,
			0x36690D51045EAAA5ULL}
		},
		.Z = {.key64 = {
			0x343E6B19779F2AE0ULL,
			0x287844E9FAB1252AULL,
			0xAD0F51F3B08F0D2FULL,
			0x63A15A30BEEFC750ULL}
		}
	};
	printf("Test Case 263\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 263 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -263;
	} else {
		printf("Test Case 263 PASSED\n");
	}

	steps = 9;
	X1 = (curve25519_key_t){.key64 = {
		0x871B82A0C5B0A4F8ULL,
		0x6C6818F6ACEB3BF2ULL,
		0xB61A878A01D961A2ULL,
		0x444C9A0CEF0E929AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x871B82A0C5B0A4F8ULL,
			0x6C6818F6ACEB3BF2ULL,
			0xB61A878A01D961A2ULL,
			0x444C9A0CEF0E929AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA7BB252429E0C429ULL,
			0x66872D14AE92BDAFULL,
			0x47D0BEC7E16FFB45ULL,
			0x5C643301F725B6BBULL}
		},
		.Z = {.key64 = {
			0xCD4FB5FFE8A1EBF2ULL,
			0x418C899FAB27F971ULL,
			0x78978A7C0D24689FULL,
			0x4CD3E037224EF98AULL}
		}
	};
	printf("Test Case 264\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 264 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -264;
	} else {
		printf("Test Case 264 PASSED\n");
	}

	steps = 9;
	X1 = (curve25519_key_t){.key64 = {
		0x8077FBBCEA3CDFE8ULL,
		0x2B3114946613EA81ULL,
		0x57E69F157CB717EAULL,
		0x7F167BABECACDCEAULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8077FBBCEA3CDFE8ULL,
			0x2B3114946613EA81ULL,
			0x57E69F157CB717EAULL,
			0x7F167BABECACDCEAULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF59EF8C89CA40612ULL,
			0x25A6F85ADCE94942ULL,
			0x8725CE9DAEEEA140ULL,
			0x19F5577032EF7C34ULL}
		},
		.Z = {.key64 = {
			0xE103E05682745845ULL,
			0xC9E6E86B036E5E83ULL,
			0x1245B233951CBA98ULL,
			0x016E7BCAB7300D7BULL}
		}
	};
	printf("Test Case 265\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 265 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -265;
	} else {
		printf("Test Case 265 PASSED\n");
	}

	steps = 19;
	X1 = (curve25519_key_t){.key64 = {
		0x5BE88052F4E42228ULL,
		0x014AFCBA14FFBC82ULL,
		0xBA345C47AEE7251EULL,
		0x772BD4AEB52831D8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5BE88052F4E42228ULL,
			0x014AFCBA14FFBC82ULL,
			0xBA345C47AEE7251EULL,
			0x772BD4AEB52831D8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1F59B21328213FA0ULL,
			0xECB606AEBB63378DULL,
			0x52D856A9BB853ED9ULL,
			0x6F8190B4B25A7FFCULL}
		},
		.Z = {.key64 = {
			0xAC3DF8E0920DE635ULL,
			0xA892A2F4A10CCAC9ULL,
			0x2F2C881B14F5D2BAULL,
			0x3E595C132905E4C6ULL}
		}
	};
	printf("Test Case 266\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 266 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -266;
	} else {
		printf("Test Case 266 PASSED\n");
	}

	steps = 30;
	X1 = (curve25519_key_t){.key64 = {
		0x2FFDFC6921436AA0ULL,
		0x9F6EDFB56A368E3BULL,
		0x319BE8F145E491F6ULL,
		0x6A4EB8948B264435ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2FFDFC6921436AA0ULL,
			0x9F6EDFB56A368E3BULL,
			0x319BE8F145E491F6ULL,
			0x6A4EB8948B264435ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x10673150F22DB0B4ULL,
			0x8DBE327C5B57FD2FULL,
			0x68A99B9912E15EBFULL,
			0x618D9F0A1EC26D1BULL}
		},
		.Z = {.key64 = {
			0x05B12A93D049D32EULL,
			0x6B6DB41F8AFA41ADULL,
			0xF43D3C1511601C09ULL,
			0x04E7BB507D6C2065ULL}
		}
	};
	printf("Test Case 267\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 267 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -267;
	} else {
		printf("Test Case 267 PASSED\n");
	}

	steps = 32;
	X1 = (curve25519_key_t){.key64 = {
		0x472FC97989560650ULL,
		0xAAF9A012E4276EE6ULL,
		0xE2749DA2ADFC03BCULL,
		0x6564F5AE154DE842ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x472FC97989560650ULL,
			0xAAF9A012E4276EE6ULL,
			0xE2749DA2ADFC03BCULL,
			0x6564F5AE154DE842ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEBF7A89794CBD9C5ULL,
			0x0471B7CC0CC74A7DULL,
			0x596024FC79D481B9ULL,
			0x0F440E9CAC8E138FULL}
		},
		.Z = {.key64 = {
			0xDBB694EBAB863297ULL,
			0xB84D5857C50DCA49ULL,
			0x96B37CD984E055BBULL,
			0x1146B1F06F89B6DAULL}
		}
	};
	printf("Test Case 268\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 268 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -268;
	} else {
		printf("Test Case 268 PASSED\n");
	}

	steps = 22;
	X1 = (curve25519_key_t){.key64 = {
		0x619D1F930BA139E0ULL,
		0x030132D46AE9DC7FULL,
		0x2D4F1330A2162A0FULL,
		0x4C2F430D7F12EDACULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x619D1F930BA139E0ULL,
			0x030132D46AE9DC7FULL,
			0x2D4F1330A2162A0FULL,
			0x4C2F430D7F12EDACULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x086C4FCBA8039C7FULL,
			0xF07A2084D7A34D29ULL,
			0x025F43EA14633451ULL,
			0x2A2D72B567AD89E4ULL}
		},
		.Z = {.key64 = {
			0x6C19EA9794280B4DULL,
			0x8D8468DDFE7CE21CULL,
			0x0F6DA7BFFECD7FE5ULL,
			0x510F9025D950CFF9ULL}
		}
	};
	printf("Test Case 269\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 269 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -269;
	} else {
		printf("Test Case 269 PASSED\n");
	}

	steps = 7;
	X1 = (curve25519_key_t){.key64 = {
		0x26C000F68EC64930ULL,
		0x18F6C2E3FC13AA1BULL,
		0xDA3ADAC5623E9ABBULL,
		0x5D14F45104CCB5CDULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x26C000F68EC64930ULL,
			0x18F6C2E3FC13AA1BULL,
			0xDA3ADAC5623E9ABBULL,
			0x5D14F45104CCB5CDULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9FF119B22A30E68AULL,
			0xA4224B69D991B44EULL,
			0xB540ED449F2B885CULL,
			0x5537AB9085970806ULL}
		},
		.Z = {.key64 = {
			0x4F2074EA2D4F3859ULL,
			0x93221545C5319FA6ULL,
			0xEB8A319DF3B3011AULL,
			0x77903DAB017FD6C8ULL}
		}
	};
	printf("Test Case 270\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 270 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -270;
	} else {
		printf("Test Case 270 PASSED\n");
	}

	steps = 30;
	X1 = (curve25519_key_t){.key64 = {
		0x0054E76CDD771710ULL,
		0xC421A3ACF50EFDD2ULL,
		0xEE338858EFBDD3F2ULL,
		0x575CA062AB738E2EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0054E76CDD771710ULL,
			0xC421A3ACF50EFDD2ULL,
			0xEE338858EFBDD3F2ULL,
			0x575CA062AB738E2EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7DE25BC62C0D993BULL,
			0x5AE5E64D3699D838ULL,
			0x24AE078581BE1C57ULL,
			0x4416271A0978BAF4ULL}
		},
		.Z = {.key64 = {
			0x223813AE6FC757BBULL,
			0x3D25ECEC210B41CEULL,
			0x4BE3651CD41D00DAULL,
			0x1C89F35C1780C7B5ULL}
		}
	};
	printf("Test Case 271\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 271 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -271;
	} else {
		printf("Test Case 271 PASSED\n");
	}

	steps = 31;
	X1 = (curve25519_key_t){.key64 = {
		0x10C5735C6ACFAC20ULL,
		0xA34184EB2C224EABULL,
		0x0D773714D8F5ADC9ULL,
		0x6A6F35D25DDC1EFBULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x10C5735C6ACFAC20ULL,
			0xA34184EB2C224EABULL,
			0x0D773714D8F5ADC9ULL,
			0x6A6F35D25DDC1EFBULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF59AA914A66A925EULL,
			0x970F5FBD2EA82FB2ULL,
			0x051C9CBE50FB51EBULL,
			0x36BB33368D54AAA6ULL}
		},
		.Z = {.key64 = {
			0x647D079C5EAA38B0ULL,
			0x4CE11511709DE936ULL,
			0x213C27BC5FF50926ULL,
			0x34383798E5D24967ULL}
		}
	};
	printf("Test Case 272\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 272 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -272;
	} else {
		printf("Test Case 272 PASSED\n");
	}

	steps = 6;
	X1 = (curve25519_key_t){.key64 = {
		0x33508B7944520548ULL,
		0xD7E3737A41CFFE6DULL,
		0x296699EF2E5E20D2ULL,
		0x719F982C617EB2D8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x33508B7944520548ULL,
			0xD7E3737A41CFFE6DULL,
			0x296699EF2E5E20D2ULL,
			0x719F982C617EB2D8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5EEC88E1F147A4A1ULL,
			0xDB47FE14FA006B01ULL,
			0xA655B94EACB5534AULL,
			0x172196A5D917B4D9ULL}
		},
		.Z = {.key64 = {
			0xB18F750FFE515E3AULL,
			0xEE94699E2C1E560FULL,
			0x07BF7D211568FDC6ULL,
			0x5B799566EE07B948ULL}
		}
	};
	printf("Test Case 273\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 273 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -273;
	} else {
		printf("Test Case 273 PASSED\n");
	}

	steps = 27;
	X1 = (curve25519_key_t){.key64 = {
		0xDED568ACDB1ABAF8ULL,
		0x95BB803D5070EA27ULL,
		0x56698C98A31E2874ULL,
		0x6069E4ABA1472EE6ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDED568ACDB1ABAF8ULL,
			0x95BB803D5070EA27ULL,
			0x56698C98A31E2874ULL,
			0x6069E4ABA1472EE6ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x03235523FA6CE5DEULL,
			0xD55ADB0EB280C19CULL,
			0x78003C35C4A0A063ULL,
			0x72062B937A4B3A1BULL}
		},
		.Z = {.key64 = {
			0x60BC27D068AFB9E2ULL,
			0x73E1356D68B26744ULL,
			0x58C856C833AD3068ULL,
			0x669B0E11A013F8D3ULL}
		}
	};
	printf("Test Case 274\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 274 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -274;
	} else {
		printf("Test Case 274 PASSED\n");
	}

	steps = 37;
	X1 = (curve25519_key_t){.key64 = {
		0xE703D96AC4E9C118ULL,
		0x103186213CA65886ULL,
		0x41DCF17D73F375BBULL,
		0x4E060B06AFD0DDA0ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE703D96AC4E9C118ULL,
			0x103186213CA65886ULL,
			0x41DCF17D73F375BBULL,
			0x4E060B06AFD0DDA0ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4AD59ECF0B1A635EULL,
			0x4D3143226488F53BULL,
			0xF580C3F1E17585B3ULL,
			0x2955A638C015D6ABULL}
		},
		.Z = {.key64 = {
			0xCEC2B3EF339D42DEULL,
			0x2F4D6D99509E627AULL,
			0x26F4430DC902B079ULL,
			0x1729DECC9B1876D3ULL}
		}
	};
	printf("Test Case 275\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 275 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -275;
	} else {
		printf("Test Case 275 PASSED\n");
	}

	steps = 51;
	X1 = (curve25519_key_t){.key64 = {
		0xCA8884EC452EF210ULL,
		0x3A48AA04850A55F7ULL,
		0xBF6505CFCB669FA2ULL,
		0x64C7BAE68960EF04ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCA8884EC452EF210ULL,
			0x3A48AA04850A55F7ULL,
			0xBF6505CFCB669FA2ULL,
			0x64C7BAE68960EF04ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x957FB8530D36CF4BULL,
			0xC5638D07E43EED20ULL,
			0x9D916E2D8A967123ULL,
			0x360FBDF905DCEFD3ULL}
		},
		.Z = {.key64 = {
			0x663F584D2EC3F8C0ULL,
			0x4AA86FFA222434B8ULL,
			0x94086B3A194A84D3ULL,
			0x2B77520511AC14A8ULL}
		}
	};
	printf("Test Case 276\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 276 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -276;
	} else {
		printf("Test Case 276 PASSED\n");
	}

	steps = 21;
	X1 = (curve25519_key_t){.key64 = {
		0x4CCDA4A3DF920360ULL,
		0xB1658801871C4CF5ULL,
		0xB037ADE9E96E8D5CULL,
		0x5EF5781D0C601C58ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4CCDA4A3DF920360ULL,
			0xB1658801871C4CF5ULL,
			0xB037ADE9E96E8D5CULL,
			0x5EF5781D0C601C58ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x828B05F3877D757BULL,
			0x0E5C9D012E28D778ULL,
			0xB6774D55DC93E316ULL,
			0x56AB990198371574ULL}
		},
		.Z = {.key64 = {
			0xAEEB8F25C1D7338FULL,
			0xE99447C181FEC819ULL,
			0x3ECA01C1913D7D71ULL,
			0x6E0E637A6A40776BULL}
		}
	};
	printf("Test Case 277\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 277 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -277;
	} else {
		printf("Test Case 277 PASSED\n");
	}

	steps = 14;
	X1 = (curve25519_key_t){.key64 = {
		0x5057A5BE95F70810ULL,
		0x81F76529617E4A4EULL,
		0xE96D0BE7D8BCC124ULL,
		0x4EF0469FADE75A8FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5057A5BE95F70810ULL,
			0x81F76529617E4A4EULL,
			0xE96D0BE7D8BCC124ULL,
			0x4EF0469FADE75A8FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF38C00DCAA89AD74ULL,
			0xFE6E21EE6CD7E512ULL,
			0xE0FCEA6717BAC64CULL,
			0x071609C8E5D3B6FFULL}
		},
		.Z = {.key64 = {
			0xCB1D43FE5B4C1B23ULL,
			0x3561A55506A17DDFULL,
			0x921FBEE7F6E75868ULL,
			0x52882DAD214435C2ULL}
		}
	};
	printf("Test Case 278\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 278 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -278;
	} else {
		printf("Test Case 278 PASSED\n");
	}

	steps = 43;
	X1 = (curve25519_key_t){.key64 = {
		0x0C28DADCE71224A8ULL,
		0x2C2E8580E00CC0F4ULL,
		0x462246F51971814DULL,
		0x6810EA4F89E456DCULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0C28DADCE71224A8ULL,
			0x2C2E8580E00CC0F4ULL,
			0x462246F51971814DULL,
			0x6810EA4F89E456DCULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF9E07A2D213F4B00ULL,
			0x11C99969D63A8CFAULL,
			0x629E1364997E9537ULL,
			0x7EED43857DA5B40CULL}
		},
		.Z = {.key64 = {
			0x904F1F699F28414CULL,
			0xC0CCBA113D08FE8AULL,
			0x0D6497FF327CA4D0ULL,
			0x1579B060F4B38F7DULL}
		}
	};
	printf("Test Case 279\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 279 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -279;
	} else {
		printf("Test Case 279 PASSED\n");
	}

	steps = 62;
	X1 = (curve25519_key_t){.key64 = {
		0x04D32018D7509DC8ULL,
		0x53934656501AA75BULL,
		0x0E9E9677835D37F6ULL,
		0x50B5E6C7A410A33BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x04D32018D7509DC8ULL,
			0x53934656501AA75BULL,
			0x0E9E9677835D37F6ULL,
			0x50B5E6C7A410A33BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5930133EFB594530ULL,
			0xE326085EE6D15471ULL,
			0x34A40B4DAEB59524ULL,
			0x4D2F37FC63A25A84ULL}
		},
		.Z = {.key64 = {
			0x1CA81C77F139D9EEULL,
			0xBC14BA94C94BE4B2ULL,
			0x7EC10EDA605E59BBULL,
			0x1816959942EB9FF9ULL}
		}
	};
	printf("Test Case 280\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 280 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -280;
	} else {
		printf("Test Case 280 PASSED\n");
	}

	steps = 16;
	X1 = (curve25519_key_t){.key64 = {
		0xFDB48D752D53D178ULL,
		0xCA5728182089E145ULL,
		0x349EF39F04BD5D8EULL,
		0x5D999CFD31D3B904ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFDB48D752D53D178ULL,
			0xCA5728182089E145ULL,
			0x349EF39F04BD5D8EULL,
			0x5D999CFD31D3B904ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x81D6AC5F0FC6086DULL,
			0x3C85E8C7CCDA91D2ULL,
			0xDDCFA5DAFF0887B7ULL,
			0x33C68686DD962BF6ULL}
		},
		.Z = {.key64 = {
			0xF257F1BE58ABCBDFULL,
			0x0CACF43414376829ULL,
			0xC24559742ADC3846ULL,
			0x6219E71356096420ULL}
		}
	};
	printf("Test Case 281\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 281 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -281;
	} else {
		printf("Test Case 281 PASSED\n");
	}

	steps = 30;
	X1 = (curve25519_key_t){.key64 = {
		0xCA32D17527DF2800ULL,
		0x3873B6403F54CABDULL,
		0x1ECE8C5D64F77F4FULL,
		0x552B5B57009D106DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCA32D17527DF2800ULL,
			0x3873B6403F54CABDULL,
			0x1ECE8C5D64F77F4FULL,
			0x552B5B57009D106DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x88F06512656D8318ULL,
			0x54F359D8D866EA15ULL,
			0x95A4E7BD2344ECBAULL,
			0x7247B38AF0C6C457ULL}
		},
		.Z = {.key64 = {
			0x7A5B54072D6ECA68ULL,
			0x1BFF97CE14B16FC1ULL,
			0xBEFAAC8FE4472FBDULL,
			0x6C8304A59C63599CULL}
		}
	};
	printf("Test Case 282\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 282 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -282;
	} else {
		printf("Test Case 282 PASSED\n");
	}

	steps = 53;
	X1 = (curve25519_key_t){.key64 = {
		0x0352AE9C8CF7E028ULL,
		0x81E4095E32AB69D7ULL,
		0x6A804CBBCEF5BD24ULL,
		0x753465EC5B59D031ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0352AE9C8CF7E028ULL,
			0x81E4095E32AB69D7ULL,
			0x6A804CBBCEF5BD24ULL,
			0x753465EC5B59D031ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF2253504E57D05FEULL,
			0x2BF4B3260D79FAB3ULL,
			0x9243D6F50106FF42ULL,
			0x0C5ED89CD72E03C9ULL}
		},
		.Z = {.key64 = {
			0xB129933714358EF9ULL,
			0x286B1110C4D1344CULL,
			0x1A325A199BF0F1DBULL,
			0x29BE9B3EE1AF5E08ULL}
		}
	};
	printf("Test Case 283\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 283 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -283;
	} else {
		printf("Test Case 283 PASSED\n");
	}

	steps = 44;
	X1 = (curve25519_key_t){.key64 = {
		0x2648507D23664260ULL,
		0x9614E6FA1BA75714ULL,
		0x70B12EBBC2909F42ULL,
		0x43ABBA0589BC5857ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2648507D23664260ULL,
			0x9614E6FA1BA75714ULL,
			0x70B12EBBC2909F42ULL,
			0x43ABBA0589BC5857ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD1B1749E0F7E7077ULL,
			0xAA931491B7B26467ULL,
			0xBC3F7B89CECAD4D6ULL,
			0x018B4DBCA8C96D86ULL}
		},
		.Z = {.key64 = {
			0x8798266C40101D13ULL,
			0xFA2BBBA638B5B726ULL,
			0x87DC7031C73AFEFCULL,
			0x3B937BF00F40E3E1ULL}
		}
	};
	printf("Test Case 284\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 284 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -284;
	} else {
		printf("Test Case 284 PASSED\n");
	}

	steps = 53;
	X1 = (curve25519_key_t){.key64 = {
		0xB8BCAD4A81B86DA8ULL,
		0x6BFD3EE43E029261ULL,
		0x4658F8BD5B172AE3ULL,
		0x4460924070DE6BC9ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB8BCAD4A81B86DA8ULL,
			0x6BFD3EE43E029261ULL,
			0x4658F8BD5B172AE3ULL,
			0x4460924070DE6BC9ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA2410C4E3E8D8C56ULL,
			0xA42E4F8C2EF7000DULL,
			0x0D74A234BCD6FF7FULL,
			0x5E960115622D0644ULL}
		},
		.Z = {.key64 = {
			0x13E04FB41320C389ULL,
			0x80FFD66AFB2A65E2ULL,
			0xE97B8ECA0765B0AEULL,
			0x71DDCD75FEB6A4BAULL}
		}
	};
	printf("Test Case 285\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 285 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -285;
	} else {
		printf("Test Case 285 PASSED\n");
	}

	steps = 57;
	X1 = (curve25519_key_t){.key64 = {
		0x5B440795FE682E88ULL,
		0x938130243D875DA9ULL,
		0xD641127826ED7275ULL,
		0x7721486ACE80072BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5B440795FE682E88ULL,
			0x938130243D875DA9ULL,
			0xD641127826ED7275ULL,
			0x7721486ACE80072BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5C9E00F13032F589ULL,
			0x92A5728FC64BBCFCULL,
			0x3AE35C1506743BD4ULL,
			0x766CFB0609A82818ULL}
		},
		.Z = {.key64 = {
			0xBCCC934C6A465436ULL,
			0xD3D479F2E97C2920ULL,
			0x7C3F4D37176452B8ULL,
			0x1539367E2F8E1B74ULL}
		}
	};
	printf("Test Case 286\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 286 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -286;
	} else {
		printf("Test Case 286 PASSED\n");
	}

	steps = 49;
	X1 = (curve25519_key_t){.key64 = {
		0x6BFDA487AD2EE308ULL,
		0xB6B8795FFFFFAEB4ULL,
		0x85A1D60EC2EC0B10ULL,
		0x79D6B016B5C0523DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6BFDA487AD2EE308ULL,
			0xB6B8795FFFFFAEB4ULL,
			0x85A1D60EC2EC0B10ULL,
			0x79D6B016B5C0523DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBA5181477AE89818ULL,
			0x2BFA46737A0444D9ULL,
			0xDAA9BC70E76A3B06ULL,
			0x6EF7F387C7B1E5C3ULL}
		},
		.Z = {.key64 = {
			0x8B9BE89DBE8E1A29ULL,
			0x3DE86D79DFF7D9AAULL,
			0x32B272FED5D18F2AULL,
			0x000B59BE364A12B3ULL}
		}
	};
	printf("Test Case 287\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 287 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -287;
	} else {
		printf("Test Case 287 PASSED\n");
	}

	steps = 27;
	X1 = (curve25519_key_t){.key64 = {
		0x65D51E915ECFA550ULL,
		0x48AC77E26E3EC926ULL,
		0xE703E698A9FCA6F0ULL,
		0x74EADDF9979DE9E6ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x65D51E915ECFA550ULL,
			0x48AC77E26E3EC926ULL,
			0xE703E698A9FCA6F0ULL,
			0x74EADDF9979DE9E6ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7A89E4CC12B5432AULL,
			0x68589E8B218E79B7ULL,
			0x1DECBCA5CDBF5523ULL,
			0x02AFFEB3686F5F98ULL}
		},
		.Z = {.key64 = {
			0x5CB03F351530D701ULL,
			0xA1E3BCFD9277F913ULL,
			0xC1A103AB90E580B0ULL,
			0x16243BE23D91E58FULL}
		}
	};
	printf("Test Case 288\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 288 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -288;
	} else {
		printf("Test Case 288 PASSED\n");
	}

	steps = 63;
	X1 = (curve25519_key_t){.key64 = {
		0x760AED216D522D08ULL,
		0x732F7CD0998FC500ULL,
		0xD01C991CDBD520ADULL,
		0x71D03706DDF8A797ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x760AED216D522D08ULL,
			0x732F7CD0998FC500ULL,
			0xD01C991CDBD520ADULL,
			0x71D03706DDF8A797ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3D9983B3FBF876CAULL,
			0x6AE4C79ED5F36B05ULL,
			0x51D2AF2AA80F67A5ULL,
			0x73B9864BEF7ECB51ULL}
		},
		.Z = {.key64 = {
			0x47F49DBCD17086B6ULL,
			0xBD1584B8F2DFDD7CULL,
			0xD4E74A94A96BA8D4ULL,
			0x5DF7AEA38E662E2BULL}
		}
	};
	printf("Test Case 289\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 289 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -289;
	} else {
		printf("Test Case 289 PASSED\n");
	}

	steps = 62;
	X1 = (curve25519_key_t){.key64 = {
		0x9CFFFEC7CB639DB0ULL,
		0x4C87DC5859441AD8ULL,
		0xD4298714B0CB49A4ULL,
		0x672FBCE6D779BD73ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9CFFFEC7CB639DB0ULL,
			0x4C87DC5859441AD8ULL,
			0xD4298714B0CB49A4ULL,
			0x672FBCE6D779BD73ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD686043E52B792D5ULL,
			0x9207820E7782F64DULL,
			0x85C94DBBFBE9625CULL,
			0x70DCA17C1173F4F6ULL}
		},
		.Z = {.key64 = {
			0x08599C86A93161E2ULL,
			0xA10B961E125B9F57ULL,
			0x594D3E403AF87CC8ULL,
			0x0D5D1A5601B3B588ULL}
		}
	};
	printf("Test Case 290\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 290 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -290;
	} else {
		printf("Test Case 290 PASSED\n");
	}

	steps = 45;
	X1 = (curve25519_key_t){.key64 = {
		0xEAFDA365F31390F8ULL,
		0x05E15665593B334EULL,
		0x00D384A5F72E65F3ULL,
		0x6AC9372C8A6DD718ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEAFDA365F31390F8ULL,
			0x05E15665593B334EULL,
			0x00D384A5F72E65F3ULL,
			0x6AC9372C8A6DD718ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB1C1DC370F696F70ULL,
			0x213F6EA517FA5017ULL,
			0x9A3558C6289D8FDAULL,
			0x102FA6A9BA757A67ULL}
		},
		.Z = {.key64 = {
			0x20BDA22737AD8A07ULL,
			0x5B105AFBAD68902BULL,
			0x55023293E836F24BULL,
			0x1BC332E118CDC721ULL}
		}
	};
	printf("Test Case 291\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 291 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -291;
	} else {
		printf("Test Case 291 PASSED\n");
	}

	steps = 23;
	X1 = (curve25519_key_t){.key64 = {
		0xA3AE3CA3DB8909E8ULL,
		0xCE6BC1A0DE4337EDULL,
		0x9E90FA24CD189215ULL,
		0x685D8B33139FE920ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA3AE3CA3DB8909E8ULL,
			0xCE6BC1A0DE4337EDULL,
			0x9E90FA24CD189215ULL,
			0x685D8B33139FE920ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0AC2147B8E60F36EULL,
			0xA2E765DCA1621DFFULL,
			0x45F0E0A4BB5E7FA7ULL,
			0x7662F872E7B7FB99ULL}
		},
		.Z = {.key64 = {
			0x0B2B7B7FCBF0FB52ULL,
			0x8F0D51B1B3335BF8ULL,
			0x74CFB5A48EC34698ULL,
			0x7E9DF64F815FDD35ULL}
		}
	};
	printf("Test Case 292\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 292 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -292;
	} else {
		printf("Test Case 292 PASSED\n");
	}

	steps = 26;
	X1 = (curve25519_key_t){.key64 = {
		0x137574ECB1BFAE70ULL,
		0x7FFA551AD1D69BCBULL,
		0xD8A63C8B4D3BA160ULL,
		0x75F5521303624495ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x137574ECB1BFAE70ULL,
			0x7FFA551AD1D69BCBULL,
			0xD8A63C8B4D3BA160ULL,
			0x75F5521303624495ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7372BFD2074D421FULL,
			0x9AEE2ED6289CD154ULL,
			0xE881A642C174E785ULL,
			0x6934CBD6262ACA06ULL}
		},
		.Z = {.key64 = {
			0x2C62263BD75EE77FULL,
			0xDB999EFBF766E6A5ULL,
			0x570B25D4634B7175ULL,
			0x675B5BD96CFE2CE9ULL}
		}
	};
	printf("Test Case 293\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 293 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -293;
	} else {
		printf("Test Case 293 PASSED\n");
	}

	steps = 33;
	X1 = (curve25519_key_t){.key64 = {
		0x124C47E631CEEA78ULL,
		0xF2E3B7535EFA2A18ULL,
		0x48224285B19995E3ULL,
		0x5F6D40B06552CE2DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x124C47E631CEEA78ULL,
			0xF2E3B7535EFA2A18ULL,
			0x48224285B19995E3ULL,
			0x5F6D40B06552CE2DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE662126511A1154BULL,
			0xDC6E3D09CDB892EEULL,
			0x19B292501D00A61AULL,
			0x26F43AD44DEE864DULL}
		},
		.Z = {.key64 = {
			0x3116981A5AA85B77ULL,
			0x14A2DECB7DFE7F39ULL,
			0x62745E78E0D926BCULL,
			0x135DB3A88306870AULL}
		}
	};
	printf("Test Case 294\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 294 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -294;
	} else {
		printf("Test Case 294 PASSED\n");
	}

	steps = 42;
	X1 = (curve25519_key_t){.key64 = {
		0x498816314E05BA90ULL,
		0xAC0284A91729ACAFULL,
		0x60010CC7849A9CECULL,
		0x5087899D486A2CD4ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x498816314E05BA90ULL,
			0xAC0284A91729ACAFULL,
			0x60010CC7849A9CECULL,
			0x5087899D486A2CD4ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBAAA020DC4043CD7ULL,
			0x93C2AF6C1D122EE9ULL,
			0x58ADFD12DF3422C2ULL,
			0x0F2FE47C796AA12FULL}
		},
		.Z = {.key64 = {
			0xED6CB404F929947BULL,
			0xD083F48E317237D5ULL,
			0xF261D3901A0A5485ULL,
			0x3A99D185DF33913FULL}
		}
	};
	printf("Test Case 295\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 295 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -295;
	} else {
		printf("Test Case 295 PASSED\n");
	}

	steps = 11;
	X1 = (curve25519_key_t){.key64 = {
		0xA96E385410AAD4A8ULL,
		0x64064FD844C4853DULL,
		0x8832C57C2C1687A1ULL,
		0x524BAFC719B3D4D7ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA96E385410AAD4A8ULL,
			0x64064FD844C4853DULL,
			0x8832C57C2C1687A1ULL,
			0x524BAFC719B3D4D7ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE402107F59AF266FULL,
			0xDA231F127897B219ULL,
			0xEE811ECBD41D1F5BULL,
			0x7A8874B0C99EBA73ULL}
		},
		.Z = {.key64 = {
			0x91F744413A56F1C1ULL,
			0x443C8C92CE3B0AB1ULL,
			0xE6109DDDC58885ACULL,
			0x1826C9E33226B425ULL}
		}
	};
	printf("Test Case 296\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 296 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -296;
	} else {
		printf("Test Case 296 PASSED\n");
	}

	steps = 45;
	X1 = (curve25519_key_t){.key64 = {
		0x50CE118B9C28B6F8ULL,
		0x1282F551B376F420ULL,
		0x6536572330BC0424ULL,
		0x5C58921837367157ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x50CE118B9C28B6F8ULL,
			0x1282F551B376F420ULL,
			0x6536572330BC0424ULL,
			0x5C58921837367157ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC7A5DEA3329DFFACULL,
			0x0BB2A2BBF4D0300BULL,
			0xCEA3D20A60629191ULL,
			0x5DBE1A5C5669CBB6ULL}
		},
		.Z = {.key64 = {
			0x5AB73E96F582810FULL,
			0x25B192ED1D22F59AULL,
			0x45E0181CE0883F33ULL,
			0x72CE9CF15F5F22F6ULL}
		}
	};
	printf("Test Case 297\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 297 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -297;
	} else {
		printf("Test Case 297 PASSED\n");
	}

	steps = 29;
	X1 = (curve25519_key_t){.key64 = {
		0x09EEC01085E2FD90ULL,
		0x8CB8FE8785EB6E3AULL,
		0x3FFFDA2D17172663ULL,
		0x60831DA7C55648BDULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x09EEC01085E2FD90ULL,
			0x8CB8FE8785EB6E3AULL,
			0x3FFFDA2D17172663ULL,
			0x60831DA7C55648BDULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5E3D6C040A21A956ULL,
			0xAE044EA3F8FF583EULL,
			0x8A4E8F31EBA58A6AULL,
			0x53FB827B4BD21BFAULL}
		},
		.Z = {.key64 = {
			0xCEDBD194A74ADA23ULL,
			0xA58007F7C246CD5BULL,
			0x553CC9F1F1FC2A7DULL,
			0x39E109566963C814ULL}
		}
	};
	printf("Test Case 298\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 298 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -298;
	} else {
		printf("Test Case 298 PASSED\n");
	}

	steps = 15;
	X1 = (curve25519_key_t){.key64 = {
		0x9523D80F92DB72F8ULL,
		0x2D652DA0FBB35D27ULL,
		0x46ACF472C3EC41F9ULL,
		0x75A1651620BB4BF9ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9523D80F92DB72F8ULL,
			0x2D652DA0FBB35D27ULL,
			0x46ACF472C3EC41F9ULL,
			0x75A1651620BB4BF9ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6041B3BB4807C9EAULL,
			0xD37D6E5C7781CA29ULL,
			0xF6E754FDB205E1B7ULL,
			0x5455C2375F8CF018ULL}
		},
		.Z = {.key64 = {
			0x9F3C2727404A192EULL,
			0x05C4300AD309C3A2ULL,
			0x0E8D9F568E060EB5ULL,
			0x6E4D3EB42BD8AA04ULL}
		}
	};
	printf("Test Case 299\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 299 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -299;
	} else {
		printf("Test Case 299 PASSED\n");
	}

	steps = 34;
	X1 = (curve25519_key_t){.key64 = {
		0x16DCC490A527E370ULL,
		0xA5F1CD79E09C2574ULL,
		0xCE776B82E766A333ULL,
		0x62B3B3507E99B254ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x16DCC490A527E370ULL,
			0xA5F1CD79E09C2574ULL,
			0xCE776B82E766A333ULL,
			0x62B3B3507E99B254ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF78506636F9F94CAULL,
			0xF1893C0DE1C131AAULL,
			0x22428E5D39507203ULL,
			0x53C1CBDE9AC72DDBULL}
		},
		.Z = {.key64 = {
			0x36AADDD3D170AFB5ULL,
			0x7DB594B31487FB78ULL,
			0xE5CEA7AAFEC221DCULL,
			0x30A21842A4E01820ULL}
		}
	};
	printf("Test Case 300\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 300 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -300;
	} else {
		printf("Test Case 300 PASSED\n");
	}

	steps = 61;
	X1 = (curve25519_key_t){.key64 = {
		0xB1EF8B2D61229F88ULL,
		0xCD5572953A95267BULL,
		0xFAB4DF1DFA3B5D94ULL,
		0x50985FBE4DA4F645ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB1EF8B2D61229F88ULL,
			0xCD5572953A95267BULL,
			0xFAB4DF1DFA3B5D94ULL,
			0x50985FBE4DA4F645ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x14C06E2536A84FFDULL,
			0x27D17C362D0D911CULL,
			0x3CF873F0FF9FEC4DULL,
			0x6ED504299D4A8E1CULL}
		},
		.Z = {.key64 = {
			0xE333953712120A74ULL,
			0x2C09756D130B7F3FULL,
			0x4F0D676DA658B6ADULL,
			0x63E6EE3D733B0BEBULL}
		}
	};
	printf("Test Case 301\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 301 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -301;
	} else {
		printf("Test Case 301 PASSED\n");
	}

	steps = 47;
	X1 = (curve25519_key_t){.key64 = {
		0x216C4A8A2D475338ULL,
		0xC73663D69E0691BEULL,
		0x48796C3C3C557106ULL,
		0x6DFBEC8754015CC0ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x216C4A8A2D475338ULL,
			0xC73663D69E0691BEULL,
			0x48796C3C3C557106ULL,
			0x6DFBEC8754015CC0ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7D81AFFB4F8CC09EULL,
			0xD8B2B6896AAB9AF1ULL,
			0x5951D51266D2CD4EULL,
			0x4940A3802D20CDEDULL}
		},
		.Z = {.key64 = {
			0x5518414387524877ULL,
			0xF14D446D85E1FA7AULL,
			0x251C1A5684E646D1ULL,
			0x21E55E9E8E358DBAULL}
		}
	};
	printf("Test Case 302\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 302 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -302;
	} else {
		printf("Test Case 302 PASSED\n");
	}

	steps = 19;
	X1 = (curve25519_key_t){.key64 = {
		0xCAAFFD3F79D8A108ULL,
		0xB8970613D08BCA83ULL,
		0x9F44585AE30FDA39ULL,
		0x4D2705428BC0694EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCAAFFD3F79D8A108ULL,
			0xB8970613D08BCA83ULL,
			0x9F44585AE30FDA39ULL,
			0x4D2705428BC0694EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA5662C63B0ACB4F0ULL,
			0x7DD931ED2323C668ULL,
			0x5CC0C4EF33E15698ULL,
			0x6E305EC52BC88A66ULL}
		},
		.Z = {.key64 = {
			0x8261B91A2D9652A9ULL,
			0xC1EBDD30A42A14ADULL,
			0x489C2A489C21C8E4ULL,
			0x3D2CEDD6927005E7ULL}
		}
	};
	printf("Test Case 303\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 303 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -303;
	} else {
		printf("Test Case 303 PASSED\n");
	}

	steps = 26;
	X1 = (curve25519_key_t){.key64 = {
		0xD969D4BE245A8970ULL,
		0x947BEB8D46B4549CULL,
		0xECEDBEE66710D815ULL,
		0x4E64054182CC040AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD969D4BE245A8970ULL,
			0x947BEB8D46B4549CULL,
			0xECEDBEE66710D815ULL,
			0x4E64054182CC040AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7815E6EB03748D29ULL,
			0x83E782DAD44301B1ULL,
			0x292472D2FA833D11ULL,
			0x25A48778DC40B83AULL}
		},
		.Z = {.key64 = {
			0x839760CED828E868ULL,
			0x1F490C2CEDB9E8F5ULL,
			0xAD7B5C484B26EC7FULL,
			0x164CD20089117EC8ULL}
		}
	};
	printf("Test Case 304\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 304 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -304;
	} else {
		printf("Test Case 304 PASSED\n");
	}

	steps = 2;
	X1 = (curve25519_key_t){.key64 = {
		0x837899170CC5C8F8ULL,
		0xB299E9FDE9439A08ULL,
		0x3B72081D8F6F4746ULL,
		0x57083D98F32BF346ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x837899170CC5C8F8ULL,
			0xB299E9FDE9439A08ULL,
			0x3B72081D8F6F4746ULL,
			0x57083D98F32BF346ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x698718B50D400F09ULL,
			0x495D3AF213CF01C0ULL,
			0xA25D00F0DB188D37ULL,
			0x2A7643947663168BULL}
		},
		.Z = {.key64 = {
			0x221C4746C504FC2FULL,
			0xCB881680C73871D3ULL,
			0xED08D73297B27A7FULL,
			0x7DFE16406CC2E363ULL}
		}
	};
	printf("Test Case 305\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 305 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -305;
	} else {
		printf("Test Case 305 PASSED\n");
	}

	steps = 19;
	X1 = (curve25519_key_t){.key64 = {
		0x374739F83FC402F8ULL,
		0xB8647A15729F50C4ULL,
		0xD33123D883128DD3ULL,
		0x69712F248EEAD1F1ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x374739F83FC402F8ULL,
			0xB8647A15729F50C4ULL,
			0xD33123D883128DD3ULL,
			0x69712F248EEAD1F1ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0AAC2761A9DC80C9ULL,
			0xBC9B55F0099B2E95ULL,
			0xA689A809B581BF0AULL,
			0x4EAA718DD74B95D1ULL}
		},
		.Z = {.key64 = {
			0xBE9AA2BD8B9E826AULL,
			0xA0F662C12FF885C5ULL,
			0x073895F93FB11E12ULL,
			0x2AB4604557EBDCBFULL}
		}
	};
	printf("Test Case 306\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 306 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -306;
	} else {
		printf("Test Case 306 PASSED\n");
	}

	steps = 52;
	X1 = (curve25519_key_t){.key64 = {
		0x83BDFA65CD515210ULL,
		0x56B4377F5CF00D9CULL,
		0x9B0C1E4ABF2A5E7BULL,
		0x4223433B2DCDA0DDULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x83BDFA65CD515210ULL,
			0x56B4377F5CF00D9CULL,
			0x9B0C1E4ABF2A5E7BULL,
			0x4223433B2DCDA0DDULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x34F2C3FE05B9D088ULL,
			0x07C28E9F3D19911CULL,
			0x71B4067F757B2D6EULL,
			0x7479906F2894B905ULL}
		},
		.Z = {.key64 = {
			0xA4ACCC9F7AE36522ULL,
			0x8AE0A05678E67E41ULL,
			0xE175201D85A781B4ULL,
			0x5001A3B9AC92A700ULL}
		}
	};
	printf("Test Case 307\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 307 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -307;
	} else {
		printf("Test Case 307 PASSED\n");
	}

	steps = 37;
	X1 = (curve25519_key_t){.key64 = {
		0x44EBAEED7F784EE8ULL,
		0x32EAD89A395EFDBEULL,
		0x41775A54C57F3DD3ULL,
		0x461A997A10BC2443ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x44EBAEED7F784EE8ULL,
			0x32EAD89A395EFDBEULL,
			0x41775A54C57F3DD3ULL,
			0x461A997A10BC2443ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x41031EBD9F681CD1ULL,
			0xFF44819B6D5F028FULL,
			0x6314E58C916871A0ULL,
			0x77023379B2D68B7AULL}
		},
		.Z = {.key64 = {
			0xCE856CEA6B7D2E31ULL,
			0x9638FFE8DBF9C8A6ULL,
			0x537464BAE727D098ULL,
			0x2276AAC18FF4A907ULL}
		}
	};
	printf("Test Case 308\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 308 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -308;
	} else {
		printf("Test Case 308 PASSED\n");
	}

	steps = 3;
	X1 = (curve25519_key_t){.key64 = {
		0xEB541D4946E3F458ULL,
		0x2A447CEB06AD1A2BULL,
		0x946E35EE952A52B5ULL,
		0x66F90FF9BD0BE1D7ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEB541D4946E3F458ULL,
			0x2A447CEB06AD1A2BULL,
			0x946E35EE952A52B5ULL,
			0x66F90FF9BD0BE1D7ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x11C51CDD17BC3250ULL,
			0x858DB1771396EA1CULL,
			0xA91A53526B3E658AULL,
			0x01DC4D14055584A6ULL}
		},
		.Z = {.key64 = {
			0xB1E1AB4F7036204AULL,
			0x3AA8027C57BE6E92ULL,
			0x1E3D41C2B0BCA619ULL,
			0x198BFDAFCC7E393AULL}
		}
	};
	printf("Test Case 309\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 309 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -309;
	} else {
		printf("Test Case 309 PASSED\n");
	}

	steps = 15;
	X1 = (curve25519_key_t){.key64 = {
		0xE46C3ACD9FB9B2C0ULL,
		0xD78BB66425BB2968ULL,
		0xDB5FDFADB86A032CULL,
		0x7566B475917DBC6BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE46C3ACD9FB9B2C0ULL,
			0xD78BB66425BB2968ULL,
			0xDB5FDFADB86A032CULL,
			0x7566B475917DBC6BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC659430929211F48ULL,
			0x3171C434A450C543ULL,
			0x9512E3731B3A3D22ULL,
			0x0F9F7AB568AD578FULL}
		},
		.Z = {.key64 = {
			0x2327F6E81CBF5415ULL,
			0x00022EC78448E495ULL,
			0x3815AD80BB45615EULL,
			0x515AF2A63ECFF476ULL}
		}
	};
	printf("Test Case 310\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 310 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -310;
	} else {
		printf("Test Case 310 PASSED\n");
	}

	steps = 24;
	X1 = (curve25519_key_t){.key64 = {
		0xB4CB3E3C29014D90ULL,
		0xD54A8872482D58CEULL,
		0x6D7AF5B2770EBFC4ULL,
		0x52B9545F8C78154EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB4CB3E3C29014D90ULL,
			0xD54A8872482D58CEULL,
			0x6D7AF5B2770EBFC4ULL,
			0x52B9545F8C78154EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0EC50F8E93EF5EBBULL,
			0x3AD7E87AE1683624ULL,
			0xC70017FCDB95CDE1ULL,
			0x1F7D1FC487046B2AULL}
		},
		.Z = {.key64 = {
			0xCD3E85A6D10655EBULL,
			0x2009B6D2D46F0D5BULL,
			0x6293DF1F557984AFULL,
			0x395DB834D313C699ULL}
		}
	};
	printf("Test Case 311\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 311 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -311;
	} else {
		printf("Test Case 311 PASSED\n");
	}

	steps = 19;
	X1 = (curve25519_key_t){.key64 = {
		0xBD0FC2C4BFF159D8ULL,
		0xE86AD9CFB7933371ULL,
		0xB66190D37ABFEAEFULL,
		0x63A8BB78FA0D2243ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBD0FC2C4BFF159D8ULL,
			0xE86AD9CFB7933371ULL,
			0xB66190D37ABFEAEFULL,
			0x63A8BB78FA0D2243ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x64093B22FF6C1043ULL,
			0xBB1E8E9BBC534DFBULL,
			0x04107E7C03C83E05ULL,
			0x732910652FC4A72FULL}
		},
		.Z = {.key64 = {
			0x61446D819C6B7A28ULL,
			0x9F51C5C6322C486BULL,
			0x7B28775C83C3F730ULL,
			0x559191FDAE08C05FULL}
		}
	};
	printf("Test Case 312\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 312 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -312;
	} else {
		printf("Test Case 312 PASSED\n");
	}

	steps = 19;
	X1 = (curve25519_key_t){.key64 = {
		0xBEB99009D1C30EC8ULL,
		0xA23EF3F5597EE61BULL,
		0x2B574E880861210AULL,
		0x749E8DB7F424CDCAULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBEB99009D1C30EC8ULL,
			0xA23EF3F5597EE61BULL,
			0x2B574E880861210AULL,
			0x749E8DB7F424CDCAULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3371798D357A8ABAULL,
			0xF5CA6AE5E82B1309ULL,
			0x967C9999CD707859ULL,
			0x560C791391C86593ULL}
		},
		.Z = {.key64 = {
			0x2B14E3F4BCFC9A28ULL,
			0x2305FB655C33698BULL,
			0xF9E10ED0665B22E1ULL,
			0x5281269B9B905817ULL}
		}
	};
	printf("Test Case 313\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 313 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -313;
	} else {
		printf("Test Case 313 PASSED\n");
	}

	steps = 54;
	X1 = (curve25519_key_t){.key64 = {
		0x06DCE8123C873BD0ULL,
		0xEFE14A04837079ECULL,
		0x47A9DA4176BB53A7ULL,
		0x57E4F404BE682A5EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x06DCE8123C873BD0ULL,
			0xEFE14A04837079ECULL,
			0x47A9DA4176BB53A7ULL,
			0x57E4F404BE682A5EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4FE5D719ED06317AULL,
			0xE91F4259D937C94EULL,
			0x5B4C2BAEB37BC2E6ULL,
			0x66525F2AA4BEA759ULL}
		},
		.Z = {.key64 = {
			0x6956355AFC4F219FULL,
			0x147AEF1A955A2133ULL,
			0x1AF9A1E70CF52B97ULL,
			0x38203B3AB2A0749BULL}
		}
	};
	printf("Test Case 314\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 314 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -314;
	} else {
		printf("Test Case 314 PASSED\n");
	}

	steps = 44;
	X1 = (curve25519_key_t){.key64 = {
		0x453A2652854BA5E0ULL,
		0x919B92825B1C8407ULL,
		0xBD8AB1383939DA38ULL,
		0x6D692C16D0B1DD53ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x453A2652854BA5E0ULL,
			0x919B92825B1C8407ULL,
			0xBD8AB1383939DA38ULL,
			0x6D692C16D0B1DD53ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC9EC0E6AD9DE9E81ULL,
			0x5FF6E9A6B7416988ULL,
			0x17A0A8E7AA2C3BB1ULL,
			0x7970995B274C4996ULL}
		},
		.Z = {.key64 = {
			0x465E434A80509139ULL,
			0x40BB8436C9366BE6ULL,
			0xEE6CCC66877669A0ULL,
			0x4109444FD9371929ULL}
		}
	};
	printf("Test Case 315\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 315 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -315;
	} else {
		printf("Test Case 315 PASSED\n");
	}

	steps = 5;
	X1 = (curve25519_key_t){.key64 = {
		0x99B55C6749D5CCF0ULL,
		0xE54FFB48D287785CULL,
		0x51CB9544644C08C0ULL,
		0x5C10EC87EE938F57ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x99B55C6749D5CCF0ULL,
			0xE54FFB48D287785CULL,
			0x51CB9544644C08C0ULL,
			0x5C10EC87EE938F57ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x889CE1771472CB20ULL,
			0xDF1330C8AE968FEDULL,
			0xBADF297924FCF716ULL,
			0x1AEC930974A72AB4ULL}
		},
		.Z = {.key64 = {
			0x0F1D3D1E621A305BULL,
			0x2F84002A0C833140ULL,
			0x5A58A6C4BB616740ULL,
			0x0AC69A535F9886B1ULL}
		}
	};
	printf("Test Case 316\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 316 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -316;
	} else {
		printf("Test Case 316 PASSED\n");
	}

	steps = 13;
	X1 = (curve25519_key_t){.key64 = {
		0x342E61046E4720B0ULL,
		0x863CFACA5B3D47FCULL,
		0x04AD137F496EEBA3ULL,
		0x51425C16293F7829ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x342E61046E4720B0ULL,
			0x863CFACA5B3D47FCULL,
			0x04AD137F496EEBA3ULL,
			0x51425C16293F7829ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9345963DAEEBAA43ULL,
			0xBDD6129E8A626E5AULL,
			0xAEA34AF739E9DB20ULL,
			0x09A7056406CA2B9DULL}
		},
		.Z = {.key64 = {
			0x0D8A3A851798C0C6ULL,
			0xA4DE9F1C8C1560BDULL,
			0x2CEAF14F2B95973AULL,
			0x2087FED83FACBB54ULL}
		}
	};
	printf("Test Case 317\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 317 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -317;
	} else {
		printf("Test Case 317 PASSED\n");
	}

	steps = 7;
	X1 = (curve25519_key_t){.key64 = {
		0x0EDAD4F24D768D90ULL,
		0x5DE8650FE4D4AB3DULL,
		0x3A3C7373FAA5D7BDULL,
		0x7EE3EF7A549F5F67ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0EDAD4F24D768D90ULL,
			0x5DE8650FE4D4AB3DULL,
			0x3A3C7373FAA5D7BDULL,
			0x7EE3EF7A549F5F67ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2944796625BB9FD8ULL,
			0x6DD52B03BCCF6652ULL,
			0xC8E57854805028D9ULL,
			0x1A232B60860CAAAAULL}
		},
		.Z = {.key64 = {
			0x88C6070D04BFC256ULL,
			0x41FC1575B10416E3ULL,
			0x3C957A220DC8857DULL,
			0x7C20341894A1E4C7ULL}
		}
	};
	printf("Test Case 318\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 318 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -318;
	} else {
		printf("Test Case 318 PASSED\n");
	}

	steps = 57;
	X1 = (curve25519_key_t){.key64 = {
		0x4691A56671A09870ULL,
		0x5AC01E75353BB1FBULL,
		0x5ADA171ED7D7300AULL,
		0x640FF4397B0983F3ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4691A56671A09870ULL,
			0x5AC01E75353BB1FBULL,
			0x5ADA171ED7D7300AULL,
			0x640FF4397B0983F3ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4B94509C999588C7ULL,
			0xA41D15B76951CE63ULL,
			0x26AE1C11EAF956ABULL,
			0x3993FFEF1A722ABDULL}
		},
		.Z = {.key64 = {
			0xCFD94ADA99FAD3C5ULL,
			0x97A003C6803E3E52ULL,
			0x95F3FC529AF216F7ULL,
			0x1FFC595E3DDE6360ULL}
		}
	};
	printf("Test Case 319\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 319 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -319;
	} else {
		printf("Test Case 319 PASSED\n");
	}

	steps = 50;
	X1 = (curve25519_key_t){.key64 = {
		0x6A2F98017E7864D8ULL,
		0x8E512B1A530E4EECULL,
		0x5CADF1C689627F85ULL,
		0x639D4A4F4A22FA43ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6A2F98017E7864D8ULL,
			0x8E512B1A530E4EECULL,
			0x5CADF1C689627F85ULL,
			0x639D4A4F4A22FA43ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFB6A7F2F8CF8242DULL,
			0x440D08359C6F1EB7ULL,
			0x75CF80C102C7939CULL,
			0x1C740C7046003987ULL}
		},
		.Z = {.key64 = {
			0x1C6623E7A3895A26ULL,
			0x5693D6DBA1373EC5ULL,
			0xFF5D0880C5377D4CULL,
			0x12B9CF682F71DC45ULL}
		}
	};
	printf("Test Case 320\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 320 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -320;
	} else {
		printf("Test Case 320 PASSED\n");
	}

	steps = 58;
	X1 = (curve25519_key_t){.key64 = {
		0x290E7A14A3710758ULL,
		0x9E1CDD3AECEB86FCULL,
		0xB702A0AA40AFB998ULL,
		0x7B2A48A7460CA3DBULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x290E7A14A3710758ULL,
			0x9E1CDD3AECEB86FCULL,
			0xB702A0AA40AFB998ULL,
			0x7B2A48A7460CA3DBULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x608193E7A4F8B0E7ULL,
			0x1F2E766B43D60CBCULL,
			0xCF084726912FB836ULL,
			0x6D1A95C683C4905DULL}
		},
		.Z = {.key64 = {
			0xB9E2BBA405FE49B5ULL,
			0xD72EA076AF1A1E1BULL,
			0x5820FD712DFF91D8ULL,
			0x23A377ABD61CCE1EULL}
		}
	};
	printf("Test Case 321\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 321 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -321;
	} else {
		printf("Test Case 321 PASSED\n");
	}

	steps = 51;
	X1 = (curve25519_key_t){.key64 = {
		0xCD7DE93BDA2A8738ULL,
		0xA2AA004598D151F7ULL,
		0xBA008DDD13C09502ULL,
		0x4C3BE51DB4003395ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCD7DE93BDA2A8738ULL,
			0xA2AA004598D151F7ULL,
			0xBA008DDD13C09502ULL,
			0x4C3BE51DB4003395ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7402759834FA60A6ULL,
			0xF72FB3350AC8F7D2ULL,
			0x65D2169ADC343825ULL,
			0x28560E20CF750EB8ULL}
		},
		.Z = {.key64 = {
			0x10334A122E597338ULL,
			0x0ACBD3A429313ABAULL,
			0xC970F19F38F1197CULL,
			0x7D65D155EBF494ACULL}
		}
	};
	printf("Test Case 322\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 322 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -322;
	} else {
		printf("Test Case 322 PASSED\n");
	}

	steps = 63;
	X1 = (curve25519_key_t){.key64 = {
		0x8758563F37EB8408ULL,
		0xDA9A4D5237979587ULL,
		0xFB368DF14B11C37CULL,
		0x5F49AB7FF609DEE6ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8758563F37EB8408ULL,
			0xDA9A4D5237979587ULL,
			0xFB368DF14B11C37CULL,
			0x5F49AB7FF609DEE6ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x71AF9929AB5CF965ULL,
			0x291AEF18F473E005ULL,
			0xA2C89D978D25ECB9ULL,
			0x6CDB146FB0D11858ULL}
		},
		.Z = {.key64 = {
			0x83107EFEDC76BECEULL,
			0x0A91253E2DBB4423ULL,
			0x63A3F1E49FB3D50BULL,
			0x752D93980C754473ULL}
		}
	};
	printf("Test Case 323\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 323 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -323;
	} else {
		printf("Test Case 323 PASSED\n");
	}

	steps = 21;
	X1 = (curve25519_key_t){.key64 = {
		0xDE1C35333CF38480ULL,
		0xBFB6AAAC552ADA7EULL,
		0xDD58535A9AEA1F64ULL,
		0x4ED04717B3883A77ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDE1C35333CF38480ULL,
			0xBFB6AAAC552ADA7EULL,
			0xDD58535A9AEA1F64ULL,
			0x4ED04717B3883A77ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3AC46A3EA73C00FFULL,
			0x356EF4B7F21C3024ULL,
			0xD54CFEA4AA3CE323ULL,
			0x2E04711E5DEB3909ULL}
		},
		.Z = {.key64 = {
			0x1B05A8B6855E34AEULL,
			0x1E2ED97A8136C227ULL,
			0xE745A272A5843AF0ULL,
			0x71DE4B3B212CB116ULL}
		}
	};
	printf("Test Case 324\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 324 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -324;
	} else {
		printf("Test Case 324 PASSED\n");
	}

	steps = 31;
	X1 = (curve25519_key_t){.key64 = {
		0xF591ACC7E89E8978ULL,
		0x916C72289369D528ULL,
		0x2A6A8EF3D1B862B4ULL,
		0x5B75FCFE267691DCULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF591ACC7E89E8978ULL,
			0x916C72289369D528ULL,
			0x2A6A8EF3D1B862B4ULL,
			0x5B75FCFE267691DCULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4AED0D996ED173CAULL,
			0xD0D019E431D1D176ULL,
			0x1E21944A5F26BB1EULL,
			0x7984DA97CC7B24D8ULL}
		},
		.Z = {.key64 = {
			0xE284B0B74D368378ULL,
			0x18B52D183853519DULL,
			0xA48F0C3C0434DD02ULL,
			0x62D4D4F6D0874FF8ULL}
		}
	};
	printf("Test Case 325\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 325 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -325;
	} else {
		printf("Test Case 325 PASSED\n");
	}

	steps = 2;
	X1 = (curve25519_key_t){.key64 = {
		0x02315DDB5E50E3D0ULL,
		0x9F01D1EFF2A28964ULL,
		0x09066EB4E703EDC0ULL,
		0x49275919F0AFCF45ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x02315DDB5E50E3D0ULL,
			0x9F01D1EFF2A28964ULL,
			0x09066EB4E703EDC0ULL,
			0x49275919F0AFCF45ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4D047B1A08C8B9A4ULL,
			0x5B519D7FBB455C27ULL,
			0xDB9CD347D8CFD24CULL,
			0x0B329E3CAC519EEFULL}
		},
		.Z = {.key64 = {
			0x980ED3D8C6D389F5ULL,
			0x60D4AC67465641FAULL,
			0x22E25DEB6D526198ULL,
			0x16FF33C76993EA97ULL}
		}
	};
	printf("Test Case 326\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 326 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -326;
	} else {
		printf("Test Case 326 PASSED\n");
	}

	steps = 26;
	X1 = (curve25519_key_t){.key64 = {
		0x60B2135599B91BA8ULL,
		0xFEDC9A864C295394ULL,
		0xAF0D6B9E8502E8FFULL,
		0x48ABE3D54BED3295ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x60B2135599B91BA8ULL,
			0xFEDC9A864C295394ULL,
			0xAF0D6B9E8502E8FFULL,
			0x48ABE3D54BED3295ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD0AB5AC4A0BCBF81ULL,
			0x5E712BD5606554CCULL,
			0x8E8BC5C0FE8CFA96ULL,
			0x1A3E6E79001EA6ACULL}
		},
		.Z = {.key64 = {
			0xD476A71A792F9FBFULL,
			0x04B12477637C0164ULL,
			0x346E0E01E72612F6ULL,
			0x44258EDE0C3607DDULL}
		}
	};
	printf("Test Case 327\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 327 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -327;
	} else {
		printf("Test Case 327 PASSED\n");
	}

	steps = 54;
	X1 = (curve25519_key_t){.key64 = {
		0x15988E58DE74DA48ULL,
		0x258DA69D574031A7ULL,
		0xB6520E796665F5B5ULL,
		0x47CAC9B0B1690D7BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x15988E58DE74DA48ULL,
			0x258DA69D574031A7ULL,
			0xB6520E796665F5B5ULL,
			0x47CAC9B0B1690D7BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x18FA5152DB953628ULL,
			0xDC72A15256817E15ULL,
			0x2ADE87937926279CULL,
			0x1D2BBDE6B2026BB7ULL}
		},
		.Z = {.key64 = {
			0xE710360DEC61E26AULL,
			0xC68A94F0126EB915ULL,
			0x09A3CA74C32D4860ULL,
			0x618FEE646F36C593ULL}
		}
	};
	printf("Test Case 328\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 328 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -328;
	} else {
		printf("Test Case 328 PASSED\n");
	}

	steps = 9;
	X1 = (curve25519_key_t){.key64 = {
		0xFB7D587512AAEC28ULL,
		0xDCC733FBA2D51C42ULL,
		0x85CFAF3A2AFD0980ULL,
		0x6D51565500500B75ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFB7D587512AAEC28ULL,
			0xDCC733FBA2D51C42ULL,
			0x85CFAF3A2AFD0980ULL,
			0x6D51565500500B75ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8D4F2B259E523281ULL,
			0x55AF91F879463F3AULL,
			0x851E6DBBD85CDE2AULL,
			0x5E28E13FBC9B80E7ULL}
		},
		.Z = {.key64 = {
			0x12BEAC41DF2943B9ULL,
			0x998CA693DF762855ULL,
			0xD02180A6ABBE9946ULL,
			0x0E7C480ABDC92A80ULL}
		}
	};
	printf("Test Case 329\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 329 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -329;
	} else {
		printf("Test Case 329 PASSED\n");
	}

	steps = 44;
	X1 = (curve25519_key_t){.key64 = {
		0x00D48E5B0BF1BDC0ULL,
		0x448BBBA486A4F4F0ULL,
		0xDCC5AC1357D255BEULL,
		0x4914C039DB194637ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x00D48E5B0BF1BDC0ULL,
			0x448BBBA486A4F4F0ULL,
			0xDCC5AC1357D255BEULL,
			0x4914C039DB194637ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x171F6DD2BC2873A5ULL,
			0xDE29229BFD512B6DULL,
			0x4B2C0DA784699560ULL,
			0x070B87C3B5BAA342ULL}
		},
		.Z = {.key64 = {
			0xF119F78C38677323ULL,
			0xE7AE8F0424A667ADULL,
			0xBFA61721F58DEEADULL,
			0x2A7002E85B4DC99CULL}
		}
	};
	printf("Test Case 330\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 330 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -330;
	} else {
		printf("Test Case 330 PASSED\n");
	}

	steps = 42;
	X1 = (curve25519_key_t){.key64 = {
		0x6BEC4F6F8C1CB2F8ULL,
		0x2541BD38C9ACB2E3ULL,
		0xD5396AAE3607BA1AULL,
		0x65D832A9543257C8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6BEC4F6F8C1CB2F8ULL,
			0x2541BD38C9ACB2E3ULL,
			0xD5396AAE3607BA1AULL,
			0x65D832A9543257C8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x00EA844793C3DA4BULL,
			0x6808122DBFB32D00ULL,
			0x9F13C9E759A83664ULL,
			0x1EEBA79630E44311ULL}
		},
		.Z = {.key64 = {
			0xA6D99D634B5DBB34ULL,
			0x041A3342E166AA43ULL,
			0x3F8499FB07D928D9ULL,
			0x528868819CA9396DULL}
		}
	};
	printf("Test Case 331\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 331 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -331;
	} else {
		printf("Test Case 331 PASSED\n");
	}

	steps = 34;
	X1 = (curve25519_key_t){.key64 = {
		0xBD873E0E45909898ULL,
		0x6C9C61939DB66149ULL,
		0x2CC2499A3382CB19ULL,
		0x5320BF7E4FFE3789ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBD873E0E45909898ULL,
			0x6C9C61939DB66149ULL,
			0x2CC2499A3382CB19ULL,
			0x5320BF7E4FFE3789ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF1C61C3CD39994FAULL,
			0x8DE8EB4B792D68EEULL,
			0x621DBD9B039195EBULL,
			0x4804C7162B5B985DULL}
		},
		.Z = {.key64 = {
			0xBB80851440EB4772ULL,
			0x0A6D6A388ED5CF3BULL,
			0x44DEFE5ED78BFC69ULL,
			0x346A32036AAFFD62ULL}
		}
	};
	printf("Test Case 332\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 332 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -332;
	} else {
		printf("Test Case 332 PASSED\n");
	}

	steps = 6;
	X1 = (curve25519_key_t){.key64 = {
		0x5B62385055681538ULL,
		0xEC4460FD4496616BULL,
		0x841000EC5EA9D13BULL,
		0x7BB2C730616E27FAULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5B62385055681538ULL,
			0xEC4460FD4496616BULL,
			0x841000EC5EA9D13BULL,
			0x7BB2C730616E27FAULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3A81CCFA43996CC7ULL,
			0x10712F0225AB1452ULL,
			0x43012825121D839AULL,
			0x537566D19F941FADULL}
		},
		.Z = {.key64 = {
			0x65E1F651D5DB44B0ULL,
			0xF06E2B9CB38AF513ULL,
			0x00FE03F0B1FF8386ULL,
			0x73A43EB78BC1734FULL}
		}
	};
	printf("Test Case 333\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 333 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -333;
	} else {
		printf("Test Case 333 PASSED\n");
	}

	steps = 17;
	X1 = (curve25519_key_t){.key64 = {
		0xC839211BFFEB2140ULL,
		0x7B51F85246099C51ULL,
		0x39F892496A6EE6A7ULL,
		0x541A3B76738BF9F9ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC839211BFFEB2140ULL,
			0x7B51F85246099C51ULL,
			0x39F892496A6EE6A7ULL,
			0x541A3B76738BF9F9ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x60349CD309A4F965ULL,
			0x43B40039020B1817ULL,
			0x5059D4999172ADCEULL,
			0x2C2408B373FF79B5ULL}
		},
		.Z = {.key64 = {
			0xC02A397242570C1EULL,
			0x8998AD2C562D0CB8ULL,
			0x0C99E2B460E5455DULL,
			0x2D480A66371AE0ECULL}
		}
	};
	printf("Test Case 334\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 334 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -334;
	} else {
		printf("Test Case 334 PASSED\n");
	}

	steps = 35;
	X1 = (curve25519_key_t){.key64 = {
		0x3F42015330198410ULL,
		0x364C64129D1397A2ULL,
		0x157775EE8631930FULL,
		0x5792813050F6DFEEULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3F42015330198410ULL,
			0x364C64129D1397A2ULL,
			0x157775EE8631930FULL,
			0x5792813050F6DFEEULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0EA27105A358D398ULL,
			0xF59F716DF844A304ULL,
			0x1FC48DBC3636C976ULL,
			0x534755E022A221B0ULL}
		},
		.Z = {.key64 = {
			0x7EB012900D20A932ULL,
			0x0E7CF15E7AF8AEDDULL,
			0x850D31C6B2F0A3FDULL,
			0x1684D210C1BC3C0DULL}
		}
	};
	printf("Test Case 335\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 335 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -335;
	} else {
		printf("Test Case 335 PASSED\n");
	}

	steps = 64;
	X1 = (curve25519_key_t){.key64 = {
		0x2A9454819098A240ULL,
		0xE83F0C6281232D8CULL,
		0x1AC942667E95D898ULL,
		0x57A148C0D1FDD11DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2A9454819098A240ULL,
			0xE83F0C6281232D8CULL,
			0x1AC942667E95D898ULL,
			0x57A148C0D1FDD11DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB12EC1602D429974ULL,
			0xC0BF41B13AA7F551ULL,
			0x5A81CAE421AD6708ULL,
			0x68AE9A90D5406C12ULL}
		},
		.Z = {.key64 = {
			0x0F45E03436F284CDULL,
			0xFB7725AE0549BDB8ULL,
			0xF81E41DEFDEDACCDULL,
			0x01975F7981910738ULL}
		}
	};
	printf("Test Case 336\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 336 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -336;
	} else {
		printf("Test Case 336 PASSED\n");
	}

	steps = 59;
	X1 = (curve25519_key_t){.key64 = {
		0x7C84C84E11231490ULL,
		0x2A6FCF27AFC808C1ULL,
		0xB22FDBABE97A907FULL,
		0x7F5F0D0B9BB1F948ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7C84C84E11231490ULL,
			0x2A6FCF27AFC808C1ULL,
			0xB22FDBABE97A907FULL,
			0x7F5F0D0B9BB1F948ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDA01FF4203AE3656ULL,
			0x2E05E3CAA1521B8CULL,
			0xF8945F2764186379ULL,
			0x73E60B5C7FD1EFCCULL}
		},
		.Z = {.key64 = {
			0xA3092499AD81CC91ULL,
			0x2CF01A361DA450E6ULL,
			0x4C905B392FD53745ULL,
			0x0E63E8A68787DF5AULL}
		}
	};
	printf("Test Case 337\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 337 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -337;
	} else {
		printf("Test Case 337 PASSED\n");
	}

	steps = 62;
	X1 = (curve25519_key_t){.key64 = {
		0xD1B16A7ADDFF70D0ULL,
		0xB37218B850C62FD4ULL,
		0x235D656101EEEB13ULL,
		0x5345BFA98D8F947BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD1B16A7ADDFF70D0ULL,
			0xB37218B850C62FD4ULL,
			0x235D656101EEEB13ULL,
			0x5345BFA98D8F947BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x06B3E39AAE7A3F89ULL,
			0x64D5B0765C089CD7ULL,
			0x9572F35CE3A695CBULL,
			0x424D4D72207F8135ULL}
		},
		.Z = {.key64 = {
			0xCD473C6E08E5B89EULL,
			0xA51398EAB479CC84ULL,
			0xE500C5A7B8FC2F2CULL,
			0x2E05074B48155C4AULL}
		}
	};
	printf("Test Case 338\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 338 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -338;
	} else {
		printf("Test Case 338 PASSED\n");
	}

	steps = 52;
	X1 = (curve25519_key_t){.key64 = {
		0x2D83BEB72CA21560ULL,
		0x016288E4BA63B241ULL,
		0xC0BAC6D3AE7C0D56ULL,
		0x59ED7D73C0497BD5ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2D83BEB72CA21560ULL,
			0x016288E4BA63B241ULL,
			0xC0BAC6D3AE7C0D56ULL,
			0x59ED7D73C0497BD5ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x40B90602EE3F1D65ULL,
			0x898F07206A9485EDULL,
			0x3731A8F4D9C2153FULL,
			0x39552C51CA7CDCCBULL}
		},
		.Z = {.key64 = {
			0x63E4DDF0571E0412ULL,
			0xD4E11CD408FFB6F2ULL,
			0x2806E4FE9470776DULL,
			0x3737706C7C1048F3ULL}
		}
	};
	printf("Test Case 339\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 339 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -339;
	} else {
		printf("Test Case 339 PASSED\n");
	}

	steps = 45;
	X1 = (curve25519_key_t){.key64 = {
		0xC2ACDEB8A7764B98ULL,
		0x4B46765C6E1D5137ULL,
		0x34AC0C1A8A297422ULL,
		0x4C5707E8E4717139ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC2ACDEB8A7764B98ULL,
			0x4B46765C6E1D5137ULL,
			0x34AC0C1A8A297422ULL,
			0x4C5707E8E4717139ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9B774805137A71A9ULL,
			0xE231B7D6174BDE10ULL,
			0x09DD8AE7159EA276ULL,
			0x6442966A9ECA5C30ULL}
		},
		.Z = {.key64 = {
			0x281539F19C7F7F73ULL,
			0x00FEDE2E3F4119C2ULL,
			0x1E5ED999C43922F5ULL,
			0x563239F19F220211ULL}
		}
	};
	printf("Test Case 340\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 340 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -340;
	} else {
		printf("Test Case 340 PASSED\n");
	}

	steps = 25;
	X1 = (curve25519_key_t){.key64 = {
		0x8CA5F6B13B197058ULL,
		0x70A68E314AC9B644ULL,
		0x0811529253E78BB9ULL,
		0x62B7B08FD40C121BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8CA5F6B13B197058ULL,
			0x70A68E314AC9B644ULL,
			0x0811529253E78BB9ULL,
			0x62B7B08FD40C121BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA0214BFAD69F166EULL,
			0x83A9D5DC89F10EA7ULL,
			0xF6EE2E97642E2807ULL,
			0x15DF0BF0386B5FC1ULL}
		},
		.Z = {.key64 = {
			0xC494DDE5FF841638ULL,
			0xFD540C2F46225937ULL,
			0x7C210F51F535EEFAULL,
			0x6E76F1DDE95AE755ULL}
		}
	};
	printf("Test Case 341\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 341 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -341;
	} else {
		printf("Test Case 341 PASSED\n");
	}

	steps = 35;
	X1 = (curve25519_key_t){.key64 = {
		0x370735AF35D3AFE0ULL,
		0x9CF3BA4E97528552ULL,
		0xCE791DE748571225ULL,
		0x75D49B3DA044871CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x370735AF35D3AFE0ULL,
			0x9CF3BA4E97528552ULL,
			0xCE791DE748571225ULL,
			0x75D49B3DA044871CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB22AB3CA885954ACULL,
			0x23C732CE94B99DF5ULL,
			0x80FC502CAB575642ULL,
			0x3BBFB3DD76DCEE31ULL}
		},
		.Z = {.key64 = {
			0xE160AB8F241DCA0BULL,
			0x36B4618897924815ULL,
			0xE5BB2E16D876C93FULL,
			0x1BF80FA2233DE2CCULL}
		}
	};
	printf("Test Case 342\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 342 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -342;
	} else {
		printf("Test Case 342 PASSED\n");
	}

	steps = 11;
	X1 = (curve25519_key_t){.key64 = {
		0xDF084CEFBD0F58D8ULL,
		0xF8EFD56586BC2B10ULL,
		0x8AD2AC86CF2685B5ULL,
		0x6922F9ED9CAFDB5CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDF084CEFBD0F58D8ULL,
			0xF8EFD56586BC2B10ULL,
			0x8AD2AC86CF2685B5ULL,
			0x6922F9ED9CAFDB5CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9C76B0240C5AC11AULL,
			0x7F04A3ECFF9DA1E1ULL,
			0xDD4E3350386C7B81ULL,
			0x1046C7C090F20D17ULL}
		},
		.Z = {.key64 = {
			0x676D46E601226A44ULL,
			0x009FF3C2094682D4ULL,
			0xE168D3F408CAC51BULL,
			0x63D0EDC113F54CB3ULL}
		}
	};
	printf("Test Case 343\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 343 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -343;
	} else {
		printf("Test Case 343 PASSED\n");
	}

	steps = 26;
	X1 = (curve25519_key_t){.key64 = {
		0xCB8ECEB20256A260ULL,
		0xCDD59A949610EB1BULL,
		0x791FDF69D475CF5FULL,
		0x75B67270C991AE48ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCB8ECEB20256A260ULL,
			0xCDD59A949610EB1BULL,
			0x791FDF69D475CF5FULL,
			0x75B67270C991AE48ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0DB5BD68E484988EULL,
			0xC692F5D3C72B9381ULL,
			0x4321732EA302DB42ULL,
			0x2FAC0ED75BFC65FEULL}
		},
		.Z = {.key64 = {
			0x51EA311682ECD7BEULL,
			0x27BDC966024CC8E1ULL,
			0xD880614E56E449EAULL,
			0x231994C480CA5168ULL}
		}
	};
	printf("Test Case 344\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 344 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -344;
	} else {
		printf("Test Case 344 PASSED\n");
	}

	steps = 10;
	X1 = (curve25519_key_t){.key64 = {
		0xC1EB233055274B00ULL,
		0xBE89EE7351E1194BULL,
		0x2E1232971BCE0FA4ULL,
		0x69E568A0CA1CEF98ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC1EB233055274B00ULL,
			0xBE89EE7351E1194BULL,
			0x2E1232971BCE0FA4ULL,
			0x69E568A0CA1CEF98ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4D4ED02025530C86ULL,
			0x8D386E1CD8464471ULL,
			0x53B9DD8A9B52ABB1ULL,
			0x6BB8D1798B505F13ULL}
		},
		.Z = {.key64 = {
			0x4D7C2D5E8C2FE0A5ULL,
			0x544683392AF75D96ULL,
			0x49A3BD8CCA59A65AULL,
			0x3EAB491039543868ULL}
		}
	};
	printf("Test Case 345\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 345 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -345;
	} else {
		printf("Test Case 345 PASSED\n");
	}

	steps = 5;
	X1 = (curve25519_key_t){.key64 = {
		0x0073FE5E4009B170ULL,
		0xE3A654AA15095F27ULL,
		0x9882C6BC5F0482F1ULL,
		0x71037ECDDB7C434EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0073FE5E4009B170ULL,
			0xE3A654AA15095F27ULL,
			0x9882C6BC5F0482F1ULL,
			0x71037ECDDB7C434EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6264178CCFCA633CULL,
			0x0C6670260C968150ULL,
			0x5809B7ED5A53A283ULL,
			0x0C609EDF064654D8ULL}
		},
		.Z = {.key64 = {
			0xDB5706CDB85396EAULL,
			0xA0972018B80EF4B9ULL,
			0xBCBD31DDFFCFFB3FULL,
			0x557DE9BDBF7A9825ULL}
		}
	};
	printf("Test Case 346\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 346 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -346;
	} else {
		printf("Test Case 346 PASSED\n");
	}

	steps = 1;
	X1 = (curve25519_key_t){.key64 = {
		0x18E1672CF51F6EF8ULL,
		0x11C2F55DFF6307F8ULL,
		0x3B9D1FE36B93D6E9ULL,
		0x4D5247D081FB4856ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x18E1672CF51F6EF8ULL,
			0x11C2F55DFF6307F8ULL,
			0x3B9D1FE36B93D6E9ULL,
			0x4D5247D081FB4856ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x51630B6C7122750EULL,
			0xD30413F9E43D4315ULL,
			0xF2E6F09A02950508ULL,
			0x42F68ACF111CC887ULL}
		},
		.Z = {.key64 = {
			0x63859CB3D47DBC06ULL,
			0x470BD577FD8C1FE0ULL,
			0xEE747F8DAE4F5BA4ULL,
			0x35491F4207ED2158ULL}
		}
	};
	printf("Test Case 347\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 347 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -347;
	} else {
		printf("Test Case 347 PASSED\n");
	}

	steps = 9;
	X1 = (curve25519_key_t){.key64 = {
		0x844079AF7749EC50ULL,
		0x18EF88AD1BE3B175ULL,
		0x198D1B4A982BA20EULL,
		0x7181BA6E8A4A3638ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x844079AF7749EC50ULL,
			0x18EF88AD1BE3B175ULL,
			0x198D1B4A982BA20EULL,
			0x7181BA6E8A4A3638ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5B536E2C17814A69ULL,
			0xE1F61764401F05A5ULL,
			0x14EF3B44977B726DULL,
			0x63AD24C8AA07B236ULL}
		},
		.Z = {.key64 = {
			0x086B1F46DFB7C183ULL,
			0xEC6EB7399C48E395ULL,
			0x16C4EF6D7A3AC0AAULL,
			0x5AA8749E05D2A295ULL}
		}
	};
	printf("Test Case 348\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 348 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -348;
	} else {
		printf("Test Case 348 PASSED\n");
	}

	steps = 4;
	X1 = (curve25519_key_t){.key64 = {
		0x0E29B529C6D2DCD8ULL,
		0x546EEC2C8E8A8CEBULL,
		0xC53309D9E5975999ULL,
		0x4A20E1BDD07F044DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0E29B529C6D2DCD8ULL,
			0x546EEC2C8E8A8CEBULL,
			0xC53309D9E5975999ULL,
			0x4A20E1BDD07F044DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA17FB74E32DFD7B7ULL,
			0x31A9DBCE9B78F251ULL,
			0x610C7A70D44DECA4ULL,
			0x3732226DA25D3CC5ULL}
		},
		.Z = {.key64 = {
			0x72B599E32F91584CULL,
			0x799D461CB3BA57B3ULL,
			0x963518FD8D858978ULL,
			0x10E6BB29B375D016ULL}
		}
	};
	printf("Test Case 349\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 349 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -349;
	} else {
		printf("Test Case 349 PASSED\n");
	}

	steps = 13;
	X1 = (curve25519_key_t){.key64 = {
		0xFD7C6A79C88128F8ULL,
		0x39248EA21636DF11ULL,
		0xCDC19924B5B75390ULL,
		0x4EACF19C6038FDD5ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFD7C6A79C88128F8ULL,
			0x39248EA21636DF11ULL,
			0xCDC19924B5B75390ULL,
			0x4EACF19C6038FDD5ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCD9D9F7EFAB0EA8AULL,
			0x036740193BFCA4BFULL,
			0x28AC9AB486B87DF1ULL,
			0x06E03F33E3C6E5D3ULL}
		},
		.Z = {.key64 = {
			0x0CF87E60F1D7ABC6ULL,
			0x458D4A916D137BCFULL,
			0xB4EDCD89724B15B5ULL,
			0x43E2B5A44415F2B0ULL}
		}
	};
	printf("Test Case 350\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 350 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -350;
	} else {
		printf("Test Case 350 PASSED\n");
	}

	steps = 21;
	X1 = (curve25519_key_t){.key64 = {
		0x83B9FD06CCCB03D8ULL,
		0x361FB554AC92D1E3ULL,
		0x59E45556C0877D24ULL,
		0x6F248A1A601B830CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x83B9FD06CCCB03D8ULL,
			0x361FB554AC92D1E3ULL,
			0x59E45556C0877D24ULL,
			0x6F248A1A601B830CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x40CDF6272BE33B7FULL,
			0xDE44B12AC189D65EULL,
			0x5C875CCBD684DDBBULL,
			0x39DF5D1E38B1EE83ULL}
		},
		.Z = {.key64 = {
			0xA07F7003352BADF3ULL,
			0x7C211A590F8948E0ULL,
			0xB99CBF1B56720358ULL,
			0x6966587E361103A1ULL}
		}
	};
	printf("Test Case 351\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 351 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -351;
	} else {
		printf("Test Case 351 PASSED\n");
	}

	steps = 60;
	X1 = (curve25519_key_t){.key64 = {
		0x644E6B38F0713340ULL,
		0x8C177E6CAD6DDBAAULL,
		0x09E35AD2002DFBC2ULL,
		0x6B5CD63A2F6060AFULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x644E6B38F0713340ULL,
			0x8C177E6CAD6DDBAAULL,
			0x09E35AD2002DFBC2ULL,
			0x6B5CD63A2F6060AFULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x61AE23F0391C886FULL,
			0xDA6A90735D851D6FULL,
			0x070BD592018E73B4ULL,
			0x19D50CF029FD7860ULL}
		},
		.Z = {.key64 = {
			0x600786E12912165CULL,
			0x54161C4CE94971AFULL,
			0xD326274E3A117A20ULL,
			0x1963495C5420EBA8ULL}
		}
	};
	printf("Test Case 352\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 352 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -352;
	} else {
		printf("Test Case 352 PASSED\n");
	}

	steps = 17;
	X1 = (curve25519_key_t){.key64 = {
		0x4C11885ECE0170F8ULL,
		0xDD3390651D327291ULL,
		0xD8B557CBB4FEF5ECULL,
		0x5C3BA2EA9E630134ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4C11885ECE0170F8ULL,
			0xDD3390651D327291ULL,
			0xD8B557CBB4FEF5ECULL,
			0x5C3BA2EA9E630134ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6B039952EA9675E8ULL,
			0xC47EC8F16FE1A11CULL,
			0xD16062CF656CF114ULL,
			0x5F57BD3A6D8C43C7ULL}
		},
		.Z = {.key64 = {
			0x947825066849D4F4ULL,
			0x22AA5BD67A828BAEULL,
			0xB8AC21744763251BULL,
			0x32B42AE87C515443ULL}
		}
	};
	printf("Test Case 353\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 353 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -353;
	} else {
		printf("Test Case 353 PASSED\n");
	}

	steps = 30;
	X1 = (curve25519_key_t){.key64 = {
		0xF8C264502B0AF198ULL,
		0x04804D4ACBE50420ULL,
		0x80B8F7439E757181ULL,
		0x4D13F62B90587F9AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF8C264502B0AF198ULL,
			0x04804D4ACBE50420ULL,
			0x80B8F7439E757181ULL,
			0x4D13F62B90587F9AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x41B75595D3106E4BULL,
			0x5BBD1B0697098A7BULL,
			0x0B54485499AF127DULL,
			0x4A7CA8D49583A2F1ULL}
		},
		.Z = {.key64 = {
			0xBDF228185DA09BDFULL,
			0x346ABB8FAA53A479ULL,
			0x1EF6CF39720C532CULL,
			0x48E37AA5423EE27EULL}
		}
	};
	printf("Test Case 354\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 354 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -354;
	} else {
		printf("Test Case 354 PASSED\n");
	}

	steps = 23;
	X1 = (curve25519_key_t){.key64 = {
		0x33D51AF3F485AFF0ULL,
		0x295E26907EB11395ULL,
		0x48ABE48588133DEFULL,
		0x6E1A746993229D38ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x33D51AF3F485AFF0ULL,
			0x295E26907EB11395ULL,
			0x48ABE48588133DEFULL,
			0x6E1A746993229D38ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB890EDD3DAFEAD83ULL,
			0x9E818BE9E3537642ULL,
			0xCEC37C824E8E1CBDULL,
			0x18446A40E9A80331ULL}
		},
		.Z = {.key64 = {
			0xC16361B4EAEB11C7ULL,
			0xD9152D90D669749EULL,
			0x2E92E7CDCC94F2CDULL,
			0x041D3DBF33FB968CULL}
		}
	};
	printf("Test Case 355\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 355 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -355;
	} else {
		printf("Test Case 355 PASSED\n");
	}

	steps = 30;
	X1 = (curve25519_key_t){.key64 = {
		0x1E58B2A7753EA9B8ULL,
		0x19ECFB7E6A8EE844ULL,
		0x01DBC1B00B75B9C7ULL,
		0x658B79C614FFCE3CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1E58B2A7753EA9B8ULL,
			0x19ECFB7E6A8EE844ULL,
			0x01DBC1B00B75B9C7ULL,
			0x658B79C614FFCE3CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE54533D2E227CB76ULL,
			0x3038ABAD7872ED2EULL,
			0x9E02ACF7276DC2D8ULL,
			0x56850E660DCBEC2AULL}
		},
		.Z = {.key64 = {
			0x9AB470E1526094E5ULL,
			0xBCE1B30C05D6F8CEULL,
			0x1ED77890A22DB16CULL,
			0x17265C3DD9EAD2E1ULL}
		}
	};
	printf("Test Case 356\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 356 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -356;
	} else {
		printf("Test Case 356 PASSED\n");
	}

	steps = 51;
	X1 = (curve25519_key_t){.key64 = {
		0xA10DB2F2C6EA30B0ULL,
		0x1A8BCC0DA78F35D6ULL,
		0xA96C4C87034C356BULL,
		0x685124BECDEF57BDULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA10DB2F2C6EA30B0ULL,
			0x1A8BCC0DA78F35D6ULL,
			0xA96C4C87034C356BULL,
			0x685124BECDEF57BDULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA6CA2FFE8B54BFB3ULL,
			0xCF266D1BC2A96301ULL,
			0x598114B2E0860702ULL,
			0x61DE76480934CC5EULL}
		},
		.Z = {.key64 = {
			0x78C2560EA506CF00ULL,
			0x6B2A3E1F44B40A5FULL,
			0x9CCD77E2C0E2CA2EULL,
			0x053A5209C755416CULL}
		}
	};
	printf("Test Case 357\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 357 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -357;
	} else {
		printf("Test Case 357 PASSED\n");
	}

	steps = 15;
	X1 = (curve25519_key_t){.key64 = {
		0x230C6A5351659E68ULL,
		0xBF1030B66D6A8D42ULL,
		0xC233F66CCA9819BEULL,
		0x651364AB8ADDE0E3ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x230C6A5351659E68ULL,
			0xBF1030B66D6A8D42ULL,
			0xC233F66CCA9819BEULL,
			0x651364AB8ADDE0E3ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x078794F3B3180206ULL,
			0xC0AC5DC3F1C210A7ULL,
			0xA883FE9DD7ECCBDDULL,
			0x144CB014585D0D5FULL}
		},
		.Z = {.key64 = {
			0xE02003EF80A7558EULL,
			0x71C3ED291675E39BULL,
			0xD9A062AB96F7D2EBULL,
			0x09633414D63DF928ULL}
		}
	};
	printf("Test Case 358\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 358 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -358;
	} else {
		printf("Test Case 358 PASSED\n");
	}

	steps = 15;
	X1 = (curve25519_key_t){.key64 = {
		0xBCE9BC62D565BEE0ULL,
		0xC9F980E31396B3BCULL,
		0x935660100A3A9898ULL,
		0x63A820E259A0800AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBCE9BC62D565BEE0ULL,
			0xC9F980E31396B3BCULL,
			0x935660100A3A9898ULL,
			0x63A820E259A0800AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC869C547AF288DE6ULL,
			0x26B04227A2753223ULL,
			0x9D8F135A61FA3F02ULL,
			0x0166880F6347A0D6ULL}
		},
		.Z = {.key64 = {
			0x7CD7E713D1B5AB70ULL,
			0x32B3A36FD8CA9217ULL,
			0xBB8A10798A84B09DULL,
			0x2A0FEE7ABADA8021ULL}
		}
	};
	printf("Test Case 359\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 359 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -359;
	} else {
		printf("Test Case 359 PASSED\n");
	}

	steps = 52;
	X1 = (curve25519_key_t){.key64 = {
		0x45A0CA4934EC0568ULL,
		0x31A2589AD1D0A559ULL,
		0x33532920D66AF336ULL,
		0x78122CD2AD362B28ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x45A0CA4934EC0568ULL,
			0x31A2589AD1D0A559ULL,
			0x33532920D66AF336ULL,
			0x78122CD2AD362B28ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1F8C92F421FE234BULL,
			0x1D589D8519446F56ULL,
			0x9B89079729D3AECAULL,
			0x6233DD3F77D550B6ULL}
		},
		.Z = {.key64 = {
			0xADF21007377DE5C7ULL,
			0x58526145998BC75BULL,
			0xB0A96DDD8B59D342ULL,
			0x005C0C0D395B15F0ULL}
		}
	};
	printf("Test Case 360\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 360 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -360;
	} else {
		printf("Test Case 360 PASSED\n");
	}

	steps = 3;
	X1 = (curve25519_key_t){.key64 = {
		0x5A8D493192E2C208ULL,
		0xB4051DD8E8ABDD6AULL,
		0x4ADFE4A3559FA2A8ULL,
		0x686BC8462CC75686ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5A8D493192E2C208ULL,
			0xB4051DD8E8ABDD6AULL,
			0x4ADFE4A3559FA2A8ULL,
			0x686BC8462CC75686ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD36CC358D17D15D0ULL,
			0x48FCAD05F4005DEBULL,
			0x91B4A8A08541377AULL,
			0x0270CE000729215FULL}
		},
		.Z = {.key64 = {
			0x3C6184FA078D6C8AULL,
			0xC7DC0505DA505995ULL,
			0xB33F6E7227D5AF79ULL,
			0x2E3117C9BA2F853BULL}
		}
	};
	printf("Test Case 361\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 361 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -361;
	} else {
		printf("Test Case 361 PASSED\n");
	}

	steps = 49;
	X1 = (curve25519_key_t){.key64 = {
		0x532E7E862B244830ULL,
		0x88EF3EB562D881B1ULL,
		0xC85DF29DCCD5F2DBULL,
		0x56F84D6EFF6459DAULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x532E7E862B244830ULL,
			0x88EF3EB562D881B1ULL,
			0xC85DF29DCCD5F2DBULL,
			0x56F84D6EFF6459DAULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x25BB73506AF4DEB5ULL,
			0x795303D98A1066F2ULL,
			0xEA67A80E75D066B4ULL,
			0x0C990777FC8EC4EBULL}
		},
		.Z = {.key64 = {
			0xDCB0E4229D784E01ULL,
			0x5AE1016B87A6A6D9ULL,
			0xADAA378EE010A92DULL,
			0x0BCB2A1DD37ACCE1ULL}
		}
	};
	printf("Test Case 362\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 362 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -362;
	} else {
		printf("Test Case 362 PASSED\n");
	}

	steps = 46;
	X1 = (curve25519_key_t){.key64 = {
		0x859FF9D3639A2600ULL,
		0x4B220A54E68A595BULL,
		0x2678949832FE5E17ULL,
		0x7992D8FEFBA619BEULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x859FF9D3639A2600ULL,
			0x4B220A54E68A595BULL,
			0x2678949832FE5E17ULL,
			0x7992D8FEFBA619BEULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x38C166F1D57B4BD3ULL,
			0x4CD2B1C4FDAEF626ULL,
			0xBE969A10B9846EC7ULL,
			0x59B4DAA4994D5129ULL}
		},
		.Z = {.key64 = {
			0xA14531526EB60446ULL,
			0xCD1607FD2561C10CULL,
			0xE49A498B474C4997ULL,
			0x65C7E14BEE813B0CULL}
		}
	};
	printf("Test Case 363\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 363 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -363;
	} else {
		printf("Test Case 363 PASSED\n");
	}

	steps = 52;
	X1 = (curve25519_key_t){.key64 = {
		0x42F2BE7456FCB230ULL,
		0x17B7648CFE0ACEB5ULL,
		0x54AF6958BFF6B2D4ULL,
		0x7EE3553B1A2115F8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x42F2BE7456FCB230ULL,
			0x17B7648CFE0ACEB5ULL,
			0x54AF6958BFF6B2D4ULL,
			0x7EE3553B1A2115F8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x37FFD32028C3CFF6ULL,
			0x3960AE579305FAB5ULL,
			0x1B074F3876284B05ULL,
			0x44B38112128D49EDULL}
		},
		.Z = {.key64 = {
			0x9892344DFDC39644ULL,
			0x2BC52624ABF6F506ULL,
			0xE7DC62C560FF232FULL,
			0x0B4AC34DD400D2D4ULL}
		}
	};
	printf("Test Case 364\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 364 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -364;
	} else {
		printf("Test Case 364 PASSED\n");
	}

	steps = 14;
	X1 = (curve25519_key_t){.key64 = {
		0x50418959CDFB1E68ULL,
		0xC8C2384B3491B581ULL,
		0xE1C2AD7DA6978AE5ULL,
		0x70997ECF375C4728ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x50418959CDFB1E68ULL,
			0xC8C2384B3491B581ULL,
			0xE1C2AD7DA6978AE5ULL,
			0x70997ECF375C4728ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF6889152EB887268ULL,
			0xE5CFCCA77578975CULL,
			0x41EAFEA8D779FC71ULL,
			0x5026CD653959AA75ULL}
		},
		.Z = {.key64 = {
			0x97AA5616E5B66D4AULL,
			0x44B437595BF39C29ULL,
			0xA9A496F7D26585B0ULL,
			0x3C90646619EDE6B1ULL}
		}
	};
	printf("Test Case 365\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 365 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -365;
	} else {
		printf("Test Case 365 PASSED\n");
	}

	steps = 43;
	X1 = (curve25519_key_t){.key64 = {
		0x310CB3963040C328ULL,
		0x3213E18AB5493DA9ULL,
		0x32C91E87097D5455ULL,
		0x604D839D47B3EAC5ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x310CB3963040C328ULL,
			0x3213E18AB5493DA9ULL,
			0x32C91E87097D5455ULL,
			0x604D839D47B3EAC5ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x967F415493A9CE99ULL,
			0x2901ED27051C7449ULL,
			0x04C65943AD13861EULL,
			0x6D1829E0D39E618DULL}
		},
		.Z = {.key64 = {
			0xBE0E680157910D0EULL,
			0x9C54CE4AD57ACB01ULL,
			0x569F33645B7D9309ULL,
			0x64334684EBAEDC23ULL}
		}
	};
	printf("Test Case 366\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 366 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -366;
	} else {
		printf("Test Case 366 PASSED\n");
	}

	steps = 30;
	X1 = (curve25519_key_t){.key64 = {
		0xB48CE9B7C3407CC0ULL,
		0x7572BB27031292C8ULL,
		0x9DE11B0C55173B53ULL,
		0x60525DE788287372ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB48CE9B7C3407CC0ULL,
			0x7572BB27031292C8ULL,
			0x9DE11B0C55173B53ULL,
			0x60525DE788287372ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x95B3D9E18803520EULL,
			0x59268E9AD34F1874ULL,
			0x33C97F6E73F83FCAULL,
			0x788AA0C23134A13DULL}
		},
		.Z = {.key64 = {
			0xB5A289EF54DB3C5BULL,
			0x46C9FBC847E159F8ULL,
			0x42EE6E0111FF5CF7ULL,
			0x153FB1E5F51BFA66ULL}
		}
	};
	printf("Test Case 367\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 367 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -367;
	} else {
		printf("Test Case 367 PASSED\n");
	}

	steps = 28;
	X1 = (curve25519_key_t){.key64 = {
		0x3FFFFA1ADE0097F0ULL,
		0x6D2227E5C0173131ULL,
		0xAFC88A9748B477B1ULL,
		0x4D8EC0CEC8782F84ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3FFFFA1ADE0097F0ULL,
			0x6D2227E5C0173131ULL,
			0xAFC88A9748B477B1ULL,
			0x4D8EC0CEC8782F84ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE207268DA76647F7ULL,
			0x4F0CC22E339F19A3ULL,
			0x136C4EA81C0CA3A4ULL,
			0x182A6413A91D7DDDULL}
		},
		.Z = {.key64 = {
			0x14F120542D313AA8ULL,
			0x7B94376CFA5DCADAULL,
			0xE30D1BA541B3E5D4ULL,
			0x16F2B33BF5877B41ULL}
		}
	};
	printf("Test Case 368\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 368 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -368;
	} else {
		printf("Test Case 368 PASSED\n");
	}

	steps = 32;
	X1 = (curve25519_key_t){.key64 = {
		0x4452E34373BC0860ULL,
		0xC88342D9D95532E8ULL,
		0xD5D153D138DFA447ULL,
		0x5823B27EEA27FC8AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4452E34373BC0860ULL,
			0xC88342D9D95532E8ULL,
			0xD5D153D138DFA447ULL,
			0x5823B27EEA27FC8AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD2C3BBF099D653DDULL,
			0x4D32C4799625F499ULL,
			0xBAF4CC191969A592ULL,
			0x3EB61D56837B7FA3ULL}
		},
		.Z = {.key64 = {
			0xF652F3A6107F879DULL,
			0xA7401D81D00DF36BULL,
			0x6BA4350D99C4369EULL,
			0x6CC36F094BBF3CA9ULL}
		}
	};
	printf("Test Case 369\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 369 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -369;
	} else {
		printf("Test Case 369 PASSED\n");
	}

	steps = 3;
	X1 = (curve25519_key_t){.key64 = {
		0xA5B4F95CABC1BE60ULL,
		0x16F38880CBF9BD07ULL,
		0x3F1759A82CD2C155ULL,
		0x71DB355933250F8FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA5B4F95CABC1BE60ULL,
			0x16F38880CBF9BD07ULL,
			0x3F1759A82CD2C155ULL,
			0x71DB355933250F8FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAD843B0FADF136ACULL,
			0xCA518803094EFD36ULL,
			0x78CB914D32907EFBULL,
			0x3C722ABEF0CEA8FDULL}
		},
		.Z = {.key64 = {
			0x6499870FB641FAA4ULL,
			0xDD2209E2D48C8519ULL,
			0x33E974D989EAD1F1ULL,
			0x76DDA72AFF1C9643ULL}
		}
	};
	printf("Test Case 370\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 370 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -370;
	} else {
		printf("Test Case 370 PASSED\n");
	}

	steps = 22;
	X1 = (curve25519_key_t){.key64 = {
		0x8C42A60FB852FB20ULL,
		0x1268235D58E4B2C3ULL,
		0xDCB82D1E697D8005ULL,
		0x6F5EFDA341F164F8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8C42A60FB852FB20ULL,
			0x1268235D58E4B2C3ULL,
			0xDCB82D1E697D8005ULL,
			0x6F5EFDA341F164F8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x59229F3A4E28A75DULL,
			0x91760EE2A498B926ULL,
			0x026C6DE254F477CAULL,
			0x2499DDA74E0C406AULL}
		},
		.Z = {.key64 = {
			0xACC0D924D8A73374ULL,
			0x9DA822250943D719ULL,
			0x5AB26EB6B3374D87ULL,
			0x1A50329CCEE4FBB8ULL}
		}
	};
	printf("Test Case 371\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 371 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -371;
	} else {
		printf("Test Case 371 PASSED\n");
	}

	steps = 11;
	X1 = (curve25519_key_t){.key64 = {
		0x47BB813FD1DD0FA0ULL,
		0x17E6AFD2E95E837BULL,
		0x82A9E0D41052F5E0ULL,
		0x48EB6DC070B2C981ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x47BB813FD1DD0FA0ULL,
			0x17E6AFD2E95E837BULL,
			0x82A9E0D41052F5E0ULL,
			0x48EB6DC070B2C981ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC581D2DE09DDB3C2ULL,
			0xE0FD9813168C0B47ULL,
			0x7E6E5475EEAB9548ULL,
			0x747F29A9DBFC5C00ULL}
		},
		.Z = {.key64 = {
			0xA41AE0A9A5963E84ULL,
			0x7C58F257F9C54915ULL,
			0x3EF6296D617429C5ULL,
			0x5F92A960486056AEULL}
		}
	};
	printf("Test Case 372\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 372 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -372;
	} else {
		printf("Test Case 372 PASSED\n");
	}

	steps = 15;
	X1 = (curve25519_key_t){.key64 = {
		0x351480DF09562010ULL,
		0xD568C39DE5C52D28ULL,
		0x293074409C7CD2EDULL,
		0x5491EFF6DEF7A8CFULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x351480DF09562010ULL,
			0xD568C39DE5C52D28ULL,
			0x293074409C7CD2EDULL,
			0x5491EFF6DEF7A8CFULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF597407FAA775590ULL,
			0xC60DA589DF13A713ULL,
			0x3CAE12B8DB4D2E32ULL,
			0x32A0F04E1BFF21DEULL}
		},
		.Z = {.key64 = {
			0xB01661FD01228A6DULL,
			0xFEC254B26501036EULL,
			0x8D24097F48E8B278ULL,
			0x1D27FE02D14DD6EDULL}
		}
	};
	printf("Test Case 373\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 373 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -373;
	} else {
		printf("Test Case 373 PASSED\n");
	}

	steps = 61;
	X1 = (curve25519_key_t){.key64 = {
		0xC5C385730C8B0438ULL,
		0x017ACC1567AC6D9DULL,
		0x3918973AD672356DULL,
		0x57631E286663724FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC5C385730C8B0438ULL,
			0x017ACC1567AC6D9DULL,
			0x3918973AD672356DULL,
			0x57631E286663724FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x60AF7D6A1F765767ULL,
			0xE33D31428094CD7CULL,
			0xD2926B09479E8DC3ULL,
			0x3AC019594EE09C33ULL}
		},
		.Z = {.key64 = {
			0xD184BEC389F4A735ULL,
			0x1466880C676386CBULL,
			0x5A98DE0EA29C2716ULL,
			0x5AD79DF0BCE07A0FULL}
		}
	};
	printf("Test Case 374\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 374 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -374;
	} else {
		printf("Test Case 374 PASSED\n");
	}

	steps = 38;
	X1 = (curve25519_key_t){.key64 = {
		0x28628367420FED68ULL,
		0x795D340CF343170FULL,
		0x109524B7AE0CB0F8ULL,
		0x7A130FFACB8BD7A3ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x28628367420FED68ULL,
			0x795D340CF343170FULL,
			0x109524B7AE0CB0F8ULL,
			0x7A130FFACB8BD7A3ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB5B023C55282B3EEULL,
			0x8D68D824ABA1A50EULL,
			0xE89B4026F6F925A4ULL,
			0x2B6E0B8836AF45AAULL}
		},
		.Z = {.key64 = {
			0xF47F7506DE89C6C3ULL,
			0xE1FACAB03443D49BULL,
			0x68E822375401CA4AULL,
			0x740979ACCE778CF1ULL}
		}
	};
	printf("Test Case 375\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 375 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -375;
	} else {
		printf("Test Case 375 PASSED\n");
	}

	steps = 11;
	X1 = (curve25519_key_t){.key64 = {
		0xA5B04ACAEFA0D050ULL,
		0x06FD69E88235603FULL,
		0xBEB64E8A4E89F3E1ULL,
		0x7EE4DAD1C45911C0ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA5B04ACAEFA0D050ULL,
			0x06FD69E88235603FULL,
			0xBEB64E8A4E89F3E1ULL,
			0x7EE4DAD1C45911C0ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA7AD91DA491F8AF5ULL,
			0x0A5CB76AFB9CE7D4ULL,
			0x479A82F384C39353ULL,
			0x44F52231241C9DA3ULL}
		},
		.Z = {.key64 = {
			0x9FF044C774D19B60ULL,
			0x61FC3FBF6F57C097ULL,
			0xC3BF0468048A1EAAULL,
			0x6DB5A15FFECEAE26ULL}
		}
	};
	printf("Test Case 376\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 376 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -376;
	} else {
		printf("Test Case 376 PASSED\n");
	}

	steps = 60;
	X1 = (curve25519_key_t){.key64 = {
		0x68B97EE806FEAC80ULL,
		0x9AC2587A7CFB96E2ULL,
		0xDF15DECFE4D25B7AULL,
		0x683C94F22BCE9C78ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x68B97EE806FEAC80ULL,
			0x9AC2587A7CFB96E2ULL,
			0xDF15DECFE4D25B7AULL,
			0x683C94F22BCE9C78ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x537E63963E5539E5ULL,
			0x3DA30D3B47AC9547ULL,
			0xA9BC49B6E1468E7CULL,
			0x01445CEE59F30935ULL}
		},
		.Z = {.key64 = {
			0x81E0CA30AA7A716FULL,
			0x910346CDA77E5E9CULL,
			0xE47422FA3254BB3CULL,
			0x66225A55390243ACULL}
		}
	};
	printf("Test Case 377\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 377 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -377;
	} else {
		printf("Test Case 377 PASSED\n");
	}

	steps = 2;
	X1 = (curve25519_key_t){.key64 = {
		0x4856960C59DFA1D0ULL,
		0xF4E29E08A3028760ULL,
		0x55BBFB6B3815AA24ULL,
		0x462E16BB324A2422ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4856960C59DFA1D0ULL,
			0xF4E29E08A3028760ULL,
			0x55BBFB6B3815AA24ULL,
			0x462E16BB324A2422ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x199EB86E9E5CA304ULL,
			0x69FA653E1CC7C940ULL,
			0xD99AECA977FD91FAULL,
			0x0EEC405D0AC55738ULL}
		},
		.Z = {.key64 = {
			0xF0EE05C74363FFB4ULL,
			0xA0548EF908C23FE0ULL,
			0x43C1899F1801D200ULL,
			0x6A28E47A026E4D3EULL}
		}
	};
	printf("Test Case 378\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 378 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -378;
	} else {
		printf("Test Case 378 PASSED\n");
	}

	steps = 63;
	X1 = (curve25519_key_t){.key64 = {
		0x72853E4C5B8DF040ULL,
		0x5C8CC0F7F20626C1ULL,
		0x57A1FB0DEC6E4C77ULL,
		0x497E1A103BD8080AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x72853E4C5B8DF040ULL,
			0x5C8CC0F7F20626C1ULL,
			0x57A1FB0DEC6E4C77ULL,
			0x497E1A103BD8080AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB739A0643188D116ULL,
			0x1412F55F0F6B40ECULL,
			0x4081AD82BB1E7BF9ULL,
			0x0E773B2C7FF36BE2ULL}
		},
		.Z = {.key64 = {
			0x9BF742A16B653E89ULL,
			0xD87DF3E23928A0B4ULL,
			0xBC29666D80E1253CULL,
			0x02FE0290DA0520E9ULL}
		}
	};
	printf("Test Case 379\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 379 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -379;
	} else {
		printf("Test Case 379 PASSED\n");
	}

	steps = 14;
	X1 = (curve25519_key_t){.key64 = {
		0x9EE29220250DC1B8ULL,
		0x4D2190725E817363ULL,
		0x8245635D468904A6ULL,
		0x79B3A36CDE89539AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9EE29220250DC1B8ULL,
			0x4D2190725E817363ULL,
			0x8245635D468904A6ULL,
			0x79B3A36CDE89539AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB7DA1929F151DBD4ULL,
			0x3F43B53E0F2F3E29ULL,
			0x4D2EEB670FBD1C77ULL,
			0x443AD6FB9F91AA4EULL}
		},
		.Z = {.key64 = {
			0x9BF7EFB112118C8FULL,
			0xC44C80A3BE8FCB2EULL,
			0xFC69FD334AB59F79ULL,
			0x5C4D16D4EFC12A7EULL}
		}
	};
	printf("Test Case 380\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 380 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -380;
	} else {
		printf("Test Case 380 PASSED\n");
	}

	steps = 40;
	X1 = (curve25519_key_t){.key64 = {
		0x75AA59BE1767D2E8ULL,
		0xFD4D41BB552476F6ULL,
		0x9C1CF8A68722B938ULL,
		0x5F726A82FC26A193ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x75AA59BE1767D2E8ULL,
			0xFD4D41BB552476F6ULL,
			0x9C1CF8A68722B938ULL,
			0x5F726A82FC26A193ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x00F0044C15F8A39BULL,
			0x4FBCAFD851AAC360ULL,
			0x922606CAAD064825ULL,
			0x3E7D0CE6B22FDFC1ULL}
		},
		.Z = {.key64 = {
			0x4D26C8826CFFF6B5ULL,
			0x496CD87838299E2AULL,
			0x6EE4BA882C5EE4C1ULL,
			0x7B4B3D5BB20DA207ULL}
		}
	};
	printf("Test Case 381\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 381 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -381;
	} else {
		printf("Test Case 381 PASSED\n");
	}

	steps = 32;
	X1 = (curve25519_key_t){.key64 = {
		0xFE670176F7EF7F48ULL,
		0x47AE74B3A12E1B7EULL,
		0xFD96501FAA5ED313ULL,
		0x6A0A7BD5AC67E471ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFE670176F7EF7F48ULL,
			0x47AE74B3A12E1B7EULL,
			0xFD96501FAA5ED313ULL,
			0x6A0A7BD5AC67E471ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x557F593F02A1060DULL,
			0xDF60B203BB17C374ULL,
			0x01218890DCC7E573ULL,
			0x0AF907B49FA6CA68ULL}
		},
		.Z = {.key64 = {
			0x7F8E4BF048D5444FULL,
			0x97B0F878B7C858B5ULL,
			0x69677EE57C8FC9CFULL,
			0x5E7603035075FF0BULL}
		}
	};
	printf("Test Case 382\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 382 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -382;
	} else {
		printf("Test Case 382 PASSED\n");
	}

	steps = 11;
	X1 = (curve25519_key_t){.key64 = {
		0x96EDDD7FDD279788ULL,
		0x4A8226BC087AFF14ULL,
		0x41E9F80838B8FD5FULL,
		0x71826A34A4799A57ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x96EDDD7FDD279788ULL,
			0x4A8226BC087AFF14ULL,
			0x41E9F80838B8FD5FULL,
			0x71826A34A4799A57ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD9D815FE83E7AB24ULL,
			0xF822DE117D880A74ULL,
			0x9E8EC37E3981B541ULL,
			0x69BE733E2BB7EC0BULL}
		},
		.Z = {.key64 = {
			0x58A3335CEDD038A4ULL,
			0xAE2A881205CC1239ULL,
			0x61A94FFB77B50F44ULL,
			0x516A18DFC3643460ULL}
		}
	};
	printf("Test Case 383\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 383 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -383;
	} else {
		printf("Test Case 383 PASSED\n");
	}

	steps = 59;
	X1 = (curve25519_key_t){.key64 = {
		0x5DBB264F26A05810ULL,
		0x76C4BA309975D168ULL,
		0xA35E6239BBF967D7ULL,
		0x423A37BA0A3E619AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5DBB264F26A05810ULL,
			0x76C4BA309975D168ULL,
			0xA35E6239BBF967D7ULL,
			0x423A37BA0A3E619AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1DCBA019A1A77DF0ULL,
			0x22175EAAAF64F56CULL,
			0xEA4BF314E44AB153ULL,
			0x7DDFDD00FFF4E31EULL}
		},
		.Z = {.key64 = {
			0x094C5BA090079C07ULL,
			0xD28D6FC1C5417290ULL,
			0xB4EC6E30AA0D4885ULL,
			0x07CAEE3094AE7215ULL}
		}
	};
	printf("Test Case 384\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 384 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -384;
	} else {
		printf("Test Case 384 PASSED\n");
	}

	steps = 26;
	X1 = (curve25519_key_t){.key64 = {
		0x8250DC9E659F1680ULL,
		0x1FDA8A120C99BE0DULL,
		0x13CDFE3273C539D0ULL,
		0x67D236A6033CCF2BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8250DC9E659F1680ULL,
			0x1FDA8A120C99BE0DULL,
			0x13CDFE3273C539D0ULL,
			0x67D236A6033CCF2BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4FECB449B96E1861ULL,
			0xE6BCD2BC81184EF6ULL,
			0x8356C1B2414656C6ULL,
			0x71A2F34D67B7B17FULL}
		},
		.Z = {.key64 = {
			0x5D0237DE722CB729ULL,
			0xC62A48ECE48DF124ULL,
			0x57308B0805437D6BULL,
			0x35A42A10DF0D4A03ULL}
		}
	};
	printf("Test Case 385\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 385 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -385;
	} else {
		printf("Test Case 385 PASSED\n");
	}

	steps = 8;
	X1 = (curve25519_key_t){.key64 = {
		0xF8AF516E0B400098ULL,
		0xAC0ACBEA6DFA3A6DULL,
		0xF70C7892F6DAA153ULL,
		0x732351EB3B575977ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF8AF516E0B400098ULL,
			0xAC0ACBEA6DFA3A6DULL,
			0xF70C7892F6DAA153ULL,
			0x732351EB3B575977ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6CB5803E5DD50CC2ULL,
			0x34DA5EC5A73ABE8DULL,
			0x46C837630F3FECA7ULL,
			0x48C97064D31B5AF0ULL}
		},
		.Z = {.key64 = {
			0x5724DC6CC0EC9373ULL,
			0x2820A13FE950D4D1ULL,
			0x511E37C9FCDB1AF9ULL,
			0x018C1A75436B9109ULL}
		}
	};
	printf("Test Case 386\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 386 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -386;
	} else {
		printf("Test Case 386 PASSED\n");
	}

	steps = 16;
	X1 = (curve25519_key_t){.key64 = {
		0xA6768802E8D97F98ULL,
		0xA3A3DB654D17554AULL,
		0x2E8CA2F5A6AB7089ULL,
		0x6D1484575B330DFBULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA6768802E8D97F98ULL,
			0xA3A3DB654D17554AULL,
			0x2E8CA2F5A6AB7089ULL,
			0x6D1484575B330DFBULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEED3EEABD792A61CULL,
			0x4B71AD2060653D15ULL,
			0xD6250F141598F2F3ULL,
			0x0F6324DF38055A10ULL}
		},
		.Z = {.key64 = {
			0xD831EA1343E0E1E6ULL,
			0xA65C42FA2FFFB789ULL,
			0x85C4650DC22B7483ULL,
			0x6E50B4056311CA29ULL}
		}
	};
	printf("Test Case 387\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 387 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -387;
	} else {
		printf("Test Case 387 PASSED\n");
	}

	steps = 54;
	X1 = (curve25519_key_t){.key64 = {
		0x799B79A529A2DD78ULL,
		0x513440A7A06755B3ULL,
		0x30CB8A4F49A7DFA6ULL,
		0x5783E687540BE32FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x799B79A529A2DD78ULL,
			0x513440A7A06755B3ULL,
			0x30CB8A4F49A7DFA6ULL,
			0x5783E687540BE32FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAC6FA34FD4BC0927ULL,
			0x9530C9CB76861713ULL,
			0x38A8441F8F45D0CBULL,
			0x5B483512DA62C889ULL}
		},
		.Z = {.key64 = {
			0xF677E6E4858B05E6ULL,
			0xA6E0F0BC36E2D4A5ULL,
			0xAE34EB9D47C1BC31ULL,
			0x37211DB21384646BULL}
		}
	};
	printf("Test Case 388\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 388 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -388;
	} else {
		printf("Test Case 388 PASSED\n");
	}

	steps = 42;
	X1 = (curve25519_key_t){.key64 = {
		0x49FC2FB314D4E2F0ULL,
		0xDD62A419C11D1041ULL,
		0x55D97037E0E9B457ULL,
		0x775EB0D3CD057382ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x49FC2FB314D4E2F0ULL,
			0xDD62A419C11D1041ULL,
			0x55D97037E0E9B457ULL,
			0x775EB0D3CD057382ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x407FCC55F93A92BDULL,
			0xD6DF1A7089D4D736ULL,
			0x13A4104F73D20B30ULL,
			0x5A78C9F8748A8818ULL}
		},
		.Z = {.key64 = {
			0xF4359B27CA542FDAULL,
			0xFF0872739F1FA834ULL,
			0xB8BD917907B20083ULL,
			0x7927BC32DB6B77F7ULL}
		}
	};
	printf("Test Case 389\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 389 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -389;
	} else {
		printf("Test Case 389 PASSED\n");
	}

	steps = 42;
	X1 = (curve25519_key_t){.key64 = {
		0x2F5C2975456233F0ULL,
		0x5819BCFF95CFD7CFULL,
		0xBF19C39B411C27F7ULL,
		0x6F8ACB1CD55A6A17ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2F5C2975456233F0ULL,
			0x5819BCFF95CFD7CFULL,
			0xBF19C39B411C27F7ULL,
			0x6F8ACB1CD55A6A17ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x77D5F0F5CCBCB2DDULL,
			0xA4FFDDA7FB594315ULL,
			0x5D7C84213DAE0543ULL,
			0x7F7B6413016CED55ULL}
		},
		.Z = {.key64 = {
			0xEF226AF5B2158358ULL,
			0x4DF393D27F5E7E2AULL,
			0x7476431C1687326CULL,
			0x40E953ECBD554256ULL}
		}
	};
	printf("Test Case 390\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 390 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -390;
	} else {
		printf("Test Case 390 PASSED\n");
	}

	steps = 59;
	X1 = (curve25519_key_t){.key64 = {
		0x7A2300D1763CDFC0ULL,
		0xC16746230985FBA0ULL,
		0x789982FBA9B08636ULL,
		0x5F1E68447EA78DDBULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7A2300D1763CDFC0ULL,
			0xC16746230985FBA0ULL,
			0x789982FBA9B08636ULL,
			0x5F1E68447EA78DDBULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA36A8D8FFE99209AULL,
			0xC5F37EB0DD32D0A4ULL,
			0xEF51D4673C08BFC8ULL,
			0x680D2B3DAB73C7FEULL}
		},
		.Z = {.key64 = {
			0x97C3C17BDAA618E0ULL,
			0xA2DD190B31F33255ULL,
			0xCA028932218C5C60ULL,
			0x3645F701691501B5ULL}
		}
	};
	printf("Test Case 391\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 391 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -391;
	} else {
		printf("Test Case 391 PASSED\n");
	}

	steps = 43;
	X1 = (curve25519_key_t){.key64 = {
		0x9670BD1773665850ULL,
		0x1698735F243E4E9AULL,
		0x7378E867F6D598E9ULL,
		0x5104B5F1C2818D3DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9670BD1773665850ULL,
			0x1698735F243E4E9AULL,
			0x7378E867F6D598E9ULL,
			0x5104B5F1C2818D3DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD9605878BFC257E2ULL,
			0x5498CF7B38D9E79CULL,
			0x5D9B94DE640B8D66ULL,
			0x32953E19827D7AF4ULL}
		},
		.Z = {.key64 = {
			0x17AEDA97FD7E65F4ULL,
			0x5EB2CAEA9B0BBC85ULL,
			0x6E7A9DBF5EE220FCULL,
			0x5215F7093BC15412ULL}
		}
	};
	printf("Test Case 392\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 392 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -392;
	} else {
		printf("Test Case 392 PASSED\n");
	}

	steps = 23;
	X1 = (curve25519_key_t){.key64 = {
		0x46A0D5F132000FA8ULL,
		0x7116B12AB9F7A864ULL,
		0x12B3A1472D39FF41ULL,
		0x5C8FD2FEE89AA740ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x46A0D5F132000FA8ULL,
			0x7116B12AB9F7A864ULL,
			0x12B3A1472D39FF41ULL,
			0x5C8FD2FEE89AA740ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x32FA27818D19F955ULL,
			0xD89E17AD69A18795ULL,
			0xFBD452FCB1FD8D5DULL,
			0x3FAD6767354EAD84ULL}
		},
		.Z = {.key64 = {
			0x902AD52257D82D65ULL,
			0x20D35D19E0CEDAD8ULL,
			0xC6CEC8CDFF8DC27FULL,
			0x4A963F3FA9725F4DULL}
		}
	};
	printf("Test Case 393\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 393 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -393;
	} else {
		printf("Test Case 393 PASSED\n");
	}

	steps = 37;
	X1 = (curve25519_key_t){.key64 = {
		0x42356DDF63F6BE80ULL,
		0x1FEC24EF1317A348ULL,
		0x76C78605D400C29AULL,
		0x7F25B69BAACF93FBULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x42356DDF63F6BE80ULL,
			0x1FEC24EF1317A348ULL,
			0x76C78605D400C29AULL,
			0x7F25B69BAACF93FBULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAB8A15C16C7C7009ULL,
			0x0439AF8EFA10748CULL,
			0x983819A275DD68BFULL,
			0x70B5634991BD7945ULL}
		},
		.Z = {.key64 = {
			0x606223B3F120C519ULL,
			0x711F59F9A9A46A0DULL,
			0xC64AD3ABE308A56FULL,
			0x3B03BE20BFF17C39ULL}
		}
	};
	printf("Test Case 394\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 394 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -394;
	} else {
		printf("Test Case 394 PASSED\n");
	}

	steps = 1;
	X1 = (curve25519_key_t){.key64 = {
		0x28DA88DCB60F5568ULL,
		0x4A04842875B56B81ULL,
		0x5927B0703DF796F6ULL,
		0x6F5FA1CC6AA22C2EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x28DA88DCB60F5568ULL,
			0x4A04842875B56B81ULL,
			0x5927B0703DF796F6ULL,
			0x6F5FA1CC6AA22C2EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6697A623AEF7C9E5ULL,
			0xB7E9F934ECAAF1E5ULL,
			0x149EF8B52F501DA9ULL,
			0x4DA5CE11F6850A48ULL}
		},
		.Z = {.key64 = {
			0xA36A2372D83D55D9ULL,
			0x281210A1D6D5AE04ULL,
			0x649EC1C0F7DE5BD9ULL,
			0x3D7E8731AA88B0B9ULL}
		}
	};
	printf("Test Case 395\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 395 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -395;
	} else {
		printf("Test Case 395 PASSED\n");
	}

	steps = 39;
	X1 = (curve25519_key_t){.key64 = {
		0x41243C3A307C8E58ULL,
		0x0852AC4F42E00F64ULL,
		0x45489EAFD15264A5ULL,
		0x48A64F84C7D41B13ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x41243C3A307C8E58ULL,
			0x0852AC4F42E00F64ULL,
			0x45489EAFD15264A5ULL,
			0x48A64F84C7D41B13ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2872C6771DEE703EULL,
			0xEA955006A7D5A394ULL,
			0x44AD6EFFBDAEC15BULL,
			0x745DA806DF488452ULL}
		},
		.Z = {.key64 = {
			0x3E12B834A23B2DD7ULL,
			0x2F9CC991FF9BE563ULL,
			0x8856F3055B59E682ULL,
			0x0141D6F0554FF413ULL}
		}
	};
	printf("Test Case 396\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 396 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -396;
	} else {
		printf("Test Case 396 PASSED\n");
	}

	steps = 8;
	X1 = (curve25519_key_t){.key64 = {
		0xA8512402A38A7380ULL,
		0xD03E1422517A00F1ULL,
		0x9F0D5B3BCAE8C86DULL,
		0x4791C03D698FC126ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA8512402A38A7380ULL,
			0xD03E1422517A00F1ULL,
			0x9F0D5B3BCAE8C86DULL,
			0x4791C03D698FC126ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x45257B3997E1AB9BULL,
			0x76ACED39790D9D24ULL,
			0x5151E5713178EC9BULL,
			0x1D53E3E8A375058BULL}
		},
		.Z = {.key64 = {
			0x515B9B7D142C4FF4ULL,
			0x6E75A14AB99DEE86ULL,
			0x0EAC29102B01CBC1ULL,
			0x1C19F8388B91F6D0ULL}
		}
	};
	printf("Test Case 397\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 397 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -397;
	} else {
		printf("Test Case 397 PASSED\n");
	}

	steps = 10;
	X1 = (curve25519_key_t){.key64 = {
		0x8DBE37CAD4ED6238ULL,
		0x2D245D98030D8848ULL,
		0x49A44555D6C0B21CULL,
		0x405FDCB7DBA40101ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8DBE37CAD4ED6238ULL,
			0x2D245D98030D8848ULL,
			0x49A44555D6C0B21CULL,
			0x405FDCB7DBA40101ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x66AD54459D1DAD96ULL,
			0x125C3331C0965730ULL,
			0xF3D977F46B6D888DULL,
			0x3E739A6296801562ULL}
		},
		.Z = {.key64 = {
			0x29CE0B192DE36F92ULL,
			0xBC7FF5035F5EFAACULL,
			0x023DF99BC475ADCCULL,
			0x78B0FC0C0C6F174FULL}
		}
	};
	printf("Test Case 398\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 398 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -398;
	} else {
		printf("Test Case 398 PASSED\n");
	}

	steps = 19;
	X1 = (curve25519_key_t){.key64 = {
		0x57AB73AF237065D8ULL,
		0x003AE09562E26777ULL,
		0x07502117BDBF3980ULL,
		0x52E12DCE7A055B7BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x57AB73AF237065D8ULL,
			0x003AE09562E26777ULL,
			0x07502117BDBF3980ULL,
			0x52E12DCE7A055B7BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4035860D40ED793AULL,
			0xEEDB66EA3A2B8D47ULL,
			0xA6FBBF1372ECA8FDULL,
			0x1210F6AA22DFE381ULL}
		},
		.Z = {.key64 = {
			0x97EFE38A5E045BD8ULL,
			0x06B35E550A3E9512ULL,
			0x413B03A446C64B2EULL,
			0x144C54845F290E0AULL}
		}
	};
	printf("Test Case 399\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 399 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -399;
	} else {
		printf("Test Case 399 PASSED\n");
	}

	steps = 33;
	X1 = (curve25519_key_t){.key64 = {
		0x38C6FFD05EFE5588ULL,
		0x65A44C74356DB539ULL,
		0x4DFCDBBC844761F7ULL,
		0x563B57ADADF8A014ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x38C6FFD05EFE5588ULL,
			0x65A44C74356DB539ULL,
			0x4DFCDBBC844761F7ULL,
			0x563B57ADADF8A014ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD03C2FF7D614E0ACULL,
			0xA5BD6DC038966BBDULL,
			0x6AEF39A914499821ULL,
			0x463EB600370E26AEULL}
		},
		.Z = {.key64 = {
			0xB09782E8E86C45C9ULL,
			0xA9F528758E7989B5ULL,
			0x6E83475C838CA0CBULL,
			0x2D5BE29DF14AC43FULL}
		}
	};
	printf("Test Case 400\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 400 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -400;
	} else {
		printf("Test Case 400 PASSED\n");
	}

	steps = 26;
	X1 = (curve25519_key_t){.key64 = {
		0x0D94A7B20D393A20ULL,
		0x9F2A52CD9ABC21DBULL,
		0x0F579B42444D9D42ULL,
		0x6889A37EEF56983CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0D94A7B20D393A20ULL,
			0x9F2A52CD9ABC21DBULL,
			0x0F579B42444D9D42ULL,
			0x6889A37EEF56983CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2BD57BDB6D9AE37AULL,
			0x67880EB8F8C64932ULL,
			0x9A85977274527D00ULL,
			0x4CC399BC05C0BFD0ULL}
		},
		.Z = {.key64 = {
			0x6ADD00383D161203ULL,
			0xE8AFD8C3452ABF36ULL,
			0x0D5A11ACA109D724ULL,
			0x0CE5C1E6FFE4CFC2ULL}
		}
	};
	printf("Test Case 401\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 401 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -401;
	} else {
		printf("Test Case 401 PASSED\n");
	}

	steps = 48;
	X1 = (curve25519_key_t){.key64 = {
		0x765B7208617BE1B8ULL,
		0x8EE48F5E5994BB8DULL,
		0xFF6DE0D39508B06CULL,
		0x55D2D9BD509A4EE2ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x765B7208617BE1B8ULL,
			0x8EE48F5E5994BB8DULL,
			0xFF6DE0D39508B06CULL,
			0x55D2D9BD509A4EE2ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x687307FB392E7F72ULL,
			0xAC328EEB1C0FE072ULL,
			0x4EE20D2635E4B3CCULL,
			0x731AFA3A33C008DBULL}
		},
		.Z = {.key64 = {
			0x782741FE480A5592ULL,
			0xA59671F74BB7BB24ULL,
			0x92A5DF4FB07CA9F6ULL,
			0x758AF54E8F7B1345ULL}
		}
	};
	printf("Test Case 402\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 402 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -402;
	} else {
		printf("Test Case 402 PASSED\n");
	}

	steps = 27;
	X1 = (curve25519_key_t){.key64 = {
		0x91C8980D995A4AA0ULL,
		0x31927DC536A94871ULL,
		0x0A70EC5F861F06AAULL,
		0x6822FEF3F9C13494ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x91C8980D995A4AA0ULL,
			0x31927DC536A94871ULL,
			0x0A70EC5F861F06AAULL,
			0x6822FEF3F9C13494ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6CA3A55E058FA32AULL,
			0xCEE27A330F81C955ULL,
			0x84BD10ACB4980C77ULL,
			0x31A0EF9764F0F89FULL}
		},
		.Z = {.key64 = {
			0x86F10F9A0D33B17EULL,
			0x1BA2A443F2886C51ULL,
			0xD5B800B01C652387ULL,
			0x5D1C4C0877C0F42BULL}
		}
	};
	printf("Test Case 403\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 403 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -403;
	} else {
		printf("Test Case 403 PASSED\n");
	}

	steps = 56;
	X1 = (curve25519_key_t){.key64 = {
		0x19925D6F2DC23E00ULL,
		0x37823C7AA414C636ULL,
		0xB59C25830B7EDA00ULL,
		0x49AFBB42448E19FFULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x19925D6F2DC23E00ULL,
			0x37823C7AA414C636ULL,
			0xB59C25830B7EDA00ULL,
			0x49AFBB42448E19FFULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF6676B997F80083AULL,
			0xE62F8F6DEB3D755AULL,
			0x509F15D4082EE011ULL,
			0x01C9C87B2F7E0B1FULL}
		},
		.Z = {.key64 = {
			0x04352EB0CA008388ULL,
			0x5DB4A2BA3954037DULL,
			0x8B94D6D1E4A00B4DULL,
			0x6C946D551195D551ULL}
		}
	};
	printf("Test Case 404\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 404 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -404;
	} else {
		printf("Test Case 404 PASSED\n");
	}

	steps = 3;
	X1 = (curve25519_key_t){.key64 = {
		0x63EA65DFA6287918ULL,
		0x5CD537CA213385EAULL,
		0xBA85820DCBD6DC2FULL,
		0x7F2A7668F1D4FBA1ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x63EA65DFA6287918ULL,
			0x5CD537CA213385EAULL,
			0xBA85820DCBD6DC2FULL,
			0x7F2A7668F1D4FBA1ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5F8B4F74BA9740E5ULL,
			0x1E6FA0AF90CE75FEULL,
			0x23F8BF9FB8EBB08AULL,
			0x7BEBD02876214CECULL}
		},
		.Z = {.key64 = {
			0x9515930E4969E4CAULL,
			0x9BF0A46469048F08ULL,
			0xE48BD19D20C019C2ULL,
			0x1103C849E6CD53CCULL}
		}
	};
	printf("Test Case 405\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 405 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -405;
	} else {
		printf("Test Case 405 PASSED\n");
	}

	steps = 59;
	X1 = (curve25519_key_t){.key64 = {
		0x9388C7DF466F9AA0ULL,
		0x4CF21F1F3A28C5A6ULL,
		0xDFCD55773245D398ULL,
		0x5F5D5C5ABE95EAB3ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9388C7DF466F9AA0ULL,
			0x4CF21F1F3A28C5A6ULL,
			0xDFCD55773245D398ULL,
			0x5F5D5C5ABE95EAB3ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAB7043702B0CFEBCULL,
			0xB16C21D64636B0D2ULL,
			0x9565F97184DA0DBCULL,
			0x763C9091AB5CDF3FULL}
		},
		.Z = {.key64 = {
			0x4DFE4FE8C512865FULL,
			0x528635DAB82BCC50ULL,
			0x3FBD46A67A6CD7E8ULL,
			0x787A742A69640A7FULL}
		}
	};
	printf("Test Case 406\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 406 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -406;
	} else {
		printf("Test Case 406 PASSED\n");
	}

	steps = 4;
	X1 = (curve25519_key_t){.key64 = {
		0x064F4D9C2A76D7C0ULL,
		0x3B6199EB4298752BULL,
		0x1CAFA8CAD83B4DEFULL,
		0x56EB5C8EAE238568ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x064F4D9C2A76D7C0ULL,
			0x3B6199EB4298752BULL,
			0x1CAFA8CAD83B4DEFULL,
			0x56EB5C8EAE238568ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x24D2D2DDA97DAE26ULL,
			0x907EADD4181D12E2ULL,
			0x61AF6EF01062BB5FULL,
			0x6F038222DBE29129ULL}
		},
		.Z = {.key64 = {
			0x86CE5B9D820D28E3ULL,
			0xEE7E2F6FA1B67809ULL,
			0x2E45563875021C76ULL,
			0x5DF530DB9ACCB65AULL}
		}
	};
	printf("Test Case 407\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 407 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -407;
	} else {
		printf("Test Case 407 PASSED\n");
	}

	steps = 63;
	X1 = (curve25519_key_t){.key64 = {
		0x328DE7B411FEB548ULL,
		0x5F15E115225E0035ULL,
		0x8F5E611A0E47396FULL,
		0x62CE5C7102597DCDULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x328DE7B411FEB548ULL,
			0x5F15E115225E0035ULL,
			0x8F5E611A0E47396FULL,
			0x62CE5C7102597DCDULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7743BB9EF1C2957DULL,
			0xC33B148C26EBDC76ULL,
			0x2ADAAD52D86F6B1EULL,
			0x2BEE0213AFD9BDD4ULL}
		},
		.Z = {.key64 = {
			0x0C726E476380E2E7ULL,
			0x89F89E701215AE91ULL,
			0xA6059466EB3ABBB9ULL,
			0x187D584C1D770CC6ULL}
		}
	};
	printf("Test Case 408\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 408 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -408;
	} else {
		printf("Test Case 408 PASSED\n");
	}

	steps = 4;
	X1 = (curve25519_key_t){.key64 = {
		0x8133529F6A3DC9A0ULL,
		0xD8F78DCAF5E3A9D8ULL,
		0xB770A2F38C595E70ULL,
		0x4CCD7A8A5262ABA7ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8133529F6A3DC9A0ULL,
			0xD8F78DCAF5E3A9D8ULL,
			0xB770A2F38C595E70ULL,
			0x4CCD7A8A5262ABA7ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2E420FCFADC7CF47ULL,
			0x9DA2D0F3F486359DULL,
			0x573E0C69F4C55766ULL,
			0x4FE1F9D6A2A600B7ULL}
		},
		.Z = {.key64 = {
			0x07610C144F54552DULL,
			0x099FFEECE4CA2F98ULL,
			0x477A376E69EDD93CULL,
			0x2CD3210D7AE2B748ULL}
		}
	};
	printf("Test Case 409\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 409 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -409;
	} else {
		printf("Test Case 409 PASSED\n");
	}

	steps = 44;
	X1 = (curve25519_key_t){.key64 = {
		0xD7CA76F292CB49F0ULL,
		0xF43C59F1A8B5F97CULL,
		0xF20AEDA79197BD64ULL,
		0x6CF4546D947BD51EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD7CA76F292CB49F0ULL,
			0xF43C59F1A8B5F97CULL,
			0xF20AEDA79197BD64ULL,
			0x6CF4546D947BD51EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x24BD83EB821FEAAAULL,
			0x6650A941500291E9ULL,
			0xEE80CBEB4CAE944AULL,
			0x24FB4BAB38D49979ULL}
		},
		.Z = {.key64 = {
			0x041AF61CCDB77C87ULL,
			0xB384B7B5575FDA09ULL,
			0xB502BD416FD445E6ULL,
			0x1F167D419302588BULL}
		}
	};
	printf("Test Case 410\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 410 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -410;
	} else {
		printf("Test Case 410 PASSED\n");
	}

	steps = 14;
	X1 = (curve25519_key_t){.key64 = {
		0x30DAEC1A2E074138ULL,
		0x26450C6E082AB766ULL,
		0xE891DB101CCBE6F8ULL,
		0x7DBA935A9C883CD2ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x30DAEC1A2E074138ULL,
			0x26450C6E082AB766ULL,
			0xE891DB101CCBE6F8ULL,
			0x7DBA935A9C883CD2ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0CF5649E5BAA5CF4ULL,
			0x673A4EF69E91CD20ULL,
			0x1E4ABC2B7AA4CFF2ULL,
			0x7642AA4D57601FC8ULL}
		},
		.Z = {.key64 = {
			0x5369B9BC046A5E18ULL,
			0x738EB5710AD12DB3ULL,
			0xC3207DC150D86B69ULL,
			0x66E26FE626FA385BULL}
		}
	};
	printf("Test Case 411\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 411 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -411;
	} else {
		printf("Test Case 411 PASSED\n");
	}

	steps = 31;
	X1 = (curve25519_key_t){.key64 = {
		0x83CA1B6B3661FF28ULL,
		0x43D19CBCB74CDE3BULL,
		0x50429DF1F0084DAFULL,
		0x767CBB38919275E1ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x83CA1B6B3661FF28ULL,
			0x43D19CBCB74CDE3BULL,
			0x50429DF1F0084DAFULL,
			0x767CBB38919275E1ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2B0BA3AC49261364ULL,
			0x816F0EA8870883DDULL,
			0x2172E1F83DB32E14ULL,
			0x6964359E97768AF2ULL}
		},
		.Z = {.key64 = {
			0x71C79FC78C36420DULL,
			0xCB0E4027C1808735ULL,
			0xE18B3B2F05D3515CULL,
			0x029D05DDFFF321CAULL}
		}
	};
	printf("Test Case 412\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 412 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -412;
	} else {
		printf("Test Case 412 PASSED\n");
	}

	steps = 51;
	X1 = (curve25519_key_t){.key64 = {
		0xBEEF604B6D68B0D0ULL,
		0x662B77788640A237ULL,
		0xAEB1C21E9742042CULL,
		0x5A18033F59EA036FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBEEF604B6D68B0D0ULL,
			0x662B77788640A237ULL,
			0xAEB1C21E9742042CULL,
			0x5A18033F59EA036FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x277126FB27E6EB77ULL,
			0x9711204C0B104700ULL,
			0x0C56BBB233CAFEC5ULL,
			0x63675722EA7C8AA5ULL}
		},
		.Z = {.key64 = {
			0xB0264E24135A27F2ULL,
			0x25B4429BE33AEF79ULL,
			0xF16D42661AA603C3ULL,
			0x780E5BD233A74A46ULL}
		}
	};
	printf("Test Case 413\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 413 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -413;
	} else {
		printf("Test Case 413 PASSED\n");
	}

	steps = 50;
	X1 = (curve25519_key_t){.key64 = {
		0x7278ED67292D02C8ULL,
		0x0E2A0A93BA28F094ULL,
		0x65CBB41D1BB94B3AULL,
		0x60B3BACE3288B5DCULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7278ED67292D02C8ULL,
			0x0E2A0A93BA28F094ULL,
			0x65CBB41D1BB94B3AULL,
			0x60B3BACE3288B5DCULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB0234204C6F2DDF1ULL,
			0xEAF76EBAD8E36E4EULL,
			0x6AF230C5583E17BDULL,
			0x2E5BB408E0B6F2B3ULL}
		},
		.Z = {.key64 = {
			0xF605069FB5ECDE9AULL,
			0x8F0C4BCC06D072FCULL,
			0x08F18438CD3FB800ULL,
			0x7E8BEF7FE6E2C086ULL}
		}
	};
	printf("Test Case 414\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 414 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -414;
	} else {
		printf("Test Case 414 PASSED\n");
	}

	steps = 4;
	X1 = (curve25519_key_t){.key64 = {
		0x8B5F7B58B9907A40ULL,
		0x43CEBF4B1969AE0CULL,
		0xC83090FF981B9242ULL,
		0x734A064B4EF6FD76ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8B5F7B58B9907A40ULL,
			0x43CEBF4B1969AE0CULL,
			0xC83090FF981B9242ULL,
			0x734A064B4EF6FD76ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEC1937C4434967ADULL,
			0xC325460336197E39ULL,
			0x654A7DA3CBE61540ULL,
			0x033E4E58931C5958ULL}
		},
		.Z = {.key64 = {
			0xC7B1C817329C7286ULL,
			0xD0F59D2AB2E0C25EULL,
			0xB9C8C956501DE6E3ULL,
			0x76DF302DAA0D174EULL}
		}
	};
	printf("Test Case 415\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 415 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -415;
	} else {
		printf("Test Case 415 PASSED\n");
	}

	steps = 13;
	X1 = (curve25519_key_t){.key64 = {
		0xC4F94BEDE451FAA8ULL,
		0x6C5116C576093F1AULL,
		0x1674F07BC9A816DDULL,
		0x50C8BD829D4B4E71ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC4F94BEDE451FAA8ULL,
			0x6C5116C576093F1AULL,
			0x1674F07BC9A816DDULL,
			0x50C8BD829D4B4E71ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA5D6B8FF4B92488BULL,
			0x36788A8D0A077CFCULL,
			0x7F631276AFE0AFCFULL,
			0x4FF6043323F8D8FBULL}
		},
		.Z = {.key64 = {
			0x8EB6BA7C558F8892ULL,
			0x1C61C6F7E177AE47ULL,
			0x532416C583F8782CULL,
			0x58075B3609513528ULL}
		}
	};
	printf("Test Case 416\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 416 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -416;
	} else {
		printf("Test Case 416 PASSED\n");
	}

	steps = 34;
	X1 = (curve25519_key_t){.key64 = {
		0x8380E5B11F800E10ULL,
		0xFC92C93E02AD409FULL,
		0xA1FB174AA3B57BEDULL,
		0x7D5DF5445486B2C4ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8380E5B11F800E10ULL,
			0xFC92C93E02AD409FULL,
			0xA1FB174AA3B57BEDULL,
			0x7D5DF5445486B2C4ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD0DE7FDB8CFC85EBULL,
			0x4823CCB14B12A730ULL,
			0x4DCA1AE8C9747D52ULL,
			0x7E82A7E7872C2632ULL}
		},
		.Z = {.key64 = {
			0x9C9355F0E42BB78BULL,
			0x3AB99EC514900333ULL,
			0x21730C58CF1B81B3ULL,
			0x567D8C317BEE51E0ULL}
		}
	};
	printf("Test Case 417\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 417 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -417;
	} else {
		printf("Test Case 417 PASSED\n");
	}

	steps = 54;
	X1 = (curve25519_key_t){.key64 = {
		0x8CB1F7596464A070ULL,
		0x2F4D4F7326713389ULL,
		0xB4DD3E0F16102923ULL,
		0x7E966E936134333CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8CB1F7596464A070ULL,
			0x2F4D4F7326713389ULL,
			0xB4DD3E0F16102923ULL,
			0x7E966E936134333CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD0A5B6B3B724E81CULL,
			0x0C2923F51F255990ULL,
			0xFEBE00563D8408E1ULL,
			0x7F682B344AD60064ULL}
		},
		.Z = {.key64 = {
			0xA9115A556E31FDE5ULL,
			0x60FFE17EF3AC3985ULL,
			0xBBF79A126EE47A51ULL,
			0x75CDA07A7882F1B3ULL}
		}
	};
	printf("Test Case 418\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 418 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -418;
	} else {
		printf("Test Case 418 PASSED\n");
	}

	steps = 37;
	X1 = (curve25519_key_t){.key64 = {
		0xB0F4876203A6C900ULL,
		0x29E6D7CED353AE77ULL,
		0x156665CBF20BDCAEULL,
		0x5E5248141154FEDDULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB0F4876203A6C900ULL,
			0x29E6D7CED353AE77ULL,
			0x156665CBF20BDCAEULL,
			0x5E5248141154FEDDULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x06C9D77A352CD50CULL,
			0x2EA0F9D1F17915FAULL,
			0x5B1B462911A17384ULL,
			0x7F62D3F7932C9792ULL}
		},
		.Z = {.key64 = {
			0x6A85002477D2C758ULL,
			0x8B5C5F28C880B086ULL,
			0x3873420668AFB40DULL,
			0x558292E37464BE46ULL}
		}
	};
	printf("Test Case 419\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 419 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -419;
	} else {
		printf("Test Case 419 PASSED\n");
	}

	steps = 58;
	X1 = (curve25519_key_t){.key64 = {
		0x1EAC5BE37520FB28ULL,
		0x736B8194D8AF495FULL,
		0xB9AEDC6CF7EF80D5ULL,
		0x45FF4E0778AFF9C0ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1EAC5BE37520FB28ULL,
			0x736B8194D8AF495FULL,
			0xB9AEDC6CF7EF80D5ULL,
			0x45FF4E0778AFF9C0ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3EAED7059FEC6C9AULL,
			0x9DCFE098490F0729ULL,
			0x7F96F70B75684558ULL,
			0x33B678A57EC1DBC0ULL}
		},
		.Z = {.key64 = {
			0xB298BF59F336BAFDULL,
			0x682E569942EB7A48ULL,
			0x1BFE391D9BAF0908ULL,
			0x751394AB3224D98EULL}
		}
	};
	printf("Test Case 420\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 420 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -420;
	} else {
		printf("Test Case 420 PASSED\n");
	}

	steps = 6;
	X1 = (curve25519_key_t){.key64 = {
		0xC867ABBD6FC6E070ULL,
		0xDCFEE09DA08A9B08ULL,
		0xF5167C1418A2D6DEULL,
		0x770F7773AA5FD743ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC867ABBD6FC6E070ULL,
			0xDCFEE09DA08A9B08ULL,
			0xF5167C1418A2D6DEULL,
			0x770F7773AA5FD743ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7884DE33B7651381ULL,
			0x68C0D8659F88ACC7ULL,
			0xE9979D2F96EA8E6BULL,
			0x142E069842C98CC5ULL}
		},
		.Z = {.key64 = {
			0x18D9D34038C3186EULL,
			0x52D52C93CF22C631ULL,
			0xA3BB978F8CCB16B9ULL,
			0x5FB4D0AAFB45A134ULL}
		}
	};
	printf("Test Case 421\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 421 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -421;
	} else {
		printf("Test Case 421 PASSED\n");
	}

	steps = 39;
	X1 = (curve25519_key_t){.key64 = {
		0x63DAB42B18B0BCC8ULL,
		0x6FC06742B5970404ULL,
		0xE2479817EE213046ULL,
		0x4F3F6096849FB0A5ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x63DAB42B18B0BCC8ULL,
			0x6FC06742B5970404ULL,
			0xE2479817EE213046ULL,
			0x4F3F6096849FB0A5ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF20B8992EC7962C9ULL,
			0xCE29A00D5C5E2512ULL,
			0x77249CD2677DE976ULL,
			0x36CC8F4E244F27BBULL}
		},
		.Z = {.key64 = {
			0x5D8F3172BF80D5FAULL,
			0x39E9B5728641760BULL,
			0xCFDB2A0375E55249ULL,
			0x69BBECF4ADCD4642ULL}
		}
	};
	printf("Test Case 422\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 422 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -422;
	} else {
		printf("Test Case 422 PASSED\n");
	}

	steps = 42;
	X1 = (curve25519_key_t){.key64 = {
		0xA56F54E11AA45340ULL,
		0xCCB7B872E6263180ULL,
		0xC27A0B0FB52F920BULL,
		0x7935C016AC120DE1ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA56F54E11AA45340ULL,
			0xCCB7B872E6263180ULL,
			0xC27A0B0FB52F920BULL,
			0x7935C016AC120DE1ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x12ED6CE2D22AEFFCULL,
			0x1EC3E571F909BDFEULL,
			0x6D4E94AFA27B0020ULL,
			0x3A0A5FB08FAF8C9EULL}
		},
		.Z = {.key64 = {
			0x272BF7BBFEA9D75CULL,
			0xDD471ACD0EF13DFDULL,
			0x0BD5DE19610508B2ULL,
			0x0A109E90BB5E0ECBULL}
		}
	};
	printf("Test Case 423\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 423 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -423;
	} else {
		printf("Test Case 423 PASSED\n");
	}

	steps = 54;
	X1 = (curve25519_key_t){.key64 = {
		0x1E6084F6C9048A80ULL,
		0x6BF277D1AA78DC77ULL,
		0x93CD6CFCBC169023ULL,
		0x72E4700F2E28B878ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1E6084F6C9048A80ULL,
			0x6BF277D1AA78DC77ULL,
			0x93CD6CFCBC169023ULL,
			0x72E4700F2E28B878ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC03AE35D22673A87ULL,
			0x49A0EE88DA1F25EDULL,
			0x1E39658F73DF82D9ULL,
			0x626DF9183E99DCF6ULL}
		},
		.Z = {.key64 = {
			0x82C72104B422D330ULL,
			0x92B5C17E20E56A2FULL,
			0x051499BC12E3168BULL,
			0x2B8C8534A0ADF1DDULL}
		}
	};
	printf("Test Case 424\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 424 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -424;
	} else {
		printf("Test Case 424 PASSED\n");
	}

	steps = 54;
	X1 = (curve25519_key_t){.key64 = {
		0x3F0D6C35150B9778ULL,
		0x9933E91331510309ULL,
		0x57A940D68DC13449ULL,
		0x6ED3F9EA1047CFE1ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3F0D6C35150B9778ULL,
			0x9933E91331510309ULL,
			0x57A940D68DC13449ULL,
			0x6ED3F9EA1047CFE1ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2403DA2740D3282AULL,
			0x81A755E07721FA14ULL,
			0x675C412BF83A596DULL,
			0x2077E0147A63B8DAULL}
		},
		.Z = {.key64 = {
			0x9615F39465EB1960ULL,
			0x02019B1E60F1746DULL,
			0x42F0A626B801069EULL,
			0x7599943577AA33FFULL}
		}
	};
	printf("Test Case 425\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 425 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -425;
	} else {
		printf("Test Case 425 PASSED\n");
	}

	steps = 10;
	X1 = (curve25519_key_t){.key64 = {
		0xDB56706754B5E048ULL,
		0x0D13B027B0CA309CULL,
		0xD31789A0E86A377DULL,
		0x52955E878481EA1CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDB56706754B5E048ULL,
			0x0D13B027B0CA309CULL,
			0xD31789A0E86A377DULL,
			0x52955E878481EA1CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x48C6C08CE7768A95ULL,
			0xB9C59A4EF11D487FULL,
			0x1280671BDBBBFD69ULL,
			0x7C7B694B9CD8DE73ULL}
		},
		.Z = {.key64 = {
			0x494B90A6071985A3ULL,
			0x5B10F1EB701126D6ULL,
			0xD7F4DD5B99DFA358ULL,
			0x7E4781AAE5DBC721ULL}
		}
	};
	printf("Test Case 426\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 426 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -426;
	} else {
		printf("Test Case 426 PASSED\n");
	}

	steps = 63;
	X1 = (curve25519_key_t){.key64 = {
		0x5501E9C5E4008520ULL,
		0x5C040F41A2638EF8ULL,
		0x05E40502DCAA68C4ULL,
		0x756EB5FB2C231B5EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5501E9C5E4008520ULL,
			0x5C040F41A2638EF8ULL,
			0x05E40502DCAA68C4ULL,
			0x756EB5FB2C231B5EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3FFB2FE1A0455585ULL,
			0x88985B04E4F615ECULL,
			0xE525B333F0092732ULL,
			0x5ABF9A902A5407F2ULL}
		},
		.Z = {.key64 = {
			0x293087A297772F3EULL,
			0xA0F39839F9C06A86ULL,
			0x5A5777436168C155ULL,
			0x4573EE3002823EDBULL}
		}
	};
	printf("Test Case 427\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 427 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -427;
	} else {
		printf("Test Case 427 PASSED\n");
	}

	steps = 53;
	X1 = (curve25519_key_t){.key64 = {
		0x7ADFBC7E96797140ULL,
		0x368B7F4DE54D9031ULL,
		0xC4B6C67D3F34749EULL,
		0x651C73BC997F8A47ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7ADFBC7E96797140ULL,
			0x368B7F4DE54D9031ULL,
			0xC4B6C67D3F34749EULL,
			0x651C73BC997F8A47ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x52DE44FE7E6A6214ULL,
			0x8FAB59C059FFBB60ULL,
			0xAB11A25F28902F1EULL,
			0x0449698E3BCF5D83ULL}
		},
		.Z = {.key64 = {
			0x320E497143A52B04ULL,
			0x9C306D10570AD25CULL,
			0xF9406F512D5EED14ULL,
			0x272CB3FE2B38A7A9ULL}
		}
	};
	printf("Test Case 428\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 428 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -428;
	} else {
		printf("Test Case 428 PASSED\n");
	}

	steps = 58;
	X1 = (curve25519_key_t){.key64 = {
		0xC5CCC9A865B2C998ULL,
		0x3269110A21A7D334ULL,
		0x96C230258CE25456ULL,
		0x77033B4D870FE609ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC5CCC9A865B2C998ULL,
			0x3269110A21A7D334ULL,
			0x96C230258CE25456ULL,
			0x77033B4D870FE609ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x242693989C7DFA7AULL,
			0xEA6BB321CEE830E1ULL,
			0xD1EB397B06884733ULL,
			0x015B5806DCB0066BULL}
		},
		.Z = {.key64 = {
			0x72F6EB8478AC664CULL,
			0x461C16B04453A568ULL,
			0x40AA10BB4830B53DULL,
			0x5F369B0D572603DBULL}
		}
	};
	printf("Test Case 429\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 429 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -429;
	} else {
		printf("Test Case 429 PASSED\n");
	}

	steps = 42;
	X1 = (curve25519_key_t){.key64 = {
		0x6D9A086AEFF54FA8ULL,
		0x68075FCCB783D029ULL,
		0x19B2473F893CCE2EULL,
		0x4CF18CFD91E2EE88ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6D9A086AEFF54FA8ULL,
			0x68075FCCB783D029ULL,
			0x19B2473F893CCE2EULL,
			0x4CF18CFD91E2EE88ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x508A250D5F399EFDULL,
			0x5B6517E6F36148A5ULL,
			0x261B9BB8E2BCEB81ULL,
			0x484834E433E6AB6FULL}
		},
		.Z = {.key64 = {
			0x2F238FD3E1298BFBULL,
			0x01E1DEF192A6A539ULL,
			0x991505C8D0876EEAULL,
			0x3D14500C59F9810EULL}
		}
	};
	printf("Test Case 430\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 430 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -430;
	} else {
		printf("Test Case 430 PASSED\n");
	}

	steps = 39;
	X1 = (curve25519_key_t){.key64 = {
		0x5236664212163418ULL,
		0xE91CA3E0461F03BAULL,
		0xB996DC1C90964CA1ULL,
		0x783DC1D955842E3CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5236664212163418ULL,
			0xE91CA3E0461F03BAULL,
			0xB996DC1C90964CA1ULL,
			0x783DC1D955842E3CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA2E8A0573D9DAE90ULL,
			0x55060AD2625DDDE0ULL,
			0x9BA3C15B62E5110BULL,
			0x15FF49A8C33B887FULL}
		},
		.Z = {.key64 = {
			0x828DC0DC0268B08AULL,
			0x26C720C33519F3A4ULL,
			0x5223B9B8907C6A72ULL,
			0x78974D356D5BDE9EULL}
		}
	};
	printf("Test Case 431\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 431 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -431;
	} else {
		printf("Test Case 431 PASSED\n");
	}

	steps = 51;
	X1 = (curve25519_key_t){.key64 = {
		0x44ABF811A54C6070ULL,
		0xECB6872D4E49B5E0ULL,
		0x232B536B5C56195BULL,
		0x47E4B696BF4B2B26ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x44ABF811A54C6070ULL,
			0xECB6872D4E49B5E0ULL,
			0x232B536B5C56195BULL,
			0x47E4B696BF4B2B26ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE8A563F0BCF636EEULL,
			0x8739316B7B1B9F01ULL,
			0x562C25ACF67593BEULL,
			0x5EFE8FD0B344776BULL}
		},
		.Z = {.key64 = {
			0x8EC4546466F7BD91ULL,
			0x92542472F5BA4E59ULL,
			0x181EE656A56B2B44ULL,
			0x7EE1CAF4DC113591ULL}
		}
	};
	printf("Test Case 432\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 432 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -432;
	} else {
		printf("Test Case 432 PASSED\n");
	}

	steps = 19;
	X1 = (curve25519_key_t){.key64 = {
		0xFE8B33A4DEA72D50ULL,
		0xFE531793C5998E5FULL,
		0x69490A3B31736518ULL,
		0x523DC041F25D75C1ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFE8B33A4DEA72D50ULL,
			0xFE531793C5998E5FULL,
			0x69490A3B31736518ULL,
			0x523DC041F25D75C1ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCC8D926BBF4D30CAULL,
			0xAA676FD79DDDB30CULL,
			0xE77A2ACD1E2B4A54ULL,
			0x1F8F23C74B69255EULL}
		},
		.Z = {.key64 = {
			0x447FAB017814AAAFULL,
			0x4B6A2AB1C8599347ULL,
			0xD3FA503FCD7353D3ULL,
			0x1D128F9B2B04AF22ULL}
		}
	};
	printf("Test Case 433\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 433 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -433;
	} else {
		printf("Test Case 433 PASSED\n");
	}

	steps = 51;
	X1 = (curve25519_key_t){.key64 = {
		0x15992DAA76302CF0ULL,
		0x9BB5F615B4C942B2ULL,
		0x373E41CD293C8FBAULL,
		0x401C8AE5FCABB51BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x15992DAA76302CF0ULL,
			0x9BB5F615B4C942B2ULL,
			0x373E41CD293C8FBAULL,
			0x401C8AE5FCABB51BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF381CDEAC4CB92C2ULL,
			0x16D1884F03784ACBULL,
			0x3C6F8DB5A252511FULL,
			0x586AE15911D2FEB0ULL}
		},
		.Z = {.key64 = {
			0x7E60E960353427E8ULL,
			0xC3EAE48BC63E67F0ULL,
			0xF1E6BC8FD1263462ULL,
			0x259E5E271467FAC3ULL}
		}
	};
	printf("Test Case 434\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 434 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -434;
	} else {
		printf("Test Case 434 PASSED\n");
	}

	steps = 42;
	X1 = (curve25519_key_t){.key64 = {
		0x15715416DBA0E0A0ULL,
		0x72881CA918646E52ULL,
		0xD97ED354BF21884BULL,
		0x437A017A6E7F1206ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x15715416DBA0E0A0ULL,
			0x72881CA918646E52ULL,
			0xD97ED354BF21884BULL,
			0x437A017A6E7F1206ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB5B23C4FD16D4388ULL,
			0xB772D45F63704D70ULL,
			0x24265646F9BD2304ULL,
			0x4E37745CA2A65E7FULL}
		},
		.Z = {.key64 = {
			0x3866D7FF85997BC4ULL,
			0xF3F1BA3B29726555ULL,
			0x434D26832FD90854ULL,
			0x62F6E7D403BEB1E9ULL}
		}
	};
	printf("Test Case 435\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 435 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -435;
	} else {
		printf("Test Case 435 PASSED\n");
	}

	steps = 60;
	X1 = (curve25519_key_t){.key64 = {
		0xF263F431B3AB9B80ULL,
		0x4450FE77E517BC18ULL,
		0x764B07EFA7834179ULL,
		0x6C2B875D910F5413ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF263F431B3AB9B80ULL,
			0x4450FE77E517BC18ULL,
			0x764B07EFA7834179ULL,
			0x6C2B875D910F5413ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7482622DCA3797AAULL,
			0xD3795FEA3CC15998ULL,
			0xEF87E13E253E1765ULL,
			0x35101519FDC11F48ULL}
		},
		.Z = {.key64 = {
			0x30A6F6B85217B56CULL,
			0x99A1FCB7A9884A42ULL,
			0xF7FD7AC1807F9408ULL,
			0x2D9253D795FF8428ULL}
		}
	};
	printf("Test Case 436\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 436 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -436;
	} else {
		printf("Test Case 436 PASSED\n");
	}

	steps = 30;
	X1 = (curve25519_key_t){.key64 = {
		0x94679C4EAFFFD180ULL,
		0xC979E6CBE647756CULL,
		0xFE68C4802380F926ULL,
		0x56351B6497A88406ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x94679C4EAFFFD180ULL,
			0xC979E6CBE647756CULL,
			0xFE68C4802380F926ULL,
			0x56351B6497A88406ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6F63D1E3FD8F8D2DULL,
			0xCE5DAFCB4AE1463EULL,
			0xA351B28B8BB7DFD2ULL,
			0x11B09ABC09012195ULL}
		},
		.Z = {.key64 = {
			0x280061109DFAFBCBULL,
			0x3D01B9D2F3F818C7ULL,
			0x8B1409EE32950D1BULL,
			0x36B05D8AEEE38D12ULL}
		}
	};
	printf("Test Case 437\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 437 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -437;
	} else {
		printf("Test Case 437 PASSED\n");
	}

	steps = 1;
	X1 = (curve25519_key_t){.key64 = {
		0x81A6154C8D5E77E8ULL,
		0x688C04576CF38E2EULL,
		0xE57EC1605715EDF1ULL,
		0x7DC4645BE5C77C8AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x81A6154C8D5E77E8ULL,
			0x688C04576CF38E2EULL,
			0xE57EC1605715EDF1ULL,
			0x7DC4645BE5C77C8AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFAEFAF5E77712D9DULL,
			0x7FB73783C32DCD9BULL,
			0x1EDBA965D6B2AA3CULL,
			0x148F391E2AFEACC2ULL}
		},
		.Z = {.key64 = {
			0x069855323579DFD9ULL,
			0xA230115DB3CE38BAULL,
			0x95FB05815C57B7C5ULL,
			0x7711916F971DF22BULL}
		}
	};
	printf("Test Case 438\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 438 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -438;
	} else {
		printf("Test Case 438 PASSED\n");
	}

	steps = 55;
	X1 = (curve25519_key_t){.key64 = {
		0xA3F56D8B1A1550D0ULL,
		0xF5930B456FAD1106ULL,
		0x6F0874EFFFC23270ULL,
		0x4BB9BCFF4DE43321ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA3F56D8B1A1550D0ULL,
			0xF5930B456FAD1106ULL,
			0x6F0874EFFFC23270ULL,
			0x4BB9BCFF4DE43321ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x49B8F5720FE8B005ULL,
			0xAB3079537093CEDFULL,
			0x583DA13E3BEF2B1CULL,
			0x73C938A9E0CB776EULL}
		},
		.Z = {.key64 = {
			0x05CCC4AE2C5700D9ULL,
			0x633493983DAD8905ULL,
			0x8B9EE5F3EAED7A93ULL,
			0x5D8643F81BBFCCFEULL}
		}
	};
	printf("Test Case 439\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 439 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -439;
	} else {
		printf("Test Case 439 PASSED\n");
	}

	steps = 10;
	X1 = (curve25519_key_t){.key64 = {
		0x270CDDC9985A9940ULL,
		0xCF5B3FD9E69ACD68ULL,
		0xE2885B28DBB84426ULL,
		0x799C54B9342D0C65ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x270CDDC9985A9940ULL,
			0xCF5B3FD9E69ACD68ULL,
			0xE2885B28DBB84426ULL,
			0x799C54B9342D0C65ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xABD4F74604D4C983ULL,
			0x1674D57B3D0997FEULL,
			0x56949EF7EC6F2D4DULL,
			0x0C9C746EA5BB853DULL}
		},
		.Z = {.key64 = {
			0x0E9916FE62741239ULL,
			0xE8AE9B3230B978AEULL,
			0xC1F57F98F12BA2B2ULL,
			0x2686D115E1EA3AEBULL}
		}
	};
	printf("Test Case 440\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 440 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -440;
	} else {
		printf("Test Case 440 PASSED\n");
	}

	steps = 12;
	X1 = (curve25519_key_t){.key64 = {
		0xD8A0790423445C48ULL,
		0x26C156B07BD3B419ULL,
		0xF45D8BC3A327917AULL,
		0x593B64C3CB03D1BBULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD8A0790423445C48ULL,
			0x26C156B07BD3B419ULL,
			0xF45D8BC3A327917AULL,
			0x593B64C3CB03D1BBULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB9AD8093DD94DED6ULL,
			0x95EF9F3CBB1BA4B4ULL,
			0xDFDF4B1E3AE90D06ULL,
			0x74F2517C1B75916DULL}
		},
		.Z = {.key64 = {
			0x4677312474D166F1ULL,
			0x528CCBB11B37A8AFULL,
			0x41D5AF42F6AE184DULL,
			0x5972CD734992D1CBULL}
		}
	};
	printf("Test Case 441\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 441 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -441;
	} else {
		printf("Test Case 441 PASSED\n");
	}

	steps = 44;
	X1 = (curve25519_key_t){.key64 = {
		0x275186B296191488ULL,
		0x32D782FEE6C7684DULL,
		0xA9E8FACB67BD84A2ULL,
		0x63F89CCD649CAAEAULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x275186B296191488ULL,
			0x32D782FEE6C7684DULL,
			0xA9E8FACB67BD84A2ULL,
			0x63F89CCD649CAAEAULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4FA35ACC8500B84AULL,
			0xE535BA7B0DD717D1ULL,
			0xCE85976B79898F43ULL,
			0x770C88434CED8E81ULL}
		},
		.Z = {.key64 = {
			0x0768136C0B4E9CFFULL,
			0x4E52FEAB680B1FECULL,
			0x29E3437C85DB9003ULL,
			0x09AC54F43C9FBB6DULL}
		}
	};
	printf("Test Case 442\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 442 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -442;
	} else {
		printf("Test Case 442 PASSED\n");
	}

	steps = 18;
	X1 = (curve25519_key_t){.key64 = {
		0x2078C76D1E4004F8ULL,
		0xAB2D2A15EFE0F6AEULL,
		0x68993671536298FEULL,
		0x4394573802CD29F8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2078C76D1E4004F8ULL,
			0xAB2D2A15EFE0F6AEULL,
			0x68993671536298FEULL,
			0x4394573802CD29F8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDA91392177989D79ULL,
			0x850AA3CC8B2EF824ULL,
			0x01AB500C8F445F12ULL,
			0x180AE2906C9D436FULL}
		},
		.Z = {.key64 = {
			0x85F1EC2872E55BD4ULL,
			0xE5846A9D93D01B0EULL,
			0x1BEE23E9465945DAULL,
			0x7E09C018CBDCB4C3ULL}
		}
	};
	printf("Test Case 443\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 443 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -443;
	} else {
		printf("Test Case 443 PASSED\n");
	}

	steps = 59;
	X1 = (curve25519_key_t){.key64 = {
		0x4F990B9B0BBDB3E0ULL,
		0xD3DE7697449CEE02ULL,
		0x44E567832E50F906ULL,
		0x6A3BC09195F02204ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4F990B9B0BBDB3E0ULL,
			0xD3DE7697449CEE02ULL,
			0x44E567832E50F906ULL,
			0x6A3BC09195F02204ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB6E1386DF69E0A67ULL,
			0xF94EF0F5B3FBCADFULL,
			0xD10479EDD727EF25ULL,
			0x5013E711A5E0C7DFULL}
		},
		.Z = {.key64 = {
			0x45D70E347ED1D1FCULL,
			0x2E2BBE5A7E3E6EDCULL,
			0xE5E3FE7EDACB15B3ULL,
			0x2625A1D761DDAEFBULL}
		}
	};
	printf("Test Case 444\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 444 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -444;
	} else {
		printf("Test Case 444 PASSED\n");
	}

	steps = 56;
	X1 = (curve25519_key_t){.key64 = {
		0x6778E00E0B1EB110ULL,
		0x892D80614C42871BULL,
		0x0C28361120139EA8ULL,
		0x7DC1BBBCBB5A1811ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6778E00E0B1EB110ULL,
			0x892D80614C42871BULL,
			0x0C28361120139EA8ULL,
			0x7DC1BBBCBB5A1811ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x874CD13C3DE4CD40ULL,
			0x26C3F9333EB09C43ULL,
			0x42647EDD9E73308FULL,
			0x26DCD81D29856B3BULL}
		},
		.Z = {.key64 = {
			0xDE4B9D10444574F5ULL,
			0xD10E339800C47037ULL,
			0x2618B46A9730EC14ULL,
			0x097831FB38707424ULL}
		}
	};
	printf("Test Case 445\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 445 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -445;
	} else {
		printf("Test Case 445 PASSED\n");
	}

	steps = 17;
	X1 = (curve25519_key_t){.key64 = {
		0xE2065CA6B659BEB0ULL,
		0xCEB23970D4FDF488ULL,
		0x69D141F5D4BFCCF5ULL,
		0x7267AC47DCA91AB5ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE2065CA6B659BEB0ULL,
			0xCEB23970D4FDF488ULL,
			0x69D141F5D4BFCCF5ULL,
			0x7267AC47DCA91AB5ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD8DA99F78ED63F0DULL,
			0xD923F72A16F94A0EULL,
			0xEEA74E8FB6F9B802ULL,
			0x16E5AB5355C9688CULL}
		},
		.Z = {.key64 = {
			0xC62CCF5204B7F8E9ULL,
			0x4401075074480646ULL,
			0x5EE6CA9347F7A7B4ULL,
			0x678F1C3FF0556DA9ULL}
		}
	};
	printf("Test Case 446\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 446 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -446;
	} else {
		printf("Test Case 446 PASSED\n");
	}

	steps = 47;
	X1 = (curve25519_key_t){.key64 = {
		0xCBF670EACE7C4418ULL,
		0x47E5F9E2C3945EABULL,
		0x18CD17A989D50471ULL,
		0x4817759A3F992AEEULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCBF670EACE7C4418ULL,
			0x47E5F9E2C3945EABULL,
			0x18CD17A989D50471ULL,
			0x4817759A3F992AEEULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x544A3602C3795EFFULL,
			0x740AC63659537FB5ULL,
			0x93C1BD7AF22F7FB0ULL,
			0x7D476C49AB06313EULL}
		},
		.Z = {.key64 = {
			0x484F98582D2215E4ULL,
			0x2269057FE1EDE055ULL,
			0xC71B8A5CC01653BAULL,
			0x4CB391DB4BA74875ULL}
		}
	};
	printf("Test Case 447\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 447 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -447;
	} else {
		printf("Test Case 447 PASSED\n");
	}

	steps = 45;
	X1 = (curve25519_key_t){.key64 = {
		0x5B670810C8D799C0ULL,
		0xD7469576AD163AD9ULL,
		0x0494782AD90AFF4EULL,
		0x54C0904A0885DFCCULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5B670810C8D799C0ULL,
			0xD7469576AD163AD9ULL,
			0x0494782AD90AFF4EULL,
			0x54C0904A0885DFCCULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE93BBA50A8AB61EFULL,
			0x6374799FBD43EAB9ULL,
			0x6C2265E92844E01BULL,
			0x7D108FC4B342343CULL}
		},
		.Z = {.key64 = {
			0xB76CEE54C861DF4CULL,
			0xA04A6D91DF223BB1ULL,
			0x9FC4F516B9990400ULL,
			0x7C518664CC2CB820ULL}
		}
	};
	printf("Test Case 448\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 448 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -448;
	} else {
		printf("Test Case 448 PASSED\n");
	}

	steps = 10;
	X1 = (curve25519_key_t){.key64 = {
		0x89DA301A90936EF8ULL,
		0xDEFB2286E2D07B7AULL,
		0x96216229F725A53BULL,
		0x72C8CBD57FFAFD1DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x89DA301A90936EF8ULL,
			0xDEFB2286E2D07B7AULL,
			0x96216229F725A53BULL,
			0x72C8CBD57FFAFD1DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCA85110531F57EF6ULL,
			0xB41EC7A22D714A46ULL,
			0x06F10CA36B437888ULL,
			0x6214887626255754ULL}
		},
		.Z = {.key64 = {
			0xBCE99A08C118E059ULL,
			0x9E8BFF77560F5637ULL,
			0x0BCC05BF4D1FE997ULL,
			0x7B5CD2D17833A904ULL}
		}
	};
	printf("Test Case 449\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 449 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -449;
	} else {
		printf("Test Case 449 PASSED\n");
	}

	steps = 28;
	X1 = (curve25519_key_t){.key64 = {
		0xBAD498F308F89FA0ULL,
		0xEF3B80F6D5E243A4ULL,
		0xEAC4A4E852B6B512ULL,
		0x63F0FDBDA7663279ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBAD498F308F89FA0ULL,
			0xEF3B80F6D5E243A4ULL,
			0xEAC4A4E852B6B512ULL,
			0x63F0FDBDA7663279ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x23803D7C3C707DC2ULL,
			0x5412EB5A58890FC5ULL,
			0xC609CFDD4E0F151BULL,
			0x0779BEADBDD57A72ULL}
		},
		.Z = {.key64 = {
			0x2C43893788786BA0ULL,
			0x610761DA237D4F9AULL,
			0x27BF42577057DC48ULL,
			0x71DE257B2A58FC43ULL}
		}
	};
	printf("Test Case 450\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 450 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -450;
	} else {
		printf("Test Case 450 PASSED\n");
	}

	steps = 62;
	X1 = (curve25519_key_t){.key64 = {
		0x2545B7624E7C90D8ULL,
		0x92DC07B9E1EA7AF8ULL,
		0x4639C9E41DEAB717ULL,
		0x7612D8751C5BAFD3ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2545B7624E7C90D8ULL,
			0x92DC07B9E1EA7AF8ULL,
			0x4639C9E41DEAB717ULL,
			0x7612D8751C5BAFD3ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF426BD89259D5795ULL,
			0xF27C2AA7081BE936ULL,
			0x9E34C59B2F2F6983ULL,
			0x29BFBC6F11A87BD6ULL}
		},
		.Z = {.key64 = {
			0xD7BAAEEBBF64E12BULL,
			0xC6E4CE5CA32382C2ULL,
			0xA7EB360EDCDAC2DBULL,
			0x4A014974D1DC4A75ULL}
		}
	};
	printf("Test Case 451\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 451 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -451;
	} else {
		printf("Test Case 451 PASSED\n");
	}

	steps = 4;
	X1 = (curve25519_key_t){.key64 = {
		0xFDE09DCC704B5FA0ULL,
		0xA0CBC8B8AE9944C2ULL,
		0xF3B02E9F0E1E1875ULL,
		0x73B198DC42E18C7DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFDE09DCC704B5FA0ULL,
			0xA0CBC8B8AE9944C2ULL,
			0xF3B02E9F0E1E1875ULL,
			0x73B198DC42E18C7DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA130C2CA6B4141FBULL,
			0x772A0186B6520014ULL,
			0xB4E63F51DEC8531CULL,
			0x0D339CF6189BC99DULL}
		},
		.Z = {.key64 = {
			0x183F84A96CC1CD94ULL,
			0xC7C775FF29920030ULL,
			0xC662DF6228174FCAULL,
			0x159C8060F8A4C0ECULL}
		}
	};
	printf("Test Case 452\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 452 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -452;
	} else {
		printf("Test Case 452 PASSED\n");
	}

	steps = 18;
	X1 = (curve25519_key_t){.key64 = {
		0x3AF1BFF07E06FBC0ULL,
		0xC74CFA8E9BAD05ACULL,
		0x0BD56B506E62082CULL,
		0x5A2AFF9F2B29DBCCULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3AF1BFF07E06FBC0ULL,
			0xC74CFA8E9BAD05ACULL,
			0x0BD56B506E62082CULL,
			0x5A2AFF9F2B29DBCCULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAF483406AE628103ULL,
			0x39EBC69BEB22FBCAULL,
			0x80FC7193E0C4B237ULL,
			0x7BED9D7325CCC38DULL}
		},
		.Z = {.key64 = {
			0x4123375185718F61ULL,
			0xE23EE70207AA7D93ULL,
			0x11484C35B7DB7001ULL,
			0x3A9C7D4433F2A070ULL}
		}
	};
	printf("Test Case 453\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 453 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -453;
	} else {
		printf("Test Case 453 PASSED\n");
	}

	steps = 18;
	X1 = (curve25519_key_t){.key64 = {
		0x171CD5F45D91A8B0ULL,
		0xF3D129C1127DEF3EULL,
		0x495FF30F8AF43697ULL,
		0x4D2D39AF63A86427ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x171CD5F45D91A8B0ULL,
			0xF3D129C1127DEF3EULL,
			0x495FF30F8AF43697ULL,
			0x4D2D39AF63A86427ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAA695E638C0F6438ULL,
			0xD9426AD3748D5F80ULL,
			0xB3D8FDA014D3337DULL,
			0x49F776FD1417BF38ULL}
		},
		.Z = {.key64 = {
			0x46124026661F9AD0ULL,
			0x071FB6A736AA5DC2ULL,
			0x66B9E5336301E100ULL,
			0x7631669DE27CBF64ULL}
		}
	};
	printf("Test Case 454\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 454 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -454;
	} else {
		printf("Test Case 454 PASSED\n");
	}

	steps = 53;
	X1 = (curve25519_key_t){.key64 = {
		0x7C8F57DBD1485448ULL,
		0xD2DA5B86DBB94326ULL,
		0x00F2AC32F1AC7303ULL,
		0x6083A6A17234A18BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7C8F57DBD1485448ULL,
			0xD2DA5B86DBB94326ULL,
			0x00F2AC32F1AC7303ULL,
			0x6083A6A17234A18BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7BA4ED5C8D740F1BULL,
			0xFB1B0A49ED5A8E59ULL,
			0x7FF673AB0A5CF114ULL,
			0x0FEB435FB245556BULL}
		},
		.Z = {.key64 = {
			0xB77E1F0353162E10ULL,
			0xFA9596579BDF7033ULL,
			0xA79D87A01065A0CCULL,
			0x000A7F4A995D4795ULL}
		}
	};
	printf("Test Case 455\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 455 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -455;
	} else {
		printf("Test Case 455 PASSED\n");
	}

	steps = 40;
	X1 = (curve25519_key_t){.key64 = {
		0x56CB8E8E543406E0ULL,
		0xE6FAF314C758F7D4ULL,
		0x561029A09E968306ULL,
		0x6EF0F69E65AC326DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x56CB8E8E543406E0ULL,
			0xE6FAF314C758F7D4ULL,
			0x561029A09E968306ULL,
			0x6EF0F69E65AC326DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE51EB0F60E3C1205ULL,
			0x455CCEC299DE5C88ULL,
			0x9EA7E40919C32CB3ULL,
			0x11FFA3AECF5C4D0BULL}
		},
		.Z = {.key64 = {
			0xE598AA2B636E652CULL,
			0xD9286101F91B293EULL,
			0xDA42D3A1268A1B31ULL,
			0x4D763EFC3493F9B4ULL}
		}
	};
	printf("Test Case 456\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 456 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -456;
	} else {
		printf("Test Case 456 PASSED\n");
	}

	steps = 47;
	X1 = (curve25519_key_t){.key64 = {
		0x1170C8EA46C5A0C0ULL,
		0xCF293113CB098FB8ULL,
		0x637BFCA261FE9875ULL,
		0x747111FDFB5DB393ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1170C8EA46C5A0C0ULL,
			0xCF293113CB098FB8ULL,
			0x637BFCA261FE9875ULL,
			0x747111FDFB5DB393ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8339E480374435A9ULL,
			0x47046CD5608F4825ULL,
			0x584BEEA8763C4F3EULL,
			0x3BA2BC30B47B32AEULL}
		},
		.Z = {.key64 = {
			0xC54D56B72CC01A08ULL,
			0x2D444549875A71C1ULL,
			0x29D5B14EDC1BB243ULL,
			0x493ED7A6A4F010C4ULL}
		}
	};
	printf("Test Case 457\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 457 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -457;
	} else {
		printf("Test Case 457 PASSED\n");
	}

	steps = 19;
	X1 = (curve25519_key_t){.key64 = {
		0x2D97A71973C429B0ULL,
		0xCEAE43A094165418ULL,
		0xA4D74DA1FB26349AULL,
		0x5C2D9EC3546FB3FDULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2D97A71973C429B0ULL,
			0xCEAE43A094165418ULL,
			0xA4D74DA1FB26349AULL,
			0x5C2D9EC3546FB3FDULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1B47B56E6E88D78DULL,
			0x15E81C3D5FEE3DC2ULL,
			0xC88CD38B934977CBULL,
			0x189D989BE857DB18ULL}
		},
		.Z = {.key64 = {
			0x0B3604D9D5448469ULL,
			0x9E38C24C0040353BULL,
			0xCE2FFB4CFCC01019ULL,
			0x1A1D9A8514E56E46ULL}
		}
	};
	printf("Test Case 458\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 458 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -458;
	} else {
		printf("Test Case 458 PASSED\n");
	}

	steps = 50;
	X1 = (curve25519_key_t){.key64 = {
		0xDA195106AFA02D10ULL,
		0x596BCBE13BBCD1A8ULL,
		0x9E83583ACDED25AEULL,
		0x537F17185E9AB8D4ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDA195106AFA02D10ULL,
			0x596BCBE13BBCD1A8ULL,
			0x9E83583ACDED25AEULL,
			0x537F17185E9AB8D4ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x002340B7F0ABEE86ULL,
			0xB0A1D1E37A6477FFULL,
			0x0B82BE1F9D3E344EULL,
			0x7AB1B010F5E8DD1EULL}
		},
		.Z = {.key64 = {
			0xCF7B3F0A9FF5FB93ULL,
			0x5526660B1BB4AE83ULL,
			0x7DBE85615EE17B57ULL,
			0x0F5375B04268BA9EULL}
		}
	};
	printf("Test Case 459\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 459 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -459;
	} else {
		printf("Test Case 459 PASSED\n");
	}

	steps = 51;
	X1 = (curve25519_key_t){.key64 = {
		0x9126C83890A69F38ULL,
		0xE9ED1F2E8BD05BA1ULL,
		0x3EECF57219765CDBULL,
		0x6DCDEA14D000010FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9126C83890A69F38ULL,
			0xE9ED1F2E8BD05BA1ULL,
			0x3EECF57219765CDBULL,
			0x6DCDEA14D000010FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD7801FBE47A0113EULL,
			0xAB18789EBC82AD15ULL,
			0xD16C21C5ACC03D06ULL,
			0x58D28DBDB774F389ULL}
		},
		.Z = {.key64 = {
			0xE42D0F9151D23DBAULL,
			0xF79404EAE49EF279ULL,
			0xD214C0212C2A4FF2ULL,
			0x1EE4ECA9FDC5BCF9ULL}
		}
	};
	printf("Test Case 460\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 460 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -460;
	} else {
		printf("Test Case 460 PASSED\n");
	}

	steps = 50;
	X1 = (curve25519_key_t){.key64 = {
		0xB6F376874D984998ULL,
		0x7DABB35BDF6BB11FULL,
		0x1FF45D99D422FAC3ULL,
		0x43C8087E6891C3B3ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB6F376874D984998ULL,
			0x7DABB35BDF6BB11FULL,
			0x1FF45D99D422FAC3ULL,
			0x43C8087E6891C3B3ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFFAC572F85EAF340ULL,
			0x3708865ABBB3D2B5ULL,
			0xA19E49FC36428265ULL,
			0x4CA57B69D7C2A662ULL}
		},
		.Z = {.key64 = {
			0xB95064FCE7303227ULL,
			0xBBA34E053B98DCA0ULL,
			0x32D6DB0F18D99461ULL,
			0x4EE0F3EB73D5E38AULL}
		}
	};
	printf("Test Case 461\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 461 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -461;
	} else {
		printf("Test Case 461 PASSED\n");
	}

	steps = 57;
	X1 = (curve25519_key_t){.key64 = {
		0xDC9B4D849791C1F8ULL,
		0x04710CD1BEB0C908ULL,
		0x1987D91DEDAA07E4ULL,
		0x78698CEF6006EAD8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDC9B4D849791C1F8ULL,
			0x04710CD1BEB0C908ULL,
			0x1987D91DEDAA07E4ULL,
			0x78698CEF6006EAD8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAAD0AF7BF1C0A172ULL,
			0x1FC3C6EA35F5FECDULL,
			0xCDE48D6CBC20ED9AULL,
			0x60BF74762BAD7CB3ULL}
		},
		.Z = {.key64 = {
			0x45586A2EC09910F9ULL,
			0x594FFB8F9029CCBAULL,
			0x9F5500B89B5A9626ULL,
			0x151AE75C6CFA356BULL}
		}
	};
	printf("Test Case 462\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 462 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -462;
	} else {
		printf("Test Case 462 PASSED\n");
	}

	steps = 60;
	X1 = (curve25519_key_t){.key64 = {
		0x0DC74C7E40BF01C0ULL,
		0xD220887D072D5F06ULL,
		0xF5A6DCDDEC88BEF3ULL,
		0x481BA5BAF2F634BAULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0DC74C7E40BF01C0ULL,
			0xD220887D072D5F06ULL,
			0xF5A6DCDDEC88BEF3ULL,
			0x481BA5BAF2F634BAULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7E7C15CEFBBA46F9ULL,
			0x1415146F7C4EB70BULL,
			0x92145CC667A53CF1ULL,
			0x221DA332CFCE5897ULL}
		},
		.Z = {.key64 = {
			0xCDC18BE6E39E31CEULL,
			0x6796D603F9A3117FULL,
			0x0FFA018595BDB28BULL,
			0x2E91141DBD0D74F0ULL}
		}
	};
	printf("Test Case 463\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 463 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -463;
	} else {
		printf("Test Case 463 PASSED\n");
	}

	steps = 36;
	X1 = (curve25519_key_t){.key64 = {
		0x429892A340C9BA40ULL,
		0x61ECB27ADB376324ULL,
		0x9D601161DB99EB75ULL,
		0x6EE6870EE010CD2BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x429892A340C9BA40ULL,
			0x61ECB27ADB376324ULL,
			0x9D601161DB99EB75ULL,
			0x6EE6870EE010CD2BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x237E2649888FDC77ULL,
			0xBF04C5DDB821E3D0ULL,
			0x2DDABCF1AED7697EULL,
			0x43E65B9ADFBF3C1BULL}
		},
		.Z = {.key64 = {
			0xCB34527500A6115BULL,
			0x07E663B33D88AD98ULL,
			0x44BB4D275E1762FAULL,
			0x155105F4DE3E2221ULL}
		}
	};
	printf("Test Case 464\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 464 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -464;
	} else {
		printf("Test Case 464 PASSED\n");
	}

	steps = 1;
	X1 = (curve25519_key_t){.key64 = {
		0x0F2C5FDCBEE2CAE0ULL,
		0xD1BB9ED8B9AB385DULL,
		0x6BDA6880B170A903ULL,
		0x434F002DF4786D8BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0F2C5FDCBEE2CAE0ULL,
			0xD1BB9ED8B9AB385DULL,
			0x6BDA6880B170A903ULL,
			0x434F002DF4786D8BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8A418812E3DF560FULL,
			0xBEC51D0C2A5DE195ULL,
			0xCCCF6B0505AF06DCULL,
			0x3E8E4132A1EC38B1ULL}
		},
		.Z = {.key64 = {
			0x3CB17F72FB8B2BA6ULL,
			0x46EE7B62E6ACE174ULL,
			0xAF69A202C5C2A40FULL,
			0x0D3C00B7D1E1B62DULL}
		}
	};
	printf("Test Case 465\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 465 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -465;
	} else {
		printf("Test Case 465 PASSED\n");
	}

	steps = 43;
	X1 = (curve25519_key_t){.key64 = {
		0x97C4C82C00F77858ULL,
		0x30FED8533CE1F016ULL,
		0x278EF9356EBCE6A7ULL,
		0x440DB8887EE54E52ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x97C4C82C00F77858ULL,
			0x30FED8533CE1F016ULL,
			0x278EF9356EBCE6A7ULL,
			0x440DB8887EE54E52ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3F85D2C70673ABEFULL,
			0xD18323273BE4F9E1ULL,
			0x8B1B198E32C6AF2BULL,
			0x303CD2B77C3A36DBULL}
		},
		.Z = {.key64 = {
			0xE1A0FA87D961D37FULL,
			0xF84D3B0C0675D34BULL,
			0x4107446F2B81602AULL,
			0x094820A85688CDBCULL}
		}
	};
	printf("Test Case 466\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 466 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -466;
	} else {
		printf("Test Case 466 PASSED\n");
	}

	steps = 57;
	X1 = (curve25519_key_t){.key64 = {
		0x8FC806D041410BD0ULL,
		0xC4302535F2F96946ULL,
		0x77D2AE33FC6C79A8ULL,
		0x77C4F4C39F732BE7ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8FC806D041410BD0ULL,
			0xC4302535F2F96946ULL,
			0x77D2AE33FC6C79A8ULL,
			0x77C4F4C39F732BE7ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x25E0E9C52AC538ADULL,
			0x6D08831FCF394BB5ULL,
			0x8C8C4D6D10C09ACBULL,
			0x66F47C16EE744B7EULL}
		},
		.Z = {.key64 = {
			0x91C0CE283D18C9A6ULL,
			0x77BD3D76C970B19AULL,
			0xB319B730DDC9D498ULL,
			0x0E6429D5CA701A5DULL}
		}
	};
	printf("Test Case 467\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 467 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -467;
	} else {
		printf("Test Case 467 PASSED\n");
	}

	steps = 48;
	X1 = (curve25519_key_t){.key64 = {
		0x0C57E30B3AC0A4D0ULL,
		0xEDDCC78253A1ECC6ULL,
		0x8DED55376A08D231ULL,
		0x40346D9173E96CB6ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0C57E30B3AC0A4D0ULL,
			0xEDDCC78253A1ECC6ULL,
			0x8DED55376A08D231ULL,
			0x40346D9173E96CB6ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8934351C49DA2D88ULL,
			0x5364BE57339E5831ULL,
			0x34200DC396DD3B3CULL,
			0x7E526BD77FF2C2DAULL}
		},
		.Z = {.key64 = {
			0x6CE8F98A49B054DDULL,
			0x895CA1B4F301A3F3ULL,
			0xDF4B1BCD9CCA882CULL,
			0x6C39FDCB4743EF27ULL}
		}
	};
	printf("Test Case 468\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 468 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -468;
	} else {
		printf("Test Case 468 PASSED\n");
	}

	steps = 3;
	X1 = (curve25519_key_t){.key64 = {
		0xCCB75CBBEB2757F8ULL,
		0x51FE37B8CB9D9462ULL,
		0xE4DFD3495932FE7DULL,
		0x6A8E999AE04C9310ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCCB75CBBEB2757F8ULL,
			0x51FE37B8CB9D9462ULL,
			0xE4DFD3495932FE7DULL,
			0x6A8E999AE04C9310ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE04197FF8C14EDB3ULL,
			0xD024C6F665B84FF0ULL,
			0x548EDE829A1DB22CULL,
			0x16B89328D13A2BEEULL}
		},
		.Z = {.key64 = {
			0x189E56C6B0686BB3ULL,
			0x3ADD34FD06C9616DULL,
			0x07E99A187666590AULL,
			0x42640F7AB0487398ULL}
		}
	};
	printf("Test Case 469\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 469 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -469;
	} else {
		printf("Test Case 469 PASSED\n");
	}

	steps = 45;
	X1 = (curve25519_key_t){.key64 = {
		0x18E96D42FF7B6158ULL,
		0x36E462175CEB605CULL,
		0x269F4175CAAB0EB9ULL,
		0x66B5D7A87EB56962ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x18E96D42FF7B6158ULL,
			0x36E462175CEB605CULL,
			0x269F4175CAAB0EB9ULL,
			0x66B5D7A87EB56962ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0B388B1523811DBBULL,
			0x5C9DD323EDF41C4EULL,
			0xA6F3A0564C7BCC7BULL,
			0x240328063955A526ULL}
		},
		.Z = {.key64 = {
			0xF16162575E025DF0ULL,
			0x9687CE22D27C2F16ULL,
			0x58CB8A159949E2B7ULL,
			0x29D0BF62AB3C20FEULL}
		}
	};
	printf("Test Case 470\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 470 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -470;
	} else {
		printf("Test Case 470 PASSED\n");
	}

	steps = 19;
	X1 = (curve25519_key_t){.key64 = {
		0x5818D661628E7C88ULL,
		0x3CB7BF98D5E25DC3ULL,
		0x5F902168CBF939C8ULL,
		0x697BA66B980999DEULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5818D661628E7C88ULL,
			0x3CB7BF98D5E25DC3ULL,
			0x5F902168CBF939C8ULL,
			0x697BA66B980999DEULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xACA609C5D1218346ULL,
			0x283DC082BE8F3298ULL,
			0x9FD0B457FE2D1B3BULL,
			0x542EB24811B430BBULL}
		},
		.Z = {.key64 = {
			0x4EE11499478F38ABULL,
			0x9135D243F428AE76ULL,
			0xC95A8088F5E5557EULL,
			0x78B1FAE000ACCF99ULL}
		}
	};
	printf("Test Case 471\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 471 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -471;
	} else {
		printf("Test Case 471 PASSED\n");
	}

	steps = 9;
	X1 = (curve25519_key_t){.key64 = {
		0xF9914C081FD12100ULL,
		0xEFFA316141C27492ULL,
		0xCC2697651E073B4EULL,
		0x60C4C8622919ABB7ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF9914C081FD12100ULL,
			0xEFFA316141C27492ULL,
			0xCC2697651E073B4EULL,
			0x60C4C8622919ABB7ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x16D2E4CB3E52DAFEULL,
			0xA1062962A81B2117ULL,
			0x888CDEC8C3559B04ULL,
			0x5F558E888471C833ULL}
		},
		.Z = {.key64 = {
			0x709B28B3C8694DA1ULL,
			0x8B91275D8ED76867ULL,
			0x96396F2FE7C38EE6ULL,
			0x5BFD30ACFADBE5E4ULL}
		}
	};
	printf("Test Case 472\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 472 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -472;
	} else {
		printf("Test Case 472 PASSED\n");
	}

	steps = 20;
	X1 = (curve25519_key_t){.key64 = {
		0x07F3020095836B40ULL,
		0xCFAB8862B5385E43ULL,
		0x3B57773DD5A7DC37ULL,
		0x5143B8896F601402ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x07F3020095836B40ULL,
			0xCFAB8862B5385E43ULL,
			0x3B57773DD5A7DC37ULL,
			0x5143B8896F601402ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3F626DA64025E3C1ULL,
			0xACF7A443A5D4A3A5ULL,
			0x6339430BA8414A49ULL,
			0x20965EDC812DD873ULL}
		},
		.Z = {.key64 = {
			0x02AD5DDD63D411E0ULL,
			0xC6064F92A3FF9E19ULL,
			0x4BFDB618AF68F579ULL,
			0x417A95F8CEC501FAULL}
		}
	};
	printf("Test Case 473\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 473 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -473;
	} else {
		printf("Test Case 473 PASSED\n");
	}

	steps = 1;
	X1 = (curve25519_key_t){.key64 = {
		0x8F92BA71EADA03E8ULL,
		0x1B9E2CE7416829FDULL,
		0x0C33FBA8E266B070ULL,
		0x40A1C49B31FE559FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8F92BA71EADA03E8ULL,
			0x1B9E2CE7416829FDULL,
			0x0C33FBA8E266B070ULL,
			0x40A1C49B31FE559FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA18831C057BB69CEULL,
			0xF38E59A9965AA8C1ULL,
			0xEC774C5A3011A59EULL,
			0x31534D91597CBC4EULL}
		},
		.Z = {.key64 = {
			0x3E4AE9C7AB680FC6ULL,
			0x6E78B39D05A0A7F6ULL,
			0x30CFEEA3899AC1C0ULL,
			0x0287126CC7F9567CULL}
		}
	};
	printf("Test Case 474\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 474 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -474;
	} else {
		printf("Test Case 474 PASSED\n");
	}

	steps = 34;
	X1 = (curve25519_key_t){.key64 = {
		0xEB1C52F53F05DE90ULL,
		0xA258B9A81A2C6030ULL,
		0xB5FD844E297A8BB8ULL,
		0x71C5E1584BD00121ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEB1C52F53F05DE90ULL,
			0xA258B9A81A2C6030ULL,
			0xB5FD844E297A8BB8ULL,
			0x71C5E1584BD00121ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBCC542DB3E20B9B4ULL,
			0x60945EE90FD566ABULL,
			0xEB5DFFA87B423FD6ULL,
			0x45633357406A6602ULL}
		},
		.Z = {.key64 = {
			0xBBBB432A71F61058ULL,
			0xC87A26828CC358B9ULL,
			0x0308DEB3203CD625ULL,
			0x7AD27FB3562C32D4ULL}
		}
	};
	printf("Test Case 475\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 475 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -475;
	} else {
		printf("Test Case 475 PASSED\n");
	}

	steps = 13;
	X1 = (curve25519_key_t){.key64 = {
		0x34ABD147146B3840ULL,
		0x7A8868E49153A694ULL,
		0x11581115F83DCB80ULL,
		0x761A2ABA2C4EC43AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x34ABD147146B3840ULL,
			0x7A8868E49153A694ULL,
			0x11581115F83DCB80ULL,
			0x761A2ABA2C4EC43AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0283861E1ABDDBA5ULL,
			0x06EA78CFCBD9885FULL,
			0x61AAF3C131836BDCULL,
			0x0A7EC1A0EA404E76ULL}
		},
		.Z = {.key64 = {
			0x806507392E47AFC3ULL,
			0x6196B96FC04A0F9FULL,
			0x17859D652359B1B0ULL,
			0x625C6B36D2C33539ULL}
		}
	};
	printf("Test Case 476\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 476 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -476;
	} else {
		printf("Test Case 476 PASSED\n");
	}

	steps = 17;
	X1 = (curve25519_key_t){.key64 = {
		0xE46EB290FC183B28ULL,
		0x9E9D4D3844D1EEE4ULL,
		0x888FBC308343BD76ULL,
		0x5D962796C938FE28ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE46EB290FC183B28ULL,
			0x9E9D4D3844D1EEE4ULL,
			0x888FBC308343BD76ULL,
			0x5D962796C938FE28ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFBB0DC07E3519EEFULL,
			0x1001EC644D3DF0ABULL,
			0xCC1488F54BED4931ULL,
			0x34CECE80BDE1D582ULL}
		},
		.Z = {.key64 = {
			0x236CCAEB9A2EF40BULL,
			0xE400F8A0DA645A8FULL,
			0x51B42709A5084AE7ULL,
			0x7E1C3877FF8E7AC7ULL}
		}
	};
	printf("Test Case 477\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 477 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -477;
	} else {
		printf("Test Case 477 PASSED\n");
	}

	steps = 45;
	X1 = (curve25519_key_t){.key64 = {
		0x686BC503D0A83068ULL,
		0x03D783A0B94D1FA9ULL,
		0x93FCB5353F403910ULL,
		0x53DD1EA450F6DF72ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x686BC503D0A83068ULL,
			0x03D783A0B94D1FA9ULL,
			0x93FCB5353F403910ULL,
			0x53DD1EA450F6DF72ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x399658D47E70159DULL,
			0xD951510CF67E15F2ULL,
			0xD01751D049BB095BULL,
			0x2D8666D066DA84BCULL}
		},
		.Z = {.key64 = {
			0x74FD14AFAA58D197ULL,
			0xBF5D594F426A1ECCULL,
			0x5034270BE2AAB6CBULL,
			0x133A9230C19C0C2BULL}
		}
	};
	printf("Test Case 478\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 478 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -478;
	} else {
		printf("Test Case 478 PASSED\n");
	}

	steps = 23;
	X1 = (curve25519_key_t){.key64 = {
		0x6D18092B4CDB1670ULL,
		0xD89E20B8C3D14EC8ULL,
		0x75182D9CB64800C5ULL,
		0x7090C42ED1810348ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6D18092B4CDB1670ULL,
			0xD89E20B8C3D14EC8ULL,
			0x75182D9CB64800C5ULL,
			0x7090C42ED1810348ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9465C0BA86281D36ULL,
			0x45A80C01F96C5C8BULL,
			0xD74E1EAE5523E0A7ULL,
			0x46A5DBBE88F9D710ULL}
		},
		.Z = {.key64 = {
			0xF06B3A257B3F4B94ULL,
			0x13EAEA128C7011F3ULL,
			0x9AC5A81AA15A4F81ULL,
			0x339E682E5B1C5675ULL}
		}
	};
	printf("Test Case 479\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 479 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -479;
	} else {
		printf("Test Case 479 PASSED\n");
	}

	steps = 26;
	X1 = (curve25519_key_t){.key64 = {
		0xBF0AEC70392BCB38ULL,
		0xD1A4D512497B436CULL,
		0xA6896971DC10F75BULL,
		0x5086184BCEF36D26ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBF0AEC70392BCB38ULL,
			0xD1A4D512497B436CULL,
			0xA6896971DC10F75BULL,
			0x5086184BCEF36D26ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5728C30E7C3720EAULL,
			0x86AED2E01E10C3C8ULL,
			0xF17A56B5571B6DCEULL,
			0x7CEB877A934D2852ULL}
		},
		.Z = {.key64 = {
			0x206996E1B7DC6169ULL,
			0xCBD96C3A19E223AFULL,
			0xA001A623F3A5FA0EULL,
			0x484288A1BAE6C597ULL}
		}
	};
	printf("Test Case 480\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 480 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -480;
	} else {
		printf("Test Case 480 PASSED\n");
	}

	steps = 22;
	X1 = (curve25519_key_t){.key64 = {
		0x225BD8D56DCB4F88ULL,
		0x852CD9B7F83CB4B7ULL,
		0xE2B92AB5F314E6B4ULL,
		0x5126033FA5B07898ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x225BD8D56DCB4F88ULL,
			0x852CD9B7F83CB4B7ULL,
			0xE2B92AB5F314E6B4ULL,
			0x5126033FA5B07898ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x36841AC22D92586DULL,
			0x19EFFE134359DCBCULL,
			0xFC21B385BFE9638BULL,
			0x6662FE4E16731255ULL}
		},
		.Z = {.key64 = {
			0xC355717585B98834ULL,
			0xDBB2D1E878752FB5ULL,
			0x029A9942444BCD60ULL,
			0x4D2500254658240DULL}
		}
	};
	printf("Test Case 481\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 481 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -481;
	} else {
		printf("Test Case 481 PASSED\n");
	}

	steps = 47;
	X1 = (curve25519_key_t){.key64 = {
		0xFAF9F543F45B3078ULL,
		0x0BCB9EB79F2F56B1ULL,
		0xF6729F8DFE3ACC51ULL,
		0x79DF1ADAD998CA3AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFAF9F543F45B3078ULL,
			0x0BCB9EB79F2F56B1ULL,
			0xF6729F8DFE3ACC51ULL,
			0x79DF1ADAD998CA3AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF18DD6B8D9DA0B87ULL,
			0xF208042BD8730A22ULL,
			0x8BA60CA8137CF471ULL,
			0x57752ECFE0AB10AFULL}
		},
		.Z = {.key64 = {
			0xCF975C7702A46354ULL,
			0x3F5E70C301169B2DULL,
			0x95A298CBD05C585FULL,
			0x4BEFAE1FA550F6CFULL}
		}
	};
	printf("Test Case 482\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 482 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -482;
	} else {
		printf("Test Case 482 PASSED\n");
	}

	steps = 15;
	X1 = (curve25519_key_t){.key64 = {
		0x3C863ADA73B4EB78ULL,
		0x1E5DA74FFCBAA319ULL,
		0x4E3C11CCF32A3128ULL,
		0x7F8A840F9F3D7534ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3C863ADA73B4EB78ULL,
			0x1E5DA74FFCBAA319ULL,
			0x4E3C11CCF32A3128ULL,
			0x7F8A840F9F3D7534ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEF76FE8696B76B83ULL,
			0xD4BCAC3725AA7810ULL,
			0x5D657C632AD0F010ULL,
			0x7134C4B3F2102253ULL}
		},
		.Z = {.key64 = {
			0xCDB00DB841C0392DULL,
			0x9852D554E37E5790ULL,
			0x8DCF672E7E86D727ULL,
			0x5EDA6A12E370368DULL}
		}
	};
	printf("Test Case 483\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 483 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -483;
	} else {
		printf("Test Case 483 PASSED\n");
	}

	steps = 25;
	X1 = (curve25519_key_t){.key64 = {
		0x2DD96D06D55E9F78ULL,
		0x5517E48ADF9A20F3ULL,
		0x8D7772B19F928763ULL,
		0x6A15A5D5B49BBD14ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2DD96D06D55E9F78ULL,
			0x5517E48ADF9A20F3ULL,
			0x8D7772B19F928763ULL,
			0x6A15A5D5B49BBD14ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x17FF9AB54DB13980ULL,
			0x891ED0D3BA2BF495ULL,
			0x8BFCA897F3717A11ULL,
			0x4919445319106C06ULL}
		},
		.Z = {.key64 = {
			0x0BE21493163CFC69ULL,
			0x8DF8F9AF6D6D052CULL,
			0x4AD171622AF17EBAULL,
			0x27216FC599685276ULL}
		}
	};
	printf("Test Case 484\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 484 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -484;
	} else {
		printf("Test Case 484 PASSED\n");
	}

	steps = 43;
	X1 = (curve25519_key_t){.key64 = {
		0x193FD866FBC3A6C8ULL,
		0xA9B2C9964AAEA816ULL,
		0x1D5B27F38619DA99ULL,
		0x7E0351065AEC0B66ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x193FD866FBC3A6C8ULL,
			0xA9B2C9964AAEA816ULL,
			0x1D5B27F38619DA99ULL,
			0x7E0351065AEC0B66ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8DC13B32CA2F3021ULL,
			0xA749165067308612ULL,
			0x1B592154AB829832ULL,
			0x516843ED408AADADULL}
		},
		.Z = {.key64 = {
			0xD8AE9BD4887AD622ULL,
			0x4F635426E1D84F93ULL,
			0xB6BD0B47CE056E24ULL,
			0x25E98826F544ADA8ULL}
		}
	};
	printf("Test Case 485\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 485 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -485;
	} else {
		printf("Test Case 485 PASSED\n");
	}

	steps = 32;
	X1 = (curve25519_key_t){.key64 = {
		0xA29AA45780304E08ULL,
		0xF53D83834BD4F77CULL,
		0x31ACB83B0E2D204EULL,
		0x6610750FB12BD938ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA29AA45780304E08ULL,
			0xF53D83834BD4F77CULL,
			0x31ACB83B0E2D204EULL,
			0x6610750FB12BD938ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAF08D1AC174EEBF5ULL,
			0x03B7B154FAD61ACFULL,
			0x854FBFB91FAD99B3ULL,
			0x28D841836D06C38AULL}
		},
		.Z = {.key64 = {
			0x163AB9B8DED7EB23ULL,
			0x6F7A37CDCCE08FDEULL,
			0xB01E0AAEA16D0E8DULL,
			0x7067B6A4954A02A2ULL}
		}
	};
	printf("Test Case 486\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 486 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -486;
	} else {
		printf("Test Case 486 PASSED\n");
	}

	steps = 20;
	X1 = (curve25519_key_t){.key64 = {
		0x080BD98F8463D180ULL,
		0x8C1842EA1F9F583CULL,
		0x6DDB7A1B5692DD90ULL,
		0x642868C3E84E57D6ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x080BD98F8463D180ULL,
			0x8C1842EA1F9F583CULL,
			0x6DDB7A1B5692DD90ULL,
			0x642868C3E84E57D6ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x576F4BE17F439181ULL,
			0x58359B7158741229ULL,
			0xCCF755FD69BC00BDULL,
			0x7AE558F8495CA323ULL}
		},
		.Z = {.key64 = {
			0xBF7B244F4289C000ULL,
			0xD5A00C0B2520C4DBULL,
			0xD86AC948589563BEULL,
			0x2FAA3A9595DF7465ULL}
		}
	};
	printf("Test Case 487\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 487 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -487;
	} else {
		printf("Test Case 487 PASSED\n");
	}

	steps = 30;
	X1 = (curve25519_key_t){.key64 = {
		0xB69D0BA3A695C2E0ULL,
		0xE07CDE18BB1E225EULL,
		0xBFC02DEFE8315628ULL,
		0x53594937FD4CE6C0ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB69D0BA3A695C2E0ULL,
			0xE07CDE18BB1E225EULL,
			0xBFC02DEFE8315628ULL,
			0x53594937FD4CE6C0ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF14904AA3D99B0FDULL,
			0xEAC6E2895091DAFBULL,
			0xFF87F3FD4D43CC16ULL,
			0x0E1BCA8456B64C92ULL}
		},
		.Z = {.key64 = {
			0x56E3E5AD227CC487ULL,
			0x177106791378D3D6ULL,
			0x292FB613C677A461ULL,
			0x6D63166EDC2DD1D9ULL}
		}
	};
	printf("Test Case 488\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 488 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -488;
	} else {
		printf("Test Case 488 PASSED\n");
	}

	steps = 49;
	X1 = (curve25519_key_t){.key64 = {
		0xF689D7AB9CEBE7D0ULL,
		0xE628213A6630138DULL,
		0x02B7C4437ACC866EULL,
		0x69CB794F510122C8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF689D7AB9CEBE7D0ULL,
			0xE628213A6630138DULL,
			0x02B7C4437ACC866EULL,
			0x69CB794F510122C8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDBD09832B79E1215ULL,
			0x649D7EF0EE884478ULL,
			0x1B156C54F8F04B38ULL,
			0x7578082ED55018E0ULL}
		},
		.Z = {.key64 = {
			0xDE65625C108AE4D7ULL,
			0x9BF6EAD6CCA42A78ULL,
			0x57D7E276782F3915ULL,
			0x7157451B6E791614ULL}
		}
	};
	printf("Test Case 489\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 489 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -489;
	} else {
		printf("Test Case 489 PASSED\n");
	}

	steps = 55;
	X1 = (curve25519_key_t){.key64 = {
		0x2548E04BA9A4A5A0ULL,
		0x8180DFA2D72664D3ULL,
		0xB0841745C900818BULL,
		0x40F13B5A545DD608ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2548E04BA9A4A5A0ULL,
			0x8180DFA2D72664D3ULL,
			0xB0841745C900818BULL,
			0x40F13B5A545DD608ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4C5FEC168DCA53E5ULL,
			0xE1247A789E244AC4ULL,
			0x2AEF11355F7B8157ULL,
			0x74F410CA2D69559AULL}
		},
		.Z = {.key64 = {
			0xDD7EDCDF8F24CC1FULL,
			0x318D2A28663AFB57ULL,
			0xEECC564CABBF04BBULL,
			0x1E93CB2D94C6E383ULL}
		}
	};
	printf("Test Case 490\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 490 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -490;
	} else {
		printf("Test Case 490 PASSED\n");
	}

	steps = 35;
	X1 = (curve25519_key_t){.key64 = {
		0x7F714829A1826B40ULL,
		0xE0575B180D9AF02CULL,
		0xC90FF4908CE19551ULL,
		0x66BA7804F3085D9CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7F714829A1826B40ULL,
			0xE0575B180D9AF02CULL,
			0xC90FF4908CE19551ULL,
			0x66BA7804F3085D9CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBF82483F3AF35607ULL,
			0x560FD1C04C5E369DULL,
			0x2B4AEA8BF505CD6BULL,
			0x668862662EBA2CC8ULL}
		},
		.Z = {.key64 = {
			0xAC0B3E826A952775ULL,
			0x74EF83BC19F0271DULL,
			0x7F9D3A7C51902761ULL,
			0x66725340C276DA59ULL}
		}
	};
	printf("Test Case 491\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 491 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -491;
	} else {
		printf("Test Case 491 PASSED\n");
	}

	steps = 63;
	X1 = (curve25519_key_t){.key64 = {
		0x7393D1675851C1D0ULL,
		0xDC72BE3163633E27ULL,
		0xB05530D040E7E1F2ULL,
		0x6790340275518A3FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7393D1675851C1D0ULL,
			0xDC72BE3163633E27ULL,
			0xB05530D040E7E1F2ULL,
			0x6790340275518A3FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB78EDCB226FCF68EULL,
			0x3661CB39ED2BE88EULL,
			0x2E2939F563AA756CULL,
			0x1D0BC52160EEBC26ULL}
		},
		.Z = {.key64 = {
			0xFA8F94DD34016DEBULL,
			0x60B7CD5B1483035EULL,
			0x6C6BAF89AB852C6DULL,
			0x4141E4102045B8C7ULL}
		}
	};
	printf("Test Case 492\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 492 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -492;
	} else {
		printf("Test Case 492 PASSED\n");
	}

	steps = 40;
	X1 = (curve25519_key_t){.key64 = {
		0x073E2B742C2BEB68ULL,
		0x3197E3ED29510981ULL,
		0xD39CBF8AF2716CB3ULL,
		0x69653ABAF7C4EFE0ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x073E2B742C2BEB68ULL,
			0x3197E3ED29510981ULL,
			0xD39CBF8AF2716CB3ULL,
			0x69653ABAF7C4EFE0ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1A595D4BECC6149FULL,
			0x8F13133A86324C37ULL,
			0x1C2E8A563E146742ULL,
			0x5DFB406414DC24A2ULL}
		},
		.Z = {.key64 = {
			0xD71914E690BE6D4AULL,
			0xDEB0781EE42124BAULL,
			0x01BBF6C64332B319ULL,
			0x2ECD78F568EC478FULL}
		}
	};
	printf("Test Case 493\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 493 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -493;
	} else {
		printf("Test Case 493 PASSED\n");
	}

	steps = 29;
	X1 = (curve25519_key_t){.key64 = {
		0x75C231DAAF739810ULL,
		0x0D58984B5FD4AC7FULL,
		0x8373AACAE80BC4C7ULL,
		0x557335203470B7A1ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x75C231DAAF739810ULL,
			0x0D58984B5FD4AC7FULL,
			0x8373AACAE80BC4C7ULL,
			0x557335203470B7A1ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1C61FB889CB8A496ULL,
			0x9E2AB1C0E5EAB935ULL,
			0x4BDF6F4D0CC8A2F5ULL,
			0x0376E8F30A1165CAULL}
		},
		.Z = {.key64 = {
			0x1EB1166736D85D3CULL,
			0x8E7D1FA5CDCDBB46ULL,
			0xBEC879F2B062C625ULL,
			0x2C1EE01CAF937321ULL}
		}
	};
	printf("Test Case 494\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 494 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -494;
	} else {
		printf("Test Case 494 PASSED\n");
	}

	steps = 33;
	X1 = (curve25519_key_t){.key64 = {
		0x6783EF4978E6F110ULL,
		0x713AE899B9714972ULL,
		0x265EB733602F7A7AULL,
		0x7E50CFAAD9258010ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6783EF4978E6F110ULL,
			0x713AE899B9714972ULL,
			0x265EB733602F7A7AULL,
			0x7E50CFAAD9258010ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA5F7B972EB518C6EULL,
			0x2774574C96704553ULL,
			0x0E0E1DC92600760BULL,
			0x692475CF198F7F4DULL}
		},
		.Z = {.key64 = {
			0x213CDA86D329A17DULL,
			0x564926BD48484480ULL,
			0x1308EF8D8A5DBD9DULL,
			0x5C187CCF331E71CBULL}
		}
	};
	printf("Test Case 495\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 495 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -495;
	} else {
		printf("Test Case 495 PASSED\n");
	}

	steps = 53;
	X1 = (curve25519_key_t){.key64 = {
		0xDB48AD73E77F1BE8ULL,
		0x0DCD33B23AE76744ULL,
		0xF7EF74CA6647E668ULL,
		0x6AC8B41C3A78BE3EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDB48AD73E77F1BE8ULL,
			0x0DCD33B23AE76744ULL,
			0xF7EF74CA6647E668ULL,
			0x6AC8B41C3A78BE3EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x00D7949AF244C5BDULL,
			0x7E316EE85BF14B66ULL,
			0x38C9CD4B521D1CBEULL,
			0x018410FD23570CC3ULL}
		},
		.Z = {.key64 = {
			0xCFEDC16AB50D658CULL,
			0xA5791B4861741224ULL,
			0x72C3B513EBDBFB89ULL,
			0x1F6E7F45BA8A3D4FULL}
		}
	};
	printf("Test Case 496\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 496 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -496;
	} else {
		printf("Test Case 496 PASSED\n");
	}

	steps = 58;
	X1 = (curve25519_key_t){.key64 = {
		0x41603A112CC360A0ULL,
		0x62BCD70D590D4F6EULL,
		0x59421FDF89D21AE9ULL,
		0x4807C11C443E5E41ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x41603A112CC360A0ULL,
			0x62BCD70D590D4F6EULL,
			0x59421FDF89D21AE9ULL,
			0x4807C11C443E5E41ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAA77A6C18A88A3BFULL,
			0x7A7FB572CC93BBB7ULL,
			0xC8EA30E14EE42BAAULL,
			0x7D9DC9757093DB00ULL}
		},
		.Z = {.key64 = {
			0x5CAE75B650CC58C1ULL,
			0x7F924304C821ECEDULL,
			0x3C2396579EFBE956ULL,
			0x10B818C4B1000443ULL}
		}
	};
	printf("Test Case 497\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 497 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -497;
	} else {
		printf("Test Case 497 PASSED\n");
	}

	steps = 18;
	X1 = (curve25519_key_t){.key64 = {
		0xDF11A7CF45F57548ULL,
		0xC2276A7046E98FE6ULL,
		0x4B919A3CB233D601ULL,
		0x7008506A1731D0E6ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDF11A7CF45F57548ULL,
			0xC2276A7046E98FE6ULL,
			0x4B919A3CB233D601ULL,
			0x7008506A1731D0E6ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x585FDA61F5223087ULL,
			0x9009595A28A99651ULL,
			0x2758FA4591FBE886ULL,
			0x54072B2B676769DAULL}
		},
		.Z = {.key64 = {
			0xA36F7B60692689E9ULL,
			0xE45FD5BA9F632762ULL,
			0x4F1425F5C28E03A2ULL,
			0x1F38498E139CC0BFULL}
		}
	};
	printf("Test Case 498\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 498 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -498;
	} else {
		printf("Test Case 498 PASSED\n");
	}

	steps = 62;
	X1 = (curve25519_key_t){.key64 = {
		0x68CD2096E2B7FC40ULL,
		0x1BFADD7591C2A04DULL,
		0x6B6AE083EE89FF06ULL,
		0x774BE03E5AE5CBD6ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x68CD2096E2B7FC40ULL,
			0x1BFADD7591C2A04DULL,
			0x6B6AE083EE89FF06ULL,
			0x774BE03E5AE5CBD6ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7F968ED9CD09EA00ULL,
			0x69A932F22A113B44ULL,
			0x5378ED6661AD4B34ULL,
			0x665237864E6C3F5DULL}
		},
		.Z = {.key64 = {
			0x88FAD37A5D90758CULL,
			0x5D6B0FD69DCCE00EULL,
			0x8A7F468753D8636EULL,
			0x59D9AE024143E0E0ULL}
		}
	};
	printf("Test Case 499\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 499 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -499;
	} else {
		printf("Test Case 499 PASSED\n");
	}

	steps = 41;
	X1 = (curve25519_key_t){.key64 = {
		0x3F0DBD5D940389E8ULL,
		0xFA0B57439FE6515CULL,
		0xF4814F602942F5FEULL,
		0x478CDE942F45DA94ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3F0DBD5D940389E8ULL,
			0xFA0B57439FE6515CULL,
			0xF4814F602942F5FEULL,
			0x478CDE942F45DA94ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x748A83AC384636A1ULL,
			0x75D37A909D07C4E8ULL,
			0xF8ADCBA0E5535420ULL,
			0x214B9B88D75658C2ULL}
		},
		.Z = {.key64 = {
			0x11D723338336C006ULL,
			0xA17B54B7E04EF130ULL,
			0x3530E6D1627C91C3ULL,
			0x4453BFADAE3B2CAEULL}
		}
	};
	printf("Test Case 500\n");
	printf("X1:\n");
	curve25519_key_printf(&X1, COMPLETE);
	printf("XZ3.X:\n");
	curve25519_key_printf(&XZ3.X, COMPLETE);
	printf("Expected:\n");
	printf("XZ3n.X:\n");
	curve25519_key_printf(&XZ3n.X, COMPLETE);
	printf("XZ3n.Z:\n");
	curve25519_key_printf(&XZ3n.Z, COMPLETE);
	for (int i = 0; i < steps; ++i) curve25519_ladder_step(&XZ2, &XZ3, &X1);
	res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);
	if (res) {
		printf("Test Case 500 FAILED\n");
		printf("XZ3.X:\n");
		curve25519_key_printf(&XZ3.X, COMPLETE);
		printf("XZ3.Z:\n");
		curve25519_key_printf(&XZ3.Z, COMPLETE);
		return -500;
	} else {
		printf("Test Case 500 PASSED\n");
	}

	return 0;
}