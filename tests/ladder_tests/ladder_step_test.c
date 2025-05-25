#include "../tests.h"

int32_t curve25519_ladder_step_test(void) {
	printf("Montgomery Ladder Step Test\n");
	int steps = 21;
	curve25519_key_t X1 = {.key64 = {
		0xEFA5D357947D6140ULL,
		0x9419F9EB5F83D8F9ULL,
		0x0C1E6DF4EE901649ULL,
		0x79C9C6D14B83D51EULL
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
			0xEFA5D357947D6140ULL,
			0x9419F9EB5F83D8F9ULL,
			0x0C1E6DF4EE901649ULL,
			0x79C9C6D14B83D51EULL}
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
			0x77E0C3B8B7688A2EULL,
			0x30F8CCE31F93A816ULL,
			0x968CE431360790B4ULL,
			0x17376E10B44AF2D1ULL}
		},
		.Z = {.key64 = {
			0xF8BE9955E5E3A767ULL,
			0xE083C41267E54DFEULL,
			0x6D3FA5B3FDDB8686ULL,
			0x6D54AAECE8A89039ULL}
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

	steps = 31;
	X1 = (curve25519_key_t){.key64 = {
		0x7B64C5EDD0812CF8ULL,
		0x319235BBE83ACBFAULL,
		0x1DCF07E7DDE1E74FULL,
		0x4D768A516E2A43A0ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7B64C5EDD0812CF8ULL,
			0x319235BBE83ACBFAULL,
			0x1DCF07E7DDE1E74FULL,
			0x4D768A516E2A43A0ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x501E4D583F1F104EULL,
			0x8655EE6AB8F23EA2ULL,
			0x4535A51356551BE8ULL,
			0x00B26C56829B226EULL}
		},
		.Z = {.key64 = {
			0x99425C0C2D8E0D2CULL,
			0xCBD4021DD7F5BE43ULL,
			0x8289733E66294EDDULL,
			0x54A374B1ACA87EF8ULL}
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

	steps = 7;
	X1 = (curve25519_key_t){.key64 = {
		0xD27E506096857420ULL,
		0x13CB1B4C4291DCFAULL,
		0x370E5BB2C0031044ULL,
		0x670417D77570A34DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD27E506096857420ULL,
			0x13CB1B4C4291DCFAULL,
			0x370E5BB2C0031044ULL,
			0x670417D77570A34DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDBF2C326682B5D5EULL,
			0x54B2D60518115707ULL,
			0xAAB259C543B5D0F2ULL,
			0x279C3F757F931D6EULL}
		},
		.Z = {.key64 = {
			0x9B991C925890D49DULL,
			0xA0F4653C244119CBULL,
			0xF382EB68A232BED9ULL,
			0x75D3888E28E487D4ULL}
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

	steps = 30;
	X1 = (curve25519_key_t){.key64 = {
		0xBC70A17915366B48ULL,
		0x0DFE1A0BE2FF0A46ULL,
		0xCCEE9C162A662476ULL,
		0x680DE44C14A1EBBEULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBC70A17915366B48ULL,
			0x0DFE1A0BE2FF0A46ULL,
			0xCCEE9C162A662476ULL,
			0x680DE44C14A1EBBEULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA1F6B9920E4DBCE3ULL,
			0x95181FD3C991775FULL,
			0x1E551CF35E2F4783ULL,
			0x592354018AB6D90BULL}
		},
		.Z = {.key64 = {
			0xB11D7C50DB470D45ULL,
			0x0036D0B1EEB97197ULL,
			0xFB877A07BEB909AFULL,
			0x66B38537BAC2CDF0ULL}
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

	steps = 24;
	X1 = (curve25519_key_t){.key64 = {
		0x7042029EEEDF10E8ULL,
		0x1267110D17014FF8ULL,
		0x057ABE382EA0737DULL,
		0x5856B77C5E1D3D0EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7042029EEEDF10E8ULL,
			0x1267110D17014FF8ULL,
			0x057ABE382EA0737DULL,
			0x5856B77C5E1D3D0EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD4101E95114B763DULL,
			0x06E0CD02EF4B5AEEULL,
			0xB8A52348EB5E63ABULL,
			0x6E52A9F210463008ULL}
		},
		.Z = {.key64 = {
			0x5D46F7D9CE55E7DFULL,
			0x8FA5E1787DAC253DULL,
			0x927A5ED1AD3141D1ULL,
			0x58D2C4BC142B45A9ULL}
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

	steps = 24;
	X1 = (curve25519_key_t){.key64 = {
		0x299F14D4A797EA08ULL,
		0xB8E4FB7786EE7255ULL,
		0x3F411C5CE2589616ULL,
		0x7D34DEB9E149BB63ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x299F14D4A797EA08ULL,
			0xB8E4FB7786EE7255ULL,
			0x3F411C5CE2589616ULL,
			0x7D34DEB9E149BB63ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB58F1337C6237087ULL,
			0x3FD0510C4820A8B9ULL,
			0xB72748B3D1A89CEDULL,
			0x184CBA4B743D4DAAULL}
		},
		.Z = {.key64 = {
			0x43C1306DCA6455C2ULL,
			0xE6662F77F4CD1A3AULL,
			0x7465512CB1A8C8BAULL,
			0x0EB7D3D6DC887EA7ULL}
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

	steps = 34;
	X1 = (curve25519_key_t){.key64 = {
		0x5E4724DC392DF0A8ULL,
		0x22BE6DF2D206F074ULL,
		0xDEA064234274DF9CULL,
		0x7492A25477C81524ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5E4724DC392DF0A8ULL,
			0x22BE6DF2D206F074ULL,
			0xDEA064234274DF9CULL,
			0x7492A25477C81524ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x001101941ACA9C71ULL,
			0x208CCC5EC8685701ULL,
			0xB62FE5D04E69C8EBULL,
			0x202288524BFFEDC8ULL}
		},
		.Z = {.key64 = {
			0xF34ADCA1D46303DBULL,
			0xD0A55363F2809CC6ULL,
			0x2067FB6B71CD7510ULL,
			0x0C74C2A7E0ED10ADULL}
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

	steps = 37;
	X1 = (curve25519_key_t){.key64 = {
		0x81C4435EE001E720ULL,
		0xA6F65794614C90A1ULL,
		0x7A290E9DBEC75241ULL,
		0x5B04D8FC977E8B7FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x81C4435EE001E720ULL,
			0xA6F65794614C90A1ULL,
			0x7A290E9DBEC75241ULL,
			0x5B04D8FC977E8B7FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB992B0883FAF127DULL,
			0xE4432CFCDCA8BEA3ULL,
			0x272BE53F970115D1ULL,
			0x6475E0084D963CA5ULL}
		},
		.Z = {.key64 = {
			0xB4FE7309C21EC3E8ULL,
			0x4CD2DB6CAF655D8CULL,
			0x4CD4E28698CB5208ULL,
			0x66A75BC3A310C081ULL}
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

	steps = 5;
	X1 = (curve25519_key_t){.key64 = {
		0xE257B936D064D140ULL,
		0x4BD04F79284BF7C3ULL,
		0x0F9E3AD4150294D7ULL,
		0x67B483700AD404CFULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE257B936D064D140ULL,
			0x4BD04F79284BF7C3ULL,
			0x0F9E3AD4150294D7ULL,
			0x67B483700AD404CFULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0A3CD9ACC4010109ULL,
			0x496EF0D446A9AA06ULL,
			0x259EC55913F520ABULL,
			0x4C14B815A74EA597ULL}
		},
		.Z = {.key64 = {
			0xAF69A60FE3C72F6DULL,
			0x77B97D46629502FAULL,
			0x28ADFCEBECB69C10ULL,
			0x785C644E0E8C971CULL}
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

	steps = 30;
	X1 = (curve25519_key_t){.key64 = {
		0xD5C91116F31C5F80ULL,
		0xEEB7952983463B92ULL,
		0x2EF1E4B4E913FC06ULL,
		0x53221A8CABB1278AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD5C91116F31C5F80ULL,
			0xEEB7952983463B92ULL,
			0x2EF1E4B4E913FC06ULL,
			0x53221A8CABB1278AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA702EA9413501301ULL,
			0xEF0E9B30979B7D02ULL,
			0xAD6893412D166217ULL,
			0x6516867D975EB979ULL}
		},
		.Z = {.key64 = {
			0x85391A79DACE3DF2ULL,
			0xE7CA73474D97ABD2ULL,
			0xFB4822BA51BBA8ABULL,
			0x64C79900D6371898ULL}
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

	steps = 57;
	X1 = (curve25519_key_t){.key64 = {
		0xAA3F38D0ABD07010ULL,
		0x5037E7870F77081FULL,
		0x4F672C03781C99CAULL,
		0x65311DA0D23DC118ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAA3F38D0ABD07010ULL,
			0x5037E7870F77081FULL,
			0x4F672C03781C99CAULL,
			0x65311DA0D23DC118ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE6C307194E14191BULL,
			0x36CF394CE82A94A4ULL,
			0x5552214B77CA4D07ULL,
			0x4A166C461D0C007BULL}
		},
		.Z = {.key64 = {
			0xBF76EBCF13E06B52ULL,
			0x491C92E872BF01D7ULL,
			0xF99C2DDCA1FFBA2CULL,
			0x2B242712298322B2ULL}
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

	steps = 62;
	X1 = (curve25519_key_t){.key64 = {
		0x23711D67CD19AA68ULL,
		0x22A448CE8254995CULL,
		0xBA58FA9653BF6A69ULL,
		0x64C83A9A5B663BD4ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x23711D67CD19AA68ULL,
			0x22A448CE8254995CULL,
			0xBA58FA9653BF6A69ULL,
			0x64C83A9A5B663BD4ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5BFD0902EF023E61ULL,
			0x00372B562AA4D9D0ULL,
			0xB7983BA4CD679367ULL,
			0x63F8327A1D46960AULL}
		},
		.Z = {.key64 = {
			0x4B4910691BA9148DULL,
			0xE53D713AE23B3ECBULL,
			0x048091634FB594C0ULL,
			0x551326A95EFBB23CULL}
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

	steps = 49;
	X1 = (curve25519_key_t){.key64 = {
		0x4A9CC3BE98F061D0ULL,
		0x7137BDEA1ADD1381ULL,
		0xD12177904241CCE3ULL,
		0x5EC893073CBA7642ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4A9CC3BE98F061D0ULL,
			0x7137BDEA1ADD1381ULL,
			0xD12177904241CCE3ULL,
			0x5EC893073CBA7642ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1784CEA16FE8647AULL,
			0x8B03D8E89A09BE35ULL,
			0x1A2754481635F9CDULL,
			0x23479326A578C53AULL}
		},
		.Z = {.key64 = {
			0x6A603B8E1EDF5882ULL,
			0x6976E43F2C45B1C1ULL,
			0x956F7E4FA010A31DULL,
			0x3878F3218618E9AAULL}
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

	steps = 26;
	X1 = (curve25519_key_t){.key64 = {
		0x1DD112FEB4FE79D0ULL,
		0x574EB25A873ADAFBULL,
		0xA36B6CD982B0057FULL,
		0x7819C6A551CC5EFCULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1DD112FEB4FE79D0ULL,
			0x574EB25A873ADAFBULL,
			0xA36B6CD982B0057FULL,
			0x7819C6A551CC5EFCULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE9F0594BDAB49BC4ULL,
			0xE0572AD7137386FEULL,
			0x5B8CE283249B8226ULL,
			0x39ABEE81E2743D46ULL}
		},
		.Z = {.key64 = {
			0xFBF53B07DBB11F8FULL,
			0xD388374A524DE3FBULL,
			0x84F817192A9AEA94ULL,
			0x565BF461422FC22EULL}
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

	steps = 12;
	X1 = (curve25519_key_t){.key64 = {
		0x55E4A7F05AD87AA0ULL,
		0x10B5B096565FBEC0ULL,
		0x7D724252DA687870ULL,
		0x67A40C0F8284E990ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x55E4A7F05AD87AA0ULL,
			0x10B5B096565FBEC0ULL,
			0x7D724252DA687870ULL,
			0x67A40C0F8284E990ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB712983F59411919ULL,
			0xDD04CD818D5F3BA7ULL,
			0x654F349B8F98A423ULL,
			0x09AB99C3A31E939DULL}
		},
		.Z = {.key64 = {
			0xF8DBCF30EB22BAFAULL,
			0x164F1DAA568959C8ULL,
			0x1AD700B04F910E52ULL,
			0x3063C1D6289F8BF6ULL}
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

	steps = 29;
	X1 = (curve25519_key_t){.key64 = {
		0x77999128FC28B8A8ULL,
		0xB0F5D3686B133672ULL,
		0x6E6943B56FD4DDA0ULL,
		0x43B8F3B737859C3AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x77999128FC28B8A8ULL,
			0xB0F5D3686B133672ULL,
			0x6E6943B56FD4DDA0ULL,
			0x43B8F3B737859C3AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x48C689F428CE34D8ULL,
			0x9FEDE9027261BF9BULL,
			0x35E95DA9DBA3444AULL,
			0x2C58817FDFB20805ULL}
		},
		.Z = {.key64 = {
			0xE7378E904F2D0581ULL,
			0x5EE9C5DD54C8A32CULL,
			0x600257853B7038D6ULL,
			0x5C7199E899233360ULL}
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

	steps = 31;
	X1 = (curve25519_key_t){.key64 = {
		0x60577C9149D81DD0ULL,
		0xCFAA83BBDDF721F0ULL,
		0xAB1B7DE07EB3B601ULL,
		0x6225A56F2FB6DE86ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x60577C9149D81DD0ULL,
			0xCFAA83BBDDF721F0ULL,
			0xAB1B7DE07EB3B601ULL,
			0x6225A56F2FB6DE86ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x34E230C62A6E1791ULL,
			0x6FD18D52E6DF4558ULL,
			0x0E5D51471F910B72ULL,
			0x2B6A6512059AF88AULL}
		},
		.Z = {.key64 = {
			0xD3804F81CB261762ULL,
			0x9991D1C26C6895E7ULL,
			0x9E59DC5C43A8916DULL,
			0x286E69184BAF8B1AULL}
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

	steps = 33;
	X1 = (curve25519_key_t){.key64 = {
		0x09B4912299FF5918ULL,
		0x9B4AB93977E22CD4ULL,
		0x795E0A6E496F64D3ULL,
		0x5C59FE80D75A141CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x09B4912299FF5918ULL,
			0x9B4AB93977E22CD4ULL,
			0x795E0A6E496F64D3ULL,
			0x5C59FE80D75A141CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE86C7BFA25C0589FULL,
			0x741B83BDCCC4C054ULL,
			0x3667A4BF01F68B4FULL,
			0x6EE4966476F9B42EULL}
		},
		.Z = {.key64 = {
			0x04C32F30B83DF82AULL,
			0x0A7DB7D50255F929ULL,
			0x97851C61746D21D2ULL,
			0x45AC203A9EA56514ULL}
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

	steps = 1;
	X1 = (curve25519_key_t){.key64 = {
		0xAA9261ECA9D9CAE8ULL,
		0x9E4BA4D2E7A1EB03ULL,
		0x59136144E5652D93ULL,
		0x7941CE913729772BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAA9261ECA9D9CAE8ULL,
			0x9E4BA4D2E7A1EB03ULL,
			0x59136144E5652D93ULL,
			0x7941CE913729772BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x194451D40CB824DCULL,
			0x4E207AE4C9AC80AFULL,
			0xC3B5A7F73D886AD5ULL,
			0x558A8BDD84843B28ULL}
		},
		.Z = {.key64 = {
			0xAA4987B2A7672BD9ULL,
			0x792E934B9E87AC0EULL,
			0x644D85139594B64EULL,
			0x65073A44DCA5DCADULL}
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

	steps = 59;
	X1 = (curve25519_key_t){.key64 = {
		0x78FCF226D0492608ULL,
		0xE7FC858288C2FB0BULL,
		0x77C3B673E6EE063EULL,
		0x7550C1D012510626ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x78FCF226D0492608ULL,
			0xE7FC858288C2FB0BULL,
			0x77C3B673E6EE063EULL,
			0x7550C1D012510626ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7C724CC9D6DF4E1FULL,
			0x72E249ABAE4D3E57ULL,
			0xC760B7D0E7D32A1FULL,
			0x58C36076968ABCB1ULL}
		},
		.Z = {.key64 = {
			0x6E224B12A2AC319DULL,
			0xCB862B567E66DB05ULL,
			0xA2A60372E942DF5BULL,
			0x5B529B4FCA1B77C8ULL}
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

	steps = 16;
	X1 = (curve25519_key_t){.key64 = {
		0x19DB27636E466CE0ULL,
		0xB8A7E5549CEAEE33ULL,
		0xA61706E02E30CC0FULL,
		0x5A649FCF1F0423F2ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x19DB27636E466CE0ULL,
			0xB8A7E5549CEAEE33ULL,
			0xA61706E02E30CC0FULL,
			0x5A649FCF1F0423F2ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4293234568919E95ULL,
			0xEC67DCF6A4DA2A70ULL,
			0xC074D6184CA810A1ULL,
			0x698820FD684A72B8ULL}
		},
		.Z = {.key64 = {
			0x86A5B68BA637B49AULL,
			0x756BB2BC58114705ULL,
			0x199DCE1B35B3D1F6ULL,
			0x2505BCE16495AE93ULL}
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

	steps = 60;
	X1 = (curve25519_key_t){.key64 = {
		0x99497D6BA451A5A0ULL,
		0x9DAEDA4ECDF71FF8ULL,
		0x410E0752A456AF5EULL,
		0x7F93B4285864C21FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x99497D6BA451A5A0ULL,
			0x9DAEDA4ECDF71FF8ULL,
			0x410E0752A456AF5EULL,
			0x7F93B4285864C21FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9FB87A7847F93CF9ULL,
			0x833D980627CD50D9ULL,
			0x2E069A179F9AF5D1ULL,
			0x275CC77AE23ABB60ULL}
		},
		.Z = {.key64 = {
			0x85478F6BC8D40E55ULL,
			0x6E60A17BDEBEF85AULL,
			0x219757B38DC2B6A0ULL,
			0x2A8425C027653DEDULL}
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

	steps = 41;
	X1 = (curve25519_key_t){.key64 = {
		0xAC13F9649B1C55E0ULL,
		0x519465187024FBF8ULL,
		0xC664511E49AFDB69ULL,
		0x74A18B457D676DCAULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAC13F9649B1C55E0ULL,
			0x519465187024FBF8ULL,
			0xC664511E49AFDB69ULL,
			0x74A18B457D676DCAULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x38E9A8A7457235B5ULL,
			0x31E15F76316BC130ULL,
			0xBF45375939887DD0ULL,
			0x10A12BACCC0F1EFDULL}
		},
		.Z = {.key64 = {
			0x5C3093BBEA607AC1ULL,
			0x6DDCF4898CD0FAB2ULL,
			0xBEAA9EAB3D4D0F96ULL,
			0x505F3F3A907AFFD7ULL}
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

	steps = 41;
	X1 = (curve25519_key_t){.key64 = {
		0x0963BEE054900598ULL,
		0x801C7D3142801E83ULL,
		0xF6966E8F500452C8ULL,
		0x6A7AE3070DAA39E6ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0963BEE054900598ULL,
			0x801C7D3142801E83ULL,
			0xF6966E8F500452C8ULL,
			0x6A7AE3070DAA39E6ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1269E806A80B6FBAULL,
			0xC6815C0F2F8099E6ULL,
			0x73F4352210941AFBULL,
			0x698AA2DCF5CFC563ULL}
		},
		.Z = {.key64 = {
			0xCA1BFC666C61FC9CULL,
			0x498D5256E9334678ULL,
			0xF4C8E1D2366C267DULL,
			0x0E0B9A22667C814AULL}
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

	steps = 40;
	X1 = (curve25519_key_t){.key64 = {
		0x61B58DAF6F215D38ULL,
		0x3D7FABC98874CB9CULL,
		0x3F9154316472DEA3ULL,
		0x5CF14836D6B3DDD0ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x61B58DAF6F215D38ULL,
			0x3D7FABC98874CB9CULL,
			0x3F9154316472DEA3ULL,
			0x5CF14836D6B3DDD0ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCD986AECF0239AC7ULL,
			0x356BE647BFBD0441ULL,
			0x9531FE0162D6F770ULL,
			0x26EBCA06F9A9DF73ULL}
		},
		.Z = {.key64 = {
			0xF1DD38863A675F57ULL,
			0x6F80CF0807771C94ULL,
			0x9F5D3DCE63BDC807ULL,
			0x572EB57B056A3A9DULL}
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

	steps = 25;
	X1 = (curve25519_key_t){.key64 = {
		0x33CECB5D928549D8ULL,
		0x8C6CCD7429E79F2BULL,
		0x47E939DFE10C3D63ULL,
		0x6C893F6BD11159F5ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x33CECB5D928549D8ULL,
			0x8C6CCD7429E79F2BULL,
			0x47E939DFE10C3D63ULL,
			0x6C893F6BD11159F5ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x332769D255A2EFB6ULL,
			0xECB69ECC6CDDB393ULL,
			0x7E046D23690DF113ULL,
			0x5D5EE36ED1B5BBCFULL}
		},
		.Z = {.key64 = {
			0x545304CE0C1D4D8BULL,
			0xC4AF928195299CDFULL,
			0x0D65C97260EC3E50ULL,
			0x4058C9F7DC029047ULL}
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

	steps = 12;
	X1 = (curve25519_key_t){.key64 = {
		0x9C1E3851B7D4A2B8ULL,
		0xDBBB1356F86C8683ULL,
		0x28E7F2E5F4B4DFCDULL,
		0x6D2D1D60D9712CABULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9C1E3851B7D4A2B8ULL,
			0xDBBB1356F86C8683ULL,
			0x28E7F2E5F4B4DFCDULL,
			0x6D2D1D60D9712CABULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x99F6C051EE48649EULL,
			0xF72EEC588A14F8B5ULL,
			0x566AC969AA4FB8D2ULL,
			0x4801F37EB93DDA35ULL}
		},
		.Z = {.key64 = {
			0xDABAB7F7384AC0FDULL,
			0x987B9726A4AE5F2FULL,
			0x3349C74B4E3A5DE2ULL,
			0x5785F4D54EF9FC00ULL}
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

	steps = 61;
	X1 = (curve25519_key_t){.key64 = {
		0x89B0FF0BC6A27E18ULL,
		0x6D3890C9E6112348ULL,
		0x296D0793AF3490F9ULL,
		0x4BD715F8077C62BDULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x89B0FF0BC6A27E18ULL,
			0x6D3890C9E6112348ULL,
			0x296D0793AF3490F9ULL,
			0x4BD715F8077C62BDULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAF3EBA621E058506ULL,
			0xD00CA09CB16304FFULL,
			0x456485F9AD51C39FULL,
			0x1C0DA094B40440C9ULL}
		},
		.Z = {.key64 = {
			0x65471154FB9F33B4ULL,
			0xC1C8409BCC3A674EULL,
			0x5E7A57FF47E07F7EULL,
			0x23CF8B5D1BC138D5ULL}
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
		0x0DE0CEF7804EA8E0ULL,
		0x0EC5BE8AE1A097ABULL,
		0x7C56400EACDE4653ULL,
		0x6EFD3E42495CC0A8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0DE0CEF7804EA8E0ULL,
			0x0EC5BE8AE1A097ABULL,
			0x7C56400EACDE4653ULL,
			0x6EFD3E42495CC0A8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x65EA53F5135A4370ULL,
			0x96A98067AD2C7D63ULL,
			0xE09321775BD05671ULL,
			0x6AD674AB244A9135ULL}
		},
		.Z = {.key64 = {
			0x7F0C6FD81E0E7186ULL,
			0x540303E4732C8045ULL,
			0x7C877A4A1416A44EULL,
			0x41EC0050AF2629A5ULL}
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

	steps = 1;
	X1 = (curve25519_key_t){.key64 = {
		0x4F0EB8BA5FB01710ULL,
		0xE74A6B8C6A4A0B84ULL,
		0x16929AD1AAFFC763ULL,
		0x669077ADA948DC52ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4F0EB8BA5FB01710ULL,
			0xE74A6B8C6A4A0B84ULL,
			0x16929AD1AAFFC763ULL,
			0x669077ADA948DC52ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0F9293C062ECDE21ULL,
			0xC0794BD0E0543353ULL,
			0xB25DCBBCF8D60F85ULL,
			0x33A5CC5A4BB32D7FULL}
		},
		.Z = {.key64 = {
			0x3C3AE2E97EC05C79ULL,
			0x9D29AE31A9282E11ULL,
			0x5A4A6B46ABFF1D8FULL,
			0x1A41DEB6A5237148ULL}
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

	steps = 63;
	X1 = (curve25519_key_t){.key64 = {
		0x5ABF2859FE1E8BB8ULL,
		0xEE50654541038D59ULL,
		0xD44CDC2791B7DD5CULL,
		0x4CC80E57B17AE198ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5ABF2859FE1E8BB8ULL,
			0xEE50654541038D59ULL,
			0xD44CDC2791B7DD5CULL,
			0x4CC80E57B17AE198ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC9E01674F1BDF8ABULL,
			0xC9D62B594B3E54BFULL,
			0xB1523D19C960FB2AULL,
			0x51E8FE03F3D06D4CULL}
		},
		.Z = {.key64 = {
			0x09CCE673DE0FF88FULL,
			0xF9440B0489D8D09EULL,
			0xD72234ACAC58D529ULL,
			0x673F6845B324B236ULL}
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

	steps = 36;
	X1 = (curve25519_key_t){.key64 = {
		0x1286DA45E2D19740ULL,
		0x323BC08B9FDF811BULL,
		0x3ADCF0AF1A26937EULL,
		0x612D4D72F107556AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1286DA45E2D19740ULL,
			0x323BC08B9FDF811BULL,
			0x3ADCF0AF1A26937EULL,
			0x612D4D72F107556AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x806D8FEF7A0EE216ULL,
			0xFE7A45F973B9F973ULL,
			0x68C1D3EA17A8C86AULL,
			0x76AB50822D1A36AAULL}
		},
		.Z = {.key64 = {
			0x0EE6BBFEAA6E8819ULL,
			0xDFD6A145315F6B91ULL,
			0xE6F56557726C3032ULL,
			0x640BA37C2227DD37ULL}
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

	steps = 64;
	X1 = (curve25519_key_t){.key64 = {
		0x2DB90C03F0DE7FE0ULL,
		0x72623A394FFFBB66ULL,
		0x7D737496920E94F1ULL,
		0x6A5D8EBA768904D6ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2DB90C03F0DE7FE0ULL,
			0x72623A394FFFBB66ULL,
			0x7D737496920E94F1ULL,
			0x6A5D8EBA768904D6ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9CF728111EE67516ULL,
			0x9342769D3DC1FC89ULL,
			0x40360A32F5001C78ULL,
			0x3258E3085CE97E05ULL}
		},
		.Z = {.key64 = {
			0x556487FE6DE32B4EULL,
			0xB30CA34B844BBD91ULL,
			0xD069D5FC70E123ACULL,
			0x1DF25F6F95D19545ULL}
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

	steps = 58;
	X1 = (curve25519_key_t){.key64 = {
		0x26CEBB6C1B33D5F8ULL,
		0x71C1E06C9D06F37AULL,
		0x27E61973007D78E1ULL,
		0x5C60BA08763BA633ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x26CEBB6C1B33D5F8ULL,
			0x71C1E06C9D06F37AULL,
			0x27E61973007D78E1ULL,
			0x5C60BA08763BA633ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x96002BA842074238ULL,
			0xEB926BAA9AA1B5B5ULL,
			0x9F1AE690A015BB14ULL,
			0x406D25D9F88CF0B3ULL}
		},
		.Z = {.key64 = {
			0xD0EDED411C6A30D1ULL,
			0x41D62BAE44F212B5ULL,
			0x9696528B67B94750ULL,
			0x41ABE726CE2DECE5ULL}
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

	steps = 52;
	X1 = (curve25519_key_t){.key64 = {
		0x6C7DFE6610C7CB98ULL,
		0x1EBBE5452956C75DULL,
		0x4B2F8A7AD87B5A56ULL,
		0x5B6793A0229FAAD8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6C7DFE6610C7CB98ULL,
			0x1EBBE5452956C75DULL,
			0x4B2F8A7AD87B5A56ULL,
			0x5B6793A0229FAAD8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFFE0D93059E359ABULL,
			0x2EA97B5D0DA9271EULL,
			0xDAA506FD5481EEF3ULL,
			0x64AB1F9999EDB54FULL}
		},
		.Z = {.key64 = {
			0xEE19AF3FB2E3B0B0ULL,
			0x7A61E58E71F515F4ULL,
			0xA51582C6AB85A748ULL,
			0x7E47D6CBE0B63E34ULL}
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

	steps = 64;
	X1 = (curve25519_key_t){.key64 = {
		0x8260951D4D7FE780ULL,
		0xFEB54AAFE423BDB0ULL,
		0xB2782FC4830BFCF6ULL,
		0x7009A900BDD698EDULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8260951D4D7FE780ULL,
			0xFEB54AAFE423BDB0ULL,
			0xB2782FC4830BFCF6ULL,
			0x7009A900BDD698EDULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x020751002605088DULL,
			0xB5AA46BEF79F796CULL,
			0x9C319335408E177FULL,
			0x00FC3AD4433370C7ULL}
		},
		.Z = {.key64 = {
			0x1B7FDC08FDA3C7BBULL,
			0xFAAAC2209263A634ULL,
			0xEBB66055EF7C67E3ULL,
			0x1711FC028B6059E5ULL}
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

	steps = 33;
	X1 = (curve25519_key_t){.key64 = {
		0x93E8FB545153A918ULL,
		0x657B6EA4158F8DE7ULL,
		0xC13D309970ADC051ULL,
		0x651430A1227A3C82ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x93E8FB545153A918ULL,
			0x657B6EA4158F8DE7ULL,
			0xC13D309970ADC051ULL,
			0x651430A1227A3C82ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE2E076E4597992F7ULL,
			0xC283951CDF47124CULL,
			0x1CF4BDC763270EF4ULL,
			0x7E737609BC052B74ULL}
		},
		.Z = {.key64 = {
			0xECE53C657E86FB9FULL,
			0xDDA05FDE52F2E50CULL,
			0x94B53C1F5D3AABC3ULL,
			0x327615DA5D57454AULL}
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

	steps = 30;
	X1 = (curve25519_key_t){.key64 = {
		0xA153E33AF5712820ULL,
		0x4C20560B143FDC3EULL,
		0x2B228ABA27DF0203ULL,
		0x42A43823A5215FDBULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA153E33AF5712820ULL,
			0x4C20560B143FDC3EULL,
			0x2B228ABA27DF0203ULL,
			0x42A43823A5215FDBULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC8A841F7BFFB3E9DULL,
			0x54FA111F2D03BFBEULL,
			0x75521547FFA21ECCULL,
			0x13C54CCDF26D11DAULL}
		},
		.Z = {.key64 = {
			0x64F54A6485148C96ULL,
			0xBA9912FB496500A6ULL,
			0xF70FFBDE988276F4ULL,
			0x4A73833AE05337D3ULL}
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

	steps = 4;
	X1 = (curve25519_key_t){.key64 = {
		0x36D1CB036F81DE58ULL,
		0xE7A67D7C30128C7AULL,
		0x0878BADE36331777ULL,
		0x41F4C0718D5673ADULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x36D1CB036F81DE58ULL,
			0xE7A67D7C30128C7AULL,
			0x0878BADE36331777ULL,
			0x41F4C0718D5673ADULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2B64DC90E3CBC7D5ULL,
			0x1A3AD12D84C2F80CULL,
			0x9F946377E3E888EFULL,
			0x53FDD54E87E8C854ULL}
		},
		.Z = {.key64 = {
			0x3069F3A5065F85CAULL,
			0x41BCC77EA348C8C5ULL,
			0x7AE70AF2DBD9D33BULL,
			0x400E2FA20CA2CE6AULL}
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

	steps = 10;
	X1 = (curve25519_key_t){.key64 = {
		0x125410EE88BD6720ULL,
		0xD4C448C626348818ULL,
		0x955EE2B84A36D995ULL,
		0x50EB7DBE529C5676ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x125410EE88BD6720ULL,
			0xD4C448C626348818ULL,
			0x955EE2B84A36D995ULL,
			0x50EB7DBE529C5676ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x04685B70AF19F6ECULL,
			0x43BF0505487B3F68ULL,
			0x814751D37D71C00AULL,
			0x1CD161527C7B3135ULL}
		},
		.Z = {.key64 = {
			0x54D932DDB2990F2BULL,
			0xF736FDA106A837ACULL,
			0x0D160CA9CCEB579DULL,
			0x4FD5EAD55A8E4E90ULL}
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

	steps = 62;
	X1 = (curve25519_key_t){.key64 = {
		0xDC568A067FB4E810ULL,
		0x8FE481E97E9EF53AULL,
		0x6B8C82C2B7F78B45ULL,
		0x51B6D39744F8A84FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDC568A067FB4E810ULL,
			0x8FE481E97E9EF53AULL,
			0x6B8C82C2B7F78B45ULL,
			0x51B6D39744F8A84FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBBD7F4901DD06D0FULL,
			0x9C438660F085C936ULL,
			0xDAB8D73CF0D96213ULL,
			0x59D3C45E7405CFCDULL}
		},
		.Z = {.key64 = {
			0x01C9452CBC0A007AULL,
			0xEAAD93AD7BCCB086ULL,
			0x3A13B25CA0B1A74BULL,
			0x10ECBE28C0C93C69ULL}
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

	steps = 41;
	X1 = (curve25519_key_t){.key64 = {
		0x596BFA131F5F85A8ULL,
		0x4229E410CF998D8AULL,
		0x0229726C7958FB3EULL,
		0x407155EDCD22B033ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x596BFA131F5F85A8ULL,
			0x4229E410CF998D8AULL,
			0x0229726C7958FB3EULL,
			0x407155EDCD22B033ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3A9CE14803B51B19ULL,
			0x35B868183707838DULL,
			0x4583E6FB5B63B33CULL,
			0x50A719FD63A03ED3ULL}
		},
		.Z = {.key64 = {
			0xF715DF95D74E8FF4ULL,
			0xDFFCC261D2F9AE72ULL,
			0x7061F78B925D9EA8ULL,
			0x5A62A37FCC078C2AULL}
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

	steps = 6;
	X1 = (curve25519_key_t){.key64 = {
		0xAB2254600AFF18A8ULL,
		0x068D719D592F00BFULL,
		0x5EB0F9DF552D58C6ULL,
		0x62668202B3B07548ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAB2254600AFF18A8ULL,
			0x068D719D592F00BFULL,
			0x5EB0F9DF552D58C6ULL,
			0x62668202B3B07548ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x62C2A9921B78060AULL,
			0xFFEED8D9D193A46BULL,
			0x3AB8CFD3768146B4ULL,
			0x3A94D9D7BB5B1330ULL}
		},
		.Z = {.key64 = {
			0xFF9E568190E6218CULL,
			0xFF0776A9504076F9ULL,
			0x3A71361E1B93942BULL,
			0x1DEA84CEE8214DEEULL}
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

	steps = 58;
	X1 = (curve25519_key_t){.key64 = {
		0x2415D950DBFA8068ULL,
		0x6230164CC8084D22ULL,
		0x7A8DAD120FD40C01ULL,
		0x4D81BCE4E2C46223ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2415D950DBFA8068ULL,
			0x6230164CC8084D22ULL,
			0x7A8DAD120FD40C01ULL,
			0x4D81BCE4E2C46223ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x600FD536C312FD4BULL,
			0x4858C670B88E1C10ULL,
			0x3E6ED949D57D5521ULL,
			0x59B2448E0B702449ULL}
		},
		.Z = {.key64 = {
			0xCA1C7478EE120AC8ULL,
			0xF346F87A1013C4CAULL,
			0x61FCD4C33B1B185CULL,
			0x0C066BF9573188E1ULL}
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

	steps = 43;
	X1 = (curve25519_key_t){.key64 = {
		0x520BBB3EFF340A80ULL,
		0x7E293D519906208FULL,
		0xA2B4D351BF98CDE7ULL,
		0x59A7E734720EF278ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x520BBB3EFF340A80ULL,
			0x7E293D519906208FULL,
			0xA2B4D351BF98CDE7ULL,
			0x59A7E734720EF278ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x59D47797C1DE9245ULL,
			0x227A76C76DF2CE81ULL,
			0x006121983A456BF4ULL,
			0x4EB251D0F6372A1FULL}
		},
		.Z = {.key64 = {
			0x3E62B886DEA4CDD7ULL,
			0xD0977D1112F8C104ULL,
			0x225B2EFD33449096ULL,
			0x515D00B724C62CC3ULL}
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

	steps = 49;
	X1 = (curve25519_key_t){.key64 = {
		0xE17286400D6F5438ULL,
		0x49E3DC6D51B991DAULL,
		0xB8279963DB7E3036ULL,
		0x510FCF610BF342C5ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE17286400D6F5438ULL,
			0x49E3DC6D51B991DAULL,
			0xB8279963DB7E3036ULL,
			0x510FCF610BF342C5ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6399DFD56023104EULL,
			0x6CDD532ECCADE607ULL,
			0x02D9DE0BF435E799ULL,
			0x2000C8D9839B09E6ULL}
		},
		.Z = {.key64 = {
			0xA783FCA89FFD3474ULL,
			0x6F23AEADC5154003ULL,
			0xEF1C49001333C4DFULL,
			0x42DEB1C4D38AFE64ULL}
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

	steps = 29;
	X1 = (curve25519_key_t){.key64 = {
		0xEA8EEC277A96E8F0ULL,
		0x13C75CC9349A5D24ULL,
		0x9C7DDACF520FFAE6ULL,
		0x68B3DB283B3EF3B3ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEA8EEC277A96E8F0ULL,
			0x13C75CC9349A5D24ULL,
			0x9C7DDACF520FFAE6ULL,
			0x68B3DB283B3EF3B3ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x24DF701390F0E085ULL,
			0x825CCAA64C2F406FULL,
			0x6B2C9299F04491EDULL,
			0x64180E5068421EEBULL}
		},
		.Z = {.key64 = {
			0xF61D276F20137C09ULL,
			0x1C5F7142ED5DD9FCULL,
			0x2135DE8F16890D1CULL,
			0x2B457E76DABCB221ULL}
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

	steps = 32;
	X1 = (curve25519_key_t){.key64 = {
		0xB7FF6F5050D1D920ULL,
		0x61FD90FCA2F5A48EULL,
		0x5AFCBB3657EBE627ULL,
		0x4944C53C4C7F6F4EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB7FF6F5050D1D920ULL,
			0x61FD90FCA2F5A48EULL,
			0x5AFCBB3657EBE627ULL,
			0x4944C53C4C7F6F4EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCE0C71F4B942725FULL,
			0x0ECF42054A6D34F1ULL,
			0x7E8ACDA371296B10ULL,
			0x598E3B29A188DD4FULL}
		},
		.Z = {.key64 = {
			0x800C3CA186A17732ULL,
			0xC18214AB54082078ULL,
			0xCE65927697115AB6ULL,
			0x31CDE3F5503BF90FULL}
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
		0x0BFC49DDD2E74510ULL,
		0x13A5E9B392743527ULL,
		0x1C2C9F2E997407DEULL,
		0x4BC7B1343C91BB43ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0BFC49DDD2E74510ULL,
			0x13A5E9B392743527ULL,
			0x1C2C9F2E997407DEULL,
			0x4BC7B1343C91BB43ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x79207A2076B71D09ULL,
			0x5FE64D6FFF86C23FULL,
			0xB8E4211449A4D773ULL,
			0x3CE4271C8C125007ULL}
		},
		.Z = {.key64 = {
			0x810AFEDF417D7EC7ULL,
			0x12550546E9E4F98AULL,
			0xBE8E03770A1A41E3ULL,
			0x612BDD6906876B2EULL}
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

	steps = 38;
	X1 = (curve25519_key_t){.key64 = {
		0xE91D1EA936129C40ULL,
		0x28D26592F62C7476ULL,
		0xC93699E5B684AEC6ULL,
		0x610C74061587A09BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE91D1EA936129C40ULL,
			0x28D26592F62C7476ULL,
			0xC93699E5B684AEC6ULL,
			0x610C74061587A09BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x83C544FD23324519ULL,
			0x39957CDB201B38C5ULL,
			0x24975D852202EA26ULL,
			0x3DEF0DFD7FFFAB17ULL}
		},
		.Z = {.key64 = {
			0x2F35149B7C376EB5ULL,
			0x82218D8108D3D290ULL,
			0xF0A48E7EE408096EULL,
			0x511EAEE20AE6C2C3ULL}
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

	steps = 22;
	X1 = (curve25519_key_t){.key64 = {
		0x21EDE927ABF11DB8ULL,
		0xFA199F554CFADA30ULL,
		0x4E4A478A431ECB62ULL,
		0x72983469C55FE609ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x21EDE927ABF11DB8ULL,
			0xFA199F554CFADA30ULL,
			0x4E4A478A431ECB62ULL,
			0x72983469C55FE609ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA6D19AD136EAC875ULL,
			0xAA1E6D5A54F4ACF3ULL,
			0x89B962E4B8BA83C6ULL,
			0x726EF7646D0F2AF8ULL}
		},
		.Z = {.key64 = {
			0x06B160E6D082D024ULL,
			0x8F9F0895C39B9188ULL,
			0x5579C5826E6A190EULL,
			0x5C79229270AF54F8ULL}
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

	steps = 42;
	X1 = (curve25519_key_t){.key64 = {
		0xCA8D900FB4FE4B38ULL,
		0x7C951C79EA1FF752ULL,
		0x966B709296282E3FULL,
		0x56DA8509A5EF53BBULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCA8D900FB4FE4B38ULL,
			0x7C951C79EA1FF752ULL,
			0x966B709296282E3FULL,
			0x56DA8509A5EF53BBULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x50159647D9AD9671ULL,
			0x1110F3D5F9F9E7ABULL,
			0x80E2EC1268E7DA53ULL,
			0x58E744416B73951CULL}
		},
		.Z = {.key64 = {
			0x61EE591B20DB0BA0ULL,
			0xDCBD58AFEB4B13B9ULL,
			0xCD63E5D562E7AD84ULL,
			0x3CFE9C61A9706D16ULL}
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

	steps = 48;
	X1 = (curve25519_key_t){.key64 = {
		0xA1009621268AAE88ULL,
		0x65846708A90D0E5FULL,
		0x1F75522E4754846BULL,
		0x5CC6B39678D40007ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA1009621268AAE88ULL,
			0x65846708A90D0E5FULL,
			0x1F75522E4754846BULL,
			0x5CC6B39678D40007ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA49CB49A10450543ULL,
			0x3F42F71BA16BA600ULL,
			0xCF0917ABE991C178ULL,
			0x7DEF538DD450CF19ULL}
		},
		.Z = {.key64 = {
			0x736E44DA15877558ULL,
			0xB2D0E188959B5747ULL,
			0x368F309142451877ULL,
			0x596AC16C0266F825ULL}
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

	steps = 7;
	X1 = (curve25519_key_t){.key64 = {
		0x8FD930DAC4881120ULL,
		0xE56FE02B5038E02EULL,
		0x1D9A3C5E2809A3BEULL,
		0x541363937EF6638CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8FD930DAC4881120ULL,
			0xE56FE02B5038E02EULL,
			0x1D9A3C5E2809A3BEULL,
			0x541363937EF6638CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x234B506637AD4C6DULL,
			0xC185BCAB8B3CB4D0ULL,
			0x18B9BF11DF298C63ULL,
			0x6666A777F66D545BULL}
		},
		.Z = {.key64 = {
			0x12C709880FD6759BULL,
			0x030C4AED11B9CA02ULL,
			0x984A03FF73F4548CULL,
			0x6ADC3CD8A66C3C75ULL}
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

	steps = 54;
	X1 = (curve25519_key_t){.key64 = {
		0x53EA1DA9EC573298ULL,
		0x4C94D52B8BEBEB26ULL,
		0x2D205774BC2B1977ULL,
		0x73F19DF04F293A60ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x53EA1DA9EC573298ULL,
			0x4C94D52B8BEBEB26ULL,
			0x2D205774BC2B1977ULL,
			0x73F19DF04F293A60ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF734824E30C042E1ULL,
			0x6DDCE5D4745AE07AULL,
			0x47C72FDC1787BE42ULL,
			0x7DB0117680886C47ULL}
		},
		.Z = {.key64 = {
			0x0D7155A958846BD9ULL,
			0x32037FBE94AE937BULL,
			0x52E1FDE9C09ACE9FULL,
			0x25F009F7AA58570CULL}
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

	steps = 37;
	X1 = (curve25519_key_t){.key64 = {
		0x728ABF9E60C5BB70ULL,
		0xE8E794F71EEF3261ULL,
		0x87D953671DE4FEA3ULL,
		0x7B6A03D5AAF79F42ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x728ABF9E60C5BB70ULL,
			0xE8E794F71EEF3261ULL,
			0x87D953671DE4FEA3ULL,
			0x7B6A03D5AAF79F42ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDBAF7A9D5644795BULL,
			0x37081281A4FC3025ULL,
			0xF0CDC3BE07E05A68ULL,
			0x44E6BCF26C7FE567ULL}
		},
		.Z = {.key64 = {
			0xA4534FF708072453ULL,
			0x5A6D5159BA6AEB17ULL,
			0xA156C957C579118CULL,
			0x4AFA7606A24A25BBULL}
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

	steps = 24;
	X1 = (curve25519_key_t){.key64 = {
		0x253E22EE66E37950ULL,
		0xFFFC9AF4BE6379BBULL,
		0x29F11814CB55BC46ULL,
		0x4D56B072AB687C4EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x253E22EE66E37950ULL,
			0xFFFC9AF4BE6379BBULL,
			0x29F11814CB55BC46ULL,
			0x4D56B072AB687C4EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x896BE5A414527C8BULL,
			0x36A4725F0D41A318ULL,
			0x9122B8211DEF6984ULL,
			0x1CCDA526194BCEC5ULL}
		},
		.Z = {.key64 = {
			0xD98DAA86A65E285FULL,
			0xFEDE6A51B31B68CCULL,
			0x84F19E2E493175E0ULL,
			0x4AF348456B416CE1ULL}
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

	steps = 58;
	X1 = (curve25519_key_t){.key64 = {
		0xFEB83F0BD546EA70ULL,
		0xD357B5682BEB25E0ULL,
		0x451EE474CB0FCF47ULL,
		0x72F7530FD900B558ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFEB83F0BD546EA70ULL,
			0xD357B5682BEB25E0ULL,
			0x451EE474CB0FCF47ULL,
			0x72F7530FD900B558ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7D3264FDDC01876DULL,
			0xC74415AAFA3A2F7DULL,
			0xEABCC5787B932F94ULL,
			0x412D2470DC09517AULL}
		},
		.Z = {.key64 = {
			0x236859AB973EC35CULL,
			0xFB16ED16153183FBULL,
			0x8761DC6AD7C49037ULL,
			0x6E96691D85364CF1ULL}
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

	steps = 5;
	X1 = (curve25519_key_t){.key64 = {
		0x1199047AE9CFB328ULL,
		0xF240504B4046E302ULL,
		0xAD53FFD0E1C30A98ULL,
		0x54226BD8B584BF34ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1199047AE9CFB328ULL,
			0xF240504B4046E302ULL,
			0xAD53FFD0E1C30A98ULL,
			0x54226BD8B584BF34ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA5CD05444A8CD10AULL,
			0x8964F0DE691D85C1ULL,
			0x94E82920CAEA7B2DULL,
			0x7C07A105569D15AAULL}
		},
		.Z = {.key64 = {
			0xBD5DBD14495B5028ULL,
			0xFBAFA57038AB1080ULL,
			0xA5F695F10CAEF215ULL,
			0x33A15F570EEA4271ULL}
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

	steps = 61;
	X1 = (curve25519_key_t){.key64 = {
		0xD382FDC60EA61940ULL,
		0xC5C00808A239964CULL,
		0x0AE4418C79346C8DULL,
		0x669C3A7122AD1767ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD382FDC60EA61940ULL,
			0xC5C00808A239964CULL,
			0x0AE4418C79346C8DULL,
			0x669C3A7122AD1767ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x267BC1D419F26FABULL,
			0x4D3A218D0C7F8B28ULL,
			0x918B86A1C3B3339AULL,
			0x0C074EB7A0391709ULL}
		},
		.Z = {.key64 = {
			0x699A01F400BE419BULL,
			0x1C220FA5CB4A3C39ULL,
			0xBA89FE6EE195C51EULL,
			0x7CD6A9B5E8A9AD87ULL}
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

	steps = 22;
	X1 = (curve25519_key_t){.key64 = {
		0xA0A08A9F1D791200ULL,
		0x07A5046666A24DB0ULL,
		0xEE55CFE857167AF8ULL,
		0x67F071C71ADF2CB1ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA0A08A9F1D791200ULL,
			0x07A5046666A24DB0ULL,
			0xEE55CFE857167AF8ULL,
			0x67F071C71ADF2CB1ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAE2FAA96315A1D74ULL,
			0x83E200AAE7593189ULL,
			0xB0DD1B674138BBB9ULL,
			0x2F6C297C7093F523ULL}
		},
		.Z = {.key64 = {
			0xB03DE811E30A4A22ULL,
			0x8B024F5FC7B60327ULL,
			0x213823D1D9F67FA9ULL,
			0x6D5633EF1BA9E99CULL}
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

	steps = 63;
	X1 = (curve25519_key_t){.key64 = {
		0xE2852249294C5F30ULL,
		0x666E8A7F004A031DULL,
		0x6A07E27DE1AFECD0ULL,
		0x649F0C3695D3FA3DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE2852249294C5F30ULL,
			0x666E8A7F004A031DULL,
			0x6A07E27DE1AFECD0ULL,
			0x649F0C3695D3FA3DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1B4A762390811879ULL,
			0x5B245C1FA0E3BB61ULL,
			0x6ED5413F13AE7351ULL,
			0x49D33FBB20D46FBBULL}
		},
		.Z = {.key64 = {
			0x9C9D21A6EB69A576ULL,
			0x4A5C8DF3953E0EE2ULL,
			0x1E80BE6EAFA8DCC4ULL,
			0x2F33726B821D902DULL}
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

	steps = 2;
	X1 = (curve25519_key_t){.key64 = {
		0xF0481AFFE514F878ULL,
		0xFB533C8D68C9D796ULL,
		0x71CA4D956A444519ULL,
		0x600731E66B3823D1ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF0481AFFE514F878ULL,
			0xFB533C8D68C9D796ULL,
			0x71CA4D956A444519ULL,
			0x600731E66B3823D1ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6E20B92529F7B6DCULL,
			0x3B7F41716AF18D81ULL,
			0x42C196114A450AC6ULL,
			0x5A953400B6D7A5F7ULL}
		},
		.Z = {.key64 = {
			0x92A4B8D2E3CFC435ULL,
			0x65B36AF530B06672ULL,
			0x17582FD5C8A6F92CULL,
			0x72CE4AA666156EC2ULL}
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

	steps = 18;
	X1 = (curve25519_key_t){.key64 = {
		0x00D0460B5A6F4C30ULL,
		0x6113D24352E7E44EULL,
		0x2146328F21E37ADBULL,
		0x4BAA1ED1C7116C3EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x00D0460B5A6F4C30ULL,
			0x6113D24352E7E44EULL,
			0x2146328F21E37ADBULL,
			0x4BAA1ED1C7116C3EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x940D21935FB67A1CULL,
			0xE5C740B9BED82B33ULL,
			0x634B60BCAF270788ULL,
			0x6BAECDB4A70A37C2ULL}
		},
		.Z = {.key64 = {
			0x215F4C1B480EC044ULL,
			0xDE0C105C777F7370ULL,
			0xDD151202E9CCC252ULL,
			0x35CE659D1218F145ULL}
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

	steps = 14;
	X1 = (curve25519_key_t){.key64 = {
		0xD08069B40692B948ULL,
		0x949DCDB719A88904ULL,
		0x438944E2F80D219DULL,
		0x64F1DDEF5AAFA2C6ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD08069B40692B948ULL,
			0x949DCDB719A88904ULL,
			0x438944E2F80D219DULL,
			0x64F1DDEF5AAFA2C6ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x39021B6725C8079FULL,
			0x0A73E2EED94B8034ULL,
			0xE25EB9C070BE78BAULL,
			0x25A42E9D43389C3FULL}
		},
		.Z = {.key64 = {
			0xAC60FF68E4A6BC73ULL,
			0x29FE2C8626EB97ABULL,
			0x7C13BC93329B1C5CULL,
			0x017D8A4BAAEC8062ULL}
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

	steps = 23;
	X1 = (curve25519_key_t){.key64 = {
		0x07B49D0C791D4048ULL,
		0xC9C1123BE6B38463ULL,
		0x0C68E3DE6B5D06E0ULL,
		0x6771418C92E39683ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x07B49D0C791D4048ULL,
			0xC9C1123BE6B38463ULL,
			0x0C68E3DE6B5D06E0ULL,
			0x6771418C92E39683ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA218E390946007DAULL,
			0x95C3EFBFF96FC50BULL,
			0x7636D16AF99A6CD1ULL,
			0x50CE67D4A6ADB01AULL}
		},
		.Z = {.key64 = {
			0x92E4E13450A7090DULL,
			0x79840CCC9D184251ULL,
			0xA47C55D1D8711712ULL,
			0x084F97EDE16F8BDAULL}
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

	steps = 1;
	X1 = (curve25519_key_t){.key64 = {
		0x205023CFA39DABD0ULL,
		0x4AB6F3A7A9092937ULL,
		0x8BD39776A72CDA5CULL,
		0x711AB336E87720C2ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x205023CFA39DABD0ULL,
			0x4AB6F3A7A9092937ULL,
			0x8BD39776A72CDA5CULL,
			0x711AB336E87720C2ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC3D31CC34303B3B9ULL,
			0xBD5CA36E255669F4ULL,
			0x3F6C4CCC83343B1DULL,
			0x35AF88797C589832ULL}
		},
		.Z = {.key64 = {
			0x81408F3E8E76AF79ULL,
			0x2ADBCE9EA424A4DCULL,
			0x2F4E5DDA9CB36971ULL,
			0x446ACCDBA1DC830AULL}
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

	steps = 12;
	X1 = (curve25519_key_t){.key64 = {
		0xF8B4BBDA786900C8ULL,
		0x489C5DAEA0660FACULL,
		0x88B89A052560BE19ULL,
		0x5DCAD56364319826ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF8B4BBDA786900C8ULL,
			0x489C5DAEA0660FACULL,
			0x88B89A052560BE19ULL,
			0x5DCAD56364319826ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x63FE2806DE86BB9DULL,
			0x9A71668FDAB1C418ULL,
			0xD8E7E5AA53C3022CULL,
			0x0126BDB6F7F74287ULL}
		},
		.Z = {.key64 = {
			0x0391809682CC927DULL,
			0x9883557B474D7A7EULL,
			0xEB360DAB218B7B55ULL,
			0x505DFA05EE5EFAA4ULL}
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

	steps = 20;
	X1 = (curve25519_key_t){.key64 = {
		0x350B35190AEB1C18ULL,
		0x92418C4FDC3CB21CULL,
		0x51584427B191B87CULL,
		0x72BEB3FC9A0CD330ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x350B35190AEB1C18ULL,
			0x92418C4FDC3CB21CULL,
			0x51584427B191B87CULL,
			0x72BEB3FC9A0CD330ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBA1A5E16FCF97D68ULL,
			0x5D61F23BA8DB4CB6ULL,
			0xAEA180C272D811DBULL,
			0x65A926DA17DF7A3BULL}
		},
		.Z = {.key64 = {
			0x0AE36324A7A364AAULL,
			0xC66F197E0FE7DA55ULL,
			0x847731A49E35F438ULL,
			0x6ABD709FAE7146C0ULL}
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

	steps = 31;
	X1 = (curve25519_key_t){.key64 = {
		0x57AF8F1BF5EAB388ULL,
		0x76DEB8306DE28745ULL,
		0x88D5112CFF516F18ULL,
		0x550F90D16E79D4A2ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x57AF8F1BF5EAB388ULL,
			0x76DEB8306DE28745ULL,
			0x88D5112CFF516F18ULL,
			0x550F90D16E79D4A2ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFA04F4AAD31BA3F6ULL,
			0xC90C962A12A3DE7AULL,
			0x3F9B4AD89BA74F69ULL,
			0x451CAF3DD709E1A7ULL}
		},
		.Z = {.key64 = {
			0x2A27A93604397D24ULL,
			0x29311B09B9D4E502ULL,
			0xE3CE6899CA037CDBULL,
			0x7BF6B28D30FB8F4CULL}
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

	steps = 49;
	X1 = (curve25519_key_t){.key64 = {
		0x19FCF24CDF5D44D0ULL,
		0x6FCCCD0AF688CD73ULL,
		0xA4F1E64CDE9F8F4CULL,
		0x5DEC5C2FDA76F290ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x19FCF24CDF5D44D0ULL,
			0x6FCCCD0AF688CD73ULL,
			0xA4F1E64CDE9F8F4CULL,
			0x5DEC5C2FDA76F290ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4E8131C54CD3E35DULL,
			0x87D6EB0A9342E035ULL,
			0x052AA9A8799448B5ULL,
			0x677E1A41C19400FCULL}
		},
		.Z = {.key64 = {
			0xF3EA0D0E0A50BFAFULL,
			0xBE3AEA571BF95AA4ULL,
			0xC018D048AD6328FBULL,
			0x05CB01609DE65526ULL}
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

	steps = 23;
	X1 = (curve25519_key_t){.key64 = {
		0x58E2662230F171C0ULL,
		0x5C929E8FD7D786D4ULL,
		0x10E843FC77E4739EULL,
		0x467E3016708D0862ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x58E2662230F171C0ULL,
			0x5C929E8FD7D786D4ULL,
			0x10E843FC77E4739EULL,
			0x467E3016708D0862ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4375B3A8AF07BF08ULL,
			0xE5BAFAF6426C5933ULL,
			0xAC5ECC89581E9341ULL,
			0x43EA447E2179AC77ULL}
		},
		.Z = {.key64 = {
			0x202DE2B7060F593AULL,
			0xB552785E81EAACBEULL,
			0xFD55C4A63DA63055ULL,
			0x492BCF0311EE9C10ULL}
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

	steps = 39;
	X1 = (curve25519_key_t){.key64 = {
		0x98E91EB0E747FA98ULL,
		0x50243773E795432CULL,
		0x82638572CD045DA8ULL,
		0x7032184A8C031C27ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x98E91EB0E747FA98ULL,
			0x50243773E795432CULL,
			0x82638572CD045DA8ULL,
			0x7032184A8C031C27ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x893797CEF2DCAF7EULL,
			0x550E22AB0CE3762CULL,
			0x5A35D0E98C0FC57AULL,
			0x3703E5FD653C15DBULL}
		},
		.Z = {.key64 = {
			0xD2D9535C22FC2098ULL,
			0xB2F363EBE210E85FULL,
			0xE075BA462DC4101FULL,
			0x72D1E3209230F978ULL}
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

	steps = 34;
	X1 = (curve25519_key_t){.key64 = {
		0x1D79892114B01140ULL,
		0x89144D18CC2835CBULL,
		0xBBD1ED8C1E41C31EULL,
		0x4BC57A59C95DC5B8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1D79892114B01140ULL,
			0x89144D18CC2835CBULL,
			0xBBD1ED8C1E41C31EULL,
			0x4BC57A59C95DC5B8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8792F9E4F5A8FD62ULL,
			0x0300420FF1B422CEULL,
			0x7D62EF55BAD4410EULL,
			0x23BDF4D563A3CD6CULL}
		},
		.Z = {.key64 = {
			0x58731DDFC9EAA510ULL,
			0x7CD18F62B0DA0902ULL,
			0xBCBD11EA10101611ULL,
			0x6CD124238D544473ULL}
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

	steps = 12;
	X1 = (curve25519_key_t){.key64 = {
		0x8432EE737120AC60ULL,
		0xB900D5D779743324ULL,
		0xBCED0B89CD114F9AULL,
		0x4F55539042410A57ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8432EE737120AC60ULL,
			0xB900D5D779743324ULL,
			0xBCED0B89CD114F9AULL,
			0x4F55539042410A57ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBE7DD0344CC0AD1DULL,
			0xB8B91D63B8BBF4BAULL,
			0x1B402986F4F0519DULL,
			0x578CA17D8DBA5B6FULL}
		},
		.Z = {.key64 = {
			0x27B11B4E592127DCULL,
			0x12F4BCC2BE078F11ULL,
			0x676A1C4469E6D6D2ULL,
			0x035136B12483317CULL}
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

	steps = 45;
	X1 = (curve25519_key_t){.key64 = {
		0xB7BC4BC5616A4440ULL,
		0xEFA5EB4E18A497C4ULL,
		0xDE268D2A20A6E081ULL,
		0x609BD85A39E8074AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB7BC4BC5616A4440ULL,
			0xEFA5EB4E18A497C4ULL,
			0xDE268D2A20A6E081ULL,
			0x609BD85A39E8074AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF4A50AB5912688F1ULL,
			0xB07255F6F1F621FCULL,
			0x8FD087D589784FE6ULL,
			0x73C192BB9D031B97ULL}
		},
		.Z = {.key64 = {
			0xB6A007F62EFF85A9ULL,
			0x2035B1CC48BE4BE6ULL,
			0x1907982BEC5EA1B2ULL,
			0x291B760BAE69327AULL}
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

	steps = 27;
	X1 = (curve25519_key_t){.key64 = {
		0x74357B8787545180ULL,
		0xB3D75313A68E2828ULL,
		0x367F30F35FFC06ABULL,
		0x63578AA4C8B799F6ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x74357B8787545180ULL,
			0xB3D75313A68E2828ULL,
			0x367F30F35FFC06ABULL,
			0x63578AA4C8B799F6ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x86F28A0906F48052ULL,
			0x198C526C3757C2AFULL,
			0x39A67AFDF6153B7CULL,
			0x2B53023035443654ULL}
		},
		.Z = {.key64 = {
			0x025D1881C50AD2EDULL,
			0x39BD6B9E46341F84ULL,
			0xF2A21D509D7CA241ULL,
			0x019CA06FBFE68F3FULL}
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

	steps = 58;
	X1 = (curve25519_key_t){.key64 = {
		0xA1EE37AE3A2E85A8ULL,
		0x32ED672283431FBEULL,
		0x221AC2135CE15E2CULL,
		0x79F3B05F5FDA72BCULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA1EE37AE3A2E85A8ULL,
			0x32ED672283431FBEULL,
			0x221AC2135CE15E2CULL,
			0x79F3B05F5FDA72BCULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6600D88C1CA508E3ULL,
			0xD10BD29F840A0587ULL,
			0x322B7AA9364A93DEULL,
			0x5E96498B7447205AULL}
		},
		.Z = {.key64 = {
			0xBAA31D4CE240473FULL,
			0xABE9EF56524C7825ULL,
			0x847A9D1E7F980E06ULL,
			0x0458A2C602E7AD84ULL}
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

	steps = 16;
	X1 = (curve25519_key_t){.key64 = {
		0xE081E112BAA55D30ULL,
		0xFAC8AC32302633AEULL,
		0xD8A87132C1262EB5ULL,
		0x6CB88E359EF96E11ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE081E112BAA55D30ULL,
			0xFAC8AC32302633AEULL,
			0xD8A87132C1262EB5ULL,
			0x6CB88E359EF96E11ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x89E167A70D66BE55ULL,
			0x5D29E30BF332CD07ULL,
			0x22787200E626B94BULL,
			0x314DA8279880D33BULL}
		},
		.Z = {.key64 = {
			0x716129947990D853ULL,
			0x99EDAC5CB2D288FAULL,
			0x2C41B567D1F51587ULL,
			0x7262937A30E0AF70ULL}
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

	steps = 6;
	X1 = (curve25519_key_t){.key64 = {
		0xEDA960947A655AD8ULL,
		0x57F4A1A319D711E5ULL,
		0xC752AC35FB6C993AULL,
		0x48B24D840AE2BB89ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEDA960947A655AD8ULL,
			0x57F4A1A319D711E5ULL,
			0xC752AC35FB6C993AULL,
			0x48B24D840AE2BB89ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCDE053CFAF485945ULL,
			0x1DF3C248AC73DE6EULL,
			0x783AB2F9EB4F0DCDULL,
			0x69A57A027CB131EEULL}
		},
		.Z = {.key64 = {
			0x29E79555929EA807ULL,
			0x0C66161727C273F4ULL,
			0x449049FB2AC93301ULL,
			0x64A4ACE2ED56A9B4ULL}
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

	steps = 26;
	X1 = (curve25519_key_t){.key64 = {
		0xFD408CA289320C58ULL,
		0xE2FE19E67E6293BEULL,
		0x48C88F5CD30A673CULL,
		0x51997A076AD16CB5ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFD408CA289320C58ULL,
			0xE2FE19E67E6293BEULL,
			0x48C88F5CD30A673CULL,
			0x51997A076AD16CB5ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE1D6658FCA06105BULL,
			0xF3F4FC0B8C50D1EBULL,
			0xB815955A17683787ULL,
			0x750070E110B62784ULL}
		},
		.Z = {.key64 = {
			0x84DCA5E958340833ULL,
			0x20BCE0C6E5CBCB55ULL,
			0x63855149F5D55D7FULL,
			0x67B2321E54A0F3DCULL}
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

	steps = 16;
	X1 = (curve25519_key_t){.key64 = {
		0xAA7350B63554C0A8ULL,
		0x984568320B5041FCULL,
		0x999EA928FE29545CULL,
		0x58CFC00726E025FAULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAA7350B63554C0A8ULL,
			0x984568320B5041FCULL,
			0x999EA928FE29545CULL,
			0x58CFC00726E025FAULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCCDD3A1FCA89C51BULL,
			0xDD77BE3732C10420ULL,
			0x664EAF1D71A01230ULL,
			0x051D535D01722ECDULL}
		},
		.Z = {.key64 = {
			0x13DDC55CA326D0CFULL,
			0x571A99F95DAFE0C2ULL,
			0xD56DD752C8F893DBULL,
			0x6495432756579161ULL}
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

	steps = 38;
	X1 = (curve25519_key_t){.key64 = {
		0x02AFF91572E46FB0ULL,
		0x56DAB4644A8103E4ULL,
		0x32EAFB7955E5C17BULL,
		0x6F4FCF27991DF13BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x02AFF91572E46FB0ULL,
			0x56DAB4644A8103E4ULL,
			0x32EAFB7955E5C17BULL,
			0x6F4FCF27991DF13BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x41E17D9E3FD6B415ULL,
			0x83396A703DA3F55EULL,
			0xE431997FAC1F5B7FULL,
			0x01C23D3A7DFC9C4FULL}
		},
		.Z = {.key64 = {
			0xA7FD45958EB924E9ULL,
			0x019955315FAC9811ULL,
			0x255331DA69A0A08BULL,
			0x6643372D7BD55FD1ULL}
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

	steps = 39;
	X1 = (curve25519_key_t){.key64 = {
		0x0B2D2630C6CF8210ULL,
		0x8C3627EBD2772307ULL,
		0x64D4922C15DBC61FULL,
		0x754B968928576FDDULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0B2D2630C6CF8210ULL,
			0x8C3627EBD2772307ULL,
			0x64D4922C15DBC61FULL,
			0x754B968928576FDDULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x52F0F549995F9DB8ULL,
			0xC88DBD0872C6620CULL,
			0xB20C8A17B35A8DC0ULL,
			0x0DEA24C8716E86EAULL}
		},
		.Z = {.key64 = {
			0x8FDFF524BE556A28ULL,
			0x4472287D140453CDULL,
			0x368154F4383D842BULL,
			0x03EB3D98395C9705ULL}
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

	steps = 30;
	X1 = (curve25519_key_t){.key64 = {
		0x31EAFF131E56BAA0ULL,
		0x5592D434F3424CE0ULL,
		0x60D3F519478259B7ULL,
		0x423E079DC88DEFF6ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x31EAFF131E56BAA0ULL,
			0x5592D434F3424CE0ULL,
			0x60D3F519478259B7ULL,
			0x423E079DC88DEFF6ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD1E9BD029E6B838FULL,
			0xE0CAC44FE141CDE2ULL,
			0x7E507B46A4AD0BECULL,
			0x11FC8B285930B42EULL}
		},
		.Z = {.key64 = {
			0x7EDB2A04C6F854C3ULL,
			0x83CAC4CD464BD9D2ULL,
			0x707536F802E7CBA4ULL,
			0x7C33717C3B50D27EULL}
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

	steps = 4;
	X1 = (curve25519_key_t){.key64 = {
		0xAF8ADE0B0D92E458ULL,
		0x47F14C8E95ABC878ULL,
		0x632B7614AF80A76CULL,
		0x50883E4244316C22ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAF8ADE0B0D92E458ULL,
			0x47F14C8E95ABC878ULL,
			0x632B7614AF80A76CULL,
			0x50883E4244316C22ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEFCE02F4EFC02E66ULL,
			0xD77627121FE7FAF5ULL,
			0x1972FA866545E5A2ULL,
			0x71F776AC3A488370ULL}
		},
		.Z = {.key64 = {
			0xD4206145F015D165ULL,
			0xF77ADF8D9EC67559ULL,
			0xFDE1CABBC2C5CA82ULL,
			0x547E5046B0CFAF2EULL}
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

	steps = 50;
	X1 = (curve25519_key_t){.key64 = {
		0x339FFFC32D29A170ULL,
		0x20A07D3977CE86CBULL,
		0x7694268DFD2F6BE6ULL,
		0x779B0EFE6287984CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x339FFFC32D29A170ULL,
			0x20A07D3977CE86CBULL,
			0x7694268DFD2F6BE6ULL,
			0x779B0EFE6287984CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD158120023C2254DULL,
			0x13D6D009F3D1D1DAULL,
			0x920F1D33517A6676ULL,
			0x02FE5524BA5625A1ULL}
		},
		.Z = {.key64 = {
			0x69481E1A78190739ULL,
			0x98BC3232C098D7FCULL,
			0xCDE484C0A6535A3DULL,
			0x1BF36347FF3B1247ULL}
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

	steps = 18;
	X1 = (curve25519_key_t){.key64 = {
		0xB9378F471B1EC530ULL,
		0x64789B2491CA31C0ULL,
		0xFCD56862E4E71325ULL,
		0x436DE870B1A25712ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB9378F471B1EC530ULL,
			0x64789B2491CA31C0ULL,
			0xFCD56862E4E71325ULL,
			0x436DE870B1A25712ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC6BC7D758DDBA2DBULL,
			0x2EF9A94E1749DBFCULL,
			0x9AB0915F262CD02BULL,
			0x4DDE53B745146D11ULL}
		},
		.Z = {.key64 = {
			0x65CD6CE2439C7985ULL,
			0xFB30433CFB0F5966ULL,
			0xAAF65BF5E71DAB83ULL,
			0x29C9AD9E191906B8ULL}
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

	steps = 19;
	X1 = (curve25519_key_t){.key64 = {
		0x66EB592EA0CB0928ULL,
		0x9E107294E626FCDDULL,
		0x0CE0D3A3FDCA4C7BULL,
		0x518C0E83FB622EE0ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x66EB592EA0CB0928ULL,
			0x9E107294E626FCDDULL,
			0x0CE0D3A3FDCA4C7BULL,
			0x518C0E83FB622EE0ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD890085789D3FA1EULL,
			0x9A66BF3DE35579E8ULL,
			0x40BBC7C576132D7DULL,
			0x65212A656C603DE0ULL}
		},
		.Z = {.key64 = {
			0x5AA80B751A9C7027ULL,
			0x089C0D747DB0A36EULL,
			0xDBC1C035E0A003DAULL,
			0x0C5C87605AC8A284ULL}
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

	steps = 5;
	X1 = (curve25519_key_t){.key64 = {
		0x06B36AA9D9E48298ULL,
		0xA3A085C407E22BC0ULL,
		0x1A8497E016386DC7ULL,
		0x712754B3DC1EAE63ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x06B36AA9D9E48298ULL,
			0xA3A085C407E22BC0ULL,
			0x1A8497E016386DC7ULL,
			0x712754B3DC1EAE63ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE36C03F3906FC515ULL,
			0x95B5BC5B7F00E972ULL,
			0x5ACE0D03B81678CAULL,
			0x1490C4914445F57FULL}
		},
		.Z = {.key64 = {
			0x384E678DFFBBCE65ULL,
			0x325D3AE4758A7FF4ULL,
			0x3E57ADA522BDF350ULL,
			0x5F452216AA620ABCULL}
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

	steps = 53;
	X1 = (curve25519_key_t){.key64 = {
		0xE71B7D3FF7F85498ULL,
		0x91BF6D7B9CD9F68AULL,
		0xA63AD732EE9187B8ULL,
		0x59B0CFEC8F10D16DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE71B7D3FF7F85498ULL,
			0x91BF6D7B9CD9F68AULL,
			0xA63AD732EE9187B8ULL,
			0x59B0CFEC8F10D16DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3AD7C686975657E3ULL,
			0xC22B9948049CB235ULL,
			0x3D374306A3870F67ULL,
			0x0723B3C0B54BE475ULL}
		},
		.Z = {.key64 = {
			0x3B91B39FFA195BE0ULL,
			0xCFDC6951BD817A71ULL,
			0xC00E4FCBCA784098ULL,
			0x4ACA198242A49333ULL}
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

	steps = 46;
	X1 = (curve25519_key_t){.key64 = {
		0x64EE8AEB17CC04A0ULL,
		0xF071B6AFBC26B30DULL,
		0x36E781C225D17CFDULL,
		0x4A3AE871C22EF805ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x64EE8AEB17CC04A0ULL,
			0xF071B6AFBC26B30DULL,
			0x36E781C225D17CFDULL,
			0x4A3AE871C22EF805ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB9B3ED432FD41516ULL,
			0x23E8312379FF1FFEULL,
			0x3BF1360E0A1D7E71ULL,
			0x0FA2BEA96475C9F2ULL}
		},
		.Z = {.key64 = {
			0x5F665C0C6B15BBEFULL,
			0x47120C47C36B7E00ULL,
			0xFE7862734DEDA233ULL,
			0x6313D6281C7B5E25ULL}
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

	steps = 47;
	X1 = (curve25519_key_t){.key64 = {
		0x2E56A8B8C63F5318ULL,
		0x2BF376C9CB2060E2ULL,
		0x52844B09B489AEE1ULL,
		0x4005897F5E6FEA0CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2E56A8B8C63F5318ULL,
			0x2BF376C9CB2060E2ULL,
			0x52844B09B489AEE1ULL,
			0x4005897F5E6FEA0CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1F8DF91FAD04D1C4ULL,
			0xCFD0456BFA9EE9B4ULL,
			0x755DA8DE9D524141ULL,
			0x388F415BDAA698EAULL}
		},
		.Z = {.key64 = {
			0x5F511BBC2E2C7329ULL,
			0x70407946BE5DDFB6ULL,
			0x82C06094298D1A77ULL,
			0x29D211B24065E74BULL}
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

	steps = 31;
	X1 = (curve25519_key_t){.key64 = {
		0x5E5E9713789A9A30ULL,
		0x94264F8C065302EEULL,
		0xF9C46E5B68942E81ULL,
		0x6C75BB26EAC99261ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5E5E9713789A9A30ULL,
			0x94264F8C065302EEULL,
			0xF9C46E5B68942E81ULL,
			0x6C75BB26EAC99261ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEF6810DD77BB4B39ULL,
			0x665B8A204F310E89ULL,
			0x96C9FB9482BEC9C2ULL,
			0x5AF00A79C8DD0CCFULL}
		},
		.Z = {.key64 = {
			0x837E8838CCD9740DULL,
			0x3A26E7EA0616052CULL,
			0xC1A3603AA198349AULL,
			0x149BFD1F0F7C3106ULL}
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

	steps = 22;
	X1 = (curve25519_key_t){.key64 = {
		0x863756DAE4B12648ULL,
		0xD783E68221B6D70AULL,
		0x048A98BD303D3076ULL,
		0x7669E66A9C138335ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x863756DAE4B12648ULL,
			0xD783E68221B6D70AULL,
			0x048A98BD303D3076ULL,
			0x7669E66A9C138335ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x59AF7989301AF174ULL,
			0x76E2B062A15A4522ULL,
			0x83D5524CC0A5E703ULL,
			0x0099584C703F9F5EULL}
		},
		.Z = {.key64 = {
			0xF5B1AEB2E5CCB95FULL,
			0x07186F47FD4EA508ULL,
			0x9D1EA24BFC7000EAULL,
			0x7E0AD5375828959DULL}
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

	steps = 15;
	X1 = (curve25519_key_t){.key64 = {
		0x22DA980A40EDEF70ULL,
		0x247CC2B705B33DC2ULL,
		0x714795AB59360204ULL,
		0x44217CE6FB3583F6ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x22DA980A40EDEF70ULL,
			0x247CC2B705B33DC2ULL,
			0x714795AB59360204ULL,
			0x44217CE6FB3583F6ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF02E8EF7DF38393DULL,
			0x04769FE2E5AC940DULL,
			0xBB420516B7D02542ULL,
			0x34859E9B23028261ULL}
		},
		.Z = {.key64 = {
			0x3782CCA940F8EE6CULL,
			0xCFC931C739495BD8ULL,
			0xC3800C8C82677DF0ULL,
			0x5310CF3742AC6285ULL}
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

	steps = 8;
	X1 = (curve25519_key_t){.key64 = {
		0xB15817D3FAD44098ULL,
		0x2D3BFDCCBE70CEE2ULL,
		0xA42F27DE2F2E8572ULL,
		0x52FFF06FA4D34354ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB15817D3FAD44098ULL,
			0x2D3BFDCCBE70CEE2ULL,
			0xA42F27DE2F2E8572ULL,
			0x52FFF06FA4D34354ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x289007DAE6C0744EULL,
			0xB813F8DF8009FEBFULL,
			0x0DB177956633AFC9ULL,
			0x7DBF4FB3F583E15AULL}
		},
		.Z = {.key64 = {
			0x0A265E8BC060218AULL,
			0x2B8BD5752E3CCD2CULL,
			0x56320831F2D592DBULL,
			0x541E687EB8125734ULL}
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

	steps = 64;
	X1 = (curve25519_key_t){.key64 = {
		0xEFB1F56A56EF2E28ULL,
		0xB50EEB5921C70E65ULL,
		0x1908614B9AE9833FULL,
		0x618623D78F2889C2ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEFB1F56A56EF2E28ULL,
			0xB50EEB5921C70E65ULL,
			0x1908614B9AE9833FULL,
			0x618623D78F2889C2ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x97FD696C29A94A0BULL,
			0x5B2D3C82913CD01AULL,
			0x6038904A1C2FA8A9ULL,
			0x584168A127F1A052ULL}
		},
		.Z = {.key64 = {
			0x4D97313E43BF392BULL,
			0xD483162B161A5F3FULL,
			0x16C808F31A5ACB54ULL,
			0x70B8FEB2D3137D90ULL}
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

	steps = 51;
	X1 = (curve25519_key_t){.key64 = {
		0xB2206F9FBF24F840ULL,
		0x03E51D5EAC9D44D8ULL,
		0x7F0DEAE20EC2ACF1ULL,
		0x65AEB4088CF45F2EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB2206F9FBF24F840ULL,
			0x03E51D5EAC9D44D8ULL,
			0x7F0DEAE20EC2ACF1ULL,
			0x65AEB4088CF45F2EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0DD9EFEC4FAB81D7ULL,
			0x87DF9CED1B19AD38ULL,
			0x6B230B621FEB36EAULL,
			0x694F33EA919B3A1EULL}
		},
		.Z = {.key64 = {
			0x6406F99680DFB23BULL,
			0x5C871087E16D7474ULL,
			0x7472232BD70D85D2ULL,
			0x210FA4AD43FFB639ULL}
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

	steps = 20;
	X1 = (curve25519_key_t){.key64 = {
		0xE0C20C9C684EA800ULL,
		0xBA78D49F15C63E61ULL,
		0x2D4B79941AF73732ULL,
		0x6FBC59AF73FE8BD5ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE0C20C9C684EA800ULL,
			0xBA78D49F15C63E61ULL,
			0x2D4B79941AF73732ULL,
			0x6FBC59AF73FE8BD5ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3B5E47C06F0E9A1EULL,
			0x144ABF9F301D38D8ULL,
			0xC110B6E51E6C457DULL,
			0x2AB12EC40C6BCFBDULL}
		},
		.Z = {.key64 = {
			0xCEAD1449A3690D9AULL,
			0xFB336A0A1B690A5CULL,
			0x4C1145D7911CEB9EULL,
			0x2CF1D01D5ABD3058ULL}
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

	steps = 64;
	X1 = (curve25519_key_t){.key64 = {
		0xEC723018D6D548C8ULL,
		0xD6581D97B609A88FULL,
		0xC6EC1B2FFCBF7DBDULL,
		0x52922B3B048240FEULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEC723018D6D548C8ULL,
			0xD6581D97B609A88FULL,
			0xC6EC1B2FFCBF7DBDULL,
			0x52922B3B048240FEULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC96DE2CE0CBDBC21ULL,
			0x9C2ED7B99B382428ULL,
			0x5488F78D282CC92BULL,
			0x7DF55B036F408D46ULL}
		},
		.Z = {.key64 = {
			0xEC5C5B7D27BEA0D5ULL,
			0x817698621CE337ECULL,
			0x0E417EF460CCA69AULL,
			0x67ABD185CAEB8BCAULL}
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

	steps = 62;
	X1 = (curve25519_key_t){.key64 = {
		0xF9ED0D89FE699920ULL,
		0x445921BB886E0027ULL,
		0xB7232F6EBFB674B3ULL,
		0x5D85610CE51B24E6ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF9ED0D89FE699920ULL,
			0x445921BB886E0027ULL,
			0xB7232F6EBFB674B3ULL,
			0x5D85610CE51B24E6ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8C6E46314F08D754ULL,
			0x734C431699B1B651ULL,
			0xA4BD3625261E9E37ULL,
			0x72613160259E161EULL}
		},
		.Z = {.key64 = {
			0xACE6C7C70FBC5CB4ULL,
			0xA2DBB409CC047C9BULL,
			0xB001E71097879FC8ULL,
			0x2B532A1E56F1CD9DULL}
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

	steps = 13;
	X1 = (curve25519_key_t){.key64 = {
		0x77B2F9CCA62CD7C0ULL,
		0x95B6A1BF258AFEA9ULL,
		0x8C7A639F767E2FEBULL,
		0x4DD29A889C07B1EBULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x77B2F9CCA62CD7C0ULL,
			0x95B6A1BF258AFEA9ULL,
			0x8C7A639F767E2FEBULL,
			0x4DD29A889C07B1EBULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x252085B9B6E9A2F1ULL,
			0xBF938F179B8914AAULL,
			0x5F2CAA93C21329B9ULL,
			0x104417B554EB6FECULL}
		},
		.Z = {.key64 = {
			0x4521F312C27F3370ULL,
			0x2DD881303CC86C1CULL,
			0x7C9C4578ABC7A7AEULL,
			0x75D4C4A072EE5A6DULL}
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

	steps = 50;
	X1 = (curve25519_key_t){.key64 = {
		0x38F1818D64B06058ULL,
		0x0BB5C4C4191E1585ULL,
		0x9223C8F467126546ULL,
		0x6BF5DE063DF396A1ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x38F1818D64B06058ULL,
			0x0BB5C4C4191E1585ULL,
			0x9223C8F467126546ULL,
			0x6BF5DE063DF396A1ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x01FFB7F848C1DFA7ULL,
			0xC76D653024D1CBE5ULL,
			0xD929F961FE22F108ULL,
			0x3CB855CD5866F4E9ULL}
		},
		.Z = {.key64 = {
			0xD2B0B3B1C7DBE235ULL,
			0xB62CA4F07E496708ULL,
			0x52DE69BE588F2E83ULL,
			0x674BC9FD7E5A76F4ULL}
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

	steps = 48;
	X1 = (curve25519_key_t){.key64 = {
		0xC580F8000A192800ULL,
		0xB5F3F36795C2AA6AULL,
		0x576340C2605DC436ULL,
		0x7A0565C6B53FCD53ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC580F8000A192800ULL,
			0xB5F3F36795C2AA6AULL,
			0x576340C2605DC436ULL,
			0x7A0565C6B53FCD53ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4D8020B12A2036FEULL,
			0x113D88CCD35C8E10ULL,
			0xD7F29D9C7D1A2B7CULL,
			0x440378CA1D76D213ULL}
		},
		.Z = {.key64 = {
			0xE5FEEAB0052AD403ULL,
			0xA19F37B629AB4A9DULL,
			0xAB4204D8058BA229ULL,
			0x459A57134E9D5A7BULL}
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

	steps = 44;
	X1 = (curve25519_key_t){.key64 = {
		0x364543CEA4A2A180ULL,
		0x8627212DA32D3C9AULL,
		0x9FA499D1B52B84FEULL,
		0x4EA43D1D7B363A0AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x364543CEA4A2A180ULL,
			0x8627212DA32D3C9AULL,
			0x9FA499D1B52B84FEULL,
			0x4EA43D1D7B363A0AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x459979B1FA5B6B02ULL,
			0xF5A6A842C4257B8AULL,
			0xC2D61AF83BC9338BULL,
			0x607A4C19362A40E5ULL}
		},
		.Z = {.key64 = {
			0x9D95F90E95CFE705ULL,
			0xA8A1287B02F0A538ULL,
			0xEC132F2216FC281BULL,
			0x4CA15AC274341A84ULL}
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

	steps = 47;
	X1 = (curve25519_key_t){.key64 = {
		0xF7AB587F031E8BE0ULL,
		0x4547BC5850E13F6AULL,
		0xD9FC9F18B760421CULL,
		0x4C53D547131C0E64ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF7AB587F031E8BE0ULL,
			0x4547BC5850E13F6AULL,
			0xD9FC9F18B760421CULL,
			0x4C53D547131C0E64ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC8750873D3237735ULL,
			0xE183E849041BD810ULL,
			0x130845EFF7552B25ULL,
			0x2EA6E17BA290FCE6ULL}
		},
		.Z = {.key64 = {
			0xB7AABD71D1D589E6ULL,
			0xFACF206EFCD3AF82ULL,
			0xE2F932E6E04F16A4ULL,
			0x515B73C9DF3B9CC2ULL}
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

	steps = 46;
	X1 = (curve25519_key_t){.key64 = {
		0x8CF872B718286810ULL,
		0xEF7B83E4C8D47D7FULL,
		0x8734BA8F529B2C83ULL,
		0x496447AA1BF274E5ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8CF872B718286810ULL,
			0xEF7B83E4C8D47D7FULL,
			0x8734BA8F529B2C83ULL,
			0x496447AA1BF274E5ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x18066AD77ABDC648ULL,
			0xF8DA08AFB35D2E34ULL,
			0x00E03C1D70A07E6FULL,
			0x166811FDB262D01FULL}
		},
		.Z = {.key64 = {
			0x2E793F3ABA411FE2ULL,
			0x12BD543FC8687DB5ULL,
			0x8ED458CDF4838488ULL,
			0x04FB3691C9F62F64ULL}
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

	steps = 43;
	X1 = (curve25519_key_t){.key64 = {
		0x0237FC1A46963328ULL,
		0x8DBCB11B2D57BEAFULL,
		0x025FE671FCC96E9EULL,
		0x4F93B3C89B3B6C4FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0237FC1A46963328ULL,
			0x8DBCB11B2D57BEAFULL,
			0x025FE671FCC96E9EULL,
			0x4F93B3C89B3B6C4FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x52C1832C0EFDE132ULL,
			0x69A7A05C6395D996ULL,
			0xF987DDC752E83B67ULL,
			0x4BB956A28D2957C0ULL}
		},
		.Z = {.key64 = {
			0x0A40AE8B0BCE44DDULL,
			0xFCC5D85EB8DB4E3FULL,
			0x3E6BDFCB4F3C500BULL,
			0x274BCC02528546F5ULL}
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

	steps = 40;
	X1 = (curve25519_key_t){.key64 = {
		0xEDBD775620FB9E50ULL,
		0x0E7B787FD1C7FCFCULL,
		0x0B011B1A6C93C2B4ULL,
		0x41DCCF5C8451E4F3ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEDBD775620FB9E50ULL,
			0x0E7B787FD1C7FCFCULL,
			0x0B011B1A6C93C2B4ULL,
			0x41DCCF5C8451E4F3ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFF88429D315E2917ULL,
			0xE8930367B76752F6ULL,
			0x7C547E5D448615D8ULL,
			0x29347CACA7BCAC9DULL}
		},
		.Z = {.key64 = {
			0x966643E01D73AACAULL,
			0x6CB7C0A1D0B51CD2ULL,
			0x58B22DE7600A19A5ULL,
			0x6798B334063E463CULL}
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

	steps = 20;
	X1 = (curve25519_key_t){.key64 = {
		0x6AE7E48B3CE62F08ULL,
		0xC3AF061ACF40AE29ULL,
		0x083413A09E3E537CULL,
		0x7B9163546C6F7A4BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6AE7E48B3CE62F08ULL,
			0xC3AF061ACF40AE29ULL,
			0x083413A09E3E537CULL,
			0x7B9163546C6F7A4BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9DB7D1FCD7F92739ULL,
			0x155C55035F118C76ULL,
			0x2760CEBEDB9FC403ULL,
			0x0484958D7C584B95ULL}
		},
		.Z = {.key64 = {
			0xA3D001EF838B00F8ULL,
			0x2A82340B9D77E850ULL,
			0xA42E7DD3422830A5ULL,
			0x6D9FBBC9A26697A7ULL}
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

	steps = 15;
	X1 = (curve25519_key_t){.key64 = {
		0xAA7FB1BDE65645F8ULL,
		0xFAC9B4BC5B28C110ULL,
		0x423674EA5D64D888ULL,
		0x7ECFAC768F237AA3ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAA7FB1BDE65645F8ULL,
			0xFAC9B4BC5B28C110ULL,
			0x423674EA5D64D888ULL,
			0x7ECFAC768F237AA3ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9FA2E627819A1B6DULL,
			0xEE218BE3948E3DF3ULL,
			0x04AB01F719EF2D8BULL,
			0x25F12A07380A1074ULL}
		},
		.Z = {.key64 = {
			0x34EA5FB92A4D2F71ULL,
			0xB41323375F590160ULL,
			0x1184FF39D6D9AAC2ULL,
			0x00625F32CBFA31F6ULL}
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

	steps = 23;
	X1 = (curve25519_key_t){.key64 = {
		0x115E191A5A02A2C0ULL,
		0x567DE5FD48ACBB0AULL,
		0x18A38A3F853D2348ULL,
		0x5DCCD7AFAB899E35ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x115E191A5A02A2C0ULL,
			0x567DE5FD48ACBB0AULL,
			0x18A38A3F853D2348ULL,
			0x5DCCD7AFAB899E35ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x21B8B7C63B84153AULL,
			0xF1ED59DDA949EC8FULL,
			0x54DBA8865E2B5A04ULL,
			0x751BF72F79E91CC3ULL}
		},
		.Z = {.key64 = {
			0xC1E435A06033584CULL,
			0x9009ADD9768A1C67ULL,
			0x0D61E2D28D1C61B5ULL,
			0x602CC00E6EAD7534ULL}
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

	steps = 39;
	X1 = (curve25519_key_t){.key64 = {
		0x4CD0CC82F7CDD008ULL,
		0x7C5DE39B7ABF81CCULL,
		0x9EA65E1426461B9AULL,
		0x70CF06E4EB19558AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4CD0CC82F7CDD008ULL,
			0x7C5DE39B7ABF81CCULL,
			0x9EA65E1426461B9AULL,
			0x70CF06E4EB19558AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE42BCC17BBF62AF0ULL,
			0x0837C674C54B3E2EULL,
			0xB5323E31711584C8ULL,
			0x5C7BAA87B58C40B2ULL}
		},
		.Z = {.key64 = {
			0xF748E4CAEE347F82ULL,
			0x37E7DC616F1D4F2DULL,
			0x25940C174EDEDAA6ULL,
			0x4FC80FEC3F48F458ULL}
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

	steps = 34;
	X1 = (curve25519_key_t){.key64 = {
		0x61C3F5B3468396B0ULL,
		0x912FAF443D52EDD3ULL,
		0x4463E89747D1FE25ULL,
		0x6ECC22011E329D8EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x61C3F5B3468396B0ULL,
			0x912FAF443D52EDD3ULL,
			0x4463E89747D1FE25ULL,
			0x6ECC22011E329D8EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBD1BE8CEA2EC2162ULL,
			0x5938D8FC2A331C8DULL,
			0xD53B3C40A02E21F5ULL,
			0x23F0FAE3A9A642BEULL}
		},
		.Z = {.key64 = {
			0x05DA4F4045324C0DULL,
			0x2E8466BE9F171B44ULL,
			0x3FCC88EFA125E6D6ULL,
			0x2E6CF55F098109BFULL}
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

	steps = 5;
	X1 = (curve25519_key_t){.key64 = {
		0xE02C8EF950B49330ULL,
		0xF5F2F1F1390C2E79ULL,
		0x0A58D9EB5E922DB9ULL,
		0x6AF90D4B510D2EC5ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE02C8EF950B49330ULL,
			0xF5F2F1F1390C2E79ULL,
			0x0A58D9EB5E922DB9ULL,
			0x6AF90D4B510D2EC5ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB930217973CCC6EDULL,
			0xE2B9692009683814ULL,
			0xA7BC9DC30589D4C1ULL,
			0x3131C4F5DCD00CF2ULL}
		},
		.Z = {.key64 = {
			0x0A82BC9ADEF271D8ULL,
			0x0B00DB618AF1F735ULL,
			0xC419065A7B9589E6ULL,
			0x5C8DE49FCA48750AULL}
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

	steps = 18;
	X1 = (curve25519_key_t){.key64 = {
		0xB7D9F59F4EAB1958ULL,
		0x5AB78DD313836D52ULL,
		0x7F49EC610AA9E43CULL,
		0x4FC88522BC4BDA3FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB7D9F59F4EAB1958ULL,
			0x5AB78DD313836D52ULL,
			0x7F49EC610AA9E43CULL,
			0x4FC88522BC4BDA3FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0A828FB3A29323BDULL,
			0x8E17377F116D1A60ULL,
			0x610C7A8CBEC5E123ULL,
			0x56D4D4D8EF48E3A0ULL}
		},
		.Z = {.key64 = {
			0x819FC05018054A9EULL,
			0xF792D31115933085ULL,
			0x08F3E695D6F07504ULL,
			0x0631A1A779E18BACULL}
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

	steps = 35;
	X1 = (curve25519_key_t){.key64 = {
		0xAEB65702AD6F0A00ULL,
		0x890066B94D32E246ULL,
		0xB4CC9610A09D2A64ULL,
		0x7F730C4DBD1C4148ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAEB65702AD6F0A00ULL,
			0x890066B94D32E246ULL,
			0xB4CC9610A09D2A64ULL,
			0x7F730C4DBD1C4148ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9AFFB02494CE2A0CULL,
			0x72FA4A5FBF3C485EULL,
			0x1F5B8390D9532216ULL,
			0x411FA5760D1A11CAULL}
		},
		.Z = {.key64 = {
			0x2504F1B9579EF56EULL,
			0x7A12829D28E8FFC5ULL,
			0xB63E51FC75B477EDULL,
			0x5591E07B9FF4D779ULL}
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

	steps = 12;
	X1 = (curve25519_key_t){.key64 = {
		0xB6D4556645364278ULL,
		0x4C642F03E7E5FC1BULL,
		0xA4B0EDAA46476420ULL,
		0x763A7D8FF0BF8358ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB6D4556645364278ULL,
			0x4C642F03E7E5FC1BULL,
			0xA4B0EDAA46476420ULL,
			0x763A7D8FF0BF8358ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3322C567D8D3DB2BULL,
			0xA030F989CD4536EAULL,
			0xCBF3D4C6B4E68266ULL,
			0x3878A63E17D0A6F7ULL}
		},
		.Z = {.key64 = {
			0xC5228C0CE6CB5764ULL,
			0xF42936EF3918BD67ULL,
			0x1E2DCF610F3376F1ULL,
			0x426FE3D296D65F73ULL}
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

	steps = 27;
	X1 = (curve25519_key_t){.key64 = {
		0xB37C526386E942E8ULL,
		0x2482821588C717A3ULL,
		0x45413228D725250CULL,
		0x7A4860052DA0FEB6ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB37C526386E942E8ULL,
			0x2482821588C717A3ULL,
			0x45413228D725250CULL,
			0x7A4860052DA0FEB6ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x63FED7C1CEA85FE0ULL,
			0x5AD7316EB2E4EEF9ULL,
			0x34B7487245F19DD2ULL,
			0x116E6C071FB868D3ULL}
		},
		.Z = {.key64 = {
			0x894B9CCC587FF53CULL,
			0x2A34EA4E93E65CC7ULL,
			0x8FC9C148D14EDD9AULL,
			0x214C83F0AB0FD15AULL}
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

	steps = 19;
	X1 = (curve25519_key_t){.key64 = {
		0xF00D3F7C608CEF10ULL,
		0xD2C7C465BA0625B1ULL,
		0x28780F62C6D95613ULL,
		0x6248EBEDB3E3EE60ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF00D3F7C608CEF10ULL,
			0xD2C7C465BA0625B1ULL,
			0x28780F62C6D95613ULL,
			0x6248EBEDB3E3EE60ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x80F8EC3FBDA0055EULL,
			0x2E9EF0B14F16C0CBULL,
			0x414A7F33C06805FAULL,
			0x2E48D83B98A781D2ULL}
		},
		.Z = {.key64 = {
			0x299DCD3C00150AB1ULL,
			0xC077750D8C19F324ULL,
			0xBD4F1EDF9A2BBA53ULL,
			0x5CE09638FA0293ABULL}
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

	steps = 56;
	X1 = (curve25519_key_t){.key64 = {
		0xBF9C3D83D6942AF8ULL,
		0x5E4DAA629F53BC86ULL,
		0xA4CBC6161831C8D1ULL,
		0x7310857EC5EC94DDULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBF9C3D83D6942AF8ULL,
			0x5E4DAA629F53BC86ULL,
			0xA4CBC6161831C8D1ULL,
			0x7310857EC5EC94DDULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x12E714D513E34DDFULL,
			0xAF2F87F2DC498FDFULL,
			0xDFFEAC97B5813144ULL,
			0x7BC27543ABE1AF3AULL}
		},
		.Z = {.key64 = {
			0x5812F31A2916BF2EULL,
			0x2F8889F829E8A0E4ULL,
			0x03EB3F6DAF63F745ULL,
			0x629125E7866A6133ULL}
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

	steps = 48;
	X1 = (curve25519_key_t){.key64 = {
		0x9ACAC1D8D61D5BE0ULL,
		0xF73C168E557FEEF2ULL,
		0x6D3E99A92D6774DBULL,
		0x7B50522EFC689D65ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9ACAC1D8D61D5BE0ULL,
			0xF73C168E557FEEF2ULL,
			0x6D3E99A92D6774DBULL,
			0x7B50522EFC689D65ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6BA14716C02D6C8FULL,
			0x90B948D0E871AA6BULL,
			0xAADB798D62F51B3CULL,
			0x1DF021B17158E110ULL}
		},
		.Z = {.key64 = {
			0xAD196D4D3DAF9C07ULL,
			0x8500EFBF4EF2F6C2ULL,
			0xEC3D00234E0852E3ULL,
			0x280FEADFA1E43205ULL}
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

	steps = 23;
	X1 = (curve25519_key_t){.key64 = {
		0x5FB7B330AF588C08ULL,
		0x1374CDC2701727ACULL,
		0xBAEE788CC1E67C19ULL,
		0x759357169002F712ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5FB7B330AF588C08ULL,
			0x1374CDC2701727ACULL,
			0xBAEE788CC1E67C19ULL,
			0x759357169002F712ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x726BC12E57A72469ULL,
			0xED49258C9964114EULL,
			0xAA77C41228B35D11ULL,
			0x2AB1E2F1917729C4ULL}
		},
		.Z = {.key64 = {
			0x9C9BAA451DBE546FULL,
			0x930CE551FF81C9D7ULL,
			0x990C06866FF2424FULL,
			0x6CF684B19655D0EBULL}
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

	steps = 33;
	X1 = (curve25519_key_t){.key64 = {
		0x7E7BAF879E8AD058ULL,
		0xC9594486BC01CAA4ULL,
		0xAFFE3289CF709AFDULL,
		0x72EA9A90ED1C29E3ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7E7BAF879E8AD058ULL,
			0xC9594486BC01CAA4ULL,
			0xAFFE3289CF709AFDULL,
			0x72EA9A90ED1C29E3ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA4D51FDF4E3A8671ULL,
			0xC10B29AD1BE35771ULL,
			0x01D92003910FA754ULL,
			0x4D27ECBD18AC3CFEULL}
		},
		.Z = {.key64 = {
			0x88AB0C4BF5DB33F8ULL,
			0x5B14FCF5E452AE73ULL,
			0xC7FD7A7725C0B088ULL,
			0x7EFF697AA161D451ULL}
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

	steps = 30;
	X1 = (curve25519_key_t){.key64 = {
		0x9649E3F7BB874548ULL,
		0x724EA758938D5D9BULL,
		0x6327C45932A0D52DULL,
		0x64B7F59C939B071CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9649E3F7BB874548ULL,
			0x724EA758938D5D9BULL,
			0x6327C45932A0D52DULL,
			0x64B7F59C939B071CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE367E3481A0E8757ULL,
			0xAB535AC0E5D49457ULL,
			0x4000069EFCA0E7F3ULL,
			0x2668DE9882C7CBEDULL}
		},
		.Z = {.key64 = {
			0x38631BA723415EE0ULL,
			0x62BC77D91DA94111ULL,
			0xC9CA717426BB6C25ULL,
			0x11DCEFB78ACA2FE0ULL}
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

	steps = 52;
	X1 = (curve25519_key_t){.key64 = {
		0x9A4F603156529E68ULL,
		0xD9A7A7B202A3631BULL,
		0x423B06360716B61BULL,
		0x6DC5861BE6A16C46ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9A4F603156529E68ULL,
			0xD9A7A7B202A3631BULL,
			0x423B06360716B61BULL,
			0x6DC5861BE6A16C46ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x03DB985489AF094AULL,
			0xA350D38AE45492AEULL,
			0x4250F855D73CF051ULL,
			0x466B3C9AB4D5157DULL}
		},
		.Z = {.key64 = {
			0x3273C4F3CC41575BULL,
			0xBFCA475C315E11D7ULL,
			0xA66463272365EA96ULL,
			0x6BD30953905FBCAFULL}
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

	steps = 31;
	X1 = (curve25519_key_t){.key64 = {
		0x692EAC598255DF68ULL,
		0xB49BBF4F4C432A28ULL,
		0x71DE2DA541FAA8F0ULL,
		0x66DFD7F3DEB7BD00ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x692EAC598255DF68ULL,
			0xB49BBF4F4C432A28ULL,
			0x71DE2DA541FAA8F0ULL,
			0x66DFD7F3DEB7BD00ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE0F084971E981084ULL,
			0x9E1732DCE1BA0608ULL,
			0x81B5A0337B9658A5ULL,
			0x34FD9B5803A5F153ULL}
		},
		.Z = {.key64 = {
			0x286383A591790F36ULL,
			0x153B01D9896AC379ULL,
			0xC6CEEB13F2321874ULL,
			0x51E33C106655BF0DULL}
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

	steps = 53;
	X1 = (curve25519_key_t){.key64 = {
		0x121B998A3997A9E8ULL,
		0xE89CEA3E13657870ULL,
		0xB0CA804046C646FDULL,
		0x79F1A6D2DD76275FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x121B998A3997A9E8ULL,
			0xE89CEA3E13657870ULL,
			0xB0CA804046C646FDULL,
			0x79F1A6D2DD76275FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0EBB3EDA4775916AULL,
			0x57685734DD7452B2ULL,
			0x4BFE7EB383830F24ULL,
			0x280EB0B9761B517CULL}
		},
		.Z = {.key64 = {
			0x563E08F7FADEF012ULL,
			0xDBFDB342F8C3BDBDULL,
			0x6D6FFFEF6842277DULL,
			0x547E1BBE5A06D26CULL}
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

	steps = 21;
	X1 = (curve25519_key_t){.key64 = {
		0xA8B70E3F5BF36440ULL,
		0x8DADA60C3E213474ULL,
		0xE79E99222ACF59BFULL,
		0x4599B221F9852F21ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA8B70E3F5BF36440ULL,
			0x8DADA60C3E213474ULL,
			0xE79E99222ACF59BFULL,
			0x4599B221F9852F21ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF5099A41F5C4EE1AULL,
			0x7874CA9BC221FC38ULL,
			0xF3239717C5C89899ULL,
			0x0AC05A70893BD76AULL}
		},
		.Z = {.key64 = {
			0x72D55F7F00A2AE44ULL,
			0x1401EF5322D33F51ULL,
			0xB4A98D15C96329BCULL,
			0x79DF4640CB2D3FF8ULL}
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

	steps = 1;
	X1 = (curve25519_key_t){.key64 = {
		0x513895088797B1C0ULL,
		0x32C1028C8BD38EB6ULL,
		0xC67E5315749DBD0CULL,
		0x56B4E845B85F005DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x513895088797B1C0ULL,
			0x32C1028C8BD38EB6ULL,
			0xC67E5315749DBD0CULL,
			0x56B4E845B85F005DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x906C7D28836ECB13ULL,
			0x37C24D905B9B81BEULL,
			0x99C884F827DDB1A8ULL,
			0x1E928714F12D5B0AULL}
		},
		.Z = {.key64 = {
			0x44E254221E5EC726ULL,
			0xCB040A322F4E3AD9ULL,
			0x19F94C55D276F430ULL,
			0x5AD3A116E17C0177ULL}
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

	steps = 63;
	X1 = (curve25519_key_t){.key64 = {
		0x66BE7C5EECAFDFE8ULL,
		0x1CB73FC755295D7CULL,
		0x81A9CA1E370D376FULL,
		0x77F2919833ABCD54ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x66BE7C5EECAFDFE8ULL,
			0x1CB73FC755295D7CULL,
			0x81A9CA1E370D376FULL,
			0x77F2919833ABCD54ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x957E7600D0B0853EULL,
			0x6622E63366FE8FDDULL,
			0xA1FFB411A4D1ADB5ULL,
			0x13E067A0C9B6980CULL}
		},
		.Z = {.key64 = {
			0xEB2FE1CFE5BC107FULL,
			0xF0A445D201A565F5ULL,
			0xCE4191F64A519158ULL,
			0x7E6A0E834639264CULL}
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

	steps = 39;
	X1 = (curve25519_key_t){.key64 = {
		0xB135EC1453DDCD80ULL,
		0xC1E0490801099A94ULL,
		0x9515DDDBF21E1A56ULL,
		0x6AB59B4E549BB2A3ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB135EC1453DDCD80ULL,
			0xC1E0490801099A94ULL,
			0x9515DDDBF21E1A56ULL,
			0x6AB59B4E549BB2A3ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF2E25F31941006E9ULL,
			0xFA7E398DDC126516ULL,
			0x5ECFE01E59633986ULL,
			0x0C34E920FF864826ULL}
		},
		.Z = {.key64 = {
			0x29EEBD3E2B4E63C0ULL,
			0x875FDBCB093FC880ULL,
			0xC6954163B4CBEC68ULL,
			0x0EC23595E909C4B1ULL}
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

	steps = 54;
	X1 = (curve25519_key_t){.key64 = {
		0xB5B249FECC6E7558ULL,
		0x9134A82D95F73EA7ULL,
		0x3B06A36E8993AB0CULL,
		0x5ABEDE2E5BFC2626ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB5B249FECC6E7558ULL,
			0x9134A82D95F73EA7ULL,
			0x3B06A36E8993AB0CULL,
			0x5ABEDE2E5BFC2626ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x93316E1E4D1F978BULL,
			0x3B3C110C6AB8EE10ULL,
			0x681136AEC39E07EBULL,
			0x6DF297E361CB7774ULL}
		},
		.Z = {.key64 = {
			0x8F43D11F30FBB8B3ULL,
			0xC5638CE4D17DA768ULL,
			0x22C1FA38BB3243AEULL,
			0x5ECFA4FF11A4E31DULL}
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

	steps = 28;
	X1 = (curve25519_key_t){.key64 = {
		0x67F318F55E0AB570ULL,
		0x70A8D78235BA3D89ULL,
		0x452D5F70143A509DULL,
		0x637667AFB7B79AD5ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x67F318F55E0AB570ULL,
			0x70A8D78235BA3D89ULL,
			0x452D5F70143A509DULL,
			0x637667AFB7B79AD5ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE165A89B490E8EFAULL,
			0xEF02BD10DACC533AULL,
			0xDAC0D7417BA8EEFAULL,
			0x3F9BA6ED9DE17D39ULL}
		},
		.Z = {.key64 = {
			0x0FADF309DC3A9178ULL,
			0x26C68EFFA673437BULL,
			0xFAD07BF5583F4733ULL,
			0x16E109A1CB16F52CULL}
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

	steps = 51;
	X1 = (curve25519_key_t){.key64 = {
		0x05D59A14253462E0ULL,
		0x1BE61501A1F8EB82ULL,
		0x429BA7E529AC2450ULL,
		0x520AA913D2D7DCA8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x05D59A14253462E0ULL,
			0x1BE61501A1F8EB82ULL,
			0x429BA7E529AC2450ULL,
			0x520AA913D2D7DCA8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7A76B40522BA4443ULL,
			0x0FB4185DF5F63DC1ULL,
			0xE6430671268E435EULL,
			0x7A6788B4F1AF544EULL}
		},
		.Z = {.key64 = {
			0xBED29C4B3F591546ULL,
			0x5B2C1A59A927E81AULL,
			0x1A4B230963B4AD48ULL,
			0x405EACCBD9615B0EULL}
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

	steps = 33;
	X1 = (curve25519_key_t){.key64 = {
		0x3F13C5A1028E5B78ULL,
		0x3FF887BB80A855F3ULL,
		0x35B835CAB61CAEA1ULL,
		0x5BB57F856E831B21ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3F13C5A1028E5B78ULL,
			0x3FF887BB80A855F3ULL,
			0x35B835CAB61CAEA1ULL,
			0x5BB57F856E831B21ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x66CB5226EE865A77ULL,
			0xFE3E80C1565AD0D3ULL,
			0x9DF9B7CC70A77A8BULL,
			0x123E4EAE8F8BA0EDULL}
		},
		.Z = {.key64 = {
			0x70A683DC66F9AF85ULL,
			0xA630D5E39023D5BBULL,
			0xA5131AC43DEA8599ULL,
			0x676691C8AB9D297BULL}
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

	steps = 8;
	X1 = (curve25519_key_t){.key64 = {
		0x48C872DF299A7910ULL,
		0x301ACF0CCBB0FF4CULL,
		0xCBDF89F81438AA55ULL,
		0x507FA35B533AA846ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x48C872DF299A7910ULL,
			0x301ACF0CCBB0FF4CULL,
			0xCBDF89F81438AA55ULL,
			0x507FA35B533AA846ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC4177ABCA8E774BFULL,
			0x47F932E76CE98EEAULL,
			0x60798A3D9DB159D5ULL,
			0x6A2DFA1A05F228C4ULL}
		},
		.Z = {.key64 = {
			0x2936EE742AAC8FE8ULL,
			0x11BDF07430C03DA8ULL,
			0x1F50E9DA26202AF4ULL,
			0x709B399C0B31F19EULL}
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

	steps = 26;
	X1 = (curve25519_key_t){.key64 = {
		0xD3DC8E326E238B50ULL,
		0x50F5CB8561AA8B8FULL,
		0xE0D7106D41E99E5CULL,
		0x7F34A1280C0C0499ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD3DC8E326E238B50ULL,
			0x50F5CB8561AA8B8FULL,
			0xE0D7106D41E99E5CULL,
			0x7F34A1280C0C0499ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3EFBE254AE0183D7ULL,
			0x2FCDB3F09DBED742ULL,
			0x4AA742D627AF048EULL,
			0x20FA8F9F69503CF3ULL}
		},
		.Z = {.key64 = {
			0xA3DDB283ADBCC39AULL,
			0x11CA8D685DDBD0F9ULL,
			0xB54DA9AFD398C94EULL,
			0x190F4965A89254AEULL}
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

	steps = 40;
	X1 = (curve25519_key_t){.key64 = {
		0xE0C55644C920BA08ULL,
		0xD141951917F531F8ULL,
		0xDA0F653621D76BDDULL,
		0x5850930813E8322CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE0C55644C920BA08ULL,
			0xD141951917F531F8ULL,
			0xDA0F653621D76BDDULL,
			0x5850930813E8322CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCD3AA9A8EFA8F10DULL,
			0xBE26994D76EE17E0ULL,
			0x32C6453ED0B4B750ULL,
			0x2D17A389EB564C25ULL}
		},
		.Z = {.key64 = {
			0x0A7D20EDD05550FAULL,
			0xBCB67CFF630A583EULL,
			0xAE05291A21CC855DULL,
			0x0A1A9D265B24F6E8ULL}
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

	steps = 35;
	X1 = (curve25519_key_t){.key64 = {
		0xE305C97B80553090ULL,
		0x0B589B6D963790A2ULL,
		0x8A1CED98A2ED0A70ULL,
		0x4CD7E3EB2232B59CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE305C97B80553090ULL,
			0x0B589B6D963790A2ULL,
			0x8A1CED98A2ED0A70ULL,
			0x4CD7E3EB2232B59CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8AE9E67732BC0763ULL,
			0x47AA85B21A1E6CE7ULL,
			0x692235D9E4360D48ULL,
			0x2C6230B8F4FC4E78ULL}
		},
		.Z = {.key64 = {
			0xC3AC6949845FD6EBULL,
			0x4224870219BC7708ULL,
			0xC1067956133EDC5CULL,
			0x79E2B68EE9001E95ULL}
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

	steps = 24;
	X1 = (curve25519_key_t){.key64 = {
		0x9C238D890E261E90ULL,
		0x9563B68F3A31B0AEULL,
		0x5EAEDD4820D3F0AFULL,
		0x54CB5257793DC86CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9C238D890E261E90ULL,
			0x9563B68F3A31B0AEULL,
			0x5EAEDD4820D3F0AFULL,
			0x54CB5257793DC86CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFD855ACEEB5E77B1ULL,
			0x3A40F1A46C0D084CULL,
			0xB15A19B62A612C33ULL,
			0x2F504BBB438AF1F9ULL}
		},
		.Z = {.key64 = {
			0x66D4D7AEF3A01C89ULL,
			0x179F6380688B34C7ULL,
			0xF95902FD91DE2824ULL,
			0x300B5EDDD70868F9ULL}
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

	steps = 59;
	X1 = (curve25519_key_t){.key64 = {
		0x52EF237C1F6D9810ULL,
		0x7D57775964C8A499ULL,
		0x4E71C77D0C9FD324ULL,
		0x70C8E80904753C6FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x52EF237C1F6D9810ULL,
			0x7D57775964C8A499ULL,
			0x4E71C77D0C9FD324ULL,
			0x70C8E80904753C6FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE35B7068F22B8243ULL,
			0x1AAF932A6E0017C1ULL,
			0x26B59C4B65AEDABCULL,
			0x1D0591F0D84057E0ULL}
		},
		.Z = {.key64 = {
			0x5859287E3645C96AULL,
			0x1978A9F94366D85FULL,
			0x5CB0D72901BAF0CBULL,
			0x0B9A76E6C7818E0AULL}
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

	steps = 32;
	X1 = (curve25519_key_t){.key64 = {
		0x35405E81169234A0ULL,
		0xAA0A3ECA1E73719AULL,
		0x2B097566816EB02BULL,
		0x5F4C50F20FB750ABULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x35405E81169234A0ULL,
			0xAA0A3ECA1E73719AULL,
			0x2B097566816EB02BULL,
			0x5F4C50F20FB750ABULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3B74A83C316D3991ULL,
			0x3C0B1625F33647F3ULL,
			0x20BDCA83B3A3B26AULL,
			0x73CA42AFC0E4BC1AULL}
		},
		.Z = {.key64 = {
			0x58344C93326CAE11ULL,
			0x477CC59483F35E44ULL,
			0xB038584204F0B2A2ULL,
			0x5BA0506DB7AEF1CAULL}
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

	steps = 49;
	X1 = (curve25519_key_t){.key64 = {
		0xF9AE2AAE75A03450ULL,
		0x35804CDB88168A04ULL,
		0xCD3E70A668ECC148ULL,
		0x78595E0E69742EA4ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF9AE2AAE75A03450ULL,
			0x35804CDB88168A04ULL,
			0xCD3E70A668ECC148ULL,
			0x78595E0E69742EA4ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEDE551F3584B9E25ULL,
			0x38D19070846C954DULL,
			0xC988F4BB06D7187FULL,
			0x4563F65C3A966350ULL}
		},
		.Z = {.key64 = {
			0xC883250E64E82719ULL,
			0xB1C47455B565093CULL,
			0xBF6E3897D62EB9A7ULL,
			0x54F9E53EF6185934ULL}
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

	steps = 26;
	X1 = (curve25519_key_t){.key64 = {
		0xCDF02A7E850070E8ULL,
		0xFB16CAFE21CC4560ULL,
		0x7B30CA35F5FBCBE9ULL,
		0x77EEC1525732CABDULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCDF02A7E850070E8ULL,
			0xFB16CAFE21CC4560ULL,
			0x7B30CA35F5FBCBE9ULL,
			0x77EEC1525732CABDULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x692CE16E5B3AE0B6ULL,
			0xAE8F6D2DDE551AE4ULL,
			0x9F8162F55EFB9A30ULL,
			0x38BFDF42B29A8BC3ULL}
		},
		.Z = {.key64 = {
			0x5846742417968475ULL,
			0x1C1418C19895D199ULL,
			0xE0E3F6D4E233489BULL,
			0x47D98A5CF8573597ULL}
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

	steps = 59;
	X1 = (curve25519_key_t){.key64 = {
		0x93AD32651385D9A8ULL,
		0x0F2FE4EF8D339CE4ULL,
		0x25DFFF7D1C646698ULL,
		0x6874CB11F7D16CBCULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x93AD32651385D9A8ULL,
			0x0F2FE4EF8D339CE4ULL,
			0x25DFFF7D1C646698ULL,
			0x6874CB11F7D16CBCULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x16382CA43340B53BULL,
			0x1E45A9F54083E2FFULL,
			0x42CB7A4D4CAF83DDULL,
			0x217D9F1818E5E7AEULL}
		},
		.Z = {.key64 = {
			0x161ED52CECF562E8ULL,
			0x4161FC50EB9B04AAULL,
			0x4BEE2C9D0490BC80ULL,
			0x3C363736BB90DE54ULL}
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

	steps = 2;
	X1 = (curve25519_key_t){.key64 = {
		0x5F38605BAF25C870ULL,
		0x55A12B8E05CF44DEULL,
		0x4BDA5BEE3A010F6EULL,
		0x5F23BC895FFDB6DAULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5F38605BAF25C870ULL,
			0x55A12B8E05CF44DEULL,
			0x4BDA5BEE3A010F6EULL,
			0x5F23BC895FFDB6DAULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDF2C82C4853BC830ULL,
			0x04C3C6A6403D2A7CULL,
			0x01FD91F93F52F897ULL,
			0x710D14339CD88AAEULL}
		},
		.Z = {.key64 = {
			0x7E3658DA5F925A99ULL,
			0xAD04C35E26A91642ULL,
			0x30DF46C5A2FDF16DULL,
			0x41B02197D1BE5205ULL}
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

	steps = 48;
	X1 = (curve25519_key_t){.key64 = {
		0x484AF99187FBDF30ULL,
		0xDA8F2FD89271B758ULL,
		0x18138C679D67EE75ULL,
		0x7E8DFF06888CEF00ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x484AF99187FBDF30ULL,
			0xDA8F2FD89271B758ULL,
			0x18138C679D67EE75ULL,
			0x7E8DFF06888CEF00ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6A119CB7AA804C7AULL,
			0xF8CAC5A3665B8178ULL,
			0x9E707F7BF27F5DEBULL,
			0x67C9DF7259FDEB7FULL}
		},
		.Z = {.key64 = {
			0x862CB329379A7A8DULL,
			0x4D6ABAE9805799B7ULL,
			0x4A01AB7DF32C440CULL,
			0x5BEBDDD4B3D83F00ULL}
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

	steps = 9;
	X1 = (curve25519_key_t){.key64 = {
		0xF9ABFFEA3FFEDEA0ULL,
		0xD603ED6BF06E596BULL,
		0xF2E1127EAA4CB331ULL,
		0x67BC65ED65BFB059ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF9ABFFEA3FFEDEA0ULL,
			0xD603ED6BF06E596BULL,
			0xF2E1127EAA4CB331ULL,
			0x67BC65ED65BFB059ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4BADDFE5C5F2DCD3ULL,
			0x561C46CD016F3DBEULL,
			0x8A461A66361D4BEFULL,
			0x4B63EEA95757C130ULL}
		},
		.Z = {.key64 = {
			0x26DCD0E534BFE64EULL,
			0x80EEDDDADA562914ULL,
			0xC005366020456B59ULL,
			0x5587BCA8913282B2ULL}
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

	steps = 22;
	X1 = (curve25519_key_t){.key64 = {
		0xF8F0D13D8F32E688ULL,
		0x9FAE7A2735A9D2EBULL,
		0x6D07E8C571318C6EULL,
		0x412F6996C000156DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF8F0D13D8F32E688ULL,
			0x9FAE7A2735A9D2EBULL,
			0x6D07E8C571318C6EULL,
			0x412F6996C000156DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6C08495321592D0DULL,
			0xA85F5A807F7F2EC2ULL,
			0x139DDE44E231A869ULL,
			0x1592C9F56C290D40ULL}
		},
		.Z = {.key64 = {
			0x14DB4FCF1E5DF811ULL,
			0xB2BDDF5FE7FA3F37ULL,
			0xC485F0B5D9EDB268ULL,
			0x50310C3789FC3449ULL}
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

	steps = 24;
	X1 = (curve25519_key_t){.key64 = {
		0x6B6E399F6A950470ULL,
		0x5A9FAEC772D26E8AULL,
		0x66C4CFE475A93D1CULL,
		0x7DBAEC9F779E587BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6B6E399F6A950470ULL,
			0x5A9FAEC772D26E8AULL,
			0x66C4CFE475A93D1CULL,
			0x7DBAEC9F779E587BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7C3882AB71A55C12ULL,
			0xAE4E987D1983B23EULL,
			0xDE74AB1D6EB0540DULL,
			0x5EAE2E89C7F1FD33ULL}
		},
		.Z = {.key64 = {
			0xBC97261326E5AFB5ULL,
			0x62330AA8D56E2DBAULL,
			0xE0DE5652841C658FULL,
			0x2CC701E925EEF1C5ULL}
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

	steps = 39;
	X1 = (curve25519_key_t){.key64 = {
		0xB9A0331399E4AE80ULL,
		0x0D76AEA57A676B06ULL,
		0xB98E2EE1CB110A09ULL,
		0x438B02E57AD2CA69ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB9A0331399E4AE80ULL,
			0x0D76AEA57A676B06ULL,
			0xB98E2EE1CB110A09ULL,
			0x438B02E57AD2CA69ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3E1C56029F5577E6ULL,
			0x0F3F9619B67791AFULL,
			0x2D80247FBFD2B8E4ULL,
			0x45345577CE618925ULL}
		},
		.Z = {.key64 = {
			0x44E2AAE9BB7B76CBULL,
			0xE5343F08DCCF107BULL,
			0x77B623B02D05ACD4ULL,
			0x3BC9D0968DC56FECULL}
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

	steps = 42;
	X1 = (curve25519_key_t){.key64 = {
		0x2D6EB52545EF67F8ULL,
		0xED108D71F4A37398ULL,
		0x5F9D48850226D5C9ULL,
		0x6BCA2E83DE70839DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2D6EB52545EF67F8ULL,
			0xED108D71F4A37398ULL,
			0x5F9D48850226D5C9ULL,
			0x6BCA2E83DE70839DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x63213C0A1D418D1FULL,
			0xAA9F6C8B6292DCF7ULL,
			0xF7A887136B0F637EULL,
			0x12BA713EFD2D003FULL}
		},
		.Z = {.key64 = {
			0x1E1538CC32478728ULL,
			0x42A8BA4308D7C46CULL,
			0xB5892FC259D38166ULL,
			0x5907D9A66A352184ULL}
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

	steps = 29;
	X1 = (curve25519_key_t){.key64 = {
		0xC062102ED4BDFE58ULL,
		0x4BEDF755467CFC5FULL,
		0xD5E834F82E467FC0ULL,
		0x59581E382A84C7CBULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC062102ED4BDFE58ULL,
			0x4BEDF755467CFC5FULL,
			0xD5E834F82E467FC0ULL,
			0x59581E382A84C7CBULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x41EC6C53FDB5D891ULL,
			0x79F8C29ACE6A40A8ULL,
			0xD7CF179258DB7968ULL,
			0x68BF7BD6289BF511ULL}
		},
		.Z = {.key64 = {
			0x3D37391C06BCFD56ULL,
			0x613D586476F726BEULL,
			0x1460FD488D06475AULL,
			0x0E2797BF7669C522ULL}
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

	steps = 7;
	X1 = (curve25519_key_t){.key64 = {
		0x9C398F512963D188ULL,
		0xFD55B8D837D145A4ULL,
		0x9A1A038014E124E5ULL,
		0x4186E4F9807E652CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9C398F512963D188ULL,
			0xFD55B8D837D145A4ULL,
			0x9A1A038014E124E5ULL,
			0x4186E4F9807E652CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x051BEE704B2FE12AULL,
			0xCC90AAEB0877461DULL,
			0xD60E2881C96ECD31ULL,
			0x13F5AE97753D306FULL}
		},
		.Z = {.key64 = {
			0x0F31541FA049816CULL,
			0xAD4934AC1E15681DULL,
			0xEFC937D557DC13D4ULL,
			0x53525942BD5BB5EDULL}
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

	steps = 61;
	X1 = (curve25519_key_t){.key64 = {
		0x5CC80BF012E05790ULL,
		0x5D0412914E00E6C2ULL,
		0x2903676B118517CFULL,
		0x792B76395A7F79ECULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5CC80BF012E05790ULL,
			0x5D0412914E00E6C2ULL,
			0x2903676B118517CFULL,
			0x792B76395A7F79ECULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD397F9EF0BD0AB92ULL,
			0xC768B67B9A748449ULL,
			0x13C7FA1747663E66ULL,
			0x5D46648AA57764F5ULL}
		},
		.Z = {.key64 = {
			0x0422F2B097CDE67DULL,
			0x95DA462B5640C0EDULL,
			0x156AD4CC0DC6E49CULL,
			0x6146F522EBAF17A8ULL}
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

	steps = 16;
	X1 = (curve25519_key_t){.key64 = {
		0x95BACEFB6639D8B0ULL,
		0xB63A990AE3E4E19BULL,
		0xA8BAB8B534CABD0AULL,
		0x6C105586FAB52943ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x95BACEFB6639D8B0ULL,
			0xB63A990AE3E4E19BULL,
			0xA8BAB8B534CABD0AULL,
			0x6C105586FAB52943ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x427271AE12FE5CF8ULL,
			0xE6F4661338653C4EULL,
			0x3CEB4ED9DC2AE720ULL,
			0x0A0F29B39AEDF65AULL}
		},
		.Z = {.key64 = {
			0x6B5D337082B98D70ULL,
			0x787AB4C03111DE25ULL,
			0xF49D96F3E65CEB88ULL,
			0x7FFD1034FFA6FE88ULL}
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

	steps = 30;
	X1 = (curve25519_key_t){.key64 = {
		0x3BC18B1B5C9FBF18ULL,
		0xA3372D1163E1549DULL,
		0xD87675E1FB16E2B9ULL,
		0x740C73CF3D6C238AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3BC18B1B5C9FBF18ULL,
			0xA3372D1163E1549DULL,
			0xD87675E1FB16E2B9ULL,
			0x740C73CF3D6C238AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x62C7F6F9B7DAAA4DULL,
			0xC46A61A910B01421ULL,
			0x09DC25CA91C849A0ULL,
			0x5E0C68F595181216ULL}
		},
		.Z = {.key64 = {
			0x46A696C54FDB4D2FULL,
			0xA8E5B7492925132CULL,
			0x4B5CBEBFD3FAC29DULL,
			0x3C2F7A1B3FC98413ULL}
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

	steps = 20;
	X1 = (curve25519_key_t){.key64 = {
		0xCE25D69442E86888ULL,
		0x91885ABAE27BA319ULL,
		0x9FD1E319C65C9238ULL,
		0x4BDFDDD1FA26D505ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCE25D69442E86888ULL,
			0x91885ABAE27BA319ULL,
			0x9FD1E319C65C9238ULL,
			0x4BDFDDD1FA26D505ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAB483EE648E092C2ULL,
			0x2131811FBAA0C444ULL,
			0x07F252A2BE5CB3BFULL,
			0x4E505A41205C8300ULL}
		},
		.Z = {.key64 = {
			0xA1FC5443B6E8D5C7ULL,
			0x7BFEFDEF5FC752DEULL,
			0x9F5731369CA8B421ULL,
			0x28635E25D608E9DDULL}
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

	steps = 53;
	X1 = (curve25519_key_t){.key64 = {
		0x545D41C7EF4BCD18ULL,
		0x6AB1334F9DF43BCCULL,
		0x99C482BE22C39FABULL,
		0x4289356BB0A7CC8BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x545D41C7EF4BCD18ULL,
			0x6AB1334F9DF43BCCULL,
			0x99C482BE22C39FABULL,
			0x4289356BB0A7CC8BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC901D265B760BCD0ULL,
			0x668AAC937192581DULL,
			0xFA4DC78EBAAA2C12ULL,
			0x2CF8FA22A0951410ULL}
		},
		.Z = {.key64 = {
			0x484BE663F97B4DCBULL,
			0xF454506B07758C5CULL,
			0x1706EE75B2555994ULL,
			0x17D5F60866AF98BBULL}
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

	steps = 22;
	X1 = (curve25519_key_t){.key64 = {
		0x4ED8E9F585A4FDE8ULL,
		0x78A65FCD1D6C2692ULL,
		0x695FD7222417E987ULL,
		0x53F035C9C4D574B6ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4ED8E9F585A4FDE8ULL,
			0x78A65FCD1D6C2692ULL,
			0x695FD7222417E987ULL,
			0x53F035C9C4D574B6ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCDD38F94C33E8FC4ULL,
			0x1F5B26A4A0EC40B6ULL,
			0x4F93EDA259FC9224ULL,
			0x0DA76C7C04AC1341ULL}
		},
		.Z = {.key64 = {
			0x3EBD9BCC92C8308BULL,
			0x1115752E0B248230ULL,
			0xF81FEE3AC46BA482ULL,
			0x42A39A00563CFEB3ULL}
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

	steps = 38;
	X1 = (curve25519_key_t){.key64 = {
		0xF3705090ED95FBE8ULL,
		0xBD8B68A68C1D4D29ULL,
		0x6796CB73B2E06CBCULL,
		0x60C574F80017ABE5ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF3705090ED95FBE8ULL,
			0xBD8B68A68C1D4D29ULL,
			0x6796CB73B2E06CBCULL,
			0x60C574F80017ABE5ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x36052F3F6E5F8A94ULL,
			0x24AF35B6CBF67E95ULL,
			0xF0DC304847DAD4EDULL,
			0x081B578F7CCB0964ULL}
		},
		.Z = {.key64 = {
			0x314660DCED00104EULL,
			0x603F34198DF566BAULL,
			0xBC8E69BA519AF4D2ULL,
			0x36393CCB3438B08EULL}
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

	steps = 7;
	X1 = (curve25519_key_t){.key64 = {
		0x2A3DF61BEE303E08ULL,
		0x53F39591B28443C5ULL,
		0xD28D13458619B9E5ULL,
		0x7351A88D7EF19BB3ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2A3DF61BEE303E08ULL,
			0x53F39591B28443C5ULL,
			0xD28D13458619B9E5ULL,
			0x7351A88D7EF19BB3ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEAC0393D78EB8428ULL,
			0x851E3798B986016BULL,
			0x2344DC39D7792C80ULL,
			0x0D19FED69E2404F5ULL}
		},
		.Z = {.key64 = {
			0x2866FE433578591BULL,
			0x06E8AB089D787B4BULL,
			0x8563A3B864EB4957ULL,
			0x26BA4E565A347FE8ULL}
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

	steps = 39;
	X1 = (curve25519_key_t){.key64 = {
		0x14C8AE957BFDBA50ULL,
		0x462ABA90CF65B785ULL,
		0xD907CC400087FC34ULL,
		0x46581267EBE761D8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x14C8AE957BFDBA50ULL,
			0x462ABA90CF65B785ULL,
			0xD907CC400087FC34ULL,
			0x46581267EBE761D8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5FB1782D35CF5D00ULL,
			0xBEE2EA5626D28F3DULL,
			0x67735EE40125B31BULL,
			0x5641D9E492828876ULL}
		},
		.Z = {.key64 = {
			0xD5E38A7E808D51E9ULL,
			0x0E5251BF5B6394C0ULL,
			0xFFEC7C0465105E2EULL,
			0x4D10666EC780ADCCULL}
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

	steps = 34;
	X1 = (curve25519_key_t){.key64 = {
		0x0CFFD8A9CA2994D0ULL,
		0x1337C4FC0E7C993EULL,
		0xA6C3B68C386880C6ULL,
		0x46484286E0F34068ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0CFFD8A9CA2994D0ULL,
			0x1337C4FC0E7C993EULL,
			0xA6C3B68C386880C6ULL,
			0x46484286E0F34068ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB415DF93AC9437B5ULL,
			0xEB805E6933276A2BULL,
			0xB2892273723EF380ULL,
			0x386A1E400F0E2BEDULL}
		},
		.Z = {.key64 = {
			0x62A3D011EA1C8834ULL,
			0xF4531EC052018A99ULL,
			0x70B857CB5961DEDCULL,
			0x673CBC3762036693ULL}
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

	steps = 34;
	X1 = (curve25519_key_t){.key64 = {
		0x25658BFBB90ABCE0ULL,
		0x064E336730618F57ULL,
		0x9BD6907C718F60A4ULL,
		0x74082C8F919B3AD9ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x25658BFBB90ABCE0ULL,
			0x064E336730618F57ULL,
			0x9BD6907C718F60A4ULL,
			0x74082C8F919B3AD9ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x35EFFF9421E2F0E0ULL,
			0xDB5612E4E8379E40ULL,
			0xAC6739F553F1913AULL,
			0x15A0DA78A587A1CFULL}
		},
		.Z = {.key64 = {
			0x6EF36DF9DC4E8095ULL,
			0x1AAD2017C2C483EAULL,
			0xE00AD2F2AB34B4BAULL,
			0x4A462BADAFE4E9C1ULL}
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

	steps = 53;
	X1 = (curve25519_key_t){.key64 = {
		0x76170B52D0677710ULL,
		0xD69922EBC3D03A09ULL,
		0x132F973E8FD0AE9FULL,
		0x5EA80F1EF47F2C1BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x76170B52D0677710ULL,
			0xD69922EBC3D03A09ULL,
			0x132F973E8FD0AE9FULL,
			0x5EA80F1EF47F2C1BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x56C7F413E2609A6EULL,
			0xE1885D7AEACB83C4ULL,
			0x9C1FD5C353A10EB3ULL,
			0x18AFF36E47F08603ULL}
		},
		.Z = {.key64 = {
			0x33AB3CB9C230F00FULL,
			0xAC648B83C0611EF5ULL,
			0x861A9BC57FED001DULL,
			0x3FFFA4B7B0219F01ULL}
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

	steps = 29;
	X1 = (curve25519_key_t){.key64 = {
		0x805E5302CE19EE80ULL,
		0xCD9B71D3C10858B0ULL,
		0x23EEB0E6B9020C06ULL,
		0x4ADA43F8D65F05CFULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x805E5302CE19EE80ULL,
			0xCD9B71D3C10858B0ULL,
			0x23EEB0E6B9020C06ULL,
			0x4ADA43F8D65F05CFULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x37D6A0682B51B02DULL,
			0xD1566D2CDC827E69ULL,
			0x8099A86ABFA6B70BULL,
			0x19D306ED13E4EBDBULL}
		},
		.Z = {.key64 = {
			0x68025E70AAA133C4ULL,
			0x026E3AC8E988FA53ULL,
			0xBB01884716D75ECAULL,
			0x5FA8BB3D6EA4DA99ULL}
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

	steps = 7;
	X1 = (curve25519_key_t){.key64 = {
		0x8B40548D53FB9370ULL,
		0x7246D3A6F672798AULL,
		0x78B1FB5A90801AAAULL,
		0x72B1CD33FB711587ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8B40548D53FB9370ULL,
			0x7246D3A6F672798AULL,
			0x78B1FB5A90801AAAULL,
			0x72B1CD33FB711587ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1F72971E520E5C80ULL,
			0xC24A4A9D3892352AULL,
			0xB5DBC9DB38D2E9F3ULL,
			0x042B304B08590A10ULL}
		},
		.Z = {.key64 = {
			0xE8450D4F6B87C11CULL,
			0x25D6080379A6AA5CULL,
			0x9A6103F9BB46C731ULL,
			0x6FFA49817F83D276ULL}
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

	steps = 47;
	X1 = (curve25519_key_t){.key64 = {
		0xD0A2BDB847C51FC0ULL,
		0x18BE2A8122B10649ULL,
		0xD6E3FFE0C1B03597ULL,
		0x7EF2E1C7CCFF01B7ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD0A2BDB847C51FC0ULL,
			0x18BE2A8122B10649ULL,
			0xD6E3FFE0C1B03597ULL,
			0x7EF2E1C7CCFF01B7ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x07D5CF6BD4DA5118ULL,
			0x3459E3400926A652ULL,
			0x21DB55C270507A66ULL,
			0x1955C50DF141E06CULL}
		},
		.Z = {.key64 = {
			0x9A304435EEB8FA27ULL,
			0x1DC210A8702A38FCULL,
			0xCDF5BF4F6167388EULL,
			0x53BC4D006C6BC663ULL}
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

	steps = 41;
	X1 = (curve25519_key_t){.key64 = {
		0xF67205AD1B88BA88ULL,
		0x4C936451D1CE8FFFULL,
		0xBF19EA877C59F15FULL,
		0x557C481EA2061D38ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF67205AD1B88BA88ULL,
			0x4C936451D1CE8FFFULL,
			0xBF19EA877C59F15FULL,
			0x557C481EA2061D38ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB31742C3F539CCF2ULL,
			0xBED32A560ACAF1B7ULL,
			0x4BCEEC34F9A612B6ULL,
			0x246D0D3C8F2F83F9ULL}
		},
		.Z = {.key64 = {
			0x6AD471E04AD38E12ULL,
			0xC572394636644AEDULL,
			0x26D0062CF271F73CULL,
			0x52C6F41CB1F527A5ULL}
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

	steps = 50;
	X1 = (curve25519_key_t){.key64 = {
		0x3C3CB26508FD42A8ULL,
		0x382F7AE37CE51E8AULL,
		0xFFA26E80E311A558ULL,
		0x492C167B068E35FFULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3C3CB26508FD42A8ULL,
			0x382F7AE37CE51E8AULL,
			0xFFA26E80E311A558ULL,
			0x492C167B068E35FFULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x95894E034EA39198ULL,
			0xA9D040685E1D6D01ULL,
			0x2110A6B9912AD07CULL,
			0x71BE8DD001D95B0AULL}
		},
		.Z = {.key64 = {
			0x513D57D25BE8524FULL,
			0x551219BCDB194D65ULL,
			0xEF076AFED4ED36E4ULL,
			0x0417BD4C21CE85ACULL}
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

	steps = 22;
	X1 = (curve25519_key_t){.key64 = {
		0x2CAAFCF22BF52A78ULL,
		0x5B6D288DE1F2DCA6ULL,
		0xAAEFD5D8641369DFULL,
		0x48836A19C29CE75CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2CAAFCF22BF52A78ULL,
			0x5B6D288DE1F2DCA6ULL,
			0xAAEFD5D8641369DFULL,
			0x48836A19C29CE75CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8E1CA45A967874B6ULL,
			0x361F4683AB9B1982ULL,
			0x49757C2111AB98C2ULL,
			0x3DA1C59920A99E95ULL}
		},
		.Z = {.key64 = {
			0x2CC68FA981544C4EULL,
			0xDAB1F01629753665ULL,
			0x89AE86E8402E06B4ULL,
			0x056A5A3E4D8128FEULL}
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

	steps = 5;
	X1 = (curve25519_key_t){.key64 = {
		0x11E13D241C05A6C0ULL,
		0x779F530C58A1AD17ULL,
		0x36714EBAB1B92F66ULL,
		0x7E3112F145C5EA99ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x11E13D241C05A6C0ULL,
			0x779F530C58A1AD17ULL,
			0x36714EBAB1B92F66ULL,
			0x7E3112F145C5EA99ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x06150F9B00B81971ULL,
			0xCE5DA70CB302EAE7ULL,
			0xE1B41C029FDB9E93ULL,
			0x40D145A25EDBD1BFULL}
		},
		.Z = {.key64 = {
			0xC01AD60E52CCBEF5ULL,
			0xB33BCC0BCAE2138AULL,
			0x6C44C346F8B64BECULL,
			0x763B5FDDB9C1FD66ULL}
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

	steps = 36;
	X1 = (curve25519_key_t){.key64 = {
		0x0673D1747AE6FB30ULL,
		0x3C3DE03C0D249EBFULL,
		0x3822A22FF1DEC356ULL,
		0x7606F331E6BCC4DCULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0673D1747AE6FB30ULL,
			0x3C3DE03C0D249EBFULL,
			0x3822A22FF1DEC356ULL,
			0x7606F331E6BCC4DCULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8E258CF8C8588DC1ULL,
			0xD25EF28467A35F1EULL,
			0x220EB4D0E53711EEULL,
			0x1E63398008CCDAA2ULL}
		},
		.Z = {.key64 = {
			0x8C4249C3F95A7AF2ULL,
			0xCC4CFA32F962D12EULL,
			0xFE22DAD469646803ULL,
			0x2FE55DDA18B235BBULL}
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

	steps = 40;
	X1 = (curve25519_key_t){.key64 = {
		0x956A2695CFF86DC8ULL,
		0x913F7A80142E807DULL,
		0x771D076E441C4E41ULL,
		0x5B9818788DA35E37ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x956A2695CFF86DC8ULL,
			0x913F7A80142E807DULL,
			0x771D076E441C4E41ULL,
			0x5B9818788DA35E37ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA8DE55A72EBF3CC3ULL,
			0xDB32D7B82BF3D298ULL,
			0xE5B89836B2A81191ULL,
			0x3DDBFA31CF7B4126ULL}
		},
		.Z = {.key64 = {
			0x4F72BC2BB9A20A44ULL,
			0xFDD6E1D6FF4A3C84ULL,
			0x7549100D8D4AEFBAULL,
			0x7479290FC133D785ULL}
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

	steps = 51;
	X1 = (curve25519_key_t){.key64 = {
		0xA112EEC47DC9ADB0ULL,
		0xEFF6A741EAF188ECULL,
		0x949CA6B9BFD940C0ULL,
		0x7D8942045E964762ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA112EEC47DC9ADB0ULL,
			0xEFF6A741EAF188ECULL,
			0x949CA6B9BFD940C0ULL,
			0x7D8942045E964762ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x187F71F40F9CA220ULL,
			0xEDDE958FB1755726ULL,
			0x303C89D3343E64E5ULL,
			0x017B6279905F5F06ULL}
		},
		.Z = {.key64 = {
			0x031DBBA30C61A0D7ULL,
			0xB27DE137A945A85EULL,
			0xBF311F7B63D86BE1ULL,
			0x1D322B72472DAE3CULL}
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

	steps = 22;
	X1 = (curve25519_key_t){.key64 = {
		0x82E55F564B41E800ULL,
		0x63B6869DE9A8C183ULL,
		0x725BD3CF3FA1C8A1ULL,
		0x6EC1598A940F551DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x82E55F564B41E800ULL,
			0x63B6869DE9A8C183ULL,
			0x725BD3CF3FA1C8A1ULL,
			0x6EC1598A940F551DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0846A69DC037C74EULL,
			0xCB7484EAFC71C512ULL,
			0x6D7D768A623B4E90ULL,
			0x618F98CF53F0A73FULL}
		},
		.Z = {.key64 = {
			0x8EEFB579CEDC10BDULL,
			0xCD2935D721647B04ULL,
			0x1EC924224E2996DDULL,
			0x368DA73D190E9F92ULL}
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

	steps = 14;
	X1 = (curve25519_key_t){.key64 = {
		0x6781686F3D6D42B8ULL,
		0x24EB508E36CF86C0ULL,
		0x206B6D9A7986E8A1ULL,
		0x44F3137FA401A978ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6781686F3D6D42B8ULL,
			0x24EB508E36CF86C0ULL,
			0x206B6D9A7986E8A1ULL,
			0x44F3137FA401A978ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x43DE255305A1E5EFULL,
			0x1B7F028CCA2A4C0CULL,
			0x9753D431B3995A69ULL,
			0x0DE0D10CE71B0E42ULL}
		},
		.Z = {.key64 = {
			0x96CEF293E5CD55F3ULL,
			0x0FA8E57D8951BCCBULL,
			0x932BAD297FC8EA07ULL,
			0x31D09216599BFC2FULL}
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

	steps = 44;
	X1 = (curve25519_key_t){.key64 = {
		0x5591F74F98067270ULL,
		0x86060262601C3D3FULL,
		0x6A50FDCA4CD3C0A4ULL,
		0x6A497AB217BBD5C2ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5591F74F98067270ULL,
			0x86060262601C3D3FULL,
			0x6A50FDCA4CD3C0A4ULL,
			0x6A497AB217BBD5C2ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x91DEBAA53F9273D5ULL,
			0x170298F622028E15ULL,
			0x329686BE524376A8ULL,
			0x0EE2BBA51DA2F8ABULL}
		},
		.Z = {.key64 = {
			0x0379E03E9BA92049ULL,
			0xD0C18820157D0549ULL,
			0x81D642DD3DB39305ULL,
			0x29B409912F689892ULL}
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

	steps = 12;
	X1 = (curve25519_key_t){.key64 = {
		0xEC6EAC1A42F44F50ULL,
		0xBE113017FFFB0DA3ULL,
		0x48BE86605D6009B2ULL,
		0x54C4ECBC740AE9D7ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEC6EAC1A42F44F50ULL,
			0xBE113017FFFB0DA3ULL,
			0x48BE86605D6009B2ULL,
			0x54C4ECBC740AE9D7ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4631B60FE8699FA3ULL,
			0xC273D1F0A3816FE8ULL,
			0x8A74E4914F2BF5DFULL,
			0x7028E3B77AFA7A3DULL}
		},
		.Z = {.key64 = {
			0x33C8DE05B109EDF5ULL,
			0xC820D325E519D3CFULL,
			0x1FC8CCA3CC88FA54ULL,
			0x3EA3000EF17B5FD9ULL}
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

	steps = 64;
	X1 = (curve25519_key_t){.key64 = {
		0x9A40FCDFD7C63F18ULL,
		0xABA1DAF6732734DDULL,
		0xF8525AACCC377DB5ULL,
		0x4DD0E022F6460735ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9A40FCDFD7C63F18ULL,
			0xABA1DAF6732734DDULL,
			0xF8525AACCC377DB5ULL,
			0x4DD0E022F6460735ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x74CDA342E3F0CFFBULL,
			0xB15959E465D2742EULL,
			0xF228344953B99A76ULL,
			0x185AC6A44C552809ULL}
		},
		.Z = {.key64 = {
			0xA93744456E0FC27BULL,
			0x3723A61CF9154F39ULL,
			0x373E8793F213AB63ULL,
			0x3BE03AA8FF5CFB04ULL}
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

	steps = 10;
	X1 = (curve25519_key_t){.key64 = {
		0x624934788AD41450ULL,
		0x96AF1A8DF20652DAULL,
		0x4E0FADAEE3C3268BULL,
		0x4C412ED85ADE2EA9ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x624934788AD41450ULL,
			0x96AF1A8DF20652DAULL,
			0x4E0FADAEE3C3268BULL,
			0x4C412ED85ADE2EA9ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF90161C61175F8DAULL,
			0xF08B424D6BF6D43DULL,
			0xDF9A0E6BC017D74EULL,
			0x7A527B5CAC82A166ULL}
		},
		.Z = {.key64 = {
			0xA622881DA7289923ULL,
			0x95AFD7FA96A4C1E6ULL,
			0x3BB8D47462CA37F0ULL,
			0x3B63286720ACF4FCULL}
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

	steps = 42;
	X1 = (curve25519_key_t){.key64 = {
		0xB430D141AB428A28ULL,
		0xEF0A8C593C96B04CULL,
		0xA1B7B071901271B5ULL,
		0x53E104B1DF03AA5CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB430D141AB428A28ULL,
			0xEF0A8C593C96B04CULL,
			0xA1B7B071901271B5ULL,
			0x53E104B1DF03AA5CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x902037052B965A60ULL,
			0x4598E9AE36A757ADULL,
			0x017653915E582CAAULL,
			0x4D2A0B30D4E980E6ULL}
		},
		.Z = {.key64 = {
			0xE2FABB942A69A0D9ULL,
			0x72C16BCD5AD54571ULL,
			0x411FA110FAA033CAULL,
			0x61DB3873F70E59D5ULL}
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

	steps = 30;
	X1 = (curve25519_key_t){.key64 = {
		0x6DC34D03BCDF7828ULL,
		0xF76A06A521491610ULL,
		0x15331A3A3594218FULL,
		0x5D94F71A39412779ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6DC34D03BCDF7828ULL,
			0xF76A06A521491610ULL,
			0x15331A3A3594218FULL,
			0x5D94F71A39412779ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7059535D4DC40025ULL,
			0xD5B7EF0B7175A2D0ULL,
			0xA7B6BCDB6C727EEEULL,
			0x46088605FDFD67D0ULL}
		},
		.Z = {.key64 = {
			0x00A2E69CA3BF41EEULL,
			0xB946560D1D93D666ULL,
			0x0C7DA8AEBF11D4DDULL,
			0x5B6781318BD68687ULL}
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

	steps = 41;
	X1 = (curve25519_key_t){.key64 = {
		0x0FDDAB27877CB1B0ULL,
		0xB8E63F5AF47062CCULL,
		0x47AF52CAA43D2905ULL,
		0x5CB829F30C6FA79FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0FDDAB27877CB1B0ULL,
			0xB8E63F5AF47062CCULL,
			0x47AF52CAA43D2905ULL,
			0x5CB829F30C6FA79FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8CF91F8D99C01CEFULL,
			0x80C7EFDB4C582383ULL,
			0xD70ED7437C79E345ULL,
			0x3123ECA97CDF91B4ULL}
		},
		.Z = {.key64 = {
			0xE741664F6B6406B3ULL,
			0x3168E6BBF4620522ULL,
			0x3571D59DB1DA2E48ULL,
			0x79B196C048BBFDAAULL}
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

	steps = 52;
	X1 = (curve25519_key_t){.key64 = {
		0x7398B5B34872BF60ULL,
		0xE1AC0CFA39AAC180ULL,
		0x8F6684B40D182A71ULL,
		0x5762F56D8CCE7E59ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7398B5B34872BF60ULL,
			0xE1AC0CFA39AAC180ULL,
			0x8F6684B40D182A71ULL,
			0x5762F56D8CCE7E59ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9634ED3B76265F18ULL,
			0x84C573B1126CB106ULL,
			0xD17877ADAC549CFDULL,
			0x5B82D364F9098106ULL}
		},
		.Z = {.key64 = {
			0xCBCE91C971079C39ULL,
			0x023328313A40736FULL,
			0x391BD3C6E70A24E5ULL,
			0x5A4E1C60E6F6BC46ULL}
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

	steps = 60;
	X1 = (curve25519_key_t){.key64 = {
		0x982B1E8912694398ULL,
		0xFC147972BA0BF6ADULL,
		0x3E2FB4A2D4322F4FULL,
		0x602F8894FA26AC90ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x982B1E8912694398ULL,
			0xFC147972BA0BF6ADULL,
			0x3E2FB4A2D4322F4FULL,
			0x602F8894FA26AC90ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC7B6F2E04D360167ULL,
			0x2137DEA3DD424C1FULL,
			0x1A8D9A472BF688BEULL,
			0x1EB206C747AFD496ULL}
		},
		.Z = {.key64 = {
			0x5F8942FC781CEBD3ULL,
			0xE4970C785460A9DBULL,
			0xEA782880079EF93BULL,
			0x6A8A19E52970B0A1ULL}
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

	steps = 47;
	X1 = (curve25519_key_t){.key64 = {
		0xA813E6D71107A258ULL,
		0x1682565D87716AABULL,
		0x9A819F85F78FA693ULL,
		0x4BC92856182A87D4ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA813E6D71107A258ULL,
			0x1682565D87716AABULL,
			0x9A819F85F78FA693ULL,
			0x4BC92856182A87D4ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB53C5D5C991F3338ULL,
			0xC92EA1F75515823FULL,
			0xBDD1C6B97C527AF4ULL,
			0x65E2E4E6C4A06CD5ULL}
		},
		.Z = {.key64 = {
			0xAF809A53AC02FFABULL,
			0xCBA0994A263FB686ULL,
			0x9607F8357DDD2B16ULL,
			0x3D5831BEEC8D3352ULL}
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

	steps = 29;
	X1 = (curve25519_key_t){.key64 = {
		0xB5E69218FA3E5D10ULL,
		0x227BD7F1EF5D4890ULL,
		0xF5A494A9A3D7F69CULL,
		0x5377592AA9E262BCULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB5E69218FA3E5D10ULL,
			0x227BD7F1EF5D4890ULL,
			0xF5A494A9A3D7F69CULL,
			0x5377592AA9E262BCULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x92E486268D3849BDULL,
			0x94BE1114479F8104ULL,
			0x2005831610B320F4ULL,
			0x4745DFB3736B0794ULL}
		},
		.Z = {.key64 = {
			0xFCD86D6E5DD36855ULL,
			0xBAC5AFD21AE12DE6ULL,
			0xDA626F2B6521D9C6ULL,
			0x4B413BF409E9F5E0ULL}
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

	steps = 49;
	X1 = (curve25519_key_t){.key64 = {
		0x81B354B126C6B038ULL,
		0xD1CD17516BC1010DULL,
		0x5BCC188C7035F792ULL,
		0x6982BE325EAA0FD0ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x81B354B126C6B038ULL,
			0xD1CD17516BC1010DULL,
			0x5BCC188C7035F792ULL,
			0x6982BE325EAA0FD0ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCF65677A703B0661ULL,
			0x68FA406FC04073BEULL,
			0x338E020A43E39B74ULL,
			0x23EA607CC39BFFB4ULL}
		},
		.Z = {.key64 = {
			0x29F7B224925582B0ULL,
			0x79EF934FF4067564ULL,
			0x1C4FCD335A00C9E8ULL,
			0x1B8339DE2DD15B19ULL}
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

	steps = 42;
	X1 = (curve25519_key_t){.key64 = {
		0xC299A1C801591BA0ULL,
		0xACFF63BD59F4B634ULL,
		0xBAE10B783B5750D0ULL,
		0x79AFF01F6DD142CAULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC299A1C801591BA0ULL,
			0xACFF63BD59F4B634ULL,
			0xBAE10B783B5750D0ULL,
			0x79AFF01F6DD142CAULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x644CEEAD86B69B3AULL,
			0xE78D4C7EB4222113ULL,
			0x49B065446349F1CBULL,
			0x1BF3E8016FD47AB7ULL}
		},
		.Z = {.key64 = {
			0x8AFC4F9BACC983DFULL,
			0xD1F4FC50792B2C00ULL,
			0x48984590C4C4DC3BULL,
			0x4CE50707629A268EULL}
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

	steps = 19;
	X1 = (curve25519_key_t){.key64 = {
		0xE82F31A097071C60ULL,
		0x8DC27107C51D28C7ULL,
		0x571A557149CDA786ULL,
		0x59FDBC728183F968ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE82F31A097071C60ULL,
			0x8DC27107C51D28C7ULL,
			0x571A557149CDA786ULL,
			0x59FDBC728183F968ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2A6B14CC8C3A3967ULL,
			0x8E9E1728A7E72F1EULL,
			0xCE8BC6DB1B99140CULL,
			0x43D7892139354A80ULL}
		},
		.Z = {.key64 = {
			0xF23113C2B5BEDB74ULL,
			0xAC48E700F815CECDULL,
			0xACA2D12D91D104FBULL,
			0x7F69A14B6A6C350CULL}
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

	steps = 24;
	X1 = (curve25519_key_t){.key64 = {
		0x0A0A212914C10EF8ULL,
		0x11B03ACEEAF11266ULL,
		0x625FB53B941489E9ULL,
		0x539E999FFD9F80F3ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0A0A212914C10EF8ULL,
			0x11B03ACEEAF11266ULL,
			0x625FB53B941489E9ULL,
			0x539E999FFD9F80F3ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE1CF5535BF654ECBULL,
			0x8E15483DA5BD007AULL,
			0x3E84A58439B1F4BEULL,
			0x7B21775D67194829ULL}
		},
		.Z = {.key64 = {
			0x6D181BB745396615ULL,
			0xBCF4C827B92498D6ULL,
			0x7AE3243A5A396678ULL,
			0x72F8395573D370FDULL}
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

	steps = 31;
	X1 = (curve25519_key_t){.key64 = {
		0x8AD5CB01E1527138ULL,
		0x258974811497B989ULL,
		0x72B75A2C78B3FB50ULL,
		0x586256E4BC01012AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8AD5CB01E1527138ULL,
			0x258974811497B989ULL,
			0x72B75A2C78B3FB50ULL,
			0x586256E4BC01012AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7AEFCD26D090A93BULL,
			0xC860F2E8F86CABB2ULL,
			0x010BE9A042061361ULL,
			0x568AEBEABC14D929ULL}
		},
		.Z = {.key64 = {
			0xA746726E6BD0086EULL,
			0x6AA90CF340AC3456ULL,
			0x568E288E6F681211ULL,
			0x75941853E831913CULL}
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

	steps = 12;
	X1 = (curve25519_key_t){.key64 = {
		0xFC722A4F710D3950ULL,
		0x8001D0F02C1B4B38ULL,
		0x8BA98E3E663F249AULL,
		0x43C4D0EC8801C2EAULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFC722A4F710D3950ULL,
			0x8001D0F02C1B4B38ULL,
			0x8BA98E3E663F249AULL,
			0x43C4D0EC8801C2EAULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x61394EA56EBD269FULL,
			0x6D481F14060AB0D2ULL,
			0x5C21DA14B9E7E216ULL,
			0x4D42D84E8DAE91D9ULL}
		},
		.Z = {.key64 = {
			0x8AFC3E40A88D3A6DULL,
			0x7E1C01971BE82F68ULL,
			0x98C367C1C74A6248ULL,
			0x50CD6123A9D79386ULL}
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

	steps = 35;
	X1 = (curve25519_key_t){.key64 = {
		0xC936C14F08F9EA00ULL,
		0xC4C5C69349E47023ULL,
		0xCA5686C071D9088CULL,
		0x47F96038EB233000ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC936C14F08F9EA00ULL,
			0xC4C5C69349E47023ULL,
			0xCA5686C071D9088CULL,
			0x47F96038EB233000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x15AA90996A49C6E1ULL,
			0xDC80D8717E8AFF61ULL,
			0x9A485444C0B68B83ULL,
			0x719CF8E92758B465ULL}
		},
		.Z = {.key64 = {
			0x297CDF9E6D862AA4ULL,
			0xB5721177F31137EBULL,
			0x0B9E81CE56240669ULL,
			0x1466A8CC9DBFD5BBULL}
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

	steps = 63;
	X1 = (curve25519_key_t){.key64 = {
		0x6E9AA54726B0E1F0ULL,
		0x894A5AFDB8F43816ULL,
		0xCE643E1E2ABB86B6ULL,
		0x71797AB2E6B3541EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6E9AA54726B0E1F0ULL,
			0x894A5AFDB8F43816ULL,
			0xCE643E1E2ABB86B6ULL,
			0x71797AB2E6B3541EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x999DDEF9C023BE37ULL,
			0x6E23C6E2C62CF3C6ULL,
			0x7830465637098502ULL,
			0x32424BB21F330700ULL}
		},
		.Z = {.key64 = {
			0xADD6FB754918F772ULL,
			0xBC094B3810B7DEC5ULL,
			0x84AC3536F35C3FA2ULL,
			0x55A299B32825F7EAULL}
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

	steps = 37;
	X1 = (curve25519_key_t){.key64 = {
		0x60256D7A7264F0F0ULL,
		0xAE405677107861F6ULL,
		0xDB2BAFC44C75926CULL,
		0x67738F90F4D3E7DFULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x60256D7A7264F0F0ULL,
			0xAE405677107861F6ULL,
			0xDB2BAFC44C75926CULL,
			0x67738F90F4D3E7DFULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE0467DAC4EF3806EULL,
			0xBDA1105CCAA881E0ULL,
			0x5F451E0FD42CA335ULL,
			0x45F6B6A34B7FE8BDULL}
		},
		.Z = {.key64 = {
			0x104016C11BCAEC55ULL,
			0x895087C926D807EFULL,
			0x23185DFD6E2C439AULL,
			0x60B543878E2E9C18ULL}
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

	steps = 41;
	X1 = (curve25519_key_t){.key64 = {
		0xF1978BA238F04E08ULL,
		0x60FDEBED47AEAB3FULL,
		0xCBA197A98D101114ULL,
		0x7085EA861021511CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF1978BA238F04E08ULL,
			0x60FDEBED47AEAB3FULL,
			0xCBA197A98D101114ULL,
			0x7085EA861021511CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x89F11755961E24F2ULL,
			0xEBEB89FF791561E7ULL,
			0xDAD68D0542408A73ULL,
			0x62267A72CEE4A541ULL}
		},
		.Z = {.key64 = {
			0xB2C09936E9AEE1F2ULL,
			0xA83B12F041B8C705ULL,
			0x2B15F797FB76DDCAULL,
			0x5C0030BC6CB93C58ULL}
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

	steps = 49;
	X1 = (curve25519_key_t){.key64 = {
		0xCE34DBC9BB5B5D60ULL,
		0xE46E2FFAE52BE0F7ULL,
		0x66B7D03658AF9386ULL,
		0x58C605445AFA7963ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCE34DBC9BB5B5D60ULL,
			0xE46E2FFAE52BE0F7ULL,
			0x66B7D03658AF9386ULL,
			0x58C605445AFA7963ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDA32F91C4922205CULL,
			0xD0DECB447F972ACFULL,
			0xF141F2AA28B4DF6AULL,
			0x04A8B4A933DF64B3ULL}
		},
		.Z = {.key64 = {
			0x58A20CB50D1F9098ULL,
			0xDBA55AFE582F0A3DULL,
			0x175181C1E76991B4ULL,
			0x6DEBD6AEFB2CF4E4ULL}
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

	steps = 42;
	X1 = (curve25519_key_t){.key64 = {
		0xEE4BDBF4C5F7FAF0ULL,
		0x3588F286CC4E46AAULL,
		0xE92D3D6A7E87ED55ULL,
		0x7774842E37CFD42CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEE4BDBF4C5F7FAF0ULL,
			0x3588F286CC4E46AAULL,
			0xE92D3D6A7E87ED55ULL,
			0x7774842E37CFD42CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0366B79DF4F91B65ULL,
			0x251349F31F30DDF0ULL,
			0x670D1DFE31F22CBAULL,
			0x6C53A035640F0BF7ULL}
		},
		.Z = {.key64 = {
			0x67D50DAB3300BDEEULL,
			0x1CD65FFFDE26C653ULL,
			0xFA9056F560B6918FULL,
			0x7F7299CE6A2D2333ULL}
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

	steps = 35;
	X1 = (curve25519_key_t){.key64 = {
		0xE4A443AEF80B1EE8ULL,
		0x4BC16920EF14E33EULL,
		0xCAC684834F01B58AULL,
		0x40F6E08D0FAB53D7ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE4A443AEF80B1EE8ULL,
			0x4BC16920EF14E33EULL,
			0xCAC684834F01B58AULL,
			0x40F6E08D0FAB53D7ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9E08066B34B362F1ULL,
			0x8D20AFC4F7D92EA4ULL,
			0x50DAD89F6FEFB78FULL,
			0x7C111DA53CAB9212ULL}
		},
		.Z = {.key64 = {
			0x3A0346999E767A05ULL,
			0x28613DD129292E57ULL,
			0x357E8C5D7C360A3FULL,
			0x708B061C3B85413BULL}
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

	steps = 4;
	X1 = (curve25519_key_t){.key64 = {
		0x0633CD12F4C87FD8ULL,
		0x746C03B8221A89D2ULL,
		0xE8E9878DE65BAF01ULL,
		0x5B0A98661C73261CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0633CD12F4C87FD8ULL,
			0x746C03B8221A89D2ULL,
			0xE8E9878DE65BAF01ULL,
			0x5B0A98661C73261CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEC77088CDFD6B349ULL,
			0x3BE424CD9DEE73EFULL,
			0xCB9BD71B7D3E451CULL,
			0x0F2B118B4CFC20E9ULL}
		},
		.Z = {.key64 = {
			0x29BC1B4E34ACC33CULL,
			0x43EF32773DDBFD5BULL,
			0xBF2AF99102BA2D0FULL,
			0x200F985979DB7D2CULL}
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

	steps = 45;
	X1 = (curve25519_key_t){.key64 = {
		0x4EC76B33772AC5D0ULL,
		0x59A0F91C5593A2D4ULL,
		0x8F62F26650194CABULL,
		0x4C67E736DF7E10F3ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4EC76B33772AC5D0ULL,
			0x59A0F91C5593A2D4ULL,
			0x8F62F26650194CABULL,
			0x4C67E736DF7E10F3ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x75E22322E2558C9FULL,
			0x70BD7F3A84FF31D1ULL,
			0x9CB726D6344A9850ULL,
			0x40EDC3FCEC7AB9A4ULL}
		},
		.Z = {.key64 = {
			0x85F7FB8012FEF1C8ULL,
			0x0CEAEC402F5D44C8ULL,
			0xFA2CBA947F0B07E1ULL,
			0x71BF3BC8A2E60906ULL}
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

	steps = 57;
	X1 = (curve25519_key_t){.key64 = {
		0x53C6232831219478ULL,
		0x58B4679C4AAC856CULL,
		0x3D52B63BD28A90ABULL,
		0x5B49D4E3B2E6D7A3ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x53C6232831219478ULL,
			0x58B4679C4AAC856CULL,
			0x3D52B63BD28A90ABULL,
			0x5B49D4E3B2E6D7A3ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD04B5A2FD0FA5617ULL,
			0x833E9608AB7241B6ULL,
			0x1F251D32BE931F3AULL,
			0x4BD8134D9DD14298ULL}
		},
		.Z = {.key64 = {
			0x7E95A1A0C2CE4B66ULL,
			0x3E064B788493BCD3ULL,
			0xC47BEFDEBCE2D993ULL,
			0x092AA3A13685A52FULL}
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

	steps = 59;
	X1 = (curve25519_key_t){.key64 = {
		0x1A6B39347433AD88ULL,
		0x22C630C60DE81E9BULL,
		0x716C52C8030B3A0DULL,
		0x64BFC8AE2D06E71DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1A6B39347433AD88ULL,
			0x22C630C60DE81E9BULL,
			0x716C52C8030B3A0DULL,
			0x64BFC8AE2D06E71DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9D077B85FBE078C0ULL,
			0xEAD9EC64F2670C73ULL,
			0x364B0D46B916274BULL,
			0x3C683F87FECB9FA8ULL}
		},
		.Z = {.key64 = {
			0xD5706A4953E86F52ULL,
			0x7389698158E56754ULL,
			0xEAACC6CDA6BF7E04ULL,
			0x0CE8D02B92184880ULL}
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

	steps = 7;
	X1 = (curve25519_key_t){.key64 = {
		0xF4D6B95F9C6C20B0ULL,
		0x01D8388F806C1F2DULL,
		0x642679E2EE5C9477ULL,
		0x64B1A3915F0C9FB5ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF4D6B95F9C6C20B0ULL,
			0x01D8388F806C1F2DULL,
			0x642679E2EE5C9477ULL,
			0x64B1A3915F0C9FB5ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCA64C7CCFCDC002BULL,
			0xB73A17CA924064B6ULL,
			0xC2D5EC04F0FCB737ULL,
			0x7FFAC36310BD792AULL}
		},
		.Z = {.key64 = {
			0x638D41F9C0932062ULL,
			0x407CFA2BE1DB4363ULL,
			0xA3D02592FFDF95A6ULL,
			0x6F792474E70F0313ULL}
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

	steps = 24;
	X1 = (curve25519_key_t){.key64 = {
		0xC9B0E4A853439740ULL,
		0xBFC2E43C5C8DDC50ULL,
		0xBBDBCE4A44E6384BULL,
		0x6AA1ED48AEB6A1BFULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC9B0E4A853439740ULL,
			0xBFC2E43C5C8DDC50ULL,
			0xBBDBCE4A44E6384BULL,
			0x6AA1ED48AEB6A1BFULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x62202214CB0748BEULL,
			0xA5AC340B3412BCFBULL,
			0x3B92D3EBD4518778ULL,
			0x2D222CCDA14C826DULL}
		},
		.Z = {.key64 = {
			0xC013A15433A07B0EULL,
			0x7D9F0DB9EEA0CA61ULL,
			0xCA265A3C5A7E2C47ULL,
			0x1E975B53EA2154BFULL}
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

	steps = 48;
	X1 = (curve25519_key_t){.key64 = {
		0x03847599499B0CE0ULL,
		0xA9982D9D6C398A56ULL,
		0xA45288B1A501A3C0ULL,
		0x5E1B1CCE450D2EABULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x03847599499B0CE0ULL,
			0xA9982D9D6C398A56ULL,
			0xA45288B1A501A3C0ULL,
			0x5E1B1CCE450D2EABULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4258A1016F47D200ULL,
			0x332EC5A7045ACF78ULL,
			0x09902677FF5A1AA0ULL,
			0x3D05965C60E44A0FULL}
		},
		.Z = {.key64 = {
			0x3CC774A3783999AEULL,
			0xF85EB68EA06B436DULL,
			0x529818E0692FFC75ULL,
			0x58AA8139860BC59EULL}
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

	steps = 32;
	X1 = (curve25519_key_t){.key64 = {
		0x26EDFDAAE780A790ULL,
		0x82FD832EF96F18A0ULL,
		0x3B60A68E380C00CAULL,
		0x5EF4854F0B18F76CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x26EDFDAAE780A790ULL,
			0x82FD832EF96F18A0ULL,
			0x3B60A68E380C00CAULL,
			0x5EF4854F0B18F76CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x50C86963C0BD1989ULL,
			0x553A2DF9E1E30CA5ULL,
			0x46B52B7A43C012B2ULL,
			0x60634D92DD0123E9ULL}
		},
		.Z = {.key64 = {
			0xE01EC0A36BAC59E3ULL,
			0xEF0439EEEDA8371DULL,
			0xEFB3E90D1C34D6F5ULL,
			0x7CCDE98A558D119CULL}
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

	steps = 32;
	X1 = (curve25519_key_t){.key64 = {
		0x6AA5ADDD74747B98ULL,
		0x3FA7B907227D6053ULL,
		0x74BC5E2D658526C5ULL,
		0x4F9F15293A725899ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6AA5ADDD74747B98ULL,
			0x3FA7B907227D6053ULL,
			0x74BC5E2D658526C5ULL,
			0x4F9F15293A725899ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5E818999ABA74CAEULL,
			0xFF061CF3D3E25808ULL,
			0x526C9BC0D7330AEDULL,
			0x34573D785232A64DULL}
		},
		.Z = {.key64 = {
			0xE4BF806DA3543890ULL,
			0xE7B72E85C72AE34BULL,
			0x608E37472F0F60A2ULL,
			0x40DA7BE31F0A4AA5ULL}
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

	steps = 10;
	X1 = (curve25519_key_t){.key64 = {
		0xEB7601B3F84766C8ULL,
		0xC75E75D7B1D03DD1ULL,
		0x405CA2E0DC16613BULL,
		0x50946DCE0004D975ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEB7601B3F84766C8ULL,
			0xC75E75D7B1D03DD1ULL,
			0x405CA2E0DC16613BULL,
			0x50946DCE0004D975ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF6607A8611ED30F1ULL,
			0xEB08B17AC993CC9DULL,
			0xD5FFD29BD39CA637ULL,
			0x795BD3BAA2A3E6FCULL}
		},
		.Z = {.key64 = {
			0xEDB6CD877B9EBFEBULL,
			0x9C6C630B99406DA0ULL,
			0xCE298ABD6F5BCA55ULL,
			0x0E40625E9FC1C57DULL}
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

	steps = 60;
	X1 = (curve25519_key_t){.key64 = {
		0xF93F6BBE2734C720ULL,
		0x60A40DD614042FECULL,
		0xF837F4B27A38E675ULL,
		0x4A0EEDA919BC243FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF93F6BBE2734C720ULL,
			0x60A40DD614042FECULL,
			0xF837F4B27A38E675ULL,
			0x4A0EEDA919BC243FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7CC4AB8591367669ULL,
			0x17A3045A996AD7F8ULL,
			0x7486E71502421665ULL,
			0x34A096966BA2E83FULL}
		},
		.Z = {.key64 = {
			0xBDB5954E6B19EED3ULL,
			0x7EAC5AB74485E7B2ULL,
			0x14BF15E28C245016ULL,
			0x1F4A9320DB1D1DB7ULL}
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

	steps = 62;
	X1 = (curve25519_key_t){.key64 = {
		0x9540F1556B9B2E58ULL,
		0x487C0BD447E091E6ULL,
		0xAB45034304512A38ULL,
		0x5AA96F7CD2FB5526ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9540F1556B9B2E58ULL,
			0x487C0BD447E091E6ULL,
			0xAB45034304512A38ULL,
			0x5AA96F7CD2FB5526ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDDC6BA01F887B621ULL,
			0x89425B47822A34A0ULL,
			0x44A52B95926022B8ULL,
			0x595CDA7024856168ULL}
		},
		.Z = {.key64 = {
			0x1CA8CCC6E70F4EC7ULL,
			0xA803EC508F4631F7ULL,
			0x84AECD7D3FA74536ULL,
			0x75E400A2884A201DULL}
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

	steps = 22;
	X1 = (curve25519_key_t){.key64 = {
		0xC0F9DDA41478A8D8ULL,
		0x1FE0749722B2BD93ULL,
		0x3381CCBE4E76D41AULL,
		0x49524340D5515057ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC0F9DDA41478A8D8ULL,
			0x1FE0749722B2BD93ULL,
			0x3381CCBE4E76D41AULL,
			0x49524340D5515057ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x52CC704B79A3CD50ULL,
			0x1EE5A0BC7E4ABC89ULL,
			0x86F2B35EE6964B58ULL,
			0x157714212E9BC865ULL}
		},
		.Z = {.key64 = {
			0xE78C95707944F9E0ULL,
			0x8DFAB0D6E79E85C5ULL,
			0xE84D956DBDBAF20CULL,
			0x2D907E1241CEF7B0ULL}
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

	steps = 53;
	X1 = (curve25519_key_t){.key64 = {
		0x889FE7F38D54AC80ULL,
		0x0297B1763AEF95BBULL,
		0xAD99484D9DEFB3E8ULL,
		0x5762673B4AF9887CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x889FE7F38D54AC80ULL,
			0x0297B1763AEF95BBULL,
			0xAD99484D9DEFB3E8ULL,
			0x5762673B4AF9887CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6FF622D57E004EABULL,
			0x8D3228D994F3D906ULL,
			0xC125B8E835039F29ULL,
			0x6746CE49CB01C01BULL}
		},
		.Z = {.key64 = {
			0xAA217A5DBFDAF932ULL,
			0x0382982764342706ULL,
			0x2142C75FD0BC71EEULL,
			0x3B9CC014B3695CF7ULL}
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

	steps = 8;
	X1 = (curve25519_key_t){.key64 = {
		0xC2586BA0AC142500ULL,
		0x8FCB3EAD1D195A45ULL,
		0xA927EB8C0B9AD447ULL,
		0x6FB02E58D5394794ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC2586BA0AC142500ULL,
			0x8FCB3EAD1D195A45ULL,
			0xA927EB8C0B9AD447ULL,
			0x6FB02E58D5394794ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA9D1B142165D91E1ULL,
			0xC416C704484706AAULL,
			0x2D220A164387F997ULL,
			0x2A62DA43989D4FC8ULL}
		},
		.Z = {.key64 = {
			0xD18083638B594D09ULL,
			0xF44237559FFE79EBULL,
			0x2CFFA4C653E76060ULL,
			0x7794D5ACA1562DE5ULL}
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

	steps = 61;
	X1 = (curve25519_key_t){.key64 = {
		0xB0E79A29E3F28650ULL,
		0xDEBE631991A99C67ULL,
		0xFE1BD1BDDE4D3C26ULL,
		0x60F4D83FC9083A5AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB0E79A29E3F28650ULL,
			0xDEBE631991A99C67ULL,
			0xFE1BD1BDDE4D3C26ULL,
			0x60F4D83FC9083A5AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4F994D45F05D3D3CULL,
			0x3573030C7D0E5152ULL,
			0x2485862B0C61D917ULL,
			0x31DC2072ECA9C11BULL}
		},
		.Z = {.key64 = {
			0x480D10C816AF2FCEULL,
			0x94247037F6A94D29ULL,
			0xECEBC0D632BE98FCULL,
			0x64C37E498442F548ULL}
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

	steps = 47;
	X1 = (curve25519_key_t){.key64 = {
		0x4C6D70E07D9FE968ULL,
		0x5727380CA32CFBE0ULL,
		0x138B55748F7F6FB2ULL,
		0x7EE2F07532AB3253ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4C6D70E07D9FE968ULL,
			0x5727380CA32CFBE0ULL,
			0x138B55748F7F6FB2ULL,
			0x7EE2F07532AB3253ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x83C46EB38E01E39DULL,
			0xEA577300CF17C855ULL,
			0xEBDD6BDBA68C5E89ULL,
			0x34B1FE2CC13BE40FULL}
		},
		.Z = {.key64 = {
			0xC677B2BFEEA0C6FEULL,
			0x416B47A62D90CA7CULL,
			0x15B0BF932B0327DCULL,
			0x5B6AB6A9FA4F7E17ULL}
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

	steps = 32;
	X1 = (curve25519_key_t){.key64 = {
		0xDAD7D412F3F89DD8ULL,
		0xE284FBC5127570E4ULL,
		0x330A43D7CA08753EULL,
		0x6D3F9D3C29DAFAEDULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDAD7D412F3F89DD8ULL,
			0xE284FBC5127570E4ULL,
			0x330A43D7CA08753EULL,
			0x6D3F9D3C29DAFAEDULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1C20E15588D66AAFULL,
			0x8E02FCC37DA0004AULL,
			0xCAF0C7AD14EDF2AFULL,
			0x6C486EB37CC38E57ULL}
		},
		.Z = {.key64 = {
			0x8B3521DA9349BA16ULL,
			0x6983182127B06EB6ULL,
			0xEFAA2A1A1C1AE00CULL,
			0x1E36F3917D5CCBF6ULL}
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

	steps = 40;
	X1 = (curve25519_key_t){.key64 = {
		0x86236D7592BF16F0ULL,
		0x4BD507F82FDDC801ULL,
		0x56836EB23E39DE09ULL,
		0x6C687FEE23E787ABULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x86236D7592BF16F0ULL,
			0x4BD507F82FDDC801ULL,
			0x56836EB23E39DE09ULL,
			0x6C687FEE23E787ABULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEC8544448977F363ULL,
			0xF4723685585DBFC3ULL,
			0xD42031EA3EC1D8D5ULL,
			0x6B29FF19009632F2ULL}
		},
		.Z = {.key64 = {
			0x4C0C0195ACE0B1A9ULL,
			0x103527E6E7DC7A7FULL,
			0xA7B547F7710A4317ULL,
			0x6C81BF04EC272A66ULL}
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
		0x7812B23C42D92900ULL,
		0x288C464F0775A684ULL,
		0xE360028E90106DEEULL,
		0x50580EF6D2574ABBULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7812B23C42D92900ULL,
			0x288C464F0775A684ULL,
			0xE360028E90106DEEULL,
			0x50580EF6D2574ABBULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x20F1C06FAF17FD2AULL,
			0x9FDCB503B0AE6E9DULL,
			0xB49CF23E71AD97F6ULL,
			0x77BA6FFE29967FC6ULL}
		},
		.Z = {.key64 = {
			0x70A26304C4FDD67DULL,
			0xDACBFF369AADB11CULL,
			0xD521806C820DF320ULL,
			0x320C7B7F76714795ULL}
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

	steps = 36;
	X1 = (curve25519_key_t){.key64 = {
		0x04361C0864FE4118ULL,
		0xF397DF83F4BE6159ULL,
		0x997554D27D920999ULL,
		0x5C1291554D187686ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x04361C0864FE4118ULL,
			0xF397DF83F4BE6159ULL,
			0x997554D27D920999ULL,
			0x5C1291554D187686ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0BCBDF1767DAC0D9ULL,
			0xF68032821993075AULL,
			0x43F503DD51C568D1ULL,
			0x35D0EDBFDACD8D51ULL}
		},
		.Z = {.key64 = {
			0x7BA619CB4FE47095ULL,
			0xE105C04AFC1378E9ULL,
			0x3E5068DD0FAB99FCULL,
			0x453C0B8F07C27A97ULL}
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

	steps = 50;
	X1 = (curve25519_key_t){.key64 = {
		0x08E76EC68724F418ULL,
		0x508249983D3CD13BULL,
		0x4F009EACB8196946ULL,
		0x4228FF6D03E07D4BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x08E76EC68724F418ULL,
			0x508249983D3CD13BULL,
			0x4F009EACB8196946ULL,
			0x4228FF6D03E07D4BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6DBA416839805B16ULL,
			0xA517CE1B098C3BC2ULL,
			0x1F09861B7B9EF684ULL,
			0x5B10406217592D17ULL}
		},
		.Z = {.key64 = {
			0x2658544883F20A32ULL,
			0x3B477D66955C6C3BULL,
			0xED45504C8ACB378EULL,
			0x30C65B37E1119DC9ULL}
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
		0x7D547E58B162ED20ULL,
		0x6DA9821A87BFAECEULL,
		0x453FA71E24CF5CC6ULL,
		0x687E39A15C5DBE0AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7D547E58B162ED20ULL,
			0x6DA9821A87BFAECEULL,
			0x453FA71E24CF5CC6ULL,
			0x687E39A15C5DBE0AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x697A4993A35354EAULL,
			0x06C6D409A46B00CAULL,
			0x9ED56BFE7543ABA3ULL,
			0x5AD31F5D840C7702ULL}
		},
		.Z = {.key64 = {
			0xFA3F2F2CB298267AULL,
			0x91A1E10375CE3EDFULL,
			0x79237784D449D2FAULL,
			0x48EAE4D5B6A8CB03ULL}
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

	steps = 17;
	X1 = (curve25519_key_t){.key64 = {
		0xDE397420F9760318ULL,
		0xE6F45B464766835EULL,
		0x54395E2A3238DDD7ULL,
		0x5C949D41DFBCDD5DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDE397420F9760318ULL,
			0xE6F45B464766835EULL,
			0x54395E2A3238DDD7ULL,
			0x5C949D41DFBCDD5DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x02F3E5121C9206EEULL,
			0x63DC85D3FC4C529CULL,
			0xE3672991B5AF962AULL,
			0x2E3AB6F36507BD5BULL}
		},
		.Z = {.key64 = {
			0x2C4AB44FEEFA9020ULL,
			0xBCBFDFB8E6690B3AULL,
			0x1693DE4BEC53B591ULL,
			0x101BA5A012805468ULL}
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
		0x39894367BEB08A18ULL,
		0xF17EB3B438B633D3ULL,
		0xA34DAA1117D8D5CEULL,
		0x79F5FFAB5F4E69C5ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x39894367BEB08A18ULL,
			0xF17EB3B438B633D3ULL,
			0xA34DAA1117D8D5CEULL,
			0x79F5FFAB5F4E69C5ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC920D6D53D56E87FULL,
			0x4885F683035C3AEDULL,
			0xEFD43ED5F127CED2ULL,
			0x1658CD5A602CA94CULL}
		},
		.Z = {.key64 = {
			0xC408474825811C1EULL,
			0x705221216DCD36D2ULL,
			0x3318D368302B0962ULL,
			0x4DF8C1BE6AAE524BULL}
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

	steps = 8;
	X1 = (curve25519_key_t){.key64 = {
		0xCB1247937FF1DC78ULL,
		0x5FE46B4039F48B9AULL,
		0x712706F011DE01C5ULL,
		0x6F06988B9690DB4FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCB1247937FF1DC78ULL,
			0x5FE46B4039F48B9AULL,
			0x712706F011DE01C5ULL,
			0x6F06988B9690DB4FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC3B19C86169E78D2ULL,
			0x3906074CEC320BB0ULL,
			0xAD6ACE58E50CD787ULL,
			0x0D4D0F2A72250EBBULL}
		},
		.Z = {.key64 = {
			0x899BBAAD2F42A3AAULL,
			0x48306FB83BA4FF40ULL,
			0xDC151A4D05F77E1EULL,
			0x2474663104BF9703ULL}
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
		0xB66188373FC11A90ULL,
		0x159EE82DDD1C4FA1ULL,
		0x81C8DB454B0DC7E0ULL,
		0x6BCE490F1877F9BEULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB66188373FC11A90ULL,
			0x159EE82DDD1C4FA1ULL,
			0x81C8DB454B0DC7E0ULL,
			0x6BCE490F1877F9BEULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7B73A7CD2361C4D0ULL,
			0xC63AE81CD28CE869ULL,
			0x3F4D7B18B23246EBULL,
			0x2DE7AF1B0BD89617ULL}
		},
		.Z = {.key64 = {
			0x28D49A9C02BC605DULL,
			0xB5D11BFF00EE1C50ULL,
			0x4D598615B4A0D299ULL,
			0x73BA762036D375F9ULL}
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

	steps = 63;
	X1 = (curve25519_key_t){.key64 = {
		0x7C667F518E242070ULL,
		0xE385CB396BD33E85ULL,
		0xA527ADD5F1086B91ULL,
		0x43DD75F7C6E4EB81ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7C667F518E242070ULL,
			0xE385CB396BD33E85ULL,
			0xA527ADD5F1086B91ULL,
			0x43DD75F7C6E4EB81ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF94595347BA28D8EULL,
			0x908A7472B2FA759AULL,
			0xDEDBB022DC906288ULL,
			0x6D05D7E53DF28CE4ULL}
		},
		.Z = {.key64 = {
			0x5BCDD6CB20713FA0ULL,
			0x0DBD226F432F9538ULL,
			0xD7A62B3BC15FBD52ULL,
			0x077CCF1DA57480B9ULL}
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

	steps = 62;
	X1 = (curve25519_key_t){.key64 = {
		0x6DE9C403E7B5CF88ULL,
		0xDBD0D530E6931C8DULL,
		0x588AA01BF37084AAULL,
		0x45D8BE1AB43459C5ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6DE9C403E7B5CF88ULL,
			0xDBD0D530E6931C8DULL,
			0x588AA01BF37084AAULL,
			0x45D8BE1AB43459C5ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x90CFD4C8214AD5D5ULL,
			0xA2040559578320B6ULL,
			0x210D2521290CF763ULL,
			0x1E9A4B5CAC52778AULL}
		},
		.Z = {.key64 = {
			0x831142FE8B759CB9ULL,
			0x0BCED3F3DFD5AC7BULL,
			0x16CEEEEE493359B8ULL,
			0x1F29991A8F564862ULL}
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

	steps = 49;
	X1 = (curve25519_key_t){.key64 = {
		0x90A1241790B6CEF0ULL,
		0xC242C67083A7659CULL,
		0x82802064B067EC85ULL,
		0x7E1995C5C61F32C8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x90A1241790B6CEF0ULL,
			0xC242C67083A7659CULL,
			0x82802064B067EC85ULL,
			0x7E1995C5C61F32C8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x61770FF85F1BF54DULL,
			0xBEDA5A76E3DED00EULL,
			0x839693E0BC56D37FULL,
			0x298AA864EE204A81ULL}
		},
		.Z = {.key64 = {
			0xED34F05A621211B0ULL,
			0xC54BBFDA140CE976ULL,
			0xAE0E589D13F3A5F1ULL,
			0x17B980FF537E2BC5ULL}
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

	steps = 58;
	X1 = (curve25519_key_t){.key64 = {
		0x11CBD0C59C6597C0ULL,
		0x99CB1ED1209D2A8AULL,
		0x612EFA82C961F4CEULL,
		0x43F45161694E7E5BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x11CBD0C59C6597C0ULL,
			0x99CB1ED1209D2A8AULL,
			0x612EFA82C961F4CEULL,
			0x43F45161694E7E5BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB4143E9A1D5B37B9ULL,
			0xFC088872A481AE2BULL,
			0x9123EBB015B7DA84ULL,
			0x472DFA9A2FC08EAEULL}
		},
		.Z = {.key64 = {
			0xF14BCEB6F048A908ULL,
			0x5C6E45072FF1AADCULL,
			0xA25FBB9E0C65361AULL,
			0x5A74DE2C24AB0782ULL}
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

	steps = 39;
	X1 = (curve25519_key_t){.key64 = {
		0x640521D77FB046C0ULL,
		0x661057D29C9DD965ULL,
		0xCC4B4E9177019FBDULL,
		0x74ABE5870A219986ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x640521D77FB046C0ULL,
			0x661057D29C9DD965ULL,
			0xCC4B4E9177019FBDULL,
			0x74ABE5870A219986ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x19F691D59324DD96ULL,
			0x6C541033E9C2258BULL,
			0xC0FDDDF7AEDF54E1ULL,
			0x0B913D449429B3BDULL}
		},
		.Z = {.key64 = {
			0x50EB104D5F7049E4ULL,
			0xEC6C22CC59BD92D4ULL,
			0x292919DBB00A1D28ULL,
			0x5842695C6D815B08ULL}
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

	steps = 64;
	X1 = (curve25519_key_t){.key64 = {
		0xC7835897D8CB7718ULL,
		0x5C7659D2F65EC60AULL,
		0x962BBF3841C08C2FULL,
		0x41E439062C067402ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC7835897D8CB7718ULL,
			0x5C7659D2F65EC60AULL,
			0x962BBF3841C08C2FULL,
			0x41E439062C067402ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC94E201B79593C70ULL,
			0xCE15AED33574383EULL,
			0x3FE4E5D11576EFDBULL,
			0x17723EBB50291A88ULL}
		},
		.Z = {.key64 = {
			0xF4ADBE6A04BEE090ULL,
			0x7FD4EBF7F294995EULL,
			0x6E15D60CA98E89A4ULL,
			0x5B74FB47DAC3EBFEULL}
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

	steps = 29;
	X1 = (curve25519_key_t){.key64 = {
		0x91092096F0C34ED8ULL,
		0x0C538A6BA5047757ULL,
		0x8FF1278D50A7C7DCULL,
		0x680CA8917F25ACACULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x91092096F0C34ED8ULL,
			0x0C538A6BA5047757ULL,
			0x8FF1278D50A7C7DCULL,
			0x680CA8917F25ACACULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA5CC0DD12B2D37B4ULL,
			0xE64A093F897EE805ULL,
			0x4D3207791E8D047FULL,
			0x2ED8AA43CB010E74ULL}
		},
		.Z = {.key64 = {
			0xEF0C4EF86129EA40ULL,
			0xF57364CF958A2799ULL,
			0x8180616A6F148651ULL,
			0x0E94B7FE0816F3EDULL}
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

	steps = 7;
	X1 = (curve25519_key_t){.key64 = {
		0x8B2C0845D1C35790ULL,
		0x6B60BF985C1874DAULL,
		0x3AD66C999A321FD8ULL,
		0x6F8CF35FC42BC70BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8B2C0845D1C35790ULL,
			0x6B60BF985C1874DAULL,
			0x3AD66C999A321FD8ULL,
			0x6F8CF35FC42BC70BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEA1E78188639E558ULL,
			0xB23AE4ADEA8957EBULL,
			0x1821AB570140B7F2ULL,
			0x44549B4608E60741ULL}
		},
		.Z = {.key64 = {
			0xE0C9F68BF441B88EULL,
			0x3DC3BCE3D64B17FEULL,
			0x6B95D8AA9E55018AULL,
			0x4EDA6AD3DED9F0D7ULL}
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

	steps = 53;
	X1 = (curve25519_key_t){.key64 = {
		0x9F611691319BC208ULL,
		0x2629A6F42318602BULL,
		0xC966A06765E57DC3ULL,
		0x65248A2866014A5DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9F611691319BC208ULL,
			0x2629A6F42318602BULL,
			0xC966A06765E57DC3ULL,
			0x65248A2866014A5DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0056937C29D29163ULL,
			0x72AC75BF3D02DF07ULL,
			0x6E67E6BE34CE5D42ULL,
			0x46AE2C20E3362234ULL}
		},
		.Z = {.key64 = {
			0x2A2817352B92B7FCULL,
			0x06291CAAC5796442ULL,
			0x6BBCA8782D5C1997ULL,
			0x6F028A4D8C6F5C94ULL}
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

	steps = 44;
	X1 = (curve25519_key_t){.key64 = {
		0xAA4B89F3A915B868ULL,
		0x6569EA37E06A7883ULL,
		0x1C15EF326734184EULL,
		0x5CF3DC4E2A09A149ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAA4B89F3A915B868ULL,
			0x6569EA37E06A7883ULL,
			0x1C15EF326734184EULL,
			0x5CF3DC4E2A09A149ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x737497B0697E4813ULL,
			0xFA1E3FCD746EAE82ULL,
			0x887AED670C977ABEULL,
			0x0D58E89CD60078F6ULL}
		},
		.Z = {.key64 = {
			0x9EB651F0CB193504ULL,
			0x39962B8085DF1C0EULL,
			0x847096167A34BB9BULL,
			0x7B52F6D943B32CEFULL}
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

	steps = 3;
	X1 = (curve25519_key_t){.key64 = {
		0xBDF5533764868920ULL,
		0x404ECBE1D99A3C68ULL,
		0x9EBE268C84163802ULL,
		0x4D18724CACE49690ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBDF5533764868920ULL,
			0x404ECBE1D99A3C68ULL,
			0x9EBE268C84163802ULL,
			0x4D18724CACE49690ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x75B5FA8E3E9442EEULL,
			0xDA6FE655D0C70DFFULL,
			0x00B1665CEDDA74B3ULL,
			0x2F517D097B4234C8ULL}
		},
		.Z = {.key64 = {
			0x7A45547969461341ULL,
			0x6D729809E85CBAF0ULL,
			0x496C7E5D0DF95099ULL,
			0x7F7D994CD4FF0B81ULL}
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

	steps = 16;
	X1 = (curve25519_key_t){.key64 = {
		0x7FC76FE307081EE0ULL,
		0xBFD013CAE79DE33FULL,
		0x747925B7A558D9C1ULL,
		0x6C13D4B3A17D8895ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7FC76FE307081EE0ULL,
			0xBFD013CAE79DE33FULL,
			0x747925B7A558D9C1ULL,
			0x6C13D4B3A17D8895ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE53B7D93BE31AF01ULL,
			0xC365612704E6368AULL,
			0x1658F713D3706848ULL,
			0x1980CFEA509BDBF4ULL}
		},
		.Z = {.key64 = {
			0x0B4685F4B6EAFB19ULL,
			0x9DC57EC7FD70AA78ULL,
			0x2ABB2227BCA8E9A8ULL,
			0x62718DAA2AE3D5AAULL}
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

	steps = 49;
	X1 = (curve25519_key_t){.key64 = {
		0xB5BFC459228E2678ULL,
		0x51483D64B6A9C5B8ULL,
		0x9D50EE33AFF0FDE9ULL,
		0x7675C0B9BA1DF690ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB5BFC459228E2678ULL,
			0x51483D64B6A9C5B8ULL,
			0x9D50EE33AFF0FDE9ULL,
			0x7675C0B9BA1DF690ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE766D21FD315E6CEULL,
			0xE751306C6CA09077ULL,
			0x9E37C625A40AA43DULL,
			0x1E846E862BE0AAADULL}
		},
		.Z = {.key64 = {
			0x734DA4F6F19B1D23ULL,
			0xD41AE53BB9C1FF59ULL,
			0x73CA6B56BE18A0C0ULL,
			0x1B3F59D586D31A7EULL}
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

	steps = 47;
	X1 = (curve25519_key_t){.key64 = {
		0xF44E96E69142BBE0ULL,
		0xC505019A4CFDF351ULL,
		0x3FF7CAAE8878F97AULL,
		0x4778E95C665E9E22ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF44E96E69142BBE0ULL,
			0xC505019A4CFDF351ULL,
			0x3FF7CAAE8878F97AULL,
			0x4778E95C665E9E22ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA0F2460F28F15346ULL,
			0xF94CA41BDE71E09BULL,
			0xAB529042D4F68CAEULL,
			0x2C3FD8D8219116A5ULL}
		},
		.Z = {.key64 = {
			0xFEDA105C0636B592ULL,
			0x1401CC9A02BC32E5ULL,
			0x25EC351AAFA8C3C3ULL,
			0x5785E9A595D7F340ULL}
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

	steps = 61;
	X1 = (curve25519_key_t){.key64 = {
		0x6AE874F377067888ULL,
		0xF2BFDA30FE628A0EULL,
		0xCD18714EF40FC3A4ULL,
		0x5C7E931C92DF8B62ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6AE874F377067888ULL,
			0xF2BFDA30FE628A0EULL,
			0xCD18714EF40FC3A4ULL,
			0x5C7E931C92DF8B62ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x61DDF4815E75F0B0ULL,
			0x7CB088746E3CAE41ULL,
			0xDB8DDC2BFC71CD65ULL,
			0x4FC0BCBC1377B8FDULL}
		},
		.Z = {.key64 = {
			0x3540067E96122D94ULL,
			0x24C8D780EED14176ULL,
			0x355C935C10EBD434ULL,
			0x6B54FD0D94833CF4ULL}
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

	steps = 36;
	X1 = (curve25519_key_t){.key64 = {
		0x55C036A9BCA49090ULL,
		0xF8339565CED27E37ULL,
		0xB3FA5CF06FA84FA5ULL,
		0x5E4DF31329DA3824ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x55C036A9BCA49090ULL,
			0xF8339565CED27E37ULL,
			0xB3FA5CF06FA84FA5ULL,
			0x5E4DF31329DA3824ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1F42A830BC5D7871ULL,
			0x88912BE2085BCF5FULL,
			0xEB4CF0A5A0996854ULL,
			0x19D4C41D887906EDULL}
		},
		.Z = {.key64 = {
			0x52DFE23DC4C23F42ULL,
			0x0C4608CFAA9097EBULL,
			0x2488A51F16112E21ULL,
			0x4FB381B8D4F7CA66ULL}
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

	steps = 49;
	X1 = (curve25519_key_t){.key64 = {
		0x63A51BB1153C68C8ULL,
		0x825C78E477F1A7EAULL,
		0x1A2657ED2EC4C132ULL,
		0x74CAF6343B8E157EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x63A51BB1153C68C8ULL,
			0x825C78E477F1A7EAULL,
			0x1A2657ED2EC4C132ULL,
			0x74CAF6343B8E157EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBA3672E02AF40DA4ULL,
			0xE77AAAD01A2050ACULL,
			0x3BCF08B5F803423DULL,
			0x04B7551CC35323E7ULL}
		},
		.Z = {.key64 = {
			0xB89211934B370257ULL,
			0xA0460F7664C5984EULL,
			0x70119E0402CDF830ULL,
			0x1A884E0CBA816DB4ULL}
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

	steps = 20;
	X1 = (curve25519_key_t){.key64 = {
		0x14C98F2C75A974D8ULL,
		0xE8186557DBC562DFULL,
		0xFEDCB4E429AA1FE4ULL,
		0x40DDEF9B8805D65CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x14C98F2C75A974D8ULL,
			0xE8186557DBC562DFULL,
			0xFEDCB4E429AA1FE4ULL,
			0x40DDEF9B8805D65CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDE7D3E39A7B95BC2ULL,
			0x8CECA2941652CEBBULL,
			0x170E0D00B9446D5DULL,
			0x30560069B1701022ULL}
		},
		.Z = {.key64 = {
			0xF8E2AF009058F543ULL,
			0xAF110D23D4A97BC3ULL,
			0x9F7D2F66B24B292DULL,
			0x71D79FCFE74537D0ULL}
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

	steps = 9;
	X1 = (curve25519_key_t){.key64 = {
		0x8C0F6A6F3DF71688ULL,
		0xF4B153568C996635ULL,
		0x736D9B5CAF64A5A1ULL,
		0x4740267FEF3B5AADULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8C0F6A6F3DF71688ULL,
			0xF4B153568C996635ULL,
			0x736D9B5CAF64A5A1ULL,
			0x4740267FEF3B5AADULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x615557E34E81A02EULL,
			0x40A0DD938FB6E894ULL,
			0xBAE3D24A82C481A8ULL,
			0x1717ED65EA0242B8ULL}
		},
		.Z = {.key64 = {
			0x82BE019420B9976BULL,
			0x76831DC31306CFDAULL,
			0x5EE5862DB667BDB1ULL,
			0x14472FB0AC92DEC2ULL}
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

	steps = 41;
	X1 = (curve25519_key_t){.key64 = {
		0x3CBFA3D76B96A058ULL,
		0x938ACF1F94CB6E41ULL,
		0x1D22DDD93981F501ULL,
		0x7F510D38994D3549ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3CBFA3D76B96A058ULL,
			0x938ACF1F94CB6E41ULL,
			0x1D22DDD93981F501ULL,
			0x7F510D38994D3549ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x272ED6A6C456DDEDULL,
			0xBD4077B4D156195FULL,
			0x6FB8E3F11B222A92ULL,
			0x2B06435E76535FDBULL}
		},
		.Z = {.key64 = {
			0xA30EAE395E4ABDA5ULL,
			0x022FD5240B4D5FA4ULL,
			0xBD53F25E37105860ULL,
			0x521F89CEC6327EFCULL}
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

	steps = 58;
	X1 = (curve25519_key_t){.key64 = {
		0x537A688305446080ULL,
		0x3D8012D71173C711ULL,
		0x3037B85D395B86DCULL,
		0x7690CA7C8D978F08ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x537A688305446080ULL,
			0x3D8012D71173C711ULL,
			0x3037B85D395B86DCULL,
			0x7690CA7C8D978F08ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x77E9EA6460D227B1ULL,
			0xF556F4B1F68D6447ULL,
			0x8CBE8C5C99F36301ULL,
			0x6C2CD46ECFB28466ULL}
		},
		.Z = {.key64 = {
			0x481568E303C24DE0ULL,
			0xE370C8AA7FB42399ULL,
			0xD7FD7DECEF1E5456ULL,
			0x661129CEAFB8D675ULL}
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

	steps = 18;
	X1 = (curve25519_key_t){.key64 = {
		0x10038127BBBA2440ULL,
		0xF0AE1F88346B38BBULL,
		0xD4DA53147D5A031AULL,
		0x4508D649F4C0C10CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x10038127BBBA2440ULL,
			0xF0AE1F88346B38BBULL,
			0xD4DA53147D5A031AULL,
			0x4508D649F4C0C10CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x33AB2873D199A455ULL,
			0x35EC8E349D802AD5ULL,
			0xD46220825639E64AULL,
			0x58FF3BC66EB15C16ULL}
		},
		.Z = {.key64 = {
			0xC90374820BA8A8E4ULL,
			0x54FE356779171E41ULL,
			0xBB89B043F192C5FEULL,
			0x1C0555474457B6CFULL}
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

	steps = 22;
	X1 = (curve25519_key_t){.key64 = {
		0x49D0930353D1A920ULL,
		0xCC04E64A41C914DBULL,
		0x2326DBCBC12D66DFULL,
		0x4A694897D7B831A8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x49D0930353D1A920ULL,
			0xCC04E64A41C914DBULL,
			0x2326DBCBC12D66DFULL,
			0x4A694897D7B831A8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB0BCD009889CB784ULL,
			0x6903B74D7A788970ULL,
			0xB723AD90EED769C2ULL,
			0x23C431DA5820E406ULL}
		},
		.Z = {.key64 = {
			0xB1D4B359BAD38720ULL,
			0x4866941B5D4AE415ULL,
			0xAE61740F64FF74C3ULL,
			0x1936D1D5F384A2A2ULL}
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

	steps = 29;
	X1 = (curve25519_key_t){.key64 = {
		0x204336F11320C2C0ULL,
		0x9848029879DAEE8BULL,
		0xEF022E6B1CC380D8ULL,
		0x79D73AFDBA2694D5ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x204336F11320C2C0ULL,
			0x9848029879DAEE8BULL,
			0xEF022E6B1CC380D8ULL,
			0x79D73AFDBA2694D5ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC63D62AE91016FF3ULL,
			0xA8726E6DB18E3D7DULL,
			0xA4A29C5DF49FB0FDULL,
			0x3BB2659500D7DCEFULL}
		},
		.Z = {.key64 = {
			0x1C119D6A4EC8C421ULL,
			0x74BE0EE45C3E1DA1ULL,
			0x44855DDB6A51230EULL,
			0x0D51F1795F1655CEULL}
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

	steps = 42;
	X1 = (curve25519_key_t){.key64 = {
		0xDDA5D51F45F1CA90ULL,
		0xE2EB5C7C1716FDCFULL,
		0xAA1192A54D7A0B99ULL,
		0x4F5E5F43EFB27807ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDDA5D51F45F1CA90ULL,
			0xE2EB5C7C1716FDCFULL,
			0xAA1192A54D7A0B99ULL,
			0x4F5E5F43EFB27807ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0E46F0214A6E3D97ULL,
			0xA975EC823E3A641FULL,
			0x9C1429115F39B4ABULL,
			0x352985503D10EFE3ULL}
		},
		.Z = {.key64 = {
			0x5254264F52507314ULL,
			0x0E3294B8183E3EFCULL,
			0x7503987A0FEB2684ULL,
			0x2BBF57BD825460F0ULL}
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

	steps = 42;
	X1 = (curve25519_key_t){.key64 = {
		0x6100C650D5CA1408ULL,
		0xD85AA50597B6A23EULL,
		0x5179BE1999F3074CULL,
		0x488ABBABA0400BD5ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6100C650D5CA1408ULL,
			0xD85AA50597B6A23EULL,
			0x5179BE1999F3074CULL,
			0x488ABBABA0400BD5ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5B2AA6A4BDFDF007ULL,
			0x52B17DB1127EADC6ULL,
			0x6864C7E1B5274A51ULL,
			0x4AE9E4E74AF83CF9ULL}
		},
		.Z = {.key64 = {
			0x0521C11AA91B9567ULL,
			0xD708C76B03D10D57ULL,
			0x3A9BFE2C0C283A87ULL,
			0x31F19AA6E6DECA05ULL}
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

	steps = 48;
	X1 = (curve25519_key_t){.key64 = {
		0x6F28B4B0A308FDF0ULL,
		0xB47DB333266C5889ULL,
		0xB3746277893D8B8FULL,
		0x4061AB8926B4D4A6ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6F28B4B0A308FDF0ULL,
			0xB47DB333266C5889ULL,
			0xB3746277893D8B8FULL,
			0x4061AB8926B4D4A6ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x20B370AA41B9BFA9ULL,
			0x469F8386669F2B2EULL,
			0x8C495A40D7FDF69DULL,
			0x5498203E59C11BFDULL}
		},
		.Z = {.key64 = {
			0x95EF2F0413B4D69EULL,
			0x6F0226004D38ED0CULL,
			0xEAF13FBD08BB602CULL,
			0x40E3533F923BE486ULL}
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

	steps = 18;
	X1 = (curve25519_key_t){.key64 = {
		0x2E0FDA325EB12668ULL,
		0x3B1FDC5BA4A2E29EULL,
		0xF386BDF5B15A8759ULL,
		0x6AF66769FBDF122FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2E0FDA325EB12668ULL,
			0x3B1FDC5BA4A2E29EULL,
			0xF386BDF5B15A8759ULL,
			0x6AF66769FBDF122FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x151B1E51558BA921ULL,
			0x06A0DF8AA1856F18ULL,
			0x720E2B07E8DFD94AULL,
			0x0E4B0F5D7A4E8938ULL}
		},
		.Z = {.key64 = {
			0xEF159E0B4F59D355ULL,
			0x3018A6D16ED62CBDULL,
			0xCDB84E41A7B0B282ULL,
			0x4FC495C23D89EA55ULL}
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

	steps = 40;
	X1 = (curve25519_key_t){.key64 = {
		0x91C3A2398B92B1A8ULL,
		0x8974D74C9AE25EDCULL,
		0x019CB669FEDB6EFEULL,
		0x4D45A0E1CD4A3EAFULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x91C3A2398B92B1A8ULL,
			0x8974D74C9AE25EDCULL,
			0x019CB669FEDB6EFEULL,
			0x4D45A0E1CD4A3EAFULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0916952C52B8A61AULL,
			0xCF02215E7FF93738ULL,
			0x3A9DE572DB99F332ULL,
			0x297BFC290860F8B9ULL}
		},
		.Z = {.key64 = {
			0x58C7670E65D30F90ULL,
			0xCC865A6D732BC592ULL,
			0xB56A7856D63DF465ULL,
			0x03D112B2725E7F6CULL}
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

	steps = 6;
	X1 = (curve25519_key_t){.key64 = {
		0xB074A39FF724D198ULL,
		0xDDE0F0F14F5F8B58ULL,
		0xC3632CD3A09CED90ULL,
		0x5190967E6402EACAULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB074A39FF724D198ULL,
			0xDDE0F0F14F5F8B58ULL,
			0xC3632CD3A09CED90ULL,
			0x5190967E6402EACAULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6479A6E7E18E30E2ULL,
			0x29AFA27409C64D9CULL,
			0xA85F5C09BFD0425FULL,
			0x6241660B39E4241EULL}
		},
		.Z = {.key64 = {
			0xC793E6BAF2ABFF92ULL,
			0x516477787DD8571FULL,
			0x19E39D6CACA61E7DULL,
			0x23BE5416C9E3D9B6ULL}
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

	steps = 1;
	X1 = (curve25519_key_t){.key64 = {
		0x1A445C028CB19BD0ULL,
		0xA7F303985568DE2EULL,
		0x667088AEC3CA182AULL,
		0x7F9BEC18F08A5866ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1A445C028CB19BD0ULL,
			0xA7F303985568DE2EULL,
			0x667088AEC3CA182AULL,
			0x7F9BEC18F08A5866ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x11B068CB6547408AULL,
			0xA80CCAFFD4941D5DULL,
			0x44901D186C81BA84ULL,
			0x13A43B5C0193E8B5ULL}
		},
		.Z = {.key64 = {
			0x6911700A32C66F79ULL,
			0x9FCC0E6155A378B8ULL,
			0x99C222BB0F2860AAULL,
			0x7E6FB063C2296199ULL}
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

	steps = 35;
	X1 = (curve25519_key_t){.key64 = {
		0x849A7788127E00E8ULL,
		0x782EE45FAEE7C520ULL,
		0x27A887A32533D7F8ULL,
		0x55599454731B6CABULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x849A7788127E00E8ULL,
			0x782EE45FAEE7C520ULL,
			0x27A887A32533D7F8ULL,
			0x55599454731B6CABULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x45AE221F3019A8BFULL,
			0xAE003895F5E90433ULL,
			0xD6849C5D1BBC1E77ULL,
			0x59B6772338AB5160ULL}
		},
		.Z = {.key64 = {
			0x815D34B7C5EE3A9AULL,
			0x5AAB3E5DF1AAA855ULL,
			0x2F35BECB049F83F7ULL,
			0x14F45653DB2C9157ULL}
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

	steps = 43;
	X1 = (curve25519_key_t){.key64 = {
		0xCBA947BEACDF6830ULL,
		0xB2DF0CEA9F15098BULL,
		0x4E662AC5F6E1938EULL,
		0x7B8771B53770E922ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCBA947BEACDF6830ULL,
			0xB2DF0CEA9F15098BULL,
			0x4E662AC5F6E1938EULL,
			0x7B8771B53770E922ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBFBD3430DE70880FULL,
			0x0E643E34496A9182ULL,
			0x3A61C19939DAC9FFULL,
			0x5D920880AD80F3A9ULL}
		},
		.Z = {.key64 = {
			0x0F68AA3321F2AF22ULL,
			0x1D15F4E287968873ULL,
			0x94F54038F406D0E4ULL,
			0x54378E783B92C66DULL}
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

	steps = 44;
	X1 = (curve25519_key_t){.key64 = {
		0xCD5516A8976F5B28ULL,
		0x95239E137AB2BC5AULL,
		0x2AA90CB58F4973EBULL,
		0x40334827E7389FC7ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCD5516A8976F5B28ULL,
			0x95239E137AB2BC5AULL,
			0x2AA90CB58F4973EBULL,
			0x40334827E7389FC7ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE6FBD6E58E42CD4FULL,
			0x454D6202DA0D57BDULL,
			0xD9C7C5FB5EE55CDFULL,
			0x4E65A79D172A2BD9ULL}
		},
		.Z = {.key64 = {
			0x0B9AAB2D7749D10BULL,
			0x654C1D2777B264E1ULL,
			0xE88D396FB09F6D78ULL,
			0x01FA71142583AD22ULL}
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

	steps = 29;
	X1 = (curve25519_key_t){.key64 = {
		0x69CC1FA686B67D90ULL,
		0xC35409D2AC995EACULL,
		0xCF9BA975BB388D46ULL,
		0x6B37EA32BDDF8FDFULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x69CC1FA686B67D90ULL,
			0xC35409D2AC995EACULL,
			0xCF9BA975BB388D46ULL,
			0x6B37EA32BDDF8FDFULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x122A00803709C1F5ULL,
			0xBFF401916AFBEEF3ULL,
			0x75CDA07FE7C86284ULL,
			0x21285D7272CD060CULL}
		},
		.Z = {.key64 = {
			0x2EF2085FBB3B4549ULL,
			0xB77B30683FED132AULL,
			0xCD800558F08D31BBULL,
			0x7B6D06F56439508CULL}
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

	steps = 54;
	X1 = (curve25519_key_t){.key64 = {
		0xDD708E7D2696A5A8ULL,
		0xF869419C0156AC1FULL,
		0x3E5DDE0723654B10ULL,
		0x4BD5EA7BBBC33528ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDD708E7D2696A5A8ULL,
			0xF869419C0156AC1FULL,
			0x3E5DDE0723654B10ULL,
			0x4BD5EA7BBBC33528ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x07B332388AF97CE7ULL,
			0x69B60B6FBBC62017ULL,
			0x42AE517F614017E7ULL,
			0x32AF0C4D77A8E51CULL}
		},
		.Z = {.key64 = {
			0xE67216C03821E0D0ULL,
			0x2BFAAB644EF5D9BFULL,
			0x109467AE3111D9C2ULL,
			0x16AC13F7CD5B5E29ULL}
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

	steps = 5;
	X1 = (curve25519_key_t){.key64 = {
		0x88792EB4AE4CD1E8ULL,
		0x56EB9386B8608024ULL,
		0xDB855143B684F9F8ULL,
		0x4C9CD603F8E1B2E3ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x88792EB4AE4CD1E8ULL,
			0x56EB9386B8608024ULL,
			0xDB855143B684F9F8ULL,
			0x4C9CD603F8E1B2E3ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCC939A9C01FBB67FULL,
			0x02BDD505429860E3ULL,
			0xF7D34FEE8CE51A77ULL,
			0x07A21545D5AB3236ULL}
		},
		.Z = {.key64 = {
			0x112F58F5A39175C0ULL,
			0xE7378813128A892BULL,
			0x1568113F049A5A7FULL,
			0x3294844F4421D4BFULL}
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

	steps = 62;
	X1 = (curve25519_key_t){.key64 = {
		0x8341C146C77251C8ULL,
		0xEE956F2D76B873EFULL,
		0x6C394C5711B2C354ULL,
		0x4461BF38E10F0D73ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8341C146C77251C8ULL,
			0xEE956F2D76B873EFULL,
			0x6C394C5711B2C354ULL,
			0x4461BF38E10F0D73ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBE7FAB831FD90076ULL,
			0x2DC347C2EC5EF13DULL,
			0x18C8262FCBBF2F94ULL,
			0x7F7D9749B58A39E6ULL}
		},
		.Z = {.key64 = {
			0x50D3064A08EFBF20ULL,
			0x788E8AE0520E8528ULL,
			0x658B329FC6EC16C4ULL,
			0x0D911E293A326F1EULL}
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

	steps = 44;
	X1 = (curve25519_key_t){.key64 = {
		0x850DF2A4E0CE2080ULL,
		0x71B3725DBE5F5B19ULL,
		0xE1BA51AA7A95BDB5ULL,
		0x4314F75B73C403AAULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x850DF2A4E0CE2080ULL,
			0x71B3725DBE5F5B19ULL,
			0xE1BA51AA7A95BDB5ULL,
			0x4314F75B73C403AAULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9CFC46C22818199CULL,
			0x18271A47C3EF5CAFULL,
			0xFBA0371E146037E1ULL,
			0x24244079F79D27A3ULL}
		},
		.Z = {.key64 = {
			0xA408B714EE2F5328ULL,
			0x40E894119B3FC2F8ULL,
			0xA8C9F78766597F3DULL,
			0x588974A2A4B8B868ULL}
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

	steps = 7;
	X1 = (curve25519_key_t){.key64 = {
		0x3ECD3BDF7B40DB68ULL,
		0x08520E658F6D030AULL,
		0x56D3994B199BE695ULL,
		0x659ABD07CAEEFC81ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3ECD3BDF7B40DB68ULL,
			0x08520E658F6D030AULL,
			0x56D3994B199BE695ULL,
			0x659ABD07CAEEFC81ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x15E796F47CCCF430ULL,
			0x51AA0ED4EA62F4A1ULL,
			0xB28CE3DF5F6CA7D1ULL,
			0x48CBB23DBAB67EBEULL}
		},
		.Z = {.key64 = {
			0xB42589B1A7178A4FULL,
			0xE600A6CBC9FBD41FULL,
			0x8C4843A0159E8A3FULL,
			0x6C505D9DCE216EE7ULL}
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

	steps = 45;
	X1 = (curve25519_key_t){.key64 = {
		0xC8D42002B4106CE8ULL,
		0x8FB72501C54A7052ULL,
		0x9D8D1DE5EF0D62BAULL,
		0x4B2EC9D86F6FE0D6ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC8D42002B4106CE8ULL,
			0x8FB72501C54A7052ULL,
			0x9D8D1DE5EF0D62BAULL,
			0x4B2EC9D86F6FE0D6ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7A9E0898C0141500ULL,
			0x6D165C0C3E1BB8A8ULL,
			0x8B8DACBB9AFF79CFULL,
			0x6DD81405CED6A036ULL}
		},
		.Z = {.key64 = {
			0x67392370AE038097ULL,
			0x759C50A3BF1A6317ULL,
			0x96B9B28A496396F8ULL,
			0x7263AAF682DCE57BULL}
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

	steps = 17;
	X1 = (curve25519_key_t){.key64 = {
		0x7BE1200750FD62E8ULL,
		0x0E6F97A9EB4A6B1EULL,
		0x13762C1E27B3D83FULL,
		0x7A08DCFC82CE5037ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7BE1200750FD62E8ULL,
			0x0E6F97A9EB4A6B1EULL,
			0x13762C1E27B3D83FULL,
			0x7A08DCFC82CE5037ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xED8DD21DCAA67EC7ULL,
			0xEC1388B0BA6A576AULL,
			0x2A1DED5958CC49DFULL,
			0x325E21EFA5739F69ULL}
		},
		.Z = {.key64 = {
			0xDC4F3258C4CECFC7ULL,
			0xADBD4544373EAE99ULL,
			0x1A2633C1FF8FBDC8ULL,
			0x4C0BC50761191220ULL}
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

	steps = 42;
	X1 = (curve25519_key_t){.key64 = {
		0x0C34DBB7F4964C30ULL,
		0x3B254771803EC58AULL,
		0x06360D8452F49315ULL,
		0x4A46EFAFE099CBAAULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0C34DBB7F4964C30ULL,
			0x3B254771803EC58AULL,
			0x06360D8452F49315ULL,
			0x4A46EFAFE099CBAAULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4993809EA84CA5EBULL,
			0x4A97A7D2CA475C9CULL,
			0xDEE546DA9478EF83ULL,
			0x6077613D44571806ULL}
		},
		.Z = {.key64 = {
			0x655AD7F26480FD77ULL,
			0x103B6D075B5C7B85ULL,
			0x5043EB5ECF6DC7A7ULL,
			0x505EC019ED46F00BULL}
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

	steps = 34;
	X1 = (curve25519_key_t){.key64 = {
		0x4808E32FF928BAD0ULL,
		0x059F3DFBC1880B40ULL,
		0x775741C928C00B10ULL,
		0x7E19E62FE90075D6ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4808E32FF928BAD0ULL,
			0x059F3DFBC1880B40ULL,
			0x775741C928C00B10ULL,
			0x7E19E62FE90075D6ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1BB124F4701F2751ULL,
			0x6AAA9CD9F9BAB1EFULL,
			0x4FC26539139F8417ULL,
			0x05CEDD9D877C1C4DULL}
		},
		.Z = {.key64 = {
			0xC627E0BCBA0695C9ULL,
			0x266CC29BEA5BA6F5ULL,
			0x858B1F0C253BF940ULL,
			0x6FE2E3D80A8E5A95ULL}
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

	steps = 23;
	X1 = (curve25519_key_t){.key64 = {
		0xAABBB85BF1160888ULL,
		0x0D96600B70915179ULL,
		0x08247185A6149A9EULL,
		0x5E2BA77ACCCF18C1ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAABBB85BF1160888ULL,
			0x0D96600B70915179ULL,
			0x08247185A6149A9EULL,
			0x5E2BA77ACCCF18C1ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8288D4BFC842B57DULL,
			0x9B1E96464D386CE6ULL,
			0x779F09399B325E23ULL,
			0x0838DCAAEDBED0A5ULL}
		},
		.Z = {.key64 = {
			0x18C2132D20DFCB28ULL,
			0x42FAB04C7E57BF1EULL,
			0x800727123190C7AFULL,
			0x555C8569D084DA1FULL}
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

	steps = 5;
	X1 = (curve25519_key_t){.key64 = {
		0x5ED35E38879DCF50ULL,
		0xC373F2930C749261ULL,
		0x2B6E28023D8E2B28ULL,
		0x5AADF9D1919DCF98ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5ED35E38879DCF50ULL,
			0xC373F2930C749261ULL,
			0x2B6E28023D8E2B28ULL,
			0x5AADF9D1919DCF98ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0680CD741995FCD3ULL,
			0xD5FAE661D6D580BAULL,
			0x441F6DCF4B2949FFULL,
			0x2C60C64B2FC391D8ULL}
		},
		.Z = {.key64 = {
			0x99FE3935306F90C9ULL,
			0xE9154E4FD0BFBDCEULL,
			0xCEAD8012400D4374ULL,
			0x78EF36EAA63078ECULL}
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

	steps = 17;
	X1 = (curve25519_key_t){.key64 = {
		0xF6CDBCF29E0CC740ULL,
		0x43FDF76106033136ULL,
		0x9B95B79B73E5BB3BULL,
		0x66D839359F909DDAULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF6CDBCF29E0CC740ULL,
			0x43FDF76106033136ULL,
			0x9B95B79B73E5BB3BULL,
			0x66D839359F909DDAULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2B534ED9B11E5816ULL,
			0x8C06743BDC8C3ADAULL,
			0x2A1C1C73DD8B03B4ULL,
			0x12F5A21CBEA3224DULL}
		},
		.Z = {.key64 = {
			0x2442253EF8F12585ULL,
			0x3D11FFE8018B6006ULL,
			0x00B0798AAA9CA8CBULL,
			0x067C1671436683B7ULL}
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

	steps = 40;
	X1 = (curve25519_key_t){.key64 = {
		0x95248C7DA9986790ULL,
		0xEFB7030E9D1C4F8BULL,
		0xEB5AA7F7B551E905ULL,
		0x456D94A4FF63A8FFULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x95248C7DA9986790ULL,
			0xEFB7030E9D1C4F8BULL,
			0xEB5AA7F7B551E905ULL,
			0x456D94A4FF63A8FFULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2D9637A440C54452ULL,
			0xDE136D8C2576ECF9ULL,
			0x88479A6A3F71AFD5ULL,
			0x17A9DDC2345017FCULL}
		},
		.Z = {.key64 = {
			0x5A62B77875A1195DULL,
			0x11E91BC85B2B03FBULL,
			0x5C1B833B2A3395C6ULL,
			0x09D5F5EF76788383ULL}
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

	steps = 27;
	X1 = (curve25519_key_t){.key64 = {
		0x47A588FD823BF2D8ULL,
		0xF6EBEEDE57857024ULL,
		0x53CC4B1B318EDA19ULL,
		0x5C213E4222A0F92CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x47A588FD823BF2D8ULL,
			0xF6EBEEDE57857024ULL,
			0x53CC4B1B318EDA19ULL,
			0x5C213E4222A0F92CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5DAEFA405603487AULL,
			0x6A3A0C460670D854ULL,
			0xBF5C454EF087241CULL,
			0x2CF1A86F83AA0B73ULL}
		},
		.Z = {.key64 = {
			0x919D709E93D7ED6DULL,
			0x5123CB53F2D10BF6ULL,
			0x3C0B6BBE44A530DEULL,
			0x1FD668D86A107263ULL}
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

	steps = 30;
	X1 = (curve25519_key_t){.key64 = {
		0xBD026799BAFE21A8ULL,
		0xDDA024C435311EFDULL,
		0x00D0555EBDB20A85ULL,
		0x52D8878FB3A7FDFEULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBD026799BAFE21A8ULL,
			0xDDA024C435311EFDULL,
			0x00D0555EBDB20A85ULL,
			0x52D8878FB3A7FDFEULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7CE9E84A78F0D6A2ULL,
			0xF7A0A56AB0138971ULL,
			0x74A0437D64CE44C2ULL,
			0x57E7C5BB5752B9F5ULL}
		},
		.Z = {.key64 = {
			0x24A6586F43687DF1ULL,
			0x49C720F193167607ULL,
			0x44EADC4A0935D8DDULL,
			0x29FFE77E6F719491ULL}
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

	steps = 24;
	X1 = (curve25519_key_t){.key64 = {
		0x742BB2380A9C67E8ULL,
		0x17F4D98B388241E8ULL,
		0x870A1B7A586654E8ULL,
		0x72E9D8E292BE23B8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x742BB2380A9C67E8ULL,
			0x17F4D98B388241E8ULL,
			0x870A1B7A586654E8ULL,
			0x72E9D8E292BE23B8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEF37E103D2D66ECCULL,
			0x401765101689BB72ULL,
			0x6AB62B12BE1F2B73ULL,
			0x1ED63876769C8001ULL}
		},
		.Z = {.key64 = {
			0xB1895547CD9FDACEULL,
			0x5C9E7EB4E248B477ULL,
			0xD515473350C0357AULL,
			0x348BDBB51531EDAFULL}
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

	steps = 27;
	X1 = (curve25519_key_t){.key64 = {
		0x595131D75A0D93A0ULL,
		0xE07F55CCF3D2A526ULL,
		0x0ED835CE175FDD6FULL,
		0x744B50C53247F82FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x595131D75A0D93A0ULL,
			0xE07F55CCF3D2A526ULL,
			0x0ED835CE175FDD6FULL,
			0x744B50C53247F82FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x88AD912F380CBBD6ULL,
			0xD22EAEC4068DBD1FULL,
			0xE584CEA7725B2412ULL,
			0x5A5F1A7D8D9CB3D8ULL}
		},
		.Z = {.key64 = {
			0x427CA0B1EA54A541ULL,
			0xBC7346102C6AFFDBULL,
			0xA4640F0ED908C0B5ULL,
			0x1DB9C49BD872783DULL}
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

	steps = 52;
	X1 = (curve25519_key_t){.key64 = {
		0x1683FB19137BBA90ULL,
		0x1EE0873500D7C588ULL,
		0xE376CBCCEA84AB5DULL,
		0x7733A67CC01E5BFBULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1683FB19137BBA90ULL,
			0x1EE0873500D7C588ULL,
			0xE376CBCCEA84AB5DULL,
			0x7733A67CC01E5BFBULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x99ADD03955DF8D67ULL,
			0x424E7F8B40965D53ULL,
			0x8D03E30399FF5E7AULL,
			0x1B7B48026189E354ULL}
		},
		.Z = {.key64 = {
			0xF4A832BDC7E4F362ULL,
			0x5CCEC08F71BEFF12ULL,
			0xC86953D75287D11CULL,
			0x74E157330F157C32ULL}
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

	steps = 34;
	X1 = (curve25519_key_t){.key64 = {
		0x9DB8574DFD172E78ULL,
		0x857453F3E128941EULL,
		0xD741CA9532D65CC9ULL,
		0x6C6833229821DE37ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9DB8574DFD172E78ULL,
			0x857453F3E128941EULL,
			0xD741CA9532D65CC9ULL,
			0x6C6833229821DE37ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE4E151460795C289ULL,
			0xCC526AAEC8D0458AULL,
			0x17AF922F7C355A37ULL,
			0x548B4837D5E7C6E0ULL}
		},
		.Z = {.key64 = {
			0x702A2501BD717202ULL,
			0x538EC67AFB08746EULL,
			0xE6F4B7F48A3F599BULL,
			0x04B3B268AA3696F0ULL}
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

	steps = 44;
	X1 = (curve25519_key_t){.key64 = {
		0x9C6C13D0E29B53D8ULL,
		0x25DA2B23D79B3139ULL,
		0xD0E249BD3956BD6AULL,
		0x565F5A086BF810A0ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9C6C13D0E29B53D8ULL,
			0x25DA2B23D79B3139ULL,
			0xD0E249BD3956BD6AULL,
			0x565F5A086BF810A0ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5CA4FDA4366D27A7ULL,
			0x1F8A1830BF0F5076ULL,
			0x7A98C29B3187F779ULL,
			0x2F9C8F978892DDA1ULL}
		},
		.Z = {.key64 = {
			0xB3C4442AA32318DFULL,
			0x26865D12B3738CEEULL,
			0x0DD22250E9D1E043ULL,
			0x133F2BD4E7D5DBF3ULL}
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

	steps = 42;
	X1 = (curve25519_key_t){.key64 = {
		0x054DCD856F54DA78ULL,
		0xB5DDA73240FAD414ULL,
		0x1F009CD9A7AB3008ULL,
		0x5B0617BBFF2D926BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x054DCD856F54DA78ULL,
			0xB5DDA73240FAD414ULL,
			0x1F009CD9A7AB3008ULL,
			0x5B0617BBFF2D926BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x333207580D6C074EULL,
			0x7C5BC1B6852F8776ULL,
			0x1CBAEDE384834E15ULL,
			0x1D6D77A9DDF2A7FBULL}
		},
		.Z = {.key64 = {
			0x8AE5F84436DF0FA2ULL,
			0x2365FDC14A506361ULL,
			0xAA319ECF5500D5F7ULL,
			0x27E9DA66DAF90588ULL}
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

	steps = 4;
	X1 = (curve25519_key_t){.key64 = {
		0xA52E1205BC49B9E0ULL,
		0x040873666372AF07ULL,
		0x48527D3B2B7CFBB1ULL,
		0x73DB820ED9E47DB2ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA52E1205BC49B9E0ULL,
			0x040873666372AF07ULL,
			0x48527D3B2B7CFBB1ULL,
			0x73DB820ED9E47DB2ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDE65DD5EA96DCA83ULL,
			0x890D902AF0548E85ULL,
			0x83051081384D9369ULL,
			0x0CE38D31C34889F2ULL}
		},
		.Z = {.key64 = {
			0x313E656A286FBB6DULL,
			0x68BD14948C0F4968ULL,
			0x84A0C30107431EF5ULL,
			0x17A83E81037E3125ULL}
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

	steps = 4;
	X1 = (curve25519_key_t){.key64 = {
		0xC8A329F128D0C2F8ULL,
		0x681E3EDA1ABD7A73ULL,
		0x377DEDDE350D733FULL,
		0x6CFB13C04EE4DD50ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC8A329F128D0C2F8ULL,
			0x681E3EDA1ABD7A73ULL,
			0x377DEDDE350D733FULL,
			0x6CFB13C04EE4DD50ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4D5F93447ED46823ULL,
			0xADAC86AA72869A19ULL,
			0xEC462D9EEAD71073ULL,
			0x44EF0E53B58460ECULL}
		},
		.Z = {.key64 = {
			0x6CA8FACE77431BCFULL,
			0x89183ED1E18F8BE1ULL,
			0x5D6FF76C72849A67ULL,
			0x0F8F32815AEF11D7ULL}
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

	steps = 58;
	X1 = (curve25519_key_t){.key64 = {
		0x080E19F50C8AB000ULL,
		0x872A8FCDEF151768ULL,
		0x2D0CB7BEDD71825CULL,
		0x4BCE00E0F2FEB2B5ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x080E19F50C8AB000ULL,
			0x872A8FCDEF151768ULL,
			0x2D0CB7BEDD71825CULL,
			0x4BCE00E0F2FEB2B5ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBA72B168617726ADULL,
			0x41045AF5377F8BD0ULL,
			0x284084E2AF0A905DULL,
			0x040DCAFA8A6365EFULL}
		},
		.Z = {.key64 = {
			0xAECC9F7AA49E4A3BULL,
			0x43AB2CA1A56B2F72ULL,
			0x332CC10F0804BE8EULL,
			0x5A29EDEAFD3A8871ULL}
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

	steps = 13;
	X1 = (curve25519_key_t){.key64 = {
		0x597FBFDC1ED20D30ULL,
		0x04CFD93E013937B9ULL,
		0x7FF1DB2D187EE013ULL,
		0x7DF5E45621198CEDULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x597FBFDC1ED20D30ULL,
			0x04CFD93E013937B9ULL,
			0x7FF1DB2D187EE013ULL,
			0x7DF5E45621198CEDULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x89A44F1CA1E66955ULL,
			0x66595FBFA6FC2D8CULL,
			0xB68A7EECD4F96084ULL,
			0x1B9C7670E2872CB4ULL}
		},
		.Z = {.key64 = {
			0xA398F47B6F5BE65BULL,
			0xB17160BFD656E30DULL,
			0x87A2E95B2440D581ULL,
			0x72758A1246BD1EAFULL}
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

	steps = 3;
	X1 = (curve25519_key_t){.key64 = {
		0x558CFBCF3473AB30ULL,
		0x4E518298BC9F8F6CULL,
		0x626653978AA92537ULL,
		0x4D11F8D1B29179C6ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x558CFBCF3473AB30ULL,
			0x4E518298BC9F8F6CULL,
			0x626653978AA92537ULL,
			0x4D11F8D1B29179C6ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB16993452E88CB96ULL,
			0x78E94283650F7DACULL,
			0xAFDE833DB616B326ULL,
			0x5077BE432CA8F0E0ULL}
		},
		.Z = {.key64 = {
			0x1A73ADAB8FFA0727ULL,
			0xD30E6E9ECD4D2E78ULL,
			0x9947C9D1B5F38911ULL,
			0x15CF92193AD6445FULL}
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

	steps = 24;
	X1 = (curve25519_key_t){.key64 = {
		0x818B4EEDA3BA1B78ULL,
		0x9A313513E0B731AFULL,
		0x99F22D54FAA2E54FULL,
		0x6FF1DE1FD173172CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x818B4EEDA3BA1B78ULL,
			0x9A313513E0B731AFULL,
			0x99F22D54FAA2E54FULL,
			0x6FF1DE1FD173172CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5481E755B55ACAE5ULL,
			0x9177B30F9E59B8EDULL,
			0x81FC7EFE49A418E3ULL,
			0x7D965D9D8F6DBF1CULL}
		},
		.Z = {.key64 = {
			0x36E7A653AB902ECDULL,
			0xB8776E8C77A12F4BULL,
			0x89082FEB9E860157ULL,
			0x575D293DA2710138ULL}
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

	steps = 24;
	X1 = (curve25519_key_t){.key64 = {
		0x0B754772845C20C8ULL,
		0xAB6290D711FECD75ULL,
		0xB15F8805CE2A6735ULL,
		0x4DA89196516522E8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0B754772845C20C8ULL,
			0xAB6290D711FECD75ULL,
			0xB15F8805CE2A6735ULL,
			0x4DA89196516522E8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x547110E5F0A1682DULL,
			0xC72EFAA124D84533ULL,
			0xE42B3998B76C2090ULL,
			0x08BF04110406ACDAULL}
		},
		.Z = {.key64 = {
			0x4B7E8CF85E37FBB6ULL,
			0xDEC5EA7B564100CFULL,
			0x34CC8667A37FEACAULL,
			0x2EC9BDAE393AF818ULL}
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

	steps = 41;
	X1 = (curve25519_key_t){.key64 = {
		0x4A9F3A8645F5EF30ULL,
		0xA16E5830A8111B3BULL,
		0x805157B14266F49EULL,
		0x474A9AE6EF7298A4ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4A9F3A8645F5EF30ULL,
			0xA16E5830A8111B3BULL,
			0x805157B14266F49EULL,
			0x474A9AE6EF7298A4ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x083B6F095D6D5510ULL,
			0x8395F2FD0997E0FBULL,
			0x04AC59F088924E6CULL,
			0x4BC856E3DC28E92AULL}
		},
		.Z = {.key64 = {
			0xBE4024012B3C279CULL,
			0xCB51E42C0CF6EE3DULL,
			0x02EC6157EA5CB691ULL,
			0x74397B7BE255BAAAULL}
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

	steps = 19;
	X1 = (curve25519_key_t){.key64 = {
		0x31AC78F45960D118ULL,
		0xBFEF91B52258F1A9ULL,
		0x1ECE67055C858999ULL,
		0x5FFEC13C7B49CAD1ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x31AC78F45960D118ULL,
			0xBFEF91B52258F1A9ULL,
			0x1ECE67055C858999ULL,
			0x5FFEC13C7B49CAD1ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC3C01E17A6E913B0ULL,
			0x4C9C9F0F76535D8CULL,
			0xF7CD50E7899CD5D4ULL,
			0x08FF8BE36891828AULL}
		},
		.Z = {.key64 = {
			0xE834B0AE80D9D5B7ULL,
			0xA088BC0363D7C019ULL,
			0xAB7BCFEB86BB363EULL,
			0x72CDBD0675868533ULL}
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

	steps = 9;
	X1 = (curve25519_key_t){.key64 = {
		0x2DBC0D0B3979A280ULL,
		0xFF993DAC026C8B0DULL,
		0x35FB233C22B45CFBULL,
		0x43C6F2B4C4D8BEEDULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2DBC0D0B3979A280ULL,
			0xFF993DAC026C8B0DULL,
			0x35FB233C22B45CFBULL,
			0x43C6F2B4C4D8BEEDULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE239B435CA9A65C4ULL,
			0xB0A20D6BED19977EULL,
			0x545EE34FC9D9E4E5ULL,
			0x2F5E8C899ECF6DA9ULL}
		},
		.Z = {.key64 = {
			0x1377D646987A74F2ULL,
			0xAB7E04D0126307FAULL,
			0x65009BC414D924ACULL,
			0x6F2960CF2FF1662DULL}
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

	steps = 46;
	X1 = (curve25519_key_t){.key64 = {
		0x083C12FD4A141E18ULL,
		0xD6F15507955D2C01ULL,
		0x1A979DA457A37A95ULL,
		0x40A13172D5D73961ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x083C12FD4A141E18ULL,
			0xD6F15507955D2C01ULL,
			0x1A979DA457A37A95ULL,
			0x40A13172D5D73961ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x356E62F622AC5385ULL,
			0xD845787692694E88ULL,
			0xBE5F8A295FAF442AULL,
			0x59E28B5A08BD2622ULL}
		},
		.Z = {.key64 = {
			0xE026A762FEA1AE28ULL,
			0x4D53CD23F7CF6BAEULL,
			0xB30E798D4A8E3D44ULL,
			0x274EC6299ACDE117ULL}
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

	steps = 47;
	X1 = (curve25519_key_t){.key64 = {
		0x840BBF12450DA6A0ULL,
		0x5F2CEF481D3E0108ULL,
		0xAAFEE77AD2AF11E3ULL,
		0x566237BB319F699BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x840BBF12450DA6A0ULL,
			0x5F2CEF481D3E0108ULL,
			0xAAFEE77AD2AF11E3ULL,
			0x566237BB319F699BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEEB27C00047D6C3DULL,
			0x8EC20C71133A77CEULL,
			0x3A1C4A12BB1EFF7BULL,
			0x4F2029BB4CD5E8E4ULL}
		},
		.Z = {.key64 = {
			0x2A0705F9D0EE087BULL,
			0x85631BECE2E1664FULL,
			0x8CD6940EB1782F36ULL,
			0x3DBB64F3BA5F3497ULL}
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

	steps = 32;
	X1 = (curve25519_key_t){.key64 = {
		0xAA56D3DDA02ED100ULL,
		0x7D28023DCAC025FCULL,
		0x1018AC8414728D7FULL,
		0x5FAD8C355412C60CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAA56D3DDA02ED100ULL,
			0x7D28023DCAC025FCULL,
			0x1018AC8414728D7FULL,
			0x5FAD8C355412C60CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5FBAC3531A62E9ECULL,
			0x69AE49DEAB15584CULL,
			0xFAC4284DA7BD09CAULL,
			0x0A38114B70021ACFULL}
		},
		.Z = {.key64 = {
			0xBFD7D530866CB0ACULL,
			0xA345C1F3FC0BE323ULL,
			0x9D853A80A6122C64ULL,
			0x322C2B2B5754BAC2ULL}
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

	steps = 53;
	X1 = (curve25519_key_t){.key64 = {
		0x55A4109E7D3C1AF0ULL,
		0x36C9D0DF7AE09622ULL,
		0x40F0A34527479EF5ULL,
		0x6481E88E66CF3743ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x55A4109E7D3C1AF0ULL,
			0x36C9D0DF7AE09622ULL,
			0x40F0A34527479EF5ULL,
			0x6481E88E66CF3743ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4883A5F6045FAECFULL,
			0x3B8FA1F03B3EAB6EULL,
			0x4A212C155B0DA87BULL,
			0x416F1A871517594EULL}
		},
		.Z = {.key64 = {
			0x6A00584A31BDED1CULL,
			0x12DAF084E9EBC088ULL,
			0x61EF06DEDA06B274ULL,
			0x7B4B9657D2927D8FULL}
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

	steps = 28;
	X1 = (curve25519_key_t){.key64 = {
		0x106895D43A89B298ULL,
		0x2F04E4DE75CBC47DULL,
		0x94B972255A9DE9B2ULL,
		0x5983C26817CF9294ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x106895D43A89B298ULL,
			0x2F04E4DE75CBC47DULL,
			0x94B972255A9DE9B2ULL,
			0x5983C26817CF9294ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5CD45B3DDA224773ULL,
			0xCF125AFD5A5F50A8ULL,
			0x5A6594FE55906570ULL,
			0x655F4400B7DEFD23ULL}
		},
		.Z = {.key64 = {
			0xE3AEF3D06319DED0ULL,
			0xA8458383BC6D85A2ULL,
			0xB2FD01A3188D13D0ULL,
			0x18D25A86A52AE01EULL}
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

	steps = 6;
	X1 = (curve25519_key_t){.key64 = {
		0x04BE0D32C4F940B0ULL,
		0x5A50D6B02C057CE0ULL,
		0xEF1BEFB122B5EA46ULL,
		0x49600492B793D3AFULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x04BE0D32C4F940B0ULL,
			0x5A50D6B02C057CE0ULL,
			0xEF1BEFB122B5EA46ULL,
			0x49600492B793D3AFULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6DC1F792F799740FULL,
			0x972DA916F69E2016ULL,
			0x90DB98F12AA51501ULL,
			0x710A07A61A75B34BULL}
		},
		.Z = {.key64 = {
			0x35770DC18DE7EF6BULL,
			0xAB9135FAF1906004ULL,
			0xCCA42C1E0DAD8F64ULL,
			0x4376D421D439A37CULL}
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

	steps = 45;
	X1 = (curve25519_key_t){.key64 = {
		0xAD8A21EAC2F62AF8ULL,
		0xAB9F2B3328D70E26ULL,
		0x04215D748B77073AULL,
		0x6690746B405DC9D4ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAD8A21EAC2F62AF8ULL,
			0xAB9F2B3328D70E26ULL,
			0x04215D748B77073AULL,
			0x6690746B405DC9D4ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x765253C33F592CF3ULL,
			0x3115D5D8A200212DULL,
			0x22928172C3C048A7ULL,
			0x77934FCE70D246D4ULL}
		},
		.Z = {.key64 = {
			0x4A651FB69DC82EC6ULL,
			0x8F3FC2BC48094900ULL,
			0x5BB6EE7802B214D9ULL,
			0x4E7DA6FAB33E8E23ULL}
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

	steps = 61;
	X1 = (curve25519_key_t){.key64 = {
		0xB314BED69C8EC138ULL,
		0x17E3370BD1ACCF49ULL,
		0x5EA110069D4802A7ULL,
		0x52D3C0450F869D91ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB314BED69C8EC138ULL,
			0x17E3370BD1ACCF49ULL,
			0x5EA110069D4802A7ULL,
			0x52D3C0450F869D91ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB9E0CA1D3AED7793ULL,
			0x7ACBCCE3DACC1370ULL,
			0x3A24986AF99F51A6ULL,
			0x134C5150CD74C250ULL}
		},
		.Z = {.key64 = {
			0xF6D037F54F0C66BDULL,
			0xDEB0FD80AD47230BULL,
			0xD334EDBDB6218007ULL,
			0x68187EDE46B27DB4ULL}
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

	steps = 50;
	X1 = (curve25519_key_t){.key64 = {
		0xB20DD431A4765C48ULL,
		0x2DDDC66B129D6577ULL,
		0x9638372ABE3B68E1ULL,
		0x7DB8AFC4811058DDULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB20DD431A4765C48ULL,
			0x2DDDC66B129D6577ULL,
			0x9638372ABE3B68E1ULL,
			0x7DB8AFC4811058DDULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2E1C7759D8BEA0A1ULL,
			0xE8431ABD2F8D1E40ULL,
			0x27E9514A7EF52F39ULL,
			0x6A02FABF542827E0ULL}
		},
		.Z = {.key64 = {
			0x1FCBBBB84A860345ULL,
			0xBB3285579D738115ULL,
			0x00EDACE0D9B5334FULL,
			0x219D17AB81825E70ULL}
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

	steps = 26;
	X1 = (curve25519_key_t){.key64 = {
		0x8A09BB32321C2F68ULL,
		0xA6B448EC3546736AULL,
		0xD96748C6348A4854ULL,
		0x57F3DD9DFC93DED8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8A09BB32321C2F68ULL,
			0xA6B448EC3546736AULL,
			0xD96748C6348A4854ULL,
			0x57F3DD9DFC93DED8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5DDC7F86D5936B84ULL,
			0xAA9B6AB8A3120089ULL,
			0x4C5CE7DAF9CACC8CULL,
			0x1BDFA57D7D863D3BULL}
		},
		.Z = {.key64 = {
			0x8A1A799C18D344E3ULL,
			0x614763B64088A63CULL,
			0x6C9FC5A119286220ULL,
			0x146CF67D1583A11AULL}
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

	steps = 8;
	X1 = (curve25519_key_t){.key64 = {
		0xB929285FCF3379D8ULL,
		0xB341688464C88D08ULL,
		0x80E09313E3F52636ULL,
		0x6AE19DC7054BE7C2ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB929285FCF3379D8ULL,
			0xB341688464C88D08ULL,
			0x80E09313E3F52636ULL,
			0x6AE19DC7054BE7C2ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAA34E79CD6B767AEULL,
			0xF9B70B484E6DE785ULL,
			0x7A00CF3836B998CCULL,
			0x3A3CA22566D0A14AULL}
		},
		.Z = {.key64 = {
			0xBA66EA141601C3B5ULL,
			0xAA36ED36D45A4C15ULL,
			0xC68D6EB63B7E19A7ULL,
			0x6409DED89161DD9CULL}
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

	steps = 48;
	X1 = (curve25519_key_t){.key64 = {
		0xF3276812CEB539A8ULL,
		0x23D21CA9F4822926ULL,
		0x72EDF37F370D0C59ULL,
		0x4FF7152353217C98ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF3276812CEB539A8ULL,
			0x23D21CA9F4822926ULL,
			0x72EDF37F370D0C59ULL,
			0x4FF7152353217C98ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA7842D758FC4EF2EULL,
			0x7EBC9D38E67B75C5ULL,
			0x4B17B6EAB5564701ULL,
			0x385103346E468DB6ULL}
		},
		.Z = {.key64 = {
			0x37171F218F37E59DULL,
			0xCDF11C98D570593CULL,
			0x27780DFCDA6529CBULL,
			0x2C28207D8A5E81BAULL}
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

	steps = 8;
	X1 = (curve25519_key_t){.key64 = {
		0x2F895DABDFF76DB0ULL,
		0x3343C1C80066010BULL,
		0x5EF54446FA95BBE5ULL,
		0x688E80D2AAB842EDULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2F895DABDFF76DB0ULL,
			0x3343C1C80066010BULL,
			0x5EF54446FA95BBE5ULL,
			0x688E80D2AAB842EDULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x461DB7CC950790ABULL,
			0x54521DB852C726FDULL,
			0x00341DE4CE986BF0ULL,
			0x07E1B11DC43A3338ULL}
		},
		.Z = {.key64 = {
			0x6F95918DF38D2D32ULL,
			0x61910A0AD3C81BE7ULL,
			0xA474A4AC15ECB6D1ULL,
			0x588617F50B2D0D49ULL}
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

	steps = 15;
	X1 = (curve25519_key_t){.key64 = {
		0x823760683C49B928ULL,
		0xD5DC0C927AD53523ULL,
		0x2EAECC214D5BFA74ULL,
		0x6132FACE60B9A79BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x823760683C49B928ULL,
			0xD5DC0C927AD53523ULL,
			0x2EAECC214D5BFA74ULL,
			0x6132FACE60B9A79BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x75927C634E03CF56ULL,
			0xA60D330CD34BFC73ULL,
			0x34C36C969EB70D76ULL,
			0x76A325ACDD2038B7ULL}
		},
		.Z = {.key64 = {
			0x8DB50460EC764683ULL,
			0x9703C1341ACBF6EDULL,
			0x5FA4E7BE1A5205E8ULL,
			0x6D62EBB9BFA4E3C4ULL}
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

	steps = 42;
	X1 = (curve25519_key_t){.key64 = {
		0x21E4967F594F5880ULL,
		0x4357A696DE85A74DULL,
		0x4821154E8DE82E0CULL,
		0x5A63EAAC0739CAAFULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x21E4967F594F5880ULL,
			0x4357A696DE85A74DULL,
			0x4821154E8DE82E0CULL,
			0x5A63EAAC0739CAAFULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF98C3B1092000131ULL,
			0xD781C5D118C840D9ULL,
			0x28E5E9992792783AULL,
			0x21C85372E13FD537ULL}
		},
		.Z = {.key64 = {
			0xE81096BE5C85E764ULL,
			0x93EF28F88B9B8340ULL,
			0x145FAF507895191BULL,
			0x0BEB2D8B6A54E37CULL}
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
		0x7D9F87688DEABFA8ULL,
		0xC1B707161C86FEFEULL,
		0x3E7D70B6B8A51280ULL,
		0x699A9F576C7EB2E0ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7D9F87688DEABFA8ULL,
			0xC1B707161C86FEFEULL,
			0x3E7D70B6B8A51280ULL,
			0x699A9F576C7EB2E0ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5ECA7F95E0A92E7EULL,
			0x3F2B6106D00EA84BULL,
			0xB318904BE67FE159ULL,
			0x0C8878DB5D62A5A1ULL}
		},
		.Z = {.key64 = {
			0x707D468F0418C34FULL,
			0xB8B00B1C62D11DCDULL,
			0x59B694D5DA8A0564ULL,
			0x0EB11917660A797CULL}
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

	steps = 62;
	X1 = (curve25519_key_t){.key64 = {
		0xCBDAFB673E06ED90ULL,
		0x7E7EC157ACCE3DD0ULL,
		0x1E10E84F9184F28FULL,
		0x5CAF22A7C547CDE8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCBDAFB673E06ED90ULL,
			0x7E7EC157ACCE3DD0ULL,
			0x1E10E84F9184F28FULL,
			0x5CAF22A7C547CDE8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6B30B45B1B8464F2ULL,
			0xBA4E7A05389CC6EEULL,
			0x5B83AA157E263D50ULL,
			0x5DF7A204DF868F68ULL}
		},
		.Z = {.key64 = {
			0x75430E66AEF9D982ULL,
			0x0AAA6E2C7039085CULL,
			0xCDA60819BCECB093ULL,
			0x3236FC2CBF733169ULL}
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

	steps = 34;
	X1 = (curve25519_key_t){.key64 = {
		0x11CC0F962D0299A8ULL,
		0x04181E71029FD3A3ULL,
		0x55C4CDF55ECC4C01ULL,
		0x792536AA94F51660ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x11CC0F962D0299A8ULL,
			0x04181E71029FD3A3ULL,
			0x55C4CDF55ECC4C01ULL,
			0x792536AA94F51660ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x687A174D89C83976ULL,
			0xEDD6088CAD473DDDULL,
			0xC57730368F827B9AULL,
			0x3697B664994DE560ULL}
		},
		.Z = {.key64 = {
			0x3E572F1B286C5F99ULL,
			0x242CC749AE960E2CULL,
			0xED834E7D10D52628ULL,
			0x424B27C2DBC76CEFULL}
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

	steps = 20;
	X1 = (curve25519_key_t){.key64 = {
		0xD39FBFF82A84F4F8ULL,
		0xBE71C9678D410438ULL,
		0x35417ADFD1E08FE8ULL,
		0x44CC5A78720F42C4ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD39FBFF82A84F4F8ULL,
			0xBE71C9678D410438ULL,
			0x35417ADFD1E08FE8ULL,
			0x44CC5A78720F42C4ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4839164324A75A2EULL,
			0xC2A926EF95B93F30ULL,
			0xC8994BF33837D154ULL,
			0x329F3A73E243A44AULL}
		},
		.Z = {.key64 = {
			0x78389061D9AA7C7BULL,
			0xC78379BF25C05CB4ULL,
			0xB257DAB2BDC3C83BULL,
			0x44C265D1937A8E6AULL}
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

	steps = 62;
	X1 = (curve25519_key_t){.key64 = {
		0x342BC86561C92DF0ULL,
		0x83F102F8B947270FULL,
		0xB642E3979BCE1180ULL,
		0x61FF23CAD86B336FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x342BC86561C92DF0ULL,
			0x83F102F8B947270FULL,
			0xB642E3979BCE1180ULL,
			0x61FF23CAD86B336FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8D49841159ACE175ULL,
			0xE4861CE188EEAE68ULL,
			0x884077BEE5CD2CEBULL,
			0x38C666AF452BF46DULL}
		},
		.Z = {.key64 = {
			0xF43665EBEFE6E086ULL,
			0xC46DA51556AE91B1ULL,
			0x18FEC9FA5D8A5BC3ULL,
			0x48152EB2D4B50DBAULL}
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

	steps = 62;
	X1 = (curve25519_key_t){.key64 = {
		0xF57916FB2708C150ULL,
		0x6B5698D352DD53C2ULL,
		0x44C81562367DB31AULL,
		0x52299D0624EA5060ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF57916FB2708C150ULL,
			0x6B5698D352DD53C2ULL,
			0x44C81562367DB31AULL,
			0x52299D0624EA5060ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x870917D19E43E60AULL,
			0xA9E8B6E56560E89CULL,
			0x33BD13E50C654B20ULL,
			0x128DCD003558CE97ULL}
		},
		.Z = {.key64 = {
			0x9D5C8F5AC01EFC28ULL,
			0xF3647641EF2D88BDULL,
			0xDD9374BC5054B1C2ULL,
			0x54D90E422818C3C6ULL}
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

	steps = 15;
	X1 = (curve25519_key_t){.key64 = {
		0x524729C6418E59D8ULL,
		0x619BAE595AB4A6D1ULL,
		0x15225945C9029492ULL,
		0x581978D3106E335EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x524729C6418E59D8ULL,
			0x619BAE595AB4A6D1ULL,
			0x15225945C9029492ULL,
			0x581978D3106E335EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF8F0BAFCCE7D7215ULL,
			0x5C303DBA8A132E0BULL,
			0xC2B9E09CBC378B9CULL,
			0x17B337C0C78A325CULL}
		},
		.Z = {.key64 = {
			0xB30DE75372A505B8ULL,
			0x3D323E768A4C8489ULL,
			0x9F302E4426E017E4ULL,
			0x0CA425C9EC66411CULL}
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

	steps = 31;
	X1 = (curve25519_key_t){.key64 = {
		0xC8691DA5A90F3400ULL,
		0xF27044BB008FB4D6ULL,
		0x7C9167398F3ADE75ULL,
		0x527D8AAC46F28DA5ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC8691DA5A90F3400ULL,
			0xF27044BB008FB4D6ULL,
			0x7C9167398F3ADE75ULL,
			0x527D8AAC46F28DA5ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x34397F2DB1868F40ULL,
			0xB27EE3DBCC384237ULL,
			0x4666001CA63E60F1ULL,
			0x45640D17F1C7CB16ULL}
		},
		.Z = {.key64 = {
			0x83BE660436C8FFB6ULL,
			0xEBBA1D48913FAA6BULL,
			0x9EAE24A963A8ABFCULL,
			0x75CB5216D169C654ULL}
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

	steps = 39;
	X1 = (curve25519_key_t){.key64 = {
		0x9341A7CDECC33780ULL,
		0xDF5909F225CDA06AULL,
		0xA188C5656C6984D0ULL,
		0x5377E7788CBF3A10ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9341A7CDECC33780ULL,
			0xDF5909F225CDA06AULL,
			0xA188C5656C6984D0ULL,
			0x5377E7788CBF3A10ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF8FC2D80A873F5CEULL,
			0xC09145F7B7333971ULL,
			0x87DFE501D2F551D4ULL,
			0x48E8068A69CC1C3EULL}
		},
		.Z = {.key64 = {
			0x8472E7D381D081B0ULL,
			0x94AD935B2AA056B1ULL,
			0xA7E820E697870994ULL,
			0x6A7EFF77EA59D008ULL}
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

	steps = 15;
	X1 = (curve25519_key_t){.key64 = {
		0x6571046454E08608ULL,
		0xCF7016F9517B7725ULL,
		0x0134DC05A3FA9C3BULL,
		0x77E2BF59EDAC170DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6571046454E08608ULL,
			0xCF7016F9517B7725ULL,
			0x0134DC05A3FA9C3BULL,
			0x77E2BF59EDAC170DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7CFC10CB1BD82C7DULL,
			0x18010D435909DC53ULL,
			0x746CC46639402B11ULL,
			0x63D39021CFC77623ULL}
		},
		.Z = {.key64 = {
			0x1E806071EC15D24FULL,
			0x416D515317265D0FULL,
			0x08A3E8FAB0AB0A26ULL,
			0x7C66CFF0995248A8ULL}
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

	steps = 19;
	X1 = (curve25519_key_t){.key64 = {
		0x899A6C2DCCBA6D48ULL,
		0xA7D9AA178BC653B5ULL,
		0xD5DEBCB2B8BF132BULL,
		0x490A0E7FA12455F6ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x899A6C2DCCBA6D48ULL,
			0xA7D9AA178BC653B5ULL,
			0xD5DEBCB2B8BF132BULL,
			0x490A0E7FA12455F6ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBBA4F6D9AB58C8A5ULL,
			0x236B89174DFA3326ULL,
			0xABFC0CAE66CA36C3ULL,
			0x6E062B10EE7B2925ULL}
		},
		.Z = {.key64 = {
			0x40BE8C2DD5F1F006ULL,
			0x8DEDC700BC2DD539ULL,
			0xEFDD90A72AF14613ULL,
			0x07AD3ACB7304DF10ULL}
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

	steps = 23;
	X1 = (curve25519_key_t){.key64 = {
		0x7AB9D193196C4040ULL,
		0x05BA6AC90591A383ULL,
		0xA1FC4C13DC8555E3ULL,
		0x477389ADBA1A03C3ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7AB9D193196C4040ULL,
			0x05BA6AC90591A383ULL,
			0xA1FC4C13DC8555E3ULL,
			0x477389ADBA1A03C3ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD05190796F52670DULL,
			0x72973E40669737DAULL,
			0x68FF19ECB283ADF3ULL,
			0x606A61A21C352AFDULL}
		},
		.Z = {.key64 = {
			0x519C6EE263D740E8ULL,
			0xB443C6D87A886400ULL,
			0xEC680C05D8BFE96DULL,
			0x445F9E2EC666F2BEULL}
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

	steps = 62;
	X1 = (curve25519_key_t){.key64 = {
		0x4627CFACF0FC0DC8ULL,
		0xBFC4B7BA8B9F1BB0ULL,
		0xAF4F6C566E0E8849ULL,
		0x612FBFAE09040CADULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4627CFACF0FC0DC8ULL,
			0xBFC4B7BA8B9F1BB0ULL,
			0xAF4F6C566E0E8849ULL,
			0x612FBFAE09040CADULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0931EE4D4667265AULL,
			0x20B5EEC48C96A2EAULL,
			0x870A7077FC6D4C74ULL,
			0x0FA636772A5ADB5BULL}
		},
		.Z = {.key64 = {
			0xBA4127530752B76EULL,
			0x74CCEE4975A999E4ULL,
			0xD3307D25A8C77C05ULL,
			0x7092AC3044EA665FULL}
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

	steps = 16;
	X1 = (curve25519_key_t){.key64 = {
		0xFE3C63BCE5842198ULL,
		0xB1E2EC8A0A7E723CULL,
		0x897943253B943D14ULL,
		0x6BB9A66BA86043DEULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFE3C63BCE5842198ULL,
			0xB1E2EC8A0A7E723CULL,
			0x897943253B943D14ULL,
			0x6BB9A66BA86043DEULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7F8B2E209497FC51ULL,
			0xBD7A501A5870BE99ULL,
			0xBAB58BB7FB5019E9ULL,
			0x649257AC1151742BULL}
		},
		.Z = {.key64 = {
			0x98B155C3B3971C29ULL,
			0xA52193C149697637ULL,
			0xB449B7A7740940ACULL,
			0x4FB5458B3A6A5D87ULL}
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

	steps = 2;
	X1 = (curve25519_key_t){.key64 = {
		0x41EEC6B4E775E740ULL,
		0x40293D9FC7FEE43AULL,
		0x256B631D5612EF58ULL,
		0x777E71F80CEA05A7ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x41EEC6B4E775E740ULL,
			0x40293D9FC7FEE43AULL,
			0x256B631D5612EF58ULL,
			0x777E71F80CEA05A7ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC911A1EF61DFDAEAULL,
			0xE791F3D5E78BDB39ULL,
			0xD945EC06F7751DCCULL,
			0x2B3D42B5FC8F1A1CULL}
		},
		.Z = {.key64 = {
			0x25DACB9C2CF9CF05ULL,
			0xE282902547EB2F57ULL,
			0xCC2908EBD91E1E88ULL,
			0x0F85ED9B9B1BE891ULL}
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

	steps = 30;
	X1 = (curve25519_key_t){.key64 = {
		0x1EC7DF64F7BCDBD8ULL,
		0x6A2A2BFCE91BE5BDULL,
		0x79CDCA64085CFB8FULL,
		0x40D52821FCAB4E74ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1EC7DF64F7BCDBD8ULL,
			0x6A2A2BFCE91BE5BDULL,
			0x79CDCA64085CFB8FULL,
			0x40D52821FCAB4E74ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD4E57D2F852B9E83ULL,
			0xC46F1FAEF956D7FEULL,
			0xE8AC20CD325D504FULL,
			0x578A22AA302566D5ULL}
		},
		.Z = {.key64 = {
			0xA1BB62DDF4500B21ULL,
			0x40ADABCE2953CE30ULL,
			0xCEEF9E80EA7F62A7ULL,
			0x541238EA76C25A2BULL}
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

	steps = 26;
	X1 = (curve25519_key_t){.key64 = {
		0x21EC62AD0A6B77B8ULL,
		0x296B122495689EDBULL,
		0xADE76100EA8E01A2ULL,
		0x4B6FD2E6CF8146E9ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x21EC62AD0A6B77B8ULL,
			0x296B122495689EDBULL,
			0xADE76100EA8E01A2ULL,
			0x4B6FD2E6CF8146E9ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x86EF280FB531BEEDULL,
			0x6538E1501E7D2987ULL,
			0x35E6F2650521C115ULL,
			0x090A087211A1589FULL}
		},
		.Z = {.key64 = {
			0x2D6C08E7E08ED306ULL,
			0x6AA9EC8F1B1E68BDULL,
			0xF8F683D8163FC130ULL,
			0x687E2C443D77746AULL}
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
		0x95ECF4FDAE96FC58ULL,
		0xEC484942997B7370ULL,
		0x0DE805777B846BD0ULL,
		0x708FF3B08D17074CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x95ECF4FDAE96FC58ULL,
			0xEC484942997B7370ULL,
			0x0DE805777B846BD0ULL,
			0x708FF3B08D17074CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x402441C2BE589C6EULL,
			0xECB50D39E424E013ULL,
			0x4690B4E522B7C26BULL,
			0x057038BBB8027CF4ULL}
		},
		.Z = {.key64 = {
			0xF1FC5AC5E5681B03ULL,
			0x75E03EA83B83175EULL,
			0xFCEA13263EEBF4C5ULL,
			0x0D830F751EE52E05ULL}
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

	steps = 43;
	X1 = (curve25519_key_t){.key64 = {
		0xD4C20C6B163DA6F8ULL,
		0x831FB6F0E3807162ULL,
		0x80D722913CDEFE67ULL,
		0x44FADA52C8877746ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD4C20C6B163DA6F8ULL,
			0x831FB6F0E3807162ULL,
			0x80D722913CDEFE67ULL,
			0x44FADA52C8877746ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x45E704F787198677ULL,
			0x90922B504B398846ULL,
			0xBF9B5F36A6370D48ULL,
			0x4179ACDB7D54DDCAULL}
		},
		.Z = {.key64 = {
			0xED8ABEC996DBB98EULL,
			0x8989DB9B1366AA44ULL,
			0xCFE6BA2BC9A12404ULL,
			0x79844BB8CB72A46DULL}
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

	steps = 5;
	X1 = (curve25519_key_t){.key64 = {
		0xED1D9AA0B1A02FA0ULL,
		0x9275FDB0E65919FBULL,
		0xE155D7D6AC0035A2ULL,
		0x4EEEE255CC7C0A69ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xED1D9AA0B1A02FA0ULL,
			0x9275FDB0E65919FBULL,
			0xE155D7D6AC0035A2ULL,
			0x4EEEE255CC7C0A69ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xED2A5129A1D1A432ULL,
			0xD81915F64AEF6130ULL,
			0x89E1A13C51D0D685ULL,
			0x51029C6D62682A61ULL}
		},
		.Z = {.key64 = {
			0x85ECFCFF2B369DC4ULL,
			0x9254A73E8CE013C5ULL,
			0x513BAB8A02AFDD39ULL,
			0x5E599B9C53DBCAD3ULL}
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

	steps = 32;
	X1 = (curve25519_key_t){.key64 = {
		0x6952DBC6A74AA1A8ULL,
		0x61B4DBFA68620969ULL,
		0x7156307C9A9C9370ULL,
		0x5EF15E1B7110AEDCULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6952DBC6A74AA1A8ULL,
			0x61B4DBFA68620969ULL,
			0x7156307C9A9C9370ULL,
			0x5EF15E1B7110AEDCULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3C09A4D7EFF65C8CULL,
			0x2A96EB5E147B6D47ULL,
			0xF64412035FA2F01FULL,
			0x4C1E8432F6C59E97ULL}
		},
		.Z = {.key64 = {
			0x92C327508917BB16ULL,
			0x9D13AE45BFB34F4CULL,
			0x1064007721072D95ULL,
			0x253DAD6284187D5DULL}
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

	steps = 55;
	X1 = (curve25519_key_t){.key64 = {
		0x74437D323F7BE328ULL,
		0xCF37BFFA2FF28CABULL,
		0x165F61FA1D8E1D3DULL,
		0x423EC3069BC64E60ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x74437D323F7BE328ULL,
			0xCF37BFFA2FF28CABULL,
			0x165F61FA1D8E1D3DULL,
			0x423EC3069BC64E60ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x80B511BCA28ED357ULL,
			0x397DCA429088657FULL,
			0x78F9D3808AE922E5ULL,
			0x3278831704BD64D6ULL}
		},
		.Z = {.key64 = {
			0x4D7A395E9307C921ULL,
			0xF2800BCE38F643CAULL,
			0xF7A7ABAEB7ED1541ULL,
			0x0C77B5EFC9E7157AULL}
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

	steps = 54;
	X1 = (curve25519_key_t){.key64 = {
		0x871B76BCB62066B0ULL,
		0xF7D60A2F8E59A4FDULL,
		0x3B0F86C16A78C0DAULL,
		0x568E132E63E0289FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x871B76BCB62066B0ULL,
			0xF7D60A2F8E59A4FDULL,
			0x3B0F86C16A78C0DAULL,
			0x568E132E63E0289FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5DAA9E2A64F8804BULL,
			0x104CA865BEE6F6BEULL,
			0x1F342B29B738EC95ULL,
			0x66E3B4B91861A604ULL}
		},
		.Z = {.key64 = {
			0x1BB276E452B5F66EULL,
			0x3846788C101FD6BBULL,
			0xE90DBE213B9AAB5DULL,
			0x7DD9949E5849C496ULL}
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

	steps = 15;
	X1 = (curve25519_key_t){.key64 = {
		0x93C67A2D9988FB60ULL,
		0x8DACEED1E5684BE8ULL,
		0x0FCD1776ADA344CAULL,
		0x50445801D0A0F35DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x93C67A2D9988FB60ULL,
			0x8DACEED1E5684BE8ULL,
			0x0FCD1776ADA344CAULL,
			0x50445801D0A0F35DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x413100079284CCBDULL,
			0xC81A9DFF5673DBDAULL,
			0xF3040F892694070DULL,
			0x08E566E18B767798ULL}
		},
		.Z = {.key64 = {
			0xF22785BFA1F9FFE9ULL,
			0x4F304CA0F8C37253ULL,
			0xB7C3544728A53600ULL,
			0x22562D283BBADD68ULL}
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

	steps = 54;
	X1 = (curve25519_key_t){.key64 = {
		0x7F4DE0971C450BA0ULL,
		0xF0FFD954C3CF0CBDULL,
		0x9428F553605CCF38ULL,
		0x7D7B5ACF7C04F09FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7F4DE0971C450BA0ULL,
			0xF0FFD954C3CF0CBDULL,
			0x9428F553605CCF38ULL,
			0x7D7B5ACF7C04F09FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB129BD5654B02D87ULL,
			0x2FB2E740B7FC56D3ULL,
			0x14AB4B981FBF0212ULL,
			0x2A505E9CB2C6B50EULL}
		},
		.Z = {.key64 = {
			0x9DA306EBB6B45DECULL,
			0xFF241C4F86211576ULL,
			0xC8146758FD2A5F58ULL,
			0x7F5B6DB76C976520ULL}
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

	steps = 7;
	X1 = (curve25519_key_t){.key64 = {
		0x9E9ACCF4B2C8A768ULL,
		0x094EA74172A7A4BFULL,
		0x64A7BF0FE58782E3ULL,
		0x7A0C7854D5B44EE0ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9E9ACCF4B2C8A768ULL,
			0x094EA74172A7A4BFULL,
			0x64A7BF0FE58782E3ULL,
			0x7A0C7854D5B44EE0ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC1D5163663ACB8BBULL,
			0x03A539CD575F95CFULL,
			0xF3F477FE16C84361ULL,
			0x2C2460910D291B4EULL}
		},
		.Z = {.key64 = {
			0xE6E2CAB7AEFFDA55ULL,
			0x40819FC931560ABCULL,
			0xAB698708B55C9196ULL,
			0x51A12C45304EEB25ULL}
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

	steps = 29;
	X1 = (curve25519_key_t){.key64 = {
		0x312A108585325968ULL,
		0x2E2D991FCAE31F4EULL,
		0xFFC713A449696C77ULL,
		0x48A334DEB54DCEB9ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x312A108585325968ULL,
			0x2E2D991FCAE31F4EULL,
			0xFFC713A449696C77ULL,
			0x48A334DEB54DCEB9ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD8D94F27922FE39CULL,
			0xE3D29C530ECA11D7ULL,
			0xF040F212CD14C7C7ULL,
			0x493E763C87020544ULL}
		},
		.Z = {.key64 = {
			0x064EF67DF20F6529ULL,
			0x68B0A7D37DC31075ULL,
			0x4540DF57C7BC76A4ULL,
			0x4B1225CC9DB552CDULL}
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

	steps = 7;
	X1 = (curve25519_key_t){.key64 = {
		0xD32DF36EB4230310ULL,
		0x6B04E2D6250950F4ULL,
		0x3F75052EA8E2A5CDULL,
		0x74BFEA018B5368FCULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD32DF36EB4230310ULL,
			0x6B04E2D6250950F4ULL,
			0x3F75052EA8E2A5CDULL,
			0x74BFEA018B5368FCULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA43C82AF39DD7862ULL,
			0xCBBF4E0DBC156278ULL,
			0x87060CB3D4BAE76EULL,
			0x17F4C57FF5AAB8B5ULL}
		},
		.Z = {.key64 = {
			0x3B276963FA9A8B89ULL,
			0xED81081C14302871ULL,
			0x263BCA5B91650695ULL,
			0x7AF5C875F831016AULL}
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

	steps = 45;
	X1 = (curve25519_key_t){.key64 = {
		0x13FEB6AFCEA20D48ULL,
		0xBE9553B10E4ABFADULL,
		0x89F054F2D4C9EE0BULL,
		0x532705776D11A7EBULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x13FEB6AFCEA20D48ULL,
			0xBE9553B10E4ABFADULL,
			0x89F054F2D4C9EE0BULL,
			0x532705776D11A7EBULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD330314740CF1F33ULL,
			0x4583A831D8CA05FBULL,
			0xB86007FB1103D074ULL,
			0x0A9C879F40B13FD5ULL}
		},
		.Z = {.key64 = {
			0xCB1D2C473F71973CULL,
			0x86115A7BC4CE514FULL,
			0xED814B761AFB68CEULL,
			0x2F2EEE2C5A0380ABULL}
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

	steps = 40;
	X1 = (curve25519_key_t){.key64 = {
		0x39C14B52E95F8790ULL,
		0xBA06940E34C4554AULL,
		0xF6C4B42EAF0E2631ULL,
		0x4DE44F7DD9E47FDEULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x39C14B52E95F8790ULL,
			0xBA06940E34C4554AULL,
			0xF6C4B42EAF0E2631ULL,
			0x4DE44F7DD9E47FDEULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDF634FC0A09F6785ULL,
			0xB268D13FF75DD221ULL,
			0x46807369F3002030ULL,
			0x69E1401A0968618FULL}
		},
		.Z = {.key64 = {
			0xEB485320D7F8BCC0ULL,
			0xDC91DEA24086B851ULL,
			0x17D75819D8C8D63AULL,
			0x2523741AF9F3AD13ULL}
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

	steps = 58;
	X1 = (curve25519_key_t){.key64 = {
		0x592758F0ED4B7228ULL,
		0x298A8536F64E66EBULL,
		0x461E05139E1313A6ULL,
		0x538045D4426BF10DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x592758F0ED4B7228ULL,
			0x298A8536F64E66EBULL,
			0x461E05139E1313A6ULL,
			0x538045D4426BF10DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE373AB5E7D2067D4ULL,
			0xEB05C99B4A2800C7ULL,
			0xF6C84873DAF312F7ULL,
			0x4F9329101EFA3B0FULL}
		},
		.Z = {.key64 = {
			0xDF57F6C06733B897ULL,
			0xDAD8BC523847BCBCULL,
			0xF6CB0006955975FEULL,
			0x3933705B59B23279ULL}
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

	steps = 63;
	X1 = (curve25519_key_t){.key64 = {
		0x225A16BA6B8752F0ULL,
		0xCE280F8AE36627F3ULL,
		0xDE399A19F31F55F1ULL,
		0x65284ACCFC74AB10ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x225A16BA6B8752F0ULL,
			0xCE280F8AE36627F3ULL,
			0xDE399A19F31F55F1ULL,
			0x65284ACCFC74AB10ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1893A748EE8393CAULL,
			0xDAE1D6C9DEF776DEULL,
			0x478D4FDFEE9D1878ULL,
			0x6A2BE2596932F037ULL}
		},
		.Z = {.key64 = {
			0x51417CB1F0672725ULL,
			0xAF8F7742B2F6F395ULL,
			0x8812695E599AC904ULL,
			0x69E186B43E12E102ULL}
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

	steps = 7;
	X1 = (curve25519_key_t){.key64 = {
		0x8B77B62056DB3E30ULL,
		0x09FFA79F3D3485FDULL,
		0x5B44C08CC840CD0AULL,
		0x40112E4E8648EC80ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8B77B62056DB3E30ULL,
			0x09FFA79F3D3485FDULL,
			0x5B44C08CC840CD0AULL,
			0x40112E4E8648EC80ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6E3E661E13861D2BULL,
			0x3D121EBF23CEFD14ULL,
			0x18B74C61F6125455ULL,
			0x585327FC9EDBA672ULL}
		},
		.Z = {.key64 = {
			0xDEEEBE5454065FDEULL,
			0x82D2103581D0330DULL,
			0x2CCB926ADE570022ULL,
			0x0025DDFD359A28C0ULL}
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

	steps = 18;
	X1 = (curve25519_key_t){.key64 = {
		0x0F059AD3739BB780ULL,
		0x3B1E5951C84DAFDBULL,
		0x6655FBC61BEC6322ULL,
		0x4B1420027D805098ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0F059AD3739BB780ULL,
			0x3B1E5951C84DAFDBULL,
			0x6655FBC61BEC6322ULL,
			0x4B1420027D805098ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x97BE01F7B98D05E2ULL,
			0x4118D80521E075C8ULL,
			0x08950FAF3849224EULL,
			0x5F47CC23C653D086ULL}
		},
		.Z = {.key64 = {
			0x00B0958A1E71A4E5ULL,
			0x38FB5B32AF8490CFULL,
			0xAF84345CB3B0B670ULL,
			0x0C2D9B398015F3DBULL}
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
		0xEACE7A4150C57F30ULL,
		0xC7951D3A51E98442ULL,
		0x807C88AB96B6E852ULL,
		0x5DAE2550725E1646ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEACE7A4150C57F30ULL,
			0xC7951D3A51E98442ULL,
			0x807C88AB96B6E852ULL,
			0x5DAE2550725E1646ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x02B81F2068C705B4ULL,
			0xF313AD7DD6A8AC74ULL,
			0x5F94E383E88A28BFULL,
			0x046F08499BE6B222ULL}
		},
		.Z = {.key64 = {
			0xAB39E9054315FCE6ULL,
			0x1E5474E947A6110BULL,
			0x01F222AE5ADBA14BULL,
			0x76B89541C978591AULL}
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

	steps = 49;
	X1 = (curve25519_key_t){.key64 = {
		0x2806EDC8A9C92778ULL,
		0xB19F89ED03B58388ULL,
		0xF978B8CC7E43D157ULL,
		0x5186E49CF304E9DDULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2806EDC8A9C92778ULL,
			0xB19F89ED03B58388ULL,
			0xF978B8CC7E43D157ULL,
			0x5186E49CF304E9DDULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x88BD59C59C314DC4ULL,
			0xDBC3C52C4F25A291ULL,
			0x4973C7EA4C2B2E7BULL,
			0x078A7AC6CC2388F0ULL}
		},
		.Z = {.key64 = {
			0xD191D5025C865137ULL,
			0x86A5C77F6B1183E7ULL,
			0x3327ADBBF25A56EFULL,
			0x242BC7223013F831ULL}
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

	steps = 52;
	X1 = (curve25519_key_t){.key64 = {
		0x9164EB261A4A5C00ULL,
		0x13BBC36ECFA8D233ULL,
		0xEFE4ECEF26CF4104ULL,
		0x5109B43F6EF6EB05ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9164EB261A4A5C00ULL,
			0x13BBC36ECFA8D233ULL,
			0xEFE4ECEF26CF4104ULL,
			0x5109B43F6EF6EB05ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x80F1DD73DC0BAD84ULL,
			0x397B2A673AE25DBAULL,
			0xA098B851D4B1DF0FULL,
			0x399B1DC3A1C9373DULL}
		},
		.Z = {.key64 = {
			0x39E0EE13C0897CF6ULL,
			0xC32003745353DF51ULL,
			0xFFF7C2C5E1AC615EULL,
			0x5D9A81D474AFC674ULL}
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

	steps = 56;
	X1 = (curve25519_key_t){.key64 = {
		0x97D60442BB71BAA0ULL,
		0x6ECBEC434A355E26ULL,
		0xE83BA4378607FB6FULL,
		0x62FE11BD7C9792A6ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x97D60442BB71BAA0ULL,
			0x6ECBEC434A355E26ULL,
			0xE83BA4378607FB6FULL,
			0x62FE11BD7C9792A6ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x22F10B1EA03A6BF6ULL,
			0x4B9986A6CD847ABAULL,
			0x3E4EA39B12B25480ULL,
			0x00095B5FC10A5D18ULL}
		},
		.Z = {.key64 = {
			0x4DB8DCF05C11A58EULL,
			0x8074896867C97FEEULL,
			0x5F7440E82BB1A903ULL,
			0x14618E0DA0B090F8ULL}
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

	steps = 30;
	X1 = (curve25519_key_t){.key64 = {
		0xD2BC995CBD651DA0ULL,
		0xA45B930E8F73F0C2ULL,
		0xC8C39150ACFED589ULL,
		0x7CBD580F2C3DAA11ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD2BC995CBD651DA0ULL,
			0xA45B930E8F73F0C2ULL,
			0xC8C39150ACFED589ULL,
			0x7CBD580F2C3DAA11ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x60029299C48528A5ULL,
			0xCC07A1B752C3C1E0ULL,
			0x75DBB979A7A16A3DULL,
			0x1FD0FFDBE6963BDDULL}
		},
		.Z = {.key64 = {
			0x942393C9F17789A1ULL,
			0x793D66897773CF91ULL,
			0x499A3D15EFE52346ULL,
			0x323CAB3D3B047FC0ULL}
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

	steps = 64;
	X1 = (curve25519_key_t){.key64 = {
		0x2DAA38FC48D59A88ULL,
		0x5855296C070FFA45ULL,
		0xFF6FCB932D8A1777ULL,
		0x441B6D82907DAA16ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2DAA38FC48D59A88ULL,
			0x5855296C070FFA45ULL,
			0xFF6FCB932D8A1777ULL,
			0x441B6D82907DAA16ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCE49169A96906697ULL,
			0x12A77CBDA6559CECULL,
			0x4B00E92DB41065B8ULL,
			0x78AED9350DD8C7B9ULL}
		},
		.Z = {.key64 = {
			0xCB27D75108D6E39EULL,
			0x2DC88BD113B24923ULL,
			0x864CCC711D11900EULL,
			0x60A1A10F9DF69E8AULL}
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

	steps = 33;
	X1 = (curve25519_key_t){.key64 = {
		0x039F782D734CF128ULL,
		0xADFD5DB617CDCA01ULL,
		0x2984B2A4460867CDULL,
		0x505D4F93FC8B120FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x039F782D734CF128ULL,
			0xADFD5DB617CDCA01ULL,
			0x2984B2A4460867CDULL,
			0x505D4F93FC8B120FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD93052FD9B6CF6F1ULL,
			0x3CC6A0C89AEF2A44ULL,
			0xD6B28FB34191C6F6ULL,
			0x6F16367973F24F52ULL}
		},
		.Z = {.key64 = {
			0x77935A81E5B46D6BULL,
			0x8D0C65AE562C54CDULL,
			0x4B9E9ED12CC8CD27ULL,
			0x24BC29645DB3FAB6ULL}
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

	steps = 6;
	X1 = (curve25519_key_t){.key64 = {
		0xB01FDFF3C2908B10ULL,
		0x2FAF55C576A21133ULL,
		0x405B0F3BB82608A0ULL,
		0x7B56DBD485690076ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB01FDFF3C2908B10ULL,
			0x2FAF55C576A21133ULL,
			0x405B0F3BB82608A0ULL,
			0x7B56DBD485690076ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x936D750DBCFE0BA1ULL,
			0x3F0D06EB5E9B5AC9ULL,
			0x75A997F204DD00DBULL,
			0x66521C95D931EB0FULL}
		},
		.Z = {.key64 = {
			0x67AEC51FAFC3F5F8ULL,
			0xE9ED262D9990B1D4ULL,
			0x813B77D25B39F8EEULL,
			0x78A02ED65204CD85ULL}
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

	steps = 59;
	X1 = (curve25519_key_t){.key64 = {
		0x196E594ECBB78BF8ULL,
		0x84E4C25A7610E554ULL,
		0xAE15B6F077539121ULL,
		0x6CAA64AF64F5BD3DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x196E594ECBB78BF8ULL,
			0x84E4C25A7610E554ULL,
			0xAE15B6F077539121ULL,
			0x6CAA64AF64F5BD3DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x781DAE1503932FD9ULL,
			0x12CF054A787182BDULL,
			0xF2A18053D88DCF0BULL,
			0x716CB84ADA356A2BULL}
		},
		.Z = {.key64 = {
			0x6701D2BC47D60F29ULL,
			0xF7709C740C2BE601ULL,
			0x8F624ED46FBB6E3BULL,
			0x647B4D6517D325C9ULL}
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

	steps = 16;
	X1 = (curve25519_key_t){.key64 = {
		0xC5AA9E8D7C51EC28ULL,
		0x75634C789A8EF4D1ULL,
		0x0B54DF8148E26098ULL,
		0x58C508F954DFD7B9ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC5AA9E8D7C51EC28ULL,
			0x75634C789A8EF4D1ULL,
			0x0B54DF8148E26098ULL,
			0x58C508F954DFD7B9ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x720A4DAEE90308C2ULL,
			0x56B15E1F7287F196ULL,
			0xFE292DCDC5626393ULL,
			0x4C947E17902D7F56ULL}
		},
		.Z = {.key64 = {
			0x3A0E23168EEC2169ULL,
			0x1C5A8CA1FC488B71ULL,
			0x55FDF8F9C6FEC398ULL,
			0x31B2DD85FAC5E70DULL}
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

	steps = 64;
	X1 = (curve25519_key_t){.key64 = {
		0x53A9ABD9E8D365E8ULL,
		0xD3706B7EF6C57A48ULL,
		0x8DD6CF2C753581E0ULL,
		0x4D656447168673AFULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x53A9ABD9E8D365E8ULL,
			0xD3706B7EF6C57A48ULL,
			0x8DD6CF2C753581E0ULL,
			0x4D656447168673AFULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x26AF99915A471B05ULL,
			0xEBBF5A7CF02D5BB5ULL,
			0x98F5A8A7B249F9D4ULL,
			0x05686D0C2FD90618ULL}
		},
		.Z = {.key64 = {
			0xDDA9D5A5AD429E52ULL,
			0x323EDAEA61BFFB57ULL,
			0x89262524BB147BF8ULL,
			0x7EC37C3C15B459C2ULL}
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

	steps = 16;
	X1 = (curve25519_key_t){.key64 = {
		0x105F0D0F34FB5A98ULL,
		0xA035F560FA90DB75ULL,
		0x741D52852A06BC8CULL,
		0x711A0523982C04A2ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x105F0D0F34FB5A98ULL,
			0xA035F560FA90DB75ULL,
			0x741D52852A06BC8CULL,
			0x711A0523982C04A2ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3AA6530FEF5ADD19ULL,
			0x9AB00AC09694ED84ULL,
			0x1EB9B8717CEF157DULL,
			0x66779D9ADF44D35BULL}
		},
		.Z = {.key64 = {
			0x2EAC4DF5755205FCULL,
			0x000F0AEBCD44DB18ULL,
			0xC35DE550A42E9D98ULL,
			0x39336CE2EFA50B80ULL}
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

	steps = 30;
	X1 = (curve25519_key_t){.key64 = {
		0xEC7A8A3F8A7DD7B8ULL,
		0x6D0457E2F1C7B362ULL,
		0xE857CF061FC16687ULL,
		0x41E93FBA0786DF76ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEC7A8A3F8A7DD7B8ULL,
			0x6D0457E2F1C7B362ULL,
			0xE857CF061FC16687ULL,
			0x41E93FBA0786DF76ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x57E0F4B1147FF97AULL,
			0x7CF9F514D4AE3C30ULL,
			0xEB71B8C98799F8F2ULL,
			0x40EED66D598EB3A5ULL}
		},
		.Z = {.key64 = {
			0x0EA4E71B3EC8C751ULL,
			0x63BFFE22B2C869BFULL,
			0xC1F68723861B0204ULL,
			0x0F987707D4E224D2ULL}
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

	steps = 24;
	X1 = (curve25519_key_t){.key64 = {
		0x58BE8CF9080509B0ULL,
		0xEEACE634BE99541AULL,
		0x9899D09677DE8B67ULL,
		0x58306229DF067F6AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x58BE8CF9080509B0ULL,
			0xEEACE634BE99541AULL,
			0x9899D09677DE8B67ULL,
			0x58306229DF067F6AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x59EB995DD2B9B942ULL,
			0x88CA5C6C0BDD41ACULL,
			0x629A79035FD8DB5DULL,
			0x64BA4DC8F9E45B96ULL}
		},
		.Z = {.key64 = {
			0xF950F89CEC1EF36EULL,
			0xE5D9566F23778282ULL,
			0x40CEF8030AF64C7FULL,
			0x103C32B430B20AD5ULL}
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

	steps = 14;
	X1 = (curve25519_key_t){.key64 = {
		0xBE3F0D3F7276D7E0ULL,
		0xCD93953335D2911CULL,
		0xB8D43C7F72975E1DULL,
		0x7A5862B9EF785F5CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBE3F0D3F7276D7E0ULL,
			0xCD93953335D2911CULL,
			0xB8D43C7F72975E1DULL,
			0x7A5862B9EF785F5CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEC464B7E3E514F6EULL,
			0x129DB4E777697087ULL,
			0x316EA5E8DBB5C923ULL,
			0x2C3162BE6617A6D4ULL}
		},
		.Z = {.key64 = {
			0x371438C46DB4CC61ULL,
			0x7C3C58DB7E61A9B8ULL,
			0x2E3D1F29C0C47982ULL,
			0x5A190C8831A4B959ULL}
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

	steps = 19;
	X1 = (curve25519_key_t){.key64 = {
		0xDC9F372C0D0D3F90ULL,
		0x4AD30FCFFC723E4EULL,
		0x9093A1C91EA20AFEULL,
		0x511A3B34E213AFAFULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDC9F372C0D0D3F90ULL,
			0x4AD30FCFFC723E4EULL,
			0x9093A1C91EA20AFEULL,
			0x511A3B34E213AFAFULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDA3940B36D4B7452ULL,
			0x018C817EDF186452ULL,
			0x2A119F8E36E8E5CFULL,
			0x1A45F966972AE54CULL}
		},
		.Z = {.key64 = {
			0xD0114C6DA72D05A0ULL,
			0x88AF485F8E463FC0ULL,
			0x48B80F042E3CBDA7ULL,
			0x68896F3CC0794DC4ULL}
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

	steps = 12;
	X1 = (curve25519_key_t){.key64 = {
		0x2AB5473E32BE0A20ULL,
		0xA3E875D2A332E586ULL,
		0x7FF186E3DC1758D1ULL,
		0x6CA5D8D0E9863066ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2AB5473E32BE0A20ULL,
			0xA3E875D2A332E586ULL,
			0x7FF186E3DC1758D1ULL,
			0x6CA5D8D0E9863066ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x48168F93A460AC63ULL,
			0x651303EDCE9B6289ULL,
			0xF295C39282A12141ULL,
			0x664B8C271EF747AAULL}
		},
		.Z = {.key64 = {
			0x841F990127957224ULL,
			0xBD857037F512AF49ULL,
			0x4B281CDF74DAC8FDULL,
			0x2282160738115BB4ULL}
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

	steps = 21;
	X1 = (curve25519_key_t){.key64 = {
		0xCC7B5B9C43A85118ULL,
		0x4256F32F5907189DULL,
		0x3C0963D5709B8989ULL,
		0x4AFB942C2E9F952AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCC7B5B9C43A85118ULL,
			0x4256F32F5907189DULL,
			0x3C0963D5709B8989ULL,
			0x4AFB942C2E9F952AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x693C1FF61F28A7B0ULL,
			0xD37CA4D627EFCAAAULL,
			0x37BF9BB0F5277E8AULL,
			0x1D063403338DD5A5ULL}
		},
		.Z = {.key64 = {
			0x412F7B24FA000B6DULL,
			0x68B70D475256C27BULL,
			0x81F3B0C12486F5FCULL,
			0x5EEDD62BA9323969ULL}
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

	steps = 58;
	X1 = (curve25519_key_t){.key64 = {
		0x7FE759833EF900F8ULL,
		0x0721A52C102C7E49ULL,
		0xD86CF56D1B1DFE1CULL,
		0x6628BE5286874F32ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7FE759833EF900F8ULL,
			0x0721A52C102C7E49ULL,
			0xD86CF56D1B1DFE1CULL,
			0x6628BE5286874F32ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAA81F0FC4D979EDEULL,
			0xEB3AB1D12FCFBA68ULL,
			0x55DA4573F5B77CFFULL,
			0x0778314818197DB3ULL}
		},
		.Z = {.key64 = {
			0x2145E20E154217DFULL,
			0x5FC0E42B1E85C560ULL,
			0xBEA240D47F2FBBECULL,
			0x4E38BC2F44428F68ULL}
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

	steps = 17;
	X1 = (curve25519_key_t){.key64 = {
		0x8214E4563DE706C8ULL,
		0xD396A84AD43FF2F2ULL,
		0x8D1F0D25AF6BD9F1ULL,
		0x6CC29E747E2EBD86ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8214E4563DE706C8ULL,
			0xD396A84AD43FF2F2ULL,
			0x8D1F0D25AF6BD9F1ULL,
			0x6CC29E747E2EBD86ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4C7643E5FB6A1137ULL,
			0x8095715D9ECD2366ULL,
			0xA79E44D75D18A933ULL,
			0x432CF5D965D44C45ULL}
		},
		.Z = {.key64 = {
			0x79AB710C2F2BCEFBULL,
			0x591882436ACB2480ULL,
			0xF5DEA357183D376CULL,
			0x1B5036004D0719E7ULL}
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

	steps = 33;
	X1 = (curve25519_key_t){.key64 = {
		0x544F6146BC583A00ULL,
		0xAF70B1DF12AA27DCULL,
		0xBC853DAD306D1880ULL,
		0x41887B8F7056B5D4ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x544F6146BC583A00ULL,
			0xAF70B1DF12AA27DCULL,
			0xBC853DAD306D1880ULL,
			0x41887B8F7056B5D4ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9E2A042EB8F99926ULL,
			0xAC0C8E2AB6E367D7ULL,
			0xA94B21EE52365CA3ULL,
			0x540A2A13CA0A782CULL}
		},
		.Z = {.key64 = {
			0x65C8EBD5071B964CULL,
			0x06E2865949F8FFF6ULL,
			0x3DD6F9140CD1A361ULL,
			0x0375C0787DA4CAA1ULL}
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

	steps = 40;
	X1 = (curve25519_key_t){.key64 = {
		0x94B5F99E8E0C2500ULL,
		0x449C716BB7C88036ULL,
		0xBFFB84C230724DDDULL,
		0x6D26ED9AA48037DBULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x94B5F99E8E0C2500ULL,
			0x449C716BB7C88036ULL,
			0xBFFB84C230724DDDULL,
			0x6D26ED9AA48037DBULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB0F20FE2BC1F30FEULL,
			0xF0FF80BE81E7CBC0ULL,
			0x8F018203BB386D94ULL,
			0x712537F148886674ULL}
		},
		.Z = {.key64 = {
			0xDF16CF96ACF9CD41ULL,
			0x549E429E8557D0E1ULL,
			0x953568390EA5DDC6ULL,
			0x51D00AC4CBC3CB3AULL}
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

	steps = 11;
	X1 = (curve25519_key_t){.key64 = {
		0x6FD56732E12DB948ULL,
		0x93E25BA514D3E490ULL,
		0xFFB86ED602498B0BULL,
		0x6D7D9373DF4B025AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6FD56732E12DB948ULL,
			0x93E25BA514D3E490ULL,
			0xFFB86ED602498B0BULL,
			0x6D7D9373DF4B025AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8449ACA6201CA6C4ULL,
			0x89E25317A463724DULL,
			0xD0859CCE2DCFF23DULL,
			0x5B3CE7E4533BF00BULL}
		},
		.Z = {.key64 = {
			0x53F6939EECCB9CCBULL,
			0x02B9BC758979F3EDULL,
			0xB5114B026309D43FULL,
			0x72378E2C868E7B2CULL}
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

	steps = 42;
	X1 = (curve25519_key_t){.key64 = {
		0x5F920411599C4248ULL,
		0x7A201889CAAB4D66ULL,
		0xE0E166682EC28FE7ULL,
		0x52367172DCEE2C13ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5F920411599C4248ULL,
			0x7A201889CAAB4D66ULL,
			0xE0E166682EC28FE7ULL,
			0x52367172DCEE2C13ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x44C80A0F1A044DE8ULL,
			0xB0FBBD437FEDEB4FULL,
			0x547E7B61A1410E8BULL,
			0x6D29E142E288B293ULL}
		},
		.Z = {.key64 = {
			0x4BAC5CC494B564A5ULL,
			0x6A3716C1E165E815ULL,
			0x483B1670429503EEULL,
			0x7F633C9A0B48DE98ULL}
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

	steps = 46;
	X1 = (curve25519_key_t){.key64 = {
		0x7D7948594FC9EDA8ULL,
		0xBF001EC10BCBB38FULL,
		0x9772E3E0892F5AA3ULL,
		0x6CC1880BB61128BDULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7D7948594FC9EDA8ULL,
			0xBF001EC10BCBB38FULL,
			0x9772E3E0892F5AA3ULL,
			0x6CC1880BB61128BDULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x34046CDFA6E3C381ULL,
			0xB5D3A61CA81922A8ULL,
			0xE486C5410D028F86ULL,
			0x14DF40B36CE5B601ULL}
		},
		.Z = {.key64 = {
			0x9287F4C55978C288ULL,
			0xFD350DC804AF5A2CULL,
			0x29194163F80747ECULL,
			0x4576B4FC98394DE5ULL}
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

	steps = 33;
	X1 = (curve25519_key_t){.key64 = {
		0x0419DF094152C7D0ULL,
		0x79342AA9F66537D1ULL,
		0xAF0024061F186FBCULL,
		0x51A45EC652733B2BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0419DF094152C7D0ULL,
			0x79342AA9F66537D1ULL,
			0xAF0024061F186FBCULL,
			0x51A45EC652733B2BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x56F09889853A8953ULL,
			0x4D33EA8FC927BA04ULL,
			0x640724B708338A16ULL,
			0x5C5439681465A6DEULL}
		},
		.Z = {.key64 = {
			0x83E738E1B87B37F3ULL,
			0xB4B24BBF84008EDDULL,
			0x71F9AFF405D80A21ULL,
			0x4B9FAF9FCADF0E14ULL}
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

	steps = 35;
	X1 = (curve25519_key_t){.key64 = {
		0x603BA30A09D19D68ULL,
		0x23357FDF43940F94ULL,
		0x127F3FFB4B71322FULL,
		0x59BAA7D25BE2A091ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x603BA30A09D19D68ULL,
			0x23357FDF43940F94ULL,
			0x127F3FFB4B71322FULL,
			0x59BAA7D25BE2A091ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x533229943C4AB7ECULL,
			0xA867461D88B1143DULL,
			0x9C3040909FC02A1BULL,
			0x2A5B94FD0445E9FEULL}
		},
		.Z = {.key64 = {
			0x48ED310962A5B7ADULL,
			0x838C94DADBE92600ULL,
			0x0947401EC87B365AULL,
			0x2FE5D6D9CA508198ULL}
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

	steps = 7;
	X1 = (curve25519_key_t){.key64 = {
		0x9BD1D10095913E20ULL,
		0x9C2C7B21C2D49FC6ULL,
		0xD75AB97CFAA5DFDDULL,
		0x4C9F8CB3FBC3EF43ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9BD1D10095913E20ULL,
			0x9C2C7B21C2D49FC6ULL,
			0xD75AB97CFAA5DFDDULL,
			0x4C9F8CB3FBC3EF43ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAA112624E4FF32C7ULL,
			0x27490871DDDF2DD1ULL,
			0x6916548CD36EA93AULL,
			0x6D18934147EB4996ULL}
		},
		.Z = {.key64 = {
			0x43A8C7ED8C0DA3D1ULL,
			0xE0E357EC7B2C73AFULL,
			0x3E628772F098C4C5ULL,
			0x2C88DFE55E7B9671ULL}
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

	steps = 46;
	X1 = (curve25519_key_t){.key64 = {
		0xAB55D713D294B008ULL,
		0xC8AB46F8D61A0012ULL,
		0x3E65C1253874BFE7ULL,
		0x7942E291D14D65F2ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAB55D713D294B008ULL,
			0xC8AB46F8D61A0012ULL,
			0x3E65C1253874BFE7ULL,
			0x7942E291D14D65F2ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCD969C119CE024D0ULL,
			0x2F6061740D9FC8AAULL,
			0x67DB240A41B9B4AEULL,
			0x23CD8A5E69F921F9ULL}
		},
		.Z = {.key64 = {
			0x1A321041C2A1BA05ULL,
			0x9D183E2EE637B992ULL,
			0x33B608D4CE9EC6A9ULL,
			0x7AC363D4C7F57774ULL}
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

	steps = 60;
	X1 = (curve25519_key_t){.key64 = {
		0xBCEF20DE8C35E5F0ULL,
		0xE73AA26AF23F79FBULL,
		0x4A0B66C8DEB20632ULL,
		0x569AA994A36FD62CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBCEF20DE8C35E5F0ULL,
			0xE73AA26AF23F79FBULL,
			0x4A0B66C8DEB20632ULL,
			0x569AA994A36FD62CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEF132F2371A6ECB7ULL,
			0xB86E00AABE13D11EULL,
			0xB7C14CE288EC517FULL,
			0x5C029E59ADF91373ULL}
		},
		.Z = {.key64 = {
			0x58DF3C68F3274F01ULL,
			0x407905A951155627ULL,
			0xB92E67BD1951691DULL,
			0x00030A6FB792BFA0ULL}
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

	steps = 11;
	X1 = (curve25519_key_t){.key64 = {
		0x4AD8638AFAB21298ULL,
		0x7F410E44EF1E292CULL,
		0x178F6923363520E3ULL,
		0x4D344356869A5ACEULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4AD8638AFAB21298ULL,
			0x7F410E44EF1E292CULL,
			0x178F6923363520E3ULL,
			0x4D344356869A5ACEULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x78B16FE2717E1323ULL,
			0xB142139916E23E59ULL,
			0xDD1FBA5E3C73C9F0ULL,
			0x3E8E75669A1D6D87ULL}
		},
		.Z = {.key64 = {
			0x5BB18223FC94FB87ULL,
			0x596D7D2C302329C7ULL,
			0x3679E6C4372A3A94ULL,
			0x71E639AD9AAEE42CULL}
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
		0xAC8E2F4B56F61938ULL,
		0x736EF11AF92B76CFULL,
		0x25F7378E75518847ULL,
		0x6926E60AAE2555E7ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAC8E2F4B56F61938ULL,
			0x736EF11AF92B76CFULL,
			0x25F7378E75518847ULL,
			0x6926E60AAE2555E7ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1701C9A306D823EEULL,
			0x67E97512F1079388ULL,
			0x9D37C14607530722ULL,
			0x341DF35B24C009F7ULL}
		},
		.Z = {.key64 = {
			0xB46493646607EF04ULL,
			0xA16352DD1826C4D4ULL,
			0xBCB9BBF172D15326ULL,
			0x2AD0DA791E79477CULL}
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

	steps = 23;
	X1 = (curve25519_key_t){.key64 = {
		0xB4CFD74BCFB7BD18ULL,
		0x3725C1E10AF6223DULL,
		0xD98E1AA0A7954AB2ULL,
		0x531D1CFE95BA72AEULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB4CFD74BCFB7BD18ULL,
			0x3725C1E10AF6223DULL,
			0xD98E1AA0A7954AB2ULL,
			0x531D1CFE95BA72AEULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x071DC77FBFB81102ULL,
			0x38819C0CF226CD2AULL,
			0xE64665F3B047470EULL,
			0x00B1702CE9ABF700ULL}
		},
		.Z = {.key64 = {
			0x0C1741BAB165217EULL,
			0x9F3B5544DEDBFDF6ULL,
			0x5FEECD291374AA0CULL,
			0x27EADEE32B6B4E8CULL}
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

	steps = 15;
	X1 = (curve25519_key_t){.key64 = {
		0xF89265BA0DD2B2B0ULL,
		0xC762E6C22A2EC8E2ULL,
		0x1C9EA267FA6F182BULL,
		0x4425E0581B090D09ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF89265BA0DD2B2B0ULL,
			0xC762E6C22A2EC8E2ULL,
			0x1C9EA267FA6F182BULL,
			0x4425E0581B090D09ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC99FB2027FB88C81ULL,
			0x234F1964F0A10984ULL,
			0x8DB94EDB4A040D0BULL,
			0x729C61967619A4B3ULL}
		},
		.Z = {.key64 = {
			0xBBC27CA8647F3C40ULL,
			0x486F6F14F6EE21C2ULL,
			0x6894BBF750A5EDEBULL,
			0x2C0132DD41046602ULL}
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

	steps = 20;
	X1 = (curve25519_key_t){.key64 = {
		0x870DD5DC6D16D040ULL,
		0xE1C6C672B260801DULL,
		0x11F99B8F83DB4EC7ULL,
		0x646C14FCD4229CFCULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x870DD5DC6D16D040ULL,
			0xE1C6C672B260801DULL,
			0x11F99B8F83DB4EC7ULL,
			0x646C14FCD4229CFCULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE6520D01961AAF32ULL,
			0x7217E6AB43AA0E8DULL,
			0x433C2A2B9A71BB0EULL,
			0x283E2317F126C2AEULL}
		},
		.Z = {.key64 = {
			0x31468FBDB032EED8ULL,
			0xCC469228DFC50FEAULL,
			0xEC6E3FEA49A771D6ULL,
			0x210CC83EA81703BDULL}
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

	steps = 17;
	X1 = (curve25519_key_t){.key64 = {
		0x897C7FB30656D038ULL,
		0xBF7015173075B73BULL,
		0xD1C97DC7D5913ABAULL,
		0x4D21FB0314D16B0FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x897C7FB30656D038ULL,
			0xBF7015173075B73BULL,
			0xD1C97DC7D5913ABAULL,
			0x4D21FB0314D16B0FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF2EB3B2F1EFD8F2BULL,
			0x50323EA6AF491000ULL,
			0x0133E1EB8176DD4DULL,
			0x324F7023B66CA92FULL}
		},
		.Z = {.key64 = {
			0xA71F9FBF152B4B0FULL,
			0xC7F54F45A28F9FD7ULL,
			0xEEB47B65614D4C42ULL,
			0x16C599FC4B47819AULL}
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

	steps = 9;
	X1 = (curve25519_key_t){.key64 = {
		0xFF991A28A03BBE58ULL,
		0xDAC67E2D86D97CDDULL,
		0xEA137D8C1A758DB6ULL,
		0x48A60A5B5C2A3069ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFF991A28A03BBE58ULL,
			0xDAC67E2D86D97CDDULL,
			0xEA137D8C1A758DB6ULL,
			0x48A60A5B5C2A3069ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9163EB78EF7FA833ULL,
			0x4AF4DE241D348635ULL,
			0xE99FFE22E344A8D8ULL,
			0x332AA81C45498309ULL}
		},
		.Z = {.key64 = {
			0x47E776E578126BC7ULL,
			0x3FBF3DCDAE999D3CULL,
			0x7557EDF94795F7D5ULL,
			0x5311E730A84D681DULL}
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

	steps = 12;
	X1 = (curve25519_key_t){.key64 = {
		0x9BBF0F83A2B54110ULL,
		0x41366B94C27CC131ULL,
		0x2BE4BCEF57998ADFULL,
		0x797D0FEB92A8F306ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9BBF0F83A2B54110ULL,
			0x41366B94C27CC131ULL,
			0x2BE4BCEF57998ADFULL,
			0x797D0FEB92A8F306ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC75D048329E3BCF7ULL,
			0x00681887E7D3F501ULL,
			0x4CC1D69B0F267FADULL,
			0x44F4D9A1F2262D72ULL}
		},
		.Z = {.key64 = {
			0xD91B3C196744681DULL,
			0x65F356F6B572BCFDULL,
			0x3F8B6B160C93C84DULL,
			0x70D025D06F5BDA9AULL}
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

	steps = 50;
	X1 = (curve25519_key_t){.key64 = {
		0x8F98E3E396893920ULL,
		0x2F127CBC93A75E70ULL,
		0xEFC7D03432D21F9BULL,
		0x6DC88DD96120FE5CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8F98E3E396893920ULL,
			0x2F127CBC93A75E70ULL,
			0xEFC7D03432D21F9BULL,
			0x6DC88DD96120FE5CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7D4CF3BF53F34D79ULL,
			0x39042DC08FD89503ULL,
			0x1A8781758F7A4512ULL,
			0x7B8FCBAF62CC5B2FULL}
		},
		.Z = {.key64 = {
			0xC335B17BF603CF94ULL,
			0x90854A8AF5372084ULL,
			0x2A530E6E2BDD71B5ULL,
			0x4DDE6AC018F8AF67ULL}
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
		0x0E69667EFC2C3440ULL,
		0x44A30B66672EC654ULL,
		0xA330440E68E61380ULL,
		0x693B990CACE30F20ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0E69667EFC2C3440ULL,
			0x44A30B66672EC654ULL,
			0xA330440E68E61380ULL,
			0x693B990CACE30F20ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x56382FAC20B72939ULL,
			0x8047C3FCAA8A8524ULL,
			0xCFEFE7BEB4A1254CULL,
			0x52D5D7D1C3EFD8DEULL}
		},
		.Z = {.key64 = {
			0xAE67510163334850ULL,
			0x8991A69EB437C12CULL,
			0x66E897339EA70B25ULL,
			0x5440881A25868AFBULL}
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

	steps = 18;
	X1 = (curve25519_key_t){.key64 = {
		0xF4F43203CD874480ULL,
		0xB38D481214020D0CULL,
		0xD8F9F2F621403966ULL,
		0x4972782023E9BB62ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF4F43203CD874480ULL,
			0xB38D481214020D0CULL,
			0xD8F9F2F621403966ULL,
			0x4972782023E9BB62ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3E6F43466F7F01B1ULL,
			0xB669B8A6BE23E98DULL,
			0xE6A273B1557A22AEULL,
			0x60443671236D1327ULL}
		},
		.Z = {.key64 = {
			0xA3039DF9B665ED08ULL,
			0xE28CBBB067571A79ULL,
			0x0737E93F5052C876ULL,
			0x57519ECF12AE60B1ULL}
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

	steps = 24;
	X1 = (curve25519_key_t){.key64 = {
		0x7399EB0DE21DD3A0ULL,
		0x2223911614666615ULL,
		0xFFF354ABB65CEB0FULL,
		0x5B5AABE0C2F6F43BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7399EB0DE21DD3A0ULL,
			0x2223911614666615ULL,
			0xFFF354ABB65CEB0FULL,
			0x5B5AABE0C2F6F43BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x89C8F124E09F131BULL,
			0xF42399002801E86DULL,
			0x91B84895247FB3F6ULL,
			0x6CB3EB79D9FA0502ULL}
		},
		.Z = {.key64 = {
			0xB9F11B5F98A7DB7CULL,
			0xA26E856E64108A77ULL,
			0x712B9C87376C7CF5ULL,
			0x45C5095559C918DBULL}
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

	steps = 24;
	X1 = (curve25519_key_t){.key64 = {
		0x083B49A17C9712C0ULL,
		0x8E6374CE4BB8DDE8ULL,
		0x6D08BC5053B15051ULL,
		0x760B97509B49CF3EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x083B49A17C9712C0ULL,
			0x8E6374CE4BB8DDE8ULL,
			0x6D08BC5053B15051ULL,
			0x760B97509B49CF3EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x96F76FDEB9C7E852ULL,
			0x09F6C7E77622067CULL,
			0x0F54A3FB813BB7C4ULL,
			0x11200B548139CB57ULL}
		},
		.Z = {.key64 = {
			0x5AC787FDE2DCFC2FULL,
			0x49AC04869F345E5BULL,
			0x3508A563C27C689EULL,
			0x018562EBF9D75664ULL}
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

	steps = 37;
	X1 = (curve25519_key_t){.key64 = {
		0x969AEA136F79F078ULL,
		0x80CFA94D94580BC0ULL,
		0x9D3516D1F587F42EULL,
		0x51B2790D43AD3425ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x969AEA136F79F078ULL,
			0x80CFA94D94580BC0ULL,
			0x9D3516D1F587F42EULL,
			0x51B2790D43AD3425ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2BE0F5BFCA991E8EULL,
			0x3D05D4D91E912D8DULL,
			0xAB98118AD6089914ULL,
			0x7C88B5B821B93C41ULL}
		},
		.Z = {.key64 = {
			0x5A4324207DC44CF2ULL,
			0x748DBD3F4FFE0247ULL,
			0xBC0B5BC641EE0E98ULL,
			0x5501951E443FE85DULL}
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
		0x50F49278E4910298ULL,
		0x89C6E9FC785DFE9EULL,
		0x803E69D6C09C07A7ULL,
		0x7790F8BD8F921CAFULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x50F49278E4910298ULL,
			0x89C6E9FC785DFE9EULL,
			0x803E69D6C09C07A7ULL,
			0x7790F8BD8F921CAFULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x34FA16B89E1BCD3FULL,
			0x85AF31C3066B7E8FULL,
			0x1177BDDDCC8DB294ULL,
			0x4AB0AD3C81BC7942ULL}
		},
		.Z = {.key64 = {
			0xFE10B2E7AA8912A5ULL,
			0x553FAD91F53595A6ULL,
			0xD1C99B0E6F737D49ULL,
			0x0C50BA206D7D0046ULL}
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

	steps = 22;
	X1 = (curve25519_key_t){.key64 = {
		0x85FDC4824756B638ULL,
		0x9CFB9081D4A86E57ULL,
		0x4128C7B0D06A419EULL,
		0x7A18368E1D45806DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x85FDC4824756B638ULL,
			0x9CFB9081D4A86E57ULL,
			0x4128C7B0D06A419EULL,
			0x7A18368E1D45806DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE3CA02B515277EC3ULL,
			0xED94768965CB26E4ULL,
			0x80385962F6E24C6FULL,
			0x52A4AED0A5177275ULL}
		},
		.Z = {.key64 = {
			0x4532F8AC526E9D84ULL,
			0x86640651C694F38EULL,
			0x7B77C9C0A63B0474ULL,
			0x43B461988BF6B2FEULL}
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

	steps = 60;
	X1 = (curve25519_key_t){.key64 = {
		0x62C48C15A97BCC30ULL,
		0xB5EEF46FA1A5E564ULL,
		0x5A092D0F3BBAA03FULL,
		0x698E67D5C0CD05A0ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x62C48C15A97BCC30ULL,
			0xB5EEF46FA1A5E564ULL,
			0x5A092D0F3BBAA03FULL,
			0x698E67D5C0CD05A0ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3FCA5AC75329B74EULL,
			0x173DF234CA7E282BULL,
			0xFB065F6BE304FB08ULL,
			0x3480A2668613D8FDULL}
		},
		.Z = {.key64 = {
			0x540DCBC18721EAA8ULL,
			0x21E15B35654DBA91ULL,
			0x7F71D03512D99F5CULL,
			0x1F391462647B8A7DULL}
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

	steps = 3;
	X1 = (curve25519_key_t){.key64 = {
		0x873F354062EDF890ULL,
		0x8C0E5468B653CFD3ULL,
		0xD945D7B31F44F9A0ULL,
		0x41DFDF9E787A08CEULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x873F354062EDF890ULL,
			0x8C0E5468B653CFD3ULL,
			0xD945D7B31F44F9A0ULL,
			0x41DFDF9E787A08CEULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x48F9A95802F15DDCULL,
			0xDFEF7219C8E6FB04ULL,
			0x920CEB3A8230B6FEULL,
			0x349D84F94F6A74EFULL}
		},
		.Z = {.key64 = {
			0x73E969FEA0BC8D52ULL,
			0x8D45FE2A8E72AC06ULL,
			0xD93347E67B544B66ULL,
			0x54011C5283C04DF7ULL}
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

	steps = 43;
	X1 = (curve25519_key_t){.key64 = {
		0x325536CA2BAF1EA0ULL,
		0x07FED7A3E21C4462ULL,
		0x340003010D128577ULL,
		0x489F6E56F3917DF8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x325536CA2BAF1EA0ULL,
			0x07FED7A3E21C4462ULL,
			0x340003010D128577ULL,
			0x489F6E56F3917DF8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x60135E3C29E98F58ULL,
			0xFDC21F2842DEBAEEULL,
			0x212BCE4C299CBF49ULL,
			0x14466199207D6DF5ULL}
		},
		.Z = {.key64 = {
			0xB9BF18DA9521F590ULL,
			0x264CB99FCD9E132EULL,
			0x6BB0C309ADA896CCULL,
			0x75AE47224D7B9735ULL}
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

	steps = 9;
	X1 = (curve25519_key_t){.key64 = {
		0xCEA7C1038BD5E658ULL,
		0x258DD1AD3BD281CBULL,
		0x0DF271D5169FA192ULL,
		0x6C15C02D0E3942F7ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCEA7C1038BD5E658ULL,
			0x258DD1AD3BD281CBULL,
			0x0DF271D5169FA192ULL,
			0x6C15C02D0E3942F7ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFC4E61BF3A7256F6ULL,
			0xF01B515B11C2E131ULL,
			0xD9382990F8A1D615ULL,
			0x25B1A3C357E06458ULL}
		},
		.Z = {.key64 = {
			0x3A27143772CB9A1BULL,
			0x9D0AEB14C81072CDULL,
			0xAD2FBB40DB0E4B9BULL,
			0x64A04F7A331CE01DULL}
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

	steps = 25;
	X1 = (curve25519_key_t){.key64 = {
		0x00199C87CEE78208ULL,
		0x8213686C236E4BEDULL,
		0x077DE85998F23073ULL,
		0x6D0B70D555B3BDC4ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x00199C87CEE78208ULL,
			0x8213686C236E4BEDULL,
			0x077DE85998F23073ULL,
			0x6D0B70D555B3BDC4ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF5ECE05DE6EB11D7ULL,
			0x711CBAD032C2BD8EULL,
			0x891D00FCE149A5BCULL,
			0x66AA9D3D36B79B12ULL}
		},
		.Z = {.key64 = {
			0xD4F8BF474B7D088CULL,
			0xF913F79CA33E2F78ULL,
			0x341F7AD6CA942C0CULL,
			0x3F1E0B3C6967B940ULL}
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

	steps = 45;
	X1 = (curve25519_key_t){.key64 = {
		0xCAF4EE88776E88B8ULL,
		0x3907CBDAC5F41EEFULL,
		0xF94D0AA5D6661D2BULL,
		0x579AECFE7F9E8161ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCAF4EE88776E88B8ULL,
			0x3907CBDAC5F41EEFULL,
			0xF94D0AA5D6661D2BULL,
			0x579AECFE7F9E8161ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6EC47B4DD4D9BA93ULL,
			0x5C81314626107020ULL,
			0x944016E31F44AD4FULL,
			0x4355AC8B7D998AC6ULL}
		},
		.Z = {.key64 = {
			0x5D7B1DCBDF62D428ULL,
			0x30E7A59E68DED277ULL,
			0x80937CE65876F913ULL,
			0x6DBC55E1001C131CULL}
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

	steps = 14;
	X1 = (curve25519_key_t){.key64 = {
		0x452F6CD30906BBE8ULL,
		0x7CF24F69BA8124F9ULL,
		0x88C0A06362BE3B3AULL,
		0x511DA1502489D190ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x452F6CD30906BBE8ULL,
			0x7CF24F69BA8124F9ULL,
			0x88C0A06362BE3B3AULL,
			0x511DA1502489D190ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6C7E665D9EDFEDCBULL,
			0x9DA246B33B58C319ULL,
			0xFD840D4B2382B3BDULL,
			0x163641F5BEE6E726ULL}
		},
		.Z = {.key64 = {
			0x77DBDF0BD9111809ULL,
			0xBA414A24262E5A71ULL,
			0xC82682DBC7C6CFABULL,
			0x3B5B927E8ACB13C0ULL}
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

	steps = 54;
	X1 = (curve25519_key_t){.key64 = {
		0x9C16D076578824C8ULL,
		0x97ABBD4A47562C15ULL,
		0x0AE0A1E3C9B145C6ULL,
		0x6F44EDC7D86B57D6ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9C16D076578824C8ULL,
			0x97ABBD4A47562C15ULL,
			0x0AE0A1E3C9B145C6ULL,
			0x6F44EDC7D86B57D6ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6300493060C9CC96ULL,
			0x979238F9D830BCF9ULL,
			0xBB6D8A07A217FD44ULL,
			0x2064BAA5CE546A46ULL}
		},
		.Z = {.key64 = {
			0xD09A898EC63EB55CULL,
			0x09AD5FC8CA9EB7E7ULL,
			0xA878CA12E8F610C7ULL,
			0x30395448DD4C293BULL}
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

	steps = 24;
	X1 = (curve25519_key_t){.key64 = {
		0xAA42ABD3CEAB4E70ULL,
		0x543455511B16F2D8ULL,
		0x06CF07D497BAF0AEULL,
		0x6ABF47532E3348B7ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAA42ABD3CEAB4E70ULL,
			0x543455511B16F2D8ULL,
			0x06CF07D497BAF0AEULL,
			0x6ABF47532E3348B7ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x19ADA42BD77AE360ULL,
			0x6E5C6F5853056F29ULL,
			0xBD8791D496D6DD8BULL,
			0x7A4D6E4C3DB97052ULL}
		},
		.Z = {.key64 = {
			0x5657D14C1F78B495ULL,
			0xAB0AE34A5CE1CF49ULL,
			0x35FAC253E15367A4ULL,
			0x1C8A15A170A4CEF0ULL}
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

	steps = 24;
	X1 = (curve25519_key_t){.key64 = {
		0x46C09E383B0334F0ULL,
		0xBBA24852DE70A552ULL,
		0xB06B59121076A611ULL,
		0x44C9B0B22C4C4669ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x46C09E383B0334F0ULL,
			0xBBA24852DE70A552ULL,
			0xB06B59121076A611ULL,
			0x44C9B0B22C4C4669ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x35C6446FC595C2B2ULL,
			0xFF3AA8E023563DABULL,
			0x8DE3905890EC0E98ULL,
			0x419C904310BF2303ULL}
		},
		.Z = {.key64 = {
			0x13A4D97B8279FBDDULL,
			0x8545FF89FED6474CULL,
			0xA935F1F6A1CEDFEBULL,
			0x4F30E17FE95B305DULL}
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

	steps = 14;
	X1 = (curve25519_key_t){.key64 = {
		0x689C4AF5AF7C2008ULL,
		0x35C9FD9944B16C78ULL,
		0xBDDB2CA05EABA97BULL,
		0x74F088F826C36C38ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x689C4AF5AF7C2008ULL,
			0x35C9FD9944B16C78ULL,
			0xBDDB2CA05EABA97BULL,
			0x74F088F826C36C38ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCEE3F51CF94220AEULL,
			0xF8628A7F94059A98ULL,
			0x227B16EC5A0FD19BULL,
			0x7608E3E4D13CC14AULL}
		},
		.Z = {.key64 = {
			0xDBB1C4C1317E397BULL,
			0xDE7286520DF9C2D6ULL,
			0xD658778A5B0C0251ULL,
			0x10BF897ED97E37C2ULL}
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

	steps = 29;
	X1 = (curve25519_key_t){.key64 = {
		0xAFF16879791A2850ULL,
		0xA20D0A27D4E3B062ULL,
		0x6868B19FE5E1F823ULL,
		0x795BCDDB69A60C56ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAFF16879791A2850ULL,
			0xA20D0A27D4E3B062ULL,
			0x6868B19FE5E1F823ULL,
			0x795BCDDB69A60C56ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x14A6950C7C62FE25ULL,
			0xCC70C2FF55F45E07ULL,
			0xAD6EDDF568BEC0D8ULL,
			0x0F6B88179D3CCA60ULL}
		},
		.Z = {.key64 = {
			0x2449D198AB9285CCULL,
			0x93CE57D4C4B27965ULL,
			0xBE7E034213F0FC71ULL,
			0x76A0395A8865C69EULL}
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

	steps = 2;
	X1 = (curve25519_key_t){.key64 = {
		0x66BFE700B9A60528ULL,
		0x1681B3B2EE10E92AULL,
		0xC7284FA828C24EAEULL,
		0x5318C86CD634BBDBULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x66BFE700B9A60528ULL,
			0x1681B3B2EE10E92AULL,
			0xC7284FA828C24EAEULL,
			0x5318C86CD634BBDBULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEAA1004789E620C1ULL,
			0xE0CDAAB41155A8A6ULL,
			0x3F7F8A9B0E07659CULL,
			0x307CFC1C39BEB775ULL}
		},
		.Z = {.key64 = {
			0x5E809B6E7426CD09ULL,
			0x182A576547E225CEULL,
			0x79D394911F70C36CULL,
			0x416B92CA01CAD255ULL}
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

	steps = 61;
	X1 = (curve25519_key_t){.key64 = {
		0x478BEB2AD5E6DEB0ULL,
		0x3D82C6B66BA805E9ULL,
		0x2A6A0A8719D38B49ULL,
		0x7161387888ABCE00ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x478BEB2AD5E6DEB0ULL,
			0x3D82C6B66BA805E9ULL,
			0x2A6A0A8719D38B49ULL,
			0x7161387888ABCE00ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9C0E52D808A000EEULL,
			0x9736C473A2FB2DE9ULL,
			0xB4BB2A20E61A4EA8ULL,
			0x4A6CB656BD1D8957ULL}
		},
		.Z = {.key64 = {
			0x16F3A22B4B7485F2ULL,
			0x74EB619A78E44828ULL,
			0x764B48E006382F29ULL,
			0x4376511054A36AD3ULL}
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

	steps = 49;
	X1 = (curve25519_key_t){.key64 = {
		0x28B81F3AC6DFD500ULL,
		0xF097458B02BA2582ULL,
		0x4E8B0F44191DF026ULL,
		0x58F279E65AFEFA1EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x28B81F3AC6DFD500ULL,
			0xF097458B02BA2582ULL,
			0x4E8B0F44191DF026ULL,
			0x58F279E65AFEFA1EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x71B40F096E6EEE82ULL,
			0x6DD9BEA576545D15ULL,
			0xD48B1F7BBAC54B55ULL,
			0x126588675F482632ULL}
		},
		.Z = {.key64 = {
			0x65C005AA4C9DEA2CULL,
			0xAB1D3B87DF96C2B6ULL,
			0x337D858B829CCE9FULL,
			0x2D7BC38B80A070C3ULL}
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

	steps = 64;
	X1 = (curve25519_key_t){.key64 = {
		0x85208FA0BA34D930ULL,
		0xB324F7C29CC242D5ULL,
		0xDC64B7716FA95585ULL,
		0x6A9D0FE9A1DD5561ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x85208FA0BA34D930ULL,
			0xB324F7C29CC242D5ULL,
			0xDC64B7716FA95585ULL,
			0x6A9D0FE9A1DD5561ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4DD02D69523E95BFULL,
			0xD0C2BD1F41E04DDBULL,
			0xBF5874F90479893BULL,
			0x1B56FAD71051125AULL}
		},
		.Z = {.key64 = {
			0x6DB56312BA979BACULL,
			0xA33C387714BEA318ULL,
			0xAC4103BB5B5AB54FULL,
			0x5C139DF9EF413BBDULL}
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

	steps = 13;
	X1 = (curve25519_key_t){.key64 = {
		0x7E168FFF1B6B37F8ULL,
		0xCA18A3E030A3BC6EULL,
		0xC7E43AE209A5C10FULL,
		0x7F239D7C66D446EAULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7E168FFF1B6B37F8ULL,
			0xCA18A3E030A3BC6EULL,
			0xC7E43AE209A5C10FULL,
			0x7F239D7C66D446EAULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x61C633CD0C33BDF0ULL,
			0xEDBD051A3A11AFF5ULL,
			0x859ADEEB30D475A3ULL,
			0x4DD9E04542C4967DULL}
		},
		.Z = {.key64 = {
			0x9ED32467C702A956ULL,
			0x0780E15BB3CFD463ULL,
			0x117EB7AFBA5EA83CULL,
			0x354C366DA9DC832CULL}
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

	steps = 49;
	X1 = (curve25519_key_t){.key64 = {
		0x9AC6B109DEAE97A8ULL,
		0x2F69BAB8F4EA8E11ULL,
		0x847E44A884670D83ULL,
		0x47B2D6792F0D083EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9AC6B109DEAE97A8ULL,
			0x2F69BAB8F4EA8E11ULL,
			0x847E44A884670D83ULL,
			0x47B2D6792F0D083EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2F477DA4A7886DB6ULL,
			0x2B825AA7AD611AFDULL,
			0x8CE2657A0C6F34CCULL,
			0x115DDF68B40D21A0ULL}
		},
		.Z = {.key64 = {
			0x24E701E4332458E9ULL,
			0xC5EBD532478A4E35ULL,
			0x560CC635351C00ECULL,
			0x4B42B6D9D55F1994ULL}
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

	steps = 8;
	X1 = (curve25519_key_t){.key64 = {
		0x852C0609EA5EA680ULL,
		0xE9AFD2CCFCEC23C3ULL,
		0x64D5D6B8F9957A18ULL,
		0x55FEFFE86653B8F6ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x852C0609EA5EA680ULL,
			0xE9AFD2CCFCEC23C3ULL,
			0x64D5D6B8F9957A18ULL,
			0x55FEFFE86653B8F6ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x009E9DB132F40A6EULL,
			0x9D04F97C7BFDF665ULL,
			0x5C96141A3EEE3889ULL,
			0x0DF58DFCA8EDEE28ULL}
		},
		.Z = {.key64 = {
			0xA6CEB8CB135B054BULL,
			0x764544D8FD205CDCULL,
			0xC9918BB95933A9C0ULL,
			0x3D127557D38DF97FULL}
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

	steps = 1;
	X1 = (curve25519_key_t){.key64 = {
		0x80DD6B579BA3B428ULL,
		0xEBFC7781B2472EB8ULL,
		0x600E9DB2697628CCULL,
		0x76D6B04290CC1440ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x80DD6B579BA3B428ULL,
			0xEBFC7781B2472EB8ULL,
			0x600E9DB2697628CCULL,
			0x76D6B04290CC1440ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x67D949276405D1F1ULL,
			0xC82A58A2844BEE42ULL,
			0x23652CF30A5A866DULL,
			0x16D6A2D04BBF4F52ULL}
		},
		.Z = {.key64 = {
			0x0375AD5E6E8ED0D9ULL,
			0xAFF1DE06C91CBAE2ULL,
			0x803A76C9A5D8A333ULL,
			0x5B5AC10A43305101ULL}
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

	steps = 50;
	X1 = (curve25519_key_t){.key64 = {
		0xDD16C31F6712BE20ULL,
		0x7F026AD0BEFC8A52ULL,
		0xCEFE0769F2860757ULL,
		0x5CDBE0ECCA498461ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDD16C31F6712BE20ULL,
			0x7F026AD0BEFC8A52ULL,
			0xCEFE0769F2860757ULL,
			0x5CDBE0ECCA498461ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC106D7A7A17557B5ULL,
			0x215AD2123C375C92ULL,
			0x5CBC0727EE32013FULL,
			0x63110A4219350CD7ULL}
		},
		.Z = {.key64 = {
			0x9FD0035F2715D78BULL,
			0x5491C8C5BC0156BFULL,
			0x5BE666FCE7020158ULL,
			0x2E671590384F087DULL}
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

	steps = 19;
	X1 = (curve25519_key_t){.key64 = {
		0xC760130684E3FE60ULL,
		0x362E9F3613FE81B5ULL,
		0x19F6D041BFB035EAULL,
		0x450C29AE189CE6E0ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC760130684E3FE60ULL,
			0x362E9F3613FE81B5ULL,
			0x19F6D041BFB035EAULL,
			0x450C29AE189CE6E0ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0ED529B8A1D66263ULL,
			0xAB64463CA54EE538ULL,
			0xB5B6473DF7FA4B69ULL,
			0x43D682E06D033486ULL}
		},
		.Z = {.key64 = {
			0xF4CB4480766108F5ULL,
			0xD11B33F6ED6CD3AFULL,
			0x78BDBB1786BDFE1DULL,
			0x5C5A527E537F88F9ULL}
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

	steps = 51;
	X1 = (curve25519_key_t){.key64 = {
		0xC9DC1F68A356BA50ULL,
		0xB18B17A92C912499ULL,
		0x57CCEC7C9085F3B9ULL,
		0x4DF20B28AC3320E5ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC9DC1F68A356BA50ULL,
			0xB18B17A92C912499ULL,
			0x57CCEC7C9085F3B9ULL,
			0x4DF20B28AC3320E5ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7ADA4267C8F8E5BBULL,
			0x5D50EED79AD8DC1BULL,
			0xA0A189E8687DAB43ULL,
			0x3308785C0C04094BULL}
		},
		.Z = {.key64 = {
			0x91FB93AB8A84087FULL,
			0x0A363F4E97EF8984ULL,
			0x46900D007A455722ULL,
			0x2DCAF4E3071A2140ULL}
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

	steps = 30;
	X1 = (curve25519_key_t){.key64 = {
		0xA6CF5B4628C6FDE8ULL,
		0xB0C00EB7C91BF5A1ULL,
		0x972119BAA5E71D4BULL,
		0x5FAF17DD76ED8B51ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA6CF5B4628C6FDE8ULL,
			0xB0C00EB7C91BF5A1ULL,
			0x972119BAA5E71D4BULL,
			0x5FAF17DD76ED8B51ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8FD1023E33A696E6ULL,
			0xC61B2BD30B4EF08DULL,
			0xA5F946AD56AC64E8ULL,
			0x2CB7FE57B1AA641FULL}
		},
		.Z = {.key64 = {
			0xB42EED22587F4F2CULL,
			0x060FED1DF3DE91B7ULL,
			0x3B584EAFFA48F101ULL,
			0x314A5B315EF4B1C0ULL}
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

	steps = 6;
	X1 = (curve25519_key_t){.key64 = {
		0x7EAEB5D947D075D0ULL,
		0xFF4831D419A883B6ULL,
		0x63C7F4041AD17462ULL,
		0x45AF850939341002ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7EAEB5D947D075D0ULL,
			0xFF4831D419A883B6ULL,
			0x63C7F4041AD17462ULL,
			0x45AF850939341002ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x197E7192F3A84A71ULL,
			0x709F007B51D79FA6ULL,
			0x1FCE39537E430CE2ULL,
			0x4D5D3DB9025FEF4BULL}
		},
		.Z = {.key64 = {
			0xDDA7917ED89296D1ULL,
			0x98578E7CCD9BDC6CULL,
			0x3093706CE3B8284FULL,
			0x7FC9CBCE8DBDB5B8ULL}
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

	steps = 19;
	X1 = (curve25519_key_t){.key64 = {
		0x5D6008F96343B158ULL,
		0xF8360AF037F1192FULL,
		0x3D2C86DF7E6A0C9DULL,
		0x687CAD941E53BF94ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5D6008F96343B158ULL,
			0xF8360AF037F1192FULL,
			0x3D2C86DF7E6A0C9DULL,
			0x687CAD941E53BF94ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB77716597AB524C1ULL,
			0xAB691358E9DCBEB3ULL,
			0x907D1001E3A8BAEFULL,
			0x5836793174C5142BULL}
		},
		.Z = {.key64 = {
			0x490D6220A1672D31ULL,
			0x88BE02A40DAC1C79ULL,
			0x2496FF73522F2C8CULL,
			0x0DCF9B1FBF60272EULL}
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

	steps = 10;
	X1 = (curve25519_key_t){.key64 = {
		0x9327500C64B36290ULL,
		0xF8960562744E4032ULL,
		0xF560ADDFF37B38B3ULL,
		0x57D4C29CA36E8235ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9327500C64B36290ULL,
			0xF8960562744E4032ULL,
			0xF560ADDFF37B38B3ULL,
			0x57D4C29CA36E8235ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB7137B627AE089D8ULL,
			0x61647F1AF05C5A35ULL,
			0xCB9F329ADB9F7D14ULL,
			0x7122D5D260806326ULL}
		},
		.Z = {.key64 = {
			0x6396CD71BC8A56D0ULL,
			0xC9A8405CC188BED2ULL,
			0x6E94B752331AF3E0ULL,
			0x26DBD4CDB6A2C4F4ULL}
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

	steps = 8;
	X1 = (curve25519_key_t){.key64 = {
		0xAC74F87CF4336550ULL,
		0x1632642BFD1BE631ULL,
		0x3697875741D617EDULL,
		0x6C578B891D9A00A1ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAC74F87CF4336550ULL,
			0x1632642BFD1BE631ULL,
			0x3697875741D617EDULL,
			0x6C578B891D9A00A1ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE8F63CE10FCD8B75ULL,
			0x459876BA9454EF36ULL,
			0x8584ACCAEE1BF68DULL,
			0x11711F816D48F36CULL}
		},
		.Z = {.key64 = {
			0x057540FB0B2D212DULL,
			0xBD102FC824E15A5DULL,
			0x82825EEBDD6ACAFCULL,
			0x75E5FD28142C9A6EULL}
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

	steps = 41;
	X1 = (curve25519_key_t){.key64 = {
		0x4EEF9DBBBADC07B8ULL,
		0x60B2DDE50032EC6DULL,
		0x20416D1F4FE43441ULL,
		0x5758DF876478F988ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4EEF9DBBBADC07B8ULL,
			0x60B2DDE50032EC6DULL,
			0x20416D1F4FE43441ULL,
			0x5758DF876478F988ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x202587B1118E7401ULL,
			0x6AD6AE967BB72119ULL,
			0x4C55C686E7E362D1ULL,
			0x418CA47250630524ULL}
		},
		.Z = {.key64 = {
			0xB6FFBE1F2933F369ULL,
			0xC94962CBAB85E468ULL,
			0x2B5C544AA8821582ULL,
			0x17409804FB7D8D4EULL}
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

	steps = 55;
	X1 = (curve25519_key_t){.key64 = {
		0x66EC4709B182D928ULL,
		0x543346F1F72AF2E4ULL,
		0x07DFF8A14A5D75C6ULL,
		0x5A5AA32AEA571992ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x66EC4709B182D928ULL,
			0x543346F1F72AF2E4ULL,
			0x07DFF8A14A5D75C6ULL,
			0x5A5AA32AEA571992ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9E43232909808E3CULL,
			0xB36D83C94550E80FULL,
			0x41FBBF264D82394DULL,
			0x42A8D2B2A1818F59ULL}
		},
		.Z = {.key64 = {
			0x99FF7CD99063DB0AULL,
			0xFFA32137B6428B7EULL,
			0x478055FAEE062D18ULL,
			0x75A69D9B964E5828ULL}
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

	steps = 6;
	X1 = (curve25519_key_t){.key64 = {
		0x7244B1D73B86CFA0ULL,
		0xC0810F3DD017C01AULL,
		0x1E267C061C69269EULL,
		0x518A964FA60F272AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7244B1D73B86CFA0ULL,
			0xC0810F3DD017C01AULL,
			0x1E267C061C69269EULL,
			0x518A964FA60F272AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x00ADDD30C4E55660ULL,
			0xB7CAAF4D65EFEF7CULL,
			0x045BCB88CD0D7EC8ULL,
			0x31961629C6C8B95BULL}
		},
		.Z = {.key64 = {
			0xE7B0A5A0F30740EAULL,
			0x22AF6884231F0D48ULL,
			0xB8818EF8A052B040ULL,
			0x5FF3057F268E0857ULL}
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

	steps = 14;
	X1 = (curve25519_key_t){.key64 = {
		0xF9626B8932143740ULL,
		0xD31270CC91E0EAECULL,
		0x64DEB4178D90D82AULL,
		0x74005A39C290F473ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF9626B8932143740ULL,
			0xD31270CC91E0EAECULL,
			0x64DEB4178D90D82AULL,
			0x74005A39C290F473ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8489D71949A50BA4ULL,
			0x8D6C74929A3D95C4ULL,
			0x2119CBD836FEBD39ULL,
			0x6944D67C6080EA37ULL}
		},
		.Z = {.key64 = {
			0x8FF39DF0ED452DBAULL,
			0x2DDB4FCD70263D96ULL,
			0x920DACFE31AB311FULL,
			0x165AD4A389555D42ULL}
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

	steps = 38;
	X1 = (curve25519_key_t){.key64 = {
		0xC435EFAE2029FC28ULL,
		0x6A56DBA90D1682D4ULL,
		0xDCCEB736B292DED0ULL,
		0x40D13BD4D9FBEEF3ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC435EFAE2029FC28ULL,
			0x6A56DBA90D1682D4ULL,
			0xDCCEB736B292DED0ULL,
			0x40D13BD4D9FBEEF3ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6D1438FCA975E616ULL,
			0xD04878F0E99AAA40ULL,
			0x922D83D393DB25C8ULL,
			0x3CCE68F2B165671BULL}
		},
		.Z = {.key64 = {
			0xD96104C6E8D97528ULL,
			0x59E03EAED8ED433DULL,
			0xD4A9F89D22F33380ULL,
			0x7AD822898786D65FULL}
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

	steps = 48;
	X1 = (curve25519_key_t){.key64 = {
		0x3E814B17028EDD90ULL,
		0x1F80A7EA5674813EULL,
		0x3BB0A0FA79D05C3CULL,
		0x6679F5BC3727CADDULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3E814B17028EDD90ULL,
			0x1F80A7EA5674813EULL,
			0x3BB0A0FA79D05C3CULL,
			0x6679F5BC3727CADDULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5351040D001504ABULL,
			0xB982C4C73B59F8B6ULL,
			0x5378715E70CEED22ULL,
			0x1C7278845C906E61ULL}
		},
		.Z = {.key64 = {
			0x5C28E1AF7276FFF6ULL,
			0x098C6ED2E82A8BF1ULL,
			0x54BD535C9A5EB559ULL,
			0x08C36D9AC74BF8BBULL}
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

	steps = 17;
	X1 = (curve25519_key_t){.key64 = {
		0x5AFFD6571C8C7330ULL,
		0xC011268E76FD73C2ULL,
		0x91229764061EDC09ULL,
		0x60681628FB50C729ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5AFFD6571C8C7330ULL,
			0xC011268E76FD73C2ULL,
			0x91229764061EDC09ULL,
			0x60681628FB50C729ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x810E0C0D135F0653ULL,
			0x24F895EF114ADA13ULL,
			0xD722DA386A92E236ULL,
			0x622E084D70481692ULL}
		},
		.Z = {.key64 = {
			0x5028BA2584F427ACULL,
			0xD882D903644677EBULL,
			0xF8FFDCB21D149290ULL,
			0x6D3D0D4077FF56EEULL}
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

	steps = 46;
	X1 = (curve25519_key_t){.key64 = {
		0x3107FFF96475D988ULL,
		0x084034821A563F7EULL,
		0x0D7C707DAEEE2F67ULL,
		0x75F16B601D250364ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3107FFF96475D988ULL,
			0x084034821A563F7EULL,
			0x0D7C707DAEEE2F67ULL,
			0x75F16B601D250364ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5C77623F25B54B86ULL,
			0x678E72820B19757DULL,
			0x294CB75628795300ULL,
			0x3184F0EFB612ECFEULL}
		},
		.Z = {.key64 = {
			0xE34A7949336C2920ULL,
			0xAB43A1D3C49FF06BULL,
			0x8A6EC07CEECAA51FULL,
			0x29BC65DA3B6D7B1AULL}
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

	steps = 7;
	X1 = (curve25519_key_t){.key64 = {
		0x9A5FC9DD0DA1C3F8ULL,
		0x5BE034A66F5D44B7ULL,
		0x497371E31DBF83A8ULL,
		0x47DF2F2C0C69D448ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9A5FC9DD0DA1C3F8ULL,
			0x5BE034A66F5D44B7ULL,
			0x497371E31DBF83A8ULL,
			0x47DF2F2C0C69D448ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCB80125EFE78FFCEULL,
			0x99554FF2EDD39203ULL,
			0x5EB30E32BD0E5A01ULL,
			0x7C7262B26EE03DB2ULL}
		},
		.Z = {.key64 = {
			0xEC48F7969E56EA58ULL,
			0xDD2754FEAE9B5CCCULL,
			0x73AF60E285A6B360ULL,
			0x21818469F9581684ULL}
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

	steps = 21;
	X1 = (curve25519_key_t){.key64 = {
		0xC11C5851516C4128ULL,
		0xC150A37A37FDC329ULL,
		0x1235D27B12EA2C88ULL,
		0x5099C39AAC2D27CAULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC11C5851516C4128ULL,
			0xC150A37A37FDC329ULL,
			0x1235D27B12EA2C88ULL,
			0x5099C39AAC2D27CAULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2FCCCA19E881EB28ULL,
			0x61013A07B4AD6939ULL,
			0x726D790B5253DD5FULL,
			0x343B691DF718C980ULL}
		},
		.Z = {.key64 = {
			0x1194EC1D5111929FULL,
			0xEFABE841B73D53E9ULL,
			0x10656D2E086DDED6ULL,
			0x22ADA9B72AF41B80ULL}
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

	steps = 18;
	X1 = (curve25519_key_t){.key64 = {
		0x667F677712E5A920ULL,
		0x85B4D3AC867B253FULL,
		0x5BA111BD74E3B821ULL,
		0x74E3FC53B2528445ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x667F677712E5A920ULL,
			0x85B4D3AC867B253FULL,
			0x5BA111BD74E3B821ULL,
			0x74E3FC53B2528445ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2AE7B264586DE70AULL,
			0x8208E68AC03582D8ULL,
			0xCDA47C96C7D9BC95ULL,
			0x4FA8730F8C09CFA4ULL}
		},
		.Z = {.key64 = {
			0x3049E6E2FFA7FFB2ULL,
			0x1B2F39D016D98966ULL,
			0xA715FD7D5501BF33ULL,
			0x018A5734D6D7FAA5ULL}
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

	steps = 28;
	X1 = (curve25519_key_t){.key64 = {
		0x9B3E2DCE4A63C400ULL,
		0xC1952D9A3998F31DULL,
		0xAF44582772EE257DULL,
		0x60CC58CE4751AC8BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9B3E2DCE4A63C400ULL,
			0xC1952D9A3998F31DULL,
			0xAF44582772EE257DULL,
			0x60CC58CE4751AC8BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x04E9986E2BFEE343ULL,
			0x8E8241A744564261ULL,
			0x143E5ECAF7BCC39CULL,
			0x79F3908348F9931EULL}
		},
		.Z = {.key64 = {
			0xD4668D49FA849917ULL,
			0x9F2FD27E4A923193ULL,
			0x7F437D4493E78165ULL,
			0x4B51395BC052F5EBULL}
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

	steps = 43;
	X1 = (curve25519_key_t){.key64 = {
		0xBD84160234265518ULL,
		0x2AD574272678779AULL,
		0x4BC30996C345C02DULL,
		0x7D982C800FB41441ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBD84160234265518ULL,
			0x2AD574272678779AULL,
			0x4BC30996C345C02DULL,
			0x7D982C800FB41441ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDD0CD228F518C032ULL,
			0x7F53B1ECD14C93D5ULL,
			0xCD068539E9FBF518ULL,
			0x240793F5F245D8E4ULL}
		},
		.Z = {.key64 = {
			0x2941635A6E0F0CD8ULL,
			0x8B9705FFFF380942ULL,
			0xDDD44116F47FB19EULL,
			0x2A8C15ED25B501C3ULL}
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

	steps = 61;
	X1 = (curve25519_key_t){.key64 = {
		0x317F7A625CDB7A48ULL,
		0xB6FA9A23FD579B68ULL,
		0xBE6178DF4026A3A1ULL,
		0x638E6DEB064408E2ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x317F7A625CDB7A48ULL,
			0xB6FA9A23FD579B68ULL,
			0xBE6178DF4026A3A1ULL,
			0x638E6DEB064408E2ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x424810F94574CB2EULL,
			0x01D8BF9F41970D1BULL,
			0x5D612C823DB374C0ULL,
			0x7A2679188B356B66ULL}
		},
		.Z = {.key64 = {
			0x38D07830854C4596ULL,
			0x3183B7CB6F57340BULL,
			0x1DE3EC10B0581A51ULL,
			0x123D7A4200BC48FFULL}
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

	steps = 57;
	X1 = (curve25519_key_t){.key64 = {
		0xA041AF8825195028ULL,
		0xF18B631F09F785FDULL,
		0xF0241DB2190EE611ULL,
		0x6BFB2DC414CEADACULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA041AF8825195028ULL,
			0xF18B631F09F785FDULL,
			0xF0241DB2190EE611ULL,
			0x6BFB2DC414CEADACULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5E02328561C42488ULL,
			0x809A7B3019398B63ULL,
			0x4B86706662287085ULL,
			0x3771821A32807959ULL}
		},
		.Z = {.key64 = {
			0x13265A824BB8536EULL,
			0xBEEDA5F44E4FB889ULL,
			0x7079930CAD998443ULL,
			0x64B82B5B8EDC9B3DULL}
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

	steps = 50;
	X1 = (curve25519_key_t){.key64 = {
		0xADF522791F6FF1F0ULL,
		0x849A0BD9031A282AULL,
		0x56C458D71E7145A0ULL,
		0x4E2A11EBC522038DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xADF522791F6FF1F0ULL,
			0x849A0BD9031A282AULL,
			0x56C458D71E7145A0ULL,
			0x4E2A11EBC522038DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x66C7240CA422CE88ULL,
			0xA76A368A8649598EULL,
			0x3BA118C0551058C7ULL,
			0x2F0827A030FCD470ULL}
		},
		.Z = {.key64 = {
			0xF3CD9FBBE9DECE01ULL,
			0x24BCCD4F7D58DF6EULL,
			0x57C02471421DC158ULL,
			0x723D86C3766801D0ULL}
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

	steps = 36;
	X1 = (curve25519_key_t){.key64 = {
		0x17C142D7AC5D57C0ULL,
		0x0F885878D605D3CFULL,
		0x38D4E859DFA8B144ULL,
		0x77F947D4AFBFCDD1ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x17C142D7AC5D57C0ULL,
			0x0F885878D605D3CFULL,
			0x38D4E859DFA8B144ULL,
			0x77F947D4AFBFCDD1ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAF2F27A98A0944EBULL,
			0x5E4A2562D958232CULL,
			0x29BA00683CAC7D21ULL,
			0x424C0C2CFFD4E805ULL}
		},
		.Z = {.key64 = {
			0xFC7B8DA4967D5462ULL,
			0xF710FBC46354DDDDULL,
			0xA3ADFC3A0C8C7D3BULL,
			0x15E2B57292630EDFULL}
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

	steps = 40;
	X1 = (curve25519_key_t){.key64 = {
		0x2A87FC7CA3794EE0ULL,
		0x2C5B06A5C276B895ULL,
		0x38765252B2BE05B2ULL,
		0x62A73F3EDA49BBE5ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2A87FC7CA3794EE0ULL,
			0x2C5B06A5C276B895ULL,
			0x38765252B2BE05B2ULL,
			0x62A73F3EDA49BBE5ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9CC605901015211DULL,
			0xB73A1E4304793663ULL,
			0x25CEBE6DD8CD67CFULL,
			0x11BB19A91E6FB842ULL}
		},
		.Z = {.key64 = {
			0x08900DBBB8D57C23ULL,
			0xD21B90C86D827912ULL,
			0x5DB5E148B1D8BE96ULL,
			0x19064F7C37E10E4CULL}
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

	steps = 49;
	X1 = (curve25519_key_t){.key64 = {
		0xD5DC6683471CB0A8ULL,
		0x186CEED21B753DF7ULL,
		0x802881CD47CE56DFULL,
		0x6BA0E065821C3424ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD5DC6683471CB0A8ULL,
			0x186CEED21B753DF7ULL,
			0x802881CD47CE56DFULL,
			0x6BA0E065821C3424ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9EF1DF63CF87B24EULL,
			0xFB6B50D95DD11119ULL,
			0x277DA586B30ADCA3ULL,
			0x741102327052B1FDULL}
		},
		.Z = {.key64 = {
			0x7B818951FC525354ULL,
			0x7AC4DCC735E1798EULL,
			0x5A531913542C9616ULL,
			0x6597B52156A711E8ULL}
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

	steps = 53;
	X1 = (curve25519_key_t){.key64 = {
		0xDFA9130E746F7448ULL,
		0xF705F34412AB5371ULL,
		0x679413E93BC64638ULL,
		0x7B2D282FE7A8BA7FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDFA9130E746F7448ULL,
			0xF705F34412AB5371ULL,
			0x679413E93BC64638ULL,
			0x7B2D282FE7A8BA7FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x390FE48D98740A3EULL,
			0x4C9F219563C0E56FULL,
			0xBA48019104A37617ULL,
			0x0644A52190DA19CAULL}
		},
		.Z = {.key64 = {
			0xBA97E20BCB25E0C0ULL,
			0x7F1548B5A6BE1B2DULL,
			0x72992B77DB2E3318ULL,
			0x39F547B10A6560A4ULL}
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

	steps = 43;
	X1 = (curve25519_key_t){.key64 = {
		0xE8C88FE5CBDA8C68ULL,
		0x4D2568C5E038EEEDULL,
		0xD6209AD4AE260463ULL,
		0x6298435D91B8F139ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE8C88FE5CBDA8C68ULL,
			0x4D2568C5E038EEEDULL,
			0xD6209AD4AE260463ULL,
			0x6298435D91B8F139ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x666E83BEEB28C7ECULL,
			0xCCEC4BD6AE270C91ULL,
			0xED13F5C6884A99F8ULL,
			0x5CD84D2B034CD0BBULL}
		},
		.Z = {.key64 = {
			0xE9D65C2FA68F6476ULL,
			0x84AC9B2EE5B94FB3ULL,
			0xD99339B1F5B126FBULL,
			0x3E1962CF17D9DDE8ULL}
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
		0x9BEAEEB127EB9A58ULL,
		0xEE47C891A759B8FDULL,
		0xAFF92CC530A6F428ULL,
		0x47EA2148703707CDULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9BEAEEB127EB9A58ULL,
			0xEE47C891A759B8FDULL,
			0xAFF92CC530A6F428ULL,
			0x47EA2148703707CDULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3222943AA2D13146ULL,
			0xFA3C0B0FE7866D35ULL,
			0x35092A65574833ECULL,
			0x39A2BDAC1ABA902AULL}
		},
		.Z = {.key64 = {
			0xA86CB31D1BCB2967ULL,
			0x35298B1ABC642B0BULL,
			0x1FF910D58609B88AULL,
			0x66AB1BE479725B59ULL}
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

	steps = 21;
	X1 = (curve25519_key_t){.key64 = {
		0xFCF8572289E4D428ULL,
		0x6703D1955A4BFEAEULL,
		0xD934BF7C968897EDULL,
		0x6FF838D7F60F072DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFCF8572289E4D428ULL,
			0x6703D1955A4BFEAEULL,
			0xD934BF7C968897EDULL,
			0x6FF838D7F60F072DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF4BCA1C17DCCE845ULL,
			0xE3C17D067EA26213ULL,
			0xDE2D2CAED14FB8EEULL,
			0x2FFE78D1CC1B60E6ULL}
		},
		.Z = {.key64 = {
			0x2A5062F35257EC76ULL,
			0x103452340F4AD428ULL,
			0xBE376296A2F963CAULL,
			0x0BEB6DC48AE40B7EULL}
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

	steps = 26;
	X1 = (curve25519_key_t){.key64 = {
		0xAE4D458A29C3CFD0ULL,
		0x79CE006EB38B535AULL,
		0x2D83B36349B84A7DULL,
		0x76D73405D2F6CB70ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAE4D458A29C3CFD0ULL,
			0x79CE006EB38B535AULL,
			0x2D83B36349B84A7DULL,
			0x76D73405D2F6CB70ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4170582B940E2DDCULL,
			0xCC2FFFBCAAD2632FULL,
			0x33A5F1D8D943689EULL,
			0x0DCC4ACE46641FBAULL}
		},
		.Z = {.key64 = {
			0xA4B933CAC687DA3FULL,
			0x1BDAE91B3ECB3D24ULL,
			0x41C664D79F16545DULL,
			0x30042E925BF0C0ECULL}
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

	steps = 7;
	X1 = (curve25519_key_t){.key64 = {
		0xEFA7CF0060CF05D8ULL,
		0xB40251345851C6B8ULL,
		0x61848B202E9FDDB9ULL,
		0x56150CD0FA847D59ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEFA7CF0060CF05D8ULL,
			0xB40251345851C6B8ULL,
			0x61848B202E9FDDB9ULL,
			0x56150CD0FA847D59ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4A2F575A3B0EBF82ULL,
			0x7EDFD0A3ED76FFBCULL,
			0x8DE90EC39AE9EEEBULL,
			0x20385C74D0A558F2ULL}
		},
		.Z = {.key64 = {
			0x4323648E1BB46342ULL,
			0x363948A3479EAD24ULL,
			0x20009196CD5079AAULL,
			0x16122799C977974CULL}
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

	steps = 12;
	X1 = (curve25519_key_t){.key64 = {
		0x87B2E9F2D03EF978ULL,
		0xD0F5FE7126973CBEULL,
		0x081D57DAC58B4031ULL,
		0x61AD10917C0D08E2ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x87B2E9F2D03EF978ULL,
			0xD0F5FE7126973CBEULL,
			0x081D57DAC58B4031ULL,
			0x61AD10917C0D08E2ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x820F05DADB1A4B8BULL,
			0x3C4AB11E26B1B744ULL,
			0xEC75FBBD0198B576ULL,
			0x2779C0BDEBAFB7DEULL}
		},
		.Z = {.key64 = {
			0xAC2C31799D9A2CA3ULL,
			0xC9D9AA63F3A54408ULL,
			0x8BD1CBA4E881A359ULL,
			0x705DA804C787B37DULL}
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

	steps = 51;
	X1 = (curve25519_key_t){.key64 = {
		0x34D465E579CA5B00ULL,
		0x56903813BB0EC2A8ULL,
		0x32E2E067E74E2911ULL,
		0x76AC20DF9F4AE826ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x34D465E579CA5B00ULL,
			0x56903813BB0EC2A8ULL,
			0x32E2E067E74E2911ULL,
			0x76AC20DF9F4AE826ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4DEDE05F74A093E7ULL,
			0x3EA38921791C8FD2ULL,
			0xF34D2D2804F706E4ULL,
			0x5D4A14841C8F1BF4ULL}
		},
		.Z = {.key64 = {
			0xC9E6467156374D5EULL,
			0x02510AD15E018F26ULL,
			0x5DEF7BA9DABDF5E9ULL,
			0x5AB0A38D7F418E96ULL}
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

	steps = 11;
	X1 = (curve25519_key_t){.key64 = {
		0xCC0C6499809A5990ULL,
		0x6E9B8BD662702DCBULL,
		0x2FA9E36DAEE322F9ULL,
		0x407B18ECA9F46340ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCC0C6499809A5990ULL,
			0x6E9B8BD662702DCBULL,
			0x2FA9E36DAEE322F9ULL,
			0x407B18ECA9F46340ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD08866E0EEFE6A49ULL,
			0x74105B411FCD4486ULL,
			0x2E3CCEA4122D80DBULL,
			0x4EC52E22D4AE1836ULL}
		},
		.Z = {.key64 = {
			0x26D910E4817522EBULL,
			0x14F9E7E0234B9B03ULL,
			0x111C5A7318C7F10BULL,
			0x533101A8C2279F61ULL}
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

	steps = 3;
	X1 = (curve25519_key_t){.key64 = {
		0x45FAB34C1E1C5E48ULL,
		0x1F6972AEA1032BF2ULL,
		0x85E084F7F5347DC9ULL,
		0x501BB0662EC6E27DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x45FAB34C1E1C5E48ULL,
			0x1F6972AEA1032BF2ULL,
			0x85E084F7F5347DC9ULL,
			0x501BB0662EC6E27DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x25506667E6C4365DULL,
			0x14E8F1C32540C6D4ULL,
			0xE3CED328AD2244E1ULL,
			0x271D30F20513E80EULL}
		},
		.Z = {.key64 = {
			0xCC83C10414D21017ULL,
			0xF845DBA6921739F1ULL,
			0x63D9FC7A8B778DBCULL,
			0x52604F4B1456E8E7ULL}
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

	steps = 16;
	X1 = (curve25519_key_t){.key64 = {
		0x170A78B5AFAAD4F0ULL,
		0x4DC9CD7D152DB9DFULL,
		0x9143D6A3751BCA7BULL,
		0x43757C5027EB272BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x170A78B5AFAAD4F0ULL,
			0x4DC9CD7D152DB9DFULL,
			0x9143D6A3751BCA7BULL,
			0x43757C5027EB272BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE855D9F2283874E2ULL,
			0x68EDB47940CD65E8ULL,
			0xE6F858A0FEB56E9BULL,
			0x5B65A5DAA5E0056FULL}
		},
		.Z = {.key64 = {
			0xC09194ADD8F2AF47ULL,
			0x4645F5D5B07B372BULL,
			0xE59AF452DD5AB43CULL,
			0x163464FCA6669D8EULL}
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

	steps = 44;
	X1 = (curve25519_key_t){.key64 = {
		0x0957862A578EC8F8ULL,
		0xA5954705C28D84DBULL,
		0x2EA71C38658FE1C9ULL,
		0x4DEE6109549E6350ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0957862A578EC8F8ULL,
			0xA5954705C28D84DBULL,
			0x2EA71C38658FE1C9ULL,
			0x4DEE6109549E6350ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA079F10D37A4D3D2ULL,
			0xE1EAB983C551EEC4ULL,
			0x8A681B5E8B0C98A4ULL,
			0x29ADD5C41D4C69D1ULL}
		},
		.Z = {.key64 = {
			0x4BB9C754379159EAULL,
			0xB0BA7BCFE8010A27ULL,
			0x4292EFF6D5289A06ULL,
			0x5F836D3B1A6E6CFDULL}
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

	steps = 1;
	X1 = (curve25519_key_t){.key64 = {
		0xA619AE1290545688ULL,
		0x73CD5CA142B9DEE6ULL,
		0x45BFC4A2F5AE16BEULL,
		0x68DC197D77AF20BAULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA619AE1290545688ULL,
			0x73CD5CA142B9DEE6ULL,
			0x45BFC4A2F5AE16BEULL,
			0x68DC197D77AF20BAULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDF8E1A6FAC42F3B0ULL,
			0x3EA8B1843D315357ULL,
			0x64CA7A2F1F6B89C5ULL,
			0x279B8026D184CA79ULL}
		},
		.Z = {.key64 = {
			0x9866B84A41515A59ULL,
			0xCF3572850AE77B9AULL,
			0x16FF128BD6B85AF9ULL,
			0x237065F5DEBC82E9ULL}
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

	steps = 49;
	X1 = (curve25519_key_t){.key64 = {
		0x4F98BC4D1DAF0B10ULL,
		0x783E527AAE7FDBA9ULL,
		0x321B413DFDFA3B1BULL,
		0x452F73F057F918ECULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4F98BC4D1DAF0B10ULL,
			0x783E527AAE7FDBA9ULL,
			0x321B413DFDFA3B1BULL,
			0x452F73F057F918ECULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x708C85387A84C9DBULL,
			0x39D940F139D13A13ULL,
			0x09F5D9F3E1A34BF2ULL,
			0x435FE86883775EE8ULL}
		},
		.Z = {.key64 = {
			0xDBA806DD67E7989EULL,
			0x32204250B13CCD88ULL,
			0xCF606FDFAF18E94AULL,
			0x21AD528E88F442AEULL}
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

	steps = 51;
	X1 = (curve25519_key_t){.key64 = {
		0xF8DBC7DAF57A00E8ULL,
		0x3F388FA62BCF3111ULL,
		0x4F20EBE55C0F35ECULL,
		0x6E47271AF0DE53AAULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF8DBC7DAF57A00E8ULL,
			0x3F388FA62BCF3111ULL,
			0x4F20EBE55C0F35ECULL,
			0x6E47271AF0DE53AAULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA47853F28B3654D7ULL,
			0x200030B0F03B30B9ULL,
			0x03CA12385CBCC2A4ULL,
			0x69FAE9375D159A75ULL}
		},
		.Z = {.key64 = {
			0xB1BA5381A6B89985ULL,
			0xB4C17F912615A507ULL,
			0x292B472F9A3EE433ULL,
			0x05C920BBE393C338ULL}
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

	steps = 10;
	X1 = (curve25519_key_t){.key64 = {
		0x7EDC6EC437F2E8E0ULL,
		0x6C9A4DDA5682FA96ULL,
		0x37F04E68CFD3B49DULL,
		0x77F22038B42303F2ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7EDC6EC437F2E8E0ULL,
			0x6C9A4DDA5682FA96ULL,
			0x37F04E68CFD3B49DULL,
			0x77F22038B42303F2ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1CBB9CAD5D10175DULL,
			0x8BC84869E93AE8B6ULL,
			0xE233F3E1B6272B43ULL,
			0x349569388A7D80CAULL}
		},
		.Z = {.key64 = {
			0xEE669F53CBB79517ULL,
			0xC781F86F2F169BEAULL,
			0x07F3AADD6EAF609FULL,
			0x18118D811F03E95BULL}
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

	steps = 61;
	X1 = (curve25519_key_t){.key64 = {
		0x8BA46E927C8CC670ULL,
		0x9F8AD20DF809ECA9ULL,
		0x5AE45FFB60160832ULL,
		0x5303149B4D2CD424ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8BA46E927C8CC670ULL,
			0x9F8AD20DF809ECA9ULL,
			0x5AE45FFB60160832ULL,
			0x5303149B4D2CD424ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x07024F9857A86378ULL,
			0xB1BF3A59C13768BAULL,
			0x722158D3EEF1DB43ULL,
			0x5E742DC301CB8C80ULL}
		},
		.Z = {.key64 = {
			0x34BB32C06D46EFA1ULL,
			0x502C6DBB7177D070ULL,
			0x408ACB0086315FCAULL,
			0x157BF9ECE644A625ULL}
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

	steps = 64;
	X1 = (curve25519_key_t){.key64 = {
		0xEDFC3BC3C8ADF308ULL,
		0x3FE2B75E921B7ACEULL,
		0xF1BB7E42D3275322ULL,
		0x4E66A9C53239DBF2ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEDFC3BC3C8ADF308ULL,
			0x3FE2B75E921B7ACEULL,
			0xF1BB7E42D3275322ULL,
			0x4E66A9C53239DBF2ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF8EFCAF30B403F7FULL,
			0x2D1125E406F4CBEDULL,
			0x8C14EE64A70AC785ULL,
			0x75EBFC802BCAEAC6ULL}
		},
		.Z = {.key64 = {
			0xEAB47AF7EFB0F0AEULL,
			0x76D7E12EE674B464ULL,
			0x90D7AB02AB6EC4C5ULL,
			0x50F204AD95C5F02DULL}
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

	steps = 16;
	X1 = (curve25519_key_t){.key64 = {
		0x3419B24DA7DD1758ULL,
		0x2C0732E8B953F7D5ULL,
		0xB4EBBF99078080C3ULL,
		0x4930FAC8B1F07936ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3419B24DA7DD1758ULL,
			0x2C0732E8B953F7D5ULL,
			0xB4EBBF99078080C3ULL,
			0x4930FAC8B1F07936ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFD4225341A8DFFD4ULL,
			0x1170EA8005824F54ULL,
			0x35EDBE9EB80C5B37ULL,
			0x455FABED739B1EC5ULL}
		},
		.Z = {.key64 = {
			0xB7840B36291AB3ACULL,
			0xE907F7D55BFE35F3ULL,
			0x20CE1263FADE8DFCULL,
			0x3D1BE6D13D74425FULL}
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

	steps = 37;
	X1 = (curve25519_key_t){.key64 = {
		0x8370E2BD40FFF7D0ULL,
		0xE1F21344A6D5B3F0ULL,
		0xB53FD8BC68C4DBA5ULL,
		0x6DA4565D73D0BDC4ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8370E2BD40FFF7D0ULL,
			0xE1F21344A6D5B3F0ULL,
			0xB53FD8BC68C4DBA5ULL,
			0x6DA4565D73D0BDC4ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x125D4AC3EA8E1573ULL,
			0x98794EF850DABBA9ULL,
			0xB4A174C3D748B486ULL,
			0x34FA4F15EAE34B96ULL}
		},
		.Z = {.key64 = {
			0x152AD0612ED68A05ULL,
			0xD0C36B7BADF665FCULL,
			0x21BCFBF47769AA77ULL,
			0x00019B5D91506B12ULL}
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

	steps = 33;
	X1 = (curve25519_key_t){.key64 = {
		0xB06491B4040FFF70ULL,
		0x3B1FD137225140ACULL,
		0x4A177481E5C8D6B6ULL,
		0x7927F273E8DAC07FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB06491B4040FFF70ULL,
			0x3B1FD137225140ACULL,
			0x4A177481E5C8D6B6ULL,
			0x7927F273E8DAC07FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAD842B271738EB57ULL,
			0xF444C647BF18DFA9ULL,
			0xFA87835816218901ULL,
			0x530C906D1C599AF0ULL}
		},
		.Z = {.key64 = {
			0x10C5FDEF8BAA9CDCULL,
			0x8C1C77CF04AB79CDULL,
			0x146B3D4273F7512BULL,
			0x476E4BD4F3C2B3FDULL}
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

	steps = 49;
	X1 = (curve25519_key_t){.key64 = {
		0x7153180B9818D7E0ULL,
		0x7695FCEE1E5ADF3AULL,
		0x2FC0A48C0FC15BE3ULL,
		0x75070A2B57782068ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7153180B9818D7E0ULL,
			0x7695FCEE1E5ADF3AULL,
			0x2FC0A48C0FC15BE3ULL,
			0x75070A2B57782068ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2D543CD46420E807ULL,
			0xBFA6D66858C9791FULL,
			0x1EF209C08A615749ULL,
			0x4778C96C7CB25171ULL}
		},
		.Z = {.key64 = {
			0x66F689EEE8C4C655ULL,
			0x438004D675942C5AULL,
			0x8824BB84402EDE6FULL,
			0x6D8E4492A9EF5E7AULL}
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

	steps = 49;
	X1 = (curve25519_key_t){.key64 = {
		0x6FCC57F168D233D8ULL,
		0xE2D8976C0A1B106FULL,
		0x164ABA61DBD4C02BULL,
		0x5B928BF3A6B1389EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6FCC57F168D233D8ULL,
			0xE2D8976C0A1B106FULL,
			0x164ABA61DBD4C02BULL,
			0x5B928BF3A6B1389EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD029D839803DA1DBULL,
			0x1624AA8A748ABB24ULL,
			0xB18C1D35D4D8EE72ULL,
			0x5BA4152E27531DD2ULL}
		},
		.Z = {.key64 = {
			0x5A93CC742739A00FULL,
			0x6C62FE03F047EFE6ULL,
			0x192681FF125F7ACEULL,
			0x2F82AF71D95888C8ULL}
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
		0xEB6E645D493247E8ULL,
		0xE827FC34BDB4D911ULL,
		0x8FCF855BB6AB6C8DULL,
		0x67481D012C44EED3ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEB6E645D493247E8ULL,
			0xE827FC34BDB4D911ULL,
			0x8FCF855BB6AB6C8DULL,
			0x67481D012C44EED3ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x01B83C6E78F3A1A2ULL,
			0x088A8970A03CD6C8ULL,
			0x2AB286C832C666D8ULL,
			0x7EA74E785BCE305EULL}
		},
		.Z = {.key64 = {
			0x8D22CC7490DF5C81ULL,
			0xBDD80E7786D5AD41ULL,
			0xFEF4D012B3AA1C87ULL,
			0x001B606232E2E03EULL}
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

	steps = 48;
	X1 = (curve25519_key_t){.key64 = {
		0xE1079101F261F720ULL,
		0x790C845E23BCF8D5ULL,
		0xA754A5661DF2A8BBULL,
		0x62A2536F9D8C08F6ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE1079101F261F720ULL,
			0x790C845E23BCF8D5ULL,
			0xA754A5661DF2A8BBULL,
			0x62A2536F9D8C08F6ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1D56D21D459CB51FULL,
			0xC43569057261C7E5ULL,
			0x6FA48BAE15ABF11AULL,
			0x7E9AA083DBC25766ULL}
		},
		.Z = {.key64 = {
			0x3CAAA4731AAF7952ULL,
			0xFB14FAEB324BFD61ULL,
			0xE0DA6FBA653E830DULL,
			0x0C6125E05C9490EBULL}
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

	steps = 57;
	X1 = (curve25519_key_t){.key64 = {
		0xDD549D14835A01B0ULL,
		0xE63B45BA74428AACULL,
		0xC44858D1A300823EULL,
		0x589136DF340109DDULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDD549D14835A01B0ULL,
			0xE63B45BA74428AACULL,
			0xC44858D1A300823EULL,
			0x589136DF340109DDULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB0F2C3A6B02316BCULL,
			0x85C62AE40B0A9DFBULL,
			0x91F6004676936097ULL,
			0x6D4FEA0A423FEEF3ULL}
		},
		.Z = {.key64 = {
			0xDD3D596BC9912A5AULL,
			0x28811E8834F561C4ULL,
			0xF7E528D7D7EBF89DULL,
			0x180BA60EC9792BABULL}
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

	steps = 59;
	X1 = (curve25519_key_t){.key64 = {
		0x59B28BEE8D0E6E58ULL,
		0xBA7BA4F0244CFA1FULL,
		0x37FFD5A88B3F63CBULL,
		0x541087CD26C28E4CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x59B28BEE8D0E6E58ULL,
			0xBA7BA4F0244CFA1FULL,
			0x37FFD5A88B3F63CBULL,
			0x541087CD26C28E4CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB0D34BD84634E95DULL,
			0x8BC731A0FEC5E9A8ULL,
			0x4890FE0EB12991D7ULL,
			0x5680C386D3E4D78CULL}
		},
		.Z = {.key64 = {
			0x16F25859C96A5A45ULL,
			0xC20F50BC2CE413DFULL,
			0xFB01291D79549FA9ULL,
			0x0863727DDFF246FAULL}
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

	steps = 31;
	X1 = (curve25519_key_t){.key64 = {
		0x1BCD1C59BA2001B0ULL,
		0x982C7BF0C30A27A3ULL,
		0xE02BEC73EE711779ULL,
		0x74DDB0FFC17E82CCULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1BCD1C59BA2001B0ULL,
			0x982C7BF0C30A27A3ULL,
			0xE02BEC73EE711779ULL,
			0x74DDB0FFC17E82CCULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6FC28777A1FB0BBDULL,
			0x1C31C985D4C36EFEULL,
			0xE8EF0F65C50C9EC4ULL,
			0x5B8EB28107E2665FULL}
		},
		.Z = {.key64 = {
			0x50235EE2F374E91CULL,
			0x50F0DAACE13DC9CDULL,
			0x108898E901271CF3ULL,
			0x5012BF2408269943ULL}
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

	steps = 26;
	X1 = (curve25519_key_t){.key64 = {
		0x6E28CA41007764B0ULL,
		0xA3362FB2BBF82790ULL,
		0xD8872128EFF2969FULL,
		0x679F9978AC506CE1ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6E28CA41007764B0ULL,
			0xA3362FB2BBF82790ULL,
			0xD8872128EFF2969FULL,
			0x679F9978AC506CE1ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD66C9FEAA579AE81ULL,
			0xEA50DF189692B891ULL,
			0x40725DAF15764497ULL,
			0x509464E8031A1DFDULL}
		},
		.Z = {.key64 = {
			0x357ED524BA416175ULL,
			0xF504EE095045D3C4ULL,
			0xC2EC698F6D67BFA9ULL,
			0x19580D72019F1A80ULL}
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

	steps = 46;
	X1 = (curve25519_key_t){.key64 = {
		0x8A41DCE5D131D290ULL,
		0x985869EA1E6F3811ULL,
		0x7D7FCC3745597298ULL,
		0x69BABE9D7F7ED81AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8A41DCE5D131D290ULL,
			0x985869EA1E6F3811ULL,
			0x7D7FCC3745597298ULL,
			0x69BABE9D7F7ED81AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE9C5509C79F5DE55ULL,
			0x8796B18BF8866913ULL,
			0x52B5386EAF594F64ULL,
			0x184450FCACA89FA7ULL}
		},
		.Z = {.key64 = {
			0x7EA224B56D7D7EF1ULL,
			0x036DECA7472EA72DULL,
			0x8D4CB3672513C40AULL,
			0x1566257BE6319301ULL}
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

	steps = 16;
	X1 = (curve25519_key_t){.key64 = {
		0x8C37B3B0B52B7AF0ULL,
		0x932BA60893F6ECE2ULL,
		0x4AF33D35DBFA5854ULL,
		0x4B455482C1351272ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8C37B3B0B52B7AF0ULL,
			0x932BA60893F6ECE2ULL,
			0x4AF33D35DBFA5854ULL,
			0x4B455482C1351272ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDCA54E32AAEC032FULL,
			0xF78A85B353841CEFULL,
			0x605A0B7C41B9B9BAULL,
			0x702DE891E0C49DEBULL}
		},
		.Z = {.key64 = {
			0x160C88CF6EC12707ULL,
			0x5BB7A16D47506FD6ULL,
			0x47AA7B554D0FCB72ULL,
			0x3D702CDC66EA029EULL}
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

	steps = 52;
	X1 = (curve25519_key_t){.key64 = {
		0xF796A98744BBB278ULL,
		0x449565FC230CE0E0ULL,
		0x3DE926F0B82CE04EULL,
		0x686000BCE878816DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF796A98744BBB278ULL,
			0x449565FC230CE0E0ULL,
			0x3DE926F0B82CE04EULL,
			0x686000BCE878816DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC533922E87FB7F47ULL,
			0x9EFE10EE65A6BDC1ULL,
			0xF71F86E6404B2C3AULL,
			0x684E6561451367E4ULL}
		},
		.Z = {.key64 = {
			0xA93A43FBDF3B4F7FULL,
			0x28362485B3BC9A7CULL,
			0x533E96741C1E21B2ULL,
			0x30077CD84A2DD2EEULL}
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

	steps = 12;
	X1 = (curve25519_key_t){.key64 = {
		0xC634A7847D7E3910ULL,
		0x5CA749835C91E97EULL,
		0x2BAC29FC302D679CULL,
		0x7A513D4BCF13A12BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC634A7847D7E3910ULL,
			0x5CA749835C91E97EULL,
			0x2BAC29FC302D679CULL,
			0x7A513D4BCF13A12BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x99530877FD2ED465ULL,
			0x2076861BD2DCBB1EULL,
			0x3673772049B80D45ULL,
			0x26418FBB5EB79DBCULL}
		},
		.Z = {.key64 = {
			0xFF7120B3E08E35FCULL,
			0xA4A0D07E9849547BULL,
			0xD53C071EB4F06080ULL,
			0x5E33270E8A6578ABULL}
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

	steps = 10;
	X1 = (curve25519_key_t){.key64 = {
		0xEF8CB2C42A8E2B68ULL,
		0xD56564A6CA85861DULL,
		0x244D7D85FA201EECULL,
		0x72C97049BE31E983ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEF8CB2C42A8E2B68ULL,
			0xD56564A6CA85861DULL,
			0x244D7D85FA201EECULL,
			0x72C97049BE31E983ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2529452D1FF1CEDBULL,
			0x31496A10F02B44B5ULL,
			0xDE478615974C00E5ULL,
			0x0D9CB4B0DFFF869EULL}
		},
		.Z = {.key64 = {
			0x2715F9DA0A7E03F1ULL,
			0x656F1C7EC179A732ULL,
			0x24415903513EF46FULL,
			0x030FCA7755C492E4ULL}
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

	steps = 18;
	X1 = (curve25519_key_t){.key64 = {
		0x54CED6959EECD758ULL,
		0xB02737007CA86483ULL,
		0x7A251F2D1DA679A8ULL,
		0x662EC97A081BA0F3ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x54CED6959EECD758ULL,
			0xB02737007CA86483ULL,
			0x7A251F2D1DA679A8ULL,
			0x662EC97A081BA0F3ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8C2BEB9F3CACC133ULL,
			0x4488713BC88ADDAEULL,
			0x0AA3DA5610B6BE77ULL,
			0x34D0C1A0C83B71DEULL}
		},
		.Z = {.key64 = {
			0xD99D011A681345D2ULL,
			0x4EF738F8D6AE421CULL,
			0x7B3B69E9760A6E3DULL,
			0x2D36298D7CBFD293ULL}
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

	steps = 59;
	X1 = (curve25519_key_t){.key64 = {
		0x57BE1DAA92057A28ULL,
		0xA8B9B7DCD7EA8A6BULL,
		0xDA36E03EAE74398BULL,
		0x5BB9BB0C6B6EF9B8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x57BE1DAA92057A28ULL,
			0xA8B9B7DCD7EA8A6BULL,
			0xDA36E03EAE74398BULL,
			0x5BB9BB0C6B6EF9B8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB916A5DAEDF965FCULL,
			0x4858085874F57979ULL,
			0x497D4C9E5E1DBCF1ULL,
			0x6DE0CF34204A4049ULL}
		},
		.Z = {.key64 = {
			0x737455CC38823410ULL,
			0x5DE8E0DE0C018D99ULL,
			0x95E96933819256C1ULL,
			0x2B2C30F89FBDEA2EULL}
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

	steps = 58;
	X1 = (curve25519_key_t){.key64 = {
		0xD176FF0CAF5F0600ULL,
		0xF3336982B9B1D2DCULL,
		0x31EFCD7DD8AE31E7ULL,
		0x7F230D35AF97052CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD176FF0CAF5F0600ULL,
			0xF3336982B9B1D2DCULL,
			0x31EFCD7DD8AE31E7ULL,
			0x7F230D35AF97052CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC9675F8C464EA7ECULL,
			0xBCF5687CD5CDC4E4ULL,
			0x36F3FC71A0EF58C7ULL,
			0x09DE09AAF9132DFDULL}
		},
		.Z = {.key64 = {
			0x1728F72AFFE070EAULL,
			0x64A43786889CD1C0ULL,
			0x7ECB6EB01B5DAABBULL,
			0x31AAA727AD87893AULL}
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

	steps = 9;
	X1 = (curve25519_key_t){.key64 = {
		0x88063DE3129166F0ULL,
		0xE8F94F6B988EFBF5ULL,
		0xBC235524F9CBA49FULL,
		0x5BFDB278C541B09DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x88063DE3129166F0ULL,
			0xE8F94F6B988EFBF5ULL,
			0xBC235524F9CBA49FULL,
			0x5BFDB278C541B09DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCB24C7D1CDA92033ULL,
			0x895F36E54C75A688ULL,
			0x1784EE0C044B93EAULL,
			0x7D2F9C783EB7AEA1ULL}
		},
		.Z = {.key64 = {
			0x9A9B73E46BBC9E93ULL,
			0x642262EF0E72C089ULL,
			0x8E0DB208C709DE8DULL,
			0x4099D68C021BFE44ULL}
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

	steps = 14;
	X1 = (curve25519_key_t){.key64 = {
		0x56DAA3E1C4BA8D18ULL,
		0x512B22999A9E897BULL,
		0x850B0CB0458ACACBULL,
		0x7A3E5DF0DE61E3E6ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x56DAA3E1C4BA8D18ULL,
			0x512B22999A9E897BULL,
			0x850B0CB0458ACACBULL,
			0x7A3E5DF0DE61E3E6ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC04F52B870F5D2D9ULL,
			0x32E95EC1DF77B5C7ULL,
			0xFCC43359066640CEULL,
			0x123DB433E0DF3C51ULL}
		},
		.Z = {.key64 = {
			0xA0ACBD1B249C5214ULL,
			0x34285451A97C7505ULL,
			0x5C505480EA4F23A4ULL,
			0x20E0F640C4FA27D8ULL}
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

	steps = 25;
	X1 = (curve25519_key_t){.key64 = {
		0xE2F24CC3614843A8ULL,
		0x05F5A2BE21470892ULL,
		0x12FEB2AF65FAD106ULL,
		0x67C7BD6D1CA7DBEDULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE2F24CC3614843A8ULL,
			0x05F5A2BE21470892ULL,
			0x12FEB2AF65FAD106ULL,
			0x67C7BD6D1CA7DBEDULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3ED34E97F62B1B49ULL,
			0xFE1D07C663EABBB2ULL,
			0x265EC378D6C329B4ULL,
			0x0DC735F6755ADCDEULL}
		},
		.Z = {.key64 = {
			0xAD269B62FAD729AAULL,
			0x52CC75E8B514FAD0ULL,
			0xFFC71295652A20F3ULL,
			0x34BBA1644D28000DULL}
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

	steps = 47;
	X1 = (curve25519_key_t){.key64 = {
		0x25426EFBBA8CAA18ULL,
		0x20BF449249487B85ULL,
		0x4574A04CAC38D455ULL,
		0x58718350BCC40B67ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x25426EFBBA8CAA18ULL,
			0x20BF449249487B85ULL,
			0x4574A04CAC38D455ULL,
			0x58718350BCC40B67ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAC383E3342D34906ULL,
			0x42CCA506A880CA3FULL,
			0xACFC0DD1AE1EA18BULL,
			0x6372D73E5A42FA9AULL}
		},
		.Z = {.key64 = {
			0x3D8B4614FB3C1F7FULL,
			0xEA1A362C1E0E73E9ULL,
			0xA94A9F42D65F40E2ULL,
			0x579112A561C786CDULL}
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

	steps = 62;
	X1 = (curve25519_key_t){.key64 = {
		0x2F124AA26B344158ULL,
		0x81F9CA7EF134D650ULL,
		0xD0CCC6E48EB461FEULL,
		0x76C983A3D3F5EABAULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2F124AA26B344158ULL,
			0x81F9CA7EF134D650ULL,
			0xD0CCC6E48EB461FEULL,
			0x76C983A3D3F5EABAULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4C45B05AF5A1F45AULL,
			0xDBEAB3E17D8E98DFULL,
			0x26B3758E068F92A2ULL,
			0x392D4C9429756464ULL}
		},
		.Z = {.key64 = {
			0x6419B72492CC3070ULL,
			0x10427033206B7552ULL,
			0x2AD497CCE6C738BEULL,
			0x6CF5D05DC26DE067ULL}
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

	steps = 56;
	X1 = (curve25519_key_t){.key64 = {
		0xDDB333E85B796258ULL,
		0x80E1092A8F4504C6ULL,
		0x4AD55E78C6CFF5EAULL,
		0x7C4DC935214259A8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDDB333E85B796258ULL,
			0x80E1092A8F4504C6ULL,
			0x4AD55E78C6CFF5EAULL,
			0x7C4DC935214259A8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDB887A4678921B49ULL,
			0xBCB0C1B237BCA809ULL,
			0x8A12067D21D56E35ULL,
			0x4D68A5E837A750D7ULL}
		},
		.Z = {.key64 = {
			0x8593C677C8627898ULL,
			0x4EEDA8D1324AA6C7ULL,
			0xCEA66D3778A9C64DULL,
			0x5A4A23043261226FULL}
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

	steps = 31;
	X1 = (curve25519_key_t){.key64 = {
		0x3012BEC09FC46BB8ULL,
		0x2BC264840CB7BCAFULL,
		0x436D7FD3721D5F58ULL,
		0x640626F5518CD0DDULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3012BEC09FC46BB8ULL,
			0x2BC264840CB7BCAFULL,
			0x436D7FD3721D5F58ULL,
			0x640626F5518CD0DDULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7B34D04C57646BC6ULL,
			0x6FA89ACBB67BB5D9ULL,
			0x827E014DC0C1B859ULL,
			0x19954F8CB2367D9BULL}
		},
		.Z = {.key64 = {
			0x0C8C04AC78C433F6ULL,
			0xB511D52776EFC68EULL,
			0xE24C0B3E52966429ULL,
			0x7ECEC0E1E0C234DAULL}
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

	steps = 29;
	X1 = (curve25519_key_t){.key64 = {
		0x16A196E215ECB898ULL,
		0xE002C1F187667C59ULL,
		0x2DCD3D94A738B5C9ULL,
		0x4793FBEC26E04397ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x16A196E215ECB898ULL,
			0xE002C1F187667C59ULL,
			0x2DCD3D94A738B5C9ULL,
			0x4793FBEC26E04397ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBCF7FEF7320DE5FCULL,
			0x93B3AD2B77E9EB02ULL,
			0xCE12322D6EE513DDULL,
			0x6777F5A2F87EC68EULL}
		},
		.Z = {.key64 = {
			0xAAFD54FDA5F3F9EBULL,
			0x7737D148BDAF1E0FULL,
			0x44445B2AE649B6D2ULL,
			0x72F813BDBD5AD84CULL}
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

	steps = 22;
	X1 = (curve25519_key_t){.key64 = {
		0x81B9DAD976A896F8ULL,
		0x10FF97B0616DB1CCULL,
		0x1FA007C23A3D245AULL,
		0x6976C70CD046807DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x81B9DAD976A896F8ULL,
			0x10FF97B0616DB1CCULL,
			0x1FA007C23A3D245AULL,
			0x6976C70CD046807DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE83D96BA1D86A031ULL,
			0xBE054F8585D6D46BULL,
			0xC7B444ECF09130ABULL,
			0x337E57C93EDA9EA0ULL}
		},
		.Z = {.key64 = {
			0x095FE0D9C42F26C4ULL,
			0xE4EF0A0D2CFE128CULL,
			0xF44D52B24EF03A06ULL,
			0x186567AAB52B97D3ULL}
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

	steps = 8;
	X1 = (curve25519_key_t){.key64 = {
		0x2A225511EB0B8100ULL,
		0xF5E0818D936CF5DBULL,
		0xD2DBBE82BC04FA19ULL,
		0x416DAF362A2A7FE5ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2A225511EB0B8100ULL,
			0xF5E0818D936CF5DBULL,
			0xD2DBBE82BC04FA19ULL,
			0x416DAF362A2A7FE5ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6075D41F6643214EULL,
			0xEF3E5ABCAB9BB3DAULL,
			0x6AD98977115C5982ULL,
			0x074494B8A6841977ULL}
		},
		.Z = {.key64 = {
			0xAE147021FCF357A1ULL,
			0x97A5AF6A4BAEA1D2ULL,
			0x802DAE1F8380696BULL,
			0x3112256DC1C804D5ULL}
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

	steps = 47;
	X1 = (curve25519_key_t){.key64 = {
		0x941DB967E3C367C0ULL,
		0x4045FBCB4B48F6EAULL,
		0x08316ABCDDB61388ULL,
		0x5309487B883149C8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x941DB967E3C367C0ULL,
			0x4045FBCB4B48F6EAULL,
			0x08316ABCDDB61388ULL,
			0x5309487B883149C8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x13DD1577A455388DULL,
			0x72FABCDE6977DACDULL,
			0x78360643E06DF9A9ULL,
			0x3077D61574E4637DULL}
		},
		.Z = {.key64 = {
			0xBD2C64F359AAB120ULL,
			0x9EC6E5483C13A0EDULL,
			0x66887E5F34A62D6EULL,
			0x18D5CFFDAA51B245ULL}
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

	steps = 25;
	X1 = (curve25519_key_t){.key64 = {
		0x73C1987D2D900230ULL,
		0xFCCF3115F2E7E4D5ULL,
		0xAC8E82F4FA79A5CDULL,
		0x6E187D08DF41C669ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x73C1987D2D900230ULL,
			0xFCCF3115F2E7E4D5ULL,
			0xAC8E82F4FA79A5CDULL,
			0x6E187D08DF41C669ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x89B691432D6A6E7EULL,
			0xB33B9A74651A6DA5ULL,
			0x8E9928A245573BF7ULL,
			0x2DBCF46A8B0EA9CCULL}
		},
		.Z = {.key64 = {
			0x6BEFA2D8B6E79041ULL,
			0x40FF0FEC7E9D9B72ULL,
			0x956761A2605D0676ULL,
			0x357B43E169BA2B9BULL}
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

	steps = 8;
	X1 = (curve25519_key_t){.key64 = {
		0xE48AF2210CAE4670ULL,
		0x17F65170482C68B1ULL,
		0x5E6A43767BE5B128ULL,
		0x43A4AF89FF26CD46ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE48AF2210CAE4670ULL,
			0x17F65170482C68B1ULL,
			0x5E6A43767BE5B128ULL,
			0x43A4AF89FF26CD46ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC76F0FDBF8EDEE23ULL,
			0x0CD11FF2A1D3C38FULL,
			0xF4972019AF3D74B2ULL,
			0x743944249ED2B34EULL}
		},
		.Z = {.key64 = {
			0xE21492EFEA1C0F8CULL,
			0xBF6DB4B38DA09BB5ULL,
			0x764C7E75D13B2759ULL,
			0x47445BF62813E508ULL}
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

	steps = 63;
	X1 = (curve25519_key_t){.key64 = {
		0x486466D7D6D54C58ULL,
		0xB97981CB925D0873ULL,
		0x4D1F5FBA572776FCULL,
		0x73CBA57725EF43C6ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x486466D7D6D54C58ULL,
			0xB97981CB925D0873ULL,
			0x4D1F5FBA572776FCULL,
			0x73CBA57725EF43C6ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x449D60613FF8EFC7ULL,
			0x5877EA27C6A69F3CULL,
			0xA4E5DBCCCC8AC6B4ULL,
			0x4724B8A3FB16C385ULL}
		},
		.Z = {.key64 = {
			0xBC1E1E95B22EB5DEULL,
			0x4B96256F230249F6ULL,
			0x833B1B700F1C1DB1ULL,
			0x18D6C8D1088E4708ULL}
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

	steps = 25;
	X1 = (curve25519_key_t){.key64 = {
		0xD39B48A3E23A3F78ULL,
		0x22355627270336BCULL,
		0xD5A37C69604F6EA7ULL,
		0x6CBE2BB17164E065ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD39B48A3E23A3F78ULL,
			0x22355627270336BCULL,
			0xD5A37C69604F6EA7ULL,
			0x6CBE2BB17164E065ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6DA1A411FD08D575ULL,
			0x7EE77B8E1D81FF80ULL,
			0x898C67959FB5BB51ULL,
			0x45B75DDC2CE0B581ULL}
		},
		.Z = {.key64 = {
			0x449B2CD1242E74AFULL,
			0x37295B529533BB4AULL,
			0x4328C5711202575DULL,
			0x16CF2A3B375AF798ULL}
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

	steps = 30;
	X1 = (curve25519_key_t){.key64 = {
		0x33FD78B15DEEC400ULL,
		0x99D586E9F5EBFA59ULL,
		0x8C85324D988F5760ULL,
		0x4F79CFF70A6B2D09ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x33FD78B15DEEC400ULL,
			0x99D586E9F5EBFA59ULL,
			0x8C85324D988F5760ULL,
			0x4F79CFF70A6B2D09ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9E95E52FE710C772ULL,
			0x76533ABA1F3A3A9AULL,
			0x315E9EA1F14CFCBCULL,
			0x1FA7BC903F283F33ULL}
		},
		.Z = {.key64 = {
			0x5A6E8ECC5CFDD3DCULL,
			0xE01764AEB60AAA0AULL,
			0x37FD6CB30E089154ULL,
			0x227790FCD6A5B006ULL}
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

	steps = 15;
	X1 = (curve25519_key_t){.key64 = {
		0xBF7E7F1A13860D48ULL,
		0x968702A3E487AE2FULL,
		0xCC0D631A5D0C2904ULL,
		0x4145F0D7E7697C39ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBF7E7F1A13860D48ULL,
			0x968702A3E487AE2FULL,
			0xCC0D631A5D0C2904ULL,
			0x4145F0D7E7697C39ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0B2D4996B58F249CULL,
			0xF1F46F757BA9B443ULL,
			0xF4AA695AED94D167ULL,
			0x31D9ED3F63F0965BULL}
		},
		.Z = {.key64 = {
			0x0F71E32B9ECF39EEULL,
			0x06D65EB9CD460A98ULL,
			0x1718291AEBA93AE1ULL,
			0x104EA123C5A5112FULL}
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

	steps = 12;
	X1 = (curve25519_key_t){.key64 = {
		0x5A06A1FBE99CFC38ULL,
		0xBDE957F305571CACULL,
		0xF2DFC7EC04BB0B07ULL,
		0x6C1C869A1BF9AC2FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5A06A1FBE99CFC38ULL,
			0xBDE957F305571CACULL,
			0xF2DFC7EC04BB0B07ULL,
			0x6C1C869A1BF9AC2FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x95D8FEC435351206ULL,
			0xE233578EADF47BCDULL,
			0xB4EBCF98846448D5ULL,
			0x5CCAB312BD51B56EULL}
		},
		.Z = {.key64 = {
			0x078E7E7C90BA87C8ULL,
			0xF6BBF6F6A704118BULL,
			0x96BF3BB05E3CE152ULL,
			0x66CE8FD372B32B61ULL}
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

	steps = 40;
	X1 = (curve25519_key_t){.key64 = {
		0xB9A3D6446A9E8ED0ULL,
		0x10E22BD43BBCE86FULL,
		0xDFD74D6D02E45D88ULL,
		0x4B3552244179B90AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB9A3D6446A9E8ED0ULL,
			0x10E22BD43BBCE86FULL,
			0xDFD74D6D02E45D88ULL,
			0x4B3552244179B90AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1C2C0870A004B236ULL,
			0xC1CEFFD335CAD2C0ULL,
			0x2C8C6C9A9FDE6699ULL,
			0x0D2C51FFDD8A0919ULL}
		},
		.Z = {.key64 = {
			0x2C21113E964D93A8ULL,
			0xAFD57BA554514F4AULL,
			0x79AD81A5027B82E8ULL,
			0x6DFDADE48F549941ULL}
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

	steps = 30;
	X1 = (curve25519_key_t){.key64 = {
		0x53E2A51049B37C88ULL,
		0xFFB5C489621B0ABAULL,
		0xD180FD218EB66BB6ULL,
		0x40FC65C7161E1ED8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x53E2A51049B37C88ULL,
			0xFFB5C489621B0ABAULL,
			0xD180FD218EB66BB6ULL,
			0x40FC65C7161E1ED8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF9220142C81683DCULL,
			0x7AF2DE2CA420EC94ULL,
			0x8355DBEEA18F856FULL,
			0x1CD55513718335CEULL}
		},
		.Z = {.key64 = {
			0xAB57AB8126267FDCULL,
			0xC34F5106BA4EEBA6ULL,
			0xEC9AD0381792B46AULL,
			0x01F26E5A90F7558BULL}
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

	steps = 60;
	X1 = (curve25519_key_t){.key64 = {
		0x8F54F8127FBA85B0ULL,
		0xE37182A949F81DBBULL,
		0xE492D41A632B159FULL,
		0x6131F12D7178CC05ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8F54F8127FBA85B0ULL,
			0xE37182A949F81DBBULL,
			0xE492D41A632B159FULL,
			0x6131F12D7178CC05ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE59701BCC893B7B1ULL,
			0xA8A5BDCD85A97B36ULL,
			0x0154CF3017ED70B4ULL,
			0x3C2C524A48E5C13EULL}
		},
		.Z = {.key64 = {
			0x4DA4E30735AAAE6FULL,
			0x505D31912C3EDD01ULL,
			0x5CA4A4FC3D1AC536ULL,
			0x0B4573EBF421CB2DULL}
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

	steps = 32;
	X1 = (curve25519_key_t){.key64 = {
		0x35C2F42B13A86980ULL,
		0x9D96A059AE02658BULL,
		0x575F16485DC8F645ULL,
		0x5A017B265F1DE328ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x35C2F42B13A86980ULL,
			0x9D96A059AE02658BULL,
			0x575F16485DC8F645ULL,
			0x5A017B265F1DE328ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x971014C88DE84588ULL,
			0x32F1B547B85C64CAULL,
			0x4F24474DBF49864FULL,
			0x57871445DB6676A6ULL}
		},
		.Z = {.key64 = {
			0x0BD321EC07919901ULL,
			0xCD1A8A93ADC59B23ULL,
			0xC941F31DE93A093EULL,
			0x7FD9BCE0FE8F1F4FULL}
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

	steps = 41;
	X1 = (curve25519_key_t){.key64 = {
		0x090387A77F4B0970ULL,
		0xA89625CB360227FDULL,
		0xD54193D5A0F50502ULL,
		0x60E0B0D9CF83FC64ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x090387A77F4B0970ULL,
			0xA89625CB360227FDULL,
			0xD54193D5A0F50502ULL,
			0x60E0B0D9CF83FC64ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAF5EE3790EAC3F6AULL,
			0x96B3625F57DD5601ULL,
			0x7A11AD50404A6441ULL,
			0x4E4D04C14971C694ULL}
		},
		.Z = {.key64 = {
			0xF532947CD32726FDULL,
			0x4C1BD7961BF8DC1AULL,
			0xD48E9137FC0C48BEULL,
			0x5D87FD1DF874F612ULL}
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

	steps = 10;
	X1 = (curve25519_key_t){.key64 = {
		0x9CDF514ADD61E1C0ULL,
		0x02B078E64150AF52ULL,
		0x81531E0719813501ULL,
		0x58A50D35BF393436ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9CDF514ADD61E1C0ULL,
			0x02B078E64150AF52ULL,
			0x81531E0719813501ULL,
			0x58A50D35BF393436ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7FCC8B0840A45EA1ULL,
			0x44A166841EBA1217ULL,
			0x1D89855D271943B1ULL,
			0x205EAE2E19A02A3EULL}
		},
		.Z = {.key64 = {
			0x3C987F595EA0E509ULL,
			0x12481C1BBD7E6120ULL,
			0x9734F5371421B46BULL,
			0x74107FE6B24E6111ULL}
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