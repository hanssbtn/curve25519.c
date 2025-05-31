#include "../tests.h"

int32_t curve25519_ladder_step_test(void) {
	printf("Montgomery Ladder Step Test\n");
	int steps = 54;
	curve25519_key_t X1 = {.key64 = {
		0x994419784A9E1B50ULL,
		0xA0C1730D14E97B43ULL,
		0x9A1012D305B3BC3DULL,
		0x598D766A565381D8ULL
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
			0x994419784A9E1B50ULL,
			0xA0C1730D14E97B43ULL,
			0x9A1012D305B3BC3DULL,
			0x598D766A565381D8ULL}
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
			0x86B6CE2F3CE88C19ULL,
			0xEB885D8BED92DBACULL,
			0xAC593D0C4E66F11FULL,
			0x78C2BDBDBA829BF5ULL}
		},
		.Z = {.key64 = {
			0xBF62BD96CF52DB57ULL,
			0xA4E9DB7E94760AA0ULL,
			0x38776DA0ECD47F8FULL,
			0x061DEE6F625D8F6FULL}
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

	steps = 57;
	X1 = (curve25519_key_t){.key64 = {
		0x050DE6981FE06770ULL,
		0xFC27B757E87BCD2EULL,
		0x83BAEA4E8AD9269EULL,
		0x61D852091C4395FBULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x050DE6981FE06770ULL,
			0xFC27B757E87BCD2EULL,
			0x83BAEA4E8AD9269EULL,
			0x61D852091C4395FBULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0915101789C22B48ULL,
			0x163E3F6109F6AC4BULL,
			0x6D4BB00DF802370BULL,
			0x47065C65FD5630BEULL}
		},
		.Z = {.key64 = {
			0xC5B7F77606639EBEULL,
			0x370BE3611DCC7C90ULL,
			0xB40614D6F326CA97ULL,
			0x708ACD82BE785089ULL}
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

	steps = 44;
	X1 = (curve25519_key_t){.key64 = {
		0x0C4942412D6AA0F8ULL,
		0xBBDC04A630120A91ULL,
		0x75A2454B321548A3ULL,
		0x6532BC4639604F76ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0C4942412D6AA0F8ULL,
			0xBBDC04A630120A91ULL,
			0x75A2454B321548A3ULL,
			0x6532BC4639604F76ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF5F84F396E3FCE28ULL,
			0x0FD3FB38AA71A7A2ULL,
			0xA2FE77CE4C07B4F0ULL,
			0x56C34D820857279AULL}
		},
		.Z = {.key64 = {
			0x2B415427E2B759CBULL,
			0xA2AEAFD4A532C89EULL,
			0xD270C46C9F02B049ULL,
			0x630E5417F4DC3BE0ULL}
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

	steps = 59;
	X1 = (curve25519_key_t){.key64 = {
		0x64A420E14BF01D28ULL,
		0x5EEF33696EE0A4BEULL,
		0xD5DE5F3462023F86ULL,
		0x4BB0C7E20A45EE1FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x64A420E14BF01D28ULL,
			0x5EEF33696EE0A4BEULL,
			0xD5DE5F3462023F86ULL,
			0x4BB0C7E20A45EE1FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF0A31DF3B256F7C7ULL,
			0xA180B2BCC1531D15ULL,
			0xDE2229B655AB6CE6ULL,
			0x37E38B121A847C70ULL}
		},
		.Z = {.key64 = {
			0x031A8873A6502441ULL,
			0xFE78BD9CAA19A845ULL,
			0x59552DA37386F486ULL,
			0x40FF5D2DBACE0F96ULL}
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

	steps = 54;
	X1 = (curve25519_key_t){.key64 = {
		0x02D43E6ED149F168ULL,
		0x19A6502E32988E36ULL,
		0x0D62D9D65E9F308AULL,
		0x798872DFE6933FBCULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x02D43E6ED149F168ULL,
			0x19A6502E32988E36ULL,
			0x0D62D9D65E9F308AULL,
			0x798872DFE6933FBCULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBF3127BAD610DEE3ULL,
			0x56B76AADADF96A53ULL,
			0xC171ED11EC278AD6ULL,
			0x47B39B16855AC19DULL}
		},
		.Z = {.key64 = {
			0x343A8851F0360516ULL,
			0x415B9B5AE579BD21ULL,
			0xAB9F1854FF220FCCULL,
			0x64DD470DD7570DA5ULL}
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

	steps = 56;
	X1 = (curve25519_key_t){.key64 = {
		0x4BE6AC784928D458ULL,
		0x02D2A490C1CDFA66ULL,
		0x549E96B7BE9B8599ULL,
		0x7F82DD707062C521ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4BE6AC784928D458ULL,
			0x02D2A490C1CDFA66ULL,
			0x549E96B7BE9B8599ULL,
			0x7F82DD707062C521ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC4165E93731EB8DEULL,
			0x61D53815042DD78DULL,
			0xFFC7509114B46C0CULL,
			0x285F790297D378B2ULL}
		},
		.Z = {.key64 = {
			0x2E854639717F6F5AULL,
			0x98D1C24134E52975ULL,
			0xBDA0E00F5DD420E1ULL,
			0x2F361610AC350BA2ULL}
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
		0x647C3609D4A03350ULL,
		0x693F65CD68546298ULL,
		0xB7350A2943DC6164ULL,
		0x4F306FF765B1B4ADULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x647C3609D4A03350ULL,
			0x693F65CD68546298ULL,
			0xB7350A2943DC6164ULL,
			0x4F306FF765B1B4ADULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x34FE3F973710BF77ULL,
			0xD6EDE03884BE042FULL,
			0xF9222ACACB24700EULL,
			0x63FE2A3B8DEDEDB1ULL}
		},
		.Z = {.key64 = {
			0xC79066DFD71E625DULL,
			0x33F093744991D84FULL,
			0x989DBC604BE10307ULL,
			0x185F348C421767B5ULL}
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

	steps = 38;
	X1 = (curve25519_key_t){.key64 = {
		0x1F65224E083FA520ULL,
		0xD21738BA46208B30ULL,
		0xC7306245792226B5ULL,
		0x49871127B034694BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1F65224E083FA520ULL,
			0xD21738BA46208B30ULL,
			0xC7306245792226B5ULL,
			0x49871127B034694BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x75F58BAED952A585ULL,
			0x1DDE7E66C85E6F6BULL,
			0xF3AD282CFD4F64E8ULL,
			0x3D4549C0B5AF909CULL}
		},
		.Z = {.key64 = {
			0x40B94AE3570D82FAULL,
			0x65885097753B7745ULL,
			0x3034EA980D680BA4ULL,
			0x540BA492E5403412ULL}
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

	steps = 19;
	X1 = (curve25519_key_t){.key64 = {
		0x7BE62434448EBC98ULL,
		0x22D5C229A40A78FBULL,
		0x99DE4A3B68BDFF6FULL,
		0x5E30479FC0BC159CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7BE62434448EBC98ULL,
			0x22D5C229A40A78FBULL,
			0x99DE4A3B68BDFF6FULL,
			0x5E30479FC0BC159CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9860688053B679D6ULL,
			0x3AF770C0B4BAC213ULL,
			0xBC6D1D79AAA0390AULL,
			0x3228BBCC08CD6921ULL}
		},
		.Z = {.key64 = {
			0xE9684745319461D6ULL,
			0xB9363268B3C70F4DULL,
			0x460F8D4749CE5FFCULL,
			0x10E3B720AA30D8D6ULL}
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

	steps = 37;
	X1 = (curve25519_key_t){.key64 = {
		0x4E1FEB41199B1180ULL,
		0xB839AC7F7C23C0B5ULL,
		0x7E3F6A1917417410ULL,
		0x54C07373D79F99A0ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4E1FEB41199B1180ULL,
			0xB839AC7F7C23C0B5ULL,
			0x7E3F6A1917417410ULL,
			0x54C07373D79F99A0ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x96D49A41D48D7B33ULL,
			0x2CEB6271E5CC939EULL,
			0xE3CF0890AEBE86DBULL,
			0x564F640B2BCE72EDULL}
		},
		.Z = {.key64 = {
			0x2C18C64C0EC19981ULL,
			0x76A574E33D2D1881ULL,
			0x9FFD206E20F9A97EULL,
			0x7FEF27200A62D534ULL}
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

	steps = 4;
	X1 = (curve25519_key_t){.key64 = {
		0x705BC4C5042FACA8ULL,
		0xA9BE83BF73076CBDULL,
		0x5A3CE8A6F2B1EEFAULL,
		0x6D41CECB94CCAC96ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x705BC4C5042FACA8ULL,
			0xA9BE83BF73076CBDULL,
			0x5A3CE8A6F2B1EEFAULL,
			0x6D41CECB94CCAC96ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x612F744EACEC0793ULL,
			0x431A4453D00A1650ULL,
			0xA33A3A982C694230ULL,
			0x1780C2FA24F4A2F2ULL}
		},
		.Z = {.key64 = {
			0x6F65A5E67AE9CBDEULL,
			0x9BE5F2DA4BE571A8ULL,
			0xF9D9AF9C53D6A81AULL,
			0x39E544A9DDC6EB11ULL}
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

	steps = 58;
	X1 = (curve25519_key_t){.key64 = {
		0xCDB71FE36A963088ULL,
		0xE40462CFB1D8EDF4ULL,
		0x99569AADD4D1A6DAULL,
		0x6B11A6CE01D4A51CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCDB71FE36A963088ULL,
			0xE40462CFB1D8EDF4ULL,
			0x99569AADD4D1A6DAULL,
			0x6B11A6CE01D4A51CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFB9DA65E183C862AULL,
			0x734D28DFEAEF696FULL,
			0xAEA425663235EBCFULL,
			0x2AC72DCA79DF8838ULL}
		},
		.Z = {.key64 = {
			0x616FA915480A635BULL,
			0xF5AA509591167F2FULL,
			0x5D0B91749D577738ULL,
			0x4BCACFDF9A060E28ULL}
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

	steps = 2;
	X1 = (curve25519_key_t){.key64 = {
		0x4D704D6667C2B658ULL,
		0x22F463E90B5607BBULL,
		0xC6ACD9F7A1B43E60ULL,
		0x4E90945982B12EDEULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4D704D6667C2B658ULL,
			0x22F463E90B5607BBULL,
			0xC6ACD9F7A1B43E60ULL,
			0x4E90945982B12EDEULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA9B9A6DA2F9F0761ULL,
			0x492B99B5208DFF20ULL,
			0x1388FD650E63CDA9ULL,
			0x0EADD30A06755F7AULL}
		},
		.Z = {.key64 = {
			0x92976F71C13D9DDBULL,
			0xEAAB57CBE0638285ULL,
			0x6F62989C002F3C05ULL,
			0x5565E1613BBBAE2FULL}
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

	steps = 1;
	X1 = (curve25519_key_t){.key64 = {
		0x04C059F0D9BA4798ULL,
		0x0BA75374ED712B96ULL,
		0xBE96B7DEE137974CULL,
		0x4054855856DCDF09ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x04C059F0D9BA4798ULL,
			0x0BA75374ED712B96ULL,
			0xBE96B7DEE137974CULL,
			0x4054855856DCDF09ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB2D37C444E9B8EB4ULL,
			0xED2A2CDE31CDEBC7ULL,
			0xC0E6F65917A4A381ULL,
			0x4177B0D0BC0A8910ULL}
		},
		.Z = {.key64 = {
			0x130167C366E91E86ULL,
			0x2E9D4DD3B5C4AE58ULL,
			0xFA5ADF7B84DE5D30ULL,
			0x015215615B737C26ULL}
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
		0xAA239099542D1B18ULL,
		0x35A770D1DBD286B3ULL,
		0x926EF6801EE26AB6ULL,
		0x610AD7EB29A2E3B6ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAA239099542D1B18ULL,
			0x35A770D1DBD286B3ULL,
			0x926EF6801EE26AB6ULL,
			0x610AD7EB29A2E3B6ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x92FCE08F03049C36ULL,
			0xD4DF7612EF728182ULL,
			0x2C8598F76DDD62B7ULL,
			0x4A71C3F48A665239ULL}
		},
		.Z = {.key64 = {
			0xC709A35B06AB1C8FULL,
			0x2D90F7F3516F2933ULL,
			0x30F0A7A87F11C9A8ULL,
			0x5802001370D7D8F6ULL}
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

	steps = 26;
	X1 = (curve25519_key_t){.key64 = {
		0x0BFCA4003DC05020ULL,
		0xB7CE32A5C69329E3ULL,
		0x6868BC21D65A34B4ULL,
		0x449D2FBE69CB3503ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0BFCA4003DC05020ULL,
			0xB7CE32A5C69329E3ULL,
			0x6868BC21D65A34B4ULL,
			0x449D2FBE69CB3503ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBF51FB16C903B100ULL,
			0xADBE35FB6CE014CCULL,
			0x47F1387DAB6971BCULL,
			0x08E88503B378B513ULL}
		},
		.Z = {.key64 = {
			0xFB7BACB8118B6164ULL,
			0x86DE47AE8B2A9329ULL,
			0x3491346D85A18783ULL,
			0x5929B48B4EC3D101ULL}
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

	steps = 51;
	X1 = (curve25519_key_t){.key64 = {
		0x285A2B647DE6A850ULL,
		0xB8BDE72D9C1D099BULL,
		0x3669E37AD0A76EB7ULL,
		0x76E7F2A9C60C9A41ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x285A2B647DE6A850ULL,
			0xB8BDE72D9C1D099BULL,
			0x3669E37AD0A76EB7ULL,
			0x76E7F2A9C60C9A41ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC989A2C55D030009ULL,
			0x8FF19F64410A0DBEULL,
			0xA9EEB12C52EE0DCFULL,
			0x7DC3065FBD74B48AULL}
		},
		.Z = {.key64 = {
			0x075FBA5832986B80ULL,
			0xBDD1034696B28C69ULL,
			0x92E55938880888AAULL,
			0x07D20DFF39D4C2E3ULL}
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

	steps = 48;
	X1 = (curve25519_key_t){.key64 = {
		0x2A69F60838EEBED8ULL,
		0xCCF2B65FECDF374EULL,
		0xFD697D1CC5C6667EULL,
		0x6A9909879B3CD994ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2A69F60838EEBED8ULL,
			0xCCF2B65FECDF374EULL,
			0xFD697D1CC5C6667EULL,
			0x6A9909879B3CD994ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3C4762BE85CDAE55ULL,
			0x7C83647E9315E3A2ULL,
			0xD52BEF4B79637668ULL,
			0x741386AB6D67027BULL}
		},
		.Z = {.key64 = {
			0x17C674BA69F1EE2DULL,
			0x3BB65357ABC570E3ULL,
			0x9983263B6C64B018ULL,
			0x77C7A543658861F0ULL}
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

	steps = 62;
	X1 = (curve25519_key_t){.key64 = {
		0x42F6D0BF5D6C7218ULL,
		0x6880CCBDAE11622BULL,
		0x5BA272199AEE9E80ULL,
		0x6DD3B37A286FB177ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x42F6D0BF5D6C7218ULL,
			0x6880CCBDAE11622BULL,
			0x5BA272199AEE9E80ULL,
			0x6DD3B37A286FB177ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAB1FA7DBC2CB1DB5ULL,
			0x4CA8E860D74316E5ULL,
			0x96929322F1144B0AULL,
			0x02D08BF7BA70ADD9ULL}
		},
		.Z = {.key64 = {
			0x9AE9E2002B1037C0ULL,
			0x00329920A215A49FULL,
			0x52162856D21BA700ULL,
			0x5952AC65965855A7ULL}
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

	steps = 5;
	X1 = (curve25519_key_t){.key64 = {
		0x496073268E314128ULL,
		0x0C8D6ED87789CBF5ULL,
		0xCFE88FFE77976C67ULL,
		0x46192B69BFD5AE25ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x496073268E314128ULL,
			0x0C8D6ED87789CBF5ULL,
			0xCFE88FFE77976C67ULL,
			0x46192B69BFD5AE25ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE2B3964789415129ULL,
			0x7A165AAD45341DCDULL,
			0x4DE942BC12531AC9ULL,
			0x15572E30A934A4A2ULL}
		},
		.Z = {.key64 = {
			0x5A6EEE9AA49E1FD1ULL,
			0xBF72C34DE58EC192ULL,
			0x42B9CE8450AFB4E7ULL,
			0x41554CDB62737606ULL}
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

	steps = 37;
	X1 = (curve25519_key_t){.key64 = {
		0x2E96C0ADD5FC3900ULL,
		0x3BDD646DCA1AFFFFULL,
		0xDE42C2908F368AD1ULL,
		0x60B68282AA8BB4A9ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2E96C0ADD5FC3900ULL,
			0x3BDD646DCA1AFFFFULL,
			0xDE42C2908F368AD1ULL,
			0x60B68282AA8BB4A9ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCA2D7BB13486C3E5ULL,
			0xC70F7408988E70C4ULL,
			0x7981273A73748040ULL,
			0x6571A482400999DDULL}
		},
		.Z = {.key64 = {
			0x0F6CDDD111BB2333ULL,
			0xE8DC72F98924DA72ULL,
			0x59D39C4859EED422ULL,
			0x0733395974063EA3ULL}
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

	steps = 26;
	X1 = (curve25519_key_t){.key64 = {
		0xB80E123DA4783E88ULL,
		0x0BF9AF8B3C2C4A61ULL,
		0xEA606963BDC67070ULL,
		0x754D259F7E64562AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB80E123DA4783E88ULL,
			0x0BF9AF8B3C2C4A61ULL,
			0xEA606963BDC67070ULL,
			0x754D259F7E64562AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBD460B12BDEA059BULL,
			0xE9254C9BA1635452ULL,
			0x0586092B346AA21EULL,
			0x668E1318A2BFAB5CULL}
		},
		.Z = {.key64 = {
			0x6FBB7D14AA01B457ULL,
			0x969BC9EDFEA7B75EULL,
			0x3BF673567E72F2FBULL,
			0x7ED3DE4F80D6772EULL}
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

	steps = 19;
	X1 = (curve25519_key_t){.key64 = {
		0x68A591ABFEAB17B8ULL,
		0x7CA34DF6917817F1ULL,
		0x4869B37C9700B310ULL,
		0x51F71521BE959DD8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x68A591ABFEAB17B8ULL,
			0x7CA34DF6917817F1ULL,
			0x4869B37C9700B310ULL,
			0x51F71521BE959DD8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE63243EEBB4F681DULL,
			0xE4C46D4690E82CC7ULL,
			0x7FF1EE48CE0AB318ULL,
			0x266DC608B3329B04ULL}
		},
		.Z = {.key64 = {
			0x4629C2553BE0F3B4ULL,
			0xC5835F9A58DF1E16ULL,
			0x7F6616870A55CD61ULL,
			0x0A7AF95D036B1F2FULL}
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

	steps = 15;
	X1 = (curve25519_key_t){.key64 = {
		0xE79FA4159ECE1B80ULL,
		0xDE9595E56F19E815ULL,
		0xA5ADB8307DD97015ULL,
		0x490F496547F82987ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE79FA4159ECE1B80ULL,
			0xDE9595E56F19E815ULL,
			0xA5ADB8307DD97015ULL,
			0x490F496547F82987ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9FD7BB53DF8C3477ULL,
			0xC147F9B359ABD1F0ULL,
			0x30DA8D7C4FB0D47EULL,
			0x5970BEB2169F9F79ULL}
		},
		.Z = {.key64 = {
			0xB6C041E553DE54E8ULL,
			0x110832AE51DD2A43ULL,
			0xC32BC9FEA73CBD05ULL,
			0x352D672BB27C9023ULL}
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

	steps = 21;
	X1 = (curve25519_key_t){.key64 = {
		0x9071FAF5EE5F5880ULL,
		0x726579AF33DC0E8BULL,
		0xE411B1804B24A0A0ULL,
		0x5C35CAE89818F6E7ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9071FAF5EE5F5880ULL,
			0x726579AF33DC0E8BULL,
			0xE411B1804B24A0A0ULL,
			0x5C35CAE89818F6E7ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x49637C87E5F2AD8DULL,
			0xEE1C6822CE052B6CULL,
			0xCE6A2923349330D5ULL,
			0x5214E6C56094C443ULL}
		},
		.Z = {.key64 = {
			0x42F8A9E852F23A35ULL,
			0x6EDA60AEC16DF789ULL,
			0x30489D6619B5311DULL,
			0x759B62E49A58FDF2ULL}
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

	steps = 10;
	X1 = (curve25519_key_t){.key64 = {
		0xB6AB253A733AD5B0ULL,
		0x44E83E45E8853BD2ULL,
		0x1B28B03D740AB247ULL,
		0x4BBFA4098E485DDAULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB6AB253A733AD5B0ULL,
			0x44E83E45E8853BD2ULL,
			0x1B28B03D740AB247ULL,
			0x4BBFA4098E485DDAULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBA1D4B538F5F9A98ULL,
			0x27F3375C52B5F7B2ULL,
			0x1904D170885F5F32ULL,
			0x4291A149BDD88811ULL}
		},
		.Z = {.key64 = {
			0x3048321F756A559EULL,
			0x8B01EB557A216784ULL,
			0x34CF4C1932BD8151ULL,
			0x41494C7EA1E734D1ULL}
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

	steps = 53;
	X1 = (curve25519_key_t){.key64 = {
		0xA036EE754CDD1448ULL,
		0x2A8B270B106D0E08ULL,
		0x7DA7D08BBB668B98ULL,
		0x78F492E637AF2E7DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA036EE754CDD1448ULL,
			0x2A8B270B106D0E08ULL,
			0x7DA7D08BBB668B98ULL,
			0x78F492E637AF2E7DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7111D5D99F5D1996ULL,
			0xB3251BCA87BB6DD6ULL,
			0xF39ECABEB0661A94ULL,
			0x5D1B764582EDAF59ULL}
		},
		.Z = {.key64 = {
			0x2D0E6712D9D7180EULL,
			0xF830A81E163CFE0BULL,
			0x47D480FD775B7021ULL,
			0x43F1A269724400D9ULL}
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

	steps = 23;
	X1 = (curve25519_key_t){.key64 = {
		0x07DA5C498949F820ULL,
		0xEBA6D1E785783584ULL,
		0xF66D174D5DE6DD12ULL,
		0x43847683685483D1ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x07DA5C498949F820ULL,
			0xEBA6D1E785783584ULL,
			0xF66D174D5DE6DD12ULL,
			0x43847683685483D1ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDE9A5E7751221001ULL,
			0xD97C19A04FD9CFADULL,
			0x82B42E083A8F114EULL,
			0x3261578A63F94708ULL}
		},
		.Z = {.key64 = {
			0xF1C419B50345AE69ULL,
			0xD250578C87508AA2ULL,
			0xC23CC62B98CD5BECULL,
			0x7A402E9E1CC5FB0AULL}
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

	steps = 4;
	X1 = (curve25519_key_t){.key64 = {
		0x87710C0E32C2DEE0ULL,
		0x5CDB5E99B07579BEULL,
		0xB58B293186FBF6A8ULL,
		0x7A2F7FEF4500FAEBULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x87710C0E32C2DEE0ULL,
			0x5CDB5E99B07579BEULL,
			0xB58B293186FBF6A8ULL,
			0x7A2F7FEF4500FAEBULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4FEB899368766CD7ULL,
			0x4F7EE78E009E731AULL,
			0x126986340F080030ULL,
			0x3FF3876622B77F4DULL}
		},
		.Z = {.key64 = {
			0x1875240C1AE3D3A8ULL,
			0xB3BFF773205B0A0FULL,
			0xBBA3F63CFE59D1D8ULL,
			0x5CE2F6D6D3388E60ULL}
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

	steps = 3;
	X1 = (curve25519_key_t){.key64 = {
		0x86133E9B8C33BC58ULL,
		0x7C8F34195E7B5B65ULL,
		0x77C54FC9731E0767ULL,
		0x591CDD09ED7E2782ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x86133E9B8C33BC58ULL,
			0x7C8F34195E7B5B65ULL,
			0x77C54FC9731E0767ULL,
			0x591CDD09ED7E2782ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEB72C13DD20DBBF5ULL,
			0xDC7184E5CE70B4DCULL,
			0xE6EB59B2A941FEBCULL,
			0x70BA9E7270CAF477ULL}
		},
		.Z = {.key64 = {
			0x2709E6C61D568E13ULL,
			0x3EFC9A8A923F4C07ULL,
			0x8201D5B291E67E35ULL,
			0x4D7952F7737F77E3ULL}
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

	steps = 43;
	X1 = (curve25519_key_t){.key64 = {
		0xB51990022C97E9E0ULL,
		0x748F4061208BF02EULL,
		0x91553A27BA2B4594ULL,
		0x6AD306C184922E22ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB51990022C97E9E0ULL,
			0x748F4061208BF02EULL,
			0x91553A27BA2B4594ULL,
			0x6AD306C184922E22ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x449B2BF313E71C6FULL,
			0xAE1CB1F0844D6AC2ULL,
			0x3D4B5A071A2AFCDAULL,
			0x1028B766637E1B28ULL}
		},
		.Z = {.key64 = {
			0x972183C9E8B1CDACULL,
			0xF0BC92C7163A082EULL,
			0x1A91D4AD7233F995ULL,
			0x57479DBC36C08F46ULL}
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

	steps = 30;
	X1 = (curve25519_key_t){.key64 = {
		0xFC737C290DFAD6F8ULL,
		0x344A20AB7CE9C066ULL,
		0xB8279ADD5C889AC3ULL,
		0x463039E9C48BEB61ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFC737C290DFAD6F8ULL,
			0x344A20AB7CE9C066ULL,
			0xB8279ADD5C889AC3ULL,
			0x463039E9C48BEB61ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1D405B9055F54FAAULL,
			0x9711E38135340449ULL,
			0xD8FE02FEE76988EDULL,
			0x1C09305580BBBCF7ULL}
		},
		.Z = {.key64 = {
			0xD172C7A7B5EBE72DULL,
			0x9A8B3A7B3AC89232ULL,
			0xE8EB811EF70C977FULL,
			0x326666AC8E737705ULL}
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

	steps = 56;
	X1 = (curve25519_key_t){.key64 = {
		0xA1026F7B06502B98ULL,
		0x0A8AE4710D1AD028ULL,
		0x4773C62C902658D7ULL,
		0x44518F2FF1BE7666ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA1026F7B06502B98ULL,
			0x0A8AE4710D1AD028ULL,
			0x4773C62C902658D7ULL,
			0x44518F2FF1BE7666ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEF7F178EDA77F610ULL,
			0x29887FA6AE717739ULL,
			0x614B7323001624D5ULL,
			0x38C4DF28C7133C53ULL}
		},
		.Z = {.key64 = {
			0xB53FE6E53F113BBDULL,
			0xDA4D102E511D41EDULL,
			0x73B19B4137A6FD42ULL,
			0x70A7BA788BA8F537ULL}
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

	steps = 6;
	X1 = (curve25519_key_t){.key64 = {
		0x4BC87E64A6EA3C80ULL,
		0x6C43DFCEEEABE11DULL,
		0xA3513CC3B36E9E9AULL,
		0x460A632B8BA117D4ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4BC87E64A6EA3C80ULL,
			0x6C43DFCEEEABE11DULL,
			0xA3513CC3B36E9E9AULL,
			0x460A632B8BA117D4ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0C272A2DE7D3882CULL,
			0x7BB328160EE8058EULL,
			0x9E96E1245A20C563ULL,
			0x2B484E1D2CC91584ULL}
		},
		.Z = {.key64 = {
			0x07EA21D190C26075ULL,
			0x33D0DDE9E4FA6C36ULL,
			0x4A54D850CB67A5F2ULL,
			0x3DE275E333D9383CULL}
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

	steps = 44;
	X1 = (curve25519_key_t){.key64 = {
		0x28730412154B17B8ULL,
		0xD63DF423F3A83B0EULL,
		0x4D1DC3857D08A734ULL,
		0x454190191A0163CCULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x28730412154B17B8ULL,
			0xD63DF423F3A83B0EULL,
			0x4D1DC3857D08A734ULL,
			0x454190191A0163CCULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDDB516F036445662ULL,
			0x6A7D8327DEB7448EULL,
			0x1C1378ECEA6CA2EDULL,
			0x329ACAE26AE43560ULL}
		},
		.Z = {.key64 = {
			0xD62BDF69616DB0CCULL,
			0xBE7013642A6686F0ULL,
			0x3BDC138F9CB0F2FFULL,
			0x5A0C68071ECF54EBULL}
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

	steps = 17;
	X1 = (curve25519_key_t){.key64 = {
		0x26AF1DC898E15D08ULL,
		0xC1523D826DB99CF0ULL,
		0xFE8C6204C4D7004EULL,
		0x7C54ECB356DFDCF6ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x26AF1DC898E15D08ULL,
			0xC1523D826DB99CF0ULL,
			0xFE8C6204C4D7004EULL,
			0x7C54ECB356DFDCF6ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1A9AB8DCEEFAECBFULL,
			0xF4D1B07D4A3B595BULL,
			0x72C1A31785C94FF5ULL,
			0x6BDFAD7916905C52ULL}
		},
		.Z = {.key64 = {
			0xFB9ED5DDC382CF5AULL,
			0x672FA75934F3E1D2ULL,
			0x741DC9A2D451B785ULL,
			0x23B9B738ACF2DAD6ULL}
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

	steps = 44;
	X1 = (curve25519_key_t){.key64 = {
		0xF431778723489288ULL,
		0x46C29EC0329A3451ULL,
		0x2F1B38D9B379DC48ULL,
		0x6A788DB69B16181BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF431778723489288ULL,
			0x46C29EC0329A3451ULL,
			0x2F1B38D9B379DC48ULL,
			0x6A788DB69B16181BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA4B44FB649248B2FULL,
			0x35EBA1270B39BAC9ULL,
			0x02AA779701F72F7CULL,
			0x6A937256B754E960ULL}
		},
		.Z = {.key64 = {
			0x888AAA19C77CFD48ULL,
			0xD128567F509E7402ULL,
			0xF09F0D30FC17EFC3ULL,
			0x7D537E89BD94EA47ULL}
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

	steps = 62;
	X1 = (curve25519_key_t){.key64 = {
		0x66CDB92C793EE268ULL,
		0x95E9413F9151A26CULL,
		0x4FFE274BE1407F36ULL,
		0x47CFCDD3C42C6A58ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x66CDB92C793EE268ULL,
			0x95E9413F9151A26CULL,
			0x4FFE274BE1407F36ULL,
			0x47CFCDD3C42C6A58ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6EC2D4C251C65CD3ULL,
			0xBA7B20E8483BEF27ULL,
			0xA05A7A8A801D2C10ULL,
			0x0ED7A802101236ABULL}
		},
		.Z = {.key64 = {
			0x823FE3A9BFD80A2FULL,
			0x93E4BB63F097810EULL,
			0xC90F6FFFAA888141ULL,
			0x4AC52095E180CDE4ULL}
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
		0x614C3EB760E7B590ULL,
		0x2BDA3BA8DD14316EULL,
		0xEBC5503557B7C4A3ULL,
		0x5E12878617F62B66ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x614C3EB760E7B590ULL,
			0x2BDA3BA8DD14316EULL,
			0xEBC5503557B7C4A3ULL,
			0x5E12878617F62B66ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x92DC861066886EEFULL,
			0xD2E2EB7F550AD00FULL,
			0x33FD9BE90E475C95ULL,
			0x2A44D29AA2FB3059ULL}
		},
		.Z = {.key64 = {
			0xF91A58294BDBB68FULL,
			0xA252D324543993E1ULL,
			0x544696AE931F3003ULL,
			0x4A0BE4C3F2AED696ULL}
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

	steps = 12;
	X1 = (curve25519_key_t){.key64 = {
		0x041D439731A8FBD8ULL,
		0x8D309FB4CE4E9D22ULL,
		0x5DCCED9539EEF719ULL,
		0x60CC1E8F530C1E2BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x041D439731A8FBD8ULL,
			0x8D309FB4CE4E9D22ULL,
			0x5DCCED9539EEF719ULL,
			0x60CC1E8F530C1E2BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD51F58726DD1B1B4ULL,
			0xF464753ACAA59F59ULL,
			0x2B815577FD9F1C5AULL,
			0x72A705EAFE613767ULL}
		},
		.Z = {.key64 = {
			0xEF1CC363D72F4E97ULL,
			0xAB0F93E010086B68ULL,
			0x667C6A8416A324B8ULL,
			0x6408D8EF9949A988ULL}
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

	steps = 49;
	X1 = (curve25519_key_t){.key64 = {
		0x4DD1160BC63F0A00ULL,
		0x6D86C1274E7CFEECULL,
		0xD957C2319BC4D456ULL,
		0x5170FD93E398868BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4DD1160BC63F0A00ULL,
			0x6D86C1274E7CFEECULL,
			0xD957C2319BC4D456ULL,
			0x5170FD93E398868BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA17AF0FCA35E44CCULL,
			0x4B7276E1BD00761EULL,
			0x989ABBD6EC9E7134ULL,
			0x26AA86D492451122ULL}
		},
		.Z = {.key64 = {
			0x0F183D35EC3B0404ULL,
			0x49894B31E919D35CULL,
			0xA78F638ECE846E87ULL,
			0x054E448418616F42ULL}
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

	steps = 5;
	X1 = (curve25519_key_t){.key64 = {
		0x43E3230EDA4436B0ULL,
		0xD7A015A10B5B40D2ULL,
		0x782D49538E822398ULL,
		0x7B91E6D0B332D4F3ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x43E3230EDA4436B0ULL,
			0xD7A015A10B5B40D2ULL,
			0x782D49538E822398ULL,
			0x7B91E6D0B332D4F3ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDAC43A5FA2059AFAULL,
			0xBBADB64016A3D8F8ULL,
			0x24D6FCDCD2D2D8F5ULL,
			0x21DF2C8C234EA9E0ULL}
		},
		.Z = {.key64 = {
			0x6192B955359D0B71ULL,
			0x2D235E4387127A4EULL,
			0x36FA1E133B062800ULL,
			0x458A8CFBFAE7B5FFULL}
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

	steps = 53;
	X1 = (curve25519_key_t){.key64 = {
		0x4173B7C457C847D0ULL,
		0x0475A50AEFF29D81ULL,
		0x881D75F38E1B1127ULL,
		0x66EDD0DF257B1948ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4173B7C457C847D0ULL,
			0x0475A50AEFF29D81ULL,
			0x881D75F38E1B1127ULL,
			0x66EDD0DF257B1948ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x92E3F360F2F8B75AULL,
			0x966B5A9EB826612CULL,
			0xA9CC538CCF241205ULL,
			0x4F17F921887F6D00ULL}
		},
		.Z = {.key64 = {
			0x07F5C3BDF85AE98DULL,
			0x2F8B859CD194D26FULL,
			0xED1F10BABA240B29ULL,
			0x32A3E2AED742E7F6ULL}
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

	steps = 33;
	X1 = (curve25519_key_t){.key64 = {
		0x971540A9BF9EE650ULL,
		0x5C607ED6C1B7D2FCULL,
		0x47DAF90B3FC9D2CAULL,
		0x4F95D57AFBE3FEC8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x971540A9BF9EE650ULL,
			0x5C607ED6C1B7D2FCULL,
			0x47DAF90B3FC9D2CAULL,
			0x4F95D57AFBE3FEC8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x205EBC4F986B5D0BULL,
			0x1DF2FADC14ED8DF2ULL,
			0xAC75973CBB15C592ULL,
			0x7930DF804D1563F9ULL}
		},
		.Z = {.key64 = {
			0xE1DDF7BEEABBBD58ULL,
			0xCAB30C143B8BE6C3ULL,
			0x25885C5B2A5CD541ULL,
			0x606715F12D7EFFFFULL}
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

	steps = 11;
	X1 = (curve25519_key_t){.key64 = {
		0x60A9E804B4253B88ULL,
		0xE7EBB96A25EAD2C0ULL,
		0xB24C488A6F1CF91EULL,
		0x52FC24A223B490B5ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x60A9E804B4253B88ULL,
			0xE7EBB96A25EAD2C0ULL,
			0xB24C488A6F1CF91EULL,
			0x52FC24A223B490B5ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB2029F872FE019BEULL,
			0x76AD33A334DCBA69ULL,
			0x2C780F2D84D78AB0ULL,
			0x4BAD3DFFBBEA0F5AULL}
		},
		.Z = {.key64 = {
			0x493298BE220A949EULL,
			0x6A1FF0C3E41AE37CULL,
			0xB59021C509C3A439ULL,
			0x41DABA78522E6FBEULL}
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

	steps = 12;
	X1 = (curve25519_key_t){.key64 = {
		0x7643FE32EF939FD0ULL,
		0xFBDBD1034BAEE7B8ULL,
		0xE4D63096B16F4990ULL,
		0x7E6EB75FCD074DF8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7643FE32EF939FD0ULL,
			0xFBDBD1034BAEE7B8ULL,
			0xE4D63096B16F4990ULL,
			0x7E6EB75FCD074DF8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3A08F1D2348F7B01ULL,
			0xB7560B393ECE5AF8ULL,
			0x5CE78FF38C3F100DULL,
			0x5BAB3616B7324CF7ULL}
		},
		.Z = {.key64 = {
			0x18B624C40013B41DULL,
			0x09E281165D121BEBULL,
			0x949CA80D82C4C484ULL,
			0x197B53C6D9237149ULL}
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

	steps = 38;
	X1 = (curve25519_key_t){.key64 = {
		0x32F5A8DF760015F8ULL,
		0xA3E2FB3C0637B9DAULL,
		0x8AC7EF6B7C077AEDULL,
		0x6A10FC0AA31FE107ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x32F5A8DF760015F8ULL,
			0xA3E2FB3C0637B9DAULL,
			0x8AC7EF6B7C077AEDULL,
			0x6A10FC0AA31FE107ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8BA7D97C6DD6FA39ULL,
			0x9DE00BBF95DC676BULL,
			0x35F4915BC72DC4A9ULL,
			0x338FED4BDBD09397ULL}
		},
		.Z = {.key64 = {
			0x3B1CF394CFA864C9ULL,
			0xA790BC486CD6EF3AULL,
			0x447805BB3A40BBC5ULL,
			0x315349841267411AULL}
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

	steps = 60;
	X1 = (curve25519_key_t){.key64 = {
		0xF5A3E7579C3F2770ULL,
		0x508A6C34B373D3B5ULL,
		0xDD3FCE9D347C1D9BULL,
		0x65E78849D1E4A0FDULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF5A3E7579C3F2770ULL,
			0x508A6C34B373D3B5ULL,
			0xDD3FCE9D347C1D9BULL,
			0x65E78849D1E4A0FDULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEE10CAD0B403B754ULL,
			0xE2C75D2E5B578CF2ULL,
			0x1348C0C3297C7635ULL,
			0x32B4794ACD4E211CULL}
		},
		.Z = {.key64 = {
			0x59DFBF203DEFC85CULL,
			0x2B301A8113E7D32AULL,
			0x3D412E66BE44C6ECULL,
			0x051ED8B047133AE2ULL}
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

	steps = 31;
	X1 = (curve25519_key_t){.key64 = {
		0x25D19F92521D2038ULL,
		0x5E1EC0D97E6C6B77ULL,
		0xF772A68AEA252E28ULL,
		0x7A26C1FABBD61ACEULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x25D19F92521D2038ULL,
			0x5E1EC0D97E6C6B77ULL,
			0xF772A68AEA252E28ULL,
			0x7A26C1FABBD61ACEULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4EC065E3238341BDULL,
			0x430FE5D23CC200B3ULL,
			0x1A32F479B6FCB271ULL,
			0x4255ED5A8B26124DULL}
		},
		.Z = {.key64 = {
			0x6B35DD8F4B128A36ULL,
			0xD5500BB28913D302ULL,
			0xFBE7D34444913828ULL,
			0x11175BF9C22CA3DDULL}
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

	steps = 21;
	X1 = (curve25519_key_t){.key64 = {
		0xF287BF789AC94558ULL,
		0x03C3B43A2ED642BCULL,
		0x6F93488B666BAE40ULL,
		0x62059AF56CC6A40CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF287BF789AC94558ULL,
			0x03C3B43A2ED642BCULL,
			0x6F93488B666BAE40ULL,
			0x62059AF56CC6A40CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC71F61AFA5E0628AULL,
			0x60D769852EAD490CULL,
			0xB7F37A1594989052ULL,
			0x523F71D7F513838CULL}
		},
		.Z = {.key64 = {
			0xACD66A82AAEDBBFEULL,
			0x7FCF1C2A9DCE0F74ULL,
			0xC7E30A404D92B118ULL,
			0x52CFD1A235027AAFULL}
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

	steps = 55;
	X1 = (curve25519_key_t){.key64 = {
		0x89588B726DDA6F68ULL,
		0xAF7AC1472E8DB7D3ULL,
		0xF3DEA75D19B860F5ULL,
		0x7F9B45CE38F7BF7DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x89588B726DDA6F68ULL,
			0xAF7AC1472E8DB7D3ULL,
			0xF3DEA75D19B860F5ULL,
			0x7F9B45CE38F7BF7DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1FE9A5FE9D1D0541ULL,
			0x954FE364B9654612ULL,
			0x90A1804AC1144512ULL,
			0x6A938024E4FCE340ULL}
		},
		.Z = {.key64 = {
			0x0192DEB113D6FB43ULL,
			0xD539B982C1D98E78ULL,
			0x932528F799E4BF85ULL,
			0x06C2B6BFA854FBEEULL}
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

	steps = 40;
	X1 = (curve25519_key_t){.key64 = {
		0x56E9DD972CA43008ULL,
		0x110E5ADB84464F22ULL,
		0x095DC4FB289E3F30ULL,
		0x713863E3FDD6DA68ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x56E9DD972CA43008ULL,
			0x110E5ADB84464F22ULL,
			0x095DC4FB289E3F30ULL,
			0x713863E3FDD6DA68ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0401A78C121F2D18ULL,
			0x8E37A08EFDD5409AULL,
			0x992EC085AA1F898CULL,
			0x0228EDC067C6000EULL}
		},
		.Z = {.key64 = {
			0x119E01D797F450C7ULL,
			0xC45C1D99B4900DBDULL,
			0x391A2F154D49FF0CULL,
			0x3A45E047C98DEC40ULL}
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

	steps = 16;
	X1 = (curve25519_key_t){.key64 = {
		0xE81772A9584B5570ULL,
		0x0B533F8139EC2222ULL,
		0x8E9D33E48D390848ULL,
		0x7C971E6CEE2134A0ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE81772A9584B5570ULL,
			0x0B533F8139EC2222ULL,
			0x8E9D33E48D390848ULL,
			0x7C971E6CEE2134A0ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8651BF5C87EA777CULL,
			0x51274A800116B327ULL,
			0x42B3531FA63871EAULL,
			0x056675EDD2D8FFD8ULL}
		},
		.Z = {.key64 = {
			0x78ED9CDABA0D9C8CULL,
			0x3C0AA497D4C243BFULL,
			0xA41CDA10255F6221ULL,
			0x065ABBC0E1D0EF1DULL}
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

	steps = 4;
	X1 = (curve25519_key_t){.key64 = {
		0xE5A3D533FCF9AB98ULL,
		0x3CDB258FC6667A2BULL,
		0xE89CA20780B9057FULL,
		0x4811B38603BDD21CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE5A3D533FCF9AB98ULL,
			0x3CDB258FC6667A2BULL,
			0xE89CA20780B9057FULL,
			0x4811B38603BDD21CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9555E43A6C3FD0CCULL,
			0xC68146D41F8AFEAFULL,
			0xB252A0A64300C839ULL,
			0x41CE9F4C4A9AFE61ULL}
		},
		.Z = {.key64 = {
			0x0F1B44D7FEF9AB78ULL,
			0x33867AF6F0E6A016ULL,
			0x7B388C255DE3E154ULL,
			0x32B96C6D41DD8B10ULL}
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

	steps = 24;
	X1 = (curve25519_key_t){.key64 = {
		0x40F008A9BF1710D0ULL,
		0xE1656085F304F6EFULL,
		0xCDED513ECFA0FDC5ULL,
		0x72BAD5B4A976984DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x40F008A9BF1710D0ULL,
			0xE1656085F304F6EFULL,
			0xCDED513ECFA0FDC5ULL,
			0x72BAD5B4A976984DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEA6083DEF0F3D253ULL,
			0x88FD30D16CFA2961ULL,
			0x24DF52EB51746468ULL,
			0x10E96372774E3143ULL}
		},
		.Z = {.key64 = {
			0x59F5BA11EFBAF51FULL,
			0x5ADD1D9A910BFBD2ULL,
			0x3EF2C060B5C895A0ULL,
			0x41824FAD13BA5580ULL}
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

	steps = 30;
	X1 = (curve25519_key_t){.key64 = {
		0xEDD0ED0D94251738ULL,
		0xB1EA63FFBFACD5C9ULL,
		0xD36654E0A8F09FA1ULL,
		0x4EEC80CA54A4CD36ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEDD0ED0D94251738ULL,
			0xB1EA63FFBFACD5C9ULL,
			0xD36654E0A8F09FA1ULL,
			0x4EEC80CA54A4CD36ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7ED4375721773F0BULL,
			0xC2D9244D418DBEB9ULL,
			0x0ABD6895AAAA9777ULL,
			0x36570F474CBB5A45ULL}
		},
		.Z = {.key64 = {
			0xEF9237055918CA61ULL,
			0x1DE7269017B1D994ULL,
			0x27E13B1720703576ULL,
			0x38A82BCC402A24A1ULL}
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

	steps = 58;
	X1 = (curve25519_key_t){.key64 = {
		0x5D08A4DEDF1F0F80ULL,
		0x5A8F0BAD04D8CEFCULL,
		0xD50E35847CC35907ULL,
		0x4DEA02110D2DBCFDULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5D08A4DEDF1F0F80ULL,
			0x5A8F0BAD04D8CEFCULL,
			0xD50E35847CC35907ULL,
			0x4DEA02110D2DBCFDULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9ECD5A6AF38BD3D6ULL,
			0x4CD5E8CF77294C5AULL,
			0xC7F1FE35FB39710DULL,
			0x76B35C4628786CF8ULL}
		},
		.Z = {.key64 = {
			0x516B841BAF32A2F0ULL,
			0xE17447D67015F3DBULL,
			0x916DFD6070DBA7A6ULL,
			0x32B00566ECD3A690ULL}
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

	steps = 15;
	X1 = (curve25519_key_t){.key64 = {
		0x10EC9F8D0DA79C78ULL,
		0x60C6D497A1C217F7ULL,
		0xA32B3FADFB342CB3ULL,
		0x45CB2AD289E4CF16ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x10EC9F8D0DA79C78ULL,
			0x60C6D497A1C217F7ULL,
			0xA32B3FADFB342CB3ULL,
			0x45CB2AD289E4CF16ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1B13FC916692EE4FULL,
			0x5CCBA41267C53F29ULL,
			0x4D08F62FBE3AFA8DULL,
			0x55F96B2AFADD8E7BULL}
		},
		.Z = {.key64 = {
			0xED357BE9455842FFULL,
			0x98B63FED8D4772C9ULL,
			0x03E4DE7BFE17C97DULL,
			0x5E6DD81FC8141B04ULL}
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

	steps = 9;
	X1 = (curve25519_key_t){.key64 = {
		0xA8F66EDC11425498ULL,
		0x13B664E0F3B23C05ULL,
		0x34145419F84E5616ULL,
		0x6E2BD374CFEFA887ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA8F66EDC11425498ULL,
			0x13B664E0F3B23C05ULL,
			0x34145419F84E5616ULL,
			0x6E2BD374CFEFA887ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9AC650EEF48B54FFULL,
			0x03BB8BB004F4C83FULL,
			0x82DE6E4E2E42EE40ULL,
			0x0005530DB1B8AB8AULL}
		},
		.Z = {.key64 = {
			0x07B24F888757ABEEULL,
			0x56ADBFC43139B7BFULL,
			0x5328C092EBF6E1CAULL,
			0x58789D3E7F68AB8CULL}
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
		0x49C10C6B37506D30ULL,
		0x0A1788E029433583ULL,
		0x5C158FF55EB28E5FULL,
		0x5E9200A0999305D8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x49C10C6B37506D30ULL,
			0x0A1788E029433583ULL,
			0x5C158FF55EB28E5FULL,
			0x5E9200A0999305D8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x77A26E8FD60F99D8ULL,
			0xC64FD8F3E9C5232EULL,
			0x03A05EC02BAC1D6EULL,
			0x5BC603420B7B921CULL}
		},
		.Z = {.key64 = {
			0x734F21DE60B3C36BULL,
			0x5534B5878C5C92E6ULL,
			0x57CB1EB0767E1A57ULL,
			0x21BC8F42C6CE9D6EULL}
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

	steps = 33;
	X1 = (curve25519_key_t){.key64 = {
		0x8F6253AA5CDEAA10ULL,
		0x69818FF36BC8E3A0ULL,
		0x9924D09B6B87CE52ULL,
		0x60B882FF03458384ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8F6253AA5CDEAA10ULL,
			0x69818FF36BC8E3A0ULL,
			0x9924D09B6B87CE52ULL,
			0x60B882FF03458384ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE85B464AA2BA9EA8ULL,
			0x7E4847D74EDA33DBULL,
			0x759F986FAE4CFBD7ULL,
			0x541FE45E18D2ACDCULL}
		},
		.Z = {.key64 = {
			0x84D249EE9046873CULL,
			0x5E664313E1334CBFULL,
			0x20ADEC7106BBD749ULL,
			0x781F95EE5E1DA4F0ULL}
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

	steps = 51;
	X1 = (curve25519_key_t){.key64 = {
		0x76DC0CF23772F768ULL,
		0x8EAAEBB28E065FABULL,
		0xBCACFCDB786197A8ULL,
		0x6DBED3F645216B50ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x76DC0CF23772F768ULL,
			0x8EAAEBB28E065FABULL,
			0xBCACFCDB786197A8ULL,
			0x6DBED3F645216B50ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAA76CC4E05CDB432ULL,
			0xE7924991E851141FULL,
			0xBEC2CE91DCE2625AULL,
			0x387513FDFC05E3C8ULL}
		},
		.Z = {.key64 = {
			0xF6A83ED4757030EFULL,
			0x8869AA71F060F123ULL,
			0xBFB0F9FEF983B843ULL,
			0x2099A291BAA7C178ULL}
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

	steps = 19;
	X1 = (curve25519_key_t){.key64 = {
		0x0CED543C454DB0D0ULL,
		0xBAFA68E4A9212E11ULL,
		0xBF9D880CB3F9DBF3ULL,
		0x4CDAD1443458018AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0CED543C454DB0D0ULL,
			0xBAFA68E4A9212E11ULL,
			0xBF9D880CB3F9DBF3ULL,
			0x4CDAD1443458018AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x279C78327304992CULL,
			0x6A3A893AB893882DULL,
			0xA28817DDBE1A4920ULL,
			0x5D0B6C146AE83789ULL}
		},
		.Z = {.key64 = {
			0x89191EDE68250C3DULL,
			0xC5505A1B6444A436ULL,
			0xC6EF4A2CF05E358AULL,
			0x14AEC92FA9E9111EULL}
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

	steps = 29;
	X1 = (curve25519_key_t){.key64 = {
		0xE0878A0FC6B23030ULL,
		0xA2BADEF569D98D60ULL,
		0xE95F57FFFB6B0F08ULL,
		0x601848CC999B9F9EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE0878A0FC6B23030ULL,
			0xA2BADEF569D98D60ULL,
			0xE95F57FFFB6B0F08ULL,
			0x601848CC999B9F9EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0E7C2E7AAC8CF6DAULL,
			0xB072EDF3D7D98C23ULL,
			0xB2FC4418ED692256ULL,
			0x0F8FBEAE0C63E118ULL}
		},
		.Z = {.key64 = {
			0x186FE733F1419F06ULL,
			0x44EDA87EDD2B0395ULL,
			0x7EC4CC396DC49E22ULL,
			0x6C60B841377E530DULL}
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

	steps = 10;
	X1 = (curve25519_key_t){.key64 = {
		0x21910C8D5DF39CA0ULL,
		0xA843C02A3D5BE450ULL,
		0x7A1C15A092177608ULL,
		0x47358037E17FEF5CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x21910C8D5DF39CA0ULL,
			0xA843C02A3D5BE450ULL,
			0x7A1C15A092177608ULL,
			0x47358037E17FEF5CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7A76A2459DBC1A8DULL,
			0xFBEA3668EA13259DULL,
			0xAA5EA3D62CCF4BF9ULL,
			0x5904EE47E7637E88ULL}
		},
		.Z = {.key64 = {
			0x03D14BF4BA01C6D9ULL,
			0xBDCE553909FC0F79ULL,
			0x43B20DA297756062ULL,
			0x77ADA4DDC4EAF00AULL}
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

	steps = 20;
	X1 = (curve25519_key_t){.key64 = {
		0x017900CACD688AC0ULL,
		0x9CA1C52119B5F079ULL,
		0xB3D217E5AAE37FC2ULL,
		0x5DB49B2E3910741FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x017900CACD688AC0ULL,
			0x9CA1C52119B5F079ULL,
			0xB3D217E5AAE37FC2ULL,
			0x5DB49B2E3910741FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB18EE859239A5768ULL,
			0xEE2BD4BF4BA73809ULL,
			0xFBD8C0D26D3FE548ULL,
			0x2DC859A79B6E5DCBULL}
		},
		.Z = {.key64 = {
			0x752134D1C56E9614ULL,
			0x086970B09EF8E36CULL,
			0x496E997808F32229ULL,
			0x0AEDA6A8AC5F3997ULL}
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

	steps = 40;
	X1 = (curve25519_key_t){.key64 = {
		0xA0DAFD5BBB92ECF8ULL,
		0xE1217E19EC3A1635ULL,
		0xB7174234D52C71FDULL,
		0x475AE968378F2384ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA0DAFD5BBB92ECF8ULL,
			0xE1217E19EC3A1635ULL,
			0xB7174234D52C71FDULL,
			0x475AE968378F2384ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBE91BA5FF75D7603ULL,
			0x662AA93F531F4004ULL,
			0xE51AA8A825059B28ULL,
			0x37820EF6029ECB50ULL}
		},
		.Z = {.key64 = {
			0x9667061701E38CD7ULL,
			0xB739E8757BF2F40BULL,
			0x3366F9B8E706EC00ULL,
			0x0D035FD31C1C0A68ULL}
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

	steps = 60;
	X1 = (curve25519_key_t){.key64 = {
		0x3EFFEA921F544E50ULL,
		0x325174DB80B575CCULL,
		0xD644841D4E5801CEULL,
		0x725C3723826620C0ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3EFFEA921F544E50ULL,
			0x325174DB80B575CCULL,
			0xD644841D4E5801CEULL,
			0x725C3723826620C0ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6B9D09E2E8A0BDFBULL,
			0xD79AB4FD0A09187BULL,
			0x9452A549B79204EDULL,
			0x4F1BAAF1102AD5D0ULL}
		},
		.Z = {.key64 = {
			0xBE84CAB9C7896D2AULL,
			0xA84C8C2E4A04550FULL,
			0x73D8297027A8680BULL,
			0x7A9D5FE1D3AB9661ULL}
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

	steps = 53;
	X1 = (curve25519_key_t){.key64 = {
		0x448A88131E2FEDD0ULL,
		0x2BA356FB6E3E276CULL,
		0xC822042AA9EFFA35ULL,
		0x47EE45F5D5083E3CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x448A88131E2FEDD0ULL,
			0x2BA356FB6E3E276CULL,
			0xC822042AA9EFFA35ULL,
			0x47EE45F5D5083E3CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x262466A69D00EF14ULL,
			0xF9562992ABAEAF31ULL,
			0xE54D815B27ED6D7BULL,
			0x3E74971151B9CFC5ULL}
		},
		.Z = {.key64 = {
			0xBB70B1EAA0916FA0ULL,
			0xA2E2FD4B0643488CULL,
			0xC795150A78D8F479ULL,
			0x7ECEF63FF630D1D3ULL}
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

	steps = 56;
	X1 = (curve25519_key_t){.key64 = {
		0x6840102FBACC5580ULL,
		0x2EE31830C7F3F4C2ULL,
		0xBCAF234373431B63ULL,
		0x441530E6EF848518ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6840102FBACC5580ULL,
			0x2EE31830C7F3F4C2ULL,
			0xBCAF234373431B63ULL,
			0x441530E6EF848518ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x40FBD407B769AB24ULL,
			0x94B34AED8E8DD768ULL,
			0x578297869F5CA8C9ULL,
			0x0899F8B8A13AE03FULL}
		},
		.Z = {.key64 = {
			0xF52F4DC431D688F6ULL,
			0x20D452199903D413ULL,
			0x16D591823C46B83BULL,
			0x60FE8AD0A25DB9FBULL}
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

	steps = 11;
	X1 = (curve25519_key_t){.key64 = {
		0x24CD1C48F5DC9260ULL,
		0x780FC64C72C5642EULL,
		0x1FBFD6EBCBB014E3ULL,
		0x67804FD6A6C7A5FFULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x24CD1C48F5DC9260ULL,
			0x780FC64C72C5642EULL,
			0x1FBFD6EBCBB014E3ULL,
			0x67804FD6A6C7A5FFULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9F884097F805974CULL,
			0x60A6856D1215F278ULL,
			0xDD383B3B78725F2AULL,
			0x523E01763DE0837EULL}
		},
		.Z = {.key64 = {
			0x63F999228E9FCC62ULL,
			0x46768001FD950103ULL,
			0x58D951DBBCB1C865ULL,
			0x280E6F134EB28712ULL}
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

	steps = 11;
	X1 = (curve25519_key_t){.key64 = {
		0x98517812FAAA2220ULL,
		0x772A2D77D0014AEEULL,
		0x70D684660C0D0443ULL,
		0x59DD01AD3BDC7115ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x98517812FAAA2220ULL,
			0x772A2D77D0014AEEULL,
			0x70D684660C0D0443ULL,
			0x59DD01AD3BDC7115ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0D9256AD333FE6B8ULL,
			0x9E6FE95F00EF2DCFULL,
			0x50BE92A4553C55DEULL,
			0x4DF58393C1B2D8FFULL}
		},
		.Z = {.key64 = {
			0x986AC6286CEBACEDULL,
			0xFA2705610416ABC1ULL,
			0x54E721797D4B32B4ULL,
			0x3722E6E6B062FA08ULL}
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

	steps = 5;
	X1 = (curve25519_key_t){.key64 = {
		0xC4D2E9F31BE248F8ULL,
		0xD7046C90D85C66F5ULL,
		0x516DD2EB81AA30C7ULL,
		0x7CE32C352A818AF6ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC4D2E9F31BE248F8ULL,
			0xD7046C90D85C66F5ULL,
			0x516DD2EB81AA30C7ULL,
			0x7CE32C352A818AF6ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAFF035741E84557EULL,
			0x6B0217ED08BBD851ULL,
			0x33D047177DD7031EULL,
			0x57BD701AFE2A459DULL}
		},
		.Z = {.key64 = {
			0xC13FC6D7DF1FC409ULL,
			0x460192C0F68CBB25ULL,
			0xFC97D8287AC691A8ULL,
			0x11AF1672A690DC28ULL}
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

	steps = 32;
	X1 = (curve25519_key_t){.key64 = {
		0xEFF734B7F2FA33B0ULL,
		0x2C8C47C793AF11AAULL,
		0x5ABBC99426F4228DULL,
		0x69B680D434B867A3ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEFF734B7F2FA33B0ULL,
			0x2C8C47C793AF11AAULL,
			0x5ABBC99426F4228DULL,
			0x69B680D434B867A3ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x018A76B855A524A0ULL,
			0xC6418B4E047C2759ULL,
			0x656A51A46BC60107ULL,
			0x2D0B6366158DE553ULL}
		},
		.Z = {.key64 = {
			0xF11313C9F9BB77A0ULL,
			0x5C42ED148293B87FULL,
			0xEA3DA899FAD14625ULL,
			0x31F6ECA9B0C255E5ULL}
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

	steps = 63;
	X1 = (curve25519_key_t){.key64 = {
		0x21DE6CE18E76DC28ULL,
		0x64CFF98DCBCBCA01ULL,
		0x2F297B02CB71C0D7ULL,
		0x4D27FA1125288AF7ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x21DE6CE18E76DC28ULL,
			0x64CFF98DCBCBCA01ULL,
			0x2F297B02CB71C0D7ULL,
			0x4D27FA1125288AF7ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDD25650259C29841ULL,
			0x776C117AF556861AULL,
			0xC3A44222196AD1CFULL,
			0x24D812E8AB47D123ULL}
		},
		.Z = {.key64 = {
			0xF3FFBD0B8E6B5F86ULL,
			0xD1F7E957A3657DDDULL,
			0xAD821B47F170EF91ULL,
			0x58AE1D10F76FDFFCULL}
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

	steps = 6;
	X1 = (curve25519_key_t){.key64 = {
		0xEFC5F50ACBE369C0ULL,
		0x50ACD87C3CF9DC8FULL,
		0x93D05F55ECAB0A47ULL,
		0x6543CC41FCD02158ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEFC5F50ACBE369C0ULL,
			0x50ACD87C3CF9DC8FULL,
			0x93D05F55ECAB0A47ULL,
			0x6543CC41FCD02158ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFED73C6D3294B530ULL,
			0x0CF6510210F62F1FULL,
			0x5D109769FBED28DFULL,
			0x41B6EC191DBFF38FULL}
		},
		.Z = {.key64 = {
			0xD11DD7BE8D3DAD14ULL,
			0x5257A0DEBE04C285ULL,
			0x1410182F32D36618ULL,
			0x47159AF495817FC4ULL}
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

	steps = 42;
	X1 = (curve25519_key_t){.key64 = {
		0x3C4130F29AEE5B60ULL,
		0xD07CAD1A7BE0DF09ULL,
		0xF99580C275AAB972ULL,
		0x6695817D440E34C0ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3C4130F29AEE5B60ULL,
			0xD07CAD1A7BE0DF09ULL,
			0xF99580C275AAB972ULL,
			0x6695817D440E34C0ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBF26D1217061DCC8ULL,
			0x8B0ABD38180F29DAULL,
			0x8D0866509624390CULL,
			0x738AD2233E973DB1ULL}
		},
		.Z = {.key64 = {
			0x237A2D2B46D97D55ULL,
			0x2AB19F7B28C74163ULL,
			0xA05B9B552855AE19ULL,
			0x3C76CCFE0E9EDA6CULL}
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

	steps = 3;
	X1 = (curve25519_key_t){.key64 = {
		0xB4E04C6EFE79E260ULL,
		0xFB2692C5BBA767E4ULL,
		0xD3D663A8E7665250ULL,
		0x79CDCD2BDED4E7BEULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB4E04C6EFE79E260ULL,
			0xFB2692C5BBA767E4ULL,
			0xD3D663A8E7665250ULL,
			0x79CDCD2BDED4E7BEULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9F4DA66074503BB5ULL,
			0x2064354C88E3F01AULL,
			0x17CB00C929A3744EULL,
			0x7D930D05412053E5ULL}
		},
		.Z = {.key64 = {
			0xCB16F353F9A722A0ULL,
			0x553B5D5B39528AA5ULL,
			0x348DF0B2E5C11794ULL,
			0x6D3115B00557A2F1ULL}
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

	steps = 27;
	X1 = (curve25519_key_t){.key64 = {
		0xF8D36A1B341578F0ULL,
		0x581DAC1A2E0D2476ULL,
		0x0825E06704080E0EULL,
		0x71B051498AC6EB87ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF8D36A1B341578F0ULL,
			0x581DAC1A2E0D2476ULL,
			0x0825E06704080E0EULL,
			0x71B051498AC6EB87ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB40E86DD28FC69B5ULL,
			0xEB49B8AD8A78FBC1ULL,
			0xCFFBB226022FCC77ULL,
			0x11EB461F7CFD70A2ULL}
		},
		.Z = {.key64 = {
			0x8C7E2C997C3925E7ULL,
			0x57BF0BB5653DF8E2ULL,
			0xECA67EB3E79625E1ULL,
			0x720F06F9607CB656ULL}
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

	steps = 2;
	X1 = (curve25519_key_t){.key64 = {
		0x5F2D477C6D372198ULL,
		0x5CB855097FE88C29ULL,
		0xC20609B493312EB2ULL,
		0x63B9026C02C6DB58ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5F2D477C6D372198ULL,
			0x5CB855097FE88C29ULL,
			0xC20609B493312EB2ULL,
			0x63B9026C02C6DB58ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE950C64A85D964C4ULL,
			0x5CFFF4F9D54022DEULL,
			0x5B8152669EF12801ULL,
			0x32CA072CD36B8A9BULL}
		},
		.Z = {.key64 = {
			0xA6EC996F19DC5B19ULL,
			0x8521D6B8DA3370AAULL,
			0xF43EA97A20FB5EDDULL,
			0x6104AA7FC1FBB155ULL}
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

	steps = 15;
	X1 = (curve25519_key_t){.key64 = {
		0x947E62B38BB17020ULL,
		0xFEB99C78BA4B8FE4ULL,
		0xE6306F68ED23ED0FULL,
		0x6F9D342DF3B87A99ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x947E62B38BB17020ULL,
			0xFEB99C78BA4B8FE4ULL,
			0xE6306F68ED23ED0FULL,
			0x6F9D342DF3B87A99ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x709742984016C11AULL,
			0xB994B70F7B856062ULL,
			0x79773F01B91E1D8DULL,
			0x292997EDB48931BBULL}
		},
		.Z = {.key64 = {
			0xC3B79FFC68AA497DULL,
			0x70355C5E5947F81AULL,
			0x17AF34F303EA545DULL,
			0x10F55C77BAF7160AULL}
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

	steps = 5;
	X1 = (curve25519_key_t){.key64 = {
		0x368099981A425F80ULL,
		0x30F4D3773EAE4E3BULL,
		0xE5542E9E0A1B9205ULL,
		0x4A80309C60FDACF7ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x368099981A425F80ULL,
			0x30F4D3773EAE4E3BULL,
			0xE5542E9E0A1B9205ULL,
			0x4A80309C60FDACF7ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x701545421C071EFBULL,
			0x6E995795BE42F9B2ULL,
			0xC3D2825090FDC227ULL,
			0x76C6D0B690E7ADF0ULL}
		},
		.Z = {.key64 = {
			0x7B93C8CBBAF76782ULL,
			0x8F6D160144ABAD9BULL,
			0x772A12ABBC82DF0AULL,
			0x39CC8CB23005DC62ULL}
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

	steps = 49;
	X1 = (curve25519_key_t){.key64 = {
		0x524DC4895F6ACD00ULL,
		0xAFB53BC0DFA05248ULL,
		0x40830599864067A9ULL,
		0x6FE635DD417DCC68ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x524DC4895F6ACD00ULL,
			0xAFB53BC0DFA05248ULL,
			0x40830599864067A9ULL,
			0x6FE635DD417DCC68ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x25D17363F555F1B9ULL,
			0x4C3FF7A9C46DD163ULL,
			0x5181E98784562A9FULL,
			0x3D78C64A22B48FA6ULL}
		},
		.Z = {.key64 = {
			0xBA2966C2D64F3246ULL,
			0x6AF69EE59CD680A2ULL,
			0x496BC0AE72364FF3ULL,
			0x04E8399BB3D4BCC1ULL}
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

	steps = 43;
	X1 = (curve25519_key_t){.key64 = {
		0xEDF76DDBED797560ULL,
		0x4FBAE9108801C94CULL,
		0xA2AC0AD75FEC013EULL,
		0x4E0EFAE84057B199ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEDF76DDBED797560ULL,
			0x4FBAE9108801C94CULL,
			0xA2AC0AD75FEC013EULL,
			0x4E0EFAE84057B199ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3B92711C555FA538ULL,
			0x388037DC76DD235DULL,
			0x0D5DF16D3AD0C921ULL,
			0x3EB689F7CAB3D62EULL}
		},
		.Z = {.key64 = {
			0x822C5DD1A43B57D3ULL,
			0x67F21570C1B72BB2ULL,
			0x0B2967AB11904995ULL,
			0x10FE907239500E96ULL}
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

	steps = 63;
	X1 = (curve25519_key_t){.key64 = {
		0x0A5ECB392FE32D98ULL,
		0xB16FB0A62902C25DULL,
		0xCBBD44B9DCCA92E9ULL,
		0x539C85AC55A9CB87ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0A5ECB392FE32D98ULL,
			0xB16FB0A62902C25DULL,
			0xCBBD44B9DCCA92E9ULL,
			0x539C85AC55A9CB87ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3123AA72212BD723ULL,
			0x235BDA8CDD53818FULL,
			0xBCBC62843ED270F3ULL,
			0x327A9AE3A29AEAA3ULL}
		},
		.Z = {.key64 = {
			0xAE73E767DF67D4BCULL,
			0x79AC4CFB3EE19CBDULL,
			0x021B621706A4ACCBULL,
			0x01650C1DBE77D2FDULL}
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

	steps = 50;
	X1 = (curve25519_key_t){.key64 = {
		0x9A3AEB326E451150ULL,
		0x36FC7D4029EBD230ULL,
		0x047129DF2D54A73EULL,
		0x6DEB5B104B8FF45BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9A3AEB326E451150ULL,
			0x36FC7D4029EBD230ULL,
			0x047129DF2D54A73EULL,
			0x6DEB5B104B8FF45BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9860221E3B8A4A54ULL,
			0x1641E036DF5271CDULL,
			0x52CD0CC4D5D9E468ULL,
			0x762F2B5869724D7AULL}
		},
		.Z = {.key64 = {
			0x9DB63DFF79AE4846ULL,
			0xB2109A8419321818ULL,
			0x8D9BC0FFD97054D3ULL,
			0x04BC5E42BDA33DA5ULL}
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

	steps = 32;
	X1 = (curve25519_key_t){.key64 = {
		0x7D7585C121C1ED68ULL,
		0x8EE8792220E778B6ULL,
		0x6E5CCB29EF115BB1ULL,
		0x4765C0F87A20D89DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7D7585C121C1ED68ULL,
			0x8EE8792220E778B6ULL,
			0x6E5CCB29EF115BB1ULL,
			0x4765C0F87A20D89DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7A02D8DABB0E598BULL,
			0x9B71D4C042EF47C1ULL,
			0x49323ABF344245CFULL,
			0x0003494BF4101824ULL}
		},
		.Z = {.key64 = {
			0x16A3FD127CCA291AULL,
			0xCF8B92AAC68C053FULL,
			0x97C07CB96808BE95ULL,
			0x0E8F9520F213B9CFULL}
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

	steps = 17;
	X1 = (curve25519_key_t){.key64 = {
		0xDCFCC5FAAF78D918ULL,
		0x0BC36AC57732CAD2ULL,
		0xCB714AA05A8381B8ULL,
		0x6BE015D68E5EB528ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDCFCC5FAAF78D918ULL,
			0x0BC36AC57732CAD2ULL,
			0xCB714AA05A8381B8ULL,
			0x6BE015D68E5EB528ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBD82225BE9478ED7ULL,
			0x156A37C8CBD9CE9EULL,
			0xF6B982F9FAA7D09FULL,
			0x022D777C3F54861DULL}
		},
		.Z = {.key64 = {
			0x1CF290F81928C3DCULL,
			0x9AA6F520D5AA8B7DULL,
			0xABE09EDFFA927A5DULL,
			0x6189713227DF8329ULL}
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

	steps = 8;
	X1 = (curve25519_key_t){.key64 = {
		0xFB7C95DC85EF38C8ULL,
		0x3D0150AC765E7CD3ULL,
		0xB69247ACE0DC643AULL,
		0x67A1058E8B18CFB7ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFB7C95DC85EF38C8ULL,
			0x3D0150AC765E7CD3ULL,
			0xB69247ACE0DC643AULL,
			0x67A1058E8B18CFB7ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9E0EFA0E66C82F29ULL,
			0xED80288EE2F98E8FULL,
			0x06F2C5466BF09BEFULL,
			0x4C4FAF9F1D610269ULL}
		},
		.Z = {.key64 = {
			0xA1B67A26C67F07E9ULL,
			0x16FF6295400426F5ULL,
			0x32211043A20884C2ULL,
			0x39B985EE1EFBF90CULL}
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

	steps = 29;
	X1 = (curve25519_key_t){.key64 = {
		0x7D2F791DF6597018ULL,
		0x2F3A04ABA30ED843ULL,
		0x71B08E2BF86E9408ULL,
		0x776D09CE8A44EDDDULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7D2F791DF6597018ULL,
			0x2F3A04ABA30ED843ULL,
			0x71B08E2BF86E9408ULL,
			0x776D09CE8A44EDDDULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1BDB8E0E11D9641BULL,
			0xFB5AD27B060162A0ULL,
			0xEC5DDEC16BA65088ULL,
			0x127D1B791F805BCDULL}
		},
		.Z = {.key64 = {
			0x078514686FA8E17FULL,
			0x01B2A18233AF510EULL,
			0xDF82BDA9B72F36AEULL,
			0x4BDBB1FBDB61E1FDULL}
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

	steps = 6;
	X1 = (curve25519_key_t){.key64 = {
		0x43B06517C9C20B40ULL,
		0x09B07D7956FAC6A1ULL,
		0xA94AAD6A17FB7CD1ULL,
		0x75F2564FFBF25E75ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x43B06517C9C20B40ULL,
			0x09B07D7956FAC6A1ULL,
			0xA94AAD6A17FB7CD1ULL,
			0x75F2564FFBF25E75ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEB8F8202D2D32F91ULL,
			0xCA78315081E2BC5BULL,
			0xF48042CE89D59BF0ULL,
			0x32BC37C5334F8BCDULL}
		},
		.Z = {.key64 = {
			0xDF6272378650DE35ULL,
			0xA5B46D77E1E91006ULL,
			0x438D66D02F85AF6EULL,
			0x009512B38F10D522ULL}
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

	steps = 40;
	X1 = (curve25519_key_t){.key64 = {
		0x9BC3BC7FAF601C70ULL,
		0xAE5CEC517A4A9C15ULL,
		0x0D3DFA88685D65C3ULL,
		0x57B925D2C6808CAEULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9BC3BC7FAF601C70ULL,
			0xAE5CEC517A4A9C15ULL,
			0x0D3DFA88685D65C3ULL,
			0x57B925D2C6808CAEULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x766E0CAC14499467ULL,
			0x995AD5910D543251ULL,
			0xC95E5F6E9F2261A5ULL,
			0x5AF9D6D9DBED536BULL}
		},
		.Z = {.key64 = {
			0x305315AF0EAFEFF2ULL,
			0x0014350CDC387639ULL,
			0x6B66258EC4768B9EULL,
			0x7D10E7ACFBCB256EULL}
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

	steps = 50;
	X1 = (curve25519_key_t){.key64 = {
		0x597977A1C8DF69F8ULL,
		0x8301BEEE1B53996EULL,
		0xB937ACE9E516A0FAULL,
		0x67B5C38179D11034ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x597977A1C8DF69F8ULL,
			0x8301BEEE1B53996EULL,
			0xB937ACE9E516A0FAULL,
			0x67B5C38179D11034ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0B9C96D146C1F449ULL,
			0xFBF0814B3D75F56AULL,
			0xA6BF2967100ACEC0ULL,
			0x466F9450A12C71CBULL}
		},
		.Z = {.key64 = {
			0x71AD4CC3BBD2226DULL,
			0xAA6F627340C45CD3ULL,
			0xDE460A4F3AC78846ULL,
			0x405274B12988A314ULL}
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

	steps = 3;
	X1 = (curve25519_key_t){.key64 = {
		0x590F45E9788643F8ULL,
		0xA27AE2A508C547F0ULL,
		0x9CC870271A565485ULL,
		0x438ECA15657E2097ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x590F45E9788643F8ULL,
			0xA27AE2A508C547F0ULL,
			0x9CC870271A565485ULL,
			0x438ECA15657E2097ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD7D29A6CE6D2CE98ULL,
			0xC3186F172C0F5900ULL,
			0x4BE9BBB0D0E1770AULL,
			0x3400AE093FFE2BB0ULL}
		},
		.Z = {.key64 = {
			0x389CE04446DED14AULL,
			0x96CDE700873F3647ULL,
			0xE659C1FBB3C25D3DULL,
			0x48EAE0D5DEF33D1AULL}
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

	steps = 64;
	X1 = (curve25519_key_t){.key64 = {
		0xB3B43B43DC99FA78ULL,
		0x2006810E17BE03A6ULL,
		0x0AE546E4FEF92B7DULL,
		0x7993754A3487BDB8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB3B43B43DC99FA78ULL,
			0x2006810E17BE03A6ULL,
			0x0AE546E4FEF92B7DULL,
			0x7993754A3487BDB8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4F1DAD5CC98163BDULL,
			0x19C9A4BEEF4CB4B0ULL,
			0x56BC7CEDB0A78F84ULL,
			0x0D51F53E742D9614ULL}
		},
		.Z = {.key64 = {
			0x914F661C7CBAE4F7ULL,
			0x98B9F7D96B68B6A4ULL,
			0x79664779B0B8E253ULL,
			0x544434DCD9BD8A9CULL}
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

	steps = 1;
	X1 = (curve25519_key_t){.key64 = {
		0x3CA5507618A71F90ULL,
		0xA37F73B184527C42ULL,
		0x1F3949C419EA2382ULL,
		0x542EAC601F9D093EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3CA5507618A71F90ULL,
			0xA37F73B184527C42ULL,
			0x1F3949C419EA2382ULL,
			0x542EAC601F9D093EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8F30A330E7FA9DFAULL,
			0x1D6170307355333BULL,
			0x2A0DB9D2AE0393C0ULL,
			0x4CD423E10A66A562ULL}
		},
		.Z = {.key64 = {
			0xF29541D8629C7E66ULL,
			0x8DFDCEC61149F108ULL,
			0x7CE5271067A88E0AULL,
			0x50BAB1807E7424F8ULL}
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

	steps = 43;
	X1 = (curve25519_key_t){.key64 = {
		0x25D359BC7FFA4098ULL,
		0x545BCA654B83666CULL,
		0x4C536EBE90A8FB08ULL,
		0x77FAB562ED72731EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x25D359BC7FFA4098ULL,
			0x545BCA654B83666CULL,
			0x4C536EBE90A8FB08ULL,
			0x77FAB562ED72731EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD435ED759E50E4D5ULL,
			0xFA0CF8FAAE359D76ULL,
			0x31220657CC337391ULL,
			0x31A67C2CD261A769ULL}
		},
		.Z = {.key64 = {
			0x9D86CB4795F5950EULL,
			0x991B7388F83CC603ULL,
			0xC3EBDC980CC54DCFULL,
			0x5AC165B77674AE44ULL}
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

	steps = 59;
	X1 = (curve25519_key_t){.key64 = {
		0xF5C8216B754A28A8ULL,
		0x108A771145CE7C19ULL,
		0xDFE67C7964FCA9F4ULL,
		0x6E99591052653274ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF5C8216B754A28A8ULL,
			0x108A771145CE7C19ULL,
			0xDFE67C7964FCA9F4ULL,
			0x6E99591052653274ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x836097CF2A7822FAULL,
			0x92C19EC2C70D17F9ULL,
			0x6BF575D18A9A6BD8ULL,
			0x31FE3E4D73637D50ULL}
		},
		.Z = {.key64 = {
			0x7A66E05BAD0C023FULL,
			0x7E2ADF8230FB741AULL,
			0x7F9970C90AB9F48EULL,
			0x028FB37D8A0B7ABDULL}
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

	steps = 32;
	X1 = (curve25519_key_t){.key64 = {
		0xF8BC71016BA2CA90ULL,
		0x4EBB91134DDD0674ULL,
		0xFF5AA877365B7445ULL,
		0x781E7802187A0932ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF8BC71016BA2CA90ULL,
			0x4EBB91134DDD0674ULL,
			0xFF5AA877365B7445ULL,
			0x781E7802187A0932ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x17E48A2261A4DEC4ULL,
			0x4AC4C931EB16EA6BULL,
			0x478A8F47CF07B6E7ULL,
			0x21E50B44CABC890BULL}
		},
		.Z = {.key64 = {
			0xB91E6373AA0EECB1ULL,
			0x1664D32F8E0BBD2CULL,
			0xE882B9A81C7BDAB4ULL,
			0x165297C1EEAA4505ULL}
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

	steps = 16;
	X1 = (curve25519_key_t){.key64 = {
		0x7BC5C3C835BBBD88ULL,
		0xF35AF6B997FB5EFDULL,
		0xC92C6E981B4005A6ULL,
		0x51892A798F8E2DD7ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7BC5C3C835BBBD88ULL,
			0xF35AF6B997FB5EFDULL,
			0xC92C6E981B4005A6ULL,
			0x51892A798F8E2DD7ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAA0B00008A4DBADDULL,
			0x6AAB65D86199B709ULL,
			0x79BF68C2D921D7A5ULL,
			0x42C72C2B80B38E79ULL}
		},
		.Z = {.key64 = {
			0x0E66FA01FBFD807EULL,
			0x5825068E2A530533ULL,
			0x8B793F3DBC1C7089ULL,
			0x09C22AD11819E8A6ULL}
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

	steps = 41;
	X1 = (curve25519_key_t){.key64 = {
		0xD7A4E5D49C2F7420ULL,
		0x418A4FE19AC1AEF1ULL,
		0x36BABA3DEE9E9114ULL,
		0x5B5E78F0CD3F3075ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD7A4E5D49C2F7420ULL,
			0x418A4FE19AC1AEF1ULL,
			0x36BABA3DEE9E9114ULL,
			0x5B5E78F0CD3F3075ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x665DD3D6050F34CBULL,
			0x5E13D9C046E2A55FULL,
			0xAFE523D7E25B520BULL,
			0x47FE110F1C81B9B4ULL}
		},
		.Z = {.key64 = {
			0xED7F443042E8380CULL,
			0x1853BF4A889D2CBAULL,
			0x191D874D6C56CA6CULL,
			0x6EB3028EDED34B44ULL}
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

	steps = 61;
	X1 = (curve25519_key_t){.key64 = {
		0xC09651EA8976F558ULL,
		0xC5E5869B8BA31023ULL,
		0x638D2FE91E8AD43FULL,
		0x581C3F15F855397EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC09651EA8976F558ULL,
			0xC5E5869B8BA31023ULL,
			0x638D2FE91E8AD43FULL,
			0x581C3F15F855397EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBAB226053759F89AULL,
			0x6C7325BF5B9D4772ULL,
			0x327410BE6A8FB653ULL,
			0x2276F58ECC589A00ULL}
		},
		.Z = {.key64 = {
			0xE64AA98F5FA69687ULL,
			0x1E988B5928AD7644ULL,
			0x9D72E60622F29FA0ULL,
			0x1B58324FABBCA9FDULL}
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

	steps = 7;
	X1 = (curve25519_key_t){.key64 = {
		0x659DEE77D06394D0ULL,
		0x49B4D56D87F3502BULL,
		0xB6C1431F445A9FE7ULL,
		0x74B4BF21580A68B6ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x659DEE77D06394D0ULL,
			0x49B4D56D87F3502BULL,
			0xB6C1431F445A9FE7ULL,
			0x74B4BF21580A68B6ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5F951F0562CCC009ULL,
			0xD5B96443C6CFBA7BULL,
			0xF2DCACAB6308A3E3ULL,
			0x52FCD171C8B32FC4ULL}
		},
		.Z = {.key64 = {
			0x64F070C7021BD4B2ULL,
			0x2CC23750397B5D90ULL,
			0x6CEE6BD66F6C0CB2ULL,
			0x514CD4B4945D79C6ULL}
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

	steps = 34;
	X1 = (curve25519_key_t){.key64 = {
		0xF08257B418875328ULL,
		0xA49CC23EB9D83E39ULL,
		0x838FD379DCAB6348ULL,
		0x632C0B267A235AA1ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF08257B418875328ULL,
			0xA49CC23EB9D83E39ULL,
			0x838FD379DCAB6348ULL,
			0x632C0B267A235AA1ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x470ED6A75EC18CB5ULL,
			0x4F3862D52768511CULL,
			0x0DD260FEFD8B948FULL,
			0x05185DD2DA753D86ULL}
		},
		.Z = {.key64 = {
			0xFA19D8A62A84BCACULL,
			0xF41F9970CEB84FFCULL,
			0xA34D3A9B0DBC3C5EULL,
			0x2BCF8784D5DD9DDEULL}
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

	steps = 57;
	X1 = (curve25519_key_t){.key64 = {
		0x4F0234117926AAE8ULL,
		0x38091D9C8605D531ULL,
		0x1FC6AFFA38AF10D0ULL,
		0x470B1C56CA01AFA7ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4F0234117926AAE8ULL,
			0x38091D9C8605D531ULL,
			0x1FC6AFFA38AF10D0ULL,
			0x470B1C56CA01AFA7ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4B1739BE822851A4ULL,
			0x03F3CFD2A323D2AEULL,
			0x2AEA10E76E618A2CULL,
			0x2C0742874A00A717ULL}
		},
		.Z = {.key64 = {
			0xBBA1454869837708ULL,
			0x58E1985901994B84ULL,
			0x566417FD511A8B58ULL,
			0x36B0EFADCACED5F1ULL}
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

	steps = 49;
	X1 = (curve25519_key_t){.key64 = {
		0x701574D41975B920ULL,
		0xCDB5ED798E923D8CULL,
		0x397B8C2CD22DC0B1ULL,
		0x5473CD568C60E0B7ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x701574D41975B920ULL,
			0xCDB5ED798E923D8CULL,
			0x397B8C2CD22DC0B1ULL,
			0x5473CD568C60E0B7ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5FCBCAD82BCA1544ULL,
			0x61161C6C9E98D501ULL,
			0x5B5E0850090FF66DULL,
			0x3682797C5050A333ULL}
		},
		.Z = {.key64 = {
			0xA6949A8DF897A84CULL,
			0xE5D40261A102FFD8ULL,
			0x9C2B067CF5994E4DULL,
			0x0A6489BBE6CA0E4BULL}
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

	steps = 8;
	X1 = (curve25519_key_t){.key64 = {
		0xC62B15D48B44BB80ULL,
		0x3AC13E9EE2352470ULL,
		0x5A61E3CB2C354FC6ULL,
		0x440BEC70B6612DE0ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC62B15D48B44BB80ULL,
			0x3AC13E9EE2352470ULL,
			0x5A61E3CB2C354FC6ULL,
			0x440BEC70B6612DE0ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x285FC81370791959ULL,
			0xA78DC641A204463DULL,
			0x7021B6C140DCABF2ULL,
			0x2FDF8346374F60C7ULL}
		},
		.Z = {.key64 = {
			0x61845847C7DE6527ULL,
			0x463015494CEE98A9ULL,
			0x4FD4640C0CA499F1ULL,
			0x299106A0C16B8A3EULL}
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

	steps = 58;
	X1 = (curve25519_key_t){.key64 = {
		0xBF3855A5504053A8ULL,
		0xFA9D03093692E26AULL,
		0xBA49908D0EB38201ULL,
		0x622A79B913CFCC27ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBF3855A5504053A8ULL,
			0xFA9D03093692E26AULL,
			0xBA49908D0EB38201ULL,
			0x622A79B913CFCC27ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9309A7DDE06D448DULL,
			0xCF151F509ECBEE75ULL,
			0xC9FB1C392EBDFA41ULL,
			0x3C60696B9AA9DF9CULL}
		},
		.Z = {.key64 = {
			0x8B6AA2F6EBFD55E3ULL,
			0xB6B233A713FB0855ULL,
			0x56733FE54D24F988ULL,
			0x7B1AE015D8DEBD5AULL}
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

	steps = 29;
	X1 = (curve25519_key_t){.key64 = {
		0x2E0F9202BB0AD780ULL,
		0x47FCEA588986FB0FULL,
		0x1FE2E3973D47D2E9ULL,
		0x4EB57463CC3EEE19ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2E0F9202BB0AD780ULL,
			0x47FCEA588986FB0FULL,
			0x1FE2E3973D47D2E9ULL,
			0x4EB57463CC3EEE19ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3BEAFD4B60D9F64AULL,
			0xA0FB507B94AEF5C6ULL,
			0x08F335A043A17D7CULL,
			0x0F67D1319F38CC5FULL}
		},
		.Z = {.key64 = {
			0x29EE8F820E1B0152ULL,
			0x8DE731A0A2E0043CULL,
			0xC465277FF8345A69ULL,
			0x23341F8BAF3618B9ULL}
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

	steps = 5;
	X1 = (curve25519_key_t){.key64 = {
		0x43FBCB79267D1798ULL,
		0x24280A7DFF6B60ADULL,
		0x8AF709940343CE19ULL,
		0x7559F08B7B7D1F7EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x43FBCB79267D1798ULL,
			0x24280A7DFF6B60ADULL,
			0x8AF709940343CE19ULL,
			0x7559F08B7B7D1F7EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0D9639C706530CCAULL,
			0x76DE71EF2066AE03ULL,
			0x75DD8497A34D18BCULL,
			0x7AC2E1FC5AF9F50CULL}
		},
		.Z = {.key64 = {
			0x58DBA26C7D9D52FAULL,
			0x2210D1C8AEE66C8FULL,
			0x2CD62DC53A9449ADULL,
			0x484C5579A0B74BFFULL}
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

	steps = 53;
	X1 = (curve25519_key_t){.key64 = {
		0xA8A8BDA7FA1975E8ULL,
		0x3F30CBC6BF444DC8ULL,
		0xF49A4C57729E2AF4ULL,
		0x6F787AD37AE0ED42ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA8A8BDA7FA1975E8ULL,
			0x3F30CBC6BF444DC8ULL,
			0xF49A4C57729E2AF4ULL,
			0x6F787AD37AE0ED42ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x41F1CF0D553488F0ULL,
			0x88C0B48CD8E5F622ULL,
			0xD6271EB76B7CB874ULL,
			0x17E199EFE7D62C0EULL}
		},
		.Z = {.key64 = {
			0xFF05913C011CEB9DULL,
			0x7A150CF21CE87E96ULL,
			0x438ED2C56F427C49ULL,
			0x01412C0841D9DCBCULL}
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

	steps = 34;
	X1 = (curve25519_key_t){.key64 = {
		0xBD0F0798052F9630ULL,
		0xA983FEDF4B4ADAFDULL,
		0x40F7370A23F73668ULL,
		0x7E3F57E6B0EB0BC7ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBD0F0798052F9630ULL,
			0xA983FEDF4B4ADAFDULL,
			0x40F7370A23F73668ULL,
			0x7E3F57E6B0EB0BC7ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE0CFB2DFEC4934A9ULL,
			0xA25B705A4D540F5BULL,
			0xB24EE2788D9DE1B1ULL,
			0x3CDBE7954B1CEEE4ULL}
		},
		.Z = {.key64 = {
			0x0AE46376243C5A11ULL,
			0x8EADBFA7643C1628ULL,
			0x14C2EBA1C8EA7066ULL,
			0x124A3F2EB24BAA22ULL}
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

	steps = 56;
	X1 = (curve25519_key_t){.key64 = {
		0x49E0655C925B6A30ULL,
		0x6E3A10E0EAB607CDULL,
		0x474A4965BC87C925ULL,
		0x7AA8311B8E98D3C2ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x49E0655C925B6A30ULL,
			0x6E3A10E0EAB607CDULL,
			0x474A4965BC87C925ULL,
			0x7AA8311B8E98D3C2ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xABCD238646E8EC31ULL,
			0xB7706A72A842E421ULL,
			0x5084EE82E5E1E3ABULL,
			0x6D616071B5A32D25ULL}
		},
		.Z = {.key64 = {
			0xC687119DF7E81C43ULL,
			0x7E44E8F20422900FULL,
			0x4A19E30A255F9440ULL,
			0x7A0603ED6CA74238ULL}
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

	steps = 31;
	X1 = (curve25519_key_t){.key64 = {
		0xAB514710316B8590ULL,
		0x997BC85738F2BBBEULL,
		0x2194F5F72AB8147FULL,
		0x79575218FC4A7C50ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAB514710316B8590ULL,
			0x997BC85738F2BBBEULL,
			0x2194F5F72AB8147FULL,
			0x79575218FC4A7C50ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3C327AC38F1DD6F6ULL,
			0xBBDA38B10C7D812CULL,
			0xEBC701D964F6B0E1ULL,
			0x1B9C0BE7E717DAE4ULL}
		},
		.Z = {.key64 = {
			0xF2201D77F02251EEULL,
			0x384CF051E925776BULL,
			0xF33243C371804AF6ULL,
			0x70477A23BA7F27F3ULL}
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

	steps = 45;
	X1 = (curve25519_key_t){.key64 = {
		0x97D07AA8BFA88300ULL,
		0xF780CE660C1B9DF6ULL,
		0xD57392554E9B90C4ULL,
		0x6516C4F1BC8ADA68ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x97D07AA8BFA88300ULL,
			0xF780CE660C1B9DF6ULL,
			0xD57392554E9B90C4ULL,
			0x6516C4F1BC8ADA68ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xADC6865358321C9BULL,
			0x7EC764375D612BD0ULL,
			0xAFF9CFC3FB0D4B3BULL,
			0x67D775EF9D4E7928ULL}
		},
		.Z = {.key64 = {
			0x4FAE4857E8D8209FULL,
			0xA6C6528C5BA48A99ULL,
			0x836F0E3FE43F04C0ULL,
			0x7C35ECA0187C543BULL}
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

	steps = 28;
	X1 = (curve25519_key_t){.key64 = {
		0xDF6B62354FFD5578ULL,
		0x22A6A9D605833D00ULL,
		0x5A277D276C72CC20ULL,
		0x6A5282770931FFB7ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDF6B62354FFD5578ULL,
			0x22A6A9D605833D00ULL,
			0x5A277D276C72CC20ULL,
			0x6A5282770931FFB7ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1734369B340EAEB2ULL,
			0xF8B1C4D918F446E8ULL,
			0x0FA2BB2968412484ULL,
			0x15C96F254E83831CULL}
		},
		.Z = {.key64 = {
			0x72BEDC3B3B5F7530ULL,
			0x142382908FA0B579ULL,
			0xFEC871FFEE06E928ULL,
			0x463C486137D8B3C1ULL}
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

	steps = 21;
	X1 = (curve25519_key_t){.key64 = {
		0x2D3B120D0D541D60ULL,
		0x34064FB684899888ULL,
		0xB61A194E114C8871ULL,
		0x4E70434EA349841FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2D3B120D0D541D60ULL,
			0x34064FB684899888ULL,
			0xB61A194E114C8871ULL,
			0x4E70434EA349841FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x64A0CFA09A4AD45BULL,
			0x21F5937C0E8AE6E8ULL,
			0x9AFBD74D694231E1ULL,
			0x1F00E8C3F063680AULL}
		},
		.Z = {.key64 = {
			0xBF84CC353E7A2BD2ULL,
			0x811AA87E0994C5A2ULL,
			0x5F1BF65D03C43891ULL,
			0x4BDEE795459500EEULL}
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

	steps = 41;
	X1 = (curve25519_key_t){.key64 = {
		0x7913C040CB40DD58ULL,
		0xCFB2CABA2BD252F5ULL,
		0xA3D8953501D176A2ULL,
		0x53A3A23033FAB9A7ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7913C040CB40DD58ULL,
			0xCFB2CABA2BD252F5ULL,
			0xA3D8953501D176A2ULL,
			0x53A3A23033FAB9A7ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x11048AE44F5351BBULL,
			0xE73386F73FD6364EULL,
			0x0A00D3E8B8FB08B7ULL,
			0x55BCCB58FCDAA13EULL}
		},
		.Z = {.key64 = {
			0x7A528700BD73C9E6ULL,
			0x747702543B734AC9ULL,
			0x8222B48A85EF4479ULL,
			0x649DF145902A0332ULL}
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

	steps = 37;
	X1 = (curve25519_key_t){.key64 = {
		0x2E5F543EA74682F0ULL,
		0xEF0BFADC6554A5D7ULL,
		0x635118F34E6D1CDEULL,
		0x748117AF336DA901ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2E5F543EA74682F0ULL,
			0xEF0BFADC6554A5D7ULL,
			0x635118F34E6D1CDEULL,
			0x748117AF336DA901ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x73D4D5B99A00F87AULL,
			0xB730D7EEEC9164FAULL,
			0xAD17FF2F6307F0B4ULL,
			0x3477E55E645C56C6ULL}
		},
		.Z = {.key64 = {
			0x06DC589683FCCDA7ULL,
			0x0D6D36BD8C598B82ULL,
			0x7D5C2528A1CBB79BULL,
			0x6E01F9A9DF7B1AFCULL}
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

	steps = 1;
	X1 = (curve25519_key_t){.key64 = {
		0xCD8069F0A377E340ULL,
		0x4C3A9B0B34749F61ULL,
		0x34704386FDDB2B82ULL,
		0x62430508E0E9DAFEULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCD8069F0A377E340ULL,
			0x4C3A9B0B34749F61ULL,
			0x34704386FDDB2B82ULL,
			0x62430508E0E9DAFEULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4D6E1BC07E16A64FULL,
			0xA16D921CD32CD8B3ULL,
			0x62AD437236AF25F2ULL,
			0x30BBD5C4F773A453ULL}
		},
		.Z = {.key64 = {
			0x3601A7C28DDF8D39ULL,
			0x30EA6C2CD1D27D87ULL,
			0xD1C10E1BF76CAE09ULL,
			0x090C142383A76BF8ULL}
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

	steps = 4;
	X1 = (curve25519_key_t){.key64 = {
		0x3F4FB8EF67BF6CB0ULL,
		0xCA6CC5DCECC74BF1ULL,
		0xBD43AC19CC3D855CULL,
		0x7C8D4B3F466F7C5CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3F4FB8EF67BF6CB0ULL,
			0xCA6CC5DCECC74BF1ULL,
			0xBD43AC19CC3D855CULL,
			0x7C8D4B3F466F7C5CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x730C5C86843FE6AEULL,
			0x9F49192D584EBDA3ULL,
			0xDEF5FA7BA18F6E8EULL,
			0x773DEA9F0E3C2C4CULL}
		},
		.Z = {.key64 = {
			0xF294521B76DEF9E7ULL,
			0x48D8949081FA5EEBULL,
			0xF5DDE8A312F50B0BULL,
			0x606E4A3328B049B5ULL}
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

	steps = 55;
	X1 = (curve25519_key_t){.key64 = {
		0xFDE3BAD97FFC5668ULL,
		0x2866F54D155A5787ULL,
		0x3BAC762B73F5636FULL,
		0x55863AC3C8D400B2ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFDE3BAD97FFC5668ULL,
			0x2866F54D155A5787ULL,
			0x3BAC762B73F5636FULL,
			0x55863AC3C8D400B2ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEF47F9CB7DA733C7ULL,
			0x2DAD6929F533BA8AULL,
			0x9AD5F5EABA8DC708ULL,
			0x1E7E7BAA443293DCULL}
		},
		.Z = {.key64 = {
			0x9047C5C17F8C77A1ULL,
			0xC9A80B3D8C62B373ULL,
			0x628407F6824918DBULL,
			0x5F1C1CCCFC7FD0C1ULL}
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

	steps = 49;
	X1 = (curve25519_key_t){.key64 = {
		0x9BCCAB8C25C0EB30ULL,
		0xBCC7BBA53F33B586ULL,
		0xCEC00D172F169134ULL,
		0x5382B4C7E1DA75C4ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9BCCAB8C25C0EB30ULL,
			0xBCC7BBA53F33B586ULL,
			0xCEC00D172F169134ULL,
			0x5382B4C7E1DA75C4ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2FEF585D29B49CA7ULL,
			0x5EEF4CD3406DEB37ULL,
			0xD55E0DD072E649E0ULL,
			0x74BE12BB8F00C299ULL}
		},
		.Z = {.key64 = {
			0xA08ABD18068732F6ULL,
			0xCE6136EC4B13F948ULL,
			0x862A4B445293A20BULL,
			0x7A5F5E39E68F48F3ULL}
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

	steps = 59;
	X1 = (curve25519_key_t){.key64 = {
		0x9503EF4207EA1E08ULL,
		0x1B4F34B144F2D2B7ULL,
		0x8D83BF63EBE6665FULL,
		0x5C989252AAA2B383ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9503EF4207EA1E08ULL,
			0x1B4F34B144F2D2B7ULL,
			0x8D83BF63EBE6665FULL,
			0x5C989252AAA2B383ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x157972DE6178B4CEULL,
			0xCDCCD7E4FDAA3096ULL,
			0x8D310D6B971A3C63ULL,
			0x4E18573A511D9357ULL}
		},
		.Z = {.key64 = {
			0x64926240166F8FE6ULL,
			0xE2C755C5B4DDFCBAULL,
			0x172791520DD14F80ULL,
			0x7B5466CECF4E18FBULL}
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

	steps = 15;
	X1 = (curve25519_key_t){.key64 = {
		0x8309E1CF310454E8ULL,
		0x4A1EF3B8EA53950FULL,
		0xB2C122CDD7022A6AULL,
		0x6C75F0940133B4DAULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8309E1CF310454E8ULL,
			0x4A1EF3B8EA53950FULL,
			0xB2C122CDD7022A6AULL,
			0x6C75F0940133B4DAULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3D7791610DA475C9ULL,
			0x8ACA404A520C4A9EULL,
			0x888A0DA7AD51A851ULL,
			0x093B01B7728C2C77ULL}
		},
		.Z = {.key64 = {
			0x8CF8F056FC883EAEULL,
			0x0604D53456DAB74EULL,
			0xF3F69A911D0E503EULL,
			0x5B1777B67658968CULL}
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

	steps = 19;
	X1 = (curve25519_key_t){.key64 = {
		0xFE26F3149CB2BA90ULL,
		0x7D3AAC4DBC09010FULL,
		0xD4AE70D9982C229BULL,
		0x76E76CB93F8ED279ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFE26F3149CB2BA90ULL,
			0x7D3AAC4DBC09010FULL,
			0xD4AE70D9982C229BULL,
			0x76E76CB93F8ED279ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB210EAE2110200ADULL,
			0x36224FA2E9D3E097ULL,
			0x2AAAE31648FBA22BULL,
			0x643686C46DC08A4FULL}
		},
		.Z = {.key64 = {
			0x4C22B502D8A44528ULL,
			0x4428E310D9163029ULL,
			0x59032F0E9C14B7EFULL,
			0x22A771C143A79A64ULL}
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

	steps = 22;
	X1 = (curve25519_key_t){.key64 = {
		0x81FE184E6B2E59D0ULL,
		0x11723141D6D84D6DULL,
		0x4E909802418CD864ULL,
		0x5EEDCE60BDA73E81ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x81FE184E6B2E59D0ULL,
			0x11723141D6D84D6DULL,
			0x4E909802418CD864ULL,
			0x5EEDCE60BDA73E81ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6CCAF76B3D3DA967ULL,
			0xB200F67BA66937BFULL,
			0x6BB8E08C95FDCB57ULL,
			0x2CC3CA33D090A4B1ULL}
		},
		.Z = {.key64 = {
			0x4D6AAA7471C20937ULL,
			0x3600EEE055EC0E63ULL,
			0x4660D14B04661059ULL,
			0x220A33982C0DFCB2ULL}
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

	steps = 3;
	X1 = (curve25519_key_t){.key64 = {
		0xA2479AEB7C3B2FE0ULL,
		0x46A1E26E1300A526ULL,
		0x8BDE973C552483B3ULL,
		0x4BD149D3AD87041AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA2479AEB7C3B2FE0ULL,
			0x46A1E26E1300A526ULL,
			0x8BDE973C552483B3ULL,
			0x4BD149D3AD87041AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x71CA28AF4717261AULL,
			0xDB52073337D4A188ULL,
			0xE62FC39C810CF90FULL,
			0x3142220345FAAFAFULL}
		},
		.Z = {.key64 = {
			0xE52969AB5FAF1C3FULL,
			0xB319AFDD4E465612ULL,
			0x7BF5C322B21D10FCULL,
			0x4811898172A4C6A3ULL}
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

	steps = 64;
	X1 = (curve25519_key_t){.key64 = {
		0x937C498378D9A2B0ULL,
		0xE003F33CB786493DULL,
		0x16FDB69572F552B1ULL,
		0x63DF64072226636BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x937C498378D9A2B0ULL,
			0xE003F33CB786493DULL,
			0x16FDB69572F552B1ULL,
			0x63DF64072226636BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3A7B89E12C561678ULL,
			0x967AFD8BE1AF74A5ULL,
			0xB41CC29DAA46A069ULL,
			0x3D2F87CF06181B5AULL}
		},
		.Z = {.key64 = {
			0x4C9F82B8A18A634AULL,
			0x8DD6B6D7BB6D3CBAULL,
			0x16E11F155739C035ULL,
			0x55090405711B9AE4ULL}
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

	steps = 25;
	X1 = (curve25519_key_t){.key64 = {
		0x91E774B937927D40ULL,
		0x1AB22AB271CEC210ULL,
		0x4F22878CC9ED4E67ULL,
		0x5403F6203B2FFE69ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x91E774B937927D40ULL,
			0x1AB22AB271CEC210ULL,
			0x4F22878CC9ED4E67ULL,
			0x5403F6203B2FFE69ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7F22DFB45BF9B301ULL,
			0xEEE9078D2AF83454ULL,
			0x580FC48ABA13D02FULL,
			0x13318D6E55ACDFB9ULL}
		},
		.Z = {.key64 = {
			0x23E3763C9F280CFAULL,
			0xB67C4B9429C967C3ULL,
			0xDA47891F481783C5ULL,
			0x43CDC3809E8D46FAULL}
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

	steps = 4;
	X1 = (curve25519_key_t){.key64 = {
		0xE4F4DC4063F05828ULL,
		0x698EF6486DD4DFD5ULL,
		0x1ACE76F6079982F0ULL,
		0x6EB68B77EE5CF8A9ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE4F4DC4063F05828ULL,
			0x698EF6486DD4DFD5ULL,
			0x1ACE76F6079982F0ULL,
			0x6EB68B77EE5CF8A9ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5059CB7D88F1B7D5ULL,
			0x071E55595A6CD5EAULL,
			0x36E734301F585989ULL,
			0x13D4E6798DFD9903ULL}
		},
		.Z = {.key64 = {
			0x0BA3495CFD5BBA0FULL,
			0x984AE0270C44390CULL,
			0xA119708AD4D7CECAULL,
			0x291EF12C35F4D082ULL}
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

	steps = 60;
	X1 = (curve25519_key_t){.key64 = {
		0x7CF658AAAB080818ULL,
		0x54429112A03BF723ULL,
		0x9455FE7B2DC58113ULL,
		0x7063F5925945B3E8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7CF658AAAB080818ULL,
			0x54429112A03BF723ULL,
			0x9455FE7B2DC58113ULL,
			0x7063F5925945B3E8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFA39AFAC9EBA310EULL,
			0xBEE469AF99DBA6F9ULL,
			0xE046652C3204180BULL,
			0x791E21497248CCACULL}
		},
		.Z = {.key64 = {
			0x8E78745EFAD474F2ULL,
			0xB4A06569A5D7C3EFULL,
			0x804D8CEF60AE0C96ULL,
			0x69BE8037C1CE5625ULL}
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
		0x169B2B411C089150ULL,
		0xE08BB251FE2A5CD4ULL,
		0x7648E72172252E09ULL,
		0x6F2DE0C2AA0AFE4DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x169B2B411C089150ULL,
			0xE08BB251FE2A5CD4ULL,
			0x7648E72172252E09ULL,
			0x6F2DE0C2AA0AFE4DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFF08B2CA95E80381ULL,
			0xB3D28E46681E012AULL,
			0x466F55EA74C4C491ULL,
			0x1393E8AD47C2A104ULL}
		},
		.Z = {.key64 = {
			0x21F58149C3281C01ULL,
			0x4068BC2683756847ULL,
			0x09968F27BA7518CCULL,
			0x62F1BC297B8E0CCFULL}
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

	steps = 13;
	X1 = (curve25519_key_t){.key64 = {
		0xE3EE489CA51247F8ULL,
		0x7455A9B3815A1CF4ULL,
		0xB8BB6114C6EB34FCULL,
		0x7336F333CED0E349ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE3EE489CA51247F8ULL,
			0x7455A9B3815A1CF4ULL,
			0xB8BB6114C6EB34FCULL,
			0x7336F333CED0E349ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6DF21C0AD0A6BC11ULL,
			0x521C4924CEF834C4ULL,
			0x4D4D6CAE08CEF8EAULL,
			0x6B49B68D4F5E49A5ULL}
		},
		.Z = {.key64 = {
			0xA19C0E7B027A6D9BULL,
			0x41791C833BA419F0ULL,
			0x8B0C65925116BF0EULL,
			0x309E7BFC2D26394DULL}
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

	steps = 45;
	X1 = (curve25519_key_t){.key64 = {
		0xCC83542DB7EEE630ULL,
		0x9A13E03627CB5891ULL,
		0x2F6F027B85FDD543ULL,
		0x72218EA9AA66CD59ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCC83542DB7EEE630ULL,
			0x9A13E03627CB5891ULL,
			0x2F6F027B85FDD543ULL,
			0x72218EA9AA66CD59ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5A2E81B83C6C39E4ULL,
			0x2DB7C741499E248DULL,
			0xE9674EE3E1606AD0ULL,
			0x7DC1C79CEECC69A6ULL}
		},
		.Z = {.key64 = {
			0x2A54533B689CDE60ULL,
			0x8EFB070CABAAE905ULL,
			0x98BEFF789859C648ULL,
			0x2EA9030EC2BBAD8EULL}
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

	steps = 34;
	X1 = (curve25519_key_t){.key64 = {
		0xA738356BED94C090ULL,
		0x2FE88E9288B42490ULL,
		0x5283663C244020B1ULL,
		0x5AD1EA9ACE286B0BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA738356BED94C090ULL,
			0x2FE88E9288B42490ULL,
			0x5283663C244020B1ULL,
			0x5AD1EA9ACE286B0BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x75264B2542954C4FULL,
			0xD857082182276991ULL,
			0xBC885F1FCE63C0D5ULL,
			0x1378D10F28E40564ULL}
		},
		.Z = {.key64 = {
			0xD1F0F0813F85C346ULL,
			0x6B504D26DBCFC017ULL,
			0xC8EE4BAF5B0CAD35ULL,
			0x129CFBADB9D2C351ULL}
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

	steps = 16;
	X1 = (curve25519_key_t){.key64 = {
		0xB7C738457FDD4B68ULL,
		0x15ADAB12BE474191ULL,
		0x898D0BBE1719723BULL,
		0x6DAD09495F33C184ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB7C738457FDD4B68ULL,
			0x15ADAB12BE474191ULL,
			0x898D0BBE1719723BULL,
			0x6DAD09495F33C184ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7E19100CEA0C95E0ULL,
			0x098B7F3059CC0A68ULL,
			0x8C83A1017719AEEBULL,
			0x0399939DB2E9110FULL}
		},
		.Z = {.key64 = {
			0x2D825125B0EB4837ULL,
			0xF79A4C0020A9B24FULL,
			0xA83943C955804154ULL,
			0x0D33AB427C96206AULL}
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

	steps = 63;
	X1 = (curve25519_key_t){.key64 = {
		0x768E0C87FBEC7D28ULL,
		0xD07E1A859848480BULL,
		0xA0DBF7BAFC84554FULL,
		0x7ABCAFBBA2D6AAA1ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x768E0C87FBEC7D28ULL,
			0xD07E1A859848480BULL,
			0xA0DBF7BAFC84554FULL,
			0x7ABCAFBBA2D6AAA1ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1B9B687A4F5EFE08ULL,
			0xE6507BA674F448C6ULL,
			0xDFD8A7DE2E3F5365ULL,
			0x507D4D0A94304249ULL}
		},
		.Z = {.key64 = {
			0x97AC1CE8BB64343BULL,
			0x680D98B6A3E40597ULL,
			0xB3DD072E2DD9862EULL,
			0x48852CC3C047751EULL}
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

	steps = 4;
	X1 = (curve25519_key_t){.key64 = {
		0x546C6B5A45754768ULL,
		0xA0A280B0AAFA7BADULL,
		0xCE527D5080FEC082ULL,
		0x41C2897DA8E032B9ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x546C6B5A45754768ULL,
			0xA0A280B0AAFA7BADULL,
			0xCE527D5080FEC082ULL,
			0x41C2897DA8E032B9ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x453CAA329E29FAE3ULL,
			0x1A33B6AC4EC69766ULL,
			0xBC877BC4F360301BULL,
			0x2C56890F1BAAC5CCULL}
		},
		.Z = {.key64 = {
			0x0697B7ED04ECBB8BULL,
			0x6F970C0B1046FCF8ULL,
			0x17996F122507A4D7ULL,
			0x248C4AB4C91CCB08ULL}
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
		0x6983EB0F285D4DB8ULL,
		0xF97AD7D6FE431DC2ULL,
		0x2527AEE67C7DC947ULL,
		0x5525000FF74E9BB9ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6983EB0F285D4DB8ULL,
			0xF97AD7D6FE431DC2ULL,
			0x2527AEE67C7DC947ULL,
			0x5525000FF74E9BB9ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7B9E42C2870CD2D8ULL,
			0x1D077A12A5C8D80FULL,
			0xF33CF138FFB63533ULL,
			0x6EE414543DD0B2EEULL}
		},
		.Z = {.key64 = {
			0xD2A98CCDB97D4858ULL,
			0x412D0355FC7E0AFCULL,
			0xDE91605BD289AD46ULL,
			0x652F53E99F0DD9F7ULL}
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

	steps = 17;
	X1 = (curve25519_key_t){.key64 = {
		0xE80BC813E04567D8ULL,
		0xBB773AC7A35398D3ULL,
		0x7B8FFA581E00C518ULL,
		0x6AD5988688694159ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE80BC813E04567D8ULL,
			0xBB773AC7A35398D3ULL,
			0x7B8FFA581E00C518ULL,
			0x6AD5988688694159ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFA0DB6FD7F183288ULL,
			0x6E22C06803E3FFF3ULL,
			0x6C9E4B7478BF09A9ULL,
			0x40B15DFBFEA405AAULL}
		},
		.Z = {.key64 = {
			0x2EF56E13EA44BF5BULL,
			0x17974F5930185C06ULL,
			0x519E0BE53F07D372ULL,
			0x2FBF2611C16EEC80ULL}
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

	steps = 57;
	X1 = (curve25519_key_t){.key64 = {
		0x8BF79F1B36943750ULL,
		0x138FCAFDAA63E14CULL,
		0x9358A3E7458BED12ULL,
		0x612BC244731E0C81ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8BF79F1B36943750ULL,
			0x138FCAFDAA63E14CULL,
			0x9358A3E7458BED12ULL,
			0x612BC244731E0C81ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE1957878EEC0EE07ULL,
			0xEEB15815446A2604ULL,
			0x7AEFAF062EBC1033ULL,
			0x16B9857562EA79FBULL}
		},
		.Z = {.key64 = {
			0xFC0C9ADD472F1CCBULL,
			0x423DDDA3AECDB92EULL,
			0xE7E5CE9A4D52CC63ULL,
			0x10D3A06A0578F188ULL}
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

	steps = 48;
	X1 = (curve25519_key_t){.key64 = {
		0xEEFFE142FDEF1608ULL,
		0x35CEE42FE92F4426ULL,
		0x28ABEB6B232BF9EAULL,
		0x5DF849AC3964C63BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEEFFE142FDEF1608ULL,
			0x35CEE42FE92F4426ULL,
			0x28ABEB6B232BF9EAULL,
			0x5DF849AC3964C63BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x151461CAE3F86667ULL,
			0x6E5D2DDDB7D4144BULL,
			0xAC2B15211F58BE25ULL,
			0x51991A8CB85DD888ULL}
		},
		.Z = {.key64 = {
			0x1E15456DAD587EB8ULL,
			0x120DC42B1FBAC282ULL,
			0xA6F32439D9E1741CULL,
			0x24948B4B5A1A3286ULL}
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

	steps = 48;
	X1 = (curve25519_key_t){.key64 = {
		0x6E316BDC4C59F5B0ULL,
		0xB80608CF46841B99ULL,
		0x2410B00A2E42FB98ULL,
		0x4BA4167CA5EA4728ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6E316BDC4C59F5B0ULL,
			0xB80608CF46841B99ULL,
			0x2410B00A2E42FB98ULL,
			0x4BA4167CA5EA4728ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEC4E84FA080B345DULL,
			0x0F0E7F038ECF6D7AULL,
			0x40637B659FBCA76AULL,
			0x5BA98A805D5B83C6ULL}
		},
		.Z = {.key64 = {
			0x8D1421725F356B22ULL,
			0x0CB0B58CB35AE7D0ULL,
			0x15292A79867BBD80ULL,
			0x5C1C365D4EB8EF88ULL}
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

	steps = 59;
	X1 = (curve25519_key_t){.key64 = {
		0x6DD2652C25BAE270ULL,
		0x04D9AD2FBD92ADBDULL,
		0x1D21AF6294046564ULL,
		0x55C87FB283454804ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6DD2652C25BAE270ULL,
			0x04D9AD2FBD92ADBDULL,
			0x1D21AF6294046564ULL,
			0x55C87FB283454804ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7A7ACAB73E498E0FULL,
			0xA37B471AC2699A92ULL,
			0x807B11D5937512ECULL,
			0x514FA6451CC9BD1CULL}
		},
		.Z = {.key64 = {
			0xEED9B97B0CBFDD3FULL,
			0xE1CD326B3079E853ULL,
			0x2CEB8D14591BCC95ULL,
			0x1439D8E74ABB590AULL}
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

	steps = 59;
	X1 = (curve25519_key_t){.key64 = {
		0xA59DADDF60E974A0ULL,
		0x3F9245F18FADFEA6ULL,
		0x5CCAA4DE29AE6C7BULL,
		0x74BC182C7FDD3E62ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA59DADDF60E974A0ULL,
			0x3F9245F18FADFEA6ULL,
			0x5CCAA4DE29AE6C7BULL,
			0x74BC182C7FDD3E62ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2551A95904AB4674ULL,
			0x6158FEC8324132E5ULL,
			0x44DE7BADDA2EDFBFULL,
			0x41CBD746146B6578ULL}
		},
		.Z = {.key64 = {
			0xC2A9F1EAF4C590F0ULL,
			0x11FBC3A062774D2FULL,
			0x085E2836BB140251ULL,
			0x2F4956D39588761EULL}
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

	steps = 7;
	X1 = (curve25519_key_t){.key64 = {
		0x76544EABAC9BE1F0ULL,
		0xE8459E07FB8A2F2BULL,
		0x50E7AABAB193A6B8ULL,
		0x5C494B6003CF8E86ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x76544EABAC9BE1F0ULL,
			0xE8459E07FB8A2F2BULL,
			0x50E7AABAB193A6B8ULL,
			0x5C494B6003CF8E86ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFA84F690F9B1CD33ULL,
			0x8036A393B1006FFCULL,
			0x3729DF003072E90BULL,
			0x336B9D9847113300ULL}
		},
		.Z = {.key64 = {
			0xF72C06751A7AF75EULL,
			0x493E40FEB544A764ULL,
			0x7EADE6A86B13E898ULL,
			0x3E20FA6A987F9FF7ULL}
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

	steps = 24;
	X1 = (curve25519_key_t){.key64 = {
		0x053E5DEC52F77BB8ULL,
		0x2A244410F3CD3CDEULL,
		0x5F265120DE75CE4DULL,
		0x66F2B88DB2BBABC1ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x053E5DEC52F77BB8ULL,
			0x2A244410F3CD3CDEULL,
			0x5F265120DE75CE4DULL,
			0x66F2B88DB2BBABC1ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6553F19CECECF7B7ULL,
			0x44AB7BD681D30421ULL,
			0x3B2E76FAD60E4BC2ULL,
			0x67CC16ADC3CE6723ULL}
		},
		.Z = {.key64 = {
			0xA0B5047C0A632DB7ULL,
			0x2749AE40D690A572ULL,
			0x8ED32D4E837ED44BULL,
			0x7FB0A15006C8C95AULL}
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

	steps = 1;
	X1 = (curve25519_key_t){.key64 = {
		0xE0210CC0CF9A25D8ULL,
		0x662370B1D99F8CF6ULL,
		0x141C42F8B3ED348BULL,
		0x4DB30349DC77C0F6ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE0210CC0CF9A25D8ULL,
			0x662370B1D99F8CF6ULL,
			0x141C42F8B3ED348BULL,
			0x4DB30349DC77C0F6ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6E60B2F0361A6518ULL,
			0xCE5333A61D3A58D6ULL,
			0xA5EAE36314E2FB8DULL,
			0x74DA556C98AFB195ULL}
		},
		.Z = {.key64 = {
			0x808433033E689786ULL,
			0x988DC2C7667E33DBULL,
			0x50710BE2CFB4D22DULL,
			0x36CC0D2771DF03D8ULL}
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

	steps = 23;
	X1 = (curve25519_key_t){.key64 = {
		0x61A36F78806E2688ULL,
		0xAC685DAD895B0B9FULL,
		0xA58B54E3FD74806EULL,
		0x624D9CFB554A5A54ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x61A36F78806E2688ULL,
			0xAC685DAD895B0B9FULL,
			0xA58B54E3FD74806EULL,
			0x624D9CFB554A5A54ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC45755AEA5BA49C8ULL,
			0x27F76DB3DAD61C36ULL,
			0xD438E46111EE196CULL,
			0x1ACB48B1D0E751A4ULL}
		},
		.Z = {.key64 = {
			0x87D38333534FC198ULL,
			0x6240020791180EC7ULL,
			0xAD753401AFA3AE05ULL,
			0x0FC51C7BF839ABF6ULL}
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
		0x71360AD7E0956150ULL,
		0x0C1987AF597F4AD0ULL,
		0x147BA3D7451B3D46ULL,
		0x5687791391FC5576ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x71360AD7E0956150ULL,
			0x0C1987AF597F4AD0ULL,
			0x147BA3D7451B3D46ULL,
			0x5687791391FC5576ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x95C3A5BE9C22B5E1ULL,
			0x0FD5F9759E3FD760ULL,
			0xE82DD90248C0ADDDULL,
			0x54F2CC80CF6B9005ULL}
		},
		.Z = {.key64 = {
			0x350DFF0647D0676EULL,
			0x01E3DCF7613B4609ULL,
			0xDB7F32FD9308BAEEULL,
			0x70BB82E0B21561D5ULL}
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

	steps = 19;
	X1 = (curve25519_key_t){.key64 = {
		0x85E1DF3028AF5B40ULL,
		0x429C1888FF0FA376ULL,
		0xA26F155FDDE83E0AULL,
		0x7A577790C16AFE43ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x85E1DF3028AF5B40ULL,
			0x429C1888FF0FA376ULL,
			0xA26F155FDDE83E0AULL,
			0x7A577790C16AFE43ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x37FABFB93F878991ULL,
			0x70ABA87AFDC5B3BDULL,
			0x575C5CEFD549AAC4ULL,
			0x1310263291D07A00ULL}
		},
		.Z = {.key64 = {
			0x252F30597BB43283ULL,
			0xA3479A09414A1CFEULL,
			0xDA46629E600F4D2AULL,
			0x7FBBB29AE0A1C30CULL}
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

	steps = 25;
	X1 = (curve25519_key_t){.key64 = {
		0x05A2F37EC56DD600ULL,
		0x2B8605D912B99D12ULL,
		0xD1815ACAECD8A394ULL,
		0x7F1F66DA65E35A02ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x05A2F37EC56DD600ULL,
			0x2B8605D912B99D12ULL,
			0xD1815ACAECD8A394ULL,
			0x7F1F66DA65E35A02ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA6ACD28A0839058CULL,
			0x27CDD46EE931E7D0ULL,
			0xB6CC927BCC185434ULL,
			0x38C079871859B0DCULL}
		},
		.Z = {.key64 = {
			0x780571A896A9D9CDULL,
			0x93B35D79E10A735CULL,
			0x01FB127361B3CC40ULL,
			0x4318D5F13C378E2EULL}
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

	steps = 53;
	X1 = (curve25519_key_t){.key64 = {
		0x0E8BB75241A54780ULL,
		0x9ECA8A46728ADDD0ULL,
		0x68781C1EA8FC7456ULL,
		0x5EFAE76DA7A488B4ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0E8BB75241A54780ULL,
			0x9ECA8A46728ADDD0ULL,
			0x68781C1EA8FC7456ULL,
			0x5EFAE76DA7A488B4ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5E3C9A642167E10EULL,
			0xA7B835C19E355A87ULL,
			0x74A1333282FA2942ULL,
			0x11C2BA659C3D6651ULL}
		},
		.Z = {.key64 = {
			0x1537BF079AC41486ULL,
			0x304CAF6B7E5A17C5ULL,
			0x05CB4E1E591FF1F4ULL,
			0x7EDFFF5742C1CE57ULL}
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

	steps = 50;
	X1 = (curve25519_key_t){.key64 = {
		0x19D08B2262FF2C30ULL,
		0xEF649DCEF66D3654ULL,
		0xB7752E55C37EBCDFULL,
		0x53799B131B6E8C3EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x19D08B2262FF2C30ULL,
			0xEF649DCEF66D3654ULL,
			0xB7752E55C37EBCDFULL,
			0x53799B131B6E8C3EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9998615FA9CEE46CULL,
			0x69A28124A632ED5EULL,
			0xAE21AC9ED40F09D3ULL,
			0x0C5AAF5356FFAF38ULL}
		},
		.Z = {.key64 = {
			0xD5CCC99F71904139ULL,
			0xE19F09DC2B7CCBF1ULL,
			0x20FF9902972AB8D0ULL,
			0x2C79CC5E9372B43DULL}
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

	steps = 56;
	X1 = (curve25519_key_t){.key64 = {
		0xCD43592DBD3BCC20ULL,
		0xFC415780475B8EC3ULL,
		0x0363F24BDB551D5FULL,
		0x5C2E86B466413BAFULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCD43592DBD3BCC20ULL,
			0xFC415780475B8EC3ULL,
			0x0363F24BDB551D5FULL,
			0x5C2E86B466413BAFULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF22141AF10B2AAB7ULL,
			0xE7867719F8042202ULL,
			0x5AD13F2D11E3BC81ULL,
			0x2DDA49B73B3D3233ULL}
		},
		.Z = {.key64 = {
			0x690D23CA1CD60532ULL,
			0xBD2AE24CADA6C400ULL,
			0x33D1AEF36A938516ULL,
			0x1A376F1A1038E1FAULL}
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
		0x812FA977950BD8D0ULL,
		0xB0B38E825570D5B1ULL,
		0xB8EBE9242079D79AULL,
		0x62A925A622558D93ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x812FA977950BD8D0ULL,
			0xB0B38E825570D5B1ULL,
			0xB8EBE9242079D79AULL,
			0x62A925A622558D93ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB36ED89D0CFE92DDULL,
			0x77E4C8AD96BA3DBFULL,
			0x9523DE91166C4643ULL,
			0x0EA687A3B3887CB7ULL}
		},
		.Z = {.key64 = {
			0xF750EE5DA211E8FCULL,
			0xA0F8F20241E23BE9ULL,
			0xA29C28DEA8BA6EBCULL,
			0x769FEC57BEEAAD79ULL}
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

	steps = 14;
	X1 = (curve25519_key_t){.key64 = {
		0x9CB047CC30A88750ULL,
		0x8C0933019BEC0C56ULL,
		0x580EAE7E9BE0F020ULL,
		0x53BD7184E7B39BDEULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9CB047CC30A88750ULL,
			0x8C0933019BEC0C56ULL,
			0x580EAE7E9BE0F020ULL,
			0x53BD7184E7B39BDEULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFF1E0943BA134E42ULL,
			0x509CD012A32422F7ULL,
			0xBF988A96EA932BB2ULL,
			0x66523DF7603B82F7ULL}
		},
		.Z = {.key64 = {
			0x1D94D60AEB1B31DEULL,
			0x10AFA5602F275A27ULL,
			0x609C327062970E11ULL,
			0x3EF67CDDA8464933ULL}
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

	steps = 18;
	X1 = (curve25519_key_t){.key64 = {
		0x57F62276630A5698ULL,
		0x52E80BEA1C554569ULL,
		0x3160640D17416102ULL,
		0x5457FDB58A645F93ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x57F62276630A5698ULL,
			0x52E80BEA1C554569ULL,
			0x3160640D17416102ULL,
			0x5457FDB58A645F93ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDA1FB8A9509584C7ULL,
			0x1B07A57CC83B5735ULL,
			0x807F957D696BA60EULL,
			0x76524ECEB256C957ULL}
		},
		.Z = {.key64 = {
			0xE1798A273D31F3F1ULL,
			0x94AFD6CEF61CFF21ULL,
			0xBC2B74D0A115C2FCULL,
			0x1E1DD13061B5CB65ULL}
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

	steps = 10;
	X1 = (curve25519_key_t){.key64 = {
		0x9DEBA962E8DA0AE0ULL,
		0x7625C90FD64349E0ULL,
		0x30481C9B6A0103D1ULL,
		0x77C175280A1B0235ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9DEBA962E8DA0AE0ULL,
			0x7625C90FD64349E0ULL,
			0x30481C9B6A0103D1ULL,
			0x77C175280A1B0235ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF49C90CBAE3FB868ULL,
			0x010EA9CE76710BDAULL,
			0x2A651FDC77509BDFULL,
			0x78205327E4BD1322ULL}
		},
		.Z = {.key64 = {
			0x3743259E049CA418ULL,
			0x1DB23A1F9B7841E1ULL,
			0x209022FC4966340CULL,
			0x10C4C46E237FF93FULL}
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

	steps = 27;
	X1 = (curve25519_key_t){.key64 = {
		0xE91978E4D382AC18ULL,
		0xFF7AC2CB180719F9ULL,
		0x4BEA947CBB15688AULL,
		0x4233A91A0CE61F1BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE91978E4D382AC18ULL,
			0xFF7AC2CB180719F9ULL,
			0x4BEA947CBB15688AULL,
			0x4233A91A0CE61F1BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x63A13427682C01DDULL,
			0x1F0E507AC570B0EBULL,
			0xEBFF99FE86081A90ULL,
			0x6D114082AFCC5374ULL}
		},
		.Z = {.key64 = {
			0x5419157CDC3877D1ULL,
			0xADBC54896419724DULL,
			0x0CF9F6F55D0BC68CULL,
			0x0028533E0DE49E2EULL}
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

	steps = 55;
	X1 = (curve25519_key_t){.key64 = {
		0x04B119781A71EDC8ULL,
		0x6017C2D3599127B4ULL,
		0x183919D20020DD07ULL,
		0x5EB2B413E6E2D269ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x04B119781A71EDC8ULL,
			0x6017C2D3599127B4ULL,
			0x183919D20020DD07ULL,
			0x5EB2B413E6E2D269ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9B53D21DA21C775AULL,
			0x9D15B6521A756F1EULL,
			0x67D6C2BCCE5F358AULL,
			0x035446FECFA7AA33ULL}
		},
		.Z = {.key64 = {
			0x18178DCC69A1CE14ULL,
			0xCC9A8BA0C362B851ULL,
			0x42186EC3D241E202ULL,
			0x075B31528DF11FD3ULL}
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

	steps = 44;
	X1 = (curve25519_key_t){.key64 = {
		0xC20D9E3E0BCBC2C0ULL,
		0xA2ED630AC39A1A97ULL,
		0x0DAFD66BAA4B9D23ULL,
		0x49D88B618FD40450ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC20D9E3E0BCBC2C0ULL,
			0xA2ED630AC39A1A97ULL,
			0x0DAFD66BAA4B9D23ULL,
			0x49D88B618FD40450ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD64647ADC569AABDULL,
			0x88C92F739033CFC9ULL,
			0xBE91FD991BFDB0C6ULL,
			0x7C2CC7503FB2DF4DULL}
		},
		.Z = {.key64 = {
			0xF80359A8E311DCE0ULL,
			0xE1546A05261360C9ULL,
			0x3D75E8196845574AULL,
			0x7AD573285A636D09ULL}
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

	steps = 25;
	X1 = (curve25519_key_t){.key64 = {
		0x3E8D27871AAA3E10ULL,
		0xD007961EF0C9D5BCULL,
		0xD474AEE62A27AF40ULL,
		0x55C137C40B947B95ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3E8D27871AAA3E10ULL,
			0xD007961EF0C9D5BCULL,
			0xD474AEE62A27AF40ULL,
			0x55C137C40B947B95ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x37B7FAA3F430C9FFULL,
			0xB178CDEEA2BFC35BULL,
			0x96ED8D59387ACC09ULL,
			0x449E91136EC520CAULL}
		},
		.Z = {.key64 = {
			0xEF78E98714EE7F91ULL,
			0xF22FB3A04C81D011ULL,
			0x0183885E0D0572BBULL,
			0x3B6C44A7B0DE646EULL}
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

	steps = 49;
	X1 = (curve25519_key_t){.key64 = {
		0x560CCC2DA91EF2E0ULL,
		0x0A8A4783A975E63EULL,
		0xF5770DE9A607F13FULL,
		0x538565D9E2E7F5C0ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x560CCC2DA91EF2E0ULL,
			0x0A8A4783A975E63EULL,
			0xF5770DE9A607F13FULL,
			0x538565D9E2E7F5C0ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x10FB85759FB62BB8ULL,
			0x47CBB8E33CE28EADULL,
			0xD43953ED8032B6ADULL,
			0x205CE3DE71E57036ULL}
		},
		.Z = {.key64 = {
			0xE85773EECF813BB7ULL,
			0xC87413EDE62D8B7AULL,
			0x2A50CF43C8D5AF28ULL,
			0x08B58ADEA0C23395ULL}
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

	steps = 20;
	X1 = (curve25519_key_t){.key64 = {
		0x4E8E2C57BF9EF0B8ULL,
		0x76C667ACC2401F47ULL,
		0x43AB3E7EBA44CC23ULL,
		0x5974E5B36EBFFB75ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4E8E2C57BF9EF0B8ULL,
			0x76C667ACC2401F47ULL,
			0x43AB3E7EBA44CC23ULL,
			0x5974E5B36EBFFB75ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x55B745B668436810ULL,
			0x7B7660299F1BBC4BULL,
			0x587C8A09E43018C8ULL,
			0x68C02EDBBBDA6553ULL}
		},
		.Z = {.key64 = {
			0x9DC2FABD08052E81ULL,
			0xD4551C3877744B95ULL,
			0x104EF5493C71FB01ULL,
			0x4FC69897FAFC5191ULL}
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

	steps = 64;
	X1 = (curve25519_key_t){.key64 = {
		0x8D7D7FAB37516BA8ULL,
		0x790F1F17FC2691EFULL,
		0x7710E0AB3E817F5CULL,
		0x5A5F0ED360A2A035ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8D7D7FAB37516BA8ULL,
			0x790F1F17FC2691EFULL,
			0x7710E0AB3E817F5CULL,
			0x5A5F0ED360A2A035ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x790022A0B12D0FF9ULL,
			0xB49B692420BAB4AFULL,
			0x91AAD07E912D0946ULL,
			0x1FBAB40C4C4BCCAEULL}
		},
		.Z = {.key64 = {
			0xAC926A0ABFFD4816ULL,
			0x56139324D567E94AULL,
			0xA9B1481B6A6504DCULL,
			0x565087B0FEC29365ULL}
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

	steps = 15;
	X1 = (curve25519_key_t){.key64 = {
		0x433913AE82F17398ULL,
		0x5366B857A2C231D0ULL,
		0x79623EAE62D877FDULL,
		0x76FEF2E8E648B822ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x433913AE82F17398ULL,
			0x5366B857A2C231D0ULL,
			0x79623EAE62D877FDULL,
			0x76FEF2E8E648B822ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1B62A2E40EF10C9DULL,
			0xBBB787D6FC02DAE5ULL,
			0x425CFE9746C16A1CULL,
			0x7F1F15B2E269A081ULL}
		},
		.Z = {.key64 = {
			0xB822823521864640ULL,
			0xD956C19B5CEDCDC9ULL,
			0xE0D3E010FBB9B60BULL,
			0x58A4B65809989BACULL}
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

	steps = 21;
	X1 = (curve25519_key_t){.key64 = {
		0xD47D20F50B907E58ULL,
		0xD41A2F0D11033946ULL,
		0xDED5E009C24F77F9ULL,
		0x4054EA7D5BEE9AF7ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD47D20F50B907E58ULL,
			0xD41A2F0D11033946ULL,
			0xDED5E009C24F77F9ULL,
			0x4054EA7D5BEE9AF7ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x120B8B351863B308ULL,
			0xD913D4EF1C151A24ULL,
			0xBE81EF47F1400096ULL,
			0x300DABAE0B7C9222ULL}
		},
		.Z = {.key64 = {
			0xFE351ED364FB591AULL,
			0x4CCF8EEF2159E731ULL,
			0xAB9022367672C2F4ULL,
			0x50347A4017E5AD20ULL}
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

	steps = 20;
	X1 = (curve25519_key_t){.key64 = {
		0x78888F6644041830ULL,
		0xB041DE71709A47ABULL,
		0x28D6BD63B6B94872ULL,
		0x4227DB00EBA18078ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x78888F6644041830ULL,
			0xB041DE71709A47ABULL,
			0x28D6BD63B6B94872ULL,
			0x4227DB00EBA18078ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x46A6297C341FE479ULL,
			0xDA4195E8D99894B2ULL,
			0x731B5297C98CDE66ULL,
			0x215FEEDD6E200A67ULL}
		},
		.Z = {.key64 = {
			0x6ED52F01998F65E3ULL,
			0xC4362221E99F56B8ULL,
			0x2D081C9EE063A51DULL,
			0x7E37C6C8EF904BA9ULL}
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

	steps = 38;
	X1 = (curve25519_key_t){.key64 = {
		0x00AC4D9EA2F7B540ULL,
		0x95E420D0E2557931ULL,
		0x25A30C8856A7E1F8ULL,
		0x6E824E4261530B77ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x00AC4D9EA2F7B540ULL,
			0x95E420D0E2557931ULL,
			0x25A30C8856A7E1F8ULL,
			0x6E824E4261530B77ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD2B7101DE3D906E0ULL,
			0x449475849AB94C73ULL,
			0x495D32896C6A6BBDULL,
			0x558DA42AC4D2DB04ULL}
		},
		.Z = {.key64 = {
			0x698569F312505F56ULL,
			0x534ECA5E24BA53C6ULL,
			0x2A45CCFA489304FFULL,
			0x224D4CD4662BD7C0ULL}
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

	steps = 19;
	X1 = (curve25519_key_t){.key64 = {
		0xF3DEE38462363740ULL,
		0xDC2982BFED279189ULL,
		0x1BA22B6B702574C4ULL,
		0x5E78289562416658ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF3DEE38462363740ULL,
			0xDC2982BFED279189ULL,
			0x1BA22B6B702574C4ULL,
			0x5E78289562416658ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA6F739E394FDD0C9ULL,
			0x907684C9D72785B8ULL,
			0xC1E0BD1D0B5C4EC4ULL,
			0x670B4C4D3D17295FULL}
		},
		.Z = {.key64 = {
			0x411F19B1B4BE5953ULL,
			0x1C2827E9DF1C79A1ULL,
			0x47F461B5E6D40405ULL,
			0x48E6944DC38477AEULL}
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

	steps = 46;
	X1 = (curve25519_key_t){.key64 = {
		0x6DE44F5E86FC41F0ULL,
		0x38810A03355E1234ULL,
		0xE587BD9FAF1A0688ULL,
		0x7DB4870F4483EEEBULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6DE44F5E86FC41F0ULL,
			0x38810A03355E1234ULL,
			0xE587BD9FAF1A0688ULL,
			0x7DB4870F4483EEEBULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4D914A1246FB499BULL,
			0x832F36743592CEE4ULL,
			0x2FDD6EBB08678BACULL,
			0x19A305B8FA8C6BDDULL}
		},
		.Z = {.key64 = {
			0x148BDA6029F0E8C5ULL,
			0x28503EBEA3FCD703ULL,
			0xC7EB5220BA9C87EFULL,
			0x2E8950CE4E514C72ULL}
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

	steps = 51;
	X1 = (curve25519_key_t){.key64 = {
		0xE9CA1D97DE849098ULL,
		0xE60D3891234B7E4AULL,
		0x77C6E83DBAB2CC5CULL,
		0x5D6318265419122FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE9CA1D97DE849098ULL,
			0xE60D3891234B7E4AULL,
			0x77C6E83DBAB2CC5CULL,
			0x5D6318265419122FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBBA9EFB9A26BA327ULL,
			0x09A1F7D1648BBEE2ULL,
			0x65EDBB69290BC0F4ULL,
			0x30DA44C9C3D6E5E8ULL}
		},
		.Z = {.key64 = {
			0x021AA9AE7DA412A4ULL,
			0xD32581A67EDFD18FULL,
			0x65604B6C9737F2C9ULL,
			0x0619EB523B5EA957ULL}
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

	steps = 12;
	X1 = (curve25519_key_t){.key64 = {
		0x9AD8E3F973DC6F88ULL,
		0xCDA6959DDBFDDA1CULL,
		0x6D05DC50BA1C24A5ULL,
		0x6B0850B35AEB3137ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9AD8E3F973DC6F88ULL,
			0xCDA6959DDBFDDA1CULL,
			0x6D05DC50BA1C24A5ULL,
			0x6B0850B35AEB3137ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x20DDC04AE1EBA400ULL,
			0x681E2967E08A7D8BULL,
			0xB743B4E1CE5AD284ULL,
			0x3DF64D63B898396BULL}
		},
		.Z = {.key64 = {
			0x32BFB6C7CCB01626ULL,
			0x1F81C767068E3B7EULL,
			0xE19211C71FAE72CEULL,
			0x48D580134818A8B3ULL}
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

	steps = 38;
	X1 = (curve25519_key_t){.key64 = {
		0x2EECDEFE8124C4F0ULL,
		0x5A3117E266928451ULL,
		0x64238F01B9AF7ADDULL,
		0x7A346A02FFD91490ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2EECDEFE8124C4F0ULL,
			0x5A3117E266928451ULL,
			0x64238F01B9AF7ADDULL,
			0x7A346A02FFD91490ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4C8F81AF5DD5C6F8ULL,
			0xE8DE48F4C3462045ULL,
			0x3B894D3C8794ACC6ULL,
			0x58AD47CB49660B0AULL}
		},
		.Z = {.key64 = {
			0xA362477937ED71FAULL,
			0x1BD10A2160696547ULL,
			0xD7346835F6D01B0DULL,
			0x182B1AFCE976E465ULL}
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

	steps = 13;
	X1 = (curve25519_key_t){.key64 = {
		0x8B56B0DEA450BB98ULL,
		0xC3EF9D4591FB71BCULL,
		0xBBF5F8D4EE88E1F5ULL,
		0x6C40141C8C19AF64ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8B56B0DEA450BB98ULL,
			0xC3EF9D4591FB71BCULL,
			0xBBF5F8D4EE88E1F5ULL,
			0x6C40141C8C19AF64ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC45CBFC157345442ULL,
			0xC311760E57B17334ULL,
			0x7C6F085608E6AECCULL,
			0x622AD644AC55D852ULL}
		},
		.Z = {.key64 = {
			0x74B4A41CB7346F94ULL,
			0x9576C66A9D16CB6CULL,
			0x24BDA632155630FEULL,
			0x01786E9D9E95CEB5ULL}
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

	steps = 58;
	X1 = (curve25519_key_t){.key64 = {
		0x4922E5E6F3B24628ULL,
		0xD88096BBD772279EULL,
		0x2B447F196BB157F5ULL,
		0x7E3D28DE00D668DEULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4922E5E6F3B24628ULL,
			0xD88096BBD772279EULL,
			0x2B447F196BB157F5ULL,
			0x7E3D28DE00D668DEULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF77C54C2BCD1A341ULL,
			0x60BF63F003542BB2ULL,
			0x41F0C790F944CB41ULL,
			0x3C74FF420E544AE9ULL}
		},
		.Z = {.key64 = {
			0x108182FEA16F38A7ULL,
			0xDBD601037B79C580ULL,
			0xC9A1B96BCC23D4A7ULL,
			0x767D7C35897B0669ULL}
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

	steps = 50;
	X1 = (curve25519_key_t){.key64 = {
		0x52FEB0E150F848C0ULL,
		0xB3E4FB1150B5A5B4ULL,
		0x56E739A753E66881ULL,
		0x7FD4190D766F82C8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x52FEB0E150F848C0ULL,
			0xB3E4FB1150B5A5B4ULL,
			0x56E739A753E66881ULL,
			0x7FD4190D766F82C8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8BCAE39B6883DDF4ULL,
			0xE0CEDA337D247212ULL,
			0x5A0BFF3C1751A61EULL,
			0x45CA266BBD17BA75ULL}
		},
		.Z = {.key64 = {
			0x1A2515AD09BD3E8BULL,
			0x7E3539095A795AF9ULL,
			0x623776A6150321A7ULL,
			0x4DC79A288266C10BULL}
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

	steps = 21;
	X1 = (curve25519_key_t){.key64 = {
		0xB1E50B0016E96498ULL,
		0xA6095309B6D42493ULL,
		0x05AC2DBEDB59D263ULL,
		0x6C0B1D62DF4B8CB3ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB1E50B0016E96498ULL,
			0xA6095309B6D42493ULL,
			0x05AC2DBEDB59D263ULL,
			0x6C0B1D62DF4B8CB3ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3A087EE622531895ULL,
			0x1491EC20B818B020ULL,
			0x342600911B6B863AULL,
			0x539DD56D0222006AULL}
		},
		.Z = {.key64 = {
			0xEA643C232E178C71ULL,
			0x25335F0A860FB052ULL,
			0x3CC0C2BF5A1902B4ULL,
			0x710B174E410AF62DULL}
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

	steps = 47;
	X1 = (curve25519_key_t){.key64 = {
		0xC7D8E6D8DD6BC120ULL,
		0xC6F80DBF758680BBULL,
		0x3D99E5A9AA799CFAULL,
		0x6E92CCCC8D0914C4ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC7D8E6D8DD6BC120ULL,
			0xC6F80DBF758680BBULL,
			0x3D99E5A9AA799CFAULL,
			0x6E92CCCC8D0914C4ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x489883939C5EB8E1ULL,
			0x16CDFB45F4FBB7A0ULL,
			0x8DF4FBD277415690ULL,
			0x726AB1802C27BAEDULL}
		},
		.Z = {.key64 = {
			0xCC4570EEBAD0B9FCULL,
			0xBFF7452091AFF30AULL,
			0x8A4006528D0CC697ULL,
			0x5AF4D6B3BF7B89E7ULL}
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

	steps = 7;
	X1 = (curve25519_key_t){.key64 = {
		0x7676D0967E26FE68ULL,
		0x38FF7AC4DE75EEA3ULL,
		0x0D99A639F0E7BA56ULL,
		0x7469A52354B3BD72ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7676D0967E26FE68ULL,
			0x38FF7AC4DE75EEA3ULL,
			0x0D99A639F0E7BA56ULL,
			0x7469A52354B3BD72ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFD5EA93BEDB01CB1ULL,
			0x6EA72A61D95CB008ULL,
			0x3FDCE468F3AAF646ULL,
			0x2806AA5F1763E3E0ULL}
		},
		.Z = {.key64 = {
			0x9B580198E75CC257ULL,
			0xAB2E85C51DE07E0EULL,
			0x353A1FF204FAD319ULL,
			0x0913F48215F01ACAULL}
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

	steps = 50;
	X1 = (curve25519_key_t){.key64 = {
		0xB2B18BD53F22E640ULL,
		0x1C561D6848497A9FULL,
		0x0BBF72FF62E898A2ULL,
		0x5C38690E67B100A0ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB2B18BD53F22E640ULL,
			0x1C561D6848497A9FULL,
			0x0BBF72FF62E898A2ULL,
			0x5C38690E67B100A0ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x57C01463AAD9F723ULL,
			0x448B752B566F5AC9ULL,
			0xF92F5D25E88B36E3ULL,
			0x521D6B63D945D4BDULL}
		},
		.Z = {.key64 = {
			0x62E8C43D2E0513A1ULL,
			0x4B72F5B48A946586ULL,
			0x8E2A649D6997F6D5ULL,
			0x3D00633F5B24B7A1ULL}
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

	steps = 11;
	X1 = (curve25519_key_t){.key64 = {
		0xF4CEA18C3BC79818ULL,
		0x1A8BC0710C7474A9ULL,
		0x46E673BCF20C35E8ULL,
		0x6C619D8FA2BAC27BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF4CEA18C3BC79818ULL,
			0x1A8BC0710C7474A9ULL,
			0x46E673BCF20C35E8ULL,
			0x6C619D8FA2BAC27BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC003D38754DA1F93ULL,
			0x57CEA57378CB95FFULL,
			0x4590629BD9FBA909ULL,
			0x032420FE6AFD0E7DULL}
		},
		.Z = {.key64 = {
			0x79047F1C8E733F93ULL,
			0xDCBFA765C6A977F0ULL,
			0xEAC8C99F54EE629EULL,
			0x0766882FAF3FE544ULL}
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

	steps = 43;
	X1 = (curve25519_key_t){.key64 = {
		0xA04964BE334713C8ULL,
		0x25243D5E8616C2CFULL,
		0x325814F03183F53AULL,
		0x6A9FE5A4F00EFDF8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA04964BE334713C8ULL,
			0x25243D5E8616C2CFULL,
			0x325814F03183F53AULL,
			0x6A9FE5A4F00EFDF8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDF90551837EC4DA7ULL,
			0x99856C1D5FAC1FE4ULL,
			0x6AEEEE9F44E3A7D2ULL,
			0x2840B14A37D9BBF8ULL}
		},
		.Z = {.key64 = {
			0x7CDA9A68DB9D7B60ULL,
			0x53BEC6035B2EB977ULL,
			0x63B879441ABE00B5ULL,
			0x7C5DD867F9BEACF7ULL}
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
		0xDBA59C00E0CF72D8ULL,
		0x7D0AC7FE0BA07C16ULL,
		0x92DC96E2CF3E4C68ULL,
		0x6F0BA857B434659FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDBA59C00E0CF72D8ULL,
			0x7D0AC7FE0BA07C16ULL,
			0x92DC96E2CF3E4C68ULL,
			0x6F0BA857B434659FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6B8F9DB66E018039ULL,
			0x47FC011ECC02ACAAULL,
			0x00FE6CF7639D9F8EULL,
			0x01D3D91955FFC2A9ULL}
		},
		.Z = {.key64 = {
			0xB111A90B35842773ULL,
			0xE92C26BF916694D5ULL,
			0xAF1439B29603B755ULL,
			0x6F296DC4F3315CF9ULL}
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

	steps = 21;
	X1 = (curve25519_key_t){.key64 = {
		0x820B2BF9F9DCDD10ULL,
		0xC010245D72DA437FULL,
		0xF7C1550A46DD5876ULL,
		0x69C01289B4B8DF6EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x820B2BF9F9DCDD10ULL,
			0xC010245D72DA437FULL,
			0xF7C1550A46DD5876ULL,
			0x69C01289B4B8DF6EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x91F5DC3FB09F81C3ULL,
			0x719FD29328BD6669ULL,
			0x935D068C5EB7F67AULL,
			0x175488ACC5006D4DULL}
		},
		.Z = {.key64 = {
			0xE1A77B87EEE5C00CULL,
			0x0E444F64A8F78902ULL,
			0x1ED6E8FAABE0490DULL,
			0x403D5954A6EB2B9BULL}
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

	steps = 24;
	X1 = (curve25519_key_t){.key64 = {
		0x027C8B7E4315B980ULL,
		0x69C152D85F5F4F18ULL,
		0xF398516ACF8B1A90ULL,
		0x43DA75815723B2B8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x027C8B7E4315B980ULL,
			0x69C152D85F5F4F18ULL,
			0xF398516ACF8B1A90ULL,
			0x43DA75815723B2B8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x44655A2F24A00EAAULL,
			0x60FC9DF2E44FA915ULL,
			0xFA43B3C0CBB200CDULL,
			0x464D786AF16B7460ULL}
		},
		.Z = {.key64 = {
			0xA25B15610ADAC939ULL,
			0xDAD9457DEFD5D61CULL,
			0xB5CB880A64CDFADAULL,
			0x378BA7E049E7F30CULL}
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

	steps = 11;
	X1 = (curve25519_key_t){.key64 = {
		0xFE9255D084EE8840ULL,
		0x49D8F6CE683CBC07ULL,
		0xB1C7519ADA17A2AEULL,
		0x715DF8FD1136E4D5ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFE9255D084EE8840ULL,
			0x49D8F6CE683CBC07ULL,
			0xB1C7519ADA17A2AEULL,
			0x715DF8FD1136E4D5ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAFAABD8CEC064397ULL,
			0x035411A52414DFABULL,
			0x34E60A5F21C40699ULL,
			0x47A984C9A96A9A64ULL}
		},
		.Z = {.key64 = {
			0xC710886893F76725ULL,
			0xF0802E9BA4987EE6ULL,
			0xD1C278CCB0024AA2ULL,
			0x0316197A8E38E55EULL}
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

	steps = 5;
	X1 = (curve25519_key_t){.key64 = {
		0x58BA9CE9ADCF66B8ULL,
		0xCE8DD30BAC52167BULL,
		0x33542DF694A09173ULL,
		0x768648A9444F19F3ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x58BA9CE9ADCF66B8ULL,
			0xCE8DD30BAC52167BULL,
			0x33542DF694A09173ULL,
			0x768648A9444F19F3ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x281B343AD4DCC2C0ULL,
			0x8606DE8442888871ULL,
			0x704900246A70C047ULL,
			0x42DF63810F0536B9ULL}
		},
		.Z = {.key64 = {
			0xA4C7AACAD7A43C86ULL,
			0xBD57A9303B0EB3CFULL,
			0x065D8A348B81113EULL,
			0x01022FA14C5A652AULL}
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

	steps = 38;
	X1 = (curve25519_key_t){.key64 = {
		0xC9F8116668CEB068ULL,
		0xECC73CBF75839C99ULL,
		0x8FA3A23015AACE2EULL,
		0x7C8F18A31FCBD854ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC9F8116668CEB068ULL,
			0xECC73CBF75839C99ULL,
			0x8FA3A23015AACE2EULL,
			0x7C8F18A31FCBD854ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3E9804467EBE925EULL,
			0x20F50E8013A8E4A3ULL,
			0xD5400E303F68537CULL,
			0x7541A121373BB544ULL}
		},
		.Z = {.key64 = {
			0x499700A0F14559CAULL,
			0xF86B849F8A71D211ULL,
			0xFAC80A7D3A4AE2B0ULL,
			0x2BADD0924662DE7FULL}
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

	steps = 42;
	X1 = (curve25519_key_t){.key64 = {
		0x7EF1379C95AA0000ULL,
		0x09DAD39E981C06C6ULL,
		0x86223B9C5AC38B69ULL,
		0x793F6A91B4E15A6EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7EF1379C95AA0000ULL,
			0x09DAD39E981C06C6ULL,
			0x86223B9C5AC38B69ULL,
			0x793F6A91B4E15A6EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0EE51723931E3951ULL,
			0x14F58C335A5E2DA1ULL,
			0x28EAF935923EF407ULL,
			0x406552D30252C0BEULL}
		},
		.Z = {.key64 = {
			0x9C3DFF148251AA97ULL,
			0xB4E9D5B99870DA63ULL,
			0x3A51EC768A504DA8ULL,
			0x643F6E9B08458C84ULL}
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

	steps = 17;
	X1 = (curve25519_key_t){.key64 = {
		0x1D4C749FB02A5950ULL,
		0x3D94D8B7EC843CC1ULL,
		0x078BE92DC6AE51C8ULL,
		0x72EFFEAF16FF7108ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1D4C749FB02A5950ULL,
			0x3D94D8B7EC843CC1ULL,
			0x078BE92DC6AE51C8ULL,
			0x72EFFEAF16FF7108ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFA05943BFE534EB3ULL,
			0x1D9EB84AEC1FDD60ULL,
			0x9E57E8A5E3EED9ACULL,
			0x1F9F88CD57BE205EULL}
		},
		.Z = {.key64 = {
			0x98D88C461EC0D265ULL,
			0x7E96CDC4EB4016C2ULL,
			0x843A98243831B345ULL,
			0x6F598EE519917490ULL}
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

	steps = 27;
	X1 = (curve25519_key_t){.key64 = {
		0xBC1E9F5B48F01C98ULL,
		0x81A43F15BDAB4955ULL,
		0x461663894E8B278FULL,
		0x5CBBFD285187E500ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBC1E9F5B48F01C98ULL,
			0x81A43F15BDAB4955ULL,
			0x461663894E8B278FULL,
			0x5CBBFD285187E500ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0CD0A06EEE08E1C3ULL,
			0x8BD922563FDED019ULL,
			0x22730D5C74878B08ULL,
			0x0B622F2DABFF5366ULL}
		},
		.Z = {.key64 = {
			0x34929F035F04B311ULL,
			0x2C561E21129AA5F0ULL,
			0x504688496BB652CCULL,
			0x4ECAAC5A411CC369ULL}
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

	steps = 7;
	X1 = (curve25519_key_t){.key64 = {
		0xDA10CA9DD86FA660ULL,
		0x4CF017477DEE6051ULL,
		0xEC8A892E16FD3DFEULL,
		0x569AE02DD8B11913ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDA10CA9DD86FA660ULL,
			0x4CF017477DEE6051ULL,
			0xEC8A892E16FD3DFEULL,
			0x569AE02DD8B11913ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC72A9B12E282EA0EULL,
			0x1562B39C128545FEULL,
			0x74EC18E71ABE013FULL,
			0x746065A24AF5BD1CULL}
		},
		.Z = {.key64 = {
			0xD69C09900EDA0682ULL,
			0xD60BB4DAD79E6D29ULL,
			0x05F3CED467E791C7ULL,
			0x79C0557B47C4B8A7ULL}
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

	steps = 44;
	X1 = (curve25519_key_t){.key64 = {
		0xC6A9A1B69FDEA980ULL,
		0xD1F75A9B684604E9ULL,
		0xCAC760FCB587BEFEULL,
		0x7E6B9BCEA1420967ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC6A9A1B69FDEA980ULL,
			0xD1F75A9B684604E9ULL,
			0xCAC760FCB587BEFEULL,
			0x7E6B9BCEA1420967ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x999FB0F15A681A64ULL,
			0xFA46B62A7D1D3F1CULL,
			0x78011F512B6C1900ULL,
			0x509D4E9F6995713FULL}
		},
		.Z = {.key64 = {
			0xF4B46301857D0711ULL,
			0x9616DA92FA90A3EDULL,
			0xFA0330FC5C35C7C9ULL,
			0x21D658FC62F9F9C3ULL}
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

	steps = 62;
	X1 = (curve25519_key_t){.key64 = {
		0x68F448BC0D712758ULL,
		0x50F9023FE2AC8E55ULL,
		0x0466082E4DEE34ECULL,
		0x4706A5A6C920F2CBULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x68F448BC0D712758ULL,
			0x50F9023FE2AC8E55ULL,
			0x0466082E4DEE34ECULL,
			0x4706A5A6C920F2CBULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7D9155D5A89C20D0ULL,
			0x92D2AF0A9FF87275ULL,
			0x39E53A303967E727ULL,
			0x778E6759195E9F1CULL}
		},
		.Z = {.key64 = {
			0x8E91CCB4127B5D95ULL,
			0xAF5E41669FFE5277ULL,
			0x6E829692A112455EULL,
			0x16322D374463C4E5ULL}
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

	steps = 15;
	X1 = (curve25519_key_t){.key64 = {
		0x3FC33D282F6581E8ULL,
		0x9EAAFB9847D3A522ULL,
		0xFEB44FBC864ACC6AULL,
		0x41B19CA3930BE833ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3FC33D282F6581E8ULL,
			0x9EAAFB9847D3A522ULL,
			0xFEB44FBC864ACC6AULL,
			0x41B19CA3930BE833ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2702692B7C3787B3ULL,
			0x76FE0BAB62076DB0ULL,
			0x67CA286B70ECEFF3ULL,
			0x2CF5A6D1B9366DD6ULL}
		},
		.Z = {.key64 = {
			0x28E2195EDB96B108ULL,
			0x0B8875B82F7C5E33ULL,
			0xC7D9B9DB2AB41EEAULL,
			0x33DD06FCE0767F11ULL}
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

	steps = 18;
	X1 = (curve25519_key_t){.key64 = {
		0x75725188750D02D8ULL,
		0x5EE2423C97D800C9ULL,
		0x1E9E57AB25691C7EULL,
		0x6DBA961F2487C4C3ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x75725188750D02D8ULL,
			0x5EE2423C97D800C9ULL,
			0x1E9E57AB25691C7EULL,
			0x6DBA961F2487C4C3ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x18C29C58B031F9EDULL,
			0x00A4E652648C8C5DULL,
			0x5FDE4BBC5A699600ULL,
			0x6125A840CD1EC416ULL}
		},
		.Z = {.key64 = {
			0x847C6D62DFBE3523ULL,
			0xFB762E51522EB144ULL,
			0xBEAE613DBF5A81B6ULL,
			0x331E9626099B49BFULL}
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

	steps = 44;
	X1 = (curve25519_key_t){.key64 = {
		0xDBF57EDFC1EF24A8ULL,
		0x4920CFBAE24A2119ULL,
		0x3FE01AFA0AF570BDULL,
		0x6285C7229F43A7B2ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDBF57EDFC1EF24A8ULL,
			0x4920CFBAE24A2119ULL,
			0x3FE01AFA0AF570BDULL,
			0x6285C7229F43A7B2ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0D020DB485556BB0ULL,
			0x5FB508C07B02A565ULL,
			0x2B7F758078355CE4ULL,
			0x38A3E470455EDC4BULL}
		},
		.Z = {.key64 = {
			0x451E4B94AE87D9E8ULL,
			0xAE0C7892AAD0AE14ULL,
			0x828919720909AC80ULL,
			0x24E950FE17D80521ULL}
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

	steps = 13;
	X1 = (curve25519_key_t){.key64 = {
		0x97AAED9B4E629040ULL,
		0x4BFAE2852CC54D4DULL,
		0x65D146D917198952ULL,
		0x6BEDB356E884C8DDULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x97AAED9B4E629040ULL,
			0x4BFAE2852CC54D4DULL,
			0x65D146D917198952ULL,
			0x6BEDB356E884C8DDULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x25C9021354FC7283ULL,
			0x29C8BB3E55C2DAA9ULL,
			0x7C645B3FDE6BB005ULL,
			0x6A6179580A385C1CULL}
		},
		.Z = {.key64 = {
			0x3151B8B8289FA941ULL,
			0x22E6033B6F70096CULL,
			0xB4B7EC082231B489ULL,
			0x671E2ED26B7AB427ULL}
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

	steps = 25;
	X1 = (curve25519_key_t){.key64 = {
		0xBC2788F284E1CD30ULL,
		0x69B3C87DCC4443A6ULL,
		0x46D935A918F784E3ULL,
		0x48345F31B93748DDULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBC2788F284E1CD30ULL,
			0x69B3C87DCC4443A6ULL,
			0x46D935A918F784E3ULL,
			0x48345F31B93748DDULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC484340A9F8AF150ULL,
			0x4B34937CCE945CABULL,
			0xB1A539FFB9A4EF58ULL,
			0x4CB27FC87DBA64A1ULL}
		},
		.Z = {.key64 = {
			0xF4C7840B07AA9F6BULL,
			0x2FB400D1155BC3B8ULL,
			0x0C516D55E5A00E52ULL,
			0x03C57DBE0F648C9CULL}
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

	steps = 44;
	X1 = (curve25519_key_t){.key64 = {
		0xACE307A415F3CFD8ULL,
		0xE8AA0AEE1F444171ULL,
		0x8F6ADD18DA1B6869ULL,
		0x42AEBC8B0AAC130DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xACE307A415F3CFD8ULL,
			0xE8AA0AEE1F444171ULL,
			0x8F6ADD18DA1B6869ULL,
			0x42AEBC8B0AAC130DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBB118FFCA03E0414ULL,
			0x305FEB6EE8F66360ULL,
			0xE1629CA048B55AC2ULL,
			0x7E48E788150777EBULL}
		},
		.Z = {.key64 = {
			0xE550E60CFA944489ULL,
			0x1D99735F283D46C9ULL,
			0x9254605751303C84ULL,
			0x65A49974467E9329ULL}
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

	steps = 50;
	X1 = (curve25519_key_t){.key64 = {
		0x3B29E82A2D25E490ULL,
		0x60BEA948B53BA5C7ULL,
		0x71A93F9E3410B7F0ULL,
		0x4986637F27E1CE40ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3B29E82A2D25E490ULL,
			0x60BEA948B53BA5C7ULL,
			0x71A93F9E3410B7F0ULL,
			0x4986637F27E1CE40ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0EC3363EFC93C296ULL,
			0xA25ED88743BBF560ULL,
			0x2D927BE7160ABDF5ULL,
			0x2DBF2C50CBC6FBB7ULL}
		},
		.Z = {.key64 = {
			0x638650985893D514ULL,
			0x8592156A7F0EEF15ULL,
			0xF76F9D7AB79DEC0FULL,
			0x6A1E6B4DB9C96EE2ULL}
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

	steps = 64;
	X1 = (curve25519_key_t){.key64 = {
		0x2A149227510B4530ULL,
		0x3BFAA4A5C8BD97A0ULL,
		0x46D53FFBBDF7C6C0ULL,
		0x793443A65F185A50ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2A149227510B4530ULL,
			0x3BFAA4A5C8BD97A0ULL,
			0x46D53FFBBDF7C6C0ULL,
			0x793443A65F185A50ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4C94AF2BB876A3F3ULL,
			0xC82BD3814DBB73ABULL,
			0x9C6D7D52FD07CA3AULL,
			0x6AF16D3418B4C18FULL}
		},
		.Z = {.key64 = {
			0xC1064E59E7B01F57ULL,
			0xB047DBF7E4199448ULL,
			0x028A73CF99C922DBULL,
			0x2C9C7348FBA92167ULL}
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

	steps = 18;
	X1 = (curve25519_key_t){.key64 = {
		0x641C5151FA5089A0ULL,
		0xFF4639975C9C449EULL,
		0x2C49B99F1246B2BFULL,
		0x6B2A9D93E224576EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x641C5151FA5089A0ULL,
			0xFF4639975C9C449EULL,
			0x2C49B99F1246B2BFULL,
			0x6B2A9D93E224576EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA90A4EC599DABE70ULL,
			0x7817CA9082843222ULL,
			0xF3E64E8F14C9DD40ULL,
			0x13064E763922FE3EULL}
		},
		.Z = {.key64 = {
			0x30DE1D4659782174ULL,
			0x066F4FA89528C9BCULL,
			0x45198FE865C08397ULL,
			0x016B3080755EEB96ULL}
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

	steps = 52;
	X1 = (curve25519_key_t){.key64 = {
		0xCE3E101AFACBF3E0ULL,
		0x87A316C1C073125BULL,
		0x83FD5A538277ED4DULL,
		0x413B8FC06F85B0B9ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCE3E101AFACBF3E0ULL,
			0x87A316C1C073125BULL,
			0x83FD5A538277ED4DULL,
			0x413B8FC06F85B0B9ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x37C7675F2B725DBDULL,
			0x287FB492533DBC30ULL,
			0xADC1F83E935112F2ULL,
			0x691340A69974F1A9ULL}
		},
		.Z = {.key64 = {
			0x27EE8B45C7C28B4CULL,
			0xEBC3D413B80B766BULL,
			0xEFAD6305A2378CF2ULL,
			0x0FBEF8021496B53AULL}
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

	steps = 63;
	X1 = (curve25519_key_t){.key64 = {
		0xFC5BE749F6C43698ULL,
		0xBDCDD6639FD98C07ULL,
		0xB9F2CF713B1B21A8ULL,
		0x7A1FC00F42CBDF72ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFC5BE749F6C43698ULL,
			0xBDCDD6639FD98C07ULL,
			0xB9F2CF713B1B21A8ULL,
			0x7A1FC00F42CBDF72ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6EE267162EF2C1C3ULL,
			0xCB3A224419E10C7FULL,
			0x11C0108726E14F06ULL,
			0x2CC4F1FCC393DA42ULL}
		},
		.Z = {.key64 = {
			0xE6FF4D2C0D7864F8ULL,
			0xD3ED40656C863327ULL,
			0xCD43238B6586B958ULL,
			0x1C9E160D1A98F13EULL}
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

	steps = 13;
	X1 = (curve25519_key_t){.key64 = {
		0x9EE24E522AAC50B0ULL,
		0x4304A056CF5314D7ULL,
		0x49BA6E7AB2629464ULL,
		0x74AE54F1DA0A4DA9ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9EE24E522AAC50B0ULL,
			0x4304A056CF5314D7ULL,
			0x49BA6E7AB2629464ULL,
			0x74AE54F1DA0A4DA9ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEDDBAF3F895C5F53ULL,
			0x057EB50E086DB5F6ULL,
			0x61295AAA66BF37BAULL,
			0x07E312B4211275A0ULL}
		},
		.Z = {.key64 = {
			0x26CFABC85E0C1D97ULL,
			0xD3EDF32014671C02ULL,
			0x5634A1D5259BE4B1ULL,
			0x6C996670461DD90FULL}
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

	steps = 9;
	X1 = (curve25519_key_t){.key64 = {
		0x4375AF1FC96617A0ULL,
		0xD94F6D450D3B986CULL,
		0x4DC10BAE457BDFE2ULL,
		0x4847D6CEE63EABFDULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4375AF1FC96617A0ULL,
			0xD94F6D450D3B986CULL,
			0x4DC10BAE457BDFE2ULL,
			0x4847D6CEE63EABFDULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xABD95F4FD444CEBCULL,
			0x729768EB6B0B5E02ULL,
			0x884BA8B255C5DFB2ULL,
			0x3160CC4EACB9EA54ULL}
		},
		.Z = {.key64 = {
			0xCCC9119132648F87ULL,
			0xD33C08B21E7FB0D2ULL,
			0xF75C40F770397449ULL,
			0x029F4B32BAEFFBA0ULL}
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

	steps = 11;
	X1 = (curve25519_key_t){.key64 = {
		0xAD83048D38152490ULL,
		0x5BFDBDCEAA2F382AULL,
		0x33047DD3084DAFB8ULL,
		0x4B48DB7BEF02217AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAD83048D38152490ULL,
			0x5BFDBDCEAA2F382AULL,
			0x33047DD3084DAFB8ULL,
			0x4B48DB7BEF02217AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x363DE3F7CE171D5DULL,
			0x14C5A8138D28F41EULL,
			0x81C3D975BEBA4CB8ULL,
			0x307A0E5B8A930443ULL}
		},
		.Z = {.key64 = {
			0x66227761357B6CD6ULL,
			0xCDF609FBCC149CAEULL,
			0xC75C80BDB1634EAAULL,
			0x3AA1B146DA0A82D6ULL}
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

	steps = 55;
	X1 = (curve25519_key_t){.key64 = {
		0xD7384187A2621218ULL,
		0x3C105F8B459D0A57ULL,
		0x2F650D5141118E7DULL,
		0x49841F6530BDE34CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD7384187A2621218ULL,
			0x3C105F8B459D0A57ULL,
			0x2F650D5141118E7DULL,
			0x49841F6530BDE34CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x78226F2B6FFE7E79ULL,
			0xE4F87A5C8165DEDAULL,
			0xAB1E86D5A9872B26ULL,
			0x76978003677CB2C4ULL}
		},
		.Z = {.key64 = {
			0xB82EC98B79778A19ULL,
			0xCACB587F315B8C79ULL,
			0x08AC32A9E46CC597ULL,
			0x44B00C4CE4A2E84FULL}
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
		0x2C02CE2A4E4D7D90ULL,
		0x95EA3146DBC9B60DULL,
		0x2CC8C24EF6B85F0FULL,
		0x50AB75C4F3236FF0ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2C02CE2A4E4D7D90ULL,
			0x95EA3146DBC9B60DULL,
			0x2CC8C24EF6B85F0FULL,
			0x50AB75C4F3236FF0ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x363BCAA566C54361ULL,
			0x00122C5E415E3ACCULL,
			0x1EF72BDDD9782D50ULL,
			0x268E551D979E7F87ULL}
		},
		.Z = {.key64 = {
			0x500CE3F8EBF0878CULL,
			0x42351B836689348EULL,
			0x1D965D88034B15C3ULL,
			0x48AC161BA519167DULL}
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

	steps = 29;
	X1 = (curve25519_key_t){.key64 = {
		0x58A75DE5ACEE4FF8ULL,
		0xCBAD3306C85BAEF9ULL,
		0x5007A3B62F1E676AULL,
		0x603053B6BAE894CFULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x58A75DE5ACEE4FF8ULL,
			0xCBAD3306C85BAEF9ULL,
			0x5007A3B62F1E676AULL,
			0x603053B6BAE894CFULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB7CA629A1AFC66F2ULL,
			0xCD65906371A127EBULL,
			0x0D69C5D5CD32240CULL,
			0x1EAC767F057846CEULL}
		},
		.Z = {.key64 = {
			0x65E6FC08CD8E5C8BULL,
			0xA2E9101A9434BE0BULL,
			0x70363F51663D6B39ULL,
			0x519B5C419059ABDFULL}
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

	steps = 26;
	X1 = (curve25519_key_t){.key64 = {
		0x0CA8A40A74BDED78ULL,
		0x79F5B5875E6690FAULL,
		0x3626FE803079D92CULL,
		0x52576DF2E5D01496ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0CA8A40A74BDED78ULL,
			0x79F5B5875E6690FAULL,
			0x3626FE803079D92CULL,
			0x52576DF2E5D01496ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA505AEC97FC84CC1ULL,
			0xB6DC744512DFD20AULL,
			0xBF930616D6D2D059ULL,
			0x4672CD62F59A5D7BULL}
		},
		.Z = {.key64 = {
			0x4CC1126EC8D78274ULL,
			0x914FFF93EBA39C02ULL,
			0xA29C9B3DA68E5A1FULL,
			0x3A551FE694BBE642ULL}
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

	steps = 16;
	X1 = (curve25519_key_t){.key64 = {
		0x3F01598712ABD3F0ULL,
		0x902DD7D1403B1C50ULL,
		0x5D1DDC7E28C384AFULL,
		0x73B70D29022A90F8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3F01598712ABD3F0ULL,
			0x902DD7D1403B1C50ULL,
			0x5D1DDC7E28C384AFULL,
			0x73B70D29022A90F8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3AD9F5D3FAB98E7BULL,
			0x9A96AA2051947F75ULL,
			0xDC3DE9632A6F9DB0ULL,
			0x3DFEA95E9E3B840BULL}
		},
		.Z = {.key64 = {
			0xFE730076893005C0ULL,
			0xD2FE73AA41A6BABEULL,
			0xDF26C6F7A679C328ULL,
			0x1016FD38F730138DULL}
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

	steps = 17;
	X1 = (curve25519_key_t){.key64 = {
		0xA48BDCC1A0161F08ULL,
		0xA7EBDF246AB6E9F0ULL,
		0x366C6FF171F5C54AULL,
		0x7BF300D84E027D4DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA48BDCC1A0161F08ULL,
			0xA7EBDF246AB6E9F0ULL,
			0x366C6FF171F5C54AULL,
			0x7BF300D84E027D4DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA26DB4824FA14BC0ULL,
			0x3F27BF3534B1E85BULL,
			0x6E88E16450D08703ULL,
			0x2DD1CEDE1CB884F1ULL}
		},
		.Z = {.key64 = {
			0x2C46ED9A4B3F23BDULL,
			0x3E029363DC4A8A4FULL,
			0xF037B355A35D1ACBULL,
			0x0E58682B56477ADEULL}
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

	steps = 61;
	X1 = (curve25519_key_t){.key64 = {
		0xBBCBB753C388C438ULL,
		0x5BF8778EBB6F1FEEULL,
		0xA8E0DD21251DEFE7ULL,
		0x68CBC245A0FC802DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBBCBB753C388C438ULL,
			0x5BF8778EBB6F1FEEULL,
			0xA8E0DD21251DEFE7ULL,
			0x68CBC245A0FC802DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE2E0511A719A2228ULL,
			0x1C045F3F746DA6D4ULL,
			0x904A6EF94EA9B0DEULL,
			0x25767A65F6D63038ULL}
		},
		.Z = {.key64 = {
			0x8B30270A28665582ULL,
			0xAACA66FDACFEAA14ULL,
			0x9BB42AEE92B9CA95ULL,
			0x03C14DC7E016C9EDULL}
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

	steps = 36;
	X1 = (curve25519_key_t){.key64 = {
		0x1E48EFD2E9727890ULL,
		0x9F2529B821037603ULL,
		0x54EECEEC79F3627CULL,
		0x45534AAC4EDF7987ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1E48EFD2E9727890ULL,
			0x9F2529B821037603ULL,
			0x54EECEEC79F3627CULL,
			0x45534AAC4EDF7987ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x52A1DC8237B2F432ULL,
			0xF4C1FA7E58B0351CULL,
			0x19BCE5B67294256FULL,
			0x245F5D8D3C714F9CULL}
		},
		.Z = {.key64 = {
			0x01E93177EF27CA51ULL,
			0xD475CBCFBDF1580BULL,
			0xE05D8A9539881809ULL,
			0x12FEBE2285ABAB18ULL}
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

	steps = 8;
	X1 = (curve25519_key_t){.key64 = {
		0xDBCEB01CF69E3E90ULL,
		0xBF0135328B3FB4BFULL,
		0xD4D64DE74CDBE3D5ULL,
		0x5FB38C8C67C2E70EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDBCEB01CF69E3E90ULL,
			0xBF0135328B3FB4BFULL,
			0xD4D64DE74CDBE3D5ULL,
			0x5FB38C8C67C2E70EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFC31D2E7E6915507ULL,
			0xF30561FCC6FF3275ULL,
			0xC9DED09B702B50DBULL,
			0x64D18BFC1FE56BC7ULL}
		},
		.Z = {.key64 = {
			0xB8F10C413D4300E6ULL,
			0x8C8AC116FDF310B7ULL,
			0x23CA47A699C0C2FFULL,
			0x2711BB7020AB3FCEULL}
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

	steps = 37;
	X1 = (curve25519_key_t){.key64 = {
		0xE2E8E2F65EB248D0ULL,
		0x40FD5639EF23B0B1ULL,
		0x84607590623C86DFULL,
		0x78B8BA50B07B87A4ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE2E8E2F65EB248D0ULL,
			0x40FD5639EF23B0B1ULL,
			0x84607590623C86DFULL,
			0x78B8BA50B07B87A4ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x124DF187733267DFULL,
			0xDA756EEF5BEFBA63ULL,
			0xCBA3B330036F87CEULL,
			0x64E372A35C92783BULL}
		},
		.Z = {.key64 = {
			0x194AF582F54843FDULL,
			0xDD0B5EC5D7256DB0ULL,
			0xC34024E46C9FC823ULL,
			0x4A01D2A08D2D4E02ULL}
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

	steps = 17;
	X1 = (curve25519_key_t){.key64 = {
		0xF972CF1BD7DEE510ULL,
		0x18BD78CB0C626BB9ULL,
		0x7CD135370E4F92DEULL,
		0x4C2A35C356C58992ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF972CF1BD7DEE510ULL,
			0x18BD78CB0C626BB9ULL,
			0x7CD135370E4F92DEULL,
			0x4C2A35C356C58992ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6BE937C8AD3DBC26ULL,
			0x46B07E03AD83B7CFULL,
			0x6FFA41D8FCFB6A30ULL,
			0x79099C41C52D9F9EULL}
		},
		.Z = {.key64 = {
			0xE0E4A7985032D618ULL,
			0xC1BBB8B5F8EDACC5ULL,
			0x4FF99DC455B12AC8ULL,
			0x4D2EDA2E7F76D12EULL}
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

	steps = 37;
	X1 = (curve25519_key_t){.key64 = {
		0xFFC8D92B582FB298ULL,
		0xD0140183985AA3D0ULL,
		0x4FA93A50BEA52BC2ULL,
		0x53E284381811EBA6ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFFC8D92B582FB298ULL,
			0xD0140183985AA3D0ULL,
			0x4FA93A50BEA52BC2ULL,
			0x53E284381811EBA6ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCC6DB4A5AF2FA516ULL,
			0xB197528EECCF976AULL,
			0xD4785CAA776EDD4EULL,
			0x6A47CB15D1E7B970ULL}
		},
		.Z = {.key64 = {
			0xF1107C78FBB29D88ULL,
			0x29CD4820D622C535ULL,
			0x9D9655D37B6D4396ULL,
			0x3C1AD068D480E9B7ULL}
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

	steps = 46;
	X1 = (curve25519_key_t){.key64 = {
		0x3CD85219E7FED410ULL,
		0x629B54A0716C5F41ULL,
		0x20BCB1A133902C99ULL,
		0x7C470C96A2BE324BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3CD85219E7FED410ULL,
			0x629B54A0716C5F41ULL,
			0x20BCB1A133902C99ULL,
			0x7C470C96A2BE324BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x72DB6EAFF31B29ABULL,
			0xDDBB1FA46CDE6BC9ULL,
			0x251040DA8B6D47F0ULL,
			0x498657DF3C0B105FULL}
		},
		.Z = {.key64 = {
			0x873219785F7419F0ULL,
			0xAE45639AF0D988F0ULL,
			0x2DC798FF7C35B4C6ULL,
			0x08302A0982E56BFEULL}
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

	steps = 57;
	X1 = (curve25519_key_t){.key64 = {
		0xFD54B0698BA8B2D0ULL,
		0xC62E82B4A3686ED1ULL,
		0xBD8413B56CE7E9E0ULL,
		0x603B423BCBD0D944ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFD54B0698BA8B2D0ULL,
			0xC62E82B4A3686ED1ULL,
			0xBD8413B56CE7E9E0ULL,
			0x603B423BCBD0D944ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDC06C05473D40115ULL,
			0x50F98D83BCF06554ULL,
			0x42AEC0BF30B56C0BULL,
			0x4EC03F79351B8145ULL}
		},
		.Z = {.key64 = {
			0x47754257192EB7BEULL,
			0xA87F8B51FC887E15ULL,
			0x32FB4FB4F8E781EDULL,
			0x1A25CE0D225204EDULL}
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

	steps = 33;
	X1 = (curve25519_key_t){.key64 = {
		0xC8DB6EA28F1CBFB8ULL,
		0xE2BA203B379F9DD7ULL,
		0x5165D1AECD13AAD1ULL,
		0x7C0C903B8AB02748ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC8DB6EA28F1CBFB8ULL,
			0xE2BA203B379F9DD7ULL,
			0x5165D1AECD13AAD1ULL,
			0x7C0C903B8AB02748ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF701F8AA497F14CAULL,
			0xE48DC67C6C660965ULL,
			0x505F7EA0B7CCC293ULL,
			0x30F95200BE333466ULL}
		},
		.Z = {.key64 = {
			0xB5A8E5B952042B44ULL,
			0x9C18E43FAAF9FC8BULL,
			0x4AF5B190C1656D4AULL,
			0x1815CE8AA8E785B5ULL}
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

	steps = 22;
	X1 = (curve25519_key_t){.key64 = {
		0xBD41CF8AEE40D330ULL,
		0x0399A608C4F796BFULL,
		0xC12D03886952B35BULL,
		0x78E2983D316CA792ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBD41CF8AEE40D330ULL,
			0x0399A608C4F796BFULL,
			0xC12D03886952B35BULL,
			0x78E2983D316CA792ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFF63008A1B9C3671ULL,
			0x63E53C44A1261287ULL,
			0x6D20917B8F74A5A3ULL,
			0x56A30C48937FBC81ULL}
		},
		.Z = {.key64 = {
			0x687A04B73021A8EDULL,
			0x154D090CEAB840B3ULL,
			0x59B7CC05C3E737F1ULL,
			0x2119EE6B540D0A4EULL}
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

	steps = 54;
	X1 = (curve25519_key_t){.key64 = {
		0xC0F090E47C50C260ULL,
		0xB2A55A8D5FB5B60EULL,
		0x2E16F349D619DA17ULL,
		0x4B1F395DDB761483ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC0F090E47C50C260ULL,
			0xB2A55A8D5FB5B60EULL,
			0x2E16F349D619DA17ULL,
			0x4B1F395DDB761483ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE1D4FA192EC3B45CULL,
			0x27BD298F4C035E1CULL,
			0x3512DFFB3D545336ULL,
			0x7A3017AA9751ECF0ULL}
		},
		.Z = {.key64 = {
			0xA1D52EE1C939A288ULL,
			0x6BE5293920B71AD6ULL,
			0x0055AAA25C14261EULL,
			0x3607C325C8C8246AULL}
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

	steps = 48;
	X1 = (curve25519_key_t){.key64 = {
		0x3A753B139172B3A0ULL,
		0xF2A5583E90F7F573ULL,
		0xDF662BF01D76D024ULL,
		0x6E06CB2741BEC4BBULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3A753B139172B3A0ULL,
			0xF2A5583E90F7F573ULL,
			0xDF662BF01D76D024ULL,
			0x6E06CB2741BEC4BBULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4CC448D4638305B7ULL,
			0x4A69ABFC524BD094ULL,
			0x57D9402BC61093F2ULL,
			0x4312E1520348C865ULL}
		},
		.Z = {.key64 = {
			0xFB0DBB98C0DAB68CULL,
			0xEA5865D956AA3782ULL,
			0x23AACA31440621F7ULL,
			0x14FFBC6813972193ULL}
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

	steps = 64;
	X1 = (curve25519_key_t){.key64 = {
		0x70C537D337C7D100ULL,
		0xA78165BEB40C0F47ULL,
		0x2B351E922679827DULL,
		0x67C1F6493A877053ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x70C537D337C7D100ULL,
			0xA78165BEB40C0F47ULL,
			0x2B351E922679827DULL,
			0x67C1F6493A877053ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x41B5A7C6DCD1735AULL,
			0xF810E7BC00E532CBULL,
			0x7D7B3B85A13D1A3AULL,
			0x5DED4071230F196CULL}
		},
		.Z = {.key64 = {
			0x97B3DDB803E3D862ULL,
			0x0245F9571D1DFF9EULL,
			0x2084D653C13E7BD0ULL,
			0x5377914E8A595753ULL}
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

	steps = 2;
	X1 = (curve25519_key_t){.key64 = {
		0x296084525F4CC378ULL,
		0x402F8E219D31415DULL,
		0x53F06F2274593DB6ULL,
		0x6F7A663263055B42ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x296084525F4CC378ULL,
			0x402F8E219D31415DULL,
			0x53F06F2274593DB6ULL,
			0x6F7A663263055B42ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x670A0AC4E1C855A7ULL,
			0x192C381D5C84E435ULL,
			0xD8B96EEFD693BC65ULL,
			0x4B47D6EBA4665678ULL}
		},
		.Z = {.key64 = {
			0x44895C2CAFD859C3ULL,
			0x836B1B83F7D7E786ULL,
			0xFDD515BB389D72BDULL,
			0x701353D674C268F6ULL}
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

	steps = 2;
	X1 = (curve25519_key_t){.key64 = {
		0xD545C49A2D48AE00ULL,
		0x910C5FF54C0C99FFULL,
		0x5ED9AD6B4F15C6B3ULL,
		0x7ED25DDC1CB59214ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD545C49A2D48AE00ULL,
			0x910C5FF54C0C99FFULL,
			0x5ED9AD6B4F15C6B3ULL,
			0x7ED25DDC1CB59214ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x436810734634C999ULL,
			0x8819D2125B666C12ULL,
			0x026376270B948C3AULL,
			0x284243CD1343B9D1ULL}
		},
		.Z = {.key64 = {
			0xC08C9173B6A2B9E9ULL,
			0xC799A4678F4EBDD8ULL,
			0x1ABCB7E1C54AB64CULL,
			0x478AEF161FCCAEDEULL}
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

	steps = 44;
	X1 = (curve25519_key_t){.key64 = {
		0xFF1E5F3C4EF21D60ULL,
		0xF1F485567DBE2E2CULL,
		0xAB520839971083A4ULL,
		0x419DDC7CC547AB37ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFF1E5F3C4EF21D60ULL,
			0xF1F485567DBE2E2CULL,
			0xAB520839971083A4ULL,
			0x419DDC7CC547AB37ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4512D66B989AFE66ULL,
			0x3C1ED0DCC0CA55B6ULL,
			0x437AD04162CAB953ULL,
			0x5A2B0EF4E6E6E41AULL}
		},
		.Z = {.key64 = {
			0xC381BD7090C315F7ULL,
			0x6D3D21D56762DFB0ULL,
			0x1514B99A9BFB12FFULL,
			0x27CE4FAF46081628ULL}
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

	steps = 19;
	X1 = (curve25519_key_t){.key64 = {
		0x5C599B044EF87880ULL,
		0x6B2C24A286386B89ULL,
		0xAE1D5E12F6260EABULL,
		0x4E4667E8C30B2520ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5C599B044EF87880ULL,
			0x6B2C24A286386B89ULL,
			0xAE1D5E12F6260EABULL,
			0x4E4667E8C30B2520ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1C928CC430DBA56FULL,
			0x1938D6FD08A7446BULL,
			0xB967C5A16F9A9FABULL,
			0x282268E9178EC6B4ULL}
		},
		.Z = {.key64 = {
			0x22D92CC3662C4E99ULL,
			0x4033BAF298465EE5ULL,
			0xF535294D025EABCFULL,
			0x494D73915C783CFDULL}
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

	steps = 31;
	X1 = (curve25519_key_t){.key64 = {
		0x1DB6D17DEB6A3B40ULL,
		0xCF5C9E6A94400924ULL,
		0x81345C9964D26047ULL,
		0x6310539D578E835CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1DB6D17DEB6A3B40ULL,
			0xCF5C9E6A94400924ULL,
			0x81345C9964D26047ULL,
			0x6310539D578E835CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x05DD8B0F47285ACAULL,
			0xBAE3666113F98378ULL,
			0x47AE25FD5F449254ULL,
			0x1C0486F61C5C7987ULL}
		},
		.Z = {.key64 = {
			0xFC6AD63A4ABF1CA3ULL,
			0x19FF575E80760724ULL,
			0xF0300F69B328061AULL,
			0x40831CAEA1FAD092ULL}
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

	steps = 60;
	X1 = (curve25519_key_t){.key64 = {
		0x43288E86730B83C8ULL,
		0x8CF7BF221F613F40ULL,
		0x97FA14BB492A323AULL,
		0x4B08A4C6E87AB932ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x43288E86730B83C8ULL,
			0x8CF7BF221F613F40ULL,
			0x97FA14BB492A323AULL,
			0x4B08A4C6E87AB932ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC51EF7210B2236FAULL,
			0x03291260EEE90BBEULL,
			0x8183888083A0CFB9ULL,
			0x29B829DB73BDDB8DULL}
		},
		.Z = {.key64 = {
			0xA659E7E4AE95C9DAULL,
			0xCAEFDDB6D572C9D4ULL,
			0x1A665FCB1176AE88ULL,
			0x3DA423C675C8A946ULL}
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

	steps = 13;
	X1 = (curve25519_key_t){.key64 = {
		0x1DCF56B1D6C15D40ULL,
		0xEB8841BD8F352A30ULL,
		0x465A12353274D8AAULL,
		0x4C54C78919EFC39FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1DCF56B1D6C15D40ULL,
			0xEB8841BD8F352A30ULL,
			0x465A12353274D8AAULL,
			0x4C54C78919EFC39FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x554A020A946F029FULL,
			0x7ACBB3A3E6B168CFULL,
			0xCC2735BF70F4F66EULL,
			0x7F171AD30BEE7775ULL}
		},
		.Z = {.key64 = {
			0x8B17C2A90A4643DBULL,
			0xBE3CC4CD36518E3BULL,
			0x94FF7409EB9E0C46ULL,
			0x76A0A4F7A1884A29ULL}
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

	steps = 11;
	X1 = (curve25519_key_t){.key64 = {
		0x764EBC16CF6BB730ULL,
		0xA8BF64DEB2AFD413ULL,
		0xBC63BB1CEBC42C26ULL,
		0x7DA061690459445DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x764EBC16CF6BB730ULL,
			0xA8BF64DEB2AFD413ULL,
			0xBC63BB1CEBC42C26ULL,
			0x7DA061690459445DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4C166E3B6A65B195ULL,
			0x0A278356E5459A2BULL,
			0x131C68F3304C85E1ULL,
			0x11D2FFC43F76D557ULL}
		},
		.Z = {.key64 = {
			0x75ECD271B8C0F97AULL,
			0xF3E2ECF3488540F8ULL,
			0x904157022234019AULL,
			0x2727E313469410F0ULL}
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

	steps = 64;
	X1 = (curve25519_key_t){.key64 = {
		0x6E14552DDAE949D8ULL,
		0x1C8C5C269482BDBDULL,
		0xBE6C3827C941EE81ULL,
		0x6A9A4D0E267C3CB6ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6E14552DDAE949D8ULL,
			0x1C8C5C269482BDBDULL,
			0xBE6C3827C941EE81ULL,
			0x6A9A4D0E267C3CB6ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x20337BA9ECE7AFBEULL,
			0x6379734BE8F4622DULL,
			0x210840411EDAE069ULL,
			0x5C83F3E224F66F8AULL}
		},
		.Z = {.key64 = {
			0x154478E962FAE776ULL,
			0xEDA62E8EB40E466CULL,
			0x2069D431EEDBFEC4ULL,
			0x19C67A3A33F627F1ULL}
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

	steps = 51;
	X1 = (curve25519_key_t){.key64 = {
		0x3910C3B3CD1C9D38ULL,
		0x27D06FE5C66AEBF7ULL,
		0xB2D7405375546945ULL,
		0x608C99D335E3B77CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3910C3B3CD1C9D38ULL,
			0x27D06FE5C66AEBF7ULL,
			0xB2D7405375546945ULL,
			0x608C99D335E3B77CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE2B7421F32BE16F1ULL,
			0xF0CD62B25D030B00ULL,
			0xEE941E019C3B32ACULL,
			0x24B5A307F2980257ULL}
		},
		.Z = {.key64 = {
			0x9A0145F55378C9D2ULL,
			0xE1D2E247B86EE33EULL,
			0x562FEDB8E46E02CAULL,
			0x5CBC6B0844E02F3EULL}
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

	steps = 56;
	X1 = (curve25519_key_t){.key64 = {
		0x4F4443E33E1FBB28ULL,
		0xDE5A001E4D6EE2D3ULL,
		0x934C4B608E32B1D5ULL,
		0x5F6FDD1911DF62D8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4F4443E33E1FBB28ULL,
			0xDE5A001E4D6EE2D3ULL,
			0x934C4B608E32B1D5ULL,
			0x5F6FDD1911DF62D8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x86F7F0712725B3F4ULL,
			0x11BDB2B7483548C7ULL,
			0x50B558679B257E60ULL,
			0x5FC4E215D422A459ULL}
		},
		.Z = {.key64 = {
			0xCFF3707A27971CB4ULL,
			0xEBBAAD2247DE61E3ULL,
			0xD9929E151613C375ULL,
			0x503C72AD1F31D42EULL}
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

	steps = 14;
	X1 = (curve25519_key_t){.key64 = {
		0x7AFDADAB1BCF9A08ULL,
		0xC9D9F683CAF03A92ULL,
		0xB3478051CB9E6605ULL,
		0x53EB6DCB89F16CC1ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7AFDADAB1BCF9A08ULL,
			0xC9D9F683CAF03A92ULL,
			0xB3478051CB9E6605ULL,
			0x53EB6DCB89F16CC1ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0D2D8AD67428E56DULL,
			0x2C8D7C50421F274BULL,
			0x1C67FF0B204FFB36ULL,
			0x78C2B20DAD9F1114ULL}
		},
		.Z = {.key64 = {
			0x80FD22BF307A2463ULL,
			0x26B88BA85A2053D3ULL,
			0x1A27301EC9A25365ULL,
			0x4C0ABDAEFDA80886ULL}
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

	steps = 58;
	X1 = (curve25519_key_t){.key64 = {
		0xAD70EACDE0A14020ULL,
		0xA498C1E9822AB037ULL,
		0x0814CB2BF0E98536ULL,
		0x4D2C4742E413F840ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAD70EACDE0A14020ULL,
			0xA498C1E9822AB037ULL,
			0x0814CB2BF0E98536ULL,
			0x4D2C4742E413F840ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x578323EE91F75142ULL,
			0x3BCDEC0A3A0D403AULL,
			0xFC07F8B37264070CULL,
			0x65D43B0E6A7DCC68ULL}
		},
		.Z = {.key64 = {
			0x8133CAE8956B19EEULL,
			0x8BD497443410717EULL,
			0x882C22ED371C516BULL,
			0x52A06A85FE812E9BULL}
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

	steps = 59;
	X1 = (curve25519_key_t){.key64 = {
		0x47D76F77AEB00EE8ULL,
		0x4068BAEFB2DCA5A9ULL,
		0x827D8A38D9A63620ULL,
		0x55B66311BEB50116ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x47D76F77AEB00EE8ULL,
			0x4068BAEFB2DCA5A9ULL,
			0x827D8A38D9A63620ULL,
			0x55B66311BEB50116ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE74B6B65A60C78D6ULL,
			0x082AC9AFB5397E0AULL,
			0xB7C2F38F2E18CC20ULL,
			0x202F87094CB6FAF6ULL}
		},
		.Z = {.key64 = {
			0x1F2FF5FC800A5276ULL,
			0x5EAAC15493D38736ULL,
			0xB2C2A768FE6C96A2ULL,
			0x3533736298964564ULL}
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

	steps = 32;
	X1 = (curve25519_key_t){.key64 = {
		0xF5DEDC7E31D9B620ULL,
		0xCE9378B17D10C109ULL,
		0x96C59D4ECB633315ULL,
		0x5E882A9E1C97FE2AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF5DEDC7E31D9B620ULL,
			0xCE9378B17D10C109ULL,
			0x96C59D4ECB633315ULL,
			0x5E882A9E1C97FE2AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDE084000ED0DD5E0ULL,
			0xD32012DA6987A31DULL,
			0x6C4AEA2D245363EBULL,
			0x3402011FB9CFF6F6ULL}
		},
		.Z = {.key64 = {
			0x6C20BD2AFF848111ULL,
			0xDCCD0910854997DEULL,
			0x2CFF8DAC2176307FULL,
			0x5B8F619680CF4C7FULL}
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

	steps = 2;
	X1 = (curve25519_key_t){.key64 = {
		0x8109F6F1C3901450ULL,
		0x6EC7A36229E9F845ULL,
		0x7739F8688C258D24ULL,
		0x62067025C952615BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8109F6F1C3901450ULL,
			0x6EC7A36229E9F845ULL,
			0x7739F8688C258D24ULL,
			0x62067025C952615BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3EA28C65594B5250ULL,
			0x8D9C9B38060F3119ULL,
			0xFB935F47699BAA98ULL,
			0x2971B6328152BC8AULL}
		},
		.Z = {.key64 = {
			0x2B6CE309A895521AULL,
			0x5A9A9834876AF94CULL,
			0x12D3352CA30149EEULL,
			0x773E3977EB9C4DBCULL}
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

	steps = 22;
	X1 = (curve25519_key_t){.key64 = {
		0x73A9A21B9CC91F88ULL,
		0x5DA3F83CCC3050EEULL,
		0xE81345F66327F584ULL,
		0x70D8B156536E468EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x73A9A21B9CC91F88ULL,
			0x5DA3F83CCC3050EEULL,
			0xE81345F66327F584ULL,
			0x70D8B156536E468EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1C6778A3EB3D3C7CULL,
			0x4BB84B0CA1FCA3F8ULL,
			0x426942611A176EF0ULL,
			0x2DB9A3017BED9383ULL}
		},
		.Z = {.key64 = {
			0x73BDD42C6B24B243ULL,
			0xF8DF70EEA6B58B08ULL,
			0xC3EAC833B4328C00ULL,
			0x0CFBF8C7E19E0C10ULL}
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

	steps = 14;
	X1 = (curve25519_key_t){.key64 = {
		0x9C884F7B5FB9E890ULL,
		0x7A05D25CD42FF162ULL,
		0xB823E49D031C660CULL,
		0x62024EBCC16B80EDULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9C884F7B5FB9E890ULL,
			0x7A05D25CD42FF162ULL,
			0xB823E49D031C660CULL,
			0x62024EBCC16B80EDULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x86A2BAE4C68EE98CULL,
			0x5AF29F6AC2FE2986ULL,
			0xFC4DCBF8440BAB19ULL,
			0x3222C6CBE8123D06ULL}
		},
		.Z = {.key64 = {
			0x4AABA5E3E3ED9961ULL,
			0x24F5F02EC5EDDBFEULL,
			0x29E5FE6BEAF54747ULL,
			0x43AF1BE15C28A8B1ULL}
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

	steps = 6;
	X1 = (curve25519_key_t){.key64 = {
		0x60D75C60D0322378ULL,
		0x552AC8C020C62C90ULL,
		0x860ECFE50D07045AULL,
		0x7327A4CC1C6FD654ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x60D75C60D0322378ULL,
			0x552AC8C020C62C90ULL,
			0x860ECFE50D07045AULL,
			0x7327A4CC1C6FD654ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x180FED8F2297E69FULL,
			0x3200F626C43524DFULL,
			0x95BE26B9617ADEC4ULL,
			0x6CC9EFC056ECA3AFULL}
		},
		.Z = {.key64 = {
			0x64F6142564B26901ULL,
			0x671DC4934E701321ULL,
			0xF658893A974D3ED5ULL,
			0x597318370A8831A3ULL}
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

	steps = 12;
	X1 = (curve25519_key_t){.key64 = {
		0xEF2C6534A0CFC198ULL,
		0x3AD14C9E8246F9DBULL,
		0x6075EE605871D17FULL,
		0x75FA5EA0768EE286ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEF2C6534A0CFC198ULL,
			0x3AD14C9E8246F9DBULL,
			0x6075EE605871D17FULL,
			0x75FA5EA0768EE286ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x60997537B1CDC2FCULL,
			0x350AE5C6B49BEB12ULL,
			0x6B694325DA9A61E3ULL,
			0x7BB8E18713B2C31CULL}
		},
		.Z = {.key64 = {
			0xBEF68612E48EFEC7ULL,
			0x4E5148D8141FB7D1ULL,
			0xFE5B92E12304F096ULL,
			0x5304F98C9CB918A2ULL}
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

	steps = 24;
	X1 = (curve25519_key_t){.key64 = {
		0xC605D5315BE08A08ULL,
		0x5CA5EEECCE045357ULL,
		0x254A28B0E12984D9ULL,
		0x4F3EBC785D2C7762ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC605D5315BE08A08ULL,
			0x5CA5EEECCE045357ULL,
			0x254A28B0E12984D9ULL,
			0x4F3EBC785D2C7762ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1BD51D0A20DBAF1BULL,
			0x09E7F651C4C49B8EULL,
			0x45760927B561E98FULL,
			0x347229820C75BDD5ULL}
		},
		.Z = {.key64 = {
			0xCCD2A3E0C67FD19EULL,
			0xB6EA3FCF85705101ULL,
			0xBA370C3CA604C74CULL,
			0x42F8CD88E725FED0ULL}
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

	steps = 4;
	X1 = (curve25519_key_t){.key64 = {
		0xE4EAA7FD3E093F70ULL,
		0x2AC988F82A3CC272ULL,
		0x4A1AF2630945389AULL,
		0x7D3E5A9EF677C781ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE4EAA7FD3E093F70ULL,
			0x2AC988F82A3CC272ULL,
			0x4A1AF2630945389AULL,
			0x7D3E5A9EF677C781ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9EA0D7C43EE3F666ULL,
			0x1132E15AC144A574ULL,
			0x4B21C30CC399A73CULL,
			0x7F67172AE712E5BEULL}
		},
		.Z = {.key64 = {
			0x7556EEA81E57D9F2ULL,
			0x1DAD97060FFDAF45ULL,
			0xBA82E51A2648396EULL,
			0x4A080E647455E714ULL}
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

	steps = 64;
	X1 = (curve25519_key_t){.key64 = {
		0xEA43E3BD7F723430ULL,
		0xBECE72AA482536B0ULL,
		0xE5DD162E6CA082F4ULL,
		0x408BC390D632C276ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEA43E3BD7F723430ULL,
			0xBECE72AA482536B0ULL,
			0xE5DD162E6CA082F4ULL,
			0x408BC390D632C276ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xED487AFF6512A539ULL,
			0x7B1B583CA6BEF8EEULL,
			0xA3FFB4EB07784B0DULL,
			0x2C9AEB891A995F5AULL}
		},
		.Z = {.key64 = {
			0x86EBE3F31307BA4EULL,
			0x3385384D0651D796ULL,
			0xD76B8C7A1F46D2C9ULL,
			0x16946B176BF25752ULL}
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

	steps = 43;
	X1 = (curve25519_key_t){.key64 = {
		0x4F5EB3E8955C3920ULL,
		0xFC2B6B665FB957A0ULL,
		0x0BA386BEAE25393FULL,
		0x768B7CA7CBD64D34ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4F5EB3E8955C3920ULL,
			0xFC2B6B665FB957A0ULL,
			0x0BA386BEAE25393FULL,
			0x768B7CA7CBD64D34ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE3B2BD2A78AACE64ULL,
			0xD2679B64E287EEFEULL,
			0xFCE6A5003C1163A2ULL,
			0x7C27DA0602F2961EULL}
		},
		.Z = {.key64 = {
			0x672959F15D4A4A28ULL,
			0x1595C53A5D67168BULL,
			0x6B40D86AE6594AC8ULL,
			0x71EC84234AD5F89CULL}
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

	steps = 48;
	X1 = (curve25519_key_t){.key64 = {
		0xDA63B727331404F0ULL,
		0xC5897AFA3250DB0BULL,
		0x653B79BF60BF3F35ULL,
		0x4E538C6E4599397BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDA63B727331404F0ULL,
			0xC5897AFA3250DB0BULL,
			0x653B79BF60BF3F35ULL,
			0x4E538C6E4599397BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1341172352E9D14EULL,
			0xA6F443D8CA72365EULL,
			0x325FE3A3539DB5CCULL,
			0x2BEE54E001FE228BULL}
		},
		.Z = {.key64 = {
			0x459EE908DFEE3611ULL,
			0xC117874C19F4DA4CULL,
			0x615056E3AFFE3992ULL,
			0x1FF073241E9A6CE1ULL}
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

	steps = 51;
	X1 = (curve25519_key_t){.key64 = {
		0x695AE2E294DB3730ULL,
		0x5408FA0D69C8EF2AULL,
		0x44F3D00029EB6FD3ULL,
		0x7A6E9705FDBF3EFEULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x695AE2E294DB3730ULL,
			0x5408FA0D69C8EF2AULL,
			0x44F3D00029EB6FD3ULL,
			0x7A6E9705FDBF3EFEULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x848156F38251C38FULL,
			0x5FE1CAEF3011125AULL,
			0x7471EF9DA9361C02ULL,
			0x2C66F710C46BDD8FULL}
		},
		.Z = {.key64 = {
			0x4A1DFE44A9D89191ULL,
			0xF0D958574F30A36AULL,
			0xDCEA569AEE5EAE00ULL,
			0x48DFE6DA95BD2BC7ULL}
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

	steps = 35;
	X1 = (curve25519_key_t){.key64 = {
		0xA0F76866578F5870ULL,
		0x0D7AA331C17F75ECULL,
		0x2C98877A21270924ULL,
		0x70789F5EC56D6A7AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA0F76866578F5870ULL,
			0x0D7AA331C17F75ECULL,
			0x2C98877A21270924ULL,
			0x70789F5EC56D6A7AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x88632FF33BAB8DF7ULL,
			0x664334C1F8B9D1F2ULL,
			0x65F19A882AD24D53ULL,
			0x559F80D4483A8B94ULL}
		},
		.Z = {.key64 = {
			0x1E8022EFE579B33DULL,
			0xE75B25FD7D08280CULL,
			0x7196705544DC23C2ULL,
			0x2778385E327FA458ULL}
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

	steps = 37;
	X1 = (curve25519_key_t){.key64 = {
		0x17896902FAD01A60ULL,
		0xA9636755258D483FULL,
		0xECA70AD7C71B80AFULL,
		0x4DFD79553F10FA52ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x17896902FAD01A60ULL,
			0xA9636755258D483FULL,
			0xECA70AD7C71B80AFULL,
			0x4DFD79553F10FA52ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAC53FAD3F9418DEFULL,
			0x44E982A1425E14EEULL,
			0xF479F268B8B59BB7ULL,
			0x3A518E189E630559ULL}
		},
		.Z = {.key64 = {
			0xEA87106CA4657249ULL,
			0x18F26E05E2E70A4FULL,
			0x75A1A2836800CD63ULL,
			0x47E2D879497EDA1CULL}
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

	steps = 42;
	X1 = (curve25519_key_t){.key64 = {
		0x03901BAEFDFC8230ULL,
		0x03300F96237CC380ULL,
		0xD40714756BBFEF6CULL,
		0x5FF8569349EC5046ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x03901BAEFDFC8230ULL,
			0x03300F96237CC380ULL,
			0xD40714756BBFEF6CULL,
			0x5FF8569349EC5046ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x45CF8F8DC68115D2ULL,
			0x32F545D59710CDEAULL,
			0x001428C4C8025FFDULL,
			0x0FE1058907AB2AACULL}
		},
		.Z = {.key64 = {
			0x05AC4298E1EB7E08ULL,
			0xEFA0276BE6933B4BULL,
			0x83A86A90E79DA162ULL,
			0x220A605C883B20F7ULL}
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

	steps = 4;
	X1 = (curve25519_key_t){.key64 = {
		0xF540E4B143C048F8ULL,
		0x2CD56C40AC1AC200ULL,
		0x027376CEDF87C80BULL,
		0x68E0252B703043D0ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF540E4B143C048F8ULL,
			0x2CD56C40AC1AC200ULL,
			0x027376CEDF87C80BULL,
			0x68E0252B703043D0ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0813E7154571E874ULL,
			0x4E74E9F32C4B5CE5ULL,
			0x4A07D3A0F7CAD5FDULL,
			0x5697CD206925B17FULL}
		},
		.Z = {.key64 = {
			0x9E6C1594A2860B87ULL,
			0x8B0A95B192765E62ULL,
			0x7662766ADD127CD5ULL,
			0x7C647162426AD9B8ULL}
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

	steps = 10;
	X1 = (curve25519_key_t){.key64 = {
		0x404A4610528ED5A0ULL,
		0x12DE2F7362DCF8EEULL,
		0x676DB37BE23E01E7ULL,
		0x5EC9E3D65994CFB4ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x404A4610528ED5A0ULL,
			0x12DE2F7362DCF8EEULL,
			0x676DB37BE23E01E7ULL,
			0x5EC9E3D65994CFB4ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF2170103268B23DAULL,
			0x7F808167D399EAFCULL,
			0x5B18390143DBA492ULL,
			0x5F370CF4E5F650A1ULL}
		},
		.Z = {.key64 = {
			0x5DFEE2920668DD23ULL,
			0x55BD00B1408D31CAULL,
			0xC2A382F159B37A0CULL,
			0x667C1BB39A2B2481ULL}
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

	steps = 35;
	X1 = (curve25519_key_t){.key64 = {
		0xE26A293916869FD0ULL,
		0xA1E5F9E640B127B0ULL,
		0x334210BAD2CD7EC5ULL,
		0x56CA82CBE09AB756ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE26A293916869FD0ULL,
			0xA1E5F9E640B127B0ULL,
			0x334210BAD2CD7EC5ULL,
			0x56CA82CBE09AB756ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x161E5DE2B6554DD5ULL,
			0x9840AFB3A4C854ABULL,
			0xAF350760D963A41FULL,
			0x7DF7D1F5B625B584ULL}
		},
		.Z = {.key64 = {
			0xFC7CF1907A5D38E0ULL,
			0x75D5428C46A45C24ULL,
			0xE8241A8A53DAB8B6ULL,
			0x0E6DC37207AFB47AULL}
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

	steps = 29;
	X1 = (curve25519_key_t){.key64 = {
		0xBF59F4D9F101C4D0ULL,
		0x39E6C62882D36D36ULL,
		0x0BCE0C69805DD3CBULL,
		0x6BD0E25DCE97949BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBF59F4D9F101C4D0ULL,
			0x39E6C62882D36D36ULL,
			0x0BCE0C69805DD3CBULL,
			0x6BD0E25DCE97949BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x52666DE919124D5CULL,
			0xB7D9CC52C23E5E4BULL,
			0x584EFED5F4F5592FULL,
			0x11F79754091E418DULL}
		},
		.Z = {.key64 = {
			0xD9EDD42228F457E9ULL,
			0x73CF2CB9454DE357ULL,
			0x35ADD2B0AB7999F1ULL,
			0x78B159B15CB51A31ULL}
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

	steps = 63;
	X1 = (curve25519_key_t){.key64 = {
		0x65EC86DA0975AA98ULL,
		0x0EEE05451CCB1AC9ULL,
		0xCF545BAAA9440174ULL,
		0x7FD6C7F28BF22D71ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x65EC86DA0975AA98ULL,
			0x0EEE05451CCB1AC9ULL,
			0xCF545BAAA9440174ULL,
			0x7FD6C7F28BF22D71ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x84215E246C96A2B4ULL,
			0x0B385E3330D6EA49ULL,
			0x7349F996D2233EC6ULL,
			0x17528B74F305C058ULL}
		},
		.Z = {.key64 = {
			0x28832531F1C55035ULL,
			0xC3E97E1D6946A20AULL,
			0x332AB3C278C83999ULL,
			0x0C984D982B6EBE9FULL}
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

	steps = 54;
	X1 = (curve25519_key_t){.key64 = {
		0x5D49013CBD3CE940ULL,
		0xEBDE0F89FA4B5E9FULL,
		0x0930A882781B3974ULL,
		0x7A6A186371730387ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5D49013CBD3CE940ULL,
			0xEBDE0F89FA4B5E9FULL,
			0x0930A882781B3974ULL,
			0x7A6A186371730387ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1B0C412A396FF8A1ULL,
			0x4330AA2412212B6AULL,
			0x48BFB7E1EC4A5B31ULL,
			0x2D9CEE8896F1D162ULL}
		},
		.Z = {.key64 = {
			0x61393FDEE3BD2D25ULL,
			0x021C0AC212F76A4DULL,
			0x8D0220D1C3379FA6ULL,
			0x2AD9CA6FBCA59BF7ULL}
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

	steps = 21;
	X1 = (curve25519_key_t){.key64 = {
		0x50C3A444A8C02328ULL,
		0x99A4A4C0B632039AULL,
		0x6C882B7F6FB5F10DULL,
		0x511705BB111EB014ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x50C3A444A8C02328ULL,
			0x99A4A4C0B632039AULL,
			0x6C882B7F6FB5F10DULL,
			0x511705BB111EB014ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0BB3825DE97FE56DULL,
			0x213F9450416A9EFEULL,
			0x473DBF825DE7587CULL,
			0x3CDD3CE3111B1DB9ULL}
		},
		.Z = {.key64 = {
			0x807779A23494CBCEULL,
			0x6D037B292603640BULL,
			0x86DDF3524AD56D07ULL,
			0x3820D905F780E579ULL}
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

	steps = 21;
	X1 = (curve25519_key_t){.key64 = {
		0x697258811AA51630ULL,
		0x9DA8ECDC892D8D15ULL,
		0xC5A0E9D2BCCEF51AULL,
		0x528D12B91FEC566AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x697258811AA51630ULL,
			0x9DA8ECDC892D8D15ULL,
			0xC5A0E9D2BCCEF51AULL,
			0x528D12B91FEC566AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9102D3ABEFE1A929ULL,
			0xA7D37AE4EECC981CULL,
			0xE44F76661FCF2E96ULL,
			0x09201E06ADEE2E0DULL}
		},
		.Z = {.key64 = {
			0x9DEF442D582839E7ULL,
			0xD0C35B420F8A4A39ULL,
			0x8409423EC02E8562ULL,
			0x6F9BF316D3F0D04EULL}
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

	steps = 63;
	X1 = (curve25519_key_t){.key64 = {
		0x9DCFBAAD3C52B758ULL,
		0x8DA2E2F10497AF1EULL,
		0x33285CDEE0F4A514ULL,
		0x6BB00943E30A89B6ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9DCFBAAD3C52B758ULL,
			0x8DA2E2F10497AF1EULL,
			0x33285CDEE0F4A514ULL,
			0x6BB00943E30A89B6ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3F602F5FF2FCFE28ULL,
			0x4666D2421AF5EC96ULL,
			0xB1ADD79F92310D49ULL,
			0x2A44B69DC2514EE8ULL}
		},
		.Z = {.key64 = {
			0x01E3B987D235ADEEULL,
			0xF06646122135CB7BULL,
			0x3455D41E52F4D475ULL,
			0x5A4BFACB025F2C82ULL}
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

	steps = 58;
	X1 = (curve25519_key_t){.key64 = {
		0xBF6A502F70F83BA0ULL,
		0xB61082A4015AB770ULL,
		0x3780AE6FF5AE9B35ULL,
		0x63BEFAF3673291B1ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBF6A502F70F83BA0ULL,
			0xB61082A4015AB770ULL,
			0x3780AE6FF5AE9B35ULL,
			0x63BEFAF3673291B1ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x566CF3F709819C1DULL,
			0x0B81F190AE91F2A3ULL,
			0x9569EC17F5DA0D77ULL,
			0x3652EA9946B0DCA6ULL}
		},
		.Z = {.key64 = {
			0x85189FE4893104B5ULL,
			0x1EE9D3ED008C69A6ULL,
			0xE7000EF023036A20ULL,
			0x49E172491B9FEEC0ULL}
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

	steps = 18;
	X1 = (curve25519_key_t){.key64 = {
		0xF7B6949BED44D2D0ULL,
		0x9CFBF82FFD9586A2ULL,
		0x35F2E7BD03B07424ULL,
		0x75C2A6EBCB00E822ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF7B6949BED44D2D0ULL,
			0x9CFBF82FFD9586A2ULL,
			0x35F2E7BD03B07424ULL,
			0x75C2A6EBCB00E822ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x540C818BBAA309CAULL,
			0x99943DA0DB53ECB6ULL,
			0xD23BC305C4F18B10ULL,
			0x04DDC4F1FA07A16DULL}
		},
		.Z = {.key64 = {
			0x093312914EB4BF69ULL,
			0xA31EEAC5B1ED4A4FULL,
			0x421DAB4B5FEBBFE5ULL,
			0x497C51A3F8AA2D3DULL}
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

	steps = 64;
	X1 = (curve25519_key_t){.key64 = {
		0xC0882685483FB028ULL,
		0x327ECAACCB741982ULL,
		0x12D2EA002989336DULL,
		0x6B586BB90EA2911BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC0882685483FB028ULL,
			0x327ECAACCB741982ULL,
			0x12D2EA002989336DULL,
			0x6B586BB90EA2911BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC53989EA82C183EAULL,
			0xA3FB88BFED849642ULL,
			0xA0F1E0A58320CC0FULL,
			0x76542FFB834E0FF9ULL}
		},
		.Z = {.key64 = {
			0x717A652AF2984A8DULL,
			0xC3279E7B93AB165CULL,
			0x26156376441D3DA1ULL,
			0x451FC929DF9F1F8EULL}
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

	steps = 58;
	X1 = (curve25519_key_t){.key64 = {
		0xF591C7B9D43C3EF8ULL,
		0xC71613CB4102671AULL,
		0xA07BEDF98FE0E676ULL,
		0x58E2D08FEF7DA4B2ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF591C7B9D43C3EF8ULL,
			0xC71613CB4102671AULL,
			0xA07BEDF98FE0E676ULL,
			0x58E2D08FEF7DA4B2ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF3530AB2A6AFBE63ULL,
			0xB607E590E737AEB7ULL,
			0x612FCD08FE932CB6ULL,
			0x6FEBBC6349DE7047ULL}
		},
		.Z = {.key64 = {
			0x7149EC3DD084507DULL,
			0xFBF78DAEC29D6D4BULL,
			0x470AAC3B1021958FULL,
			0x5DF6BD61819E319EULL}
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

	steps = 19;
	X1 = (curve25519_key_t){.key64 = {
		0x160006ECF25FE800ULL,
		0xA506940A7ADE3261ULL,
		0x38FE19113B95A8C0ULL,
		0x470F9B96BB5F421EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x160006ECF25FE800ULL,
			0xA506940A7ADE3261ULL,
			0x38FE19113B95A8C0ULL,
			0x470F9B96BB5F421EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x460C37522E5AA9C5ULL,
			0x067A7727130A8F1FULL,
			0x83712BA1A5789A98ULL,
			0x75D2105443431F27ULL}
		},
		.Z = {.key64 = {
			0xF26E202CD01E4120ULL,
			0xF790FD0C0AA2B3D3ULL,
			0x2D9C6A3BA48E4669ULL,
			0x55CB21D7A9005056ULL}
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

	steps = 38;
	X1 = (curve25519_key_t){.key64 = {
		0xA0138A508A64F4C8ULL,
		0xFFD498991AD14EB8ULL,
		0x747311A467FDB90DULL,
		0x5039B705A6520836ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA0138A508A64F4C8ULL,
			0xFFD498991AD14EB8ULL,
			0x747311A467FDB90DULL,
			0x5039B705A6520836ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC993AF9C42F9BC9BULL,
			0x9794EAD6CC49E7F0ULL,
			0x7D7F0A316493B4A8ULL,
			0x1D92EC33463132A8ULL}
		},
		.Z = {.key64 = {
			0x5C3695FCDAEDC54AULL,
			0x8F98082100CA6E83ULL,
			0x551BF784CC7938D6ULL,
			0x5AC6597475ADC89BULL}
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

	steps = 8;
	X1 = (curve25519_key_t){.key64 = {
		0x91D1254185B72508ULL,
		0xEECA66D5B0A6F8D6ULL,
		0x9763ECBAB512035EULL,
		0x6ABCFC3A50C90D72ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x91D1254185B72508ULL,
			0xEECA66D5B0A6F8D6ULL,
			0x9763ECBAB512035EULL,
			0x6ABCFC3A50C90D72ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD667CAF4062D2F10ULL,
			0x79C842414C94A263ULL,
			0x87DA9031DB0C7F14ULL,
			0x7D89EB45F029AC4CULL}
		},
		.Z = {.key64 = {
			0xCD79F15271F35FCCULL,
			0x94F3658DD4225D15ULL,
			0x31732C9E8DD1E686ULL,
			0x7086E7F46D33C71FULL}
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

	steps = 9;
	X1 = (curve25519_key_t){.key64 = {
		0x13B3EF76C9E9F440ULL,
		0x3DE328D70D51B09DULL,
		0x77EFD759B7D50858ULL,
		0x5B59DF3CC3647401ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x13B3EF76C9E9F440ULL,
			0x3DE328D70D51B09DULL,
			0x77EFD759B7D50858ULL,
			0x5B59DF3CC3647401ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD6FBD7E88F62AAF0ULL,
			0x2A1042E2D40B822AULL,
			0x0558B700B4AA3E64ULL,
			0x0ABD17BC790B366FULL}
		},
		.Z = {.key64 = {
			0x7CC5D602CA0328AEULL,
			0x171FF7846C019C52ULL,
			0x4103077F979A6418ULL,
			0x6C627BBCEAEECAFDULL}
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

	steps = 51;
	X1 = (curve25519_key_t){.key64 = {
		0xB37BB93D30CE8418ULL,
		0xEB929E583BA7F19AULL,
		0x7A8130FF7F398A09ULL,
		0x701D9CB13BE68289ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB37BB93D30CE8418ULL,
			0xEB929E583BA7F19AULL,
			0x7A8130FF7F398A09ULL,
			0x701D9CB13BE68289ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5B4DC91FC460423EULL,
			0xAF8FF3B1CF000A77ULL,
			0x7A96F695BA44C93EULL,
			0x68E6FEA67144923CULL}
		},
		.Z = {.key64 = {
			0xE3573B555F2874CFULL,
			0x95565E730B88AB33ULL,
			0xC7824BDDD9A36199ULL,
			0x3481B33194805716ULL}
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

	steps = 56;
	X1 = (curve25519_key_t){.key64 = {
		0xD96825FFC746C968ULL,
		0x916B8FF10EA8B964ULL,
		0xFB9BD5718756191DULL,
		0x5CE6371E0E3ED846ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD96825FFC746C968ULL,
			0x916B8FF10EA8B964ULL,
			0xFB9BD5718756191DULL,
			0x5CE6371E0E3ED846ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC1E1C9463AD33B0FULL,
			0x86741FB76AC341D5ULL,
			0xD360FBA14C3CA1DEULL,
			0x3086766A0F206286ULL}
		},
		.Z = {.key64 = {
			0x3230B0A220972C35ULL,
			0x96914C6254116728ULL,
			0xF372DFD1514ADFAFULL,
			0x4C62B4DA0E6DE41BULL}
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

	steps = 11;
	X1 = (curve25519_key_t){.key64 = {
		0x20463C63F48B0488ULL,
		0xBD978FF5869E7542ULL,
		0x09A864B9FB66090EULL,
		0x5E06E216641A2816ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x20463C63F48B0488ULL,
			0xBD978FF5869E7542ULL,
			0x09A864B9FB66090EULL,
			0x5E06E216641A2816ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x774C53D8A84F75D1ULL,
			0xB6C941B2842CB3A7ULL,
			0x8181A62F1BE728ADULL,
			0x4D0BA57A28E345FFULL}
		},
		.Z = {.key64 = {
			0xACEE9072074AB54DULL,
			0x23738FC923C86376ULL,
			0x99F6D0ECE9AF6FF4ULL,
			0x170DB8C0F77BBDD2ULL}
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

	steps = 48;
	X1 = (curve25519_key_t){.key64 = {
		0x50F8E33284E5C320ULL,
		0xA4C7A7856CEE8F0FULL,
		0x2C8357B3E57D28FEULL,
		0x48E21876B80ADC00ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x50F8E33284E5C320ULL,
			0xA4C7A7856CEE8F0FULL,
			0x2C8357B3E57D28FEULL,
			0x48E21876B80ADC00ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1BB183F1CB65D564ULL,
			0xACE95661484659D7ULL,
			0xACC0A1E45DFB7D7EULL,
			0x36CCE9ED7D55A4C0ULL}
		},
		.Z = {.key64 = {
			0x3C719D4A29798419ULL,
			0xC730A5B3DF20CF4DULL,
			0x65A643A4F7BC1541ULL,
			0x56086FF205724603ULL}
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

	steps = 48;
	X1 = (curve25519_key_t){.key64 = {
		0x7B469A1B682E1368ULL,
		0x22FEDDAE1EF2D6B4ULL,
		0x503746CC449C5E62ULL,
		0x49B23F20CB03D320ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7B469A1B682E1368ULL,
			0x22FEDDAE1EF2D6B4ULL,
			0x503746CC449C5E62ULL,
			0x49B23F20CB03D320ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2C1E0C05BC228ADDULL,
			0x32CC09F8B1C5AABBULL,
			0x55548D5331F44391ULL,
			0x06C6DFC9D57AC49AULL}
		},
		.Z = {.key64 = {
			0x6B6B72C154D45A1DULL,
			0xF78A53644E49640CULL,
			0x6C3BA4AB3CC5F052ULL,
			0x0A9E20A74B2C10F0ULL}
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

	steps = 33;
	X1 = (curve25519_key_t){.key64 = {
		0xC5B32E86E4AC52E0ULL,
		0x4014B037BEB71D06ULL,
		0x539023955017615AULL,
		0x5C971AE4424E5C08ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC5B32E86E4AC52E0ULL,
			0x4014B037BEB71D06ULL,
			0x539023955017615AULL,
			0x5C971AE4424E5C08ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEE9FADE410298D98ULL,
			0x8C507FD799D7FEC8ULL,
			0x82270D80E44FD31BULL,
			0x1C82CB363F10BC25ULL}
		},
		.Z = {.key64 = {
			0x38E896AFDA70C3F8ULL,
			0x07DCDF52C254E47BULL,
			0xC5C5251B44346B14ULL,
			0x39909E14AF36AEF5ULL}
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

	steps = 44;
	X1 = (curve25519_key_t){.key64 = {
		0xCC7934A4C77B1DA8ULL,
		0x71BE7477CBFBBDCFULL,
		0x68C7A0E4A238F470ULL,
		0x7E9F190C043E6953ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCC7934A4C77B1DA8ULL,
			0x71BE7477CBFBBDCFULL,
			0x68C7A0E4A238F470ULL,
			0x7E9F190C043E6953ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA87A0761113AC8CFULL,
			0xA02D2E291548D866ULL,
			0x22D407DC09800BC5ULL,
			0x61D55A2DBD53E3F2ULL}
		},
		.Z = {.key64 = {
			0x7EC19FE126915155ULL,
			0x3C1F08B42F954E4DULL,
			0x5742D9FD7512656CULL,
			0x2B12AEFBB34F969AULL}
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

	steps = 45;
	X1 = (curve25519_key_t){.key64 = {
		0x5B6DF9252BC9B7D0ULL,
		0x97718079BF64B84AULL,
		0x2B11CC70332E3FE7ULL,
		0x687F60306AAD9CC5ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5B6DF9252BC9B7D0ULL,
			0x97718079BF64B84AULL,
			0x2B11CC70332E3FE7ULL,
			0x687F60306AAD9CC5ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6244F3721AA74907ULL,
			0x2082E91A80D9C9ADULL,
			0xA100DF07E1F4BBF4ULL,
			0x12B6D6DB1FB90427ULL}
		},
		.Z = {.key64 = {
			0x5235DBE037A783B6ULL,
			0x0636A4F2F470D3E5ULL,
			0x0520451CE91CD525ULL,
			0x4FC2259BAB071A58ULL}
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

	steps = 49;
	X1 = (curve25519_key_t){.key64 = {
		0x7FE9324908D69120ULL,
		0x1E736FE54AC4A35FULL,
		0xB6CD02410F602926ULL,
		0x616205489D2FBB1FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7FE9324908D69120ULL,
			0x1E736FE54AC4A35FULL,
			0xB6CD02410F602926ULL,
			0x616205489D2FBB1FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF23DD0E5B1F442B9ULL,
			0xB4C4F1087B5277CEULL,
			0xFF21D0C60BB5757BULL,
			0x4B875B532261F9FCULL}
		},
		.Z = {.key64 = {
			0x6762F553A1300FBAULL,
			0x7D63977D629E9396ULL,
			0xC5CC0D47759F0157ULL,
			0x1B3E89FA0E746B65ULL}
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

	steps = 25;
	X1 = (curve25519_key_t){.key64 = {
		0x2B3FE94759A5FE00ULL,
		0x59F71DFC96738271ULL,
		0xA9FEF521EC84ABEAULL,
		0x57B7A8C36A18DBE5ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2B3FE94759A5FE00ULL,
			0x59F71DFC96738271ULL,
			0xA9FEF521EC84ABEAULL,
			0x57B7A8C36A18DBE5ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x468A2434512AB1DAULL,
			0x9311A5675FED8A74ULL,
			0xB68A636AEAAD6335ULL,
			0x5B7989A28F534622ULL}
		},
		.Z = {.key64 = {
			0x48D6049C731E9C4BULL,
			0xB0C52AFC398B752DULL,
			0x36D0A10BC0A89C19ULL,
			0x23BD0D72B58247F2ULL}
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

	steps = 18;
	X1 = (curve25519_key_t){.key64 = {
		0xBEB68212E3543568ULL,
		0x0F0ED0D196EF518FULL,
		0x40162BFA62594DAEULL,
		0x5576B481FE83F2EDULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBEB68212E3543568ULL,
			0x0F0ED0D196EF518FULL,
			0x40162BFA62594DAEULL,
			0x5576B481FE83F2EDULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x85EE33CD715264B2ULL,
			0xC419936CF5B95208ULL,
			0x6A7D18D675921C35ULL,
			0x72D1F24E26EE06D9ULL}
		},
		.Z = {.key64 = {
			0x0E22E4D18AB12007ULL,
			0x6F3CECAD269E9081ULL,
			0x06A128BCAD4F79BAULL,
			0x4CC65D25950C007EULL}
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

	steps = 15;
	X1 = (curve25519_key_t){.key64 = {
		0x90E6F7D33F3FEA98ULL,
		0x4848BFB69CDCA3D2ULL,
		0x13B439E9A14CD63AULL,
		0x4A4C87B7DC3A9B92ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x90E6F7D33F3FEA98ULL,
			0x4848BFB69CDCA3D2ULL,
			0x13B439E9A14CD63AULL,
			0x4A4C87B7DC3A9B92ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xECA1D3C82E7C7324ULL,
			0xE34A3BD19C19E56FULL,
			0x14267F39FCA8B35BULL,
			0x44A61EBFBC7B9FD7ULL}
		},
		.Z = {.key64 = {
			0x9EA486366861618CULL,
			0x10F6B70707B6A924ULL,
			0xC2F23946056A2DBEULL,
			0x0F41E5D7A0C47F8DULL}
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

	steps = 53;
	X1 = (curve25519_key_t){.key64 = {
		0x3C264ED179463268ULL,
		0xB93B2DA9A009CAE3ULL,
		0x43B0738583511C35ULL,
		0x598DD6A051350A82ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3C264ED179463268ULL,
			0xB93B2DA9A009CAE3ULL,
			0x43B0738583511C35ULL,
			0x598DD6A051350A82ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAE28F741976F5CCFULL,
			0xE52B5A4DF4C7312BULL,
			0xB83749BD7B6EFDDFULL,
			0x5654710856BCAE60ULL}
		},
		.Z = {.key64 = {
			0xC258EDF912F1B6ABULL,
			0x133E8AA36AB747B4ULL,
			0x9B6C9AF86341ADEEULL,
			0x71DCE7DA04D849AAULL}
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

	steps = 40;
	X1 = (curve25519_key_t){.key64 = {
		0x6408A0DA7B6EB7C8ULL,
		0xB96C7236A558539EULL,
		0x150EA69B60222159ULL,
		0x7FE050A843706DBFULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6408A0DA7B6EB7C8ULL,
			0xB96C7236A558539EULL,
			0x150EA69B60222159ULL,
			0x7FE050A843706DBFULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA6613F54D43934A8ULL,
			0x66FFB91C657C9FBAULL,
			0x1D5FE498B405A147ULL,
			0x65B0CAFA1BF5A4D1ULL}
		},
		.Z = {.key64 = {
			0xECCC4F6A3922F319ULL,
			0x326D42401BCE7388ULL,
			0x91D6B65AF0F75833ULL,
			0x04AA1825E3D71CB6ULL}
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

	steps = 26;
	X1 = (curve25519_key_t){.key64 = {
		0x57F64B681789C048ULL,
		0x6A6BCB1F632BA93EULL,
		0x23FBC2A9F25666FAULL,
		0x64BF261411384DE6ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x57F64B681789C048ULL,
			0x6A6BCB1F632BA93EULL,
			0x23FBC2A9F25666FAULL,
			0x64BF261411384DE6ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7EBDAD941CDD25F8ULL,
			0xDBDA84A2CACFD672ULL,
			0x71670C30A8A84BF9ULL,
			0x14AFFB0C8EDAD371ULL}
		},
		.Z = {.key64 = {
			0x9E801B73DF2C9C01ULL,
			0xC1198227257F447BULL,
			0x3DD10083FD763923ULL,
			0x1ECDF9168820D1FCULL}
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

	steps = 26;
	X1 = (curve25519_key_t){.key64 = {
		0xB3DE04DD6E59C9D8ULL,
		0x13DD149236AC3C17ULL,
		0x9D47FC19482996B8ULL,
		0x55B194CE403708A6ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB3DE04DD6E59C9D8ULL,
			0x13DD149236AC3C17ULL,
			0x9D47FC19482996B8ULL,
			0x55B194CE403708A6ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x09BEEFEEF0028B77ULL,
			0xB69B7016B0A72486ULL,
			0x6F47F9A8334CFD53ULL,
			0x317D324246FF99F0ULL}
		},
		.Z = {.key64 = {
			0x249207E5AD5B62D6ULL,
			0x7FB62153F562B39CULL,
			0x3B84F25C3335FEDDULL,
			0x777D9943C29C55D5ULL}
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

	steps = 57;
	X1 = (curve25519_key_t){.key64 = {
		0x67E37F7E72FF1EE0ULL,
		0x2C24CF5483884A57ULL,
		0x368B566D9F7ED8D1ULL,
		0x41FCDF4C191287BBULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x67E37F7E72FF1EE0ULL,
			0x2C24CF5483884A57ULL,
			0x368B566D9F7ED8D1ULL,
			0x41FCDF4C191287BBULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5BC080F2E7617283ULL,
			0x6F91A76DF74A54DCULL,
			0x71BDE08EB58F4B3CULL,
			0x5A505A6659C3AE81ULL}
		},
		.Z = {.key64 = {
			0x54EADA0EF9CADE7CULL,
			0x5A284C53C8D71D92ULL,
			0x7328343F35FF53D0ULL,
			0x5C0D1AACFD44C56BULL}
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

	steps = 19;
	X1 = (curve25519_key_t){.key64 = {
		0xEC508B50CB8C4510ULL,
		0x0F386E4CAE6F03F9ULL,
		0x47A9B010EB0300D2ULL,
		0x587D822D0BAE6E31ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEC508B50CB8C4510ULL,
			0x0F386E4CAE6F03F9ULL,
			0x47A9B010EB0300D2ULL,
			0x587D822D0BAE6E31ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0C6AA22525A0F67BULL,
			0x4CCD51DA9B29C527ULL,
			0x1E6AAEB4D648449CULL,
			0x69730F6F8CB2B6BEULL}
		},
		.Z = {.key64 = {
			0x4F73A23A2E6C0C53ULL,
			0x92E02A6829A04C3EULL,
			0xD395D551C8C582A0ULL,
			0x06E787C46BD84F2AULL}
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

	steps = 14;
	X1 = (curve25519_key_t){.key64 = {
		0xFBAAAE84A9A225F8ULL,
		0xBF97218D43CBC795ULL,
		0x32517A0F986020D5ULL,
		0x65EB1E7B08888081ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFBAAAE84A9A225F8ULL,
			0xBF97218D43CBC795ULL,
			0x32517A0F986020D5ULL,
			0x65EB1E7B08888081ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x187338F34C02DE5BULL,
			0x5DC9EDA848A09465ULL,
			0x7BAB43E2F8E6D1CAULL,
			0x7376D1B8252FA304ULL}
		},
		.Z = {.key64 = {
			0x5AB4E6115597F708ULL,
			0x19683225B2BD9FB0ULL,
			0xAE3FFCE5DCA4E27FULL,
			0x701B9F7A3167E7EEULL}
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

	steps = 12;
	X1 = (curve25519_key_t){.key64 = {
		0xF6828BD2A2832500ULL,
		0xAB474FDC471B6AD6ULL,
		0x8B2CDAE7E02766E8ULL,
		0x41C9EDB83398B2A2ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF6828BD2A2832500ULL,
			0xAB474FDC471B6AD6ULL,
			0x8B2CDAE7E02766E8ULL,
			0x41C9EDB83398B2A2ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF0876A171491BA98ULL,
			0x1234933035E9458BULL,
			0x3284BF1949B9D3ACULL,
			0x009C1ED7F7314423ULL}
		},
		.Z = {.key64 = {
			0x51F517612603A614ULL,
			0x92D8E8FB8D07CF84ULL,
			0x11FCB4A83D1FE6B3ULL,
			0x011E7F32A1DD040AULL}
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
		0x68F7BC3902B6C330ULL,
		0xA8319A5F596290D3ULL,
		0xF04C9A84352E1994ULL,
		0x6D07CD3C6C55746DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x68F7BC3902B6C330ULL,
			0xA8319A5F596290D3ULL,
			0xF04C9A84352E1994ULL,
			0x6D07CD3C6C55746DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x29B8920A39922D25ULL,
			0x446BC0D4E804BAD0ULL,
			0x85C27F2188095F08ULL,
			0x1B92854602FDF117ULL}
		},
		.Z = {.key64 = {
			0xB3BA8020912F8D99ULL,
			0x28526255A0B435F7ULL,
			0x6898F306DF76C554ULL,
			0x1D6FF99EC3F29383ULL}
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

	steps = 37;
	X1 = (curve25519_key_t){.key64 = {
		0x14CE509F21F527A0ULL,
		0xDAD85DDDA5B0D424ULL,
		0x3C0FC062C2F62A92ULL,
		0x75A71819C5FAF929ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x14CE509F21F527A0ULL,
			0xDAD85DDDA5B0D424ULL,
			0x3C0FC062C2F62A92ULL,
			0x75A71819C5FAF929ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3EF459B68399F974ULL,
			0x084FDFD337DE1F85ULL,
			0x5FE1D33539B4F7A6ULL,
			0x16B91B160F85A759ULL}
		},
		.Z = {.key64 = {
			0x10F33D044A932DAAULL,
			0x27D3795403F64721ULL,
			0xB43BA245D16D9490ULL,
			0x5084B987E237A310ULL}
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

	steps = 1;
	X1 = (curve25519_key_t){.key64 = {
		0x738E4198B0041648ULL,
		0xB1AACBC8E0F2C083ULL,
		0xC2E8CACAB635F7A6ULL,
		0x5B661EA71E707833ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x738E4198B0041648ULL,
			0xB1AACBC8E0F2C083ULL,
			0xC2E8CACAB635F7A6ULL,
			0x5B661EA71E707833ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7C61A01E186A2E57ULL,
			0x70540ED096F65BAFULL,
			0x99C3A0BA50E55500ULL,
			0x595CE943B233BC3AULL}
		},
		.Z = {.key64 = {
			0xCE390662C0105946ULL,
			0xC6AB2F2383CB020DULL,
			0x0BA32B2AD8D7DE9AULL,
			0x6D987A9C79C1E0CFULL}
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

	steps = 14;
	X1 = (curve25519_key_t){.key64 = {
		0x1DAD2690D9D46730ULL,
		0x3A354317D1ACA58EULL,
		0x3745CD97D1F7D790ULL,
		0x46F54296292CD873ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1DAD2690D9D46730ULL,
			0x3A354317D1ACA58EULL,
			0x3745CD97D1F7D790ULL,
			0x46F54296292CD873ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x026F9EC23BE03885ULL,
			0x8C580CA9A881D6BEULL,
			0x1FD40F663D4127F0ULL,
			0x06E41621A99B7E66ULL}
		},
		.Z = {.key64 = {
			0xE206D2141BDB4810ULL,
			0x57561D3008F639A9ULL,
			0x13B01FE7B1A2EE44ULL,
			0x5B08A286D4F67E02ULL}
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

	steps = 63;
	X1 = (curve25519_key_t){.key64 = {
		0x5A9E07D9411EDAC8ULL,
		0x9E2443F4D1C34274ULL,
		0x27309F073458F9E7ULL,
		0x7CAFABAE9B78FE99ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5A9E07D9411EDAC8ULL,
			0x9E2443F4D1C34274ULL,
			0x27309F073458F9E7ULL,
			0x7CAFABAE9B78FE99ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBF8362CCA8C1A572ULL,
			0x12955625B352DD97ULL,
			0x0E2006050EAEC3ECULL,
			0x602A5C71B5925613ULL}
		},
		.Z = {.key64 = {
			0x27228948FA50C3D3ULL,
			0xD2557E9CDCD41257ULL,
			0xB07DC8D1985C07FBULL,
			0x2A8080E7843A58E5ULL}
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

	steps = 63;
	X1 = (curve25519_key_t){.key64 = {
		0x97470FEE44843EA8ULL,
		0x2CCE2440FA97F754ULL,
		0x0EC676DDCB0B20CDULL,
		0x7D9D2D5CD9F8F824ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x97470FEE44843EA8ULL,
			0x2CCE2440FA97F754ULL,
			0x0EC676DDCB0B20CDULL,
			0x7D9D2D5CD9F8F824ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x85D2DF66EC647BD7ULL,
			0x1EB6FB22FB2472AFULL,
			0x66C2D0A63FA8118BULL,
			0x311BB2288818A21CULL}
		},
		.Z = {.key64 = {
			0x1178094D3AE6FF02ULL,
			0x38EAF75643440EF3ULL,
			0xCD998D77830A45B6ULL,
			0x1B9E325078DFAEA7ULL}
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

	steps = 36;
	X1 = (curve25519_key_t){.key64 = {
		0xD14E3FB645EB4A90ULL,
		0x9D01D21247701507ULL,
		0x99F1E8F219D11A39ULL,
		0x7EB0FFBCE1956AD3ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD14E3FB645EB4A90ULL,
			0x9D01D21247701507ULL,
			0x99F1E8F219D11A39ULL,
			0x7EB0FFBCE1956AD3ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8AB884D5C917B014ULL,
			0xD38656455D8ED478ULL,
			0x55A4C1FFC60E06E1ULL,
			0x5860FA08CA916310ULL}
		},
		.Z = {.key64 = {
			0xE38C4D9988855CC3ULL,
			0xFA8650A9F1B96E14ULL,
			0x58B296BE91C4F829ULL,
			0x6BA95B8748C0F624ULL}
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
		0x85111B991683EE38ULL,
		0xCB7C1E30EAB3480FULL,
		0x487FA8D0692AB05BULL,
		0x68EA347187767E30ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x85111B991683EE38ULL,
			0xCB7C1E30EAB3480FULL,
			0x487FA8D0692AB05BULL,
			0x68EA347187767E30ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8739ECC332818D46ULL,
			0x889CB1E8F6889E27ULL,
			0xB9EBC9EA00B90B3FULL,
			0x604B786032B72274ULL}
		},
		.Z = {.key64 = {
			0x4E31ADE5B5984A01ULL,
			0xFC99DA909000D750ULL,
			0x0CD57D72E3C8C101ULL,
			0x3E188115EE95EDCEULL}
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

	steps = 44;
	X1 = (curve25519_key_t){.key64 = {
		0x939F42BFA67A8C68ULL,
		0xEE07CE9241DD25EEULL,
		0x04D0DE752BB289D7ULL,
		0x7A9C512B877C0B3FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x939F42BFA67A8C68ULL,
			0xEE07CE9241DD25EEULL,
			0x04D0DE752BB289D7ULL,
			0x7A9C512B877C0B3FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2034C3EB49712ED8ULL,
			0xBFF85713F5EB1E05ULL,
			0x2082C861ED18FA33ULL,
			0x6D36992C6E69CF00ULL}
		},
		.Z = {.key64 = {
			0x821E09BC4554EDF9ULL,
			0xF8D014DEF85F3026ULL,
			0xE9FE54EF7F441F5FULL,
			0x62192F76096CAE14ULL}
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

	steps = 64;
	X1 = (curve25519_key_t){.key64 = {
		0x0FAC115CE6F18EE8ULL,
		0xAC88467E7C508F52ULL,
		0xE4E0196524CE6CEBULL,
		0x4A741D6EE5A18D73ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0FAC115CE6F18EE8ULL,
			0xAC88467E7C508F52ULL,
			0xE4E0196524CE6CEBULL,
			0x4A741D6EE5A18D73ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x513ADBCD0E7B6E9CULL,
			0xB926D3D933E7DA58ULL,
			0xD9BAB87563316D0EULL,
			0x4F28002E4798D2A7ULL}
		},
		.Z = {.key64 = {
			0x030AED4C11F6224CULL,
			0x328600503677B8DDULL,
			0xDA8FFD8B40852D1DULL,
			0x21E011DE3083A433ULL}
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

	steps = 21;
	X1 = (curve25519_key_t){.key64 = {
		0x05B10BBF8CF2D620ULL,
		0x2FDAE087B6196686ULL,
		0x099186EBE960274AULL,
		0x6E008F69590D6BE4ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x05B10BBF8CF2D620ULL,
			0x2FDAE087B6196686ULL,
			0x099186EBE960274AULL,
			0x6E008F69590D6BE4ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x605F0EFFED8FCED5ULL,
			0xF98F5AFA6A47EEF6ULL,
			0x1D4065618E1C6427ULL,
			0x4BE03F9B4DC296E3ULL}
		},
		.Z = {.key64 = {
			0x2B07742BFB8FEA2EULL,
			0x1CB626F560367083ULL,
			0xB61B119BA52C896CULL,
			0x32F091013F28F86DULL}
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

	steps = 13;
	X1 = (curve25519_key_t){.key64 = {
		0x6C7DD6698876F7F8ULL,
		0x3843BB11EB27D7B0ULL,
		0x3AC0B909125EAD51ULL,
		0x46261F4A8B118BE1ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6C7DD6698876F7F8ULL,
			0x3843BB11EB27D7B0ULL,
			0x3AC0B909125EAD51ULL,
			0x46261F4A8B118BE1ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x749E1FC142469460ULL,
			0x22B43DD563062F02ULL,
			0x312A65EC3ABD9D4BULL,
			0x69D9351459592D19ULL}
		},
		.Z = {.key64 = {
			0x9508F05185320D10ULL,
			0xD12A41821B3D2BFCULL,
			0x09271362105743C5ULL,
			0x5500AEA9A6A6FED0ULL}
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

	steps = 57;
	X1 = (curve25519_key_t){.key64 = {
		0xB8F7B01270D37F20ULL,
		0x6216055B2E082B47ULL,
		0x1E9F4461BB39C739ULL,
		0x7D74F27139249BD0ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB8F7B01270D37F20ULL,
			0x6216055B2E082B47ULL,
			0x1E9F4461BB39C739ULL,
			0x7D74F27139249BD0ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7A5A781AB4EDB5F4ULL,
			0x979AE6B44A370DB3ULL,
			0xAA0DD662F69B1CF3ULL,
			0x57062320A9AA3980ULL}
		},
		.Z = {.key64 = {
			0x6ED1AFEA7AB1A1B0ULL,
			0x0B72A2084E0E8B82ULL,
			0x1BD343F28CCD52DEULL,
			0x5BFC342B5276BAE8ULL}
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

	steps = 60;
	X1 = (curve25519_key_t){.key64 = {
		0x7302A02D035E80A0ULL,
		0x3CBD330FD4303BDAULL,
		0xB5E1625244A2736DULL,
		0x4426AD1045A833B1ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7302A02D035E80A0ULL,
			0x3CBD330FD4303BDAULL,
			0xB5E1625244A2736DULL,
			0x4426AD1045A833B1ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC99EA84436D03DF3ULL,
			0x5E2460B0BE2ECBCFULL,
			0xF1A49CCFF6455B43ULL,
			0x6888ADE685646B41ULL}
		},
		.Z = {.key64 = {
			0xF40364852A37A804ULL,
			0x013C28D620F355B3ULL,
			0xCD4AC00E7D371DD0ULL,
			0x6546736869A3F60EULL}
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

	steps = 13;
	X1 = (curve25519_key_t){.key64 = {
		0x8419D4ECAE7D6750ULL,
		0x869EA52EB5D289E8ULL,
		0xEDC6E37F80688283ULL,
		0x7923879710421AB1ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8419D4ECAE7D6750ULL,
			0x869EA52EB5D289E8ULL,
			0xEDC6E37F80688283ULL,
			0x7923879710421AB1ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF6F0AFEBC109F044ULL,
			0xEEE2802B32EE2278ULL,
			0x7DDA63D8607604D7ULL,
			0x578DA628FFB3016CULL}
		},
		.Z = {.key64 = {
			0xF9F896AC1B1A3A85ULL,
			0xCA2EA4DCB8406213ULL,
			0xD52D3FF8CA09A2A3ULL,
			0x5F4BE89E12E9D8E0ULL}
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

	steps = 25;
	X1 = (curve25519_key_t){.key64 = {
		0x757CA4C17AC78B38ULL,
		0x5C1B5756FA164749ULL,
		0x220DFB3B02D59438ULL,
		0x4BF51E360DEF6E57ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x757CA4C17AC78B38ULL,
			0x5C1B5756FA164749ULL,
			0x220DFB3B02D59438ULL,
			0x4BF51E360DEF6E57ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1E9115188088AB54ULL,
			0xD4651E7A9D4F879BULL,
			0xB97E794C13AEABB8ULL,
			0x0FDD228EEEB5B801ULL}
		},
		.Z = {.key64 = {
			0xD857F2E71A7AB2B8ULL,
			0x210602F92997A3DBULL,
			0x54C3F9E1591C7963ULL,
			0x2D77F6E6A4F9C494ULL}
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

	steps = 46;
	X1 = (curve25519_key_t){.key64 = {
		0xC04E74460B2ED000ULL,
		0xE95D3188B401D830ULL,
		0xCD9FB623B9351618ULL,
		0x69A15B2E15704172ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC04E74460B2ED000ULL,
			0xE95D3188B401D830ULL,
			0xCD9FB623B9351618ULL,
			0x69A15B2E15704172ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x55CF48E92A3DAEEAULL,
			0xB5154612D63B1960ULL,
			0x53D264BA4D4A4E96ULL,
			0x5A8550AD9F9341CFULL}
		},
		.Z = {.key64 = {
			0xBE34E970C145B14DULL,
			0xBABAD3ECB942328DULL,
			0x6C7DE2BC9A4BD5E4ULL,
			0x39CBCE0B081D00B6ULL}
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

	steps = 9;
	X1 = (curve25519_key_t){.key64 = {
		0xF56D24A84A068B60ULL,
		0x7E9996600A84A68BULL,
		0xC19CD228DFA586C5ULL,
		0x68AE80E6FAF2E428ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF56D24A84A068B60ULL,
			0x7E9996600A84A68BULL,
			0xC19CD228DFA586C5ULL,
			0x68AE80E6FAF2E428ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x629243F1E4CCC174ULL,
			0x0099E063DD4D69D0ULL,
			0x5BBB7B10A4941C47ULL,
			0x799DEFD47BFD6DABULL}
		},
		.Z = {.key64 = {
			0x75835F6902FEA658ULL,
			0x241A46D988769068ULL,
			0x6FC1F12AF6D9D182ULL,
			0x2249D31F1C7CDB50ULL}
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

	steps = 2;
	X1 = (curve25519_key_t){.key64 = {
		0xD6EA72F0007D4670ULL,
		0xB24D17D343A4EB21ULL,
		0x3577029636D878FEULL,
		0x686B64DC39CDBA74ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD6EA72F0007D4670ULL,
			0xB24D17D343A4EB21ULL,
			0x3577029636D878FEULL,
			0x686B64DC39CDBA74ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x579FD93D40F33B99ULL,
			0x9C7303F540C1314FULL,
			0x2B3A17CAB0F53593ULL,
			0x4ADF9DA5A9FA47D0ULL}
		},
		.Z = {.key64 = {
			0xEA718BF1978A037DULL,
			0x2B4178258F3354DBULL,
			0x9571132A2ED8D893ULL,
			0x787D29C014528CEEULL}
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

	steps = 61;
	X1 = (curve25519_key_t){.key64 = {
		0xC5BA99F2702DC498ULL,
		0x0952906203DC7C01ULL,
		0x4739850C245CDB9EULL,
		0x70F5C877634879C0ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC5BA99F2702DC498ULL,
			0x0952906203DC7C01ULL,
			0x4739850C245CDB9EULL,
			0x70F5C877634879C0ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6CC8231B096EE926ULL,
			0xAA4F9832F4645B7CULL,
			0xA3B44ABFDD80BCF2ULL,
			0x71AC1909B576D09FULL}
		},
		.Z = {.key64 = {
			0x391378F6DFA1DDABULL,
			0xDE2100C5F2A89B6DULL,
			0x5DDB66394BDD5778ULL,
			0x27A372F36E4646DCULL}
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

	steps = 44;
	X1 = (curve25519_key_t){.key64 = {
		0xBD9A188606F2C1A0ULL,
		0xBC8E14FA5B8394DEULL,
		0xDF8EBC56F66A2DC7ULL,
		0x755E301FE2252A45ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBD9A188606F2C1A0ULL,
			0xBC8E14FA5B8394DEULL,
			0xDF8EBC56F66A2DC7ULL,
			0x755E301FE2252A45ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC35BB1A146C35260ULL,
			0x1F417FE0BEC07D03ULL,
			0xC2630094CEF782A2ULL,
			0x327FF350AD9B0B15ULL}
		},
		.Z = {.key64 = {
			0x4D86AAC7F97A3F74ULL,
			0x6A5215376D6BC42DULL,
			0x8E51A593B2AFD184ULL,
			0x325FE5CA3A16BC38ULL}
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

	steps = 4;
	X1 = (curve25519_key_t){.key64 = {
		0x1395468A23B24C98ULL,
		0x89C24C1BBCAA5094ULL,
		0xDD97F42FE4ACB580ULL,
		0x7C2F3CEC5F237D64ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1395468A23B24C98ULL,
			0x89C24C1BBCAA5094ULL,
			0xDD97F42FE4ACB580ULL,
			0x7C2F3CEC5F237D64ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6FBF6D504E0A055BULL,
			0xBCD4578B1817F446ULL,
			0x4739B955B73BF01FULL,
			0x1EFDF84D4B939674ULL}
		},
		.Z = {.key64 = {
			0x387F88F335739B5CULL,
			0xB088B0465CAFE2C8ULL,
			0xE54CCF55FEE91296ULL,
			0x23B512D35E7A2AD1ULL}
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

	steps = 51;
	X1 = (curve25519_key_t){.key64 = {
		0xA068652E94E070C8ULL,
		0xF7DC8FF705F9BBA2ULL,
		0x21FF411D5406E7D8ULL,
		0x75F739F244F0C94CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA068652E94E070C8ULL,
			0xF7DC8FF705F9BBA2ULL,
			0x21FF411D5406E7D8ULL,
			0x75F739F244F0C94CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x130025B2ECF2188FULL,
			0x18F6E8B8FA6C4859ULL,
			0xE0EA132D330B1633ULL,
			0x28ABF8F0CD110E70ULL}
		},
		.Z = {.key64 = {
			0xD9708A2DC5D626CAULL,
			0xCADCD7E63BEC998FULL,
			0x065E02044C4CCB16ULL,
			0x34D29414C30A9AA6ULL}
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

	steps = 2;
	X1 = (curve25519_key_t){.key64 = {
		0xD10B73CCCDBFE1F0ULL,
		0x0D05938D41B84D8FULL,
		0xCC755F153BE39176ULL,
		0x60228B767B3F7CD0ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD10B73CCCDBFE1F0ULL,
			0x0D05938D41B84D8FULL,
			0xCC755F153BE39176ULL,
			0x60228B767B3F7CD0ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x22BDF288E1E2883CULL,
			0x4F9B7320C1227C6DULL,
			0x457AF21514A64C12ULL,
			0x511EED2782039750ULL}
		},
		.Z = {.key64 = {
			0xC89580A1B3E0B923ULL,
			0x1E38B425B977671AULL,
			0xF47BDF823FB7A3EEULL,
			0x0D5143409F717790ULL}
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

	steps = 8;
	X1 = (curve25519_key_t){.key64 = {
		0x3E2CE287612DC9B8ULL,
		0xE68C3A2B3CDD0581ULL,
		0xCEBB3037EA226672ULL,
		0x5B9CA3E5E68F382EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3E2CE287612DC9B8ULL,
			0xE68C3A2B3CDD0581ULL,
			0xCEBB3037EA226672ULL,
			0x5B9CA3E5E68F382EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7D59E31E1DA69662ULL,
			0x40AE8080C4D12A00ULL,
			0x31A34F89470FB964ULL,
			0x106C6BFF395B5BE3ULL}
		},
		.Z = {.key64 = {
			0x76F2E6C590816E5AULL,
			0x2FC80265F6A932C0ULL,
			0x417C69CC343BC017ULL,
			0x687901CE87C671F2ULL}
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

	steps = 6;
	X1 = (curve25519_key_t){.key64 = {
		0xAD5E667D3ADC99C8ULL,
		0x7DA9CB64B41607C2ULL,
		0xDC368D8497F557E1ULL,
		0x412AD2D34A27BC93ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAD5E667D3ADC99C8ULL,
			0x7DA9CB64B41607C2ULL,
			0xDC368D8497F557E1ULL,
			0x412AD2D34A27BC93ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7CBF844922020B30ULL,
			0x3A284F207BDCF171ULL,
			0xAB609E0957673138ULL,
			0x35AD34BFE3602346ULL}
		},
		.Z = {.key64 = {
			0x2E1D4972D009DDAEULL,
			0x292893202A0441E9ULL,
			0xFA8A6ACAE0421FEAULL,
			0x1AE4D88024354718ULL}
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

	steps = 51;
	X1 = (curve25519_key_t){.key64 = {
		0x57587DDB7F2F42D0ULL,
		0x63488C45A763ED1FULL,
		0xE02C1807924DF3CEULL,
		0x4CFCE7611A4B1A50ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x57587DDB7F2F42D0ULL,
			0x63488C45A763ED1FULL,
			0xE02C1807924DF3CEULL,
			0x4CFCE7611A4B1A50ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAF4EB79F0F63F960ULL,
			0x6349711D03A5A285ULL,
			0xEF5CB4BC12D92746ULL,
			0x325C7C18B5599DDCULL}
		},
		.Z = {.key64 = {
			0xA3CF48BA404A3868ULL,
			0x9C327BB3AE73AB22ULL,
			0x8B360437E2DC0DF7ULL,
			0x0264687CD0E6BE2AULL}
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

	steps = 61;
	X1 = (curve25519_key_t){.key64 = {
		0x2D2FB43515299528ULL,
		0x40DA55C906315775ULL,
		0x9672F73BEA3A30B7ULL,
		0x50A51151CA335B60ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2D2FB43515299528ULL,
			0x40DA55C906315775ULL,
			0x9672F73BEA3A30B7ULL,
			0x50A51151CA335B60ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBF02671269740AB4ULL,
			0x1316C53157CA712FULL,
			0x0D67F85A472A78D0ULL,
			0x4E13D62E8D0EC3F3ULL}
		},
		.Z = {.key64 = {
			0xC922C027E8C159BAULL,
			0xAB619214AD39EA39ULL,
			0x1A54A788A366A546ULL,
			0x31CA5C3627514E2DULL}
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

	steps = 10;
	X1 = (curve25519_key_t){.key64 = {
		0xC4852D65FECFFDD8ULL,
		0x84BE6AF0FDEFB53BULL,
		0xE784D9D5CEBE5059ULL,
		0x67A543947A02FB5DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC4852D65FECFFDD8ULL,
			0x84BE6AF0FDEFB53BULL,
			0xE784D9D5CEBE5059ULL,
			0x67A543947A02FB5DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0D0E7DCD39FF31BCULL,
			0x4BF5B7F3FEFC0BE9ULL,
			0x120711C6F24519C7ULL,
			0x57B4EC829937B906ULL}
		},
		.Z = {.key64 = {
			0xE26EF1F4AD8C7721ULL,
			0x531013BEDF93FE4DULL,
			0x989482FEF28B3F26ULL,
			0x30DC2C4C0F11FFFCULL}
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

	steps = 1;
	X1 = (curve25519_key_t){.key64 = {
		0xB532495F99515F28ULL,
		0x48783A86EF702D33ULL,
		0x57CD1AB61851AA48ULL,
		0x53B6DAB5B53B66E1ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB532495F99515F28ULL,
			0x48783A86EF702D33ULL,
			0x57CD1AB61851AA48ULL,
			0x53B6DAB5B53B66E1ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x505657A91DA809ADULL,
			0x7E0585A4B28A51E7ULL,
			0xCC0DFC48EB22989EULL,
			0x23392A60CD6782C0ULL}
		},
		.Z = {.key64 = {
			0xD4C9257E65457CC6ULL,
			0x21E0EA1BBDC0B4CEULL,
			0x5F346AD86146A921ULL,
			0x4EDB6AD6D4ED9B85ULL}
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

	steps = 25;
	X1 = (curve25519_key_t){.key64 = {
		0xAEF98BB7DECEEC60ULL,
		0x5CCD660713992BD4ULL,
		0x5F883C9D148C46A9ULL,
		0x45F5954D0BA97AC6ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAEF98BB7DECEEC60ULL,
			0x5CCD660713992BD4ULL,
			0x5F883C9D148C46A9ULL,
			0x45F5954D0BA97AC6ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAB84A76B0C9BC2A5ULL,
			0x0CA6D89A2FB8BE0DULL,
			0x7E970E28BD6B5A58ULL,
			0x09C37215FC590EEAULL}
		},
		.Z = {.key64 = {
			0xEF759C04EB756EA5ULL,
			0x8EA13E573DA25D97ULL,
			0xE86B2481DCFF6CE1ULL,
			0x193726354B13AC98ULL}
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

	steps = 32;
	X1 = (curve25519_key_t){.key64 = {
		0xBF0892C6000F4D10ULL,
		0x6E015F2953A62E58ULL,
		0xFC286A924C8A9B89ULL,
		0x75EE35098BD36A12ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBF0892C6000F4D10ULL,
			0x6E015F2953A62E58ULL,
			0xFC286A924C8A9B89ULL,
			0x75EE35098BD36A12ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCDF2EADA2D29085BULL,
			0xE34D3CFD5687E04FULL,
			0x058A293663C2C5D3ULL,
			0x2F84230105CA6DC8ULL}
		},
		.Z = {.key64 = {
			0xD2EF66B87A3AFE22ULL,
			0x889CA0959FD92682ULL,
			0xBFD49672CE9061EFULL,
			0x6E81D52CAD5B0342ULL}
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

	steps = 19;
	X1 = (curve25519_key_t){.key64 = {
		0x092AA41921F19160ULL,
		0x1BFBCF643232DF3FULL,
		0xB43793CA3C564526ULL,
		0x78499B4B276D81DBULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x092AA41921F19160ULL,
			0x1BFBCF643232DF3FULL,
			0xB43793CA3C564526ULL,
			0x78499B4B276D81DBULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF28CFF18CD9EDEEFULL,
			0x9384D4ABF64BF52FULL,
			0x3A56ABCA58EC0A3EULL,
			0x764EED23021EAD11ULL}
		},
		.Z = {.key64 = {
			0x3DDAE93B803D1AECULL,
			0x928D1C2FD275EAB0ULL,
			0xFA72B8F541C806F4ULL,
			0x375D3F4328E9BACDULL}
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

	steps = 2;
	X1 = (curve25519_key_t){.key64 = {
		0x92737372E03DF038ULL,
		0x873C2CF0CF1F95BCULL,
		0x30F07F0AB45D9C64ULL,
		0x74168C1B3A21236EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x92737372E03DF038ULL,
			0x873C2CF0CF1F95BCULL,
			0x30F07F0AB45D9C64ULL,
			0x74168C1B3A21236EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8D9A2A8324439A2EULL,
			0xB1DB534B66C45EE8ULL,
			0xC9302E7745BF4FD2ULL,
			0x1231CC677DA06C6FULL}
		},
		.Z = {.key64 = {
			0x793A295E7C902252ULL,
			0x8196B1AB05DCCBD4ULL,
			0xD18B4C188977A86FULL,
			0x26EC1713438784F3ULL}
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

	steps = 18;
	X1 = (curve25519_key_t){.key64 = {
		0xE8E8AF004AFC96F0ULL,
		0xE82D48FF2A207E3FULL,
		0x5AD4F25535862230ULL,
		0x44A473D1256FD0C4ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE8E8AF004AFC96F0ULL,
			0xE82D48FF2A207E3FULL,
			0x5AD4F25535862230ULL,
			0x44A473D1256FD0C4ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE6DB3AB8316BCDEFULL,
			0x625B6A1A5D6A4EF4ULL,
			0x804D6C0F9A0EF88DULL,
			0x51C12F60D13909F4ULL}
		},
		.Z = {.key64 = {
			0x990A892276DCB068ULL,
			0x8E820680514EB1D1ULL,
			0xF161D987045B7002ULL,
			0x0EB80C33A9303B9AULL}
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

	steps = 11;
	X1 = (curve25519_key_t){.key64 = {
		0x2DDF90E23F5A41C8ULL,
		0xCB26BA6408B96AFCULL,
		0x3158CD559D0611E4ULL,
		0x79AF341D532EE3E8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2DDF90E23F5A41C8ULL,
			0xCB26BA6408B96AFCULL,
			0x3158CD559D0611E4ULL,
			0x79AF341D532EE3E8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB0C21028735A310DULL,
			0x1ABBFE2B37A338BBULL,
			0x4E2A29491C123799ULL,
			0x74FA69B558B52398ULL}
		},
		.Z = {.key64 = {
			0xEBD89091F0A1FA74ULL,
			0x8EF0A6E94B31EC2FULL,
			0xB6D758A45CAA4970ULL,
			0x1B3E225910D79764ULL}
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

	steps = 60;
	X1 = (curve25519_key_t){.key64 = {
		0x61D78804CF2FE928ULL,
		0x395A748E8C2CE698ULL,
		0x26B8D4C15FA7BB6BULL,
		0x6003E6A93F50757CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x61D78804CF2FE928ULL,
			0x395A748E8C2CE698ULL,
			0x26B8D4C15FA7BB6BULL,
			0x6003E6A93F50757CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x900110A122A4A05FULL,
			0xCC9E8F12046B669AULL,
			0x951E6C92B4C0D0B5ULL,
			0x48DD6994A20EBAFAULL}
		},
		.Z = {.key64 = {
			0xDB71AFAEA3039918ULL,
			0xC928DA4611481072ULL,
			0x670CEA9FDAA31E0AULL,
			0x4A6B2F72BEE3D2DCULL}
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
		0x8F2B61513E285F38ULL,
		0x6CDBBB2D651E30AEULL,
		0xD60ADB8445FDA4EEULL,
		0x5BE3FC65299F716FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8F2B61513E285F38ULL,
			0x6CDBBB2D651E30AEULL,
			0xD60ADB8445FDA4EEULL,
			0x5BE3FC65299F716FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCCE94843895FD298ULL,
			0x26C625C3F116CEAEULL,
			0xB1847681896FB28FULL,
			0x59B38AC3220D8197ULL}
		},
		.Z = {.key64 = {
			0x593E41195E709A3FULL,
			0x4E40DC9D15AD7F57ULL,
			0x9DA444A0DBF586A7ULL,
			0x2927217831E27B61ULL}
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

	steps = 28;
	X1 = (curve25519_key_t){.key64 = {
		0x5F9A095AE8F30280ULL,
		0xBFFF305C67D179F8ULL,
		0x8FB532412701E99EULL,
		0x606CFA5161BB2C7AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5F9A095AE8F30280ULL,
			0xBFFF305C67D179F8ULL,
			0x8FB532412701E99EULL,
			0x606CFA5161BB2C7AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDD5A872BA8B43AABULL,
			0x495556CAF2FB84F6ULL,
			0x0DBCD7B207293AD6ULL,
			0x2ABF6E04364A8294ULL}
		},
		.Z = {.key64 = {
			0xEC5ABAFD029F7F43ULL,
			0xE91D35E39EB9246FULL,
			0xC98008C01D82C66AULL,
			0x3EA98F3231E4B79CULL}
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

	steps = 46;
	X1 = (curve25519_key_t){.key64 = {
		0xDB4F5EB3E272A3D0ULL,
		0xEA6C47F5BF06AC46ULL,
		0x09A81B9A415C6F38ULL,
		0x7F77A85E9848E33CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDB4F5EB3E272A3D0ULL,
			0xEA6C47F5BF06AC46ULL,
			0x09A81B9A415C6F38ULL,
			0x7F77A85E9848E33CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFECD7335C62A2244ULL,
			0x45952847879FBF2FULL,
			0x890D1B208D893E47ULL,
			0x711A4FBABE8DCA67ULL}
		},
		.Z = {.key64 = {
			0x6382387AB9273F53ULL,
			0xC9EFCA1E16ED6A72ULL,
			0x4D4B17D06153DF7AULL,
			0x02290CC1C89ECD5BULL}
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

	steps = 16;
	X1 = (curve25519_key_t){.key64 = {
		0x309D4D61F48412C0ULL,
		0x8C2A527C137D86FEULL,
		0x185611AF3A0A4065ULL,
		0x6248A3217729845DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x309D4D61F48412C0ULL,
			0x8C2A527C137D86FEULL,
			0x185611AF3A0A4065ULL,
			0x6248A3217729845DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x55445E5C136C9C80ULL,
			0x02D237DF1860EC43ULL,
			0x461C308816746B59ULL,
			0x64D5D3DC96ACCE33ULL}
		},
		.Z = {.key64 = {
			0xD6BF7B2D34387472ULL,
			0x4D36BCB8E98E02FFULL,
			0xBB65AA4F483C08EAULL,
			0x7B867AB43884D816ULL}
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

	steps = 17;
	X1 = (curve25519_key_t){.key64 = {
		0x5496B639CE59E828ULL,
		0x4FED4E653A3151F6ULL,
		0x146E61BAA92F7981ULL,
		0x5997349990D45009ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5496B639CE59E828ULL,
			0x4FED4E653A3151F6ULL,
			0x146E61BAA92F7981ULL,
			0x5997349990D45009ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBD1B42AED845084BULL,
			0x1982FD6989539736ULL,
			0x3E88908D16D37429ULL,
			0x174D702432140395ULL}
		},
		.Z = {.key64 = {
			0xA6E7FC408A2BE56CULL,
			0x41E2AE83267FA82BULL,
			0x58B3360BFFD1799CULL,
			0x2C3654239F47C4E7ULL}
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

	steps = 44;
	X1 = (curve25519_key_t){.key64 = {
		0xC4909F6A80B33150ULL,
		0x0C62E7E453E241FFULL,
		0x49AEDCAE371CEB0FULL,
		0x60158C572C382476ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC4909F6A80B33150ULL,
			0x0C62E7E453E241FFULL,
			0x49AEDCAE371CEB0FULL,
			0x60158C572C382476ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3FD6BD511A52337CULL,
			0xC6D796963FD0F286ULL,
			0x6CF326123502142DULL,
			0x4AEE6F458B2D50A8ULL}
		},
		.Z = {.key64 = {
			0xFE736E52A53D380DULL,
			0x3FF109F05280DF87ULL,
			0x815618F367D472A0ULL,
			0x7FB4908743FE4FBFULL}
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

	steps = 50;
	X1 = (curve25519_key_t){.key64 = {
		0xCC033875113B9F28ULL,
		0x10F0F952F4DDDDA3ULL,
		0x5797E9225E77128AULL,
		0x67791E565F01D3BCULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCC033875113B9F28ULL,
			0x10F0F952F4DDDDA3ULL,
			0x5797E9225E77128AULL,
			0x67791E565F01D3BCULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x67E8FB7202FC2BF4ULL,
			0x63519B5440CD1F8CULL,
			0x8271FA65450A8632ULL,
			0x1F9EFE36D2375C15ULL}
		},
		.Z = {.key64 = {
			0x4E1DE01BE14E45BCULL,
			0x5EA769808FD16149ULL,
			0x2656E3CF1216648CULL,
			0x13CDDB712E804E01ULL}
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

	steps = 9;
	X1 = (curve25519_key_t){.key64 = {
		0xE1E3130D9A7E1608ULL,
		0x1E07C450AE73FF2DULL,
		0x83EF19EA36762429ULL,
		0x7B7F6D2E401FC026ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE1E3130D9A7E1608ULL,
			0x1E07C450AE73FF2DULL,
			0x83EF19EA36762429ULL,
			0x7B7F6D2E401FC026ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE890CDBE0B36785CULL,
			0x5B826D426AE0B8EFULL,
			0xFEF8D6E90080B56DULL,
			0x62A1970E04A95973ULL}
		},
		.Z = {.key64 = {
			0x798D2F9089B15F05ULL,
			0xE0B48DBDD15F022AULL,
			0xDECB6F237D89D922ULL,
			0x162E4BEF3F51D287ULL}
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

	steps = 16;
	X1 = (curve25519_key_t){.key64 = {
		0xB541CC88EDF7B428ULL,
		0x8141C1F998744A7AULL,
		0xA779EF5DAEC34D3FULL,
		0x676AEADCCDA5840CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB541CC88EDF7B428ULL,
			0x8141C1F998744A7AULL,
			0xA779EF5DAEC34D3FULL,
			0x676AEADCCDA5840CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5F1DA90EB87FC668ULL,
			0x0CFAEC69EE3B8605ULL,
			0xE38536390D89342DULL,
			0x4F0C034BE679397BULL}
		},
		.Z = {.key64 = {
			0xEAA23EE2BD9ED716ULL,
			0x6CC43CB8528F47E9ULL,
			0x71863118E2C0036BULL,
			0x30362AB89BAD1E7AULL}
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

	steps = 48;
	X1 = (curve25519_key_t){.key64 = {
		0x46E2CFD492B38710ULL,
		0xA74DA9ADB725D7A2ULL,
		0xEEAA78312728089DULL,
		0x609EE98CE1D89000ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x46E2CFD492B38710ULL,
			0xA74DA9ADB725D7A2ULL,
			0xEEAA78312728089DULL,
			0x609EE98CE1D89000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB5EBD5B556A6EEF7ULL,
			0x8C9C92C1BD87E15BULL,
			0xDAA69C6E2F6350E7ULL,
			0x0004B00FB339D068ULL}
		},
		.Z = {.key64 = {
			0x7CD4E6A876A8EC9FULL,
			0xFE15C66E0F5A291AULL,
			0x45011FBA524531CDULL,
			0x28B5B9B77E65EAC1ULL}
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

	steps = 62;
	X1 = (curve25519_key_t){.key64 = {
		0x14540A5018EDF868ULL,
		0x14F7814747D9E216ULL,
		0x52F0842B4E51D55DULL,
		0x42E4DCFDCB6DFF7BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x14540A5018EDF868ULL,
			0x14F7814747D9E216ULL,
			0x52F0842B4E51D55DULL,
			0x42E4DCFDCB6DFF7BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDEC735C4DA955E79ULL,
			0x1ADED95F84BBDBFDULL,
			0x13DEA68B3274FB70ULL,
			0x09D78F4512531504ULL}
		},
		.Z = {.key64 = {
			0xFAE66BB6D0429B62ULL,
			0x79345D96DD3ACBB7ULL,
			0x3D6EE07A92482F85ULL,
			0x6D3EE793D35E5F4BULL}
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

	steps = 8;
	X1 = (curve25519_key_t){.key64 = {
		0xFE6F9F34BA930020ULL,
		0xF5F3DD68FF6C2370ULL,
		0xC2CE9838C997409BULL,
		0x662B2210636AFBEDULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFE6F9F34BA930020ULL,
			0xF5F3DD68FF6C2370ULL,
			0xC2CE9838C997409BULL,
			0x662B2210636AFBEDULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6D248C63523C81EAULL,
			0x0B9A9239A26D3572ULL,
			0x915958FE085538E7ULL,
			0x2173EFB4B97CAF06ULL}
		},
		.Z = {.key64 = {
			0x527ABC20174AFB33ULL,
			0x7A2148B583C4D1C1ULL,
			0xBDB9EFC82B66AC73ULL,
			0x216C116174A2EBDDULL}
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

	steps = 56;
	X1 = (curve25519_key_t){.key64 = {
		0x7D776CAE89931078ULL,
		0xE1EB28436EA7CF41ULL,
		0x0B22D58EA431FF37ULL,
		0x61C14A8BB16C259CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7D776CAE89931078ULL,
			0xE1EB28436EA7CF41ULL,
			0x0B22D58EA431FF37ULL,
			0x61C14A8BB16C259CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x78FA7A6C87064B70ULL,
			0x10505BDFF7F3922DULL,
			0x04173245F88BA9F1ULL,
			0x049D3CEE1E7FCA0DULL}
		},
		.Z = {.key64 = {
			0xE3F4CA2EEA2A14D7ULL,
			0xDBB0F2B8C1543CA3ULL,
			0x0EE1E1F8E3F01E0DULL,
			0x167E62B102383CDCULL}
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

	steps = 64;
	X1 = (curve25519_key_t){.key64 = {
		0x521B1C61CE546698ULL,
		0x27BB6C00951D0270ULL,
		0x03F0182256265F4DULL,
		0x424913292BEE4F21ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x521B1C61CE546698ULL,
			0x27BB6C00951D0270ULL,
			0x03F0182256265F4DULL,
			0x424913292BEE4F21ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEAEB91118C30AE53ULL,
			0xF0A61506CC18C970ULL,
			0x2C524C8645DD39BFULL,
			0x2FA6353492EB295DULL}
		},
		.Z = {.key64 = {
			0xED66A81A1840C4CEULL,
			0x934C42334F8BAB03ULL,
			0x0C7DA799474436A3ULL,
			0x645BC5906BDBD6A0ULL}
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

	steps = 18;
	X1 = (curve25519_key_t){.key64 = {
		0x4AD885FFD68D22E8ULL,
		0xE3F64FE0D1F0BDB3ULL,
		0xBE7B0F7EDE0D0118ULL,
		0x5D2F83681CF6E394ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4AD885FFD68D22E8ULL,
			0xE3F64FE0D1F0BDB3ULL,
			0xBE7B0F7EDE0D0118ULL,
			0x5D2F83681CF6E394ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB45036856834CFA7ULL,
			0x306BD4393522739EULL,
			0x178DE7509D0B4B45ULL,
			0x725F30FEA097BA68ULL}
		},
		.Z = {.key64 = {
			0xB290DF2648A59E20ULL,
			0x8F546E1E2053EDBDULL,
			0x6A8B3B3AACE0C70AULL,
			0x693C5AB49683B724ULL}
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

	steps = 14;
	X1 = (curve25519_key_t){.key64 = {
		0x2834443C9BE73D20ULL,
		0x9D0A4A7321C6E98CULL,
		0x673CAC79853E5423ULL,
		0x4B4542B13ACA89C6ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2834443C9BE73D20ULL,
			0x9D0A4A7321C6E98CULL,
			0x673CAC79853E5423ULL,
			0x4B4542B13ACA89C6ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB75FAC83FFAE33CEULL,
			0xFE2BA294C2DEC419ULL,
			0xD00C244FE6F9FAC8ULL,
			0x0F82BB5377CB222CULL}
		},
		.Z = {.key64 = {
			0x10709425A060D023ULL,
			0xD386794D3223C5A5ULL,
			0x6574DF21307A1E07ULL,
			0x20E14967C467ED70ULL}
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

	steps = 1;
	X1 = (curve25519_key_t){.key64 = {
		0x3369194E0FD0EA50ULL,
		0x0F86F6D0002178F0ULL,
		0xDEBA62723D84927AULL,
		0x4F88BCE1F57A3B8EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3369194E0FD0EA50ULL,
			0x0F86F6D0002178F0ULL,
			0xDEBA62723D84927AULL,
			0x4F88BCE1F57A3B8EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x996B5129FFF51ED3ULL,
			0x2CB4169DE0BF5D59ULL,
			0x52D285B67ED35320ULL,
			0x0A39B7A89EC85969ULL}
		},
		.Z = {.key64 = {
			0xCDA465383F43A966ULL,
			0x3E1BDB400085E3C0ULL,
			0x7AE989C8F61249E8ULL,
			0x3E22F387D5E8EE3BULL}
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

	steps = 22;
	X1 = (curve25519_key_t){.key64 = {
		0x131FCD689159CB40ULL,
		0x284AA91155D35D4BULL,
		0x67E717C9904342E4ULL,
		0x6894C5A314060CE5ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x131FCD689159CB40ULL,
			0x284AA91155D35D4BULL,
			0x67E717C9904342E4ULL,
			0x6894C5A314060CE5ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x794D8D2A0A72383CULL,
			0xCD7C42A3EC72805BULL,
			0x8DCAE23B44C55773ULL,
			0x082C9BF42B6511AFULL}
		},
		.Z = {.key64 = {
			0x229826DD77C4AB66ULL,
			0xE3B2EEFB8C93540CULL,
			0x8FD93C74A6841098ULL,
			0x309809C4FBA9EE35ULL}
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
		0xC32E1518B0C86E48ULL,
		0x9DD2967D4C447A4FULL,
		0x709A7D9DEBAE7FE5ULL,
		0x56857CC82667FF49ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC32E1518B0C86E48ULL,
			0x9DD2967D4C447A4FULL,
			0x709A7D9DEBAE7FE5ULL,
			0x56857CC82667FF49ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9862A6B20640E152ULL,
			0x3BC72E7EB636F09AULL,
			0xB72E1E018C37A996ULL,
			0x672E157E95BA062EULL}
		},
		.Z = {.key64 = {
			0x3E05C95AFB64FC11ULL,
			0x0D0B13B6EB562BD1ULL,
			0x91E9331FC019F969ULL,
			0x66BD558BD9AB9BE2ULL}
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

	steps = 16;
	X1 = (curve25519_key_t){.key64 = {
		0x44F4CF1E0E48F3D0ULL,
		0x0E195C64D3616C26ULL,
		0x2B1812E765EF8150ULL,
		0x4FDD556CA6217ED2ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x44F4CF1E0E48F3D0ULL,
			0x0E195C64D3616C26ULL,
			0x2B1812E765EF8150ULL,
			0x4FDD556CA6217ED2ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6B72211B29918D03ULL,
			0x17201A25C0752988ULL,
			0x3BA8FC107CDA9BC3ULL,
			0x36FBF1A6B03ABBD8ULL}
		},
		.Z = {.key64 = {
			0x0A09B759472D9457ULL,
			0x94B5DF8AB34A9FC5ULL,
			0xF23BD5D61742E1E3ULL,
			0x6993245B45525D8DULL}
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

	steps = 46;
	X1 = (curve25519_key_t){.key64 = {
		0x177F318AABA5EAD8ULL,
		0xCB0BA6FAF6B58C1BULL,
		0x27A7799804FA970CULL,
		0x5CBEA0FD1FF9CB4DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x177F318AABA5EAD8ULL,
			0xCB0BA6FAF6B58C1BULL,
			0x27A7799804FA970CULL,
			0x5CBEA0FD1FF9CB4DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3C59F360CC4CE4DEULL,
			0xD64B68F66E5AB274ULL,
			0x0C57D8D851650A99ULL,
			0x6531FE8EBBFFA70DULL}
		},
		.Z = {.key64 = {
			0xE6D4C32A9A95B232ULL,
			0x51EEDFE57C84BD00ULL,
			0x9D8D79465B797EE9ULL,
			0x296F9E440B7DB6B3ULL}
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

	steps = 34;
	X1 = (curve25519_key_t){.key64 = {
		0xC337793C4330AF30ULL,
		0x564AFD899301A0B5ULL,
		0xD0106B4CEBC37B21ULL,
		0x692ADD8D591452EAULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC337793C4330AF30ULL,
			0x564AFD899301A0B5ULL,
			0xD0106B4CEBC37B21ULL,
			0x692ADD8D591452EAULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3A98E69CCCBEC63DULL,
			0xB8358DC092A43727ULL,
			0x0C8B11B2AAEDFF30ULL,
			0x12249C87540D699FULL}
		},
		.Z = {.key64 = {
			0x2278FF545F1C1CDBULL,
			0x54441058F5102E49ULL,
			0xEE5FDB1F8615FCDEULL,
			0x351ED4CE51C22318ULL}
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

	steps = 29;
	X1 = (curve25519_key_t){.key64 = {
		0x30364E01202F8EA8ULL,
		0x724520E19F6B9C82ULL,
		0xBAFC96F8020839A2ULL,
		0x75F49ED4EB470D19ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x30364E01202F8EA8ULL,
			0x724520E19F6B9C82ULL,
			0xBAFC96F8020839A2ULL,
			0x75F49ED4EB470D19ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA5D506C93ECD49AFULL,
			0xE1189C7574557A6CULL,
			0x2F22FFB1617AB1A6ULL,
			0x72803EEE4E15F268ULL}
		},
		.Z = {.key64 = {
			0x9D8D23D4F4BEE22AULL,
			0x56D2269CD1ADB387ULL,
			0xA578E416BAD72D7AULL,
			0x42B66060671D2EBAULL}
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

	steps = 53;
	X1 = (curve25519_key_t){.key64 = {
		0x5DA39EF0C63DFC58ULL,
		0x390065845B7C1E37ULL,
		0x149689EA1ECF6EBFULL,
		0x4479D9D2090F2832ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5DA39EF0C63DFC58ULL,
			0x390065845B7C1E37ULL,
			0x149689EA1ECF6EBFULL,
			0x4479D9D2090F2832ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x89CF65C915618F86ULL,
			0xEED3E9F3676ABF89ULL,
			0x2BB83B301478D999ULL,
			0x5D7E7168CBDCA0D4ULL}
		},
		.Z = {.key64 = {
			0x7C59D2CDFA18789BULL,
			0xB60B76A01260ADB3ULL,
			0x7B287EEAFE33841CULL,
			0x3A01F7CCC1C241D5ULL}
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

	steps = 13;
	X1 = (curve25519_key_t){.key64 = {
		0x900C8DC15BA97378ULL,
		0x39C34AD11FDFDB04ULL,
		0x2C521403C62461C8ULL,
		0x6FD8896DA16EF76BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x900C8DC15BA97378ULL,
			0x39C34AD11FDFDB04ULL,
			0x2C521403C62461C8ULL,
			0x6FD8896DA16EF76BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD276F8CF2022E9FDULL,
			0xFBE4D92542DF2B36ULL,
			0x1AE48F0F709F418CULL,
			0x114A310295703605ULL}
		},
		.Z = {.key64 = {
			0xC3B182CC07A8E366ULL,
			0x858EBBDB08B12DCDULL,
			0x82846D41FCED7F45ULL,
			0x426A54847A77907AULL}
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

	steps = 36;
	X1 = (curve25519_key_t){.key64 = {
		0xA3C9005BB96B39A0ULL,
		0xFD8684E0E773EE56ULL,
		0xB5F6E05808506CCDULL,
		0x699090C48F6ADFDCULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA3C9005BB96B39A0ULL,
			0xFD8684E0E773EE56ULL,
			0xB5F6E05808506CCDULL,
			0x699090C48F6ADFDCULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBB71D3833FAECDF8ULL,
			0x922E15E0C7C16F4EULL,
			0x57F7A227AFD6DD3BULL,
			0x71702669FD76593FULL}
		},
		.Z = {.key64 = {
			0xCFD9843AF2D8584BULL,
			0xAFC651E1AB236EDFULL,
			0xF4EBD26AAF151E23ULL,
			0x1F31B8D2333CCB70ULL}
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

	steps = 33;
	X1 = (curve25519_key_t){.key64 = {
		0x412ED36B15ED5FE8ULL,
		0x1EA95528B9E86DF9ULL,
		0xDE68EEA65C9CD7ADULL,
		0x4C5DED08F670A0EEULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x412ED36B15ED5FE8ULL,
			0x1EA95528B9E86DF9ULL,
			0xDE68EEA65C9CD7ADULL,
			0x4C5DED08F670A0EEULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEF14AD02E79735BAULL,
			0xFC7EE7A301622D87ULL,
			0x8EB7B09E0A9D9DB0ULL,
			0x6BFDD1D5F605A75BULL}
		},
		.Z = {.key64 = {
			0x467502F602294147ULL,
			0x10D612B4A011ABD9ULL,
			0x60BE810FA0212FEDULL,
			0x3EDEA3CC6973C07BULL}
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

	steps = 46;
	X1 = (curve25519_key_t){.key64 = {
		0xEE3EE45E40BA5328ULL,
		0xC61210ADDD60AC47ULL,
		0xFAED8669D75EB227ULL,
		0x61A10476944403D6ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEE3EE45E40BA5328ULL,
			0xC61210ADDD60AC47ULL,
			0xFAED8669D75EB227ULL,
			0x61A10476944403D6ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x05E5DEF91C0C5119ULL,
			0xCBC188377E469BD7ULL,
			0x3C42A15F9DCFFB2DULL,
			0x7AAB09730A2C4AC2ULL}
		},
		.Z = {.key64 = {
			0x4212088C0818C0BFULL,
			0xC78F53A92899541DULL,
			0xB055CB4F63A9CC46ULL,
			0x0494234C88D6B17EULL}
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

	steps = 64;
	X1 = (curve25519_key_t){.key64 = {
		0x82E4AA682FBC7A88ULL,
		0x10209963F27FF5A7ULL,
		0x1ADD66BCB8BCF7ABULL,
		0x6530A317BEAD0A39ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x82E4AA682FBC7A88ULL,
			0x10209963F27FF5A7ULL,
			0x1ADD66BCB8BCF7ABULL,
			0x6530A317BEAD0A39ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x210C34CEDC747097ULL,
			0x47DCE4A1AD5C1490ULL,
			0x52A224D249999B0CULL,
			0x2D6FD60BBCA010CCULL}
		},
		.Z = {.key64 = {
			0x7B109C8B11B4D6BFULL,
			0x5B826DE0CF5B0D10ULL,
			0x09544F078DE4BB4FULL,
			0x0E5C4B212CE671F8ULL}
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

	steps = 49;
	X1 = (curve25519_key_t){.key64 = {
		0x86917E7BA70A1D58ULL,
		0xDED45075846BD058ULL,
		0xC836931316DF9DC3ULL,
		0x5FF30ABA0631EB9FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x86917E7BA70A1D58ULL,
			0xDED45075846BD058ULL,
			0xC836931316DF9DC3ULL,
			0x5FF30ABA0631EB9FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3ADB0E638309C4FAULL,
			0x002A4D8EDB2649ADULL,
			0x6AA3F466815B51ACULL,
			0x55910D62F450A5CCULL}
		},
		.Z = {.key64 = {
			0xEB3DC683BCD7D83CULL,
			0x84C2AF319A7716EBULL,
			0xC85E1431490A6BF9ULL,
			0x44C30D17BC2DA158ULL}
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

	steps = 8;
	X1 = (curve25519_key_t){.key64 = {
		0x2F5E7C12F5B287B8ULL,
		0xF734CF178A73EC1DULL,
		0x38F611F7682C4D2CULL,
		0x58A698844D44926CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2F5E7C12F5B287B8ULL,
			0xF734CF178A73EC1DULL,
			0x38F611F7682C4D2CULL,
			0x58A698844D44926CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9A45879EEE536BB1ULL,
			0x617C1077192AA4BBULL,
			0x1C7A75087FA42193ULL,
			0x66CB63C654E190B3ULL}
		},
		.Z = {.key64 = {
			0x38C7DAA07542BB6AULL,
			0x168FFCACAD230769ULL,
			0x807B2BBA542FD8AEULL,
			0x3BCFDA49795E732EULL}
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

	steps = 3;
	X1 = (curve25519_key_t){.key64 = {
		0xBB6C19EA8DF60E18ULL,
		0x895D385EE8A73D98ULL,
		0xAE8E9FE02C4F0680ULL,
		0x6E75EA715509FCA7ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBB6C19EA8DF60E18ULL,
			0x895D385EE8A73D98ULL,
			0xAE8E9FE02C4F0680ULL,
			0x6E75EA715509FCA7ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6685748516FF3A68ULL,
			0xF95BA4C25864FA1FULL,
			0xB3FDE2D75E32B837ULL,
			0x7B50004D05385F22ULL}
		},
		.Z = {.key64 = {
			0xDC271B48152037CFULL,
			0x4653CFE37728CFB5ULL,
			0xDD36099A85C76418ULL,
			0x108DA9020107B9E9ULL}
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

	steps = 29;
	X1 = (curve25519_key_t){.key64 = {
		0x811041A02B67B8A8ULL,
		0x87E9EE908F7D940BULL,
		0xE5C6B66DFB8C1F4BULL,
		0x7DD99A2035A8CE88ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x811041A02B67B8A8ULL,
			0x87E9EE908F7D940BULL,
			0xE5C6B66DFB8C1F4BULL,
			0x7DD99A2035A8CE88ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB638CEA2D248D7DAULL,
			0xC042686D87C0399FULL,
			0x90D3052AA4F3E2E8ULL,
			0x6149F749F32FAE1FULL}
		},
		.Z = {.key64 = {
			0xB5C5EE85D5554BC5ULL,
			0x04307F14141C1071ULL,
			0x664CF14DAF3FB43CULL,
			0x28ADCE29224D5E74ULL}
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

	steps = 24;
	X1 = (curve25519_key_t){.key64 = {
		0x7ECCFCEB92408578ULL,
		0xDA60E0EF5FBF4C87ULL,
		0x3429DB9B4E621D03ULL,
		0x467FD50DE9B2506AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7ECCFCEB92408578ULL,
			0xDA60E0EF5FBF4C87ULL,
			0x3429DB9B4E621D03ULL,
			0x467FD50DE9B2506AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x934984D4DAB22ECBULL,
			0x0CEADBC2AA34BAD9ULL,
			0x9BCE945990964E85ULL,
			0x0C6B07DE5AE251EFULL}
		},
		.Z = {.key64 = {
			0x263DE24BAABA039DULL,
			0xE54B2812E555418EULL,
			0x30B88F0B1C173B17ULL,
			0x46A55033BBD01D39ULL}
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

	steps = 3;
	X1 = (curve25519_key_t){.key64 = {
		0x52AEE1151C53BEA8ULL,
		0x5FE167812A490590ULL,
		0x934D9A21192FE8D6ULL,
		0x4864801DE1B3FD78ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x52AEE1151C53BEA8ULL,
			0x5FE167812A490590ULL,
			0x934D9A21192FE8D6ULL,
			0x4864801DE1B3FD78ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5F630F39F2417CD7ULL,
			0x247C3C05529D7250ULL,
			0x38D985900CFE3C09ULL,
			0x2B3265EC98DCE667ULL}
		},
		.Z = {.key64 = {
			0xD1D834B86399A6CAULL,
			0x7583502BDA8162C9ULL,
			0xCB4EFEF054FD5EB3ULL,
			0x26D9D6DAD3C3D8AEULL}
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

	steps = 4;
	X1 = (curve25519_key_t){.key64 = {
		0x427E9CE0A502D4F8ULL,
		0x4BFB70092B4EB0E9ULL,
		0x6D750AB2FB0606EAULL,
		0x5BC9FD740492390AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x427E9CE0A502D4F8ULL,
			0x4BFB70092B4EB0E9ULL,
			0x6D750AB2FB0606EAULL,
			0x5BC9FD740492390AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC7982798B56C5152ULL,
			0xB82581850D825A38ULL,
			0xB3E0BB22DBF2BE01ULL,
			0x5FD797C12F62D328ULL}
		},
		.Z = {.key64 = {
			0x46C3720199220B85ULL,
			0x6EC6D9722CE1CACDULL,
			0x3344942CB116A3E2ULL,
			0x2EC2ED4D0ADC1784ULL}
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

	steps = 24;
	X1 = (curve25519_key_t){.key64 = {
		0x49E61597FF9A0560ULL,
		0xA324DA741F5F3BC7ULL,
		0x7723AD19DDAF3767ULL,
		0x43EEC79919A87800ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x49E61597FF9A0560ULL,
			0xA324DA741F5F3BC7ULL,
			0x7723AD19DDAF3767ULL,
			0x43EEC79919A87800ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE2B70670143349A8ULL,
			0x2999A0B52051B3ECULL,
			0x1A7B115B6CDE2AEDULL,
			0x4C77C36FA7EF84AFULL}
		},
		.Z = {.key64 = {
			0x934A8035BAECBA78ULL,
			0xE0B12A5DB665DC91ULL,
			0x1EBECCBE09AA8926ULL,
			0x77722A25A0381EE3ULL}
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

	steps = 36;
	X1 = (curve25519_key_t){.key64 = {
		0xDEB1070B18029300ULL,
		0x81DE3E85A74041F2ULL,
		0x744FC37880AA6097ULL,
		0x74C3A7BB70D6F428ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDEB1070B18029300ULL,
			0x81DE3E85A74041F2ULL,
			0x744FC37880AA6097ULL,
			0x74C3A7BB70D6F428ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB5C81BAC03044F1CULL,
			0xCE496EB3FDFD0CC8ULL,
			0xE4719C619B2AFBADULL,
			0x5E4A947D3EE86B4CULL}
		},
		.Z = {.key64 = {
			0x4A5DAEAF2E5B5C52ULL,
			0x3681BB7230CA0E80ULL,
			0x4ECBD617B6187E99ULL,
			0x1B2503E3D0A715A5ULL}
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

	steps = 50;
	X1 = (curve25519_key_t){.key64 = {
		0xFA2A6C01A9573F58ULL,
		0x35CF3E3BF969CB79ULL,
		0x2987DEE41F81338AULL,
		0x75D402FB20759BF5ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFA2A6C01A9573F58ULL,
			0x35CF3E3BF969CB79ULL,
			0x2987DEE41F81338AULL,
			0x75D402FB20759BF5ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAB1FBB53DB5766D7ULL,
			0xD44A4EB56B0AC92BULL,
			0x02272F15104BAEBDULL,
			0x3555E88C2E5172E5ULL}
		},
		.Z = {.key64 = {
			0x563E42D8164306F5ULL,
			0x6F361CBAAA037CB1ULL,
			0xDEED4D9EED2A7C07ULL,
			0x31F40A0C631071E7ULL}
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

	steps = 1;
	X1 = (curve25519_key_t){.key64 = {
		0x2657C3B2438A53F0ULL,
		0x64B55DF94FCE3161ULL,
		0x97D892AAF827014FULL,
		0x76ACF64BE123BDE1ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2657C3B2438A53F0ULL,
			0x64B55DF94FCE3161ULL,
			0x97D892AAF827014FULL,
			0x76ACF64BE123BDE1ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x839507084281B6F8ULL,
			0x9FF54FC7944F4036ULL,
			0x91208AFFFFAAB61BULL,
			0x017921A887BDF3BAULL}
		},
		.Z = {.key64 = {
			0x995F0EC90E294FF9ULL,
			0x92D577E53F38C584ULL,
			0x5F624AABE09C053DULL,
			0x5AB3D92F848EF786ULL}
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

	steps = 15;
	X1 = (curve25519_key_t){.key64 = {
		0x7C693AB3F4258DD0ULL,
		0x9ADB319DCF7B3607ULL,
		0x647A57BBADBF53D4ULL,
		0x480C5B20FF6AC9A8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7C693AB3F4258DD0ULL,
			0x9ADB319DCF7B3607ULL,
			0x647A57BBADBF53D4ULL,
			0x480C5B20FF6AC9A8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD75A89FA6D1C41E1ULL,
			0x9321D503DC9A4C8EULL,
			0xE6C1BC2059FAC12BULL,
			0x4A621CD80B1F787EULL}
		},
		.Z = {.key64 = {
			0x52355674CA7A3313ULL,
			0x51FE8C33D0A7FFB0ULL,
			0xC3CF3E8351636371ULL,
			0x027D1FB5CD72D1FFULL}
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

	steps = 23;
	X1 = (curve25519_key_t){.key64 = {
		0x95859C10631A8B88ULL,
		0x22C8DE1E055F1934ULL,
		0xEEEE3C48C7ECAE9EULL,
		0x651E5144139BA549ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x95859C10631A8B88ULL,
			0x22C8DE1E055F1934ULL,
			0xEEEE3C48C7ECAE9EULL,
			0x651E5144139BA549ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x87B330B61ACAC1A9ULL,
			0x88BF72E3BEC1DF12ULL,
			0xFC0D080092D75199ULL,
			0x6922155E6CB77C6AULL}
		},
		.Z = {.key64 = {
			0x568A420243C63DA5ULL,
			0x1127C2012B4CDC7BULL,
			0x54E977409BD980BDULL,
			0x5C5AAC1EEA225542ULL}
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

	steps = 51;
	X1 = (curve25519_key_t){.key64 = {
		0x00EB6B7A416ABA88ULL,
		0x4229DAC6909AED4EULL,
		0xDE53AEDA378608C9ULL,
		0x7D6437BFCA3144C1ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x00EB6B7A416ABA88ULL,
			0x4229DAC6909AED4EULL,
			0xDE53AEDA378608C9ULL,
			0x7D6437BFCA3144C1ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0806941B989D5EB6ULL,
			0x1A5FF657707128C5ULL,
			0x60998177FE0715DCULL,
			0x0D2F6750D5F0AAAAULL}
		},
		.Z = {.key64 = {
			0xF6440B1CFB7CCA3EULL,
			0x98545F53CFEB438FULL,
			0x4CD6CF9BD09011C1ULL,
			0x43DAF5ADF813DBB7ULL}
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

	steps = 31;
	X1 = (curve25519_key_t){.key64 = {
		0xFA5BC7636D75D688ULL,
		0xB8526D09765E13CCULL,
		0x56E62662456D7CAAULL,
		0x60C44C78E392A43CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFA5BC7636D75D688ULL,
			0xB8526D09765E13CCULL,
			0x56E62662456D7CAAULL,
			0x60C44C78E392A43CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF9DA7C18B23A5546ULL,
			0xDDD3B81F53071941ULL,
			0x8877C36440038E66ULL,
			0x6871C8891E4FDCC5ULL}
		},
		.Z = {.key64 = {
			0x0E139A596F5C2B83ULL,
			0xBDE3440F86F37AD1ULL,
			0x83EDFDE921BF9688ULL,
			0x7844F3C6DDCBA5DCULL}
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

	steps = 28;
	X1 = (curve25519_key_t){.key64 = {
		0xF8176CC2BD7D17E0ULL,
		0x1362F944BA91576DULL,
		0x3A73EB73114374B0ULL,
		0x6E73DFD147B7E1C6ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF8176CC2BD7D17E0ULL,
			0x1362F944BA91576DULL,
			0x3A73EB73114374B0ULL,
			0x6E73DFD147B7E1C6ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x62BD0EFB129B676BULL,
			0x140D0AB01FCB982BULL,
			0x51E0BF080133DA8FULL,
			0x7FFECCF3ED493143ULL}
		},
		.Z = {.key64 = {
			0xE1B7ED40175EB36BULL,
			0xDF090E0ED00EF64AULL,
			0xEA6BA0FF59938FCCULL,
			0x018005F11B24F871ULL}
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

	steps = 54;
	X1 = (curve25519_key_t){.key64 = {
		0x0D810E818E2CD040ULL,
		0x1176A1989E69D775ULL,
		0xCC90D93F5A5C93BEULL,
		0x5F24F0072448C794ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0D810E818E2CD040ULL,
			0x1176A1989E69D775ULL,
			0xCC90D93F5A5C93BEULL,
			0x5F24F0072448C794ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4D579538A3F591D5ULL,
			0x58EED79A1FA045F1ULL,
			0x9EEE536CA44C0EEBULL,
			0x53254478063CCDEBULL}
		},
		.Z = {.key64 = {
			0x26287AEACBC52D19ULL,
			0x64A4F7F8BAEE4E72ULL,
			0xCAA0E15D1A8FBEF2ULL,
			0x68493035742D563AULL}
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

	steps = 37;
	X1 = (curve25519_key_t){.key64 = {
		0x8BBA1B75F26079C8ULL,
		0x491D0554E2738B2CULL,
		0xA5436DCA9F34BC99ULL,
		0x4156C332DE3C6526ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8BBA1B75F26079C8ULL,
			0x491D0554E2738B2CULL,
			0xA5436DCA9F34BC99ULL,
			0x4156C332DE3C6526ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x13C38FF6DD8B9D25ULL,
			0x595CE34797C84E84ULL,
			0xBE2F1E46A3F1EB78ULL,
			0x5EB5E3C78167F240ULL}
		},
		.Z = {.key64 = {
			0x68696A5D03781E53ULL,
			0x6804739A035682BDULL,
			0x2B97A428B4CF18F2ULL,
			0x6636C588738EBFE9ULL}
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

	steps = 60;
	X1 = (curve25519_key_t){.key64 = {
		0xE011C6BD3573DA70ULL,
		0x07B7786B28FCBD56ULL,
		0xC2C5428A9E7DFB97ULL,
		0x469EE304594B3553ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE011C6BD3573DA70ULL,
			0x07B7786B28FCBD56ULL,
			0xC2C5428A9E7DFB97ULL,
			0x469EE304594B3553ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x02A4B0CB919998E4ULL,
			0x5BAF6A082E048DEBULL,
			0xC39C74CC2EBA7B8DULL,
			0x2DD98D1EF83650ECULL}
		},
		.Z = {.key64 = {
			0x631B8A404F674BD9ULL,
			0xE65B2BD3B22C1227ULL,
			0x4E4B2B7CB9A6F697ULL,
			0x2CFF94A62D458953ULL}
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

	steps = 23;
	X1 = (curve25519_key_t){.key64 = {
		0xC89032D0BCC24830ULL,
		0x8577DAF8D6B8BEFEULL,
		0xA378F0033C33CF83ULL,
		0x729EDC9EAA3BA62DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC89032D0BCC24830ULL,
			0x8577DAF8D6B8BEFEULL,
			0xA378F0033C33CF83ULL,
			0x729EDC9EAA3BA62DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4511E011AED97C1BULL,
			0xC7F7CC25ED9D89D0ULL,
			0xDFE7E2C3673688A2ULL,
			0x34532D5EF2A90F0CULL}
		},
		.Z = {.key64 = {
			0x8FFA480D59C7C42FULL,
			0xF3261F7D524823FDULL,
			0x8207B5929473F3E9ULL,
			0x7F75016936A2C7C5ULL}
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

	steps = 51;
	X1 = (curve25519_key_t){.key64 = {
		0xD46A62F11F1FE7D0ULL,
		0xD0FA44418D7029E5ULL,
		0xA352899898E55022ULL,
		0x67756DDA78273119ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD46A62F11F1FE7D0ULL,
			0xD0FA44418D7029E5ULL,
			0xA352899898E55022ULL,
			0x67756DDA78273119ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFB83FD60D1DBDF15ULL,
			0x9989BCDD76BEE25FULL,
			0xF4CE353031CFA6AAULL,
			0x0970C9878E11826DULL}
		},
		.Z = {.key64 = {
			0x4971A2AF72AD9B44ULL,
			0x6C9F08CF76C87093ULL,
			0x4363625045407184ULL,
			0x6E76A69359AF7AB9ULL}
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

	steps = 55;
	X1 = (curve25519_key_t){.key64 = {
		0x8DBB1CF7A08970D8ULL,
		0xAAACA0D0D870D177ULL,
		0x3338AE458F230928ULL,
		0x5D43969465E86D86ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8DBB1CF7A08970D8ULL,
			0xAAACA0D0D870D177ULL,
			0x3338AE458F230928ULL,
			0x5D43969465E86D86ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4CE1C0BB8A10D0E3ULL,
			0x681F1A1E3F0DF528ULL,
			0xBD8ADCDCCCB1B617ULL,
			0x603794999DA65CE2ULL}
		},
		.Z = {.key64 = {
			0xA9C5F597D8CF8305ULL,
			0xD0E71647C04602DFULL,
			0x29893D2CCAF237AEULL,
			0x5F1A8B4DAFA45426ULL}
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
		0x2A2EE43CADBFE1C0ULL,
		0xC42E1108F1EB0CE5ULL,
		0x1DF267C4C0A0593AULL,
		0x708C8D4FADDA52C4ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2A2EE43CADBFE1C0ULL,
			0xC42E1108F1EB0CE5ULL,
			0x1DF267C4C0A0593AULL,
			0x708C8D4FADDA52C4ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2A830C5BC8C9F670ULL,
			0x3E4A7751804B43CBULL,
			0xD0DF8029F1D899A4ULL,
			0x1FBEA6431634AD61ULL}
		},
		.Z = {.key64 = {
			0x176CE52A853E238AULL,
			0x11748426D53F20E9ULL,
			0xB7DA2575D803A915ULL,
			0x364BAFD0CDACFF7AULL}
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

	steps = 26;
	X1 = (curve25519_key_t){.key64 = {
		0xF3233F4DFB016D38ULL,
		0x209D038402A3C82AULL,
		0x8F8D37A6423187F8ULL,
		0x6AE559550489825DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF3233F4DFB016D38ULL,
			0x209D038402A3C82AULL,
			0x8F8D37A6423187F8ULL,
			0x6AE559550489825DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x89292BF7F849EE7EULL,
			0xDD0CCCF90C275CCBULL,
			0x31D7052954CEA8BFULL,
			0x17A2FE5AC21EF03EULL}
		},
		.Z = {.key64 = {
			0x98A84D5AB5C23178ULL,
			0xCCA0C31AAB71664AULL,
			0x8095D58981D47D9CULL,
			0x5B566939A4B8CE1EULL}
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

	steps = 34;
	X1 = (curve25519_key_t){.key64 = {
		0xE86F16B40B846E08ULL,
		0x13C0E9B1C818526BULL,
		0x8B0B8027676CE964ULL,
		0x491149AC1B446D36ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE86F16B40B846E08ULL,
			0x13C0E9B1C818526BULL,
			0x8B0B8027676CE964ULL,
			0x491149AC1B446D36ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2C2BC68DCDF152B9ULL,
			0xA1C1556536B34CB9ULL,
			0x6020A80908D46DC4ULL,
			0x72628E47A7364856ULL}
		},
		.Z = {.key64 = {
			0x3BDB58B137360718ULL,
			0xD03E1E2F37CF5783ULL,
			0x179D5B2A7D77CE25ULL,
			0x3536B5541531AD82ULL}
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

	steps = 58;
	X1 = (curve25519_key_t){.key64 = {
		0x039119A7626220F8ULL,
		0x9DFAB2AEF98A5D39ULL,
		0x41A6E4D86701D59DULL,
		0x5BC8E9FEE8E1FA77ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x039119A7626220F8ULL,
			0x9DFAB2AEF98A5D39ULL,
			0x41A6E4D86701D59DULL,
			0x5BC8E9FEE8E1FA77ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4D32597151263F93ULL,
			0xFA92021698758E9EULL,
			0x7C1DF1956B2056A5ULL,
			0x4137FDDBA9F07FBEULL}
		},
		.Z = {.key64 = {
			0xE917DD9013E5D685ULL,
			0xDD2B2806BBE3A5E0ULL,
			0x031C7743ABB94D8CULL,
			0x62FDB5B5686D1125ULL}
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

	steps = 43;
	X1 = (curve25519_key_t){.key64 = {
		0xD5F0E5C781ECB790ULL,
		0xEB79B48284875EA8ULL,
		0xA32B6AFFAE8602F5ULL,
		0x7699AAA11D0D68F7ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD5F0E5C781ECB790ULL,
			0xEB79B48284875EA8ULL,
			0xA32B6AFFAE8602F5ULL,
			0x7699AAA11D0D68F7ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7AA0774B5F44267BULL,
			0x9DE11055441CFC09ULL,
			0x3E51EFF2EAEFB87BULL,
			0x4372011C20573C56ULL}
		},
		.Z = {.key64 = {
			0xB8CB1BD52478AE88ULL,
			0x84A877518C547A79ULL,
			0x847B4858AC6E8D92ULL,
			0x01DADE90002FD38CULL}
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

	steps = 44;
	X1 = (curve25519_key_t){.key64 = {
		0x009EEF64B2176550ULL,
		0x0E9B350278E9C689ULL,
		0xAA15EE8F139A160EULL,
		0x708BD93806E57DEBULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x009EEF64B2176550ULL,
			0x0E9B350278E9C689ULL,
			0xAA15EE8F139A160EULL,
			0x708BD93806E57DEBULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA3C1B63A74FE0B8EULL,
			0x91BE3F793C57AA57ULL,
			0x55125294C69A0136ULL,
			0x5BD6593B84A21747ULL}
		},
		.Z = {.key64 = {
			0x82052134C4D9083FULL,
			0xE243FCCAC0413828ULL,
			0xB9D977F3C7865777ULL,
			0x2BD2AD98F43D22E1ULL}
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

	steps = 19;
	X1 = (curve25519_key_t){.key64 = {
		0x7E52BB1B538A06C0ULL,
		0xCA15C30638394143ULL,
		0xCBA78C82A2E28490ULL,
		0x767951AE9FA84C37ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7E52BB1B538A06C0ULL,
			0xCA15C30638394143ULL,
			0xCBA78C82A2E28490ULL,
			0x767951AE9FA84C37ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x011BB046E69AF7B2ULL,
			0x846FA54470282301ULL,
			0xFCDAA91CE201ED50ULL,
			0x10CF68929F6B24B3ULL}
		},
		.Z = {.key64 = {
			0xCD61FBAA04BF70D6ULL,
			0x48AF8B03400D2581ULL,
			0xC2F594BFC166A760ULL,
			0x092553F2239E8F6EULL}
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

	steps = 11;
	X1 = (curve25519_key_t){.key64 = {
		0xB33F4EAD9E8B9C38ULL,
		0xCDF8657AD3FCEA01ULL,
		0x18C864F0E796B25EULL,
		0x5B9E7EAA24464D36ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB33F4EAD9E8B9C38ULL,
			0xCDF8657AD3FCEA01ULL,
			0x18C864F0E796B25EULL,
			0x5B9E7EAA24464D36ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x88E0C21D146A8D3EULL,
			0xB4E87A07ACAB5D09ULL,
			0xB2F850EE895F4E19ULL,
			0x3E391FBBFD6074AFULL}
		},
		.Z = {.key64 = {
			0x5C1EDE39A64617F6ULL,
			0xC2A5F81768A8F685ULL,
			0xC741339E0592AF9EULL,
			0x620CD908B0537081ULL}
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

	steps = 51;
	X1 = (curve25519_key_t){.key64 = {
		0x462FA41D1FCF5480ULL,
		0xF1A2289D4C208A74ULL,
		0xD09922D8FCAB1DC2ULL,
		0x51FDD1489F059865ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x462FA41D1FCF5480ULL,
			0xF1A2289D4C208A74ULL,
			0xD09922D8FCAB1DC2ULL,
			0x51FDD1489F059865ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x64A375E4115956ACULL,
			0xF323E51C1F958AE7ULL,
			0xDCDCAC0DA2AEB82EULL,
			0x6E5B0EA345F8E602ULL}
		},
		.Z = {.key64 = {
			0x24B36B7B265360A2ULL,
			0x6DC1C7AF4A32FAE4ULL,
			0x64DE6AE1E23D76F0ULL,
			0x5623F9095FABF0DEULL}
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
		0x06C23627D8AB17C0ULL,
		0x25FD14FD3C87EEC3ULL,
		0xE34BC441FD849273ULL,
		0x596DE2000DAAF742ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x06C23627D8AB17C0ULL,
			0x25FD14FD3C87EEC3ULL,
			0xE34BC441FD849273ULL,
			0x596DE2000DAAF742ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xADB2A836E4A9655BULL,
			0xFA4F33B228AAB5FBULL,
			0xCC2A05DB5354CB4FULL,
			0x3947E9E7507AA4CEULL}
		},
		.Z = {.key64 = {
			0xBD96DF3F5329BCF5ULL,
			0xED286D8A06893A84ULL,
			0x1FC075314D8D0E6CULL,
			0x3A5630271F56E37EULL}
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

	steps = 40;
	X1 = (curve25519_key_t){.key64 = {
		0x1D3012A45F814858ULL,
		0x30627628D63E9D77ULL,
		0xA842ACB5FB122077ULL,
		0x4DD17A20B0C0AFA9ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1D3012A45F814858ULL,
			0x30627628D63E9D77ULL,
			0xA842ACB5FB122077ULL,
			0x4DD17A20B0C0AFA9ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE5E28D00B6F88570ULL,
			0x9C5DAEBFC3635418ULL,
			0x9FE9D6A7AC4328DBULL,
			0x200BEB6D19401C22ULL}
		},
		.Z = {.key64 = {
			0xD3125D73F627AC2EULL,
			0xE23FF0950F21BF04ULL,
			0xB0396CEA9A007185ULL,
			0x73F30727C81CE4C1ULL}
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

	steps = 64;
	X1 = (curve25519_key_t){.key64 = {
		0x4E60107ACABEBC00ULL,
		0x269CFDD0D8F01203ULL,
		0xB59E253FAF83DD38ULL,
		0x6522322F6AFD202BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4E60107ACABEBC00ULL,
			0x269CFDD0D8F01203ULL,
			0xB59E253FAF83DD38ULL,
			0x6522322F6AFD202BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x38ECD1BEB9760CA2ULL,
			0x58A59A99BFDBDB59ULL,
			0xE618D9EF608D50C8ULL,
			0x4A076A2CC51DCDF7ULL}
		},
		.Z = {.key64 = {
			0x51147E17AF575383ULL,
			0x3033BFCCADFC1F7EULL,
			0x8AE49D93CB5BB066ULL,
			0x547FD771DBF9F63FULL}
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

	steps = 7;
	X1 = (curve25519_key_t){.key64 = {
		0x78AB7779C9C60C98ULL,
		0xEBE52D72AADCCDA9ULL,
		0xBEEB6B594ABE4DFDULL,
		0x4FC1E3543FBE4BC5ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x78AB7779C9C60C98ULL,
			0xEBE52D72AADCCDA9ULL,
			0xBEEB6B594ABE4DFDULL,
			0x4FC1E3543FBE4BC5ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB2754E31FCA25B52ULL,
			0xF48FBC60469F0D92ULL,
			0x7A215AE588DC633BULL,
			0x55B7791610459F62ULL}
		},
		.Z = {.key64 = {
			0x52B3069EDE7606F0ULL,
			0x9AB67624547AF7DEULL,
			0xE115AC1BFE6E9EADULL,
			0x4F45F6C6BAFEEC1DULL}
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

	steps = 50;
	X1 = (curve25519_key_t){.key64 = {
		0x31E4993D9DED0858ULL,
		0x2DD11780E5A90C1FULL,
		0xFF972C38DD67BEEDULL,
		0x74913E2B01785DE2ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x31E4993D9DED0858ULL,
			0x2DD11780E5A90C1FULL,
			0xFF972C38DD67BEEDULL,
			0x74913E2B01785DE2ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC7C78C41FCD11123ULL,
			0x905B1947BDD84B1AULL,
			0x61D1677C429ADC12ULL,
			0x030CC50AD510C1F2ULL}
		},
		.Z = {.key64 = {
			0xB8EA86DD2C9A2482ULL,
			0x7D8958557970B86EULL,
			0x073D1EE4C605A36CULL,
			0x4917E9DDFDC34577ULL}
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

	steps = 8;
	X1 = (curve25519_key_t){.key64 = {
		0x28C1845E1D566000ULL,
		0xAF1533A5B8B03B6DULL,
		0x3A9602FEF4AD8CB0ULL,
		0x40517FE5970C52C8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x28C1845E1D566000ULL,
			0xAF1533A5B8B03B6DULL,
			0x3A9602FEF4AD8CB0ULL,
			0x40517FE5970C52C8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2D7E54FE98EDBC0AULL,
			0xD43E1F9D449CC021ULL,
			0xEA769AF9D91D05F2ULL,
			0x763FFABDAE579C7DULL}
		},
		.Z = {.key64 = {
			0xFC4409FC76CE8E89ULL,
			0xDC12908D411504F9ULL,
			0x03440A809827291FULL,
			0x37E3BE9EB0F85943ULL}
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

	steps = 8;
	X1 = (curve25519_key_t){.key64 = {
		0x0F3D6DA608290EC0ULL,
		0x738524AAC8DB3607ULL,
		0x454E71409AAF05B7ULL,
		0x64E6382970326EB8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0F3D6DA608290EC0ULL,
			0x738524AAC8DB3607ULL,
			0x454E71409AAF05B7ULL,
			0x64E6382970326EB8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6980A237F64175C1ULL,
			0x0165FD234B1A02AAULL,
			0x10D20C632615C531ULL,
			0x2A3A28A1365EB100ULL}
		},
		.Z = {.key64 = {
			0xD0AABE1C620A0055ULL,
			0xA6953BF3AA6BF64CULL,
			0x58DD404895ED9C14ULL,
			0x264F6011508711E5ULL}
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

	steps = 8;
	X1 = (curve25519_key_t){.key64 = {
		0x94AEBFD49AC1A388ULL,
		0xB5DF2BC7F20655F5ULL,
		0x1616C86B335CC2ECULL,
		0x7A43B43C520833D7ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x94AEBFD49AC1A388ULL,
			0xB5DF2BC7F20655F5ULL,
			0x1616C86B335CC2ECULL,
			0x7A43B43C520833D7ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF018D8F03344F789ULL,
			0x55D2492594A4C125ULL,
			0x30F96B024C229509ULL,
			0x601272982789F5B3ULL}
		},
		.Z = {.key64 = {
			0xB3939663A3FB45A0ULL,
			0x6396BD09E2703B70ULL,
			0x50F3F9C7DED4AFD0ULL,
			0x791C149CBB93AEC1ULL}
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

	steps = 7;
	X1 = (curve25519_key_t){.key64 = {
		0x9430BDE595B8AD40ULL,
		0x76FE264F0195DA8DULL,
		0x43C5E7AC7CAB95DCULL,
		0x62CF4EB280187051ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9430BDE595B8AD40ULL,
			0x76FE264F0195DA8DULL,
			0x43C5E7AC7CAB95DCULL,
			0x62CF4EB280187051ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEE770EC55880AE79ULL,
			0xD7F1EA8E30F6BFCAULL,
			0x37C4218BC325941BULL,
			0x2EFE02F600E5C650ULL}
		},
		.Z = {.key64 = {
			0xFBB2F6F21C6411C7ULL,
			0xCE52E8B2CE6A5329ULL,
			0xFC06072FB47C720BULL,
			0x2D546E305DB58315ULL}
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

	steps = 41;
	X1 = (curve25519_key_t){.key64 = {
		0xD0B8B5EDF9C7A540ULL,
		0x470C82D7DEFF671CULL,
		0x1D3E0EB827072787ULL,
		0x786B2A6799DC2659ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD0B8B5EDF9C7A540ULL,
			0x470C82D7DEFF671CULL,
			0x1D3E0EB827072787ULL,
			0x786B2A6799DC2659ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x01DDEF856066B46CULL,
			0xB35FCBCA15DCA613ULL,
			0x732DFCF899BFD18DULL,
			0x7EF9E89CA5F38065ULL}
		},
		.Z = {.key64 = {
			0xEF7CFC14C09F184AULL,
			0xFD4041BA873C69E8ULL,
			0x7A4D48D7C55795CBULL,
			0x6E3739683425AB71ULL}
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

	steps = 17;
	X1 = (curve25519_key_t){.key64 = {
		0x0622649703592088ULL,
		0x5835157CEE8E99BEULL,
		0x7B91E23314CE49BDULL,
		0x63C16120C249D254ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0622649703592088ULL,
			0x5835157CEE8E99BEULL,
			0x7B91E23314CE49BDULL,
			0x63C16120C249D254ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x10F6AD900D35E228ULL,
			0x6CA15F6C5EB116CBULL,
			0x850436033505F535ULL,
			0x1C3DFCB482C98F6FULL}
		},
		.Z = {.key64 = {
			0xA1D9A2C2E0989652ULL,
			0x334A9EBD69D4BD07ULL,
			0xF9E774314D182C0AULL,
			0x00D06DD676111230ULL}
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

	steps = 29;
	X1 = (curve25519_key_t){.key64 = {
		0x6C32FB12BA64FEA8ULL,
		0x65EFCA43386875A7ULL,
		0x9F2376BF21C4AA01ULL,
		0x7E5388FCC23A82EEULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6C32FB12BA64FEA8ULL,
			0x65EFCA43386875A7ULL,
			0x9F2376BF21C4AA01ULL,
			0x7E5388FCC23A82EEULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x774D1BA31089AA54ULL,
			0x04CB08B0096BB0EAULL,
			0xB8E3C37A7CF77AEAULL,
			0x2873D6E88D0B5BB5ULL}
		},
		.Z = {.key64 = {
			0xC6AB52F56CE2D7CAULL,
			0xB267274CBDCAD56FULL,
			0x462EABE950F6C8B2ULL,
			0x55B11C14EA93E17BULL}
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

	steps = 52;
	X1 = (curve25519_key_t){.key64 = {
		0x2DCBB6EA389F6918ULL,
		0x33E0393D3C03831EULL,
		0xF2BC50F302E31524ULL,
		0x46A6AD2E3C84870CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2DCBB6EA389F6918ULL,
			0x33E0393D3C03831EULL,
			0xF2BC50F302E31524ULL,
			0x46A6AD2E3C84870CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3E308C47B4C52F48ULL,
			0x4A1306136986BF8DULL,
			0x6C1B1DA62DB13B2AULL,
			0x2CB4E70F3ACF950FULL}
		},
		.Z = {.key64 = {
			0x5EEF7F7B1DC2C56CULL,
			0x64782360875EC374ULL,
			0xF510BAE0120D79B7ULL,
			0x63C5B53A89BE9DE1ULL}
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

	steps = 3;
	X1 = (curve25519_key_t){.key64 = {
		0xC25325E64826B890ULL,
		0x7DC58E287F662079ULL,
		0x6C2B4CB0F3D3EA7DULL,
		0x6AC888666EFFB7F8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC25325E64826B890ULL,
			0x7DC58E287F662079ULL,
			0x6C2B4CB0F3D3EA7DULL,
			0x6AC888666EFFB7F8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x329D041D0FC5E3C0ULL,
			0x785705A0054084D9ULL,
			0x5A4A85437992C263ULL,
			0x2519EF0A0FE2444CULL}
		},
		.Z = {.key64 = {
			0x0D869C45DCA1559EULL,
			0x6758F1CA850CA3C1ULL,
			0x5C3E95851FDD4335ULL,
			0x5C2570ACB107F9F8ULL}
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

	steps = 38;
	X1 = (curve25519_key_t){.key64 = {
		0x46AC9024099C64F8ULL,
		0xE09A026F0F8C0F6EULL,
		0x5A02C8668ACB0DD7ULL,
		0x774AA1711C47CFBDULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x46AC9024099C64F8ULL,
			0xE09A026F0F8C0F6EULL,
			0x5A02C8668ACB0DD7ULL,
			0x774AA1711C47CFBDULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x64073C8E411FCB92ULL,
			0x40C5328B288916C5ULL,
			0x5C23FF891D691C66ULL,
			0x5672848B0CB1AA4EULL}
		},
		.Z = {.key64 = {
			0x8CA4DFFF222068A1ULL,
			0xCF0C06F6994DD45DULL,
			0x34B9A969DE81048CULL,
			0x0604B258B5B251C8ULL}
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

	steps = 64;
	X1 = (curve25519_key_t){.key64 = {
		0x87770CEAC54B0058ULL,
		0x5CF84A486FD4B6C2ULL,
		0x7E6681105A27E4B9ULL,
		0x65D905E8717BE4ACULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x87770CEAC54B0058ULL,
			0x5CF84A486FD4B6C2ULL,
			0x7E6681105A27E4B9ULL,
			0x65D905E8717BE4ACULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x20AA42C808F52036ULL,
			0x31A50F5D0BB27169ULL,
			0xA03E8FBC12E05CC0ULL,
			0x7C9261CAEB36E32FULL}
		},
		.Z = {.key64 = {
			0xD499FA7E0250A95EULL,
			0x74780A562FB704C1ULL,
			0x41657F2FA3F46E6EULL,
			0x73E23B59B8C688DDULL}
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

	steps = 22;
	X1 = (curve25519_key_t){.key64 = {
		0x71B68C7A5C3821C0ULL,
		0x6C3C1ED4EC0B7041ULL,
		0xD0C073CA3DD96A22ULL,
		0x6FA06FE724C43BA0ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x71B68C7A5C3821C0ULL,
			0x6C3C1ED4EC0B7041ULL,
			0xD0C073CA3DD96A22ULL,
			0x6FA06FE724C43BA0ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9FEA10DC7AC600F8ULL,
			0x9946781B6D752A80ULL,
			0xB56803563DC0A5D5ULL,
			0x775FC03A8B4BF06CULL}
		},
		.Z = {.key64 = {
			0xFCA31D20C7830F13ULL,
			0x05CDB52CFF137D53ULL,
			0x273A8EF9F94739DBULL,
			0x0C38E9A8D101AABAULL}
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

	steps = 48;
	X1 = (curve25519_key_t){.key64 = {
		0xA0250FF196CF3BD8ULL,
		0xA5D671CA44DFD3D0ULL,
		0x3E779D0E5D4197A7ULL,
		0x736454E674CC760FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA0250FF196CF3BD8ULL,
			0xA5D671CA44DFD3D0ULL,
			0x3E779D0E5D4197A7ULL,
			0x736454E674CC760FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4E6F290ACFB9DEBCULL,
			0xF46B6D1021606AFDULL,
			0x14E2D396CA85689FULL,
			0x3D1DE4A2C446C784ULL}
		},
		.Z = {.key64 = {
			0x793E761CB789E66FULL,
			0xFA7231DC282B4A44ULL,
			0x5E1448E0B71D5F52ULL,
			0x620ED038919F1A17ULL}
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

	steps = 5;
	X1 = (curve25519_key_t){.key64 = {
		0x346FDCB82B658FD8ULL,
		0xED033742D2202C65ULL,
		0x8C0FB39686CD54A6ULL,
		0x4AAF9A55CE3A0720ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x346FDCB82B658FD8ULL,
			0xED033742D2202C65ULL,
			0x8C0FB39686CD54A6ULL,
			0x4AAF9A55CE3A0720ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2C091A936372417CULL,
			0x3EC5F99B066759F5ULL,
			0xCEC3C018EB5B864DULL,
			0x1A3E77C98EAAE4C3ULL}
		},
		.Z = {.key64 = {
			0x0E045234752980E1ULL,
			0x41FA7CD38C466792ULL,
			0xAD3AF3CB5E52C3FFULL,
			0x542B79E6ED221B86ULL}
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

	steps = 40;
	X1 = (curve25519_key_t){.key64 = {
		0x6835A871A5E18FA0ULL,
		0xF96CADC36C611789ULL,
		0x5577476F36B558CBULL,
		0x443D1F27E8360266ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6835A871A5E18FA0ULL,
			0xF96CADC36C611789ULL,
			0x5577476F36B558CBULL,
			0x443D1F27E8360266ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x69B3ABA55A485562ULL,
			0x0F4F8E9595A09A21ULL,
			0x1E79202A6BBBFFF9ULL,
			0x0E4A83A610DC95BFULL}
		},
		.Z = {.key64 = {
			0x0FB4FCF82786EDD5ULL,
			0x13CFF59C0406544AULL,
			0x93DBFFC2D0C8A56CULL,
			0x72948B6F4F5196D5ULL}
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

	steps = 15;
	X1 = (curve25519_key_t){.key64 = {
		0x29D0DFF1E4ABF7E8ULL,
		0xF0C7EDAFE8F3C94BULL,
		0x8FA2D8CBCDBAB17DULL,
		0x4E32E48336EF2085ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x29D0DFF1E4ABF7E8ULL,
			0xF0C7EDAFE8F3C94BULL,
			0x8FA2D8CBCDBAB17DULL,
			0x4E32E48336EF2085ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEADEDEC8D49AB26EULL,
			0xD03BD5B652700C84ULL,
			0x86EBE17E43BA024BULL,
			0x3D6B65FED4248A7CULL}
		},
		.Z = {.key64 = {
			0xD0FC101BC0858CA9ULL,
			0x85608194661252CCULL,
			0xDC3B048F452E54A3ULL,
			0x2FBDFCF14798E3E1ULL}
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

	steps = 56;
	X1 = (curve25519_key_t){.key64 = {
		0x6E85C6BD0B785258ULL,
		0x20C17CB1D326C280ULL,
		0x0CF4A5403C25FB66ULL,
		0x4BBC37B2037F45E0ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6E85C6BD0B785258ULL,
			0x20C17CB1D326C280ULL,
			0x0CF4A5403C25FB66ULL,
			0x4BBC37B2037F45E0ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC71EAA1C3C7608EAULL,
			0x8B6E2312BD8167FBULL,
			0x3996581ED5E07DCBULL,
			0x42B3C7F4DFF96654ULL}
		},
		.Z = {.key64 = {
			0xEED726F0CFC10FE7ULL,
			0x16033DF573740CB2ULL,
			0x6F55F048296A3D2EULL,
			0x5C52A969602E1936ULL}
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

	steps = 25;
	X1 = (curve25519_key_t){.key64 = {
		0x2D4D60035226CD18ULL,
		0xD83D3CDC8900BDCFULL,
		0x1E4DA29C25699459ULL,
		0x4D93D997F1CF9927ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2D4D60035226CD18ULL,
			0xD83D3CDC8900BDCFULL,
			0x1E4DA29C25699459ULL,
			0x4D93D997F1CF9927ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x919F65E3FC75B315ULL,
			0x85CA1B6AF0AA4220ULL,
			0x7F1E16A2E8376A29ULL,
			0x70357454D6BD389EULL}
		},
		.Z = {.key64 = {
			0x591450C8070D2328ULL,
			0x7C0B7A7A3AA8F74AULL,
			0x2873554634DE5F1EULL,
			0x28465651DD2C8BC7ULL}
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

	steps = 35;
	X1 = (curve25519_key_t){.key64 = {
		0x7E60B10727EE02F8ULL,
		0xF70A067D0EF2F105ULL,
		0xA3A85D1007A3F13FULL,
		0x586CDEFB72177261ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7E60B10727EE02F8ULL,
			0xF70A067D0EF2F105ULL,
			0xA3A85D1007A3F13FULL,
			0x586CDEFB72177261ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5A1D8F01BE012A62ULL,
			0xA57ADDC05AD886E0ULL,
			0x3833F4C66BE0771AULL,
			0x0093A65780584A8EULL}
		},
		.Z = {.key64 = {
			0x62443CDB89CAB918ULL,
			0xB8F36128760E6DD7ULL,
			0xEF29F19D4E62E21FULL,
			0x20D96B78F19198EDULL}
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

	steps = 7;
	X1 = (curve25519_key_t){.key64 = {
		0x5FD47E4CB4E04100ULL,
		0x8A505E93EBC88F01ULL,
		0x7537047C5B04F20CULL,
		0x7BAA0CE913EA0FD0ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5FD47E4CB4E04100ULL,
			0x8A505E93EBC88F01ULL,
			0x7537047C5B04F20CULL,
			0x7BAA0CE913EA0FD0ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA2F100606F7711DFULL,
			0xC68BC05082A0DFB0ULL,
			0x7D253614D35B9A36ULL,
			0x0B7F54AD415A0C44ULL}
		},
		.Z = {.key64 = {
			0x5FF36F7753FF51DFULL,
			0xA87EE90C65523ECEULL,
			0x11728A8F1B48C04AULL,
			0x4837902F10DF8CB2ULL}
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

	steps = 29;
	X1 = (curve25519_key_t){.key64 = {
		0xB71F083913C7C808ULL,
		0x69A01109AF6BDB5CULL,
		0xE6EA8568432B438EULL,
		0x594E49E76C3AF384ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB71F083913C7C808ULL,
			0x69A01109AF6BDB5CULL,
			0xE6EA8568432B438EULL,
			0x594E49E76C3AF384ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x268E31C24164C7DBULL,
			0x4225BE31E58C5334ULL,
			0xE8D5CA4FE951726DULL,
			0x48EE2F7952C1B5E2ULL}
		},
		.Z = {.key64 = {
			0x5913A75E9CF13DD3ULL,
			0x7D26E71AEED4054FULL,
			0x3C7324A7213AE2C5ULL,
			0x01ED99406F08C5DBULL}
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

	steps = 45;
	X1 = (curve25519_key_t){.key64 = {
		0x7A16031AE0DBABB8ULL,
		0x53866489B4E7FA78ULL,
		0x604673D0139374C8ULL,
		0x4CBE84B495184584ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7A16031AE0DBABB8ULL,
			0x53866489B4E7FA78ULL,
			0x604673D0139374C8ULL,
			0x4CBE84B495184584ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x82A110B502855A64ULL,
			0x70BBAAAED0009092ULL,
			0x40910BE877BB96C2ULL,
			0x2ED5027277B3732CULL}
		},
		.Z = {.key64 = {
			0xF2EBE7D8326A13FAULL,
			0xE2B037381359D794ULL,
			0x326E23ADD38F53CEULL,
			0x17D6C15677608805ULL}
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

	steps = 9;
	X1 = (curve25519_key_t){.key64 = {
		0xD8CE268AFBFF0B18ULL,
		0xBBF8522923024BF2ULL,
		0xA990FF2D4C767905ULL,
		0x4A9F3D64EDC435E8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD8CE268AFBFF0B18ULL,
			0xBBF8522923024BF2ULL,
			0xA990FF2D4C767905ULL,
			0x4A9F3D64EDC435E8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x381123156C3EE044ULL,
			0x3B1C5D56E7D03261ULL,
			0xCD47D70C8900FA0EULL,
			0x0476EC783468B036ULL}
		},
		.Z = {.key64 = {
			0x41147B99AA30FAA5ULL,
			0x1AB60B42E23CD5C6ULL,
			0xCE560F2B59ED1FFEULL,
			0x69FA361E832B4051ULL}
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

	steps = 23;
	X1 = (curve25519_key_t){.key64 = {
		0x3E7C968B78C923F0ULL,
		0xF3FC8FF155158D60ULL,
		0xD75076EBA479C2CBULL,
		0x6AA8443976F5B592ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3E7C968B78C923F0ULL,
			0xF3FC8FF155158D60ULL,
			0xD75076EBA479C2CBULL,
			0x6AA8443976F5B592ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD67DA1199AE2DA53ULL,
			0x5D9EDC72AE6F3DB6ULL,
			0x614B35C7CF6A88DCULL,
			0x5226AE13E978DBA7ULL}
		},
		.Z = {.key64 = {
			0xA5001B813B5C7E61ULL,
			0xFC557A0D8117A67BULL,
			0xB2E8CAD4DBC15F12ULL,
			0x2967E4047FBCB84BULL}
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

	steps = 3;
	X1 = (curve25519_key_t){.key64 = {
		0xE702FEF1DFB67F10ULL,
		0x17D05FC47417B6E3ULL,
		0x86055827E67BDE35ULL,
		0x68DA151627A37235ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE702FEF1DFB67F10ULL,
			0x17D05FC47417B6E3ULL,
			0x86055827E67BDE35ULL,
			0x68DA151627A37235ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x633E14A567304142ULL,
			0x14DBBBF7711B421BULL,
			0xE4FDE3D2B104A10AULL,
			0x4DAA058A3B402D15ULL}
		},
		.Z = {.key64 = {
			0x8528AE5CD4CA84C4ULL,
			0x280D1B33E16AAE6AULL,
			0x93BF65F8F9180C86ULL,
			0x3855AD7225BE7407ULL}
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

	steps = 21;
	X1 = (curve25519_key_t){.key64 = {
		0x47E6869695EEBF68ULL,
		0xB13CB75D209D25B3ULL,
		0xE4D504977C3A9C54ULL,
		0x45D9B99656DD2460ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x47E6869695EEBF68ULL,
			0xB13CB75D209D25B3ULL,
			0xE4D504977C3A9C54ULL,
			0x45D9B99656DD2460ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x55D006F1864076FBULL,
			0x146BC8B3E2C3DA19ULL,
			0x64F1CE4F7181E952ULL,
			0x2B52A864A25B4822ULL}
		},
		.Z = {.key64 = {
			0x3E3980D90E262737ULL,
			0x84A252162BB00EB9ULL,
			0xE1C16E4CEB88F070ULL,
			0x06CCF8A032C033FAULL}
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

	steps = 37;
	X1 = (curve25519_key_t){.key64 = {
		0x5483AB1B0BC13458ULL,
		0xB6D86948DF405AD3ULL,
		0x643F0E25CB074A41ULL,
		0x6262A9DDE3E43364ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5483AB1B0BC13458ULL,
			0xB6D86948DF405AD3ULL,
			0x643F0E25CB074A41ULL,
			0x6262A9DDE3E43364ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x164F09D4AA711BBBULL,
			0x24FF2F59A184454EULL,
			0x318F4FBC5006A657ULL,
			0x2768D908B1EB3AA0ULL}
		},
		.Z = {.key64 = {
			0x3966B9C00455AF69ULL,
			0xEEA74234AB122DD4ULL,
			0x09B8EF6B5A55457CULL,
			0x52F3248343147082ULL}
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

	steps = 26;
	X1 = (curve25519_key_t){.key64 = {
		0xE3332EE00A3BA520ULL,
		0x2DA039B0BA7F4642ULL,
		0x08283F6984800151ULL,
		0x70AF25699CFA8C02ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE3332EE00A3BA520ULL,
			0x2DA039B0BA7F4642ULL,
			0x08283F6984800151ULL,
			0x70AF25699CFA8C02ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF0F9C36E5612F6CEULL,
			0x212D4B9A1753D83BULL,
			0x854C9ED65391FEF0ULL,
			0x4782D85547020E15ULL}
		},
		.Z = {.key64 = {
			0x3655453F5B28AA23ULL,
			0x70E2CF450832A321ULL,
			0xC52D16EBB77BC9BCULL,
			0x05B9F7524EA766DDULL}
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

	steps = 18;
	X1 = (curve25519_key_t){.key64 = {
		0xE02EABDD399F1C10ULL,
		0x769E7315BFF21ED8ULL,
		0x75FE602CF9913C95ULL,
		0x697CF0559A2215ECULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE02EABDD399F1C10ULL,
			0x769E7315BFF21ED8ULL,
			0x75FE602CF9913C95ULL,
			0x697CF0559A2215ECULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6A7583E76DB9041EULL,
			0xCFAE8480D434E3DCULL,
			0x0A655DBF1B0EEB89ULL,
			0x670DFA36C0E0D0ACULL}
		},
		.Z = {.key64 = {
			0x4992D8332F13D06CULL,
			0x3174233BF7D4BEFFULL,
			0x0AE0584FD8F33003ULL,
			0x1CB3BBD12BD34904ULL}
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

	steps = 42;
	X1 = (curve25519_key_t){.key64 = {
		0x8F83DB4D6461BC48ULL,
		0x0EF1995F2A90C19EULL,
		0x5BD0E291AB720DDEULL,
		0x483AC021D5DA9774ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8F83DB4D6461BC48ULL,
			0x0EF1995F2A90C19EULL,
			0x5BD0E291AB720DDEULL,
			0x483AC021D5DA9774ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC20983109C1F2AB5ULL,
			0xC0662FD70F2EA14BULL,
			0x3BE5864781226319ULL,
			0x177E0E230528FD47ULL}
		},
		.Z = {.key64 = {
			0x7CD8D478F088B557ULL,
			0xCF412FE0932042B0ULL,
			0x938BDF05F63660D3ULL,
			0x3A8FE545D9C60E55ULL}
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

	steps = 31;
	X1 = (curve25519_key_t){.key64 = {
		0x59970234071CDBC0ULL,
		0x6E8E088C4A4558B5ULL,
		0x6C05D5EAA0EF7526ULL,
		0x74B607E58F41C624ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x59970234071CDBC0ULL,
			0x6E8E088C4A4558B5ULL,
			0x6C05D5EAA0EF7526ULL,
			0x74B607E58F41C624ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7D2676F296755EDDULL,
			0x8A73378009625D85ULL,
			0x8FE5FD3444E3783BULL,
			0x73589BF52B92A85BULL}
		},
		.Z = {.key64 = {
			0xB7568E1C0740CD11ULL,
			0xED575C3295CB677AULL,
			0xFB964F2598E2DA7CULL,
			0x6482D49982D43354ULL}
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

	steps = 5;
	X1 = (curve25519_key_t){.key64 = {
		0x57706DBF21FB0598ULL,
		0x119605BF47A5F966ULL,
		0x8916724F6F84ABBBULL,
		0x7DB7F140B58A099BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x57706DBF21FB0598ULL,
			0x119605BF47A5F966ULL,
			0x8916724F6F84ABBBULL,
			0x7DB7F140B58A099BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0BDA14B2431ADCF9ULL,
			0xC7306930A28B7D8DULL,
			0x745C25EE24B48376ULL,
			0x4FAC87F95676A099ULL}
		},
		.Z = {.key64 = {
			0x2045339ABCC20D8AULL,
			0xE7B3DC4BECD89F9FULL,
			0x0028558798BD5A2CULL,
			0x17921EEFA1B9CB8BULL}
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

	steps = 21;
	X1 = (curve25519_key_t){.key64 = {
		0x4609E1DD6F17C648ULL,
		0x61E4B9EB70FBE7CFULL,
		0x09B2685A7C7AF03FULL,
		0x65B0CC1BB404F40BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4609E1DD6F17C648ULL,
			0x61E4B9EB70FBE7CFULL,
			0x09B2685A7C7AF03FULL,
			0x65B0CC1BB404F40BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC7E3D60E18E8215AULL,
			0x13573113EB4B18F0ULL,
			0x89A68A6DA5FE7B46ULL,
			0x0808CF045AD1FEB9ULL}
		},
		.Z = {.key64 = {
			0x078B619BFEEFFFE0ULL,
			0x0F4C78E946F5F5A0ULL,
			0x75045C415C6C3BE0ULL,
			0x07070BF1D566B9C2ULL}
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

	steps = 46;
	X1 = (curve25519_key_t){.key64 = {
		0xF2A7DC2EF85DB718ULL,
		0x5079734CBFBE3805ULL,
		0x9C5258823C21E6EDULL,
		0x49C487FB087003B9ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF2A7DC2EF85DB718ULL,
			0x5079734CBFBE3805ULL,
			0x9C5258823C21E6EDULL,
			0x49C487FB087003B9ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA401D3F67E8E6A62ULL,
			0xCAFD6D2038BC7ADBULL,
			0xF1A748B55980114DULL,
			0x233D82DA0824D055ULL}
		},
		.Z = {.key64 = {
			0xEBC14855E33284B2ULL,
			0x15BAA901CFF2DEBEULL,
			0xCAE77E6F30C91739ULL,
			0x41A392380DF20CF6ULL}
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

	steps = 16;
	X1 = (curve25519_key_t){.key64 = {
		0x0089C04CF18DC0C0ULL,
		0x0475DDB846A62C0CULL,
		0xA41978156EF52B04ULL,
		0x7DD2FD3743D01F08ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0089C04CF18DC0C0ULL,
			0x0475DDB846A62C0CULL,
			0xA41978156EF52B04ULL,
			0x7DD2FD3743D01F08ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3E2F6D89AD7E8E6CULL,
			0xFA1DEAF11D32DA88ULL,
			0x2015B33D3BFFBB37ULL,
			0x3A908876DC6AA39FULL}
		},
		.Z = {.key64 = {
			0xE620268F6E375448ULL,
			0x1F1B56E2045F453CULL,
			0x2895DA71BF97041EULL,
			0x7F0461C2807E73AAULL}
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

	steps = 43;
	X1 = (curve25519_key_t){.key64 = {
		0x3D7130E539F14C40ULL,
		0x968DC674B1AF680BULL,
		0x4021C602BFDFB55DULL,
		0x7C4A39C471961AC9ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3D7130E539F14C40ULL,
			0x968DC674B1AF680BULL,
			0x4021C602BFDFB55DULL,
			0x7C4A39C471961AC9ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x798D43ABF5B18D3DULL,
			0x0916992FB983A983ULL,
			0xE094B74AC764487CULL,
			0x6D1D9DA83C09D8E0ULL}
		},
		.Z = {.key64 = {
			0xF28AAEBD4D776AD9ULL,
			0xB080B0C4AAE643B6ULL,
			0x8340E8D861AE096BULL,
			0x12F60B93C2BE969DULL}
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

	steps = 45;
	X1 = (curve25519_key_t){.key64 = {
		0x288DA239ACDB9EA8ULL,
		0x5B7B8A34FF3DECD0ULL,
		0x523EAE3837A0C46FULL,
		0x76D7209EAE7C514FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x288DA239ACDB9EA8ULL,
			0x5B7B8A34FF3DECD0ULL,
			0x523EAE3837A0C46FULL,
			0x76D7209EAE7C514FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x37BBF25C1BA130E4ULL,
			0x72ECF4C6B33CBBD0ULL,
			0x7FB4A0805E448BE2ULL,
			0x6F2FDEEEE67CB676ULL}
		},
		.Z = {.key64 = {
			0xC785C868B52BEA16ULL,
			0x8BC5F48CEFC75EF5ULL,
			0x1C58677768966433ULL,
			0x04934AAF2420E3C8ULL}
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

	steps = 22;
	X1 = (curve25519_key_t){.key64 = {
		0xEF691FB4582E4CE8ULL,
		0x104BB977BF6776A7ULL,
		0x7359630C1A6A2E0CULL,
		0x4369112B3AA0CD19ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEF691FB4582E4CE8ULL,
			0x104BB977BF6776A7ULL,
			0x7359630C1A6A2E0CULL,
			0x4369112B3AA0CD19ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF6971440B40457FFULL,
			0xD61BB2688D2C0550ULL,
			0x31C93F89DBDA585EULL,
			0x1B9972535D93E40DULL}
		},
		.Z = {.key64 = {
			0xD02FB30588B5D539ULL,
			0x44694A804751C76FULL,
			0x8FD1C0BD38FC6399ULL,
			0x35D14ACD8453E98FULL}
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

	steps = 31;
	X1 = (curve25519_key_t){.key64 = {
		0x4993C60AAFE25218ULL,
		0xDB3AF5CA28ACC382ULL,
		0x7AB4FA475B64343AULL,
		0x6ECE3EE3E75F89A1ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4993C60AAFE25218ULL,
			0xDB3AF5CA28ACC382ULL,
			0x7AB4FA475B64343AULL,
			0x6ECE3EE3E75F89A1ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0DD62E1F89BA393DULL,
			0x29C7BAFF81E270CAULL,
			0xA1B884D87C4B9C83ULL,
			0x16ABF5FBEDB52E4FULL}
		},
		.Z = {.key64 = {
			0x5E9115F64F934EAAULL,
			0x92D96A8A8B71092DULL,
			0xA5AFF7FFAEB31069ULL,
			0x493AD3BDEE75C7FEULL}
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

	steps = 25;
	X1 = (curve25519_key_t){.key64 = {
		0xFB59B6415EE9C9D8ULL,
		0x695EE3262D0A0034ULL,
		0xDB9BF6E6AFAE5FAAULL,
		0x4C40BE5E70C12994ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFB59B6415EE9C9D8ULL,
			0x695EE3262D0A0034ULL,
			0xDB9BF6E6AFAE5FAAULL,
			0x4C40BE5E70C12994ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7E1ADF3880CD209AULL,
			0xD2D6F72205C4D2FDULL,
			0x28CC0B92D41C4DABULL,
			0x2D1171F121B77866ULL}
		},
		.Z = {.key64 = {
			0xBD16506E8158BEE2ULL,
			0x2034C72D0E1E8933ULL,
			0xDD6828ACCA9D05D5ULL,
			0x618CCEF9FACA0BC2ULL}
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

	steps = 24;
	X1 = (curve25519_key_t){.key64 = {
		0x0B4D919D9D41D510ULL,
		0x801AFCACC81138ADULL,
		0xFFAF7342BDA26FC7ULL,
		0x5B55D0CFCC2BD896ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0B4D919D9D41D510ULL,
			0x801AFCACC81138ADULL,
			0xFFAF7342BDA26FC7ULL,
			0x5B55D0CFCC2BD896ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x158520BE1C02319EULL,
			0xB01F47857E2B30B4ULL,
			0x6271E0A20EE39151ULL,
			0x12FA5CAF82BBEC91ULL}
		},
		.Z = {.key64 = {
			0xD65D32341BC7DC1CULL,
			0xAB0554EBA2EB0B02ULL,
			0xDF3C4732FA5271ABULL,
			0x2E31B651D63A4E3DULL}
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

	steps = 13;
	X1 = (curve25519_key_t){.key64 = {
		0xBB543BBF163E4BA8ULL,
		0xCF1162A97FAE96FCULL,
		0x4DBB3944FFC6ACAFULL,
		0x70DAFBD00CE40161ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBB543BBF163E4BA8ULL,
			0xCF1162A97FAE96FCULL,
			0x4DBB3944FFC6ACAFULL,
			0x70DAFBD00CE40161ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x28DBFD811197F716ULL,
			0x141CA14D98DCE0D6ULL,
			0x2C366F341D18383BULL,
			0x6C14FDD3B99A1D65ULL}
		},
		.Z = {.key64 = {
			0x91084A3B839318A7ULL,
			0xB7423B1EEFA86092ULL,
			0xDB387A29D654AE8EULL,
			0x52250966293DC718ULL}
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

	steps = 25;
	X1 = (curve25519_key_t){.key64 = {
		0x2CD3298E83BE5B30ULL,
		0x88D55767C67FCF09ULL,
		0x5607274606C5A023ULL,
		0x687404BF700BF086ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2CD3298E83BE5B30ULL,
			0x88D55767C67FCF09ULL,
			0x5607274606C5A023ULL,
			0x687404BF700BF086ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x87109236D9D617F4ULL,
			0x35E2299E8C43B234ULL,
			0x2D3FB2022CCECEB2ULL,
			0x68F0CE57CFB27BB2ULL}
		},
		.Z = {.key64 = {
			0xBB246B8FBD191E1FULL,
			0xE70997BE37D3558FULL,
			0x161B03CBE52195E7ULL,
			0x70D0FBB82E53AA2DULL}
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

	steps = 64;
	X1 = (curve25519_key_t){.key64 = {
		0x4418992A445E49A8ULL,
		0x045874767B9F2086ULL,
		0x1F2B07CF04D0AC96ULL,
		0x648915632D52C9E5ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4418992A445E49A8ULL,
			0x045874767B9F2086ULL,
			0x1F2B07CF04D0AC96ULL,
			0x648915632D52C9E5ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x41C60C85E75DED8CULL,
			0x5B43F8EF2A392477ULL,
			0xE90241B487B8BAC9ULL,
			0x3223C2EEC96C32C6ULL}
		},
		.Z = {.key64 = {
			0xA57782F6E98253C5ULL,
			0x15B1A41EE9459DAEULL,
			0x2976D485C0EDAED0ULL,
			0x48E45184E9389EDAULL}
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

	steps = 50;
	X1 = (curve25519_key_t){.key64 = {
		0x8EB5F6B7A5EACFF8ULL,
		0x72EA64D5F1FBB1E5ULL,
		0x061D87CAB88A2974ULL,
		0x425727627BE9CA6BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8EB5F6B7A5EACFF8ULL,
			0x72EA64D5F1FBB1E5ULL,
			0x061D87CAB88A2974ULL,
			0x425727627BE9CA6BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2C6719DFD29B520BULL,
			0x8621AB3D0957C0D0ULL,
			0x718EEC871C2AC8C4ULL,
			0x48E3B1FAA447E95AULL}
		},
		.Z = {.key64 = {
			0xDC5631FAC1EFFD4FULL,
			0x83287707A9A45011ULL,
			0xCFB1B77422AFED50ULL,
			0x3DEDF791377B41B6ULL}
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

	steps = 38;
	X1 = (curve25519_key_t){.key64 = {
		0xE14E8F0859BE4948ULL,
		0x06E29AFCE79C02AAULL,
		0xD3A4A2B7D8AAE829ULL,
		0x7E253EE35E78D688ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE14E8F0859BE4948ULL,
			0x06E29AFCE79C02AAULL,
			0xD3A4A2B7D8AAE829ULL,
			0x7E253EE35E78D688ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE6681C82F9019E5CULL,
			0x651B27B7E47F2F0DULL,
			0x8EE3060ED3A83EEDULL,
			0x4A3291A343DE179DULL}
		},
		.Z = {.key64 = {
			0xE73A9A48396D5041ULL,
			0x24C8B4897F5DEA40ULL,
			0xF9BBA23B3FB4C425ULL,
			0x0DC5F087F0E32C4BULL}
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

	steps = 58;
	X1 = (curve25519_key_t){.key64 = {
		0x29F856BA3C9E7E00ULL,
		0xFFB935BC8DDC24EBULL,
		0x08BDB1D89CFB1D2FULL,
		0x6E52437837D4EA73ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x29F856BA3C9E7E00ULL,
			0xFFB935BC8DDC24EBULL,
			0x08BDB1D89CFB1D2FULL,
			0x6E52437837D4EA73ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCBB10F6AE05618E4ULL,
			0x9DC673734C27721DULL,
			0x0307C9CF581FCA64ULL,
			0x782FDB3E089D7A08ULL}
		},
		.Z = {.key64 = {
			0x5B5BFB7BE18BA937ULL,
			0x8B9D8FE4E8C8C3FAULL,
			0x0918DE22F3D74739ULL,
			0x00CA71B3FD3AD2DBULL}
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

	steps = 39;
	X1 = (curve25519_key_t){.key64 = {
		0x3689AF584C507258ULL,
		0x624560F77A604157ULL,
		0x8BA15FF49C9A8A6FULL,
		0x670B02FA5029A0E9ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3689AF584C507258ULL,
			0x624560F77A604157ULL,
			0x8BA15FF49C9A8A6FULL,
			0x670B02FA5029A0E9ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD91CFA25E21B1674ULL,
			0xAD8976C37F90DDC2ULL,
			0x4543628777611BCCULL,
			0x04EB35278F4FD7BCULL}
		},
		.Z = {.key64 = {
			0x1846FB35DD6FF233ULL,
			0xF32B0BD6F6350F3EULL,
			0x201F987A514E7A74ULL,
			0x0D3F8DB748318790ULL}
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

	steps = 15;
	X1 = (curve25519_key_t){.key64 = {
		0xEFC51D108502B8E8ULL,
		0x2819242C2B1CE828ULL,
		0x71042AE8220964A5ULL,
		0x6E701081EDE90A78ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEFC51D108502B8E8ULL,
			0x2819242C2B1CE828ULL,
			0x71042AE8220964A5ULL,
			0x6E701081EDE90A78ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8771B6787FCCA108ULL,
			0xF126B5988F9F1BB2ULL,
			0x85F559D23103DC4DULL,
			0x40B5006418C36854ULL}
		},
		.Z = {.key64 = {
			0x57400837F5946816ULL,
			0xA69641CBE8DDB48AULL,
			0x81CEAFE8CD8F3E20ULL,
			0x45EE54BCC52D63BAULL}
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

	steps = 50;
	X1 = (curve25519_key_t){.key64 = {
		0x12CF2176B5D43C98ULL,
		0x2A96D765A5888814ULL,
		0xB278A213B36227AEULL,
		0x5B28F6C8F8059EF2ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x12CF2176B5D43C98ULL,
			0x2A96D765A5888814ULL,
			0xB278A213B36227AEULL,
			0x5B28F6C8F8059EF2ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE94A6156C7983855ULL,
			0x460A9EF5EA9E5DBEULL,
			0xE5FC8E5A1B731AD3ULL,
			0x733BA15CEFFBD68EULL}
		},
		.Z = {.key64 = {
			0x9D10ABC28DDDE413ULL,
			0x30819EE8D452061EULL,
			0x8AC78B3EE6DE93A5ULL,
			0x1117755B9E9554F4ULL}
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

	steps = 14;
	X1 = (curve25519_key_t){.key64 = {
		0xFAEC92A72A03DC28ULL,
		0x4FB5A526B71B0746ULL,
		0x8B54E0DF7C604C50ULL,
		0x4DF66C33B7FCEC4BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFAEC92A72A03DC28ULL,
			0x4FB5A526B71B0746ULL,
			0x8B54E0DF7C604C50ULL,
			0x4DF66C33B7FCEC4BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8414F3A294B7D8AAULL,
			0xB7D5B1E47E708451ULL,
			0xE4930FE31F12CDDCULL,
			0x3C8FF6E8C332D8AFULL}
		},
		.Z = {.key64 = {
			0x8F7C01EFDDC77484ULL,
			0x0A62BCA445D1562AULL,
			0xB8B728A6C522F7DCULL,
			0x42243D04B7694EC8ULL}
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

	steps = 22;
	X1 = (curve25519_key_t){.key64 = {
		0x44458C77707E7CD8ULL,
		0x4877F2D03A6CAFF7ULL,
		0xF3D6EC443C0875DEULL,
		0x69291F135BB0DF8FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x44458C77707E7CD8ULL,
			0x4877F2D03A6CAFF7ULL,
			0xF3D6EC443C0875DEULL,
			0x69291F135BB0DF8FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC72FCF2381E6FFA3ULL,
			0x01BD7330F0340FFFULL,
			0xA21507DEFDBD8C41ULL,
			0x495740E62E6084DBULL}
		},
		.Z = {.key64 = {
			0x0119814B6665E12CULL,
			0x16701FADEB8CC559ULL,
			0x8E5871DB0560F686ULL,
			0x2A6033EBBDD3B38FULL}
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

	steps = 20;
	X1 = (curve25519_key_t){.key64 = {
		0x41E8CB19AA4BB540ULL,
		0xF5BBA184284E6E52ULL,
		0x380D3A06A19D3926ULL,
		0x5C480DC5FE053462ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x41E8CB19AA4BB540ULL,
			0xF5BBA184284E6E52ULL,
			0x380D3A06A19D3926ULL,
			0x5C480DC5FE053462ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5A0CA55170357C6AULL,
			0x6101E50BBC5E5FB3ULL,
			0x17BD372A9500FE49ULL,
			0x036CF95272A80EEEULL}
		},
		.Z = {.key64 = {
			0x2A12173574ED69D8ULL,
			0x53B0F872493D908EULL,
			0xF9B8D48D377C4B81ULL,
			0x7E424A0349A88B4EULL}
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

	steps = 47;
	X1 = (curve25519_key_t){.key64 = {
		0x66D22E6EFB6BDAF8ULL,
		0x40E693F2FFED91D0ULL,
		0x72DA1BDF4152C76CULL,
		0x58F53385C456ADA9ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x66D22E6EFB6BDAF8ULL,
			0x40E693F2FFED91D0ULL,
			0x72DA1BDF4152C76CULL,
			0x58F53385C456ADA9ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x629DD0C172C74DAEULL,
			0x1DC3C67F92E9CBD4ULL,
			0x977DD2584FD34792ULL,
			0x51088DADA0D52520ULL}
		},
		.Z = {.key64 = {
			0xE7C7A9725383431FULL,
			0xEB21C5FFB0F30295ULL,
			0xF03570B936AC92F3ULL,
			0x7AD18F63DDCE3251ULL}
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

	steps = 16;
	X1 = (curve25519_key_t){.key64 = {
		0x56E1565AE43C8998ULL,
		0xA5C62D8151552E45ULL,
		0x84BF50A2F349714EULL,
		0x50168AC1EADB44BCULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x56E1565AE43C8998ULL,
			0xA5C62D8151552E45ULL,
			0x84BF50A2F349714EULL,
			0x50168AC1EADB44BCULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x48B447C3545DAB5CULL,
			0x294D00D0C3632836ULL,
			0x9C61F61E47828C44ULL,
			0x09A5A00B95C6CC1BULL}
		},
		.Z = {.key64 = {
			0x77981D0EBFB2DFBCULL,
			0x438A270A1251AAB7ULL,
			0x9E99A76FD9369966ULL,
			0x418C25228164F8D2ULL}
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

	steps = 1;
	X1 = (curve25519_key_t){.key64 = {
		0xE54D5CD96A4C8E80ULL,
		0x94DA3932C9D29C3FULL,
		0x2A5857AFF4902951ULL,
		0x5F0EBC79793BC229ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE54D5CD96A4C8E80ULL,
			0x94DA3932C9D29C3FULL,
			0x2A5857AFF4902951ULL,
			0x5F0EBC79793BC229ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x819C187FF938A40AULL,
			0xF10EE880F9F431A0ULL,
			0x3A781113457C5BEEULL,
			0x5D24C093626F3050ULL}
		},
		.Z = {.key64 = {
			0x95357365A9323A26ULL,
			0x5368E4CB274A70FFULL,
			0xA9615EBFD240A546ULL,
			0x7C3AF1E5E4EF08A4ULL}
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

	steps = 19;
	X1 = (curve25519_key_t){.key64 = {
		0x6E5407ACE8A3DB48ULL,
		0xAAE45FBDEA3558B9ULL,
		0xEE2D502C84BF7F4AULL,
		0x788437EBBF644EA4ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6E5407ACE8A3DB48ULL,
			0xAAE45FBDEA3558B9ULL,
			0xEE2D502C84BF7F4AULL,
			0x788437EBBF644EA4ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8FE7E50F106815C7ULL,
			0x9171AD58DB72B8FFULL,
			0xA1E16303C5CC1A0AULL,
			0x03B3F6FCD52AC405ULL}
		},
		.Z = {.key64 = {
			0x455AC9B10C2771FAULL,
			0xE96AB7E2659BC6C6ULL,
			0x20ADEBAD7D9CDB99ULL,
			0x04747159B36FE7EEULL}
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

	steps = 57;
	X1 = (curve25519_key_t){.key64 = {
		0x3DE496DE07E68B78ULL,
		0xFEC6B0CAD6CBB10CULL,
		0x747CE6C08C2FCD07ULL,
		0x641C44AAD38A8C53ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3DE496DE07E68B78ULL,
			0xFEC6B0CAD6CBB10CULL,
			0x747CE6C08C2FCD07ULL,
			0x641C44AAD38A8C53ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0A910A7DE94CF4CBULL,
			0x44C2FDEFA487D69BULL,
			0xB2FD7A6CDFADF41BULL,
			0x355F35EFC4CEAF5BULL}
		},
		.Z = {.key64 = {
			0x566B15EEC7724C2DULL,
			0x9D02E6A2ED2C37E9ULL,
			0x305051E40B76058CULL,
			0x61A279ED4ABC7428ULL}
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

	steps = 30;
	X1 = (curve25519_key_t){.key64 = {
		0xB6D3CFC85B628FA0ULL,
		0x38A1AF397741FC0DULL,
		0xC223F39284C34F9AULL,
		0x44BA266FF8235D44ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB6D3CFC85B628FA0ULL,
			0x38A1AF397741FC0DULL,
			0xC223F39284C34F9AULL,
			0x44BA266FF8235D44ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD2808B181CAB70F0ULL,
			0x51C47B41FFCF7792ULL,
			0x1F5455888DCCB98EULL,
			0x578C884D2630ABF9ULL}
		},
		.Z = {.key64 = {
			0x85E4A5B7655E8F87ULL,
			0x626A4316E626D862ULL,
			0x7195C677AFE7F8DEULL,
			0x393EAC3DD895E68AULL}
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

	steps = 31;
	X1 = (curve25519_key_t){.key64 = {
		0x26B9B314968448E0ULL,
		0x2636AA5CAB496CB2ULL,
		0xD53B7690C65B426AULL,
		0x53D592292D036E79ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x26B9B314968448E0ULL,
			0x2636AA5CAB496CB2ULL,
			0xD53B7690C65B426AULL,
			0x53D592292D036E79ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDAF00D9A38BDA94DULL,
			0xB11FEA72CE9E571DULL,
			0x48FBDB89674D822CULL,
			0x718B3368FF8FFFA4ULL}
		},
		.Z = {.key64 = {
			0x1CD63EA0BB77E077ULL,
			0xC32FEF2B94B6F9CBULL,
			0x4A4CB88A5296DD18ULL,
			0x0BC3105110608EF3ULL}
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

	steps = 46;
	X1 = (curve25519_key_t){.key64 = {
		0x221B1B2FDBBC7378ULL,
		0x58EFC5768DB2B5A9ULL,
		0xCA54EBD523B5D365ULL,
		0x4A90B2A62DE1C09CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x221B1B2FDBBC7378ULL,
			0x58EFC5768DB2B5A9ULL,
			0xCA54EBD523B5D365ULL,
			0x4A90B2A62DE1C09CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2CC53B8239D3F40AULL,
			0x00AA44B45763392FULL,
			0x7D000AF6487D69C5ULL,
			0x61BA2413BF84E408ULL}
		},
		.Z = {.key64 = {
			0x75280F6F5B8A0A5DULL,
			0x164B5CF9D45437B0ULL,
			0x55CF511FDA55A54CULL,
			0x662D7D1D642B2E7DULL}
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

	steps = 60;
	X1 = (curve25519_key_t){.key64 = {
		0x13570C2EFAC0D578ULL,
		0x4F019105A7F003FDULL,
		0x39B081F18D8E7000ULL,
		0x768983E551968C72ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x13570C2EFAC0D578ULL,
			0x4F019105A7F003FDULL,
			0x39B081F18D8E7000ULL,
			0x768983E551968C72ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7502E7133AE80062ULL,
			0x032187E8776B5604ULL,
			0xE112F3157E63FE1FULL,
			0x7E0217EBB90CEE0EULL}
		},
		.Z = {.key64 = {
			0xE02C43FAE2B05AC3ULL,
			0xBC001DBA4FF1407FULL,
			0x247746F7275CC2A1ULL,
			0x592C587414130317ULL}
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

	steps = 18;
	X1 = (curve25519_key_t){.key64 = {
		0x406D5C046D8D5668ULL,
		0xA771F234635D3F11ULL,
		0x74D3B49DBE84AED8ULL,
		0x7D73F2B69ED5A816ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x406D5C046D8D5668ULL,
			0xA771F234635D3F11ULL,
			0x74D3B49DBE84AED8ULL,
			0x7D73F2B69ED5A816ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x26EAAFFA2008253DULL,
			0xADA4A38564090043ULL,
			0x7B03A5A4FADE6576ULL,
			0x0F324EE4FD167C84ULL}
		},
		.Z = {.key64 = {
			0x7A0C0C948FAFC0DCULL,
			0x52368EBE22168554ULL,
			0x546400E87B0C357FULL,
			0x605C8FCAFEA55CE4ULL}
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

	steps = 28;
	X1 = (curve25519_key_t){.key64 = {
		0xA8B063E8D5609DF0ULL,
		0x8F5BCD21928E777DULL,
		0x2DF9346C413FF003ULL,
		0x68348EFAF436FFDEULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA8B063E8D5609DF0ULL,
			0x8F5BCD21928E777DULL,
			0x2DF9346C413FF003ULL,
			0x68348EFAF436FFDEULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD27B084483716CBBULL,
			0x738AA1222F803441ULL,
			0xC5DCDEA8424E536AULL,
			0x4ADE29FF71B8DB18ULL}
		},
		.Z = {.key64 = {
			0x4243E498838A570BULL,
			0xB8A36753FF0F5D93ULL,
			0xF5E07ECFB4C37E4EULL,
			0x5EAD66D563AE7021ULL}
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

	steps = 28;
	X1 = (curve25519_key_t){.key64 = {
		0xB9CE614F6B1C8AF8ULL,
		0xB812C39AD2A13849ULL,
		0xE9EC8EC5E29D04A1ULL,
		0x47545590282C1724ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB9CE614F6B1C8AF8ULL,
			0xB812C39AD2A13849ULL,
			0xE9EC8EC5E29D04A1ULL,
			0x47545590282C1724ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFB28E663C5920E0EULL,
			0x3054DBE1B67E7547ULL,
			0xC95F57A829E09C12ULL,
			0x4029228BDE9DBA60ULL}
		},
		.Z = {.key64 = {
			0xB9530EE0E80B2018ULL,
			0xE623A503BBB14396ULL,
			0x72624710410E99ACULL,
			0x098FDD901CA8CBDBULL}
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

	steps = 17;
	X1 = (curve25519_key_t){.key64 = {
		0x1CBBBDCBF6878FD0ULL,
		0x851D81616EF26457ULL,
		0x3785C7DDA39B3DC5ULL,
		0x4CAAD52AB1C44E1BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1CBBBDCBF6878FD0ULL,
			0x851D81616EF26457ULL,
			0x3785C7DDA39B3DC5ULL,
			0x4CAAD52AB1C44E1BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1D498B5C4EE9FFE5ULL,
			0x1C8987CDD3F98825ULL,
			0x36D1EFB8B8A9C851ULL,
			0x3DEE7D433EFFF122ULL}
		},
		.Z = {.key64 = {
			0x5D4FC081B647C29EULL,
			0x0A3B591408E1591CULL,
			0x644522A846ADD0CCULL,
			0x40967484E70C6D36ULL}
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

	steps = 34;
	X1 = (curve25519_key_t){.key64 = {
		0xDF05BD49CB15AB58ULL,
		0xF6319F98A34DEF4AULL,
		0xA9C7F1B704FD5508ULL,
		0x6260A126F5708F4FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDF05BD49CB15AB58ULL,
			0xF6319F98A34DEF4AULL,
			0xA9C7F1B704FD5508ULL,
			0x6260A126F5708F4FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x704993A1E68E4D9BULL,
			0x9CF5797773B2957FULL,
			0x675311C028B75E52ULL,
			0x16684D77289B363EULL}
		},
		.Z = {.key64 = {
			0x0B02D627ADE7BF69ULL,
			0x3D3396ACC1F5E506ULL,
			0xB96A558B418DA44EULL,
			0x5AA57B44F4A8BFD6ULL}
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

	steps = 24;
	X1 = (curve25519_key_t){.key64 = {
		0xB031942158174B60ULL,
		0x3F0C7C8A77CD4689ULL,
		0xE9A63DFD1A73C8A8ULL,
		0x458FA9EFF7F38E85ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB031942158174B60ULL,
			0x3F0C7C8A77CD4689ULL,
			0xE9A63DFD1A73C8A8ULL,
			0x458FA9EFF7F38E85ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC92B25C228A75824ULL,
			0x84DB3A9CD8C2D413ULL,
			0x7E0357A55CC73484ULL,
			0x59E58A50C5E9E90EULL}
		},
		.Z = {.key64 = {
			0x37AC51F7E71677AFULL,
			0xD0CF4E314415027DULL,
			0xCBB8EF417689C94DULL,
			0x46F5F78411793019ULL}
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

	steps = 41;
	X1 = (curve25519_key_t){.key64 = {
		0x4B5707677D120838ULL,
		0xEA858DC8A2E7EFEBULL,
		0x54FCD08680295A77ULL,
		0x7B41A8CAB2C412D3ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4B5707677D120838ULL,
			0xEA858DC8A2E7EFEBULL,
			0x54FCD08680295A77ULL,
			0x7B41A8CAB2C412D3ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFF3767F80B0A58E5ULL,
			0x75B55DE2953B9666ULL,
			0x0A6C0ECD04C60081ULL,
			0x5052A60EB671ADB3ULL}
		},
		.Z = {.key64 = {
			0x4FFB39CC2B715397ULL,
			0x1452D33A3383C956ULL,
			0xC53F51DF621EB294ULL,
			0x29C4EBD7100F0A07ULL}
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

	steps = 5;
	X1 = (curve25519_key_t){.key64 = {
		0x277202FD67A46468ULL,
		0xEB1409845A0598BBULL,
		0xFEFFAB06EFAD2AB1ULL,
		0x5A634308F837EBD2ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x277202FD67A46468ULL,
			0xEB1409845A0598BBULL,
			0xFEFFAB06EFAD2AB1ULL,
			0x5A634308F837EBD2ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA46631CC1FE60D5BULL,
			0x3F8C5FE08AACE317ULL,
			0x2797175F80F0BDF5ULL,
			0x3D6A6FBB68B6718FULL}
		},
		.Z = {.key64 = {
			0x230B1CBB039EE233ULL,
			0x69F5C54AF8C7D6EEULL,
			0x522642D3C2DF6697ULL,
			0x72C5C196DCA800E9ULL}
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

	steps = 50;
	X1 = (curve25519_key_t){.key64 = {
		0x5F124B7B77C33BC8ULL,
		0x9E4436344FDBC909ULL,
		0xBD4F89A49B476580ULL,
		0x7ABC692FBC180694ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5F124B7B77C33BC8ULL,
			0x9E4436344FDBC909ULL,
			0xBD4F89A49B476580ULL,
			0x7ABC692FBC180694ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCE8D4957F24B664BULL,
			0x62633EE183CDB469ULL,
			0x082871EBA07BE24EULL,
			0x06F550A81A1A2FA0ULL}
		},
		.Z = {.key64 = {
			0x1891C70080521321ULL,
			0xFFEEC61040EB0145ULL,
			0xE038835271EC290FULL,
			0x57F50999818501FFULL}
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

	steps = 8;
	X1 = (curve25519_key_t){.key64 = {
		0x0663FDFD3E03EC68ULL,
		0xBF6D22C996D664F6ULL,
		0x094731538D2B44BBULL,
		0x45F14E22CEB29744ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0663FDFD3E03EC68ULL,
			0xBF6D22C996D664F6ULL,
			0x094731538D2B44BBULL,
			0x45F14E22CEB29744ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF846D2C0C2D7CCB9ULL,
			0x0408AA9CBF148A34ULL,
			0x3B6D888850F06204ULL,
			0x79C55B14E7A197D2ULL}
		},
		.Z = {.key64 = {
			0x6C38FB016B9773D3ULL,
			0x838EA8F61C40B967ULL,
			0xAE2E0DF284F91CE5ULL,
			0x3AD2908ED09DCAF0ULL}
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

	steps = 46;
	X1 = (curve25519_key_t){.key64 = {
		0x98BAFE4F13089378ULL,
		0x738BBC7D1291039CULL,
		0x9C0B843BC90F7CA2ULL,
		0x52BAAD0450EF46BFULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x98BAFE4F13089378ULL,
			0x738BBC7D1291039CULL,
			0x9C0B843BC90F7CA2ULL,
			0x52BAAD0450EF46BFULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8EB699FACDC8660DULL,
			0x27A929E295271D73ULL,
			0xD30CF6DABAACCBD2ULL,
			0x4DA402B3A9F600DAULL}
		},
		.Z = {.key64 = {
			0xD700C188CE1577FCULL,
			0xF999865BEF5D2317ULL,
			0xA9A414F2B367A763ULL,
			0x455551CCF156D44AULL}
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

	steps = 23;
	X1 = (curve25519_key_t){.key64 = {
		0xD364A5F05F8225F0ULL,
		0xCC81F833848B6A86ULL,
		0x24F5AEB4CE47E45DULL,
		0x5E335B1C77CF8F0FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD364A5F05F8225F0ULL,
			0xCC81F833848B6A86ULL,
			0x24F5AEB4CE47E45DULL,
			0x5E335B1C77CF8F0FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x56B20A7121568EFAULL,
			0x90B7046F3C15CA40ULL,
			0x74EBA96F9DAB3D93ULL,
			0x0517567EBAEF5881ULL}
		},
		.Z = {.key64 = {
			0x3697C05C64F338DBULL,
			0xB3986CB920BB54EFULL,
			0x1AC598283695FFA7ULL,
			0x1B219D2F13193C82ULL}
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

	steps = 23;
	X1 = (curve25519_key_t){.key64 = {
		0xD8EBAB0F08E96E88ULL,
		0xF47952F2663E9026ULL,
		0x45DFD5E627304768ULL,
		0x44C9D7ABB4FA885AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD8EBAB0F08E96E88ULL,
			0xF47952F2663E9026ULL,
			0x45DFD5E627304768ULL,
			0x44C9D7ABB4FA885AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA14917923EC9288EULL,
			0x991F253282BDF5B9ULL,
			0x1A23424A15E5C96DULL,
			0x1A6DF0E739D0103BULL}
		},
		.Z = {.key64 = {
			0x839536725EF3F816ULL,
			0x64237EF8D25A01D6ULL,
			0xB1DEDE20F066E06FULL,
			0x1018C82C21C49879ULL}
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

	steps = 38;
	X1 = (curve25519_key_t){.key64 = {
		0x41F519FCEDC1AF68ULL,
		0x3067CB6CE97C76C4ULL,
		0x088137C8070DE235ULL,
		0x71B5832DDF64ADE0ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x41F519FCEDC1AF68ULL,
			0x3067CB6CE97C76C4ULL,
			0x088137C8070DE235ULL,
			0x71B5832DDF64ADE0ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x760377B9B1CE57B7ULL,
			0xBB497B4C7FD34B00ULL,
			0xF4FE03B2F4200B25ULL,
			0x1928C519B07B7518ULL}
		},
		.Z = {.key64 = {
			0x2F39AB88DB77B086ULL,
			0x59FAACC320A142B0ULL,
			0xC8F909A05395B001ULL,
			0x28C71028D7DDEC5AULL}
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

	steps = 61;
	X1 = (curve25519_key_t){.key64 = {
		0xA895F1563CD66E20ULL,
		0xC886B6D18B426164ULL,
		0xD5DC64C19EB9FF0DULL,
		0x6BA1642C9A8EE585ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA895F1563CD66E20ULL,
			0xC886B6D18B426164ULL,
			0xD5DC64C19EB9FF0DULL,
			0x6BA1642C9A8EE585ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1ADC10C87F6A8E0CULL,
			0xC65DD7F3AFD3CE0BULL,
			0x3B8EDF4E667C5ACDULL,
			0x15DB20AAB0858A0BULL}
		},
		.Z = {.key64 = {
			0x212486711EC549B3ULL,
			0x51D9FAD0C4D7CAE5ULL,
			0x108CEB01278D5661ULL,
			0x2C868EEE011A3899ULL}
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

	steps = 9;
	X1 = (curve25519_key_t){.key64 = {
		0x10D082CCA76AD7F0ULL,
		0x26BC8B11ADEB4B2AULL,
		0xE1D78244F9233092ULL,
		0x525B85D60B696167ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x10D082CCA76AD7F0ULL,
			0x26BC8B11ADEB4B2AULL,
			0xE1D78244F9233092ULL,
			0x525B85D60B696167ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF7F8F23584AC72A5ULL,
			0xFAA2D8A6BDBC62BBULL,
			0x9B4D25C398ED1A3DULL,
			0x70B386F5F293667DULL}
		},
		.Z = {.key64 = {
			0xB35B6176CDA1EDA0ULL,
			0x7FA87D3E4F17964BULL,
			0x32D98D77EBDC85D8ULL,
			0x46C9A8D89488062EULL}
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

	steps = 35;
	X1 = (curve25519_key_t){.key64 = {
		0xF83EA735C246A8E8ULL,
		0x4300D9F672E6F100ULL,
		0x6E8B451E3FBE7F4AULL,
		0x68ACEBA72B7F4A06ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF83EA735C246A8E8ULL,
			0x4300D9F672E6F100ULL,
			0x6E8B451E3FBE7F4AULL,
			0x68ACEBA72B7F4A06ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x02321A5BAEB10FD1ULL,
			0x906F809AB46B6421ULL,
			0x2F142BC6FCC6D36AULL,
			0x3C5A992401697DDFULL}
		},
		.Z = {.key64 = {
			0xEEE91A0319F9CE9FULL,
			0x637390E459D2D9D9ULL,
			0xD42B59F100D01CB1ULL,
			0x5D25498D9D0CEFFBULL}
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

	steps = 18;
	X1 = (curve25519_key_t){.key64 = {
		0x9EB02D2BD864B830ULL,
		0xCD9E893CF8723256ULL,
		0xC687E953D1EBC0B8ULL,
		0x7E2184728EC0FE11ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9EB02D2BD864B830ULL,
			0xCD9E893CF8723256ULL,
			0xC687E953D1EBC0B8ULL,
			0x7E2184728EC0FE11ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8342FAAF3536228DULL,
			0xC618A9F52C2E4B0BULL,
			0x54D277FD04D053B0ULL,
			0x6F3E3BF8F1D10D2EULL}
		},
		.Z = {.key64 = {
			0xAABB29857053F85BULL,
			0xCAD41A535865A5EDULL,
			0x473A3F57461C545BULL,
			0x533273587D308FC5ULL}
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

	steps = 41;
	X1 = (curve25519_key_t){.key64 = {
		0xC3875A3E02F3AA28ULL,
		0x8901EC23A9B2BADCULL,
		0x23943F1C64BDFB80ULL,
		0x5DAFF597CD13EEDCULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC3875A3E02F3AA28ULL,
			0x8901EC23A9B2BADCULL,
			0x23943F1C64BDFB80ULL,
			0x5DAFF597CD13EEDCULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x011D44F17922CF33ULL,
			0x721A5712B9046428ULL,
			0x777DA5D15A75BE1DULL,
			0x7B908CDE0EAD7E97ULL}
		},
		.Z = {.key64 = {
			0xD5847BA1BA0CECF8ULL,
			0x527DCDC910C44CEEULL,
			0x1ED2CB2FB5FC5AA1ULL,
			0x07D3B4E2DA2E7F02ULL}
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

	steps = 1;
	X1 = (curve25519_key_t){.key64 = {
		0x7BEFE2DDD53A7158ULL,
		0xBD101668C40AF100ULL,
		0xF0453067CB2655E3ULL,
		0x7B63DE00F28E0E86ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7BEFE2DDD53A7158ULL,
			0xBD101668C40AF100ULL,
			0xF0453067CB2655E3ULL,
			0x7B63DE00F28E0E86ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6992DDC3F3CCE569ULL,
			0xA8D2A3F08C3F8ECAULL,
			0x42350288EB803311ULL,
			0x72B10B41A063B0CDULL}
		},
		.Z = {.key64 = {
			0xEFBF8B7754E9C599ULL,
			0xF44059A3102BC401ULL,
			0xC114C19F2C99578EULL,
			0x6D8F7803CA383A1BULL}
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

	steps = 61;
	X1 = (curve25519_key_t){.key64 = {
		0x16DD09E855BFE428ULL,
		0x3DB3B15CAC125042ULL,
		0x06D224F2564D65A3ULL,
		0x7B6C1032FE337C85ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x16DD09E855BFE428ULL,
			0x3DB3B15CAC125042ULL,
			0x06D224F2564D65A3ULL,
			0x7B6C1032FE337C85ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x25F824F34C7B0459ULL,
			0x881FBC2D3FEE9F0FULL,
			0x2FA8C4D423871ABDULL,
			0x142752C5110B2AC7ULL}
		},
		.Z = {.key64 = {
			0x0CED2371D3BDBF2AULL,
			0x2EC5519A8090232AULL,
			0xD777370AC9B46081ULL,
			0x1512CDC1470057A9ULL}
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

	steps = 38;
	X1 = (curve25519_key_t){.key64 = {
		0x57F3E19905F442E0ULL,
		0xEE7079AA4388A904ULL,
		0x7DD1712D54C08966ULL,
		0x52DB785B50BE7A48ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x57F3E19905F442E0ULL,
			0xEE7079AA4388A904ULL,
			0x7DD1712D54C08966ULL,
			0x52DB785B50BE7A48ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3E998BAE3031F307ULL,
			0xFCFCAE06768D708EULL,
			0x431ECC73EA217D9DULL,
			0x0658B897F822D493ULL}
		},
		.Z = {.key64 = {
			0x976171D0F7A3A18EULL,
			0x00DDE77862D4C90CULL,
			0x9D13893EC04D865AULL,
			0x70D6716BDE27E8CFULL}
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

	steps = 42;
	X1 = (curve25519_key_t){.key64 = {
		0x208B807FE1A3C520ULL,
		0x6616314AF74758CAULL,
		0x93CE49A82E90517EULL,
		0x579A882E5183EBC9ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x208B807FE1A3C520ULL,
			0x6616314AF74758CAULL,
			0x93CE49A82E90517EULL,
			0x579A882E5183EBC9ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3DC137A43A281B55ULL,
			0x2C669319F9914ABCULL,
			0xFF9B9061B5823899ULL,
			0x72EA94941119E38DULL}
		},
		.Z = {.key64 = {
			0x982B0850FA0E4AA7ULL,
			0xFFCABA2DF46BBA84ULL,
			0x65F72E2BA0AF649DULL,
			0x51450F7EB6111534ULL}
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

	steps = 11;
	X1 = (curve25519_key_t){.key64 = {
		0x5F2CFD795F0CC918ULL,
		0xD7AED87AD3125C72ULL,
		0x6130394A7FD183AAULL,
		0x4EDCF953ADDE271AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5F2CFD795F0CC918ULL,
			0xD7AED87AD3125C72ULL,
			0x6130394A7FD183AAULL,
			0x4EDCF953ADDE271AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x631074028EDBEF6AULL,
			0xD92DF30802525143ULL,
			0x0988A3AD6021DC29ULL,
			0x43278BEFC0D395C8ULL}
		},
		.Z = {.key64 = {
			0x4EC572F54CCA2298ULL,
			0x2D4E71B92FCC30CFULL,
			0x3423EC19466F6F0FULL,
			0x51C8F87E3D8707EBULL}
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

	steps = 49;
	X1 = (curve25519_key_t){.key64 = {
		0x4F3060229E046AE8ULL,
		0x21E203DDBB9F74B3ULL,
		0xCEDAAC0EFA37138FULL,
		0x72A280C1FADBB03AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4F3060229E046AE8ULL,
			0x21E203DDBB9F74B3ULL,
			0xCEDAAC0EFA37138FULL,
			0x72A280C1FADBB03AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x78E8B894AEDB337EULL,
			0x643977E4CD7EB0D4ULL,
			0x8656C1E5924802E7ULL,
			0x0475F3ED8A17EB99ULL}
		},
		.Z = {.key64 = {
			0xE37372A9A2A7CB09ULL,
			0xADAE988F7EF98CCAULL,
			0xB937CFBE6CDBA8DFULL,
			0x441BE99A8D3D4426ULL}
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

	steps = 27;
	X1 = (curve25519_key_t){.key64 = {
		0xF4C27CDDEF1BEDB0ULL,
		0xD99EEC856E630686ULL,
		0x8AAD7B09434DD8AFULL,
		0x475D6A0C7F7D7700ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF4C27CDDEF1BEDB0ULL,
			0xD99EEC856E630686ULL,
			0x8AAD7B09434DD8AFULL,
			0x475D6A0C7F7D7700ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBF1816DF19FDF6D9ULL,
			0x894543AD40A80E65ULL,
			0xD4E2A8ED747EE3BAULL,
			0x321144CC6E81EF2EULL}
		},
		.Z = {.key64 = {
			0xCD3DE5B0341D94E4ULL,
			0x79D2C08343BF9707ULL,
			0x0B35776A4A450AE8ULL,
			0x68BD01E205A8BD75ULL}
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

	steps = 38;
	X1 = (curve25519_key_t){.key64 = {
		0x63FCD19CED6C68B0ULL,
		0x91436522E474E60CULL,
		0x979E3E00FA3EE0EDULL,
		0x579C3DB8A934DC29ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x63FCD19CED6C68B0ULL,
			0x91436522E474E60CULL,
			0x979E3E00FA3EE0EDULL,
			0x579C3DB8A934DC29ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE395EB14290A0763ULL,
			0xF7C620BAFFB17467ULL,
			0xD742FF889D6A8DF0ULL,
			0x661311D9ABDA21A6ULL}
		},
		.Z = {.key64 = {
			0xA6724E3D6EF178FCULL,
			0x223C6D11AC919871ULL,
			0x1D00DD4A0572DF31ULL,
			0x3B2A014AFAA6EAEDULL}
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

	steps = 8;
	X1 = (curve25519_key_t){.key64 = {
		0xC6EE763D80F46BF0ULL,
		0x74BDF41FA5A7586FULL,
		0x241ABCDE0CF02802ULL,
		0x40211A335A0D257CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC6EE763D80F46BF0ULL,
			0x74BDF41FA5A7586FULL,
			0x241ABCDE0CF02802ULL,
			0x40211A335A0D257CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAE380CA5421E5BF5ULL,
			0x9CCC2C8B31BE1162ULL,
			0x42DDE2B21121021CULL,
			0x5DE162E033C81C67ULL}
		},
		.Z = {.key64 = {
			0x7B5E6A293EC1C265ULL,
			0xE691541C17C09441ULL,
			0xCD9420E8E31FB701ULL,
			0x482BF41169C51D1FULL}
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

	steps = 35;
	X1 = (curve25519_key_t){.key64 = {
		0x4D85AA85C7219A28ULL,
		0x6EAEFB5209869E4DULL,
		0x7254CA362E6486F8ULL,
		0x6BBB8264C8B33E8CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4D85AA85C7219A28ULL,
			0x6EAEFB5209869E4DULL,
			0x7254CA362E6486F8ULL,
			0x6BBB8264C8B33E8CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA011C453B0141617ULL,
			0x36B0EDFD337786F6ULL,
			0x05E90020A05CA8C7ULL,
			0x55F97BD31EC8F399ULL}
		},
		.Z = {.key64 = {
			0x4A2B52E06E48E347ULL,
			0xFDE4A99B1B59168BULL,
			0xBECB83BBDA5D959CULL,
			0x673D7709A7C4E551ULL}
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

	steps = 3;
	X1 = (curve25519_key_t){.key64 = {
		0x91ED3383431DE718ULL,
		0xCC4F5E900473C824ULL,
		0x4F6F0889CE8C95E6ULL,
		0x7494904CE9969250ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x91ED3383431DE718ULL,
			0xCC4F5E900473C824ULL,
			0x4F6F0889CE8C95E6ULL,
			0x7494904CE9969250ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x499E8E2930418AEEULL,
			0x2352508077799802ULL,
			0x88B3EBB1CDC402C2ULL,
			0x68BE4F884E1F5274ULL}
		},
		.Z = {.key64 = {
			0xBC97823C98352D1FULL,
			0xEF3E941C7F48C62DULL,
			0x84BDC62F07A61DEAULL,
			0x69BC0DEBBEAA01ECULL}
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

	steps = 47;
	X1 = (curve25519_key_t){.key64 = {
		0x111568D112D79440ULL,
		0x899C04A5C1AB1EDBULL,
		0xD12388C5A054572DULL,
		0x446E88DF0F87029EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x111568D112D79440ULL,
			0x899C04A5C1AB1EDBULL,
			0xD12388C5A054572DULL,
			0x446E88DF0F87029EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5B5D105759756489ULL,
			0x123510E8E17548CEULL,
			0x75048271B27A5949ULL,
			0x5C389BE2C338D7F0ULL}
		},
		.Z = {.key64 = {
			0xA250ADF9E99B5575ULL,
			0x23A825E16E959A07ULL,
			0x0536E3B3AB7A0201ULL,
			0x56D88EE989075050ULL}
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

	steps = 5;
	X1 = (curve25519_key_t){.key64 = {
		0x69519C6D8B22B020ULL,
		0x891A096BB4B8A598ULL,
		0x2E1E14D72F2EAD34ULL,
		0x7B8B59B4B17309E2ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x69519C6D8B22B020ULL,
			0x891A096BB4B8A598ULL,
			0x2E1E14D72F2EAD34ULL,
			0x7B8B59B4B17309E2ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x98C0362EE2DDF351ULL,
			0x77DA70FD52691721ULL,
			0xA583E0DC5F7F05EDULL,
			0x28735932165D0CDBULL}
		},
		.Z = {.key64 = {
			0xF723A737E62E600DULL,
			0x1528BB40E236F7D3ULL,
			0x9117D4E6209CE840ULL,
			0x4D1FE7D3388BC1B1ULL}
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

	steps = 24;
	X1 = (curve25519_key_t){.key64 = {
		0x1B354F24E3BAD198ULL,
		0xDF79C4FAB00CC3B5ULL,
		0xD9FEB96421D6789CULL,
		0x493F213E51516D8DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1B354F24E3BAD198ULL,
			0xDF79C4FAB00CC3B5ULL,
			0xD9FEB96421D6789CULL,
			0x493F213E51516D8DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBDBBE1A64FE910CAULL,
			0xA52E17454D66A51EULL,
			0xDBF92D30C8087058ULL,
			0x13C462D98EA021BFULL}
		},
		.Z = {.key64 = {
			0x1A58784D8E1C0AE9ULL,
			0xA3BEC5D35FFDD5A2ULL,
			0x0BDBD538E905AB84ULL,
			0x66BE0E6623EF166DULL}
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

	steps = 55;
	X1 = (curve25519_key_t){.key64 = {
		0xE6CDA9054FE44988ULL,
		0xB58EB23A9E0C4675ULL,
		0x10CEB2201CA713CCULL,
		0x5B33DB5423EE6851ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE6CDA9054FE44988ULL,
			0xB58EB23A9E0C4675ULL,
			0x10CEB2201CA713CCULL,
			0x5B33DB5423EE6851ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0D8880C0697E8F15ULL,
			0x95D33085872DB5A3ULL,
			0x045A1584D83C608CULL,
			0x5ECD9DEE0D4A47B3ULL}
		},
		.Z = {.key64 = {
			0x6C88BC3ABC68FA0BULL,
			0x674E1BB1B77D8D9EULL,
			0xAF955D0B212AC32DULL,
			0x4F6313C1038D74C9ULL}
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

	steps = 24;
	X1 = (curve25519_key_t){.key64 = {
		0x768153752F4905F0ULL,
		0x1318873079A7CFE3ULL,
		0xE986D40DB557BB00ULL,
		0x65F7D1818EC25997ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x768153752F4905F0ULL,
			0x1318873079A7CFE3ULL,
			0xE986D40DB557BB00ULL,
			0x65F7D1818EC25997ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7D0FAF0F8D7448A2ULL,
			0x3933124FC0BCF744ULL,
			0x157B5CB87CED2925ULL,
			0x0317D8E0F1E21BB1ULL}
		},
		.Z = {.key64 = {
			0xBE6F996DBFBB84C5ULL,
			0x25660F1D0B78903AULL,
			0xCDA8860AA2951A3EULL,
			0x00B8D94DA5D6F301ULL}
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

	steps = 45;
	X1 = (curve25519_key_t){.key64 = {
		0x95DEB8075070F508ULL,
		0xC60D5C9587D1AF12ULL,
		0x5D5750D1CA290F01ULL,
		0x4367C86940BAA39FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x95DEB8075070F508ULL,
			0xC60D5C9587D1AF12ULL,
			0x5D5750D1CA290F01ULL,
			0x4367C86940BAA39FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6A490F23775C6D97ULL,
			0xAA3559AE00115DFBULL,
			0xE53AAA9601758F02ULL,
			0x1E79C9BF9090591FULL}
		},
		.Z = {.key64 = {
			0xC33F778F212D27BDULL,
			0x46596818C99479A5ULL,
			0xF337EEABD15F113FULL,
			0x009C211725400D98ULL}
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

	steps = 17;
	X1 = (curve25519_key_t){.key64 = {
		0x020BF64369B4B6B8ULL,
		0x9B61420DB73F43F8ULL,
		0xD6BA55A65BF9948BULL,
		0x51F6690C489A669CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x020BF64369B4B6B8ULL,
			0x9B61420DB73F43F8ULL,
			0xD6BA55A65BF9948BULL,
			0x51F6690C489A669CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7BD42B02F66E8B98ULL,
			0x83F7C0CDC61A9E8DULL,
			0xC385B3B8E10E937BULL,
			0x5BABAB7B60DC4E64ULL}
		},
		.Z = {.key64 = {
			0xD92941005FE89117ULL,
			0x3338544C5F69732DULL,
			0xF68D99F39DFA7541ULL,
			0x431FA340959DBE68ULL}
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

	steps = 38;
	X1 = (curve25519_key_t){.key64 = {
		0x51D9E03553061BD0ULL,
		0x97E1B96293BEA03DULL,
		0x98D885F60067235BULL,
		0x49F4AFBEBC4BCC56ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x51D9E03553061BD0ULL,
			0x97E1B96293BEA03DULL,
			0x98D885F60067235BULL,
			0x49F4AFBEBC4BCC56ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE76751E9A99F53F3ULL,
			0x7699B942EAED793BULL,
			0x0F052DBB27910122ULL,
			0x5AC6B9161972EA1AULL}
		},
		.Z = {.key64 = {
			0xAD3C3C4BC38ED4ECULL,
			0x5F1BA77D6E92967EULL,
			0xB4F42D0BD87F2713ULL,
			0x51476E68661A0C11ULL}
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

	steps = 32;
	X1 = (curve25519_key_t){.key64 = {
		0xA04DD45D362E97F0ULL,
		0xBD353B29450E7BCEULL,
		0x2FFBA7A3D824DFBDULL,
		0x77A25DC3AB0EEBC3ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA04DD45D362E97F0ULL,
			0xBD353B29450E7BCEULL,
			0x2FFBA7A3D824DFBDULL,
			0x77A25DC3AB0EEBC3ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC9884D3BE5A680BCULL,
			0x697CC7C3BC03C2BDULL,
			0xA4628EB01C0102C7ULL,
			0x011D6FA6B53D6BA0ULL}
		},
		.Z = {.key64 = {
			0xB2C7F0CFBB3A70CEULL,
			0x5244D3D9CC524D66ULL,
			0xAE1C4FEBDEA86011ULL,
			0x777FCDC968C1ABADULL}
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

	steps = 40;
	X1 = (curve25519_key_t){.key64 = {
		0x0A4B35BBC091FDE0ULL,
		0xBA47294ABF7D0EACULL,
		0x6A7862B6B5B510CCULL,
		0x4A900D0D121D6C4CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0A4B35BBC091FDE0ULL,
			0xBA47294ABF7D0EACULL,
			0x6A7862B6B5B510CCULL,
			0x4A900D0D121D6C4CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x96D0C23000AECBF7ULL,
			0xDFB8079FB5AFFF7DULL,
			0x68574B96AB41D5CDULL,
			0x6BDBD973740F82E8ULL}
		},
		.Z = {.key64 = {
			0xCB8521015A882EBAULL,
			0x329547801B248438ULL,
			0xE8AF368A7D0F5F08ULL,
			0x2D0D2B8AE157C592ULL}
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