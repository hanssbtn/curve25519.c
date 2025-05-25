#include "../../curve25519.h"
#include "../tests.h"

int32_t curve25519_ladder_step_test(void) {
	printf("Montgomery Ladder Step Test\n");
	int steps = 14;
	curve25519_key_t X1 = {.key64 = {
		0x7D9EBD9245341140ULL,
		0x279BD8A8C75DF60EULL,
		0xCF68F7AFEA3F9E5AULL,
		0x591EEA8A4E7A051FULL
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
			0x7D9EBD9245341140ULL,
			0x279BD8A8C75DF60EULL,
			0xCF68F7AFEA3F9E5AULL,
			0x591EEA8A4E7A051FULL}
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
			0x537D55F3867819A9ULL,
			0x4C432CC9B796DA22ULL,
			0xC62E8CB7CB48F007ULL,
			0x2ACCD0C1EFB9B357ULL}
		},
		.Z = {.key64 = {
			0x92CB327C2A9AAD0CULL,
			0x11BBF16F6E55EEA8ULL,
			0x08905B6154AAE2E7ULL,
			0x70D1C656F8DC972FULL}
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

	steps = 63;
	X1 = (curve25519_key_t){.key64 = {
		0x9B655C973BBFCD78ULL,
		0x43AF5C95135ECA6DULL,
		0x1F699D935DC306E2ULL,
		0x66D4982C7B6D2524ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9B655C973BBFCD78ULL,
			0x43AF5C95135ECA6DULL,
			0x1F699D935DC306E2ULL,
			0x66D4982C7B6D2524ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x815C3C6EB5DDFE49ULL,
			0xE65B7F5D5785DBC7ULL,
			0x0EE19EF8863AD7D6ULL,
			0x6E51D99A8724EF3DULL}
		},
		.Z = {.key64 = {
			0x9CB07B6A9CAF968AULL,
			0xCC86FC464B2AF2A7ULL,
			0xB5C8D69DE001AAB7ULL,
			0x7570DCAC5A04B605ULL}
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

	steps = 6;
	X1 = (curve25519_key_t){.key64 = {
		0xB97020FE5D226468ULL,
		0x9BD4BCC511359A69ULL,
		0x4F56AAB38359C9CCULL,
		0x56E1CBEFF61E93AFULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB97020FE5D226468ULL,
			0x9BD4BCC511359A69ULL,
			0x4F56AAB38359C9CCULL,
			0x56E1CBEFF61E93AFULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC273167E23B01663ULL,
			0xD62A93D401BACD6EULL,
			0x6044023D0513737BULL,
			0x54ECC8531393B456ULL}
		},
		.Z = {.key64 = {
			0xEE51395A944A7D88ULL,
			0x2DA3F090AB41DC01ULL,
			0xA9C7EDC4AC61001AULL,
			0x3DF5E649A30B02E8ULL}
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

	steps = 50;
	X1 = (curve25519_key_t){.key64 = {
		0x8BDB787040433708ULL,
		0x76BF9B4BDEC92ABBULL,
		0x1B99DF9695B7A33BULL,
		0x54B122A08AC04C00ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8BDB787040433708ULL,
			0x76BF9B4BDEC92ABBULL,
			0x1B99DF9695B7A33BULL,
			0x54B122A08AC04C00ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3FF7BC8FF222F66DULL,
			0x2D254E3859A9C92FULL,
			0x4C702F72AFE42EF9ULL,
			0x75C5B4F39092D5DEULL}
		},
		.Z = {.key64 = {
			0x2B12A35E71A3B97CULL,
			0x02889CF135CF7B0FULL,
			0x52FF785C4D7414FBULL,
			0x14484126A97F55BCULL}
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

	steps = 44;
	X1 = (curve25519_key_t){.key64 = {
		0x164A4BE34D0E2A80ULL,
		0x5DD05651937E81AAULL,
		0xA4CDFE48448A35F6ULL,
		0x68206A6900905F70ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x164A4BE34D0E2A80ULL,
			0x5DD05651937E81AAULL,
			0xA4CDFE48448A35F6ULL,
			0x68206A6900905F70ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC8CF0DCF1B99A6CDULL,
			0x6A1D159879F3209DULL,
			0xB5D49D4F70F089F7ULL,
			0x2EA729A99F44B4BFULL}
		},
		.Z = {.key64 = {
			0x50687DB65D27B218ULL,
			0x14868E3300A9CBDBULL,
			0x298C4611A3FBE7EAULL,
			0x257129591EEAC415ULL}
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

	steps = 27;
	X1 = (curve25519_key_t){.key64 = {
		0x2588E1D4518AEAF8ULL,
		0xD6AC9600441526A4ULL,
		0x46F483B1E042AB6DULL,
		0x620FF48F97EC708DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2588E1D4518AEAF8ULL,
			0xD6AC9600441526A4ULL,
			0x46F483B1E042AB6DULL,
			0x620FF48F97EC708DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5AD91CABC7004FF7ULL,
			0x2A6F46145BF9827EULL,
			0xA937C41C1EBA15E1ULL,
			0x35D1675A50E0DB2EULL}
		},
		.Z = {.key64 = {
			0xA8240C2F0FC85DD1ULL,
			0xE49BAB4339CC57E9ULL,
			0xBDEA90B6AEBD7532ULL,
			0x32A5161BFF5CD81AULL}
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

	steps = 24;
	X1 = (curve25519_key_t){.key64 = {
		0xB2FC6C9367012FC0ULL,
		0x98F05EA7EEE81ADDULL,
		0xF5F23752543AE9CDULL,
		0x770B87E672B4D9B4ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB2FC6C9367012FC0ULL,
			0x98F05EA7EEE81ADDULL,
			0xF5F23752543AE9CDULL,
			0x770B87E672B4D9B4ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEEDD8373B4C1EC78ULL,
			0x92197AA886BBABFAULL,
			0x59D43E0DABCA26F5ULL,
			0x0EC74271811C2406ULL}
		},
		.Z = {.key64 = {
			0x7F46F046ED586D02ULL,
			0xB83105962E7E51DCULL,
			0xECDD6CE1C3E2B691ULL,
			0x3E333FE323A96C95ULL}
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

	steps = 56;
	X1 = (curve25519_key_t){.key64 = {
		0x6E5BFEDEE5FA3E20ULL,
		0x2516683F0A8A9EF5ULL,
		0x6044A0065A56C956ULL,
		0x618EC8FFA24FD742ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6E5BFEDEE5FA3E20ULL,
			0x2516683F0A8A9EF5ULL,
			0x6044A0065A56C956ULL,
			0x618EC8FFA24FD742ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC9AA7BBE335F400EULL,
			0x54DFB8A59BE11D4EULL,
			0x7E3AAEDBEA8036A1ULL,
			0x3E91AF7ACCEC7E64ULL}
		},
		.Z = {.key64 = {
			0xD89E9E41D98BDE7CULL,
			0xDC04FF282FB12575ULL,
			0x59AFE45E4FF7FA15ULL,
			0x36FBD53C2F408B19ULL}
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

	steps = 47;
	X1 = (curve25519_key_t){.key64 = {
		0x73EF28615077AC98ULL,
		0x7FD9C6B2D6A8AA97ULL,
		0x2689FB558603E685ULL,
		0x63C18842C70BEEAEULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x73EF28615077AC98ULL,
			0x7FD9C6B2D6A8AA97ULL,
			0x2689FB558603E685ULL,
			0x63C18842C70BEEAEULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x52210E20671C26F8ULL,
			0x4609DA995F1FEBD0ULL,
			0xEF8B9BDAD26421CBULL,
			0x5A3DD962B807EDEEULL}
		},
		.Z = {.key64 = {
			0x1A33EA838EA296E8ULL,
			0x2E704B63EC531567ULL,
			0xB0E550CDDAA5228CULL,
			0x16613504BFD2AE70ULL}
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

	steps = 39;
	X1 = (curve25519_key_t){.key64 = {
		0x6A44DF34C64217F0ULL,
		0xC1B6A40C7D505771ULL,
		0xB9A180DBE3872E34ULL,
		0x73EBBB51C045D0B2ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6A44DF34C64217F0ULL,
			0xC1B6A40C7D505771ULL,
			0xB9A180DBE3872E34ULL,
			0x73EBBB51C045D0B2ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB3A8A41DDBF8830EULL,
			0xC2E0728DF2FE62E8ULL,
			0xA783C0B91225665AULL,
			0x234E0FB30A315163ULL}
		},
		.Z = {.key64 = {
			0x84111C6B9FCE36E5ULL,
			0xA3A98A8448FFA8DFULL,
			0xD39FC88402A4EFB8ULL,
			0x5AFDB864600D7367ULL}
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

	steps = 63;
	X1 = (curve25519_key_t){.key64 = {
		0x0136C40442D2AC90ULL,
		0xAD4CDEF410C8698BULL,
		0x559A7D533AD568FDULL,
		0x7723D59C497EDC65ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0136C40442D2AC90ULL,
			0xAD4CDEF410C8698BULL,
			0x559A7D533AD568FDULL,
			0x7723D59C497EDC65ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x19401E0B72AE267BULL,
			0x6168D90B89B812C0ULL,
			0xCA039F07EA1359D1ULL,
			0x3B5F240C595F849FULL}
		},
		.Z = {.key64 = {
			0x6B5B0279F8FC097EULL,
			0x30B2A1A500EC46B2ULL,
			0x561C49B5FE8EF627ULL,
			0x473F4E03EDCF32C6ULL}
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

	steps = 49;
	X1 = (curve25519_key_t){.key64 = {
		0xF39582B46512D9B0ULL,
		0x0FC4BB8C26B2C42AULL,
		0xE6FC120480C18808ULL,
		0x794BE6321BB4E043ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF39582B46512D9B0ULL,
			0x0FC4BB8C26B2C42AULL,
			0xE6FC120480C18808ULL,
			0x794BE6321BB4E043ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBD0CEF2C45CE97C2ULL,
			0x2DFAC3ED50056296ULL,
			0x13490583EE15F5E2ULL,
			0x5849E085CBAA6128ULL}
		},
		.Z = {.key64 = {
			0xD3993C0B5D12FCAFULL,
			0x2F32C4564F92F734ULL,
			0x5294077205B95EF5ULL,
			0x10BD0142EEFEDAA8ULL}
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

	steps = 39;
	X1 = (curve25519_key_t){.key64 = {
		0x19371375ADC742B8ULL,
		0x48FA641DEA1118C3ULL,
		0xD5E51BBBFEE70900ULL,
		0x599DEACBDD53657CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x19371375ADC742B8ULL,
			0x48FA641DEA1118C3ULL,
			0xD5E51BBBFEE70900ULL,
			0x599DEACBDD53657CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0E14FE920396E2E5ULL,
			0x4396AB342017720BULL,
			0x4878AA1A53736929ULL,
			0x13BF84F5F5C6D1BDULL}
		},
		.Z = {.key64 = {
			0x15AB07A82B1C3189ULL,
			0x52D2A78319F6A77AULL,
			0x03ED536DDAEFAFC3ULL,
			0x5DE7A320DE907E67ULL}
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

	steps = 63;
	X1 = (curve25519_key_t){.key64 = {
		0xFA8A8BB432797820ULL,
		0xBE3DFA3D5021797FULL,
		0x4099F32171C9614EULL,
		0x6293A41F7BCBF33CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFA8A8BB432797820ULL,
			0xBE3DFA3D5021797FULL,
			0x4099F32171C9614EULL,
			0x6293A41F7BCBF33CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB5EFA3DB4B0B4F16ULL,
			0xD445EB2F8A2DC549ULL,
			0xD5D3752BADA96121ULL,
			0x086ABA951A41C416ULL}
		},
		.Z = {.key64 = {
			0x48A8ED6D019C0106ULL,
			0x5CF90026F11DEB05ULL,
			0x2E0484FA762750DAULL,
			0x2857944DEE951E3DULL}
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

	steps = 15;
	X1 = (curve25519_key_t){.key64 = {
		0x318CF45077B84F68ULL,
		0xFD4704BD4074AC81ULL,
		0x7ED3A2AFB3C7DEADULL,
		0x498413411D38DEE6ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x318CF45077B84F68ULL,
			0xFD4704BD4074AC81ULL,
			0x7ED3A2AFB3C7DEADULL,
			0x498413411D38DEE6ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x25241753D8A1490EULL,
			0xCC2BB7EA77456CF8ULL,
			0x0E6709E3F13FF4ADULL,
			0x4D33C3BE14159EEEULL}
		},
		.Z = {.key64 = {
			0x147827A00A65EF6AULL,
			0x6F762929A94F8A7BULL,
			0xAC7C1F7AAE77EA15ULL,
			0x1BF208B8EE023787ULL}
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

	steps = 34;
	X1 = (curve25519_key_t){.key64 = {
		0x01935E80198C8B98ULL,
		0xB79B50333EAEC436ULL,
		0x1B128899EEFF17BDULL,
		0x6DBC27C0F26687DDULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x01935E80198C8B98ULL,
			0xB79B50333EAEC436ULL,
			0x1B128899EEFF17BDULL,
			0x6DBC27C0F26687DDULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x765CB8189A7E5B02ULL,
			0x77DF4A390FF98983ULL,
			0x0A7C25D2ADD7F822ULL,
			0x2C9B34D3F34026D1ULL}
		},
		.Z = {.key64 = {
			0x82360788475A2DCBULL,
			0x89096EFA2DFBB367ULL,
			0x75CFC58C6D85ADA8ULL,
			0x1536152DC7BCA232ULL}
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

	steps = 49;
	X1 = (curve25519_key_t){.key64 = {
		0x7EA055D0EBD11180ULL,
		0x51B2B8BB19D55108ULL,
		0x4CD8418F366B5E5AULL,
		0x7211E38EC0DEB41DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7EA055D0EBD11180ULL,
			0x51B2B8BB19D55108ULL,
			0x4CD8418F366B5E5AULL,
			0x7211E38EC0DEB41DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBF453EE0CE0474E3ULL,
			0xE85C38BDA27C7FB7ULL,
			0x1316136DB9C68593ULL,
			0x7D347F5B0D21751EULL}
		},
		.Z = {.key64 = {
			0xAA05FAE842436463ULL,
			0x45F173D303B0D031ULL,
			0x61527B76793FA4D2ULL,
			0x48B10A26D5279437ULL}
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

	steps = 37;
	X1 = (curve25519_key_t){.key64 = {
		0x55774AC2A6434188ULL,
		0xAC08E935686D11A2ULL,
		0xC1478D33E5798F9CULL,
		0x508685BA2C04FED6ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x55774AC2A6434188ULL,
			0xAC08E935686D11A2ULL,
			0xC1478D33E5798F9CULL,
			0x508685BA2C04FED6ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3D70E4F3EF7D40F3ULL,
			0x845A26F0511F3EA5ULL,
			0xB6D85F0A9B2FADC6ULL,
			0x1D3510E5DFA660BCULL}
		},
		.Z = {.key64 = {
			0xE90322ED97A62E68ULL,
			0x3EF580985CB088B5ULL,
			0xE18ED65D7331E182ULL,
			0x5D4D3FAFFFB55D4FULL}
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

	steps = 21;
	X1 = (curve25519_key_t){.key64 = {
		0xF123AC743A371340ULL,
		0x7C1ED22B050BC3F0ULL,
		0xCCF4A27F40A2CA2EULL,
		0x4FC01D29C0AFE0F3ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF123AC743A371340ULL,
			0x7C1ED22B050BC3F0ULL,
			0xCCF4A27F40A2CA2EULL,
			0x4FC01D29C0AFE0F3ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x27B88ACBF221E726ULL,
			0xB78E59E76B3779B4ULL,
			0xB2AB3F1DF9843AE8ULL,
			0x7CC52599BD8052D9ULL}
		},
		.Z = {.key64 = {
			0x900E6316A82BF9EDULL,
			0xD91E5AEF0DF522C7ULL,
			0xF0981B210D64C17AULL,
			0x7A1575BF88834471ULL}
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

	steps = 52;
	X1 = (curve25519_key_t){.key64 = {
		0xF2214DCCD293F058ULL,
		0xBDAB3FCD33FF9ADCULL,
		0x6CC89E3AEE2CE854ULL,
		0x7747243420154461ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF2214DCCD293F058ULL,
			0xBDAB3FCD33FF9ADCULL,
			0x6CC89E3AEE2CE854ULL,
			0x7747243420154461ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCB19FB55B2C1D725ULL,
			0x8F2ABF0C318C5885ULL,
			0x942CD9F933E5F8E6ULL,
			0x60041A7C31A7CEE9ULL}
		},
		.Z = {.key64 = {
			0x694BD8F4E3399425ULL,
			0xA3CB7873BCC48CE2ULL,
			0xBEAE2A4F24D60DD0ULL,
			0x50B206302040FA43ULL}
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

	steps = 29;
	X1 = (curve25519_key_t){.key64 = {
		0x367213D93C312EC0ULL,
		0xF4115B0B8ECFE30BULL,
		0x195FF7073AF386F5ULL,
		0x4B2C632420A66963ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x367213D93C312EC0ULL,
			0xF4115B0B8ECFE30BULL,
			0x195FF7073AF386F5ULL,
			0x4B2C632420A66963ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3B15B8B7FACB7F91ULL,
			0x8D10E0F5D6FF182BULL,
			0x2CAA105D36521DC4ULL,
			0x02202753DFDBDF13ULL}
		},
		.Z = {.key64 = {
			0xEBBD8718B9F05EDCULL,
			0xD04C47931D6551DBULL,
			0x6E729D6E4504D896ULL,
			0x0B19031021B35285ULL}
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

	steps = 9;
	X1 = (curve25519_key_t){.key64 = {
		0x47D80E9CAFDA4580ULL,
		0x02BDDA599DE5BDDCULL,
		0x422A24C6A3E081C7ULL,
		0x5776EAAB9BCBF798ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x47D80E9CAFDA4580ULL,
			0x02BDDA599DE5BDDCULL,
			0x422A24C6A3E081C7ULL,
			0x5776EAAB9BCBF798ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBBBC93022BA2C292ULL,
			0xDA7B0DE541F0ABB7ULL,
			0x137EDEDF748A6DB9ULL,
			0x5E42B45F506DCF3DULL}
		},
		.Z = {.key64 = {
			0xD34C64B784BF270BULL,
			0xD1EA32B65A1A4057ULL,
			0xFDE7A197FE6BE8DEULL,
			0x78D7557787F88F77ULL}
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

	steps = 2;
	X1 = (curve25519_key_t){.key64 = {
		0x9CB5318976801518ULL,
		0x59B7624011F81164ULL,
		0x3EC1907A0B8C015BULL,
		0x490D45BD48426C61ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9CB5318976801518ULL,
			0x59B7624011F81164ULL,
			0x3EC1907A0B8C015BULL,
			0x490D45BD48426C61ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBE6E31C2664BA62FULL,
			0x99A57851ACE3C441ULL,
			0x8AB1E6BD307E3D5EULL,
			0x69BB771F73D4F753ULL}
		},
		.Z = {.key64 = {
			0xAE4D82A68DD5D473ULL,
			0x659EF41C3D47EA05ULL,
			0xBD4CA1ED27AD23AFULL,
			0x7FC5DFD607A12C2FULL}
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

	steps = 51;
	X1 = (curve25519_key_t){.key64 = {
		0x646F91E669034CC0ULL,
		0xB92F8FC56ABF27A9ULL,
		0xCED92406EA271FFEULL,
		0x440498260EF73608ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x646F91E669034CC0ULL,
			0xB92F8FC56ABF27A9ULL,
			0xCED92406EA271FFEULL,
			0x440498260EF73608ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEB2A72D3BF249B2BULL,
			0xAE0140624C64907EULL,
			0x6C2CEF1C7E438291ULL,
			0x544CD34373AB1294ULL}
		},
		.Z = {.key64 = {
			0xF9A03E2348835ECCULL,
			0x81CC6F61E7190047ULL,
			0xC865C5A7E99833B8ULL,
			0x23634A26EF694FFCULL}
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
		0xDEF49DE398D735D0ULL,
		0x9C10B6471F0E1BFDULL,
		0x81F8F786A3A51B9CULL,
		0x5CFC8FBAAA0D7DB0ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDEF49DE398D735D0ULL,
			0x9C10B6471F0E1BFDULL,
			0x81F8F786A3A51B9CULL,
			0x5CFC8FBAAA0D7DB0ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0F56A5BAA6BE751BULL,
			0x90AD8A7EF00CA2AEULL,
			0x583614531F834DA2ULL,
			0x23FEB2C19DCA7309ULL}
		},
		.Z = {.key64 = {
			0xBC5FEC6986FA277BULL,
			0x3DC4717B062CBADDULL,
			0x394CB536C6ADEF25ULL,
			0x59FFA54D52AC8375ULL}
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

	steps = 31;
	X1 = (curve25519_key_t){.key64 = {
		0xD7DC18EF1C936638ULL,
		0xE9D4A9EA99947360ULL,
		0x22940C33E88C7C11ULL,
		0x606AFDBAF562F686ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD7DC18EF1C936638ULL,
			0xE9D4A9EA99947360ULL,
			0x22940C33E88C7C11ULL,
			0x606AFDBAF562F686ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x899028D8FFB19EDAULL,
			0x00B27A7DCA1CC045ULL,
			0xBBA4EB23C4FD4596ULL,
			0x1A587D83873E10E5ULL}
		},
		.Z = {.key64 = {
			0xA368F80B129AD9F7ULL,
			0xE5CAA741E7A6E2A2ULL,
			0x9D25964F6ED3530FULL,
			0x331D7DD0D7BC2150ULL}
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
		0x6563A4BE81B5D8A8ULL,
		0x94E191384F9404AEULL,
		0x2688C6A2793A5ED1ULL,
		0x447B2C97857BF5CCULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6563A4BE81B5D8A8ULL,
			0x94E191384F9404AEULL,
			0x2688C6A2793A5ED1ULL,
			0x447B2C97857BF5CCULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7AE3101FBEA6A02EULL,
			0x574053ACB32974DEULL,
			0xC897B4C31BBE7C73ULL,
			0x10F8681745BA5FC6ULL}
		},
		.Z = {.key64 = {
			0x9EA432ACABEA6B61ULL,
			0x338A9261FDEFD7B1ULL,
			0xCF35D99AB4873871ULL,
			0x2A677F1AFB1A0F3AULL}
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

	steps = 46;
	X1 = (curve25519_key_t){.key64 = {
		0xA5D8FF8D362A5A68ULL,
		0xE244DC52B6ECE921ULL,
		0x2406B5EBFF52650CULL,
		0x51A676D2B4D45288ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA5D8FF8D362A5A68ULL,
			0xE244DC52B6ECE921ULL,
			0x2406B5EBFF52650CULL,
			0x51A676D2B4D45288ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x85C6D7F7F1A56C2BULL,
			0x90F010903640C750ULL,
			0x7D16D6A4F7B5288EULL,
			0x5971D3A50DBB194CULL}
		},
		.Z = {.key64 = {
			0x46C29697A3B13E3BULL,
			0x90885AFE3A0AB795ULL,
			0x85768584C93AD09AULL,
			0x4F64E83B244BC2DCULL}
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

	steps = 31;
	X1 = (curve25519_key_t){.key64 = {
		0xF7E3D25891B724A8ULL,
		0x984857F695B594E8ULL,
		0x80103BEA73C4F0C0ULL,
		0x4B2E252E759C341DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF7E3D25891B724A8ULL,
			0x984857F695B594E8ULL,
			0x80103BEA73C4F0C0ULL,
			0x4B2E252E759C341DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x16CE7C858531D14CULL,
			0x1704B75642A231E8ULL,
			0x79C76323D5275BA3ULL,
			0x2E8A326C9F27B774ULL}
		},
		.Z = {.key64 = {
			0x90E126C1E050AAA9ULL,
			0xDBD7B17F80262E15ULL,
			0x45A7F9D47712F329ULL,
			0x1E000F758FE4F89CULL}
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

	steps = 54;
	X1 = (curve25519_key_t){.key64 = {
		0x9CD32A147CF93B70ULL,
		0x0C347B99A025FD94ULL,
		0x5BE5FB066A8A1E0AULL,
		0x61F8D1D27FD6EEDDULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9CD32A147CF93B70ULL,
			0x0C347B99A025FD94ULL,
			0x5BE5FB066A8A1E0AULL,
			0x61F8D1D27FD6EEDDULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x21BDB981F22188C1ULL,
			0xC4D2785DA07840ADULL,
			0x9D8D904EAF44BE0AULL,
			0x18DDCB2C6C5AB4CEULL}
		},
		.Z = {.key64 = {
			0xD8E3628363E70373ULL,
			0x3C23ED9BBBEF567DULL,
			0x97E64FA0E465E38DULL,
			0x043F79600702EF0FULL}
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

	steps = 39;
	X1 = (curve25519_key_t){.key64 = {
		0x6CDC3004D023A8F8ULL,
		0x4BA505C84CECD0B5ULL,
		0x6A9F9C9B564628A1ULL,
		0x68E08D78763F4893ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6CDC3004D023A8F8ULL,
			0x4BA505C84CECD0B5ULL,
			0x6A9F9C9B564628A1ULL,
			0x68E08D78763F4893ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2DE1B1C43CC13715ULL,
			0x371655B1A7839C10ULL,
			0x011A89B4382F21D3ULL,
			0x129007AB4BCCE3B9ULL}
		},
		.Z = {.key64 = {
			0x7DC2D70206B7B09FULL,
			0x20A8C120B64E163AULL,
			0x2B3B28541C9C8A16ULL,
			0x69EA7E20CAC0CB68ULL}
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

	steps = 2;
	X1 = (curve25519_key_t){.key64 = {
		0x17E4F86C88269108ULL,
		0x6473B819B6118D72ULL,
		0x40F44060AC60AF53ULL,
		0x549B16ECE6F22226ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x17E4F86C88269108ULL,
			0x6473B819B6118D72ULL,
			0x40F44060AC60AF53ULL,
			0x549B16ECE6F22226ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x56D32CFFD6CAA3F5ULL,
			0xE89BAE3124F7C00BULL,
			0x5AC3402DBDF3580EULL,
			0x08DFC593492CCDBFULL}
		},
		.Z = {.key64 = {
			0x108003E84E288152ULL,
			0x6CD3075E9EE176EBULL,
			0xA0B5B1E741583AE4ULL,
			0x187715932DF202E3ULL}
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

	steps = 28;
	X1 = (curve25519_key_t){.key64 = {
		0xA1366EDE100A7040ULL,
		0x32810189D47B6457ULL,
		0xB547A6BDB0C03FB3ULL,
		0x64490D7E7CD4F0ACULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA1366EDE100A7040ULL,
			0x32810189D47B6457ULL,
			0xB547A6BDB0C03FB3ULL,
			0x64490D7E7CD4F0ACULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x105B175319791ED3ULL,
			0xCC2A5D786B1244A2ULL,
			0x3CE6FC7B02CE1103ULL,
			0x5DF85E39D60C7257ULL}
		},
		.Z = {.key64 = {
			0x5C1603535CC99FB1ULL,
			0x9C92D1E6F7A617D5ULL,
			0x24EEF33201ED314CULL,
			0x74347A31051C1468ULL}
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

	steps = 22;
	X1 = (curve25519_key_t){.key64 = {
		0x4C102F8CAF14F3F8ULL,
		0x359E0F3895618699ULL,
		0x9C733BE432BF37C9ULL,
		0x56EAF70CDD2DD9E0ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4C102F8CAF14F3F8ULL,
			0x359E0F3895618699ULL,
			0x9C733BE432BF37C9ULL,
			0x56EAF70CDD2DD9E0ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x20D2CAF5381DB475ULL,
			0x825251D2C64DDEEAULL,
			0xD73B87CD672B34CFULL,
			0x4A0ACBE2D1D9F1D0ULL}
		},
		.Z = {.key64 = {
			0x0294350792EC5C05ULL,
			0x8C2C3DBF565E4DC7ULL,
			0x2411029E72CFD302ULL,
			0x6C31FD8C70B8671FULL}
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

	steps = 18;
	X1 = (curve25519_key_t){.key64 = {
		0xFDA1C0DF952E1F20ULL,
		0x35D3119FC9145176ULL,
		0x8A2A2B253E136C21ULL,
		0x7146E7B56DC0C53BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFDA1C0DF952E1F20ULL,
			0x35D3119FC9145176ULL,
			0x8A2A2B253E136C21ULL,
			0x7146E7B56DC0C53BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFE2496CB70E03D9BULL,
			0xEC922C401C104C21ULL,
			0xED5CE3B7D01208D0ULL,
			0x5805802FDA3CC3E8ULL}
		},
		.Z = {.key64 = {
			0xECEEF318220B4E57ULL,
			0x1CF5A322191353D4ULL,
			0x9A56D02A5B181D90ULL,
			0x1E1D4DDE33EAB078ULL}
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

	steps = 5;
	X1 = (curve25519_key_t){.key64 = {
		0x6CC1DEDE62687CF8ULL,
		0x6A357AA5280CE4ACULL,
		0x3962EE8A5582C322ULL,
		0x76FFB9C400CEF936ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6CC1DEDE62687CF8ULL,
			0x6A357AA5280CE4ACULL,
			0x3962EE8A5582C322ULL,
			0x76FFB9C400CEF936ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD73D78F84B18BBE6ULL,
			0xBAD62372FE9C998DULL,
			0x8E507B0DFD43EA16ULL,
			0x30E804079CA607ABULL}
		},
		.Z = {.key64 = {
			0x4E7BD876DF961F11ULL,
			0xD0080E2C827ADF3AULL,
			0xFA405A7B3DB884BFULL,
			0x0146EF21CA094456ULL}
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

	steps = 57;
	X1 = (curve25519_key_t){.key64 = {
		0x626974B6418A9598ULL,
		0xFB3589CF6B20F9D4ULL,
		0x4A678478E60C1A51ULL,
		0x74DF4EA495AF466FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x626974B6418A9598ULL,
			0xFB3589CF6B20F9D4ULL,
			0x4A678478E60C1A51ULL,
			0x74DF4EA495AF466FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE591C368929533D9ULL,
			0xDC8AC2FB790AF09AULL,
			0x816B7BA14D71906BULL,
			0x44917698E94C84E7ULL}
		},
		.Z = {.key64 = {
			0x031AF51333DF0864ULL,
			0xF9FA88FC955D2EE9ULL,
			0x3D0ABA11F5CC0A8DULL,
			0x6E446828051D8FA5ULL}
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

	steps = 45;
	X1 = (curve25519_key_t){.key64 = {
		0x2000C15FA02D5388ULL,
		0xC5A191264EDB1E2CULL,
		0x7B83CCEE2F210070ULL,
		0x549E2BF59AF60053ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2000C15FA02D5388ULL,
			0xC5A191264EDB1E2CULL,
			0x7B83CCEE2F210070ULL,
			0x549E2BF59AF60053ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF56428CA9EB7A6C4ULL,
			0xC20857D356638006ULL,
			0x533AE63E23046FCAULL,
			0x0C0081E1896DE44EULL}
		},
		.Z = {.key64 = {
			0x7886520F1C66A8E1ULL,
			0xAFDEAB4ABDFD2794ULL,
			0xC6083FDF4F0C46E7ULL,
			0x68CE6E76C8CA0CBAULL}
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

	steps = 60;
	X1 = (curve25519_key_t){.key64 = {
		0x4B3709FAF078B990ULL,
		0x842A95C339DE7144ULL,
		0x8E0B5545C327E8F1ULL,
		0x665B098897A5C227ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4B3709FAF078B990ULL,
			0x842A95C339DE7144ULL,
			0x8E0B5545C327E8F1ULL,
			0x665B098897A5C227ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2F8B1A050D9398ACULL,
			0x20D21CC83AB6391FULL,
			0x3BE7E3C318422277ULL,
			0x73E8840762F12777ULL}
		},
		.Z = {.key64 = {
			0xBF365AAFBEB5DB5BULL,
			0x46AA955DA6CDB65DULL,
			0xA568E320D4CD9827ULL,
			0x087955ADDC495853ULL}
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

	steps = 50;
	X1 = (curve25519_key_t){.key64 = {
		0x1E5642BA3A044E10ULL,
		0xE2AD69FE3866377CULL,
		0x26A95CE31F19F1ECULL,
		0x5E8B2C798338708BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1E5642BA3A044E10ULL,
			0xE2AD69FE3866377CULL,
			0x26A95CE31F19F1ECULL,
			0x5E8B2C798338708BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xADEF1A4E6BD2997DULL,
			0x9FDE8BF5564730C5ULL,
			0x3F8AB4F7BEFACEEDULL,
			0x0D3DFDBCF4800B0BULL}
		},
		.Z = {.key64 = {
			0xC8ECBAA9D3A17C7DULL,
			0x5F098217BFFC9D03ULL,
			0x2ADBB3876D6A5524ULL,
			0x2559EE7AB0F34993ULL}
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

	steps = 56;
	X1 = (curve25519_key_t){.key64 = {
		0x54F55F3E68F76340ULL,
		0xEEA2762BDAB08628ULL,
		0xE332BB66E30499F8ULL,
		0x6BD8CA55CFE5C53BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x54F55F3E68F76340ULL,
			0xEEA2762BDAB08628ULL,
			0xE332BB66E30499F8ULL,
			0x6BD8CA55CFE5C53BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1BCF3B0276D6C597ULL,
			0x67DE9C5A64A3322DULL,
			0xADBF7C4E615183DBULL,
			0x69FCC86149A01BC8ULL}
		},
		.Z = {.key64 = {
			0x3A510B754E8E6A63ULL,
			0xD884A41B14C618DDULL,
			0x4712291CE9A1B15EULL,
			0x416DD9DFF43789D6ULL}
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

	steps = 45;
	X1 = (curve25519_key_t){.key64 = {
		0xA65838AF27D14D40ULL,
		0x4CFCAEA514F6A837ULL,
		0xF078C1BC01D79D6BULL,
		0x77F25AB93D384F72ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA65838AF27D14D40ULL,
			0x4CFCAEA514F6A837ULL,
			0xF078C1BC01D79D6BULL,
			0x77F25AB93D384F72ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2BE941A0C00E4799ULL,
			0x401E57A9BAC9F3F3ULL,
			0xB747E2DA089E15D7ULL,
			0x25D999E42D1BF560ULL}
		},
		.Z = {.key64 = {
			0xC2A51E7C5C5CFD5FULL,
			0xBE18556BCE5B01E1ULL,
			0x9D616DEF4457951BULL,
			0x5C73C744791E6D06ULL}
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

	steps = 8;
	X1 = (curve25519_key_t){.key64 = {
		0x3CFD1CF2FB423EE0ULL,
		0xA22D506CAD44AF23ULL,
		0xBF26C8BCA12767F8ULL,
		0x47A62E0BDAE5856BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3CFD1CF2FB423EE0ULL,
			0xA22D506CAD44AF23ULL,
			0xBF26C8BCA12767F8ULL,
			0x47A62E0BDAE5856BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEF9E6045641333CEULL,
			0xB70F2DC3694E3EC7ULL,
			0x9FD1190FE5DCA88EULL,
			0x7841F06895CDF3EFULL}
		},
		.Z = {.key64 = {
			0xB7F7F51EBF1858DCULL,
			0x10C438461117CA18ULL,
			0x366836D7167CDEA8ULL,
			0x205E96B816571B3EULL}
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

	steps = 5;
	X1 = (curve25519_key_t){.key64 = {
		0xF08499BE078732A0ULL,
		0x69DC6A4C71B0D7FCULL,
		0x8D96B1BF9EFDE938ULL,
		0x619F1ECA0DCF65B1ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF08499BE078732A0ULL,
			0x69DC6A4C71B0D7FCULL,
			0x8D96B1BF9EFDE938ULL,
			0x619F1ECA0DCF65B1ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD7553B3D662A8E0DULL,
			0x2422DA9F1B6D92AAULL,
			0x6A1999FD70D697CDULL,
			0x2462A9D2F62E23EBULL}
		},
		.Z = {.key64 = {
			0x1C84663FD45D4D93ULL,
			0xE1F57A799D1AD072ULL,
			0x429E94CF51D2EF8DULL,
			0x3895B3CC569DCC1EULL}
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

	steps = 9;
	X1 = (curve25519_key_t){.key64 = {
		0x6D022A4E44896BA0ULL,
		0xF501E687D3557199ULL,
		0xC92C0B8B1CED5199ULL,
		0x50AC4808C3C2FCCEULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6D022A4E44896BA0ULL,
			0xF501E687D3557199ULL,
			0xC92C0B8B1CED5199ULL,
			0x50AC4808C3C2FCCEULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDFA3AF19862249BDULL,
			0x10EA949598178471ULL,
			0x57FD3EC7ECFCEF3CULL,
			0x76EFFA2F0D8D78C5ULL}
		},
		.Z = {.key64 = {
			0xFAC6A071071BE311ULL,
			0x1CBBC1EFE6F33FCCULL,
			0xF951B39BA0C11904ULL,
			0x4C15A72F3B5270D0ULL}
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

	steps = 41;
	X1 = (curve25519_key_t){.key64 = {
		0xC19D7657FC5CCA58ULL,
		0xF5B5A2B7538A87AAULL,
		0x86F23F28F6102E51ULL,
		0x6CD1B88F827AAEE1ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC19D7657FC5CCA58ULL,
			0xF5B5A2B7538A87AAULL,
			0x86F23F28F6102E51ULL,
			0x6CD1B88F827AAEE1ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7F0E8E0D9163E28CULL,
			0x7C1A6119370678A3ULL,
			0xFDA22F24D3C76670ULL,
			0x2D0A5986E9A52EB5ULL}
		},
		.Z = {.key64 = {
			0x8067AD37DCE9DD53ULL,
			0x321A5D66D8D53296ULL,
			0x62D675D56B7DC4E8ULL,
			0x5682E4CEE02E60DDULL}
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

	steps = 50;
	X1 = (curve25519_key_t){.key64 = {
		0xF191C362B5AE12E0ULL,
		0x7757B3D0F34FECD9ULL,
		0x161E7C5D7C47E7FCULL,
		0x6C18CC616F301A60ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF191C362B5AE12E0ULL,
			0x7757B3D0F34FECD9ULL,
			0x161E7C5D7C47E7FCULL,
			0x6C18CC616F301A60ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA6C403D45573D645ULL,
			0xF09DF2AE41E6C754ULL,
			0x4829B556E198B074ULL,
			0x785FFDC265AC2763ULL}
		},
		.Z = {.key64 = {
			0x774A0F5D1F930658ULL,
			0xE75E25818071C689ULL,
			0x314A518D91C87763ULL,
			0x569B278E0CBF1D36ULL}
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

	steps = 19;
	X1 = (curve25519_key_t){.key64 = {
		0x178C8E0F3A1F84E8ULL,
		0x57DFDBABF0CA6D44ULL,
		0x88CE417FACD34212ULL,
		0x7C6D296DFE090EE4ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x178C8E0F3A1F84E8ULL,
			0x57DFDBABF0CA6D44ULL,
			0x88CE417FACD34212ULL,
			0x7C6D296DFE090EE4ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB881218DF9A20783ULL,
			0xFD08BABD81EEAAD9ULL,
			0x607390EA2D0E0531ULL,
			0x25C80B14A2EF5433ULL}
		},
		.Z = {.key64 = {
			0x13C926CD790BFA6CULL,
			0x462B76B0E842F6F7ULL,
			0xE941C4B074A6072DULL,
			0x0E7013221B4564A7ULL}
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

	steps = 40;
	X1 = (curve25519_key_t){.key64 = {
		0xD5E1F79F7FBD3308ULL,
		0xC30FBA776C08A9D0ULL,
		0xC4C9C4F7618EF544ULL,
		0x7FB20F828163D148ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD5E1F79F7FBD3308ULL,
			0xC30FBA776C08A9D0ULL,
			0xC4C9C4F7618EF544ULL,
			0x7FB20F828163D148ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD91C0D8067F01433ULL,
			0xE58A45A9185D6B0DULL,
			0xF407A35D447C979BULL,
			0x6F953E083D584818ULL}
		},
		.Z = {.key64 = {
			0xA71D729C06EF210BULL,
			0x568ADA086DB22C33ULL,
			0xEB0A60C4F4274634ULL,
			0x372049F56D45A5C2ULL}
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

	steps = 16;
	X1 = (curve25519_key_t){.key64 = {
		0x1FC956C0DC5BDF88ULL,
		0x1BA5D548AE766F4BULL,
		0x700C4396057B7069ULL,
		0x7AF0444B1B3979EEULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1FC956C0DC5BDF88ULL,
			0x1BA5D548AE766F4BULL,
			0x700C4396057B7069ULL,
			0x7AF0444B1B3979EEULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4467F36460571D2FULL,
			0x097BC01439C78278ULL,
			0xB4A8767657E87286ULL,
			0x71E54082B2679121ULL}
		},
		.Z = {.key64 = {
			0xFB872AA25408B2B1ULL,
			0x2796560806414CBDULL,
			0xF020CF938F2B97A5ULL,
			0x03112E716F6D89B7ULL}
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

	steps = 32;
	X1 = (curve25519_key_t){.key64 = {
		0x5860F32DD6DE3A88ULL,
		0xC597C2F12FB48C11ULL,
		0xD2A3EBB69226EDB1ULL,
		0x492940CC9A639FC7ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5860F32DD6DE3A88ULL,
			0xC597C2F12FB48C11ULL,
			0xD2A3EBB69226EDB1ULL,
			0x492940CC9A639FC7ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x573BCFCE15C26E6EULL,
			0x6947D4E11840FD2CULL,
			0xF5E583837F60C62BULL,
			0x29B4478BA8BDA818ULL}
		},
		.Z = {.key64 = {
			0x8F5A6355DB3ADDA1ULL,
			0x34DF1C53BFF13360ULL,
			0x0CDA31AB1159FCB6ULL,
			0x4F7A67EA9ECA26F3ULL}
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

	steps = 3;
	X1 = (curve25519_key_t){.key64 = {
		0xCD36EF0314F6A7A8ULL,
		0xAE447462A433FC7AULL,
		0xAD8F72CD1773459BULL,
		0x6387CE59CD346507ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCD36EF0314F6A7A8ULL,
			0xAE447462A433FC7AULL,
			0xAD8F72CD1773459BULL,
			0x6387CE59CD346507ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC0994E586F56E7ECULL,
			0x2D118FEA9B38F83AULL,
			0x3DF3B4DFC35E7E77ULL,
			0x5EDEFF07068ED69CULL}
		},
		.Z = {.key64 = {
			0x7715B769A22821C7ULL,
			0xB6188FCA409BA3FDULL,
			0xB255FF8CEA5D79EFULL,
			0x79C2C1C39871CCF5ULL}
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

	steps = 29;
	X1 = (curve25519_key_t){.key64 = {
		0x1591DF9350464048ULL,
		0x0CD020978685B611ULL,
		0x95DDD46E3A4FF47AULL,
		0x6FACA6784951293CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1591DF9350464048ULL,
			0x0CD020978685B611ULL,
			0x95DDD46E3A4FF47AULL,
			0x6FACA6784951293CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x44929AED514A7B24ULL,
			0x9B487272FFF48759ULL,
			0x92FC0573371DC9ABULL,
			0x60F583E741A62526ULL}
		},
		.Z = {.key64 = {
			0x927D896778266760ULL,
			0xC2E4C04AE101E1FBULL,
			0x688FED29809AC663ULL,
			0x67F70DCA8968A110ULL}
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

	steps = 6;
	X1 = (curve25519_key_t){.key64 = {
		0x4E227B4FB3D41218ULL,
		0xBE5C4F4A52A125E3ULL,
		0xC774F1C1D78ADC3DULL,
		0x71B4C7A431DE0862ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4E227B4FB3D41218ULL,
			0xBE5C4F4A52A125E3ULL,
			0xC774F1C1D78ADC3DULL,
			0x71B4C7A431DE0862ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCE039F497CD56EAAULL,
			0x8DD51BE90EB0B5FAULL,
			0x79218987253EFD53ULL,
			0x15AC11C7E35D2544ULL}
		},
		.Z = {.key64 = {
			0xB971C76F50313847ULL,
			0xCCE7D821D67591A0ULL,
			0xC2B97F75518DE2E5ULL,
			0x2CDA39D7D74E29D1ULL}
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

	steps = 10;
	X1 = (curve25519_key_t){.key64 = {
		0xD93CAFE19B90D5D8ULL,
		0x8CA410950A4B70CAULL,
		0x7ACC847859927380ULL,
		0x52174268F80D5B9AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD93CAFE19B90D5D8ULL,
			0x8CA410950A4B70CAULL,
			0x7ACC847859927380ULL,
			0x52174268F80D5B9AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFB1AD98F5E0CFDEEULL,
			0x07A080E84C17089CULL,
			0x9F4A5CA90FCAA970ULL,
			0x0C755DE8C1FCE990ULL}
		},
		.Z = {.key64 = {
			0x18B4BB817C029831ULL,
			0x4F1E8DF48FD539EAULL,
			0x6EE4C73142D451B4ULL,
			0x3B7D750BB77914CEULL}
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

	steps = 49;
	X1 = (curve25519_key_t){.key64 = {
		0x1A510F12D2ED2200ULL,
		0x619CCA1685B85F89ULL,
		0x6E78C88B8BAC8250ULL,
		0x6912A6FBE8F4716FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1A510F12D2ED2200ULL,
			0x619CCA1685B85F89ULL,
			0x6E78C88B8BAC8250ULL,
			0x6912A6FBE8F4716FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4695CA9B0BA61B35ULL,
			0xD4BED75C4CFEC1ADULL,
			0x8DC85F698FE825AEULL,
			0x28C6C9DEF7F4F49CULL}
		},
		.Z = {.key64 = {
			0x8A17DA36A61448B4ULL,
			0xD1C547B480EBB463ULL,
			0x8B51A0A41D34D61DULL,
			0x63F37EC67215FF33ULL}
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

	steps = 6;
	X1 = (curve25519_key_t){.key64 = {
		0xE13A566541543738ULL,
		0x06DCD50DAED04813ULL,
		0xFB7CEE675197CE3DULL,
		0x77582C5DA410622EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE13A566541543738ULL,
			0x06DCD50DAED04813ULL,
			0xFB7CEE675197CE3DULL,
			0x77582C5DA410622EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDC0ADE891C7B1362ULL,
			0x367874607F3DD8A9ULL,
			0x1AD161A9031BB9A3ULL,
			0x67413BBDB89D2156ULL}
		},
		.Z = {.key64 = {
			0x643CC3280E814E82ULL,
			0x9AF9C7CD56CE194BULL,
			0xFE7C1B407F2A9BD0ULL,
			0x178A77B169D430A8ULL}
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

	steps = 1;
	X1 = (curve25519_key_t){.key64 = {
		0x3B3AB45119292788ULL,
		0xBA63F444150D306FULL,
		0xFC1C75AE8A357263ULL,
		0x5D280646F9710872ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3B3AB45119292788ULL,
			0xBA63F444150D306FULL,
			0xFC1C75AE8A357263ULL,
			0x5D280646F9710872ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x78A53C80A7A15342ULL,
			0xEC8A6CDBD982F95FULL,
			0xCEEE49EE9F394CA8ULL,
			0x0ECF630678FD6C67ULL}
		},
		.Z = {.key64 = {
			0xECEAD14464A49E46ULL,
			0xE98FD1105434C1BCULL,
			0xF071D6BA28D5C98EULL,
			0x74A0191BE5C421CBULL}
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

	steps = 41;
	X1 = (curve25519_key_t){.key64 = {
		0x71E326EAFC9C8420ULL,
		0x7CB88628BC0F3486ULL,
		0x838558D6DA50B9BEULL,
		0x4E24978F12395E9AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x71E326EAFC9C8420ULL,
			0x7CB88628BC0F3486ULL,
			0x838558D6DA50B9BEULL,
			0x4E24978F12395E9AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x26335A8F3E7ED4C7ULL,
			0x92DFF478CB3400EDULL,
			0x39D52BAAF9D7DC0BULL,
			0x3DC0B18F2E9F2F41ULL}
		},
		.Z = {.key64 = {
			0x5F0DF0DEE15C04F8ULL,
			0x95403BA59A4904ACULL,
			0x116DF3C888332433ULL,
			0x792D96F7B4422239ULL}
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
		0x2812212DB362A1B8ULL,
		0x517BEC79D7D8F1CBULL,
		0x0FD07F3EC753D744ULL,
		0x4F7BE15C7FDFD41DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2812212DB362A1B8ULL,
			0x517BEC79D7D8F1CBULL,
			0x0FD07F3EC753D744ULL,
			0x4F7BE15C7FDFD41DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x323722D85C8D1427ULL,
			0x9BF0F68AA2EA22DDULL,
			0xE0C4A37E885EFAF7ULL,
			0x0C8A3537E057F28FULL}
		},
		.Z = {.key64 = {
			0xFA347C6489342BF2ULL,
			0x0207F2FDD2C6482BULL,
			0x0846E92FBDDFD93AULL,
			0x2AA5E092BD213A63ULL}
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

	steps = 50;
	X1 = (curve25519_key_t){.key64 = {
		0x11A51C112EC15110ULL,
		0x6C11B0E569580466ULL,
		0x6C4EA1CF30C2B1D6ULL,
		0x78501249AB02C183ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x11A51C112EC15110ULL,
			0x6C11B0E569580466ULL,
			0x6C4EA1CF30C2B1D6ULL,
			0x78501249AB02C183ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0C53B5669B184C1EULL,
			0x4BC6EDAFB3A08126ULL,
			0xCC587662F0EB807BULL,
			0x6AD0533332F96B4DULL}
		},
		.Z = {.key64 = {
			0x6EA8050CDEDF7E7CULL,
			0x5FB202D99905121CULL,
			0xB5ED5185556F6BECULL,
			0x50D24923A66CE499ULL}
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

	steps = 31;
	X1 = (curve25519_key_t){.key64 = {
		0x626695367A7055E8ULL,
		0xF3F7C22976C2BB84ULL,
		0x7F743DDBBF7D467BULL,
		0x5274C7E2C4020352ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x626695367A7055E8ULL,
			0xF3F7C22976C2BB84ULL,
			0x7F743DDBBF7D467BULL,
			0x5274C7E2C4020352ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2C452D3B9D308125ULL,
			0x9ABB88A80A4D1F89ULL,
			0x57547806CA354DD3ULL,
			0x3CEEEA7FE72F2777ULL}
		},
		.Z = {.key64 = {
			0x19790B6552A36C09ULL,
			0x051E0EE4CC69E41AULL,
			0x0A16B9A1A79CFA02ULL,
			0x25B158C2E540ACA8ULL}
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

	steps = 62;
	X1 = (curve25519_key_t){.key64 = {
		0x9BED43810ACF3428ULL,
		0xEADEFFC247A0CB9FULL,
		0x9DDD9470A843A9A7ULL,
		0x6D65AC434BFF792CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9BED43810ACF3428ULL,
			0xEADEFFC247A0CB9FULL,
			0x9DDD9470A843A9A7ULL,
			0x6D65AC434BFF792CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA8BDD46D12DDA791ULL,
			0xD9EE505A199DF2C0ULL,
			0xE8D245989B4C565DULL,
			0x7F5E6188525B4249ULL}
		},
		.Z = {.key64 = {
			0x14AD4C22D86CFA02ULL,
			0xE8E7DED1EAE5A4F5ULL,
			0x16CAE89C749F47A9ULL,
			0x61C8A3359B379D45ULL}
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

	steps = 6;
	X1 = (curve25519_key_t){.key64 = {
		0xBBA667D7AA7A36E0ULL,
		0x0C65BD4E88F22669ULL,
		0xC7B25F21F96C2B22ULL,
		0x57CD37DF9729CA26ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBBA667D7AA7A36E0ULL,
			0x0C65BD4E88F22669ULL,
			0xC7B25F21F96C2B22ULL,
			0x57CD37DF9729CA26ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD7546DA1475B0594ULL,
			0x9E08E3CA823536E1ULL,
			0x9E61249B5C0B9EB9ULL,
			0x71952133DC74CD9BULL}
		},
		.Z = {.key64 = {
			0x0A686DCED21D1129ULL,
			0x9672DB43B701BDD7ULL,
			0x31103700EB3427DEULL,
			0x5C69A57E6172CD44ULL}
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

	steps = 42;
	X1 = (curve25519_key_t){.key64 = {
		0xEDCC938FAAC4D100ULL,
		0x08276F3CCF490AC6ULL,
		0x5CACA4CB2F05779EULL,
		0x5C6DADBFA678A4AEULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEDCC938FAAC4D100ULL,
			0x08276F3CCF490AC6ULL,
			0x5CACA4CB2F05779EULL,
			0x5C6DADBFA678A4AEULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFD5F24A93898C41CULL,
			0xB6EC66BA8F22F097ULL,
			0xA2D3A883EFB47641ULL,
			0x4468DC1A316AB71FULL}
		},
		.Z = {.key64 = {
			0x3E1AA91B6A3BC4A7ULL,
			0x261692B6D9D7B80EULL,
			0x8B4861C533878EBFULL,
			0x686363FA338EF92FULL}
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

	steps = 19;
	X1 = (curve25519_key_t){.key64 = {
		0xA5762772EFBD2D10ULL,
		0x6257FF22D0AD5B6EULL,
		0xF07CD64764DA080CULL,
		0x57380B1AA6473DFEULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA5762772EFBD2D10ULL,
			0x6257FF22D0AD5B6EULL,
			0xF07CD64764DA080CULL,
			0x57380B1AA6473DFEULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFD58B93755942496ULL,
			0xB3A242E6AAAC621AULL,
			0xEEDE7FA6DD96FBE4ULL,
			0x024D7D0A93ED19A0ULL}
		},
		.Z = {.key64 = {
			0x869B334E3144F859ULL,
			0x949D31F4B9128A03ULL,
			0xBE448304ABB02E9EULL,
			0x4E32023E100379B9ULL}
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

	steps = 51;
	X1 = (curve25519_key_t){.key64 = {
		0x5F9D3EB033F3A408ULL,
		0x08E68A9D8170DC02ULL,
		0x5095FE8A970883B1ULL,
		0x4BD723C8098E049DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5F9D3EB033F3A408ULL,
			0x08E68A9D8170DC02ULL,
			0x5095FE8A970883B1ULL,
			0x4BD723C8098E049DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x50DFAC7D1B78E013ULL,
			0xD62756AC568FC6D7ULL,
			0x6D509C5AE88A651DULL,
			0x3B74558B67DE7588ULL}
		},
		.Z = {.key64 = {
			0xF2EDDF5B41C86E5EULL,
			0x1FB8D0EEF102D5C3ULL,
			0x1613F545670545E6ULL,
			0x606D52F17FD11024ULL}
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

	steps = 9;
	X1 = (curve25519_key_t){.key64 = {
		0x4F75FBF98C20C1E8ULL,
		0x6B42F68DCF75D081ULL,
		0x9C462916CE09414CULL,
		0x4C3B2A94A98917CAULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4F75FBF98C20C1E8ULL,
			0x6B42F68DCF75D081ULL,
			0x9C462916CE09414CULL,
			0x4C3B2A94A98917CAULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEA86992C374E563BULL,
			0xF1471511067C4CCAULL,
			0x2C040E605D55C3AEULL,
			0x1054205923B68D76ULL}
		},
		.Z = {.key64 = {
			0x1C823B5214D128E3ULL,
			0xDB76B778A26E214FULL,
			0x718D39AD8F71B6B4ULL,
			0x25497F0592C54AA1ULL}
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

	steps = 62;
	X1 = (curve25519_key_t){.key64 = {
		0xB0ADDAABB53F7930ULL,
		0x5237345D06A79125ULL,
		0x64C15DDEA5A02E6FULL,
		0x46B64C2D9F75FB40ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB0ADDAABB53F7930ULL,
			0x5237345D06A79125ULL,
			0x64C15DDEA5A02E6FULL,
			0x46B64C2D9F75FB40ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3B0A125EB860A57CULL,
			0xD8DEC88DF4465253ULL,
			0xC1F4316522AC9D1EULL,
			0x2FB34A1C0947C971ULL}
		},
		.Z = {.key64 = {
			0xE586183B08155A11ULL,
			0x0FE9A6198050A7E8ULL,
			0x0F0F5622BD4424E8ULL,
			0x593C7CC708E8F1DDULL}
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

	steps = 24;
	X1 = (curve25519_key_t){.key64 = {
		0x91DB02ABC3AF78B8ULL,
		0xDB9163C5F6CF324CULL,
		0x5415E883560BECA1ULL,
		0x569D28EC193EF648ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x91DB02ABC3AF78B8ULL,
			0xDB9163C5F6CF324CULL,
			0x5415E883560BECA1ULL,
			0x569D28EC193EF648ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF0D7D1A20FE0F6D0ULL,
			0xC31AB5E96B598B8FULL,
			0x96661A68BCE062B7ULL,
			0x2BBB0FE0E716A934ULL}
		},
		.Z = {.key64 = {
			0x1BC7C19556BD930AULL,
			0x45FB3D9B00C0C398ULL,
			0x46215492068FF316ULL,
			0x5EA668016DA08DA8ULL}
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

	steps = 26;
	X1 = (curve25519_key_t){.key64 = {
		0xB8FBF8CE18D4B750ULL,
		0x4A78A0C5E21AB7BEULL,
		0x91C44AD73E2143A1ULL,
		0x68A4D274E9F4EA7AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB8FBF8CE18D4B750ULL,
			0x4A78A0C5E21AB7BEULL,
			0x91C44AD73E2143A1ULL,
			0x68A4D274E9F4EA7AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB287083619494FA0ULL,
			0x0C0CB745DF7A2258ULL,
			0x50BABC51DE067515ULL,
			0x7EA5107A3AA5967DULL}
		},
		.Z = {.key64 = {
			0xAE2A511B354C1627ULL,
			0xFEBC3B71CC89246DULL,
			0x4AC3C405C21BC47BULL,
			0x28DA953AACB08F5EULL}
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

	steps = 57;
	X1 = (curve25519_key_t){.key64 = {
		0x366D86FAB5BC6360ULL,
		0x0FF629434F0292F3ULL,
		0xBC86D754F9CF31B8ULL,
		0x50AB071F41B9AFEAULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x366D86FAB5BC6360ULL,
			0x0FF629434F0292F3ULL,
			0xBC86D754F9CF31B8ULL,
			0x50AB071F41B9AFEAULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2D397B5D2B8D6A3AULL,
			0x4B5A832113145C23ULL,
			0x0C28A1E918005878ULL,
			0x5FDCFB31151E759AULL}
		},
		.Z = {.key64 = {
			0x9EA45C6915F59998ULL,
			0xEACC7CE3091A1C0AULL,
			0xEE9744410F346701ULL,
			0x192482962D0117E1ULL}
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

	steps = 30;
	X1 = (curve25519_key_t){.key64 = {
		0x396301365DB6D228ULL,
		0x4E5A43EF9E2FE7F3ULL,
		0xD2A8EC12073FD3E1ULL,
		0x699096C9AD632EE4ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x396301365DB6D228ULL,
			0x4E5A43EF9E2FE7F3ULL,
			0xD2A8EC12073FD3E1ULL,
			0x699096C9AD632EE4ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE003CC855D5087D2ULL,
			0xD4B8A9335923B726ULL,
			0x5C79A6455E7E75FEULL,
			0x7E5F5A510E1CCBF7ULL}
		},
		.Z = {.key64 = {
			0x2370D28A89851FB9ULL,
			0x4100D559AAA9927DULL,
			0x02D60D3966180204ULL,
			0x737C449C6BEF98BEULL}
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

	steps = 50;
	X1 = (curve25519_key_t){.key64 = {
		0x20B53193750DBED8ULL,
		0x3A9C70CF79AC31DCULL,
		0x74D5A4DB5EF026D0ULL,
		0x482322B1D8A948ADULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x20B53193750DBED8ULL,
			0x3A9C70CF79AC31DCULL,
			0x74D5A4DB5EF026D0ULL,
			0x482322B1D8A948ADULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEF6D4E7CAA07E579ULL,
			0xAB953962D088A06DULL,
			0x26DB826A58EE7AA4ULL,
			0x5D2419DF8FACC443ULL}
		},
		.Z = {.key64 = {
			0xCEFFA6A6B21590C4ULL,
			0x7DC0A5650E2D4824ULL,
			0x6C0BA542E43B4C51ULL,
			0x79C0AA45D68262C9ULL}
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

	steps = 6;
	X1 = (curve25519_key_t){.key64 = {
		0xB43A7EDE88E6D9B0ULL,
		0x8ED07090312C250DULL,
		0xC398AFD40EAD5241ULL,
		0x4932D72502FA235EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB43A7EDE88E6D9B0ULL,
			0x8ED07090312C250DULL,
			0xC398AFD40EAD5241ULL,
			0x4932D72502FA235EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE25492A2AD6F1F2DULL,
			0x604E5ABC7C5D163BULL,
			0xA987330F1CEDD114ULL,
			0x0782AD63D77D5E9EULL}
		},
		.Z = {.key64 = {
			0xF5048F289B5BF5ABULL,
			0x23B494413165D2F3ULL,
			0x463E6A61BB590E15ULL,
			0x14FF61F8F7E1AEF9ULL}
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

	steps = 53;
	X1 = (curve25519_key_t){.key64 = {
		0x0437AFA7445937E0ULL,
		0xEF4A3A8687406936ULL,
		0x867DCF8D00999819ULL,
		0x6B61D45B5006E412ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0437AFA7445937E0ULL,
			0xEF4A3A8687406936ULL,
			0x867DCF8D00999819ULL,
			0x6B61D45B5006E412ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0AF8B4A0D66D9FA7ULL,
			0xFBE544A6C31A8A01ULL,
			0x1BFA797F2B876B33ULL,
			0x4BDD12699244117DULL}
		},
		.Z = {.key64 = {
			0x45752CC0E1730811ULL,
			0x3FD1CB242569020EULL,
			0x74230F1E73393728ULL,
			0x320BD615B954F3BEULL}
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

	steps = 13;
	X1 = (curve25519_key_t){.key64 = {
		0xBB93140DD7664E38ULL,
		0x216ACA746DB135F3ULL,
		0x1F6C307F53BE90C5ULL,
		0x5F47A3A1E3C0231BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBB93140DD7664E38ULL,
			0x216ACA746DB135F3ULL,
			0x1F6C307F53BE90C5ULL,
			0x5F47A3A1E3C0231BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x62D63BBBC4CD01BAULL,
			0xE06EEAD095826583ULL,
			0xBED7EBF4790F5396ULL,
			0x57ACDE1168A89784ULL}
		},
		.Z = {.key64 = {
			0x0C968CD2707FD995ULL,
			0xD9EBE5C57B844ACCULL,
			0x0E8A73A70AAC8CD9ULL,
			0x7814323F2DADC4AAULL}
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
		0xD99CFF10DEBB1818ULL,
		0x6D23194B9DF9FB21ULL,
		0x43CCE53C7E5B4315ULL,
		0x7FD50988D49B546BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD99CFF10DEBB1818ULL,
			0x6D23194B9DF9FB21ULL,
			0x43CCE53C7E5B4315ULL,
			0x7FD50988D49B546BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1711032919FDFCE2ULL,
			0xFA54338141C637D4ULL,
			0xA8AAB22DC642A2A6ULL,
			0x7B2C449A6A34AE5CULL}
		},
		.Z = {.key64 = {
			0x822DF28171E5E99BULL,
			0x1585491D4215C391ULL,
			0x93B54318EDD73FF7ULL,
			0x71E158783B810E80ULL}
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
		0x1A06FAC01B8F8628ULL,
		0xCC2977FA435D50D3ULL,
		0xE5E0E6CFC89AE0F3ULL,
		0x479AC4F71DD686F9ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1A06FAC01B8F8628ULL,
			0xCC2977FA435D50D3ULL,
			0xE5E0E6CFC89AE0F3ULL,
			0x479AC4F71DD686F9ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC5C4BF821F66D4C9ULL,
			0xF69459573761B37FULL,
			0x3446B42C85D62A30ULL,
			0x3B82BB7C88FABBCDULL}
		},
		.Z = {.key64 = {
			0x4AE120541A719BAFULL,
			0xF0FE64B2AB64A4CDULL,
			0xD97025A65DFCE2AFULL,
			0x1530F2B3DDBE0DE7ULL}
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

	steps = 21;
	X1 = (curve25519_key_t){.key64 = {
		0xE6BC112BEDA75198ULL,
		0x358E72CB10FC309DULL,
		0xE6AD0566AFB7CC87ULL,
		0x76D1AADD82F7BD69ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE6BC112BEDA75198ULL,
			0x358E72CB10FC309DULL,
			0xE6AD0566AFB7CC87ULL,
			0x76D1AADD82F7BD69ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0AF3E520E8781E38ULL,
			0x1C50FF88BCDDB066ULL,
			0xF4AAB1FE08D519E2ULL,
			0x5F035BC8A06B2835ULL}
		},
		.Z = {.key64 = {
			0x6A8B73CD4EF30DD5ULL,
			0x6B9016FE57786C18ULL,
			0xC3C518514DC8B37EULL,
			0x1015F7CBAA92D2A5ULL}
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

	steps = 34;
	X1 = (curve25519_key_t){.key64 = {
		0xB52A080994E6F4A8ULL,
		0x0D263EBF86E866DAULL,
		0x068A5819F7AB20F7ULL,
		0x426CDB989A4054B9ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB52A080994E6F4A8ULL,
			0x0D263EBF86E866DAULL,
			0x068A5819F7AB20F7ULL,
			0x426CDB989A4054B9ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x773EC7FC6AD1A3CEULL,
			0x9922EC8AB27F98EEULL,
			0x29656B94F3E881EFULL,
			0x644256918F12171EULL}
		},
		.Z = {.key64 = {
			0xF042DF8131E2C385ULL,
			0x5CB16A01D52C744BULL,
			0xEEDF0D921B08297DULL,
			0x45CA47D460F6E59CULL}
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

	steps = 63;
	X1 = (curve25519_key_t){.key64 = {
		0x02B5AFBD46880E28ULL,
		0xF8B9830778F16FF2ULL,
		0xFB0F701A6CE759BDULL,
		0x50EF44309869DBC9ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x02B5AFBD46880E28ULL,
			0xF8B9830778F16FF2ULL,
			0xFB0F701A6CE759BDULL,
			0x50EF44309869DBC9ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4CB0C89F2867D3DDULL,
			0x5481A1AA50B5E2BAULL,
			0x431E32F7B4D65BEAULL,
			0x1F4B3452BA2E83E9ULL}
		},
		.Z = {.key64 = {
			0x5E8F1A07FFB55DDAULL,
			0xD4A96C202410663DULL,
			0xD0BD837AADFB7E66ULL,
			0x6C97F56D3EF31CDEULL}
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

	steps = 6;
	X1 = (curve25519_key_t){.key64 = {
		0x8D900FE6BE16F890ULL,
		0x40D1855C5D08FBE5ULL,
		0x034773C0F5D8154DULL,
		0x511A892C24F06897ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8D900FE6BE16F890ULL,
			0x40D1855C5D08FBE5ULL,
			0x034773C0F5D8154DULL,
			0x511A892C24F06897ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x44182EE4C1E4C419ULL,
			0x2CB388F9EA852F3BULL,
			0x0817B65A23683A07ULL,
			0x3D407F8B9C33642EULL}
		},
		.Z = {.key64 = {
			0x224048065D7A98D7ULL,
			0x7852970A1304A78AULL,
			0x583531D04704153BULL,
			0x42A4276256F3AD76ULL}
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

	steps = 12;
	X1 = (curve25519_key_t){.key64 = {
		0xD273656BE135B080ULL,
		0xA18E63B0BAE109A7ULL,
		0xCB11DC9752B4A99FULL,
		0x539736A583443795ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD273656BE135B080ULL,
			0xA18E63B0BAE109A7ULL,
			0xCB11DC9752B4A99FULL,
			0x539736A583443795ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x40FCACB90697C22FULL,
			0x436A8D82C52D38CDULL,
			0x16DFB2624FAE3F92ULL,
			0x0B5AC599E5DFB09BULL}
		},
		.Z = {.key64 = {
			0x11D120B3A101083AULL,
			0x3042DD8972954CB9ULL,
			0xF3FEEEB15D522B80ULL,
			0x60C54E89091E6751ULL}
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

	steps = 16;
	X1 = (curve25519_key_t){.key64 = {
		0xAA5183759C3F5E08ULL,
		0x726DEE667184B1D7ULL,
		0x76E0D5E1571ACB82ULL,
		0x658B15C1A1F83DC5ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAA5183759C3F5E08ULL,
			0x726DEE667184B1D7ULL,
			0x76E0D5E1571ACB82ULL,
			0x658B15C1A1F83DC5ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8321C090578A685BULL,
			0x7D597E3C027A9EFAULL,
			0x2A24966261B27CB3ULL,
			0x71B745AF86B83F83ULL}
		},
		.Z = {.key64 = {
			0x53720ECECB6DE22EULL,
			0x6FFBA6C6A3412E52ULL,
			0xDB1B930C1339A631ULL,
			0x3B24650EC592FABAULL}
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

	steps = 1;
	X1 = (curve25519_key_t){.key64 = {
		0xC1E1DCD215530560ULL,
		0xDCFA1F7D49B7E6C1ULL,
		0x6000078F01322D80ULL,
		0x7742D79EF110F72EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC1E1DCD215530560ULL,
			0xDCFA1F7D49B7E6C1ULL,
			0x6000078F01322D80ULL,
			0x7742D79EF110F72EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFF7490AAD8222F21ULL,
			0x56FB4CAC30F4FC40ULL,
			0x1163801264D44092ULL,
			0x0398216E5008033AULL}
		},
		.Z = {.key64 = {
			0x07877348554C15B9ULL,
			0x73E87DF526DF9B07ULL,
			0x80001E3C04C8B603ULL,
			0x5D0B5E7BC443DCB9ULL}
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

	steps = 30;
	X1 = (curve25519_key_t){.key64 = {
		0x1F99CFDB44726A68ULL,
		0xA9DBDC39D01A249EULL,
		0x6E75F08FE1587C3BULL,
		0x59D5381E42FCC8DCULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1F99CFDB44726A68ULL,
			0xA9DBDC39D01A249EULL,
			0x6E75F08FE1587C3BULL,
			0x59D5381E42FCC8DCULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x52B8C398DFBB9680ULL,
			0x88B48F6EC702120AULL,
			0x689B987E47EC4CFCULL,
			0x45398955BA1330E1ULL}
		},
		.Z = {.key64 = {
			0xFE46AED8219E92E3ULL,
			0xB63F2EAA8FBE1CE2ULL,
			0xAC40CC7B6C8FC6A4ULL,
			0x0CEE020988E338C2ULL}
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

	steps = 20;
	X1 = (curve25519_key_t){.key64 = {
		0xF49108A10B381688ULL,
		0xA48F87EDAA782E14ULL,
		0x0739BF935D722908ULL,
		0x729335CBB9C93AC3ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF49108A10B381688ULL,
			0xA48F87EDAA782E14ULL,
			0x0739BF935D722908ULL,
			0x729335CBB9C93AC3ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x48F497136997E89FULL,
			0xC769B59605254130ULL,
			0xF42172AE7C81BD5AULL,
			0x22909722E2BA79FCULL}
		},
		.Z = {.key64 = {
			0x509B993BE0FADFBDULL,
			0x1FD32A38881BE93FULL,
			0xDC7D87D2F1B76E16ULL,
			0x189756533F5AEFB6ULL}
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

	steps = 47;
	X1 = (curve25519_key_t){.key64 = {
		0x0E787ECB588E0FF0ULL,
		0x1157554F8C2A89BFULL,
		0xF0AF7AC8C5A82EBCULL,
		0x68890689526CA4C4ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0E787ECB588E0FF0ULL,
			0x1157554F8C2A89BFULL,
			0xF0AF7AC8C5A82EBCULL,
			0x68890689526CA4C4ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x66E8755592A29DC9ULL,
			0xF1AA55E3BFFC67FBULL,
			0xCC6786138CDF3E3DULL,
			0x1910BC9818037328ULL}
		},
		.Z = {.key64 = {
			0x2490E69D3D647243ULL,
			0x3A536F3848F9C6FFULL,
			0x61A8B4511362AC05ULL,
			0x55CF6F7F68E92FB2ULL}
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

	steps = 51;
	X1 = (curve25519_key_t){.key64 = {
		0x70C396A2EFC9CCF0ULL,
		0x102148D7AD016725ULL,
		0xD6097E10649D7B99ULL,
		0x611BF2D8F92EFA7EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x70C396A2EFC9CCF0ULL,
			0x102148D7AD016725ULL,
			0xD6097E10649D7B99ULL,
			0x611BF2D8F92EFA7EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x071E75B1790651BAULL,
			0xF281F63076A1ACC9ULL,
			0x04BB0736BEE33778ULL,
			0x7E515074BED942CDULL}
		},
		.Z = {.key64 = {
			0x3FF2F908F7DE828EULL,
			0x84F4CB171BBD6736ULL,
			0x16C2D96ECD373B08ULL,
			0x363F742A3CEF1D47ULL}
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

	steps = 17;
	X1 = (curve25519_key_t){.key64 = {
		0x30EE2F4A7E5AFA70ULL,
		0x96D9569E9536F6B9ULL,
		0x424D43FE0D87491AULL,
		0x7A526F3CFA90A5B1ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x30EE2F4A7E5AFA70ULL,
			0x96D9569E9536F6B9ULL,
			0x424D43FE0D87491AULL,
			0x7A526F3CFA90A5B1ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC301B3003F80AE81ULL,
			0x2D804D3B504A045DULL,
			0x1868346CD9BF1C6AULL,
			0x563D3114E2FF1ED5ULL}
		},
		.Z = {.key64 = {
			0x31BD6606EE833E4DULL,
			0x85B9DCC69BAD7CD8ULL,
			0x02ED25E468B9F522ULL,
			0x5C7D5C30E043FFA3ULL}
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

	steps = 54;
	X1 = (curve25519_key_t){.key64 = {
		0x01D6C25750E4D118ULL,
		0x696E415FAA5871CBULL,
		0xCAEFE30B072C81ACULL,
		0x4A418E89A445EC49ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x01D6C25750E4D118ULL,
			0x696E415FAA5871CBULL,
			0xCAEFE30B072C81ACULL,
			0x4A418E89A445EC49ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x00624125493F3AC7ULL,
			0xE10E8DD34217D817ULL,
			0x8D699395584F36DDULL,
			0x4005A637A3CB4EC8ULL}
		},
		.Z = {.key64 = {
			0x619B4CEAD767434BULL,
			0x382E52B43A58AF46ULL,
			0x8CF14A7CE3878972ULL,
			0x776EF9C9A8005985ULL}
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

	steps = 52;
	X1 = (curve25519_key_t){.key64 = {
		0x3C624EF198BA16B0ULL,
		0x4BB8438D9C800812ULL,
		0x8107F6BABE386694ULL,
		0x6672B22D212551D9ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3C624EF198BA16B0ULL,
			0x4BB8438D9C800812ULL,
			0x8107F6BABE386694ULL,
			0x6672B22D212551D9ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x30A44119D6E1AF9AULL,
			0x86FF0D57C7A13297ULL,
			0x673C0875F3C630A1ULL,
			0x33405214726F9D22ULL}
		},
		.Z = {.key64 = {
			0xDBDD54123DE97859ULL,
			0x02DC39254795E82CULL,
			0xF6CFCAB62E41C474ULL,
			0x00E4B88335C35C6CULL}
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

	steps = 26;
	X1 = (curve25519_key_t){.key64 = {
		0x075C0ECD9A20C240ULL,
		0x69EA0EDACE30A5F8ULL,
		0x2536B82BA6793CA5ULL,
		0x4A54687511D5B367ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x075C0ECD9A20C240ULL,
			0x69EA0EDACE30A5F8ULL,
			0x2536B82BA6793CA5ULL,
			0x4A54687511D5B367ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2452018A2E17B1EDULL,
			0x2A1D0E30EC30AEB5ULL,
			0xF545CDCAB4F2EFEFULL,
			0x3CE4D650D907ECB9ULL}
		},
		.Z = {.key64 = {
			0x43A30F9BE2C1D33AULL,
			0x60B94FDA42D7884FULL,
			0x56EB8688CD117865ULL,
			0x1E844F0FA27823D2ULL}
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

	steps = 14;
	X1 = (curve25519_key_t){.key64 = {
		0xEB8C2452F025B8C8ULL,
		0xA4761694A6268931ULL,
		0x7DDF2033546303ACULL,
		0x759F24AE07EE3DBEULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEB8C2452F025B8C8ULL,
			0xA4761694A6268931ULL,
			0x7DDF2033546303ACULL,
			0x759F24AE07EE3DBEULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x22CA8C8DC0DCEFBAULL,
			0x9AF7B35A88A4D193ULL,
			0x6E3D24C80F63DEFAULL,
			0x54A82FA75BDF3016ULL}
		},
		.Z = {.key64 = {
			0x7E95EF4D88B8A09AULL,
			0x169AE48F9B5A05CEULL,
			0x433F92F964719659ULL,
			0x6E362CA89C0DB745ULL}
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

	steps = 14;
	X1 = (curve25519_key_t){.key64 = {
		0x4C052478F8132F30ULL,
		0x8EF9EEDFB6066436ULL,
		0xDC1D488D78D4206EULL,
		0x5E94C3C61C9CFE49ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4C052478F8132F30ULL,
			0x8EF9EEDFB6066436ULL,
			0xDC1D488D78D4206EULL,
			0x5E94C3C61C9CFE49ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB73600FE8F1F9610ULL,
			0xBB56753091303529ULL,
			0x91C9486DE5714057ULL,
			0x4C98E20A029983A0ULL}
		},
		.Z = {.key64 = {
			0x9DDA587ECBED4753ULL,
			0x438BB5C6F9510686ULL,
			0x2109458DA0534123ULL,
			0x6A92E6386A525B84ULL}
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

	steps = 15;
	X1 = (curve25519_key_t){.key64 = {
		0x6AD6C7ED85CFDE40ULL,
		0x789CCDACD6C277C9ULL,
		0xBA5593B16C3364D6ULL,
		0x67CDE88E8CB7DECDULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6AD6C7ED85CFDE40ULL,
			0x789CCDACD6C277C9ULL,
			0xBA5593B16C3364D6ULL,
			0x67CDE88E8CB7DECDULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE0B6FC07860359E2ULL,
			0x130DA3C7CAFAFCA2ULL,
			0x3F4B4776E3AF9C5EULL,
			0x349ABBF6E731FF10ULL}
		},
		.Z = {.key64 = {
			0xD0FDD40228A1820FULL,
			0x5304B86DB95B0CDBULL,
			0xAE9EF8F6BCE329CAULL,
			0x73F48FC3891274B8ULL}
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

	steps = 51;
	X1 = (curve25519_key_t){.key64 = {
		0xA6CA269AC0FEFA80ULL,
		0x34249228E0FAD539ULL,
		0xD8B7DD0E4920338BULL,
		0x498A1D69D1B5E53DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA6CA269AC0FEFA80ULL,
			0x34249228E0FAD539ULL,
			0xD8B7DD0E4920338BULL,
			0x498A1D69D1B5E53DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x53756564C4CA90D1ULL,
			0x22ADFBA9A22E6384ULL,
			0x3B3499EDBFFA1859ULL,
			0x60945F5F0B5947C9ULL}
		},
		.Z = {.key64 = {
			0xAE1EC3B231151D33ULL,
			0xB81DD8F1DBFC36E3ULL,
			0x76D24A13546E8C6EULL,
			0x03178582DDDB2232ULL}
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

	steps = 3;
	X1 = (curve25519_key_t){.key64 = {
		0xFC8A02D914F1B068ULL,
		0x4244BCCC4014FECDULL,
		0x52F802D5FA8851B3ULL,
		0x4B23648C2971849DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFC8A02D914F1B068ULL,
			0x4244BCCC4014FECDULL,
			0x52F802D5FA8851B3ULL,
			0x4B23648C2971849DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x30A0A676690F0D9BULL,
			0x4E781171EF619DE4ULL,
			0x79836462FCFD44F7ULL,
			0x44057BFD696BBD1BULL}
		},
		.Z = {.key64 = {
			0x1A47763ED3C76AE0ULL,
			0x309839EE2AD80145ULL,
			0x744F7CAA3B5717D8ULL,
			0x30F5B6A51DFB91DFULL}
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

	steps = 39;
	X1 = (curve25519_key_t){.key64 = {
		0x1D13384D18B178B8ULL,
		0xA232E0EE6DC8E910ULL,
		0x723972929A1497E2ULL,
		0x6965153CA64BA120ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1D13384D18B178B8ULL,
			0xA232E0EE6DC8E910ULL,
			0x723972929A1497E2ULL,
			0x6965153CA64BA120ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x62B1809815D899FFULL,
			0x11AEAF0E36D0E951ULL,
			0x655118F79CC0F481ULL,
			0x12277AFB1EE18654ULL}
		},
		.Z = {.key64 = {
			0x43CEF03320D17F66ULL,
			0xC54FF123FB4AEBD1ULL,
			0x666C2DE30F6AF89CULL,
			0x191755444C598AE9ULL}
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

	steps = 15;
	X1 = (curve25519_key_t){.key64 = {
		0xCC971AEF64171710ULL,
		0xAEFDCFA0ECDA02C3ULL,
		0x8666A1D881CC0B14ULL,
		0x699F7C2EEDA3DFC8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCC971AEF64171710ULL,
			0xAEFDCFA0ECDA02C3ULL,
			0x8666A1D881CC0B14ULL,
			0x699F7C2EEDA3DFC8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x74B7298AFA5B53DBULL,
			0xF08190DFDEA2C66FULL,
			0x9E51572918F597C3ULL,
			0x704F17E4B9654C41ULL}
		},
		.Z = {.key64 = {
			0x5519CF60F5FABB48ULL,
			0xF744E0D184A27332ULL,
			0xE4DD2796E1A5C7C6ULL,
			0x570EAFC2701B6442ULL}
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

	steps = 38;
	X1 = (curve25519_key_t){.key64 = {
		0x8F10A43A539B0870ULL,
		0x2EB7CC055405BF3DULL,
		0x930C43F5B89A0F6EULL,
		0x6B5643720FDE3179ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8F10A43A539B0870ULL,
			0x2EB7CC055405BF3DULL,
			0x930C43F5B89A0F6EULL,
			0x6B5643720FDE3179ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x06CE19C00A84B0DAULL,
			0x2F0149A6B534266EULL,
			0x397AE37B5B35F825ULL,
			0x64BB466228AD2B75ULL}
		},
		.Z = {.key64 = {
			0xDDE7BE62C945736CULL,
			0x0EC6DA9F2938A7CBULL,
			0xAA1AA0AECBA59F9CULL,
			0x156E406DDC9B8A09ULL}
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

	steps = 26;
	X1 = (curve25519_key_t){.key64 = {
		0x09E25489CF28D388ULL,
		0x96C34DF2B8AB13F4ULL,
		0xEFB0604C2A6D5F33ULL,
		0x70928052865D8DAAULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x09E25489CF28D388ULL,
			0x96C34DF2B8AB13F4ULL,
			0xEFB0604C2A6D5F33ULL,
			0x70928052865D8DAAULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8A0863B9B7C61C4FULL,
			0xE3BFD88DDC5EBE10ULL,
			0xE5B3480D7C9BD101ULL,
			0x2D5C9E886679F78EULL}
		},
		.Z = {.key64 = {
			0x48E468DC8F3D0D0AULL,
			0x3C6979D2BCCC3BC9ULL,
			0xA847B8300F89EC0BULL,
			0x43946F797121A2FBULL}
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

	steps = 49;
	X1 = (curve25519_key_t){.key64 = {
		0xFDDCD069E6255D70ULL,
		0x74162C2233EC1146ULL,
		0xE045115043615581ULL,
		0x4F5CC667270C4456ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFDDCD069E6255D70ULL,
			0x74162C2233EC1146ULL,
			0xE045115043615581ULL,
			0x4F5CC667270C4456ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA46A13422A5FACCCULL,
			0xDEDF1374B618C333ULL,
			0xC68462D084C6B599ULL,
			0x13580CFB870F1758ULL}
		},
		.Z = {.key64 = {
			0xC265A1FD284F9B99ULL,
			0xF99430D3844A107BULL,
			0xC599A658FE98616EULL,
			0x390DE27F693237E6ULL}
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

	steps = 5;
	X1 = (curve25519_key_t){.key64 = {
		0xADA59A723A6C4278ULL,
		0xDD87453ACDAA4D61ULL,
		0xA0B053787FF67017ULL,
		0x4F4E8D197124A55CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xADA59A723A6C4278ULL,
			0xDD87453ACDAA4D61ULL,
			0xA0B053787FF67017ULL,
			0x4F4E8D197124A55CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x038C265E5F05E0BCULL,
			0xDD7B7996EFD60701ULL,
			0x73E9351C0924DAB4ULL,
			0x6FABD13F092A0F96ULL}
		},
		.Z = {.key64 = {
			0xA7FD18EDC74C63F2ULL,
			0x59D37861111035A8ULL,
			0x7A2E0439D8A1D69AULL,
			0x4E1EE7EF2E87636DULL}
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
		0x368E6E64110E85D8ULL,
		0x5FB2D5BE8B118DF5ULL,
		0xF6DEE749516B1A0EULL,
		0x70FAA063BCC98840ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x368E6E64110E85D8ULL,
			0x5FB2D5BE8B118DF5ULL,
			0xF6DEE749516B1A0EULL,
			0x70FAA063BCC98840ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC7F78894F26F8ACFULL,
			0xA0FEAF0DF8F1074BULL,
			0xF098170D75173DE4ULL,
			0x0B0539B765D4E1AFULL}
		},
		.Z = {.key64 = {
			0xE4908B9B6FA69EB1ULL,
			0x2256AFD423E05FCDULL,
			0xC87336725BCB0E48ULL,
			0x51DEA33822B7C821ULL}
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

	steps = 5;
	X1 = (curve25519_key_t){.key64 = {
		0xD1D93AAC8F69FDA0ULL,
		0x0121BA68C75CB0C3ULL,
		0x1173C0CADE57E318ULL,
		0x4B56A5A1DD9FAB70ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD1D93AAC8F69FDA0ULL,
			0x0121BA68C75CB0C3ULL,
			0x1173C0CADE57E318ULL,
			0x4B56A5A1DD9FAB70ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x67649BD26B0A153DULL,
			0x5DFD949EF1CA92C0ULL,
			0xF0A1CA5EEAC34D8EULL,
			0x7D5A2D8FE772115FULL}
		},
		.Z = {.key64 = {
			0xB6D52C6451AC0ECCULL,
			0x0993E40E4410C7FFULL,
			0x352435D5C3EB077BULL,
			0x00164A7D21E2703DULL}
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

	steps = 17;
	X1 = (curve25519_key_t){.key64 = {
		0x4EDF78F0D6EC4B30ULL,
		0xB7733DB16D1D8B06ULL,
		0x6528D81C374F27E3ULL,
		0x4B0EE256577B8CBCULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4EDF78F0D6EC4B30ULL,
			0xB7733DB16D1D8B06ULL,
			0x6528D81C374F27E3ULL,
			0x4B0EE256577B8CBCULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEF463A02D22DBE88ULL,
			0x5C84863009DAA209ULL,
			0x2DED53C1B3DF920FULL,
			0x60BB0CACBBC70ABAULL}
		},
		.Z = {.key64 = {
			0x002F69C5EAC44832ULL,
			0xAC51BF97F8761AD1ULL,
			0x14EC8FBDC94F7085ULL,
			0x251209E078A0A7F1ULL}
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

	steps = 57;
	X1 = (curve25519_key_t){.key64 = {
		0x050AE20CAB6A9600ULL,
		0x113E1DD8AC32FECAULL,
		0x4E92BBA24665465EULL,
		0x606FBA6164ABCE6AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x050AE20CAB6A9600ULL,
			0x113E1DD8AC32FECAULL,
			0x4E92BBA24665465EULL,
			0x606FBA6164ABCE6AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2342181F352F8604ULL,
			0xD6BFDB2B650E0964ULL,
			0xB9561684276C3452ULL,
			0x40BA1D1645FA9407ULL}
		},
		.Z = {.key64 = {
			0xD00E4C624415E8F2ULL,
			0xEE467A7CEB7953FCULL,
			0x0B1D1DE7AB0DE98EULL,
			0x428CBB75A7E8AB17ULL}
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

	steps = 27;
	X1 = (curve25519_key_t){.key64 = {
		0x675F1DE1723AFFD8ULL,
		0x13D229A0A6B58ADAULL,
		0xCAE093E33054D951ULL,
		0x78CA5ACE0694A2DAULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x675F1DE1723AFFD8ULL,
			0x13D229A0A6B58ADAULL,
			0xCAE093E33054D951ULL,
			0x78CA5ACE0694A2DAULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6DB900D5A24A363FULL,
			0x2FB2DF3E9F8B882AULL,
			0x38965D03EDB4997FULL,
			0x05EA81230C4B0336ULL}
		},
		.Z = {.key64 = {
			0x09D16059F18DFAC4ULL,
			0x425B7084A5FF5E3DULL,
			0x536318E0BC8A317CULL,
			0x4F6A12B83412F4E0ULL}
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

	steps = 61;
	X1 = (curve25519_key_t){.key64 = {
		0x7DED37CA2B705D00ULL,
		0x8820D4AC5EB6825AULL,
		0x851BAAFD99357590ULL,
		0x6C255C4A5A7C69F1ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7DED37CA2B705D00ULL,
			0x8820D4AC5EB6825AULL,
			0x851BAAFD99357590ULL,
			0x6C255C4A5A7C69F1ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCE8E54238DA46F39ULL,
			0x00DCDEF9C8DAA929ULL,
			0xEA1815A9480A3294ULL,
			0x660F130DE9BDC789ULL}
		},
		.Z = {.key64 = {
			0xA2652F228B4F4375ULL,
			0xFDC106955341319BULL,
			0x01EE9E897EBAD0A1ULL,
			0x27738855DF20FA56ULL}
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

	steps = 3;
	X1 = (curve25519_key_t){.key64 = {
		0xCABB3F5889A609F8ULL,
		0xFD88E0F1EFBA8ABFULL,
		0x5B616A3863871DA7ULL,
		0x43B7BE545F67B0AFULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCABB3F5889A609F8ULL,
			0xFD88E0F1EFBA8ABFULL,
			0x5B616A3863871DA7ULL,
			0x43B7BE545F67B0AFULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x68199FAC4C5092D9ULL,
			0x475E416CBCD33181ULL,
			0x14C8AC655F521EECULL,
			0x78ED3726C0B5DBCDULL}
		},
		.Z = {.key64 = {
			0xAA4FCDA7A6F8DA3AULL,
			0x3D51F186D015FE60ULL,
			0xD363DF3328DC5F68ULL,
			0x5A2FECAA511439A3ULL}
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

	steps = 40;
	X1 = (curve25519_key_t){.key64 = {
		0x77D9E3420F6985E8ULL,
		0x748B3F413ACA053EULL,
		0x2CE96C0030C7A688ULL,
		0x71F8EFA087265B0BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x77D9E3420F6985E8ULL,
			0x748B3F413ACA053EULL,
			0x2CE96C0030C7A688ULL,
			0x71F8EFA087265B0BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCC11B24BB1A7C06AULL,
			0xFBC7DA236847B8B3ULL,
			0x31CCF3607959ADD5ULL,
			0x2962295A030149A3ULL}
		},
		.Z = {.key64 = {
			0x30E512DEE58055B6ULL,
			0x56401AC168195141ULL,
			0x31E9D7C6000E0B41ULL,
			0x66861FA447E766F6ULL}
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
		0xB8F72F959AFC7C98ULL,
		0xCC4AE024D131DF03ULL,
		0x46585D21ABA0DF85ULL,
		0x4B8B1AC9EFC84B50ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB8F72F959AFC7C98ULL,
			0xCC4AE024D131DF03ULL,
			0x46585D21ABA0DF85ULL,
			0x4B8B1AC9EFC84B50ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x10552460D31F946AULL,
			0xBD8C1A374D03651EULL,
			0x3164D401D28AB0D3ULL,
			0x20CFC484E6CCDE1DULL}
		},
		.Z = {.key64 = {
			0x73E4C05F3A3E7E2DULL,
			0x64939B11A86A6860ULL,
			0x4BE77B37CDECBA8EULL,
			0x1621061FAED879A6ULL}
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

	steps = 25;
	X1 = (curve25519_key_t){.key64 = {
		0xBFDCB911B03A2AD8ULL,
		0x2A5CA4EBD3415770ULL,
		0x89BE34989F2D62D2ULL,
		0x416E22405F90A9D1ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBFDCB911B03A2AD8ULL,
			0x2A5CA4EBD3415770ULL,
			0x89BE34989F2D62D2ULL,
			0x416E22405F90A9D1ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC83808BC99045617ULL,
			0x4133679F384BD8D6ULL,
			0x5931E44A36B07785ULL,
			0x34A163F663AE0F12ULL}
		},
		.Z = {.key64 = {
			0x724355C9482110BBULL,
			0xA07264BE93EEC574ULL,
			0x362C7E9E69EA07DEULL,
			0x6EB23202085FEBB5ULL}
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

	steps = 36;
	X1 = (curve25519_key_t){.key64 = {
		0xBAE256B86CB1A8B0ULL,
		0x7D3F467B17FECF51ULL,
		0x4076F79A12D5374AULL,
		0x6142826E39434FDCULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBAE256B86CB1A8B0ULL,
			0x7D3F467B17FECF51ULL,
			0x4076F79A12D5374AULL,
			0x6142826E39434FDCULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x76B2925F9BF88AF6ULL,
			0x99F6A7C15EC2F1D8ULL,
			0xF4CB217EB1023263ULL,
			0x4F558E36E7CBF386ULL}
		},
		.Z = {.key64 = {
			0x6BA93E5C29090C7EULL,
			0xA5AF1426BD5742F1ULL,
			0x3608F101E8589E1CULL,
			0x560AECDA5A1180EDULL}
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

	steps = 24;
	X1 = (curve25519_key_t){.key64 = {
		0x22F631462B353E48ULL,
		0x3D5D435B0F714B89ULL,
		0xA61233975850C0B4ULL,
		0x73678487FFC07BD0ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x22F631462B353E48ULL,
			0x3D5D435B0F714B89ULL,
			0xA61233975850C0B4ULL,
			0x73678487FFC07BD0ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA5EA1F7A857C8FEBULL,
			0x9E8939787D7C3B50ULL,
			0xEB9EF72B19DA1884ULL,
			0x6648DF31FC23E1E2ULL}
		},
		.Z = {.key64 = {
			0x59D98392AC434330ULL,
			0xA79A8E08A1F3FDD4ULL,
			0x2749464F0E9B2DF7ULL,
			0x4CABBB41973AAC67ULL}
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

	steps = 36;
	X1 = (curve25519_key_t){.key64 = {
		0xDC37F6F80C374F98ULL,
		0x14C12D62FDBCDCEEULL,
		0x4BD03F2BA3DDBD2FULL,
		0x65A40EF0CA58FBF2ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDC37F6F80C374F98ULL,
			0x14C12D62FDBCDCEEULL,
			0x4BD03F2BA3DDBD2FULL,
			0x65A40EF0CA58FBF2ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFC20730B2622A7A3ULL,
			0xE4E9C47D27A01103ULL,
			0xC7AF3F3D9C8F74ADULL,
			0x7E04B58C8EA31C0EULL}
		},
		.Z = {.key64 = {
			0x32A1EA8C3D80022BULL,
			0xF5B6FAE69D85C968ULL,
			0x4B4A19AEAAD85C4AULL,
			0x01D229F9915D01BEULL}
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

	steps = 14;
	X1 = (curve25519_key_t){.key64 = {
		0x0EF3F7F96BA2AEB0ULL,
		0x3A0F550D9BE3A8E0ULL,
		0xEE6E8365107F432FULL,
		0x69DB0A0840647016ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0EF3F7F96BA2AEB0ULL,
			0x3A0F550D9BE3A8E0ULL,
			0xEE6E8365107F432FULL,
			0x69DB0A0840647016ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x78BC5C92C6284F6EULL,
			0x5756AEA2B5C10BB7ULL,
			0x22D54042768BE6EFULL,
			0x0A52F88BE496116BULL}
		},
		.Z = {.key64 = {
			0xD1D8C640AFFB1AEAULL,
			0x1872E4A7754BB8C9ULL,
			0x3C4E8DAC27961E13ULL,
			0x08C0A72F2A1DC8ACULL}
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

	steps = 52;
	X1 = (curve25519_key_t){.key64 = {
		0xC269B5F4E091A240ULL,
		0x30E5A03C0ED05CB4ULL,
		0xAA94F6D2B83016B9ULL,
		0x7175688DFE66642CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC269B5F4E091A240ULL,
			0x30E5A03C0ED05CB4ULL,
			0xAA94F6D2B83016B9ULL,
			0x7175688DFE66642CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1DCBF51A46578847ULL,
			0xDCCECAD3965D026FULL,
			0x84C70F8A3B909865ULL,
			0x442C65A558FD4B01ULL}
		},
		.Z = {.key64 = {
			0x8CA695BAD1B74887ULL,
			0xA8749AC09CFF4682ULL,
			0xF0268F1DECABAF96ULL,
			0x3CC30B95F057A072ULL}
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

	steps = 60;
	X1 = (curve25519_key_t){.key64 = {
		0xC358978E622077B0ULL,
		0xA4FE8C5D1CAECE83ULL,
		0x4DDCD3AAECAF1DABULL,
		0x7350D2F56EB36D76ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC358978E622077B0ULL,
			0xA4FE8C5D1CAECE83ULL,
			0x4DDCD3AAECAF1DABULL,
			0x7350D2F56EB36D76ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFFF8C48DF891E68AULL,
			0x73204BE68F4B3675ULL,
			0x38AC74C5BCAEF726ULL,
			0x06F6A2CCF027C2FDULL}
		},
		.Z = {.key64 = {
			0x3950E978D63A90BCULL,
			0xDE8ADB89E13CD491ULL,
			0xD1D36F1255E2C4D9ULL,
			0x13105CAD34CD8039ULL}
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

	steps = 52;
	X1 = (curve25519_key_t){.key64 = {
		0x2BC002D654AEE2B0ULL,
		0xAACD7A687FBF1FA1ULL,
		0xE3887A3F006595B3ULL,
		0x7FFBD706C5098C7EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2BC002D654AEE2B0ULL,
			0xAACD7A687FBF1FA1ULL,
			0xE3887A3F006595B3ULL,
			0x7FFBD706C5098C7EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4D370DF38381DD78ULL,
			0x263219F137717E26ULL,
			0x3BFF7015FD054E16ULL,
			0x4F3D83B9641C7090ULL}
		},
		.Z = {.key64 = {
			0xBC1687DC6BFC4D7CULL,
			0xADA6B312294FD102ULL,
			0x77E8FD1A09DF6AE1ULL,
			0x15D3047C08B58015ULL}
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

	steps = 37;
	X1 = (curve25519_key_t){.key64 = {
		0x5EF9D730D92C83F8ULL,
		0x92C7C4029610D320ULL,
		0x31DC60C8220CA205ULL,
		0x5168B8BC4D7029B1ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5EF9D730D92C83F8ULL,
			0x92C7C4029610D320ULL,
			0x31DC60C8220CA205ULL,
			0x5168B8BC4D7029B1ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1B35507155E455E1ULL,
			0xC40335102967404FULL,
			0x9C060518B9761AABULL,
			0x1A512CA4990E7644ULL}
		},
		.Z = {.key64 = {
			0x901D6711720F893CULL,
			0x8C2B24CEC65269F2ULL,
			0x67E530457ED9F149ULL,
			0x418BBF46D84855AEULL}
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

	steps = 33;
	X1 = (curve25519_key_t){.key64 = {
		0x753FAD218DC0C2B0ULL,
		0xB716434084786842ULL,
		0xBAED09B51D774353ULL,
		0x65C9B3693847C6AEULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x753FAD218DC0C2B0ULL,
			0xB716434084786842ULL,
			0xBAED09B51D774353ULL,
			0x65C9B3693847C6AEULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xECF7165DA5DF5075ULL,
			0x544CC98C4D57850AULL,
			0x53EB98646A32B71BULL,
			0x12B6A6EC8FF71FF7ULL}
		},
		.Z = {.key64 = {
			0x6BAD2C88F869DFC4ULL,
			0xC8FEDC84B807D6C5ULL,
			0xD082E357EEE15403ULL,
			0x5D89498F955A3C4FULL}
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

	steps = 37;
	X1 = (curve25519_key_t){.key64 = {
		0xB73AB1A392DC1EA0ULL,
		0xAE7FD7A4A88EEC22ULL,
		0x37708F4EFD399555ULL,
		0x56DA10E543FE43C9ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB73AB1A392DC1EA0ULL,
			0xAE7FD7A4A88EEC22ULL,
			0x37708F4EFD399555ULL,
			0x56DA10E543FE43C9ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDC6422B9003B3CEAULL,
			0x773263516E4ADBE5ULL,
			0xDB052655D1FE4D50ULL,
			0x6C679CDCE5B95952ULL}
		},
		.Z = {.key64 = {
			0xD1B19F323F5DC8C1ULL,
			0x03A9C9475498C101ULL,
			0xC71A9BA4996FF12DULL,
			0x61BD25EC9EEE1753ULL}
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

	steps = 12;
	X1 = (curve25519_key_t){.key64 = {
		0x23327C92870515F0ULL,
		0xE5E75744F0641AA1ULL,
		0x668D94D2C099CB2DULL,
		0x489F14C4D9854452ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x23327C92870515F0ULL,
			0xE5E75744F0641AA1ULL,
			0x668D94D2C099CB2DULL,
			0x489F14C4D9854452ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x39F66585403848BEULL,
			0x92B6F0F172805A38ULL,
			0x65D01402CEEF1E4BULL,
			0x04030F7D84E0BAFBULL}
		},
		.Z = {.key64 = {
			0xFB578ADC3BA791C0ULL,
			0xC81D0E12CBB46112ULL,
			0x1E804EAAA4C38F50ULL,
			0x57C0A9490702CA82ULL}
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

	steps = 59;
	X1 = (curve25519_key_t){.key64 = {
		0x8E3554445DEB58E8ULL,
		0x5728B0A3E83BB7BCULL,
		0x0C75B4D5DEFE4B6FULL,
		0x78138CDA7098CFFBULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8E3554445DEB58E8ULL,
			0x5728B0A3E83BB7BCULL,
			0x0C75B4D5DEFE4B6FULL,
			0x78138CDA7098CFFBULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD3612F046BC27E12ULL,
			0x306BCC52ED23360BULL,
			0xFE3CE05EAFD7EF6AULL,
			0x7445EBE4375CB326ULL}
		},
		.Z = {.key64 = {
			0x26B7AAF1EBA04605ULL,
			0xC213C98BFB9C2446ULL,
			0xC54FB4918DCCD99BULL,
			0x56BA38DB6C8DBB6CULL}
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

	steps = 15;
	X1 = (curve25519_key_t){.key64 = {
		0x353958B9683458D0ULL,
		0x7306478B0786F02FULL,
		0x87367D21A3E291B0ULL,
		0x7802CEEBEEAF6114ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x353958B9683458D0ULL,
			0x7306478B0786F02FULL,
			0x87367D21A3E291B0ULL,
			0x7802CEEBEEAF6114ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x418FD716F53FD10CULL,
			0xD6EE6167E85A2930ULL,
			0xEBEB247C8BD8808EULL,
			0x293ADC9381537012ULL}
		},
		.Z = {.key64 = {
			0x38A52088690E7F2BULL,
			0x34F3D2058B4F354BULL,
			0x77825B29D09AB99FULL,
			0x181D428E2A136985ULL}
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

	steps = 37;
	X1 = (curve25519_key_t){.key64 = {
		0x9E2B9AA7F26183C8ULL,
		0xC36C214D5DFFB401ULL,
		0xC670E2C312C5FCC2ULL,
		0x7ABD87C19B21F005ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9E2B9AA7F26183C8ULL,
			0xC36C214D5DFFB401ULL,
			0xC670E2C312C5FCC2ULL,
			0x7ABD87C19B21F005ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3E1B53968BA70128ULL,
			0x52F5EFE02227C4CEULL,
			0xC289357B99AB6D13ULL,
			0x2FDE905831465CFCULL}
		},
		.Z = {.key64 = {
			0xA3038236D49E2DE0ULL,
			0xF449AE2BD243CA3FULL,
			0x96D7B855D194C593ULL,
			0x48FD95B7DD25735AULL}
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

	steps = 5;
	X1 = (curve25519_key_t){.key64 = {
		0xB9B8FF996E93DD30ULL,
		0x97DEDE2C349BB4B9ULL,
		0xA9E938D5CE39E460ULL,
		0x4F4FABF5C12B2FDEULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB9B8FF996E93DD30ULL,
			0x97DEDE2C349BB4B9ULL,
			0xA9E938D5CE39E460ULL,
			0x4F4FABF5C12B2FDEULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3FE43AD5B708B8D2ULL,
			0x62E5BAC897C1F4AEULL,
			0x6673D5DAB14F8928ULL,
			0x36B2E5FB11ADE5CFULL}
		},
		.Z = {.key64 = {
			0x5963C18835098FFBULL,
			0x34D86F5785B201ECULL,
			0xA1BF95377BEB67ABULL,
			0x12E6565D41C2BB08ULL}
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

	steps = 16;
	X1 = (curve25519_key_t){.key64 = {
		0x8C93564D507AD920ULL,
		0x7159F64B70C09458ULL,
		0xF4796555A8938B37ULL,
		0x57741DE2CD61972CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8C93564D507AD920ULL,
			0x7159F64B70C09458ULL,
			0xF4796555A8938B37ULL,
			0x57741DE2CD61972CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFABD38391780BF1AULL,
			0x30767C6BAADBA145ULL,
			0x0A7524ABB90E4637ULL,
			0x144567BC29932270ULL}
		},
		.Z = {.key64 = {
			0x9592AE7B9FBFEDFEULL,
			0xB683A3BDE4817BC6ULL,
			0xB54DE5D8A5F80FBAULL,
			0x44AA5A2EEC97F61CULL}
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

	steps = 13;
	X1 = (curve25519_key_t){.key64 = {
		0xAB4999EEB202BEF0ULL,
		0xCD7FF505CBB40A6DULL,
		0xB7C740B8B9A5A5EDULL,
		0x4B15155EFB8C0C77ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAB4999EEB202BEF0ULL,
			0xCD7FF505CBB40A6DULL,
			0xB7C740B8B9A5A5EDULL,
			0x4B15155EFB8C0C77ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE207C85E2E5E96EBULL,
			0x215C4122A018C61AULL,
			0xD84B2521D072F837ULL,
			0x6DAE1A8A4F962ED1ULL}
		},
		.Z = {.key64 = {
			0x58FB6BDDC9BAB1DBULL,
			0x7804EF2B2B9DCCB8ULL,
			0x899ABE28DC437980ULL,
			0x2ED8A66FB0F98CA5ULL}
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

	steps = 23;
	X1 = (curve25519_key_t){.key64 = {
		0x6B31D25524355818ULL,
		0x54A26EBA920480BAULL,
		0xFEAB32EC20092E11ULL,
		0x632E4755F4B8BEAEULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6B31D25524355818ULL,
			0x54A26EBA920480BAULL,
			0xFEAB32EC20092E11ULL,
			0x632E4755F4B8BEAEULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x94D9E4A48BE6BC4FULL,
			0xF7E886A19080F927ULL,
			0xE78E2043D979D708ULL,
			0x0C8ED3C2308413A6ULL}
		},
		.Z = {.key64 = {
			0xF1C98C23CA545F2FULL,
			0x77E2C8AAB0EDBD3DULL,
			0x3557B5C43FE167E4ULL,
			0x02B35F51D749C53EULL}
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

	steps = 16;
	X1 = (curve25519_key_t){.key64 = {
		0x7FE6598214B10240ULL,
		0x43AC6A20C3A9B348ULL,
		0x8CF277144E1B85D6ULL,
		0x52F3940F41F6AD58ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7FE6598214B10240ULL,
			0x43AC6A20C3A9B348ULL,
			0x8CF277144E1B85D6ULL,
			0x52F3940F41F6AD58ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x23589FF20F05EC09ULL,
			0xA89EE38CE9B9A720ULL,
			0xEA1E3AF6367FB2B5ULL,
			0x33E97CAA43D14259ULL}
		},
		.Z = {.key64 = {
			0xFEC678726D5334CAULL,
			0x6BBB2385D41C68AFULL,
			0xECECB67A7E330270ULL,
			0x37AEDDAC790A94A0ULL}
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

	steps = 49;
	X1 = (curve25519_key_t){.key64 = {
		0x70F0B3EA27AA5FF0ULL,
		0x3F35B0035C64460AULL,
		0xE8DC31C72705BC8FULL,
		0x7BC25BEB529BEB11ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x70F0B3EA27AA5FF0ULL,
			0x3F35B0035C64460AULL,
			0xE8DC31C72705BC8FULL,
			0x7BC25BEB529BEB11ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x59804ED77CAF7FA3ULL,
			0x2C31FC08498824BCULL,
			0xCC9A097AE5149A79ULL,
			0x7D4F9FB733352DF9ULL}
		},
		.Z = {.key64 = {
			0x3E6F4A4535153AD0ULL,
			0xC2FCA9F338B8F296ULL,
			0xB048708F29CE1F4FULL,
			0x4A2DB43C8015C20EULL}
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

	steps = 6;
	X1 = (curve25519_key_t){.key64 = {
		0xE37077AEE05B17F0ULL,
		0x77AE0792DB130B57ULL,
		0x456570490BF3EC8AULL,
		0x6BEC28AD2326F997ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE37077AEE05B17F0ULL,
			0x77AE0792DB130B57ULL,
			0x456570490BF3EC8AULL,
			0x6BEC28AD2326F997ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x99897F7AD91F9869ULL,
			0x4331C4B4ACB2C757ULL,
			0xEE25F644785CC2B0ULL,
			0x24BD0374FEA56FE8ULL}
		},
		.Z = {.key64 = {
			0x3D9BAC49B1E5D2F9ULL,
			0xB3F6D03F1AD62A0FULL,
			0x2904FF8C6A1CBC29ULL,
			0x24B1CDFCD2BCBD7FULL}
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

	steps = 14;
	X1 = (curve25519_key_t){.key64 = {
		0xA4AED05F690BFEE8ULL,
		0x471E59DA1A64DE8EULL,
		0xD594438CE2611263ULL,
		0x68FCFD832464F435ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA4AED05F690BFEE8ULL,
			0x471E59DA1A64DE8EULL,
			0xD594438CE2611263ULL,
			0x68FCFD832464F435ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4C6561F16E5645FDULL,
			0xB85DD2F3DBB33CEDULL,
			0x6B719883122323ABULL,
			0x64E4961571931F1CULL}
		},
		.Z = {.key64 = {
			0xFB43E3F2EDA2710EULL,
			0x6529C4EF5447229DULL,
			0x79DE9B9F1CAF8418ULL,
			0x33A195ADADC8C949ULL}
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

	steps = 7;
	X1 = (curve25519_key_t){.key64 = {
		0x5FD239ABC398AEB0ULL,
		0xFE2A23431888A1E2ULL,
		0xA1653BE557AB3674ULL,
		0x4011550D34F6FFA7ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5FD239ABC398AEB0ULL,
			0xFE2A23431888A1E2ULL,
			0xA1653BE557AB3674ULL,
			0x4011550D34F6FFA7ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFC5B5CEC9298C458ULL,
			0x474CF0519C46DBB9ULL,
			0xF9EC07667409D97EULL,
			0x47A1137001231B31ULL}
		},
		.Z = {.key64 = {
			0x303A5CCC762C5CD9ULL,
			0xA027F8753C0D8372ULL,
			0x0C8C197EDF0C16B1ULL,
			0x656A254E7ABCBCDEULL}
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

	steps = 11;
	X1 = (curve25519_key_t){.key64 = {
		0xA88A7864055A9658ULL,
		0x1886450FF5AAB6E3ULL,
		0x7C5697FA55DDBBC2ULL,
		0x4ABF335EA1F85F40ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA88A7864055A9658ULL,
			0x1886450FF5AAB6E3ULL,
			0x7C5697FA55DDBBC2ULL,
			0x4ABF335EA1F85F40ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x21BE43DCA51AC9C2ULL,
			0x4BF2C272881B1C1BULL,
			0x35DCEA9870621798ULL,
			0x1C8A391CDC6689D2ULL}
		},
		.Z = {.key64 = {
			0x63DBD5321FC8E101ULL,
			0xE251504DD25C8CA1ULL,
			0xCD19BBDDB64ECC3CULL,
			0x131B7FC58944B281ULL}
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

	steps = 50;
	X1 = (curve25519_key_t){.key64 = {
		0x8FB265BBEA970B28ULL,
		0x49E9495EFF745313ULL,
		0x327CD46F1208EF9DULL,
		0x41C44AF730B30F44ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8FB265BBEA970B28ULL,
			0x49E9495EFF745313ULL,
			0x327CD46F1208EF9DULL,
			0x41C44AF730B30F44ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x75FE4A5CF02F7EA6ULL,
			0x97586868249F0A4CULL,
			0x2F6620556432CFD9ULL,
			0x0A5C78DFDC501F98ULL}
		},
		.Z = {.key64 = {
			0x9728A5B08EDE55A0ULL,
			0xEDE9112901AB20CFULL,
			0x9C80E39A837221ACULL,
			0x20CAC0EA6D135E32ULL}
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
		0x104341EF7B64CB80ULL,
		0x0743DFF4466C6664ULL,
		0x15F1827818DFFB4DULL,
		0x5472E46C798C4DB1ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x104341EF7B64CB80ULL,
			0x0743DFF4466C6664ULL,
			0x15F1827818DFFB4DULL,
			0x5472E46C798C4DB1ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB07E18FF6D6C70A1ULL,
			0x5C39F842EF30752CULL,
			0x31363D06BECA27AEULL,
			0x438ABC8A4CD4D8D5ULL}
		},
		.Z = {.key64 = {
			0x55C11E6D93F0F400ULL,
			0x3BA370743FD256BEULL,
			0xFED7B69DB5F7D105ULL,
			0x3AAFDE79FAB35593ULL}
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

	steps = 5;
	X1 = (curve25519_key_t){.key64 = {
		0xB19183BA0B54D488ULL,
		0x5F15EF1511F98471ULL,
		0x2D095E0F5C132682ULL,
		0x6EF0D755EEDD1918ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB19183BA0B54D488ULL,
			0x5F15EF1511F98471ULL,
			0x2D095E0F5C132682ULL,
			0x6EF0D755EEDD1918ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9083D2225010643CULL,
			0x166BD615504D5537ULL,
			0x2A0677CA2CF0564BULL,
			0x2DCB8F948BC84F88ULL}
		},
		.Z = {.key64 = {
			0x7350574D1698249DULL,
			0x5F213147654719D3ULL,
			0xFFB276024B890A42ULL,
			0x191BEF315708DB2AULL}
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

	steps = 29;
	X1 = (curve25519_key_t){.key64 = {
		0xC9402E11E990F810ULL,
		0x593A6FB9A2C10120ULL,
		0xB63F36A275664F12ULL,
		0x5EF0B8B02DCB9D3EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC9402E11E990F810ULL,
			0x593A6FB9A2C10120ULL,
			0xB63F36A275664F12ULL,
			0x5EF0B8B02DCB9D3EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB9E17DDD2D7DDEBCULL,
			0x10CA0CB9D45D0A35ULL,
			0x1357B67BD54DF315ULL,
			0x3A70D70640D40760ULL}
		},
		.Z = {.key64 = {
			0x1775E207A306A757ULL,
			0x3A6219F7566CD269ULL,
			0x6F566AD7541DD91AULL,
			0x6BA8E6D1A2E9A73CULL}
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

	steps = 39;
	X1 = (curve25519_key_t){.key64 = {
		0xF1C774244F420538ULL,
		0xBC042E9117EE15B0ULL,
		0x79CD076D5AA290E9ULL,
		0x792266FBA2BBA04EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF1C774244F420538ULL,
			0xBC042E9117EE15B0ULL,
			0x79CD076D5AA290E9ULL,
			0x792266FBA2BBA04EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC787D6BD36681294ULL,
			0x866DD53C32A8E22BULL,
			0x9413D685AB2B23A2ULL,
			0x7C067574C4BCFFE9ULL}
		},
		.Z = {.key64 = {
			0x680759D4995CFDFFULL,
			0x12B3B593EBFCB865ULL,
			0x512C07B91F33780BULL,
			0x1FB47D6B16A42E51ULL}
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

	steps = 33;
	X1 = (curve25519_key_t){.key64 = {
		0x11AFFE9971117A68ULL,
		0x3FB5887FCAD227DBULL,
		0xA441D729D53152F1ULL,
		0x7EFBCDF3BA71E269ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x11AFFE9971117A68ULL,
			0x3FB5887FCAD227DBULL,
			0xA441D729D53152F1ULL,
			0x7EFBCDF3BA71E269ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB7B952EC1C357B92ULL,
			0x419A7A468BC03BCCULL,
			0x1E5A12991B973AA7ULL,
			0x60675A5A6BD442CAULL}
		},
		.Z = {.key64 = {
			0x228F1AFFAB43C8E3ULL,
			0x906E31259AAAA480ULL,
			0x1F77E22E799AB6EAULL,
			0x05941A238F19D37EULL}
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

	steps = 63;
	X1 = (curve25519_key_t){.key64 = {
		0x031E20F0F8F45FC0ULL,
		0xEC4B30DB351036E8ULL,
		0x24121410AF210670ULL,
		0x739918E86BED0D75ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x031E20F0F8F45FC0ULL,
			0xEC4B30DB351036E8ULL,
			0x24121410AF210670ULL,
			0x739918E86BED0D75ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x08777B7ACB4B481AULL,
			0x773120138056AAABULL,
			0xC187A9F04E80CEBEULL,
			0x4E7E2DCC4F903EF7ULL}
		},
		.Z = {.key64 = {
			0x6660942331005498ULL,
			0xAF9426E8C2B16F79ULL,
			0x6A753E2D2C1FC259ULL,
			0x4C818B29098E5AABULL}
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

	steps = 17;
	X1 = (curve25519_key_t){.key64 = {
		0x5943DDB5C1F09D10ULL,
		0x169DEA86F0AE9205ULL,
		0xB2C5D8145715629DULL,
		0x608EA539964124DEULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5943DDB5C1F09D10ULL,
			0x169DEA86F0AE9205ULL,
			0xB2C5D8145715629DULL,
			0x608EA539964124DEULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8DF2F5516FB51343ULL,
			0xEF1636E9B01A350EULL,
			0x213ACE695DF48F6DULL,
			0x544FDFC3E9EF3349ULL}
		},
		.Z = {.key64 = {
			0x3C6DADCAE5DC59A2ULL,
			0x88947A6D3B93D8F3ULL,
			0x00B9D065AF17626DULL,
			0x4E92CC1A2BA4C196ULL}
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

	steps = 37;
	X1 = (curve25519_key_t){.key64 = {
		0xB63614C2E1BE4170ULL,
		0xE2F6B62D88C8F378ULL,
		0xF5577293C8A79BA3ULL,
		0x4435F4901AE3F5C8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB63614C2E1BE4170ULL,
			0xE2F6B62D88C8F378ULL,
			0xF5577293C8A79BA3ULL,
			0x4435F4901AE3F5C8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE445D9A7868D2EEDULL,
			0x879EB2175F6E0264ULL,
			0x83C2591016BBCC65ULL,
			0x3376534AF909A4D3ULL}
		},
		.Z = {.key64 = {
			0xB6C53DFBB74E3AB1ULL,
			0xDA709E02D199F4E6ULL,
			0x9306B846E9237486ULL,
			0x026F3085621FCD6FULL}
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

	steps = 12;
	X1 = (curve25519_key_t){.key64 = {
		0x37C3825C19828020ULL,
		0xE6EDDFB8E0FE984AULL,
		0xE280FACC557CCAE2ULL,
		0x644E4DF2C3A5FCD1ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x37C3825C19828020ULL,
			0xE6EDDFB8E0FE984AULL,
			0xE280FACC557CCAE2ULL,
			0x644E4DF2C3A5FCD1ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4580C7A6942B9015ULL,
			0xAD3CDDD253CB8F91ULL,
			0x766D754C8D86E3AEULL,
			0x7EEE9132D4419A22ULL}
		},
		.Z = {.key64 = {
			0x63366DC548E6DEF5ULL,
			0x79F3413A5F30A303ULL,
			0x423F74684E958A26ULL,
			0x2EA8C9CD0C9DE4A2ULL}
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

	steps = 24;
	X1 = (curve25519_key_t){.key64 = {
		0x7407CAD4B9B02260ULL,
		0x892B57FD67CCF661ULL,
		0xCB497EA6642D3601ULL,
		0x5FCF1013C9D98B3BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7407CAD4B9B02260ULL,
			0x892B57FD67CCF661ULL,
			0xCB497EA6642D3601ULL,
			0x5FCF1013C9D98B3BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x29684BEDE2A0F04AULL,
			0x5940570D1F1DDC88ULL,
			0xFCD5EE48EF062FCDULL,
			0x5CCE9F5F7A7981C9ULL}
		},
		.Z = {.key64 = {
			0xD27EB87F2B5080BEULL,
			0xEEAE92870FFD8F95ULL,
			0xC3FD14F35D3A3DE0ULL,
			0x3C19E70910DCB85AULL}
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

	steps = 8;
	X1 = (curve25519_key_t){.key64 = {
		0xA99782D78E2AA2A0ULL,
		0x98143ABC1766037FULL,
		0x40094BACF1A68CA9ULL,
		0x740BF91EEB08EB4EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA99782D78E2AA2A0ULL,
			0x98143ABC1766037FULL,
			0x40094BACF1A68CA9ULL,
			0x740BF91EEB08EB4EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x78D315A7B2FDF9F3ULL,
			0x962AEA26AD9BE113ULL,
			0x2EB807A8EB5D396CULL,
			0x4E3720A31DA3716DULL}
		},
		.Z = {.key64 = {
			0x009F59A61EFB3E06ULL,
			0x78E062F0EDCA93E0ULL,
			0x7CF6CE5DAFD649DAULL,
			0x0288D02853F9C2BDULL}
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

	steps = 28;
	X1 = (curve25519_key_t){.key64 = {
		0xEB8C3C7FAFCAEEC8ULL,
		0x93DD76BD62BCD63EULL,
		0xDDF47F63CFEF61B3ULL,
		0x77361BD19A09C4CFULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEB8C3C7FAFCAEEC8ULL,
			0x93DD76BD62BCD63EULL,
			0xDDF47F63CFEF61B3ULL,
			0x77361BD19A09C4CFULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC670DD76755AB921ULL,
			0xCB32FCD690EBD81CULL,
			0xE228DD91A7874890ULL,
			0x1A335771A451C125ULL}
		},
		.Z = {.key64 = {
			0xBE550259DBFC8CBAULL,
			0x5C93B2DBA6BE8C8EULL,
			0x20B6D63537677F5AULL,
			0x18B72F961E49B75BULL}
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

	steps = 48;
	X1 = (curve25519_key_t){.key64 = {
		0x37211ACEEE0A7298ULL,
		0x30D9126C5939672EULL,
		0x3F7FBD3304E56121ULL,
		0x51B812333835982EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x37211ACEEE0A7298ULL,
			0x30D9126C5939672EULL,
			0x3F7FBD3304E56121ULL,
			0x51B812333835982EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB778EC04AE100AC2ULL,
			0xB82C249FB32B49A9ULL,
			0x29D00546823257FFULL,
			0x3EEA0CB55A8F740EULL}
		},
		.Z = {.key64 = {
			0x6D0780773E89CF5AULL,
			0xFE6963215C091A35ULL,
			0x2C82B5927D5E58C7ULL,
			0x201145E1492CC97CULL}
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

	steps = 31;
	X1 = (curve25519_key_t){.key64 = {
		0x5437D8FA046069C8ULL,
		0x6D2ACA223EFB8A50ULL,
		0x48D544F0C1544667ULL,
		0x64551DDC292F26FFULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5437D8FA046069C8ULL,
			0x6D2ACA223EFB8A50ULL,
			0x48D544F0C1544667ULL,
			0x64551DDC292F26FFULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFEA9707AB325428EULL,
			0x54003B56DD8FDD37ULL,
			0xE87D153978D203C0ULL,
			0x299BEAE9A0EFCDB4ULL}
		},
		.Z = {.key64 = {
			0x3DC954803F50780CULL,
			0xCD6D924CD0CCB8C8ULL,
			0x1C0BF57DE6B30992ULL,
			0x55BEE65FABD501B2ULL}
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

	steps = 21;
	X1 = (curve25519_key_t){.key64 = {
		0xE371B25FC38F8C00ULL,
		0x30BF1DC04F7FFA30ULL,
		0x49DF60C07ECFF5D3ULL,
		0x56614E3F184D229FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE371B25FC38F8C00ULL,
			0x30BF1DC04F7FFA30ULL,
			0x49DF60C07ECFF5D3ULL,
			0x56614E3F184D229FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC900443013B008D8ULL,
			0x7D48DBC4F78DD50CULL,
			0x5B0B38C62EB785DBULL,
			0x5FCDC7A1F374547CULL}
		},
		.Z = {.key64 = {
			0xF05D10BBE224EC1EULL,
			0xBF40B67F26E4A327ULL,
			0x2560F52C84D9BE56ULL,
			0x69F72253B36A0E7FULL}
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

	steps = 18;
	X1 = (curve25519_key_t){.key64 = {
		0x19BF58D9D50A4640ULL,
		0xF99713CDA0ECCF0DULL,
		0x98C3CD2B564411D2ULL,
		0x6C3F1ED1C7C2B343ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x19BF58D9D50A4640ULL,
			0xF99713CDA0ECCF0DULL,
			0x98C3CD2B564411D2ULL,
			0x6C3F1ED1C7C2B343ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEA91B8B98541CACFULL,
			0x80A92E42BF7B0EC8ULL,
			0x2A41B7C5D518296DULL,
			0x46B3BC8E3400C6F4ULL}
		},
		.Z = {.key64 = {
			0x0DD1E33FAD13597AULL,
			0x55C2846841C68354ULL,
			0x4B14805A7CEB5762ULL,
			0x610DA260B6C48CA3ULL}
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

	steps = 35;
	X1 = (curve25519_key_t){.key64 = {
		0x243B68DDA0D49520ULL,
		0xF6BCEE7118D653C6ULL,
		0x247EFB6D7382D534ULL,
		0x7F08455A8B9A5161ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x243B68DDA0D49520ULL,
			0xF6BCEE7118D653C6ULL,
			0x247EFB6D7382D534ULL,
			0x7F08455A8B9A5161ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF5557869BCA53736ULL,
			0x872893915678F23BULL,
			0x4B21426BA93A65E0ULL,
			0x1DB9C60A09EAE486ULL}
		},
		.Z = {.key64 = {
			0xF2736C83F2778500ULL,
			0x2981FF5673A441BEULL,
			0x417D40B6C3A801D6ULL,
			0x66607834B30132D3ULL}
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

	steps = 11;
	X1 = (curve25519_key_t){.key64 = {
		0x6E7471D183572C90ULL,
		0x7A5E1D0B62ED7B1DULL,
		0xBF77DA89F7C4C306ULL,
		0x7C60AA7DD5FF158DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6E7471D183572C90ULL,
			0x7A5E1D0B62ED7B1DULL,
			0xBF77DA89F7C4C306ULL,
			0x7C60AA7DD5FF158DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1C8AC04C54E8F731ULL,
			0xAF04E68D00A5A99EULL,
			0x3C52037FAF126736ULL,
			0x785695D6219FE893ULL}
		},
		.Z = {.key64 = {
			0xA370CD0A21D1F39CULL,
			0xF4796BF487F9DE7AULL,
			0xD0332DB1C816C4FEULL,
			0x61F00BF36C2CCADDULL}
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

	steps = 38;
	X1 = (curve25519_key_t){.key64 = {
		0x4A355299E2E8C7A0ULL,
		0xD72EE111A7707534ULL,
		0x7F38C7952380748CULL,
		0x6AD71EC4FD1BE67DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4A355299E2E8C7A0ULL,
			0xD72EE111A7707534ULL,
			0x7F38C7952380748CULL,
			0x6AD71EC4FD1BE67DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD01C1F6EE4173403ULL,
			0x69AA22C51F0800C3ULL,
			0x92AB11DADC599F2FULL,
			0x248D9303B6AFF130ULL}
		},
		.Z = {.key64 = {
			0x23B34A0B09074C4EULL,
			0x84C2DEE883FD5807ULL,
			0x91A6DD85B6B9C18EULL,
			0x085C11F7D02E7398ULL}
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

	steps = 40;
	X1 = (curve25519_key_t){.key64 = {
		0xE5B86B529D6543D0ULL,
		0x418E750CCA39E705ULL,
		0xDA44EC6DF09588C6ULL,
		0x75CE289C7C04A89CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE5B86B529D6543D0ULL,
			0x418E750CCA39E705ULL,
			0xDA44EC6DF09588C6ULL,
			0x75CE289C7C04A89CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x92C362F6924426D9ULL,
			0xBD07FCA0700DB520ULL,
			0x900C2385EC06D6F1ULL,
			0x48D007AEDF18274FULL}
		},
		.Z = {.key64 = {
			0x351B4CBAD793A11FULL,
			0x0A222BE4E2E13A52ULL,
			0x351E8D64C8655ADBULL,
			0x6C5787D931C45514ULL}
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

	steps = 32;
	X1 = (curve25519_key_t){.key64 = {
		0xA63A40D7A78FD8F0ULL,
		0xCE5F4D4BDB99A4CAULL,
		0xDB208A9E6D182E80ULL,
		0x65193B2BC0CA55DCULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA63A40D7A78FD8F0ULL,
			0xCE5F4D4BDB99A4CAULL,
			0xDB208A9E6D182E80ULL,
			0x65193B2BC0CA55DCULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x662AA45E1E1E2EB6ULL,
			0xADB0A1A5F04CAC54ULL,
			0xE14A134403B4F84CULL,
			0x5FC7A347EBB636E6ULL}
		},
		.Z = {.key64 = {
			0x512A32FB51F375BAULL,
			0xB336D90F09874B81ULL,
			0xE5C3AEDA813BD931ULL,
			0x4F413D80A8070C4AULL}
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

	steps = 4;
	X1 = (curve25519_key_t){.key64 = {
		0xBD82DF0498E06610ULL,
		0x7E5B201E1509CD39ULL,
		0xB9603D7E7B8ACB95ULL,
		0x44B4B424C5EBB980ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBD82DF0498E06610ULL,
			0x7E5B201E1509CD39ULL,
			0xB9603D7E7B8ACB95ULL,
			0x44B4B424C5EBB980ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3D4176123A92D316ULL,
			0x947D8769FF1A8C5AULL,
			0x2CB09790265805B8ULL,
			0x79D02E89D93B7F95ULL}
		},
		.Z = {.key64 = {
			0xC6316D06A1726F09ULL,
			0xC78725772995DB4BULL,
			0x01E5C632A42CD2FFULL,
			0x32C7A9F26C4B27FDULL}
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

	steps = 34;
	X1 = (curve25519_key_t){.key64 = {
		0xF10B6A89C2EFF3D8ULL,
		0x034A57A765D662B2ULL,
		0xA69C60F2C9298296ULL,
		0x63715A0EE1C504E4ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF10B6A89C2EFF3D8ULL,
			0x034A57A765D662B2ULL,
			0xA69C60F2C9298296ULL,
			0x63715A0EE1C504E4ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x50EA85CAA9AD58BAULL,
			0x701BE5143B55B4A9ULL,
			0x7A612770BD50F118ULL,
			0x597F780FA178952DULL}
		},
		.Z = {.key64 = {
			0xA15AF180C0395BA3ULL,
			0x62A71F00E2BDED30ULL,
			0x77261A7A8FDE792CULL,
			0x1B6AC86D94DDA803ULL}
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

	steps = 50;
	X1 = (curve25519_key_t){.key64 = {
		0x5ABDCF36056DF170ULL,
		0xA2A9B7C1824133E6ULL,
		0x8E0490CCCA6CC22EULL,
		0x6454F8385CA5E06AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5ABDCF36056DF170ULL,
			0xA2A9B7C1824133E6ULL,
			0x8E0490CCCA6CC22EULL,
			0x6454F8385CA5E06AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6BEFA6F2C5557EFCULL,
			0x3D950223CCEBA01DULL,
			0xF7E65A9860D37286ULL,
			0x20379F197EA9DA6BULL}
		},
		.Z = {.key64 = {
			0xD16422D753CD6188ULL,
			0x86AF310D54B3740AULL,
			0x0695FE8D57F252AFULL,
			0x6D4470F2044C1425ULL}
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
		0x3C0AA63BCDCBD308ULL,
		0xC6A17D2C6B8272DAULL,
		0xEB69497D46376FFEULL,
		0x49B723B80AA34950ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3C0AA63BCDCBD308ULL,
			0xC6A17D2C6B8272DAULL,
			0xEB69497D46376FFEULL,
			0x49B723B80AA34950ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7243A12E58473FA8ULL,
			0x100A31AD4E1AF778ULL,
			0xA28314990757B976ULL,
			0x59D10B4C67CCA64AULL}
		},
		.Z = {.key64 = {
			0x7A227D27A1A22AABULL,
			0x52123797E4CCC52CULL,
			0xDA982F214EC16FDCULL,
			0x6C25ACCB2F1C19ACULL}
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

	steps = 55;
	X1 = (curve25519_key_t){.key64 = {
		0xA05FA6B2677F5978ULL,
		0xF2F3EBE0AA022C38ULL,
		0x843C2AF23006C122ULL,
		0x71FE2D2E3488D174ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA05FA6B2677F5978ULL,
			0xF2F3EBE0AA022C38ULL,
			0x843C2AF23006C122ULL,
			0x71FE2D2E3488D174ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA933832F4A3EDC19ULL,
			0x832C609775CC4AA6ULL,
			0x1486454699FBA12BULL,
			0x7721B749D441FF45ULL}
		},
		.Z = {.key64 = {
			0xBCD18AB0A40A25D1ULL,
			0x25F5953A292F75D8ULL,
			0x7F1F88BF2A8D51B2ULL,
			0x70C818F7CCD312BFULL}
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

	steps = 31;
	X1 = (curve25519_key_t){.key64 = {
		0x6C240774B8947710ULL,
		0x761EACAD661DBD7AULL,
		0x8B53F10CEDC8D96DULL,
		0x49AF24638E9F5B44ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6C240774B8947710ULL,
			0x761EACAD661DBD7AULL,
			0x8B53F10CEDC8D96DULL,
			0x49AF24638E9F5B44ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDE4D7CD8FF4791C6ULL,
			0xCA0A56A2CC476D18ULL,
			0xC9F5536B84074C99ULL,
			0x65D381A5C3324075ULL}
		},
		.Z = {.key64 = {
			0x22FCDAC63772A079ULL,
			0xD512385C09048635ULL,
			0xBB70B7F6C3AB83ABULL,
			0x20D60992E7CF2050ULL}
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
		0x8E873619FBF75E38ULL,
		0xB6D689FCC906D04AULL,
		0xD34C5F02A62C4B59ULL,
		0x71B5E43D8F6C9705ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8E873619FBF75E38ULL,
			0xB6D689FCC906D04AULL,
			0xD34C5F02A62C4B59ULL,
			0x71B5E43D8F6C9705ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x85477F8F0CF7FE6AULL,
			0x9A5FE1D4A05BA1A8ULL,
			0x2A8C766CF5B2F26BULL,
			0x5CE4F98E10B6E349ULL}
		},
		.Z = {.key64 = {
			0x60AE3704DCE9C292ULL,
			0xDF4236D6F82B0251ULL,
			0x1A78867CA6EA1E5CULL,
			0x343C4009D4CAE79EULL}
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

	steps = 43;
	X1 = (curve25519_key_t){.key64 = {
		0xF0331C6210E0B500ULL,
		0x3637C18FF235396EULL,
		0x8C8BEDC54711D7B7ULL,
		0x66301052249795B6ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF0331C6210E0B500ULL,
			0x3637C18FF235396EULL,
			0x8C8BEDC54711D7B7ULL,
			0x66301052249795B6ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBBD3296E3FC36CFDULL,
			0xFA28687E7D4E03EFULL,
			0xF856B8A899501929ULL,
			0x3520481CC33E0291ULL}
		},
		.Z = {.key64 = {
			0x0B5275DE0AA17C6DULL,
			0x55443BB1AD2AAFDFULL,
			0xE81779E4CE967639ULL,
			0x2D7F2F62965B1959ULL}
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

	steps = 39;
	X1 = (curve25519_key_t){.key64 = {
		0x97B4E7E58F959CE0ULL,
		0xB3E441449535E363ULL,
		0x70D9251D1CA0334DULL,
		0x5D963EE5C23530EDULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x97B4E7E58F959CE0ULL,
			0xB3E441449535E363ULL,
			0x70D9251D1CA0334DULL,
			0x5D963EE5C23530EDULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5E3306F5BFBCB8A0ULL,
			0xBDA8EF56DB7A1B68ULL,
			0x2B3DC3DCA9C665A9ULL,
			0x5EB9C3C0F314AB15ULL}
		},
		.Z = {.key64 = {
			0xA0D60DE3FB088E4EULL,
			0xC5458FFA37A23064ULL,
			0x9AEF845F2AE3093DULL,
			0x10E39781AC7FD821ULL}
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

	steps = 63;
	X1 = (curve25519_key_t){.key64 = {
		0x0EDE700D93834448ULL,
		0xC3542B998AD85C8BULL,
		0xDE54982C692889D8ULL,
		0x695FBF8AB520DA1EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0EDE700D93834448ULL,
			0xC3542B998AD85C8BULL,
			0xDE54982C692889D8ULL,
			0x695FBF8AB520DA1EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5810E383DBF46483ULL,
			0xF2729C3507755EEAULL,
			0x04AD6F1278EAAC30ULL,
			0x6159C4D6F8E160B1ULL}
		},
		.Z = {.key64 = {
			0x195B86990419CAC0ULL,
			0x898669D0DDF60A80ULL,
			0xA37902584459965DULL,
			0x4284E729FF1E4F68ULL}
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
		0xDCEEB6FDDDCC91F8ULL,
		0xB2425C1C4E293159ULL,
		0x167006E88AD11D42ULL,
		0x7B5B608C71364B70ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDCEEB6FDDDCC91F8ULL,
			0xB2425C1C4E293159ULL,
			0x167006E88AD11D42ULL,
			0x7B5B608C71364B70ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x552C1FEB0E5D315EULL,
			0x508AC0828F5A1449ULL,
			0x1BC82342CB57362DULL,
			0x083ADF2276097485ULL}
		},
		.Z = {.key64 = {
			0x97966549263A5E45ULL,
			0x11E31882E9543FFAULL,
			0x3F5C5AF68EA581C1ULL,
			0x3508640BD9B1ADBDULL}
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

	steps = 31;
	X1 = (curve25519_key_t){.key64 = {
		0xBB91FA8848F16258ULL,
		0x6D49ABA9D9479827ULL,
		0xC4F6EC478B5FFA01ULL,
		0x66A3092667FAD77BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBB91FA8848F16258ULL,
			0x6D49ABA9D9479827ULL,
			0xC4F6EC478B5FFA01ULL,
			0x66A3092667FAD77BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x07A47E7D08BCB056ULL,
			0x90EA16A6FD8954BCULL,
			0x0DDB67ED76914DB2ULL,
			0x701DA97B72487563ULL}
		},
		.Z = {.key64 = {
			0xDA5EB210BC51D9C5ULL,
			0x9EE6ECF187580B31ULL,
			0x77BE71CCA1296752ULL,
			0x44A1D63FCCF6EBE5ULL}
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

	steps = 28;
	X1 = (curve25519_key_t){.key64 = {
		0x5EABB77FCB82F268ULL,
		0xD70E0F9F04F62910ULL,
		0x88AA2A8B870DBF58ULL,
		0x6D4623980F0B9D8FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5EABB77FCB82F268ULL,
			0xD70E0F9F04F62910ULL,
			0x88AA2A8B870DBF58ULL,
			0x6D4623980F0B9D8FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0BED1F0B12C93431ULL,
			0xB1D4041EF1A722B0ULL,
			0x02862F3F9152AAFEULL,
			0x6EA52CB4E1FC3E43ULL}
		},
		.Z = {.key64 = {
			0x5D5E49B3E3DD10E1ULL,
			0x3ABABF5F55A1DE9AULL,
			0xF284D6224EE6C60AULL,
			0x6E18BCB0421A6CA6ULL}
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

	steps = 38;
	X1 = (curve25519_key_t){.key64 = {
		0xADBD4826A3FCB1E0ULL,
		0xDA805BAF36581771ULL,
		0x87E0EE62D06EC646ULL,
		0x42FE5E48CE9D5050ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xADBD4826A3FCB1E0ULL,
			0xDA805BAF36581771ULL,
			0x87E0EE62D06EC646ULL,
			0x42FE5E48CE9D5050ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCD43242302807585ULL,
			0x9EEC54053E0C65E8ULL,
			0x03C9B045DD3A7CCBULL,
			0x4BB0AE300E4B57C9ULL}
		},
		.Z = {.key64 = {
			0x141AA946A18AFC1EULL,
			0xD4D6D069CD424E5DULL,
			0xBA43D8A2CBA237A1ULL,
			0x5034AE161E2456F9ULL}
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

	steps = 27;
	X1 = (curve25519_key_t){.key64 = {
		0xF03B7F45044051C0ULL,
		0x5BE43FC2B9B3F34AULL,
		0x2E90B8A63282872AULL,
		0x69D7106ADFAA6A64ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF03B7F45044051C0ULL,
			0x5BE43FC2B9B3F34AULL,
			0x2E90B8A63282872AULL,
			0x69D7106ADFAA6A64ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA9EDD7F23815E710ULL,
			0x83D7B04C449EE486ULL,
			0x2D9AE48FD563E36CULL,
			0x3080487E4DE2BB80ULL}
		},
		.Z = {.key64 = {
			0x3DB81B7F15B86CE8ULL,
			0x38D7154F3B195A12ULL,
			0x62FAFBC5F2C8080FULL,
			0x73267844B3CE8A98ULL}
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

	steps = 5;
	X1 = (curve25519_key_t){.key64 = {
		0x418EE6BAEA99EBB8ULL,
		0x9645DAC5667C8099ULL,
		0x88A4E584D04857A7ULL,
		0x76D0F716DA2240CCULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x418EE6BAEA99EBB8ULL,
			0x9645DAC5667C8099ULL,
			0x88A4E584D04857A7ULL,
			0x76D0F716DA2240CCULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x004DE4CE6B4E759DULL,
			0xB09729577DD01E5BULL,
			0x61FBBC95582404F0ULL,
			0x54C195DC3EAE7CCFULL}
		},
		.Z = {.key64 = {
			0x72F12D6422073A43ULL,
			0xDDD9038FD620A51EULL,
			0x30CAE13DD1F71E12ULL,
			0x503C9C8398A69BDAULL}
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

	steps = 39;
	X1 = (curve25519_key_t){.key64 = {
		0xF8CB4FD95CF03760ULL,
		0xD0686F357A769236ULL,
		0x9A5EC81B6706C2ADULL,
		0x40474EB90F546163ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF8CB4FD95CF03760ULL,
			0xD0686F357A769236ULL,
			0x9A5EC81B6706C2ADULL,
			0x40474EB90F546163ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF9330C7813FB57AAULL,
			0xF6559935F8A4920EULL,
			0x92703BABA9BEABC1ULL,
			0x035EFB36678783A0ULL}
		},
		.Z = {.key64 = {
			0x2681924783D60620ULL,
			0x1DE555BEB1E755E8ULL,
			0x9A0B2EE4E4113B87ULL,
			0x7D877F0CE35F8BA4ULL}
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

	steps = 3;
	X1 = (curve25519_key_t){.key64 = {
		0xBFB623BCC3DC25C0ULL,
		0x2879575FEECA78C7ULL,
		0x390EEA9E1FE40378ULL,
		0x6E430E5EEE80C171ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBFB623BCC3DC25C0ULL,
			0x2879575FEECA78C7ULL,
			0x390EEA9E1FE40378ULL,
			0x6E430E5EEE80C171ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDC968FE1CB4A23D0ULL,
			0xE6AA73EE4F96B22FULL,
			0x314CFE0BAE8A0EC9ULL,
			0x09035617CE6B88E3ULL}
		},
		.Z = {.key64 = {
			0x597FEC16E0543354ULL,
			0xEF2FFF3BB290F2D7ULL,
			0x4092D67AC777B417ULL,
			0x3E877694E9FC409EULL}
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

	steps = 54;
	X1 = (curve25519_key_t){.key64 = {
		0xDC5686376E3F7558ULL,
		0xFC679AD8D9456C1FULL,
		0x3A179B048B8A24A0ULL,
		0x6163D644D44E281EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDC5686376E3F7558ULL,
			0xFC679AD8D9456C1FULL,
			0x3A179B048B8A24A0ULL,
			0x6163D644D44E281EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x20CA7C4FBA6F7BB6ULL,
			0xF303DF5E0E6B86FEULL,
			0x7AFBCB02B6DAF4C5ULL,
			0x040F00FFF3E4A207ULL}
		},
		.Z = {.key64 = {
			0x1AFBED9342B019C0ULL,
			0x4272ADB12A0B608DULL,
			0x766B116450FDADE9ULL,
			0x1D047C285FD67573ULL}
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

	steps = 29;
	X1 = (curve25519_key_t){.key64 = {
		0x848D6A9BEEEA45E0ULL,
		0x347F95C816706641ULL,
		0x5ED1D40E451F6586ULL,
		0x4BED898D5695A490ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x848D6A9BEEEA45E0ULL,
			0x347F95C816706641ULL,
			0x5ED1D40E451F6586ULL,
			0x4BED898D5695A490ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF7489DCEDC3DEBBAULL,
			0x5AFF39FBCFD9BCDAULL,
			0xA59A251E9F865FC1ULL,
			0x149F06F87E1C5FBCULL}
		},
		.Z = {.key64 = {
			0xBAA86764374E4614ULL,
			0x68C68C064F03334FULL,
			0xF780536E1D58DCBEULL,
			0x17703D6EFBEFBDFDULL}
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

	steps = 31;
	X1 = (curve25519_key_t){.key64 = {
		0xB6B46B106FC20368ULL,
		0x1560CDA47347703CULL,
		0x0F27D14A79606ADFULL,
		0x5324DBF04C5F1058ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB6B46B106FC20368ULL,
			0x1560CDA47347703CULL,
			0x0F27D14A79606ADFULL,
			0x5324DBF04C5F1058ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x725E3D19100D3E30ULL,
			0x9EDF53C42B3732FAULL,
			0xAB9053FA1F78DA31ULL,
			0x591E830E0FB3400FULL}
		},
		.Z = {.key64 = {
			0xCC1E3E62D83AABB3ULL,
			0xE2975A98CFAFE528ULL,
			0x4C8E2DCCE4D110ADULL,
			0x60872FABD161EDD1ULL}
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

	steps = 55;
	X1 = (curve25519_key_t){.key64 = {
		0xD65FCF0A067A6588ULL,
		0x86D2B422BE3E9AF3ULL,
		0xC48152E5486EF3A7ULL,
		0x4FACF4DA2E0B9A0BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD65FCF0A067A6588ULL,
			0x86D2B422BE3E9AF3ULL,
			0xC48152E5486EF3A7ULL,
			0x4FACF4DA2E0B9A0BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDE3A95329293C54DULL,
			0x4B99FE1927DDAF3DULL,
			0x280CC0ABB2D44D0AULL,
			0x6A06D1DB7038DA0BULL}
		},
		.Z = {.key64 = {
			0xE3882A828456979DULL,
			0xCCEB9CA5BA1814C2ULL,
			0x82B77CB776D19164ULL,
			0x5DC488A1E396D1B3ULL}
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

	steps = 63;
	X1 = (curve25519_key_t){.key64 = {
		0x8707C6E2F98FEFE8ULL,
		0x5DC2ADE630F5BCBFULL,
		0x88EE397C766179FCULL,
		0x7B8964B5EBA63F59ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8707C6E2F98FEFE8ULL,
			0x5DC2ADE630F5BCBFULL,
			0x88EE397C766179FCULL,
			0x7B8964B5EBA63F59ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3AA3E3B3A9C23F00ULL,
			0x896D943A0973036EULL,
			0xE2742CF5F75AE942ULL,
			0x539B713BC3FEA6F9ULL}
		},
		.Z = {.key64 = {
			0x3D6A9D4190D6740AULL,
			0x26B81F93DA38569AULL,
			0x6BD0B5CA7797FE33ULL,
			0x72AE45CE8C190D4EULL}
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

	steps = 13;
	X1 = (curve25519_key_t){.key64 = {
		0x8B458CFE53A2D100ULL,
		0x590AA7314A0FAE10ULL,
		0xF488DEFCB9129290ULL,
		0x56A5A9549CF24E09ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8B458CFE53A2D100ULL,
			0x590AA7314A0FAE10ULL,
			0xF488DEFCB9129290ULL,
			0x56A5A9549CF24E09ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3B58D4CC2AE68D10ULL,
			0x27FABBF3DF12F54DULL,
			0xA4186411DDAE3DBCULL,
			0x6B229673329EC432ULL}
		},
		.Z = {.key64 = {
			0x440C5563E0B716F9ULL,
			0x5355070B8F4AB653ULL,
			0x4636E8818EEFFC13ULL,
			0x339B6C025AFBAF06ULL}
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

	steps = 53;
	X1 = (curve25519_key_t){.key64 = {
		0x230191CC7ED4CFD8ULL,
		0xE6543E9FE9C907E4ULL,
		0x2BA7251AC5EA779EULL,
		0x4B76D80E065B28DDULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x230191CC7ED4CFD8ULL,
			0xE6543E9FE9C907E4ULL,
			0x2BA7251AC5EA779EULL,
			0x4B76D80E065B28DDULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x15ABFE38D521ED85ULL,
			0x75992FAE39BAC4AAULL,
			0xD2C1507272B9C65CULL,
			0x2A789421759E56F4ULL}
		},
		.Z = {.key64 = {
			0x383A0AC7D4ECB045ULL,
			0x6D0060D055186D80ULL,
			0x10F722D9F29D6E6FULL,
			0x2C149DB96BAE4FE3ULL}
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

	steps = 52;
	X1 = (curve25519_key_t){.key64 = {
		0x46122AB8B1C276B0ULL,
		0x37FC4E236F36D13AULL,
		0x174135D61CC5F052ULL,
		0x74C2CE58564C2261ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x46122AB8B1C276B0ULL,
			0x37FC4E236F36D13AULL,
			0x174135D61CC5F052ULL,
			0x74C2CE58564C2261ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2B4ED0718C0CA908ULL,
			0x6601061CA19384DAULL,
			0x71B26D010E078683ULL,
			0x7F1EB2F35BC85519ULL}
		},
		.Z = {.key64 = {
			0xC07ECE567A4E4BDBULL,
			0xF2F81046FD1103CCULL,
			0x39BDA61FABCCF964ULL,
			0x22545F3B4671477EULL}
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

	steps = 34;
	X1 = (curve25519_key_t){.key64 = {
		0xA1DD493DDF22F3F0ULL,
		0xC92DD9270012E6BDULL,
		0x190746FF6F5DA4F7ULL,
		0x51F46EA05A7A808CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA1DD493DDF22F3F0ULL,
			0xC92DD9270012E6BDULL,
			0x190746FF6F5DA4F7ULL,
			0x51F46EA05A7A808CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF523845DBBD3DECDULL,
			0x19C5C4AF35C2C4EBULL,
			0x643C50125EE23433ULL,
			0x64CD93CEA50E6471ULL}
		},
		.Z = {.key64 = {
			0xC284A3E0CAB63C8FULL,
			0x9AC2572E5F4504C2ULL,
			0x37034DF79B5D3EFAULL,
			0x2B51048D0B0BC68BULL}
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

	steps = 20;
	X1 = (curve25519_key_t){.key64 = {
		0x427B4142F4A913B8ULL,
		0x0B48063D1B6F4A20ULL,
		0x420A154D9599A9F6ULL,
		0x7FF822EAAE6E2BABULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x427B4142F4A913B8ULL,
			0x0B48063D1B6F4A20ULL,
			0x420A154D9599A9F6ULL,
			0x7FF822EAAE6E2BABULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x07D6FBF844D3748AULL,
			0x054B58B2EA17F229ULL,
			0x232E0FEEEB9E3297ULL,
			0x008476F9A0A861F8ULL}
		},
		.Z = {.key64 = {
			0xD37CB27699CB3113ULL,
			0x3EAD280CB6CCAF63ULL,
			0xAC2710EA9D22F295ULL,
			0x454FDB74BC05B5A5ULL}
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

	steps = 26;
	X1 = (curve25519_key_t){.key64 = {
		0xA11EC81EAF0404E8ULL,
		0x81C5FE9D37437BDFULL,
		0x5CB6E5FD6AB7CA02ULL,
		0x5356A18EFF7D1F0CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA11EC81EAF0404E8ULL,
			0x81C5FE9D37437BDFULL,
			0x5CB6E5FD6AB7CA02ULL,
			0x5356A18EFF7D1F0CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC808FFFDAB61D921ULL,
			0x2716B94515BC4384ULL,
			0x6DAD25E518772FE3ULL,
			0x3A0EB7FDA5B03F86ULL}
		},
		.Z = {.key64 = {
			0x644E089AE662D4FCULL,
			0x87F96AAF8FF41305ULL,
			0x3C0B3819EA45CAF0ULL,
			0x58854EC655CF699DULL}
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

	steps = 1;
	X1 = (curve25519_key_t){.key64 = {
		0x8D0FE46CAAA18380ULL,
		0xE46A85F24FF0A5EDULL,
		0xAA5DC4383241B144ULL,
		0x6E133C80FCE68C06ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8D0FE46CAAA18380ULL,
			0xE46A85F24FF0A5EDULL,
			0xAA5DC4383241B144ULL,
			0x6E133C80FCE68C06ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAA62A81723BBE1A5ULL,
			0xF877C74719FDFAA4ULL,
			0x85F94DF886378E23ULL,
			0x1EB2EE9836723118ULL}
		},
		.Z = {.key64 = {
			0x343F91B2AA860E39ULL,
			0x91AA17C93FC297B6ULL,
			0xA97710E0C906C513ULL,
			0x384CF203F39A301AULL}
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

	steps = 51;
	X1 = (curve25519_key_t){.key64 = {
		0x39AA5C9097EA1548ULL,
		0xB26DC4D43EF39321ULL,
		0x83AE30B8B2F06199ULL,
		0x41900C317C6ACF77ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x39AA5C9097EA1548ULL,
			0xB26DC4D43EF39321ULL,
			0x83AE30B8B2F06199ULL,
			0x41900C317C6ACF77ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0155E3A9B7D8A35EULL,
			0x179B8F8F3791B050ULL,
			0xB8C70B883A3416F3ULL,
			0x0D2FCCC4F69050B1ULL}
		},
		.Z = {.key64 = {
			0x9454988B94CFA794ULL,
			0xF2D5AA32A95898C0ULL,
			0x26D44306B234B6BDULL,
			0x1DC9E5F39DCBC8FBULL}
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

	steps = 27;
	X1 = (curve25519_key_t){.key64 = {
		0x068328FB9D10E528ULL,
		0x9E6876E173ECCFCBULL,
		0x3B1484FA641DFF66ULL,
		0x690CD54049A19C26ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x068328FB9D10E528ULL,
			0x9E6876E173ECCFCBULL,
			0x3B1484FA641DFF66ULL,
			0x690CD54049A19C26ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8A9F7E1AB09C6991ULL,
			0xFB5281EDAA411183ULL,
			0xEE0AB75F6FCAE5D4ULL,
			0x3D08316AE0C65694ULL}
		},
		.Z = {.key64 = {
			0x1638EBC8324D1E19ULL,
			0xCA096486925354EFULL,
			0x4FA0120C12922797ULL,
			0x3286A50BEE4A7021ULL}
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

	steps = 4;
	X1 = (curve25519_key_t){.key64 = {
		0x3B79DB2DE7F3EA18ULL,
		0xABCF728FF2972AFBULL,
		0xC6FB2D3074E2FBE8ULL,
		0x57A92446425C2058ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3B79DB2DE7F3EA18ULL,
			0xABCF728FF2972AFBULL,
			0xC6FB2D3074E2FBE8ULL,
			0x57A92446425C2058ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2C58090C220BB44AULL,
			0xE2B99EDBC1CED1C2ULL,
			0x3C1BED0E31FC3186ULL,
			0x33C6F0EEC9C432D3ULL}
		},
		.Z = {.key64 = {
			0xD98F944A0C1DD879ULL,
			0xF04E3914E6B9CA0BULL,
			0xC1B2FF0F3B17011CULL,
			0x4DA1E01D6DA88F3BULL}
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

	steps = 42;
	X1 = (curve25519_key_t){.key64 = {
		0x9CAF998A2D2EF490ULL,
		0x65A5FC4BA6EFDDF7ULL,
		0xAA0ED785407D35F3ULL,
		0x483AB12C26249346ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9CAF998A2D2EF490ULL,
			0x65A5FC4BA6EFDDF7ULL,
			0xAA0ED785407D35F3ULL,
			0x483AB12C26249346ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0D53F13A970878E8ULL,
			0x917AC6A52AE60721ULL,
			0x5C736DCF6E75A456ULL,
			0x4DC2697F40C33BD7ULL}
		},
		.Z = {.key64 = {
			0x200B9D3C6C5CCE27ULL,
			0xF30AADF97D96655AULL,
			0x9D8351B0B0C91AF0ULL,
			0x4DB63EC12FF643EEULL}
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

	steps = 17;
	X1 = (curve25519_key_t){.key64 = {
		0x8C2CB4016B96C698ULL,
		0x9CE4ACE64C58E641ULL,
		0x44706EE441E85558ULL,
		0x4B86C09A1EF0F083ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8C2CB4016B96C698ULL,
			0x9CE4ACE64C58E641ULL,
			0x44706EE441E85558ULL,
			0x4B86C09A1EF0F083ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1AE89F26ACECCCCBULL,
			0x3F889D904ED2789AULL,
			0x9C9D154EFE85CA6BULL,
			0x78017EDF9B63C9A6ULL}
		},
		.Z = {.key64 = {
			0x8AF2724FB9DA0CBBULL,
			0xE2B9445BB276A9C9ULL,
			0xFBB7ECD86F828971ULL,
			0x6888D213908300DAULL}
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

	steps = 32;
	X1 = (curve25519_key_t){.key64 = {
		0x758A99A8322D2578ULL,
		0x5C06A4DB24B96D7DULL,
		0x31B0D0A138B5D15BULL,
		0x7EAFEADF5ACDC672ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x758A99A8322D2578ULL,
			0x5C06A4DB24B96D7DULL,
			0x31B0D0A138B5D15BULL,
			0x7EAFEADF5ACDC672ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x379B2F7A5FDF3133ULL,
			0xF35AF59F01EA405FULL,
			0xF202DB5F8E0B6C22ULL,
			0x6D772BEA61B31EA8ULL}
		},
		.Z = {.key64 = {
			0x41DDE32572214F3BULL,
			0xDD76A3E655019EFDULL,
			0x27B38388DA680947ULL,
			0x376274B849720401ULL}
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

	steps = 13;
	X1 = (curve25519_key_t){.key64 = {
		0xD429A297EE75D1A0ULL,
		0xB5F3DB65F1605791ULL,
		0xABD72F26025BC197ULL,
		0x6AA3D24D2941EB3AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD429A297EE75D1A0ULL,
			0xB5F3DB65F1605791ULL,
			0xABD72F26025BC197ULL,
			0x6AA3D24D2941EB3AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x647697B7B4B724B9ULL,
			0xA01FEEDCD29A4DD9ULL,
			0x10C3BD29074DDF58ULL,
			0x28EC6D929734C646ULL}
		},
		.Z = {.key64 = {
			0x101EB179A566E429ULL,
			0x6B3D7BECAA11F5A1ULL,
			0x64A0CE8B92B95FA9ULL,
			0x2C77862C2B4C24A3ULL}
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

	steps = 21;
	X1 = (curve25519_key_t){.key64 = {
		0xFF6CBF4F11982960ULL,
		0xC888BB4671C04B47ULL,
		0xFCD46DBEE918FA9CULL,
		0x7A7AAD6582F8B4F2ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFF6CBF4F11982960ULL,
			0xC888BB4671C04B47ULL,
			0xFCD46DBEE918FA9CULL,
			0x7A7AAD6582F8B4F2ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF675D8AE7B629CBDULL,
			0x505F567FB1A7F58BULL,
			0x17EA7CF8C6DFB4AFULL,
			0x346111B6982B65A0ULL}
		},
		.Z = {.key64 = {
			0xD61ACEC2E9FFA5EBULL,
			0x9287D12E9FF44D22ULL,
			0x3B7C0BCEEDFBE701ULL,
			0x1B214CD0DCE2ABD3ULL}
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

	steps = 51;
	X1 = (curve25519_key_t){.key64 = {
		0x8793FC2C04A72718ULL,
		0xDC98856A81403758ULL,
		0x472508E26AF4CE8EULL,
		0x46E2E6784BE36354ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8793FC2C04A72718ULL,
			0xDC98856A81403758ULL,
			0x472508E26AF4CE8EULL,
			0x46E2E6784BE36354ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x65E95EDA69CC9B98ULL,
			0x74D092FD3893BA66ULL,
			0xDDCBABCD56274A34ULL,
			0x1BDA9763D95A8832ULL}
		},
		.Z = {.key64 = {
			0x3A75CD4E097B0F79ULL,
			0x47E977B5B151C772ULL,
			0x74313B8C46F3E60BULL,
			0x110D8B037FF03495ULL}
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

	steps = 60;
	X1 = (curve25519_key_t){.key64 = {
		0xC2794028D0111B80ULL,
		0xCC67021D13E990E9ULL,
		0x1E67DC3DC70A8CEBULL,
		0x4FEBC9F96A366C9BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC2794028D0111B80ULL,
			0xCC67021D13E990E9ULL,
			0x1E67DC3DC70A8CEBULL,
			0x4FEBC9F96A366C9BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD9380A315238DC3CULL,
			0xA07216DB213578B6ULL,
			0xA627FB5FE168EB06ULL,
			0x52996ADBC3D42A94ULL}
		},
		.Z = {.key64 = {
			0x2E016A3EA39E2B94ULL,
			0x8278EDBDEA4231E1ULL,
			0xB36F9FB3B08DD4D1ULL,
			0x035276F9A0302D2EULL}
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

	steps = 63;
	X1 = (curve25519_key_t){.key64 = {
		0x9EB14D20BD9439C8ULL,
		0xAED42E95F9E85848ULL,
		0x7994AC1ED2C2E29FULL,
		0x6DE1D819FEDD2908ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9EB14D20BD9439C8ULL,
			0xAED42E95F9E85848ULL,
			0x7994AC1ED2C2E29FULL,
			0x6DE1D819FEDD2908ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5CBC48FDFF9520EFULL,
			0x30786B354DFECC8DULL,
			0xE2EB356B3DD5A0FCULL,
			0x4CC194F5E96ED631ULL}
		},
		.Z = {.key64 = {
			0x2E25DE10605DBB2AULL,
			0xBBA6241DEAEC7189ULL,
			0xFA2278F0958E90BBULL,
			0x4C6B2CEF11EF75E0ULL}
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

	steps = 22;
	X1 = (curve25519_key_t){.key64 = {
		0x13DD96039239B340ULL,
		0x4C63DB4AC8EA0C1EULL,
		0x7E05D8E109033B33ULL,
		0x5F546948837B53B1ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x13DD96039239B340ULL,
			0x4C63DB4AC8EA0C1EULL,
			0x7E05D8E109033B33ULL,
			0x5F546948837B53B1ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD8277A41C92EBC20ULL,
			0x846D6B54A37347FEULL,
			0xA50CA4784C5192EAULL,
			0x43CABA00B00D60A3ULL}
		},
		.Z = {.key64 = {
			0xF0D8DFBC6AEF5727ULL,
			0x666D803FADF3C613ULL,
			0x4173A69E21A44848ULL,
			0x32E671F801ED9A6AULL}
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

	steps = 30;
	X1 = (curve25519_key_t){.key64 = {
		0x1B1DDB6ED27140D0ULL,
		0x3504D4F33ABAD5EFULL,
		0x20D3105E8A3217F4ULL,
		0x46979C0FC33EFDE7ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1B1DDB6ED27140D0ULL,
			0x3504D4F33ABAD5EFULL,
			0x20D3105E8A3217F4ULL,
			0x46979C0FC33EFDE7ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD658AF50FD9D0771ULL,
			0x6CE92F570C798D26ULL,
			0x5C3F998B7AAD744BULL,
			0x0B72E1B4726A2B66ULL}
		},
		.Z = {.key64 = {
			0x6CD4D0A9EC811760ULL,
			0xD4DA3A2DCFEB3977ULL,
			0x43C222EF647450D1ULL,
			0x1DF5416C5927A123ULL}
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

	steps = 22;
	X1 = (curve25519_key_t){.key64 = {
		0xAC2AD7EBB031E310ULL,
		0xBFD6E6790ACB38F9ULL,
		0x12B039277CAD3FBBULL,
		0x5D38899BF44FC449ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAC2AD7EBB031E310ULL,
			0xBFD6E6790ACB38F9ULL,
			0x12B039277CAD3FBBULL,
			0x5D38899BF44FC449ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9ADBBCFC4A622622ULL,
			0x8E9795C68D035BD7ULL,
			0x6771BA8FA560E531ULL,
			0x3068EB0947C138B9ULL}
		},
		.Z = {.key64 = {
			0x458E52587054EF86ULL,
			0x9CE8CABEBDE4721EULL,
			0xCC80FA7D7D7665F9ULL,
			0x4DB4DD430458C1B4ULL}
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

	steps = 27;
	X1 = (curve25519_key_t){.key64 = {
		0x3F919C66E04BE440ULL,
		0x02B341397C7A7504ULL,
		0x4E4DBF0A25A24787ULL,
		0x79BDE0BC3A5E7FD7ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3F919C66E04BE440ULL,
			0x02B341397C7A7504ULL,
			0x4E4DBF0A25A24787ULL,
			0x79BDE0BC3A5E7FD7ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE810E5C24054A05EULL,
			0x4EE49526C1732597ULL,
			0x0FAF82A4AF89C3AFULL,
			0x439F86F9932882BDULL}
		},
		.Z = {.key64 = {
			0x56B09C9D7FCAB134ULL,
			0x54C61A4DE7309636ULL,
			0xD3F123748816964CULL,
			0x2E0FD238C663CCCEULL}
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

	steps = 17;
	X1 = (curve25519_key_t){.key64 = {
		0x8F8D451065723960ULL,
		0xA700BB181584CAE7ULL,
		0xB80EDAA2E91FEF12ULL,
		0x61C8FD970AED80C8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8F8D451065723960ULL,
			0xA700BB181584CAE7ULL,
			0xB80EDAA2E91FEF12ULL,
			0x61C8FD970AED80C8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x770A3EFB030B1A83ULL,
			0xFBE8334FFC15E24EULL,
			0x2474E3A2640D5709ULL,
			0x7276C89F5C00E548ULL}
		},
		.Z = {.key64 = {
			0x43F08CEC52B65D0CULL,
			0x1A06AE26811E34E6ULL,
			0xBC9F99F4CF211B12ULL,
			0x6C0A8639135D0C84ULL}
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

	steps = 12;
	X1 = (curve25519_key_t){.key64 = {
		0x8403FC59B7469BF0ULL,
		0xC0977DB6952CBB45ULL,
		0xC21E4DED961AC535ULL,
		0x6B0BD41645BAD36AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8403FC59B7469BF0ULL,
			0xC0977DB6952CBB45ULL,
			0xC21E4DED961AC535ULL,
			0x6B0BD41645BAD36AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF8BC75810A4F7A20ULL,
			0x0604907BE6F95114ULL,
			0x31DCCE3CEB7C9D68ULL,
			0x6E57C3EDACC339E6ULL}
		},
		.Z = {.key64 = {
			0x6B36254BF9A67043ULL,
			0x55F0D36375E7BCDFULL,
			0x1368094488E5D378ULL,
			0x6DE5DC3807C66395ULL}
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

	steps = 53;
	X1 = (curve25519_key_t){.key64 = {
		0xC2CFD8BE20C27508ULL,
		0x79D2F84F1AD7CF24ULL,
		0xD691DA3CE5D7489EULL,
		0x7328D69D23593AE4ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC2CFD8BE20C27508ULL,
			0x79D2F84F1AD7CF24ULL,
			0xD691DA3CE5D7489EULL,
			0x7328D69D23593AE4ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x48192E52540A1C60ULL,
			0x9214C82F84AD2AB1ULL,
			0x32BBA53DD759D460ULL,
			0x047C199CD6A758CEULL}
		},
		.Z = {.key64 = {
			0xCF23A1B813E6AAC1ULL,
			0xA523C7CDED5A682EULL,
			0x0A8331631C2E6654ULL,
			0x08FF6962B5801137ULL}
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

	steps = 5;
	X1 = (curve25519_key_t){.key64 = {
		0xBC318D44C2674488ULL,
		0xEA5CC7AD6D47CA16ULL,
		0x24CEF65D39E5CB38ULL,
		0x6025B7DF13E67844ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBC318D44C2674488ULL,
			0xEA5CC7AD6D47CA16ULL,
			0x24CEF65D39E5CB38ULL,
			0x6025B7DF13E67844ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3940D447EF09C761ULL,
			0x6B1D6572CDF4A008ULL,
			0x398613FF7D42A3E8ULL,
			0x231B69B8854774ADULL}
		},
		.Z = {.key64 = {
			0xB3FFEF9D8742C7AEULL,
			0x76D2CE9A4CD8E210ULL,
			0x9ECAB2BD3FFC5F53ULL,
			0x553E284C8EE7CE0EULL}
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

	steps = 34;
	X1 = (curve25519_key_t){.key64 = {
		0xAB7C33070E2EF6B8ULL,
		0x7E8F4595581C1578ULL,
		0x75E59B72F585779EULL,
		0x547DF3A0FCDE6D7BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAB7C33070E2EF6B8ULL,
			0x7E8F4595581C1578ULL,
			0x75E59B72F585779EULL,
			0x547DF3A0FCDE6D7BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDF4E59BF7DB38FBFULL,
			0x9556883E1A0611B5ULL,
			0x94A3D66C15AFE258ULL,
			0x2046C58869189704ULL}
		},
		.Z = {.key64 = {
			0x7BE3BDE98D00C829ULL,
			0xBB635A443AEBF7DDULL,
			0xA65F957EDFE26CF0ULL,
			0x03F21A8D51ECAF9AULL}
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

	steps = 31;
	X1 = (curve25519_key_t){.key64 = {
		0xB1AE8EAD4A7C7D18ULL,
		0x25C861C7567CE290ULL,
		0xA051179E9670F66DULL,
		0x6CBD458994323E76ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB1AE8EAD4A7C7D18ULL,
			0x25C861C7567CE290ULL,
			0xA051179E9670F66DULL,
			0x6CBD458994323E76ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6859EB72B5296356ULL,
			0x01BB8D3CCB97C37AULL,
			0x2BC61599F8F57CE6ULL,
			0x6C164D2D3E9710AFULL}
		},
		.Z = {.key64 = {
			0xFCD7ED0F9DC9496EULL,
			0x2F0A65A55A9D2D30ULL,
			0xFBF4FE082C3D84D7ULL,
			0x1CC9519B462D6FB3ULL}
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

	steps = 30;
	X1 = (curve25519_key_t){.key64 = {
		0x1146A192B0A21F10ULL,
		0x9F88314D525374D2ULL,
		0x9CBE05B0B0D629FEULL,
		0x5FF7CEDF39E52018ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1146A192B0A21F10ULL,
			0x9F88314D525374D2ULL,
			0x9CBE05B0B0D629FEULL,
			0x5FF7CEDF39E52018ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x502CE061B4088DEEULL,
			0xEEAF3325516BF85FULL,
			0x264C358373E519E9ULL,
			0x22BB05F48321F077ULL}
		},
		.Z = {.key64 = {
			0x0F4F402431D6F4D6ULL,
			0xE541F9C733E1777AULL,
			0xFE113CB7432E03E7ULL,
			0x0CC705E2A425018AULL}
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

	steps = 1;
	X1 = (curve25519_key_t){.key64 = {
		0x4855B22A8EC49AD8ULL,
		0x43B28C2E01123FB2ULL,
		0x279D091A85D94ACBULL,
		0x56F47A0D2C3A21F6ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4855B22A8EC49AD8ULL,
			0x43B28C2E01123FB2ULL,
			0x279D091A85D94ACBULL,
			0x56F47A0D2C3A21F6ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1AD65C79CAF38050ULL,
			0xB1B739AEEBA1356DULL,
			0x8094E4DCA83F12A2ULL,
			0x6312A0E2394EEBBDULL}
		},
		.Z = {.key64 = {
			0x2156C8AA3B126B86ULL,
			0x0ECA30B80448FEC9ULL,
			0x9E74246A17652B2DULL,
			0x5BD1E834B0E887D8ULL}
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

	steps = 19;
	X1 = (curve25519_key_t){.key64 = {
		0xF517C439E8B8E390ULL,
		0x659776FF4DA24ECDULL,
		0xC9D113BD79BA4060ULL,
		0x51C7D593165679ABULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF517C439E8B8E390ULL,
			0x659776FF4DA24ECDULL,
			0xC9D113BD79BA4060ULL,
			0x51C7D593165679ABULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x47AA39FCF8EB86A0ULL,
			0xF5F8C5FAD74479EBULL,
			0x8AE023FFA5E16E97ULL,
			0x4D81BDD32D8D6159ULL}
		},
		.Z = {.key64 = {
			0x958AA98FDF0E9CB2ULL,
			0xC7381D29774F4F0EULL,
			0xDFABB66AEF74AFBCULL,
			0x22256C01FD088E28ULL}
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

	steps = 63;
	X1 = (curve25519_key_t){.key64 = {
		0x288E9C435D379FD8ULL,
		0xCE352ABE850949D7ULL,
		0xA6375441C4EC80F0ULL,
		0x50875A1989E5C903ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x288E9C435D379FD8ULL,
			0xCE352ABE850949D7ULL,
			0xA6375441C4EC80F0ULL,
			0x50875A1989E5C903ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x66060FBE14143DE6ULL,
			0xD200A84CDF3ACE93ULL,
			0x83534889EFCF29E2ULL,
			0x5BD0E5548E4A405DULL}
		},
		.Z = {.key64 = {
			0x7B9D70E9A3733B56ULL,
			0x62EEE6E744AD7C06ULL,
			0xF688A25C89F842B7ULL,
			0x2648D3EF3F1A5907ULL}
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

	steps = 13;
	X1 = (curve25519_key_t){.key64 = {
		0xB8C753EDCCEB5538ULL,
		0xCEC44B9DD4F035EEULL,
		0xB9CFF8179963C553ULL,
		0x43907F409392DABAULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB8C753EDCCEB5538ULL,
			0xCEC44B9DD4F035EEULL,
			0xB9CFF8179963C553ULL,
			0x43907F409392DABAULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x656B42AD09BAB935ULL,
			0xE4ABABB459CD1B09ULL,
			0xB76DABB8777FE023ULL,
			0x77FCC9952C9EC927ULL}
		},
		.Z = {.key64 = {
			0x7C96D3682BF5C35DULL,
			0xCE2A3589D28B0FBDULL,
			0x17C880EEB2EC66F4ULL,
			0x1DDA4EF5ECE74B09ULL}
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

	steps = 19;
	X1 = (curve25519_key_t){.key64 = {
		0xC421E0A1E8AA5F50ULL,
		0x285D7137E4B5D40DULL,
		0x071335D1748B4459ULL,
		0x6D8B87B67BA0D634ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC421E0A1E8AA5F50ULL,
			0x285D7137E4B5D40DULL,
			0x071335D1748B4459ULL,
			0x6D8B87B67BA0D634ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC00808D8626AB380ULL,
			0x670C13196BB002A8ULL,
			0xE7C45FD2F1AE3010ULL,
			0x28BB8E1AFEE970DDULL}
		},
		.Z = {.key64 = {
			0x4EB795F9C2EA9C08ULL,
			0xF086758507FFB6B3ULL,
			0xB797A942D3C88F58ULL,
			0x3EA25AE57F166E57ULL}
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

	steps = 13;
	X1 = (curve25519_key_t){.key64 = {
		0x375029663C715028ULL,
		0x4D81727DA767D7C9ULL,
		0x606A1B43D55955F5ULL,
		0x4AF1E0E32F235417ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x375029663C715028ULL,
			0x4D81727DA767D7C9ULL,
			0x606A1B43D55955F5ULL,
			0x4AF1E0E32F235417ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF62F9A4CCBC808B3ULL,
			0x8100A7F2A9F68114ULL,
			0x689318AE864FEDC7ULL,
			0x61210E1AFBEB6BE1ULL}
		},
		.Z = {.key64 = {
			0x3EC980D76B114856ULL,
			0x98A048986589EEDAULL,
			0x3980B82370181345ULL,
			0x7929B75AAAF546D7ULL}
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

	steps = 10;
	X1 = (curve25519_key_t){.key64 = {
		0x394690E979F4FEE0ULL,
		0x63FFB613EB9F8BC4ULL,
		0x4AC54EEAC95B23CDULL,
		0x78B041918E5C18C8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x394690E979F4FEE0ULL,
			0x63FFB613EB9F8BC4ULL,
			0x4AC54EEAC95B23CDULL,
			0x78B041918E5C18C8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6E057FD7D9CAC66EULL,
			0xE240AAAEE571E85FULL,
			0xCD1E5901D1BD2249ULL,
			0x37E250051518A390ULL}
		},
		.Z = {.key64 = {
			0xC7673887E68C3EC4ULL,
			0xD881873FC2F056EFULL,
			0xC6A15984F8D90C10ULL,
			0x71BFB983628BB585ULL}
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

	steps = 10;
	X1 = (curve25519_key_t){.key64 = {
		0x2D8395B1474983E8ULL,
		0x925DB1A79189A054ULL,
		0xE3C0E570347AE839ULL,
		0x43168A9BF4DBB892ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2D8395B1474983E8ULL,
			0x925DB1A79189A054ULL,
			0xE3C0E570347AE839ULL,
			0x43168A9BF4DBB892ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA8B2FE17B3F9D91DULL,
			0xF175BA9D21627C2CULL,
			0x525C74F46626CFE2ULL,
			0x3E1064150574D652ULL}
		},
		.Z = {.key64 = {
			0x26B4F6653630AC90ULL,
			0x28CB5E4B51CED61DULL,
			0xE379AC7FDB452DE9ULL,
			0x0A5B67AD4F96A1E4ULL}
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

	steps = 35;
	X1 = (curve25519_key_t){.key64 = {
		0x3D990990B0F27E88ULL,
		0x91914E5A78817E52ULL,
		0x9F174215694D5DB2ULL,
		0x593429A50DD992C0ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3D990990B0F27E88ULL,
			0x91914E5A78817E52ULL,
			0x9F174215694D5DB2ULL,
			0x593429A50DD992C0ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF9F8C2C94AEA34DCULL,
			0x27DF78EFDADE2139ULL,
			0x1D8F910E8836F15EULL,
			0x0F5E195198A02B1DULL}
		},
		.Z = {.key64 = {
			0xDFD45D6E8114E34EULL,
			0x1745A6ECDD3C6452ULL,
			0x7E6C8973B0D7A580ULL,
			0x09561078610C7380ULL}
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

	steps = 17;
	X1 = (curve25519_key_t){.key64 = {
		0x1E0F1EEA4FD1A110ULL,
		0xE4CF1B6DEE7802D5ULL,
		0x62812BB655415A5DULL,
		0x44654B1498D43E7CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1E0F1EEA4FD1A110ULL,
			0xE4CF1B6DEE7802D5ULL,
			0x62812BB655415A5DULL,
			0x44654B1498D43E7CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x99EF715488F22F25ULL,
			0x0FF9502CDE608B5EULL,
			0x9B770DDB6D391547ULL,
			0x296542E5FD7C9165ULL}
		},
		.Z = {.key64 = {
			0xFF61AD5356FAFE3DULL,
			0x99FA93CC025970BBULL,
			0xBAEF99566A79EE35ULL,
			0x49DC876622566210ULL}
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

	steps = 28;
	X1 = (curve25519_key_t){.key64 = {
		0x54C52C87BF8215F8ULL,
		0xA282D9B2307AD8E1ULL,
		0xA20D4D0D0D1DE149ULL,
		0x5A67B7ED3C56E7E1ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x54C52C87BF8215F8ULL,
			0xA282D9B2307AD8E1ULL,
			0xA20D4D0D0D1DE149ULL,
			0x5A67B7ED3C56E7E1ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB88206C6FFAC5655ULL,
			0xBACD83114B2503B2ULL,
			0xADDB8C6D4BBF45E6ULL,
			0x0FE87A21A3CA3823ULL}
		},
		.Z = {.key64 = {
			0xDAC6E1FC30E7C54DULL,
			0x810496E5CC542807ULL,
			0xD8D17C6D1535AC75ULL,
			0x2A6C0B7E92D366D3ULL}
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

	steps = 56;
	X1 = (curve25519_key_t){.key64 = {
		0xA5FFFC308AE8F4C8ULL,
		0x5F6BEF26FE572000ULL,
		0x2D7661DB9CB29031ULL,
		0x525635C6D3D508C7ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA5FFFC308AE8F4C8ULL,
			0x5F6BEF26FE572000ULL,
			0x2D7661DB9CB29031ULL,
			0x525635C6D3D508C7ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7EE5033922DA7FDBULL,
			0x1CBD71FB46E76761ULL,
			0xDC81C476EC8F6187ULL,
			0x4CF48AD1256B4046ULL}
		},
		.Z = {.key64 = {
			0x8A70306D1060C0CAULL,
			0xCA431FCA41C6DE93ULL,
			0x63E23E1D214F67F3ULL,
			0x60447AF60A32DA3DULL}
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

	steps = 45;
	X1 = (curve25519_key_t){.key64 = {
		0x89CE8287E6CC49F0ULL,
		0x391E7DB0847D864AULL,
		0x532585534D1B4616ULL,
		0x741D32708A6569D1ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x89CE8287E6CC49F0ULL,
			0x391E7DB0847D864AULL,
			0x532585534D1B4616ULL,
			0x741D32708A6569D1ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9B77CF178E52D71BULL,
			0xBC5310F91869FBE7ULL,
			0x788E97F5395BBC18ULL,
			0x500BBA5928954028ULL}
		},
		.Z = {.key64 = {
			0x84B205C051FB3F43ULL,
			0x57038EF5E385832DULL,
			0x10BEADF92BC8EAB6ULL,
			0x79C4CF891143555EULL}
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

	steps = 53;
	X1 = (curve25519_key_t){.key64 = {
		0x9C208C8027C63C40ULL,
		0x53A18D4B029F05A4ULL,
		0xC95741F6FE4D0B65ULL,
		0x40EE82E2F37E2C69ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9C208C8027C63C40ULL,
			0x53A18D4B029F05A4ULL,
			0xC95741F6FE4D0B65ULL,
			0x40EE82E2F37E2C69ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x48DBDDA8DDE840C2ULL,
			0x4B98E540AB2F761EULL,
			0x2B8ED31675D1DCBFULL,
			0x3541C0C8C0A7C558ULL}
		},
		.Z = {.key64 = {
			0xD324E4DDCD257092ULL,
			0x3A3F046B00488089ULL,
			0x1FD906EC6F422C6DULL,
			0x2B0CC2C20F98325FULL}
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

	steps = 15;
	X1 = (curve25519_key_t){.key64 = {
		0x3D62668771E59140ULL,
		0x75157EE6A309F5FDULL,
		0x247902DB6C44FB9DULL,
		0x6CB129C094F545A7ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3D62668771E59140ULL,
			0x75157EE6A309F5FDULL,
			0x247902DB6C44FB9DULL,
			0x6CB129C094F545A7ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF47A82F445BAB222ULL,
			0xEE377D7548CB4ACCULL,
			0xD1754B96CD72CB64ULL,
			0x4BC043D6DAC6972FULL}
		},
		.Z = {.key64 = {
			0x02D69E1235AE32D2ULL,
			0xD6CC226BD5B46650ULL,
			0xE9E1878F0A627C5CULL,
			0x69935A10747A3F94ULL}
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

	steps = 46;
	X1 = (curve25519_key_t){.key64 = {
		0x73CB2D769EFEA3D0ULL,
		0xC9AFDB88D9EA22BAULL,
		0x0C559406F7E95935ULL,
		0x5283B2F2533365FFULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x73CB2D769EFEA3D0ULL,
			0xC9AFDB88D9EA22BAULL,
			0x0C559406F7E95935ULL,
			0x5283B2F2533365FFULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF9A93FFD3D91FB85ULL,
			0x8F9C89C52A955F3CULL,
			0x99BD0042D8D8107DULL,
			0x183FBD29D5E435FEULL}
		},
		.Z = {.key64 = {
			0x32DC765A690EF741ULL,
			0x07D927179E3AF392ULL,
			0x5884ECC3E216D779ULL,
			0x6A55451259CB651EULL}
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
		0x5B50CCFCA1769B08ULL,
		0x7B65DF0E61D61561ULL,
		0x56BB6E19A4AE3604ULL,
		0x60F5994055658510ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5B50CCFCA1769B08ULL,
			0x7B65DF0E61D61561ULL,
			0x56BB6E19A4AE3604ULL,
			0x60F5994055658510ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5B564547C8C44ABDULL,
			0xCF93685206DA862EULL,
			0xFDEF2A9266348DEAULL,
			0x69FE3F975CC87E69ULL}
		},
		.Z = {.key64 = {
			0x3EA157D3D103E315ULL,
			0x74C87051CB0D876EULL,
			0x69128421FF7E4388ULL,
			0x22D32E7E5AC15F11ULL}
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

	steps = 62;
	X1 = (curve25519_key_t){.key64 = {
		0x3FB53386ED0938A0ULL,
		0xEFCEAE8C904D47A4ULL,
		0x246BF45BADA0688FULL,
		0x75B8102AF5D9A4BAULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3FB53386ED0938A0ULL,
			0xEFCEAE8C904D47A4ULL,
			0x246BF45BADA0688FULL,
			0x75B8102AF5D9A4BAULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF341A3F35BB7FC54ULL,
			0xFC13F39F60285233ULL,
			0xB9456D6227F7D557ULL,
			0x1659D3B26B1DE8F3ULL}
		},
		.Z = {.key64 = {
			0xC0BAF96AAD362615ULL,
			0xB9826A5162E405B4ULL,
			0xACE778FA9CEB93D9ULL,
			0x48B74AB079FAD915ULL}
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

	steps = 35;
	X1 = (curve25519_key_t){.key64 = {
		0x0724862BBD5233C0ULL,
		0x1BB1D0FBC4ACD5DBULL,
		0xA9414C7F96936093ULL,
		0x4656E80A6523F14BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0724862BBD5233C0ULL,
			0x1BB1D0FBC4ACD5DBULL,
			0xA9414C7F96936093ULL,
			0x4656E80A6523F14BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x67DD4DB24F52E329ULL,
			0x148C2035DF5A7906ULL,
			0x080B64E9D01527D8ULL,
			0x6EDB5C8C1AA28436ULL}
		},
		.Z = {.key64 = {
			0x309E072BACEE778BULL,
			0xAE59ABA833CBB35BULL,
			0x13FFCD8809FF65A5ULL,
			0x73E15709325F3270ULL}
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

	steps = 16;
	X1 = (curve25519_key_t){.key64 = {
		0x3FFA76A66C20AB20ULL,
		0x17724247BA9DC767ULL,
		0xBBCFE02104983650ULL,
		0x6AE3B41515393787ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3FFA76A66C20AB20ULL,
			0x17724247BA9DC767ULL,
			0xBBCFE02104983650ULL,
			0x6AE3B41515393787ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x25EB3DAE1E0B8BFCULL,
			0x9D9DD0EAC3B609BDULL,
			0xDE2F0A4E97ED3FA2ULL,
			0x0FE305E8E519617AULL}
		},
		.Z = {.key64 = {
			0x894B6DF279FE876FULL,
			0x8F381BA633F7A7E0ULL,
			0x3D76E2C66A3509EAULL,
			0x1EC7192E74FCFF69ULL}
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

	steps = 15;
	X1 = (curve25519_key_t){.key64 = {
		0xD49DF721A0BD0A48ULL,
		0xECF8690C6FF435C2ULL,
		0xF9DE915CEABABC5DULL,
		0x55D4309D40EF5888ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD49DF721A0BD0A48ULL,
			0xECF8690C6FF435C2ULL,
			0xF9DE915CEABABC5DULL,
			0x55D4309D40EF5888ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0B04D0F0458228B4ULL,
			0xDA18A2C4F562DD68ULL,
			0x8129917A02445DD4ULL,
			0x747189F20F618080ULL}
		},
		.Z = {.key64 = {
			0x88E507A29C202408ULL,
			0x19A1A79675062710ULL,
			0xA1BF7BD32CABD403ULL,
			0x27B95B6C3DF3D596ULL}
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

	steps = 18;
	X1 = (curve25519_key_t){.key64 = {
		0xB38A95B8B22BBB08ULL,
		0x037D2A8D7C91C600ULL,
		0x7A69A6DE83E96C6AULL,
		0x5FCDECFC959C0F7EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB38A95B8B22BBB08ULL,
			0x037D2A8D7C91C600ULL,
			0x7A69A6DE83E96C6AULL,
			0x5FCDECFC959C0F7EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5CB9CEE3AF0C4664ULL,
			0xE241E5410FD02A6AULL,
			0xAB99448960F82D7FULL,
			0x1D93B933A64B4EDAULL}
		},
		.Z = {.key64 = {
			0x82EB45F6820321A2ULL,
			0xC2D79CBD7411D639ULL,
			0x72075D170EA150A5ULL,
			0x11DC4D8482EFF343ULL}
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

	steps = 17;
	X1 = (curve25519_key_t){.key64 = {
		0x153553A542FBA5B8ULL,
		0xF91CE3103887AD4DULL,
		0xB62F0B0B67BB3A77ULL,
		0x41D09276AB339F05ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x153553A542FBA5B8ULL,
			0xF91CE3103887AD4DULL,
			0xB62F0B0B67BB3A77ULL,
			0x41D09276AB339F05ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1BCAE89E54CD0C05ULL,
			0x289A1A5F97AC700AULL,
			0x4A55892621BEE172ULL,
			0x3B9DA82318B2920DULL}
		},
		.Z = {.key64 = {
			0x12C5A621F2C700B3ULL,
			0x15FE104CE622653EULL,
			0xE47A34514E8A0F7FULL,
			0x6B1C0823FB49F6FEULL}
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

	steps = 4;
	X1 = (curve25519_key_t){.key64 = {
		0x467642DF7B8DF6A8ULL,
		0x93E2CB2A07846199ULL,
		0x533C39A2F18BBBCDULL,
		0x5A7706B802E7C7C5ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x467642DF7B8DF6A8ULL,
			0x93E2CB2A07846199ULL,
			0x533C39A2F18BBBCDULL,
			0x5A7706B802E7C7C5ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6EBE3C20FCE0B3E4ULL,
			0x2D98000B10611ECEULL,
			0xE85B865DE88AD2B7ULL,
			0x7D9364EDF11B5C94ULL}
		},
		.Z = {.key64 = {
			0x94EB1BDCC242C147ULL,
			0xA51961A2A1A995A4ULL,
			0x8E94C55DCF1D46EDULL,
			0x39EC780691AC3B1FULL}
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

	steps = 16;
	X1 = (curve25519_key_t){.key64 = {
		0x52808365BA965518ULL,
		0x2268B4E964FC8B27ULL,
		0xB4EA5D21830497E5ULL,
		0x70D967D308829EE5ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x52808365BA965518ULL,
			0x2268B4E964FC8B27ULL,
			0xB4EA5D21830497E5ULL,
			0x70D967D308829EE5ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCB555EC8CA81517EULL,
			0xB38AA3877CC87CEFULL,
			0x7C6CE922F29B9F87ULL,
			0x53CAC62CAC7AFFD1ULL}
		},
		.Z = {.key64 = {
			0x9F52B9AD8F9AA2E1ULL,
			0x4B72354DF83479CAULL,
			0xD6E2DC2F079F6D66ULL,
			0x4481F652B88F6D22ULL}
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

	steps = 50;
	X1 = (curve25519_key_t){.key64 = {
		0x51E7F2F5DA7A3B18ULL,
		0x42CC2DCD8CAD1289ULL,
		0x9F79DCFED4BCB72CULL,
		0x70EE14E057A6C499ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x51E7F2F5DA7A3B18ULL,
			0x42CC2DCD8CAD1289ULL,
			0x9F79DCFED4BCB72CULL,
			0x70EE14E057A6C499ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFE76758FABC52867ULL,
			0xC66E7DB638CB1BA7ULL,
			0x8B87BEBB8733ADFEULL,
			0x5989A74CD4B6F498ULL}
		},
		.Z = {.key64 = {
			0xEC31A580DB478A10ULL,
			0x3D62415F82439BFFULL,
			0x8C1A26338759DDB5ULL,
			0x041584A7227B9285ULL}
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

	steps = 54;
	X1 = (curve25519_key_t){.key64 = {
		0xDD713D2AADB22F90ULL,
		0xD454C634B75863C9ULL,
		0xC8AE22C82ABAEDF1ULL,
		0x4B9C9D48AA2AFDFAULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDD713D2AADB22F90ULL,
			0xD454C634B75863C9ULL,
			0xC8AE22C82ABAEDF1ULL,
			0x4B9C9D48AA2AFDFAULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAF2AF8EE0567FAE0ULL,
			0xBDB651AA0A530E40ULL,
			0x71E5C8061C90C069ULL,
			0x5F5871EE6F5E6A15ULL}
		},
		.Z = {.key64 = {
			0xFC108958B62C8D38ULL,
			0x9141BD0F76EE6963ULL,
			0x50B8B344E2C68E9DULL,
			0x27F65DC7EF29CA37ULL}
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

	steps = 63;
	X1 = (curve25519_key_t){.key64 = {
		0x6B958723DB9EC530ULL,
		0x160BB37419E3E432ULL,
		0xF7AE4EF7588EBF32ULL,
		0x5E0BEDFE53A3123DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6B958723DB9EC530ULL,
			0x160BB37419E3E432ULL,
			0xF7AE4EF7588EBF32ULL,
			0x5E0BEDFE53A3123DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC64D60E3296CC55CULL,
			0xC2C00C9583E0EB21ULL,
			0x86ED96DDE5DCE7FEULL,
			0x14CFAFA3A411269FULL}
		},
		.Z = {.key64 = {
			0x7508E3050B9281EAULL,
			0x4419194F62FF1FCAULL,
			0xB8915FCCA56824C4ULL,
			0x7FE9C65E868D14E6ULL}
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

	steps = 28;
	X1 = (curve25519_key_t){.key64 = {
		0x508A86652FA025D8ULL,
		0xA2C259E01B8CB8C3ULL,
		0x02FAD6099317FFE7ULL,
		0x6D0FAC0317537C42ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x508A86652FA025D8ULL,
			0xA2C259E01B8CB8C3ULL,
			0x02FAD6099317FFE7ULL,
			0x6D0FAC0317537C42ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD5EAD5BB1A2734A6ULL,
			0x242236020643B5E2ULL,
			0xD793BF802E3021F5ULL,
			0x49DB36757E184366ULL}
		},
		.Z = {.key64 = {
			0x1E7CFEF0715FABE4ULL,
			0x4FE8AD301094D29AULL,
			0x043471BBDCD2BE83ULL,
			0x49995686DF085818ULL}
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

	steps = 46;
	X1 = (curve25519_key_t){.key64 = {
		0x791ED895645EBC50ULL,
		0x829DA79996DF1EC2ULL,
		0x8D062C18A068ACC0ULL,
		0x7A7B12F01F1070B3ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x791ED895645EBC50ULL,
			0x829DA79996DF1EC2ULL,
			0x8D062C18A068ACC0ULL,
			0x7A7B12F01F1070B3ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0ED8E8296303EC00ULL,
			0xBDB1BD48E7894714ULL,
			0x443940EAD50E6E76ULL,
			0x3D49DC78B1285DE0ULL}
		},
		.Z = {.key64 = {
			0x7489E116449ECE1DULL,
			0x9A8A87FFE67A55DDULL,
			0x08EB7D1842AD2515ULL,
			0x17FFEB1D01F80478ULL}
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

	steps = 46;
	X1 = (curve25519_key_t){.key64 = {
		0x55514AFC7CD60080ULL,
		0x881EBBAD73C62B7FULL,
		0x720A79A8B2B4BC5CULL,
		0x6969C5073268EFCFULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x55514AFC7CD60080ULL,
			0x881EBBAD73C62B7FULL,
			0x720A79A8B2B4BC5CULL,
			0x6969C5073268EFCFULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB17EBA908100965CULL,
			0x71E9F8AB57BF2446ULL,
			0x44233303D199DE39ULL,
			0x458EEEF27229061AULL}
		},
		.Z = {.key64 = {
			0x9FE1B20ABFBD9D86ULL,
			0x0E31D4B57DEBD151ULL,
			0x2EC65F9651324271ULL,
			0x48C50883FF5918A5ULL}
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

	steps = 28;
	X1 = (curve25519_key_t){.key64 = {
		0xD3AD13990FB5E488ULL,
		0xED591C12E486C4CAULL,
		0x9A51490E6A7A0C78ULL,
		0x762F88D565C104A4ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD3AD13990FB5E488ULL,
			0xED591C12E486C4CAULL,
			0x9A51490E6A7A0C78ULL,
			0x762F88D565C104A4ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x03856E38F502EB0EULL,
			0xE4B4E38687B27B06ULL,
			0x8673960B273C75C4ULL,
			0x43FFA8081B768DCAULL}
		},
		.Z = {.key64 = {
			0x8752AA87D9172113ULL,
			0x45310D2666E956F7ULL,
			0xAAA3FC32EC2DC7CFULL,
			0x418400EDAB95B45CULL}
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

	steps = 64;
	X1 = (curve25519_key_t){.key64 = {
		0x09BFBD05A08CE3F8ULL,
		0x318FB87372353447ULL,
		0x1A972531B55A8518ULL,
		0x6759DFD3F8EBCD1FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x09BFBD05A08CE3F8ULL,
			0x318FB87372353447ULL,
			0x1A972531B55A8518ULL,
			0x6759DFD3F8EBCD1FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC1508424AC4A0D6AULL,
			0xA65023BD9E38A8E5ULL,
			0x92C98923D127B04CULL,
			0x5E7203BD18B4301EULL}
		},
		.Z = {.key64 = {
			0x08050C7358858DE1ULL,
			0xF53B5915115B1CA3ULL,
			0x24A6DC3EC66FD0F7ULL,
			0x2B02E44E5345C87DULL}
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

	steps = 27;
	X1 = (curve25519_key_t){.key64 = {
		0x3240BDA27DFBC5C0ULL,
		0x51290106D6172BEBULL,
		0xA4F902A86B85A5E3ULL,
		0x47C63D072F741BE8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3240BDA27DFBC5C0ULL,
			0x51290106D6172BEBULL,
			0xA4F902A86B85A5E3ULL,
			0x47C63D072F741BE8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x34BA9191791F0F97ULL,
			0x1B38D21913C6E94BULL,
			0x4022D57DBE1D1C67ULL,
			0x0A1D8461113403CCULL}
		},
		.Z = {.key64 = {
			0x6DB9323789991914ULL,
			0x59E8CC41B15EA392ULL,
			0xB31AA056A41EC5E3ULL,
			0x1F171DFECD1A9183ULL}
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
		0xDF07591F48DB6D68ULL,
		0xBDA592D8FAD4B1CBULL,
		0x55B0B0573E54E77DULL,
		0x57002B53F3932B48ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDF07591F48DB6D68ULL,
			0xBDA592D8FAD4B1CBULL,
			0x55B0B0573E54E77DULL,
			0x57002B53F3932B48ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0C9768ED2B87CB8CULL,
			0x6180556BA3E81B24ULL,
			0x0FE165168A040B9AULL,
			0x7235C8A92B50C325ULL}
		},
		.Z = {.key64 = {
			0x158182A374F0544AULL,
			0x7761E28EA41D2C28ULL,
			0x83272BD92E54AF82ULL,
			0x616A76A8DF9A694FULL}
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

	steps = 9;
	X1 = (curve25519_key_t){.key64 = {
		0xD2F14966ECBF9208ULL,
		0x9AA113CC9844AE41ULL,
		0x9119253347510253ULL,
		0x7F1C13A622C931E7ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD2F14966ECBF9208ULL,
			0x9AA113CC9844AE41ULL,
			0x9119253347510253ULL,
			0x7F1C13A622C931E7ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x87837991E3F90C0AULL,
			0x316A6247A77A58D7ULL,
			0x7B2DCA875725FA49ULL,
			0x1BD24BE52F8F23FEULL}
		},
		.Z = {.key64 = {
			0xBCD866169B2A4E43ULL,
			0xE02090A53E1EEB40ULL,
			0x5FF792BFE52A3C50ULL,
			0x2A69DCC16DAE997DULL}
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

	steps = 47;
	X1 = (curve25519_key_t){.key64 = {
		0x3B43C3FABD308100ULL,
		0xFF9EA6E324B8155AULL,
		0x5C7C84D8EE841CECULL,
		0x678A93086B98E4F5ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3B43C3FABD308100ULL,
			0xFF9EA6E324B8155AULL,
			0x5C7C84D8EE841CECULL,
			0x678A93086B98E4F5ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x61C7F0CA893E909FULL,
			0x8BA44B6AEC97A24CULL,
			0x6C41957F33A6B5AAULL,
			0x1A6AEE67B2DB8DB0ULL}
		},
		.Z = {.key64 = {
			0xE4BE13E737E31EE1ULL,
			0x7490D216D1A41AE1ULL,
			0xED60FA9B67356691ULL,
			0x3749D8E81B1C802FULL}
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

	steps = 7;
	X1 = (curve25519_key_t){.key64 = {
		0xA7EB6F513F580550ULL,
		0x25D996E6B9347882ULL,
		0x9D71D0560F4B71E8ULL,
		0x5CB778491E484DE8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA7EB6F513F580550ULL,
			0x25D996E6B9347882ULL,
			0x9D71D0560F4B71E8ULL,
			0x5CB778491E484DE8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF32671D2ECA76FD3ULL,
			0x1C15F44A6D41CC13ULL,
			0xBB4BEE83A02D71E1ULL,
			0x62379B5909BD4EA0ULL}
		},
		.Z = {.key64 = {
			0x5344851AECC2F7CDULL,
			0x6D5E266C8442CDBDULL,
			0x884E960EABE1892EULL,
			0x7FDF36EA2F8A0616ULL}
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

	steps = 21;
	X1 = (curve25519_key_t){.key64 = {
		0x004E53110D99ECE0ULL,
		0x65A8C718173F31C2ULL,
		0x8CE1B0433E0F566EULL,
		0x658E96B1CC6FF66EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x004E53110D99ECE0ULL,
			0x65A8C718173F31C2ULL,
			0x8CE1B0433E0F566EULL,
			0x658E96B1CC6FF66EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3E09268BD5964657ULL,
			0x9933D7B646DC7135ULL,
			0xBA0AAC2DFD52E56CULL,
			0x03504EDA4D321E09ULL}
		},
		.Z = {.key64 = {
			0x8DB7DC6E15796595ULL,
			0xAF7DBFF339855F81ULL,
			0x4AA40313E513C9D6ULL,
			0x37041DD349C15684ULL}
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

	steps = 41;
	X1 = (curve25519_key_t){.key64 = {
		0xF3D29890397FE198ULL,
		0x9A1AA88CFD7A7454ULL,
		0xB613BEF246D3F0C4ULL,
		0x604AC105117F54B5ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF3D29890397FE198ULL,
			0x9A1AA88CFD7A7454ULL,
			0xB613BEF246D3F0C4ULL,
			0x604AC105117F54B5ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAAC4BA27BDB1BEE1ULL,
			0x23AC32ED0BE3E6A0ULL,
			0x0E7FF98DA53289DFULL,
			0x10E641A84B165E9AULL}
		},
		.Z = {.key64 = {
			0x3B3FC2E684D2E8E4ULL,
			0xF3C3F7A27EF54F4FULL,
			0x69FE5315701BA299ULL,
			0x7F4CB6AE3EAE6135ULL}
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

	steps = 31;
	X1 = (curve25519_key_t){.key64 = {
		0xA917BDD88EF30C08ULL,
		0x3A587B206A8FADCEULL,
		0xD00ADE359CBC1B86ULL,
		0x62C38B526798E93CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA917BDD88EF30C08ULL,
			0x3A587B206A8FADCEULL,
			0xD00ADE359CBC1B86ULL,
			0x62C38B526798E93CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF2CFD396B76FF2CBULL,
			0x96EAF1CD4B65B159ULL,
			0x7F19EEA0DD209A92ULL,
			0x02EBF867D4CAD69AULL}
		},
		.Z = {.key64 = {
			0x33A9ED43CC49B300ULL,
			0xB818526F1C01ED23ULL,
			0x122021F8ACCC1E4DULL,
			0x5204BD8EC2AD0392ULL}
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

	steps = 37;
	X1 = (curve25519_key_t){.key64 = {
		0x0BE76F1C75362450ULL,
		0x406DA3A1121DC8A1ULL,
		0x044F1C0AEB0A1E86ULL,
		0x6DA5D7DD7259490FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0BE76F1C75362450ULL,
			0x406DA3A1121DC8A1ULL,
			0x044F1C0AEB0A1E86ULL,
			0x6DA5D7DD7259490FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x377CF3F1E8BA256DULL,
			0xDEB1E21974F9DC2AULL,
			0xFF88718FD168A6D4ULL,
			0x0D149CDC1D40AECFULL}
		},
		.Z = {.key64 = {
			0x10547E9E2C4E4F9CULL,
			0x1C5AC3996DF5F0A9ULL,
			0x9D31743B9FDEB68FULL,
			0x5E7118C01939094AULL}
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

	steps = 11;
	X1 = (curve25519_key_t){.key64 = {
		0x1CE5BA845DAF9EE0ULL,
		0x186D59B24ACB4B10ULL,
		0x9FDD027F6DE3D644ULL,
		0x6A8BB95CC8017C65ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1CE5BA845DAF9EE0ULL,
			0x186D59B24ACB4B10ULL,
			0x9FDD027F6DE3D644ULL,
			0x6A8BB95CC8017C65ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xABC8FB11E57D796EULL,
			0x2EEE23FABDCCD737ULL,
			0x59BB57F22CEA6E56ULL,
			0x3DD1F8BBF41AABC0ULL}
		},
		.Z = {.key64 = {
			0x65B4E28CD130D6FCULL,
			0xEF55036F81C1DD09ULL,
			0x0FCAEF6796EA7EE9ULL,
			0x3FCC950D7E11CC42ULL}
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

	steps = 32;
	X1 = (curve25519_key_t){.key64 = {
		0x1A72B60C0FEAA288ULL,
		0x864FE0087488FE2EULL,
		0x9B37B29064C7CC94ULL,
		0x7E75F9F711AE3D1CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1A72B60C0FEAA288ULL,
			0x864FE0087488FE2EULL,
			0x9B37B29064C7CC94ULL,
			0x7E75F9F711AE3D1CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x565E1A1FDD12F772ULL,
			0x2BB4AA3E586B72DBULL,
			0x30D1CA46CE3545DDULL,
			0x472B40880CF72CB0ULL}
		},
		.Z = {.key64 = {
			0xD60EDB9F90E84EDAULL,
			0x5A204081F5153069ULL,
			0xA520655419BE6F81ULL,
			0x45C1160764F02B84ULL}
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

	steps = 64;
	X1 = (curve25519_key_t){.key64 = {
		0x586983C32DA4BDE8ULL,
		0xB13B4F7B1ED38081ULL,
		0x548AB3F8477AD07AULL,
		0x5D693452C8A70383ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x586983C32DA4BDE8ULL,
			0xB13B4F7B1ED38081ULL,
			0x548AB3F8477AD07AULL,
			0x5D693452C8A70383ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x28E87580C35C3882ULL,
			0xC1C3A58E1D99370EULL,
			0xC41F11CB0D647458ULL,
			0x1D11731B50A57B31ULL}
		},
		.Z = {.key64 = {
			0x45B7374A4C9CC381ULL,
			0x840322A78B5F1937ULL,
			0x03C70F01666C6E96ULL,
			0x36E70C39B1EA28D0ULL}
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

	steps = 60;
	X1 = (curve25519_key_t){.key64 = {
		0x0869F02BC2416D18ULL,
		0x84ACD9FF368973EEULL,
		0xF0007AC742B2AAC5ULL,
		0x539D7F0502B41C99ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0869F02BC2416D18ULL,
			0x84ACD9FF368973EEULL,
			0xF0007AC742B2AAC5ULL,
			0x539D7F0502B41C99ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x881E39FEB7A89298ULL,
			0x5E8520517E404119ULL,
			0x70097C13052189F0ULL,
			0x73BEF71F782D5273ULL}
		},
		.Z = {.key64 = {
			0x561816AAF13287A9ULL,
			0xDBFF6CCB0825F8FCULL,
			0x7D447C37BF350844ULL,
			0x46EDA19D49659BB1ULL}
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

	steps = 62;
	X1 = (curve25519_key_t){.key64 = {
		0x14378A7F148425F8ULL,
		0x4302AB2CBAF6D0E5ULL,
		0x9F3620C76236B3EBULL,
		0x7F62951E3BB64B50ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x14378A7F148425F8ULL,
			0x4302AB2CBAF6D0E5ULL,
			0x9F3620C76236B3EBULL,
			0x7F62951E3BB64B50ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x862FB7E6DF828E9BULL,
			0x7E8B4E01C34105D5ULL,
			0x2444A6866603C7CEULL,
			0x705FBCE5BF0BEAD5ULL}
		},
		.Z = {.key64 = {
			0x01F4B758BB45B240ULL,
			0xC2D8126001E9148DULL,
			0xFA166AE27848B5CCULL,
			0x3C4F0AA65687F158ULL}
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

	steps = 3;
	X1 = (curve25519_key_t){.key64 = {
		0x2033D1B450A6C378ULL,
		0xB614339F1B852BACULL,
		0x4379020641D558FCULL,
		0x4E4BC9CA22F0B7AFULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2033D1B450A6C378ULL,
			0xB614339F1B852BACULL,
			0x4379020641D558FCULL,
			0x4E4BC9CA22F0B7AFULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA5D0EC942EDD1661ULL,
			0xBD443E54184277F2ULL,
			0x901FB8566C0BD5A3ULL,
			0x543EB2F1EF4240F0ULL}
		},
		.Z = {.key64 = {
			0xD4567C72589DC918ULL,
			0x48EA1CF8F233461CULL,
			0x046CFDB662D0FD66ULL,
			0x65454035CEF5E6D2ULL}
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
		0x8610DF7706D070F8ULL,
		0x0F42A307E0D150FEULL,
		0x81939CBEBF55D68CULL,
		0x79B34B2306317F43ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8610DF7706D070F8ULL,
			0x0F42A307E0D150FEULL,
			0x81939CBEBF55D68CULL,
			0x79B34B2306317F43ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA2D30DB55206897DULL,
			0xA9E644E74AD77246ULL,
			0xA79B120A1BF86292ULL,
			0x4B1972396BB767D3ULL}
		},
		.Z = {.key64 = {
			0xB79B86AC54902009ULL,
			0xAF5EE0351A513B81ULL,
			0x471B3E4806E54D03ULL,
			0x55B306C6CE335A3AULL}
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

	steps = 59;
	X1 = (curve25519_key_t){.key64 = {
		0xC5DF9E0E9D6B4AB0ULL,
		0x6CEA281FBEB87994ULL,
		0x39E9613CD3C47A88ULL,
		0x7A338E6D3A3D5464ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC5DF9E0E9D6B4AB0ULL,
			0x6CEA281FBEB87994ULL,
			0x39E9613CD3C47A88ULL,
			0x7A338E6D3A3D5464ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1A855A30BF22F527ULL,
			0xBFD7D5D1C358B903ULL,
			0xABE97FC40C40797FULL,
			0x3B84771145F863D8ULL}
		},
		.Z = {.key64 = {
			0xE5DCAE138BDFED94ULL,
			0x3CA4E501546FC01AULL,
			0xACEC325D39CC7502ULL,
			0x76B59340417A73EBULL}
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

	steps = 13;
	X1 = (curve25519_key_t){.key64 = {
		0x9F3CA7EDBACEC030ULL,
		0xDF607A4F19A1FEE2ULL,
		0xC4050597832B2E97ULL,
		0x6CDBB14648EEB047ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9F3CA7EDBACEC030ULL,
			0xDF607A4F19A1FEE2ULL,
			0xC4050597832B2E97ULL,
			0x6CDBB14648EEB047ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x88006B3CCC820686ULL,
			0xB1955BF27CBF4DE4ULL,
			0x937F5082CB512BDAULL,
			0x1B9209145C83F64BULL}
		},
		.Z = {.key64 = {
			0xF5976538EEBAABABULL,
			0x8A274DE55C0595EEULL,
			0x378A779D53065731ULL,
			0x33451D38E77D210FULL}
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

	steps = 17;
	X1 = (curve25519_key_t){.key64 = {
		0xCA4A0115857100A0ULL,
		0x076684B857367E5BULL,
		0x5477969C4B8BF284ULL,
		0x466A46E5BF38B55DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCA4A0115857100A0ULL,
			0x076684B857367E5BULL,
			0x5477969C4B8BF284ULL,
			0x466A46E5BF38B55DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0814D2F9780BD1C8ULL,
			0x488357F5E04F5E13ULL,
			0xB8E3367C8962B868ULL,
			0x238B29ADF4F62228ULL}
		},
		.Z = {.key64 = {
			0xCC9C6F67D43E6591ULL,
			0x39CB5EE13C84F4AAULL,
			0x416A81F57E174A22ULL,
			0x1647683800B4C673ULL}
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

	steps = 45;
	X1 = (curve25519_key_t){.key64 = {
		0x7B18D51AC2E0E078ULL,
		0xA452167E65CA7E35ULL,
		0xAD8D661A6B72D5F2ULL,
		0x7339EA6433DBAE51ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7B18D51AC2E0E078ULL,
			0xA452167E65CA7E35ULL,
			0xAD8D661A6B72D5F2ULL,
			0x7339EA6433DBAE51ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x778304571F7CC666ULL,
			0xD69206FFB2E8515BULL,
			0x0E9BC807E27602C8ULL,
			0x5DD247DFD6B3E0F6ULL}
		},
		.Z = {.key64 = {
			0x7C5EA420D16F8A3AULL,
			0xA8D0A3DDD0B4EF0EULL,
			0x8D3E53331F5188B2ULL,
			0x25A68424AA82DB89ULL}
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

	steps = 61;
	X1 = (curve25519_key_t){.key64 = {
		0x955B54646D9D4490ULL,
		0xDC065C2D44B51C32ULL,
		0x97945E40EE9BE0D9ULL,
		0x74AE5400FDD197EEULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x955B54646D9D4490ULL,
			0xDC065C2D44B51C32ULL,
			0x97945E40EE9BE0D9ULL,
			0x74AE5400FDD197EEULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xABF15A6A75E98686ULL,
			0x504DC038902DC369ULL,
			0x469BF4A5AEC90E97ULL,
			0x69EE4A8ED38DFE55ULL}
		},
		.Z = {.key64 = {
			0xA474BD40C1277E88ULL,
			0x4F84F36F7DF30794ULL,
			0xA27315631E9ED661ULL,
			0x0D6C43577744EF16ULL}
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

	steps = 17;
	X1 = (curve25519_key_t){.key64 = {
		0xB7AB932164F4B530ULL,
		0x872405AE335DE42EULL,
		0xA6D343901EF2C50BULL,
		0x762458CB3DED173FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB7AB932164F4B530ULL,
			0x872405AE335DE42EULL,
			0xA6D343901EF2C50BULL,
			0x762458CB3DED173FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x26D81B6FBCDB81BEULL,
			0x3E1CF058FEEB82A8ULL,
			0x82E927022B2BB6DCULL,
			0x2863AF571BF01A9CULL}
		},
		.Z = {.key64 = {
			0xF4692B0CD908C413ULL,
			0x6001E6983243B5D3ULL,
			0x3D27CD7940FA2CC1ULL,
			0x40E9C56B08848C8DULL}
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

	steps = 64;
	X1 = (curve25519_key_t){.key64 = {
		0x52BE596BC364B540ULL,
		0x92CB059B3C2AC760ULL,
		0x1D41605F257942B2ULL,
		0x596C8A37FC437E81ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x52BE596BC364B540ULL,
			0x92CB059B3C2AC760ULL,
			0x1D41605F257942B2ULL,
			0x596C8A37FC437E81ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x064823E37957BC33ULL,
			0xCACD5F9C303D0A8CULL,
			0x1B0AC9717F36B73BULL,
			0x5A5820AEE532114AULL}
		},
		.Z = {.key64 = {
			0xA4C5D3384C9323E9ULL,
			0x2E3E9418F79D06C2ULL,
			0x37776B9F3DAEF63BULL,
			0x0C8E91EEFF2C337AULL}
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

	steps = 53;
	X1 = (curve25519_key_t){.key64 = {
		0xD54454645F8600C0ULL,
		0x5DC4F67E78E37C1DULL,
		0x59EFBB5EE1B9FA05ULL,
		0x7C8ED28EB6407D98ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD54454645F8600C0ULL,
			0x5DC4F67E78E37C1DULL,
			0x59EFBB5EE1B9FA05ULL,
			0x7C8ED28EB6407D98ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2807049B68E3DA48ULL,
			0xE5C2A70F5FEF060BULL,
			0xDD8831807456ED58ULL,
			0x367E4481CDA737CAULL}
		},
		.Z = {.key64 = {
			0x2C2252000AC8A501ULL,
			0xEF57487B47592DDAULL,
			0xBCAE986737BDF75FULL,
			0x7580E352B072402DULL}
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
		0xC30BF3C38208F370ULL,
		0x8C1FAB5828070445ULL,
		0x725C50CDE55CACBBULL,
		0x6787B378ED950F6CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC30BF3C38208F370ULL,
			0x8C1FAB5828070445ULL,
			0x725C50CDE55CACBBULL,
			0x6787B378ED950F6CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA5F1123067C89A8AULL,
			0xAE36BF53858AC348ULL,
			0x98B6D71B3CF6FCF6ULL,
			0x7A62EB76180891C3ULL}
		},
		.Z = {.key64 = {
			0x3BA156029C0B811EULL,
			0x07792BADB60F28DAULL,
			0xBFD1EAF2A564D521ULL,
			0x4D82CA056A677133ULL}
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

	steps = 6;
	X1 = (curve25519_key_t){.key64 = {
		0xEEB6B0D58D6E6A20ULL,
		0xA20047EB02933FFDULL,
		0x38E0205122095CCBULL,
		0x5F1016BE4E441875ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEEB6B0D58D6E6A20ULL,
			0xA20047EB02933FFDULL,
			0x38E0205122095CCBULL,
			0x5F1016BE4E441875ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1D2F2A71689A5F13ULL,
			0xFDFFFE415A06075CULL,
			0x7A7D33DF364878C3ULL,
			0x7DB0DC68F7E69C09ULL}
		},
		.Z = {.key64 = {
			0x48C2E38D1E480730ULL,
			0x26393B47B65AA33BULL,
			0xCEC848DA531E43A3ULL,
			0x19EE0ECDEE175476ULL}
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

	steps = 9;
	X1 = (curve25519_key_t){.key64 = {
		0x6B94F9A069D54608ULL,
		0x3B4FA9F258C7BCE2ULL,
		0xAC330811DB27D954ULL,
		0x65C9B88D28F3F85AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6B94F9A069D54608ULL,
			0x3B4FA9F258C7BCE2ULL,
			0xAC330811DB27D954ULL,
			0x65C9B88D28F3F85AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5262BF9381E6DAEAULL,
			0x00D18CB17D6F8E09ULL,
			0xE98B2C182868AAA9ULL,
			0x1FEEFE46C9FECDCFULL}
		},
		.Z = {.key64 = {
			0x76DF57ED43EC451AULL,
			0x3852100F0312A627ULL,
			0xC747B071D573CC54ULL,
			0x73948CA54E332DF4ULL}
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
		0xE99BF1E9B2B44500ULL,
		0x5349D427AECAB385ULL,
		0x963D116699AB55A4ULL,
		0x4B96CEA280237CF3ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE99BF1E9B2B44500ULL,
			0x5349D427AECAB385ULL,
			0x963D116699AB55A4ULL,
			0x4B96CEA280237CF3ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7EDB6519103A9D35ULL,
			0xE3AA7429077BB7B6ULL,
			0x4958FAE849DE03CBULL,
			0x0E667E89F24EB480ULL}
		},
		.Z = {.key64 = {
			0xA95CE8C00590343FULL,
			0xC4B3C7C669AF4121ULL,
			0x607388AE00363917ULL,
			0x4F3CFEA0184AEEE1ULL}
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

	steps = 24;
	X1 = (curve25519_key_t){.key64 = {
		0xEE3564AE41B4EC00ULL,
		0x2337637E2948D885ULL,
		0xF95E2535CFEF014CULL,
		0x55270351D7481B4DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEE3564AE41B4EC00ULL,
			0x2337637E2948D885ULL,
			0xF95E2535CFEF014CULL,
			0x55270351D7481B4DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2CA3278A8DA9702AULL,
			0x0FDB8239A6402565ULL,
			0xBEAC4C428457037AULL,
			0x7DD2DA8ACBE25130ULL}
		},
		.Z = {.key64 = {
			0x27C6D498D180E643ULL,
			0xE5339000D1C7FB82ULL,
			0xA9690946AA53A443ULL,
			0x103F3A157CA7F62AULL}
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

	steps = 24;
	X1 = (curve25519_key_t){.key64 = {
		0x602C5FDEB862E560ULL,
		0xF82D3A65ABFAB95BULL,
		0x8607A9E866005FD1ULL,
		0x6A018E562BCA5420ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x602C5FDEB862E560ULL,
			0xF82D3A65ABFAB95BULL,
			0x8607A9E866005FD1ULL,
			0x6A018E562BCA5420ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE473BC51EE7EA100ULL,
			0x33D119353DD209CBULL,
			0x8F31DFC768596833ULL,
			0x0C9759A3D7EFEBCCULL}
		},
		.Z = {.key64 = {
			0x7C1CE2810B5A1B0EULL,
			0xC2617D3CD2B1ED27ULL,
			0x57E5EF495AAD0E76ULL,
			0x61651514C7929FD7ULL}
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

	steps = 10;
	X1 = (curve25519_key_t){.key64 = {
		0x98FD91B5F9077060ULL,
		0x4247DC6B92CAB1D2ULL,
		0xD6FFA320B3CEEBBEULL,
		0x60C0A6671962C80CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x98FD91B5F9077060ULL,
			0x4247DC6B92CAB1D2ULL,
			0xD6FFA320B3CEEBBEULL,
			0x60C0A6671962C80CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7EFA1D83B337FD83ULL,
			0x6CD4D149734BF538ULL,
			0x878AA977B0468D6FULL,
			0x3E93F1C0C8C0DAA9ULL}
		},
		.Z = {.key64 = {
			0x4C529BF7AB0C10F0ULL,
			0x126954CEC73DC7F0ULL,
			0x5B41A846B1126F02ULL,
			0x35413841E927648BULL}
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

	steps = 64;
	X1 = (curve25519_key_t){.key64 = {
		0x0EE11B20D5430768ULL,
		0x6D20462581994F5FULL,
		0x7C9B2B20B4B34F28ULL,
		0x644459C09CE34EE8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0EE11B20D5430768ULL,
			0x6D20462581994F5FULL,
			0x7C9B2B20B4B34F28ULL,
			0x644459C09CE34EE8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE92E805BCD66C6B1ULL,
			0x5DE4A9BB8E6D9DE9ULL,
			0x036E906FCD461EBBULL,
			0x45D8E3E3206ADFEFULL}
		},
		.Z = {.key64 = {
			0x8C643A7EBF58C1A6ULL,
			0x4D1229D0533223C7ULL,
			0x8E4FB44E7CE23E84ULL,
			0x2DFFC2AEC41D110CULL}
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

	steps = 62;
	X1 = (curve25519_key_t){.key64 = {
		0xE6A99AC379E1E8E8ULL,
		0x4634563A68F797B8ULL,
		0x061059B97CB9EA18ULL,
		0x740398862BEE9F64ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE6A99AC379E1E8E8ULL,
			0x4634563A68F797B8ULL,
			0x061059B97CB9EA18ULL,
			0x740398862BEE9F64ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2560AE291E6226B6ULL,
			0x2577259D5A55A4C1ULL,
			0xAD8AFDA0D98E6A08ULL,
			0x17E5F7AB70640458ULL}
		},
		.Z = {.key64 = {
			0xFBFDA5AB40449CCDULL,
			0x9073E3A6F8A0D633ULL,
			0xEA3CF6290EA91B7DULL,
			0x5B865CC6FBC73332ULL}
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

	steps = 14;
	X1 = (curve25519_key_t){.key64 = {
		0x437B5D80C835EB80ULL,
		0x1F53DA8F78750669ULL,
		0xD850615C225D68DEULL,
		0x70AD8CE104B80818ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x437B5D80C835EB80ULL,
			0x1F53DA8F78750669ULL,
			0xD850615C225D68DEULL,
			0x70AD8CE104B80818ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC24EE4E49274C2B6ULL,
			0x021CB1F6217F40ADULL,
			0x9C4A0066E5F2A1FAULL,
			0x4F058C6366C94F1AULL}
		},
		.Z = {.key64 = {
			0x8BA2A9FB926FFB41ULL,
			0x0DA6EC15A468F207ULL,
			0x7E7BF16D4B6FA62DULL,
			0x3B1886A135A94BE2ULL}
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

	steps = 26;
	X1 = (curve25519_key_t){.key64 = {
		0x594CB0D56D51B9C8ULL,
		0xFECA2C266B33E87AULL,
		0xC74BA4DD49059F79ULL,
		0x45DBF7B7D415BF2DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x594CB0D56D51B9C8ULL,
			0xFECA2C266B33E87AULL,
			0xC74BA4DD49059F79ULL,
			0x45DBF7B7D415BF2DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE55676E5ACE38E4CULL,
			0x4BE05690062C156EULL,
			0x23D4F4FA5527CBDDULL,
			0x236004768F28DE38ULL}
		},
		.Z = {.key64 = {
			0x4B7807BE3AF3E8CCULL,
			0x25C564781416DEABULL,
			0x3100B7001FD21DEDULL,
			0x0ACC41549C5770FBULL}
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

	steps = 55;
	X1 = (curve25519_key_t){.key64 = {
		0x5529E7B30D973FD8ULL,
		0xF49FD74DB126BA82ULL,
		0x3ED4AD1D340DC864ULL,
		0x55D0BF58F48DD9E1ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5529E7B30D973FD8ULL,
			0xF49FD74DB126BA82ULL,
			0x3ED4AD1D340DC864ULL,
			0x55D0BF58F48DD9E1ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x92A6440E1C3BF823ULL,
			0xCA681967AF5B6401ULL,
			0xE925704AB6E735A0ULL,
			0x71A84556690F27B8ULL}
		},
		.Z = {.key64 = {
			0xD1C245F73D1A96E2ULL,
			0x71C1E9E78DA317C7ULL,
			0x7F1C37CD2C6AF6E7ULL,
			0x4CF1219C4D0A6D21ULL}
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

	steps = 63;
	X1 = (curve25519_key_t){.key64 = {
		0x155DA65312E759A0ULL,
		0xEE5D18BBD2AB084EULL,
		0xC3482B8AF8B5EFACULL,
		0x5E85533BF5AD34E0ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x155DA65312E759A0ULL,
			0xEE5D18BBD2AB084EULL,
			0xC3482B8AF8B5EFACULL,
			0x5E85533BF5AD34E0ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0390D488B664FF10ULL,
			0x1CBE50428B5EEEA3ULL,
			0x2610D23074A53B90ULL,
			0x4C5ED4AF92351143ULL}
		},
		.Z = {.key64 = {
			0xF22687FFA205298CULL,
			0x7FA7D7290218139DULL,
			0x895399D85AC793CDULL,
			0x11BFC247D032E7C8ULL}
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

	steps = 8;
	X1 = (curve25519_key_t){.key64 = {
		0x6542D4518CC5E740ULL,
		0xD72B9AB1C854E5B5ULL,
		0x281B08BDE080E3B4ULL,
		0x78AC33C60E699615ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6542D4518CC5E740ULL,
			0xD72B9AB1C854E5B5ULL,
			0x281B08BDE080E3B4ULL,
			0x78AC33C60E699615ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x532DDEB8FEAEED5EULL,
			0xD526117B2F96A614ULL,
			0xE95F945D10D17DFBULL,
			0x18EA7A504E9985BCULL}
		},
		.Z = {.key64 = {
			0x87AA3442B1978754ULL,
			0xFDDB65EB8EB4FDC1ULL,
			0x4200580A0000B54FULL,
			0x70E3A0BE79E70E7DULL}
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
		0xC06E81FCEA27F9F8ULL,
		0xC31E37F26C305D58ULL,
		0x73AB79577C33A564ULL,
		0x505E81EDB0E8FE5BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC06E81FCEA27F9F8ULL,
			0xC31E37F26C305D58ULL,
			0x73AB79577C33A564ULL,
			0x505E81EDB0E8FE5BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF6812ABC3E920CC3ULL,
			0x29105C16C2566A90ULL,
			0x45D14E1DA4110264ULL,
			0x3D3365CAF6A71D39ULL}
		},
		.Z = {.key64 = {
			0x6E74784DBCB91F94ULL,
			0x7F0C928F23970F0BULL,
			0x49349730558E92C4ULL,
			0x37686E9792B0B668ULL}
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

	steps = 33;
	X1 = (curve25519_key_t){.key64 = {
		0x0F62D221984D6408ULL,
		0x43CB60579373F654ULL,
		0x6F5BCA721851F890ULL,
		0x44499031832A7E64ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0F62D221984D6408ULL,
			0x43CB60579373F654ULL,
			0x6F5BCA721851F890ULL,
			0x44499031832A7E64ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x71D6DF5DA1F33ECEULL,
			0x40179AF709FB72ACULL,
			0xD9F5EC6B8C650C96ULL,
			0x4EAC5ABED64AA5BAULL}
		},
		.Z = {.key64 = {
			0xF48306C3D369EAF9ULL,
			0x482278338D465730ULL,
			0xC943DAED173C4884ULL,
			0x3AA7661A41004DA6ULL}
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

	steps = 13;
	X1 = (curve25519_key_t){.key64 = {
		0x0731B3D1D2CD15A0ULL,
		0x9339FCCEC4D404FBULL,
		0x74CA0ACAA7F183E0ULL,
		0x604B64361D7C9350ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0731B3D1D2CD15A0ULL,
			0x9339FCCEC4D404FBULL,
			0x74CA0ACAA7F183E0ULL,
			0x604B64361D7C9350ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE5CC067058D8B82FULL,
			0xBE41C0F8BA5E00F1ULL,
			0x00CF4C83DD76F48AULL,
			0x73608814555C004DULL}
		},
		.Z = {.key64 = {
			0xA1F8C4E35D61E791ULL,
			0x28667821E6F73C3FULL,
			0x82F050651690AF8DULL,
			0x6F377BF0260C86D9ULL}
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

	steps = 60;
	X1 = (curve25519_key_t){.key64 = {
		0x67D725B0CA83B8B0ULL,
		0x426ABF7DB1E35A52ULL,
		0xC70B77AC3DDB9699ULL,
		0x71DC8B75835A1A5CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x67D725B0CA83B8B0ULL,
			0x426ABF7DB1E35A52ULL,
			0xC70B77AC3DDB9699ULL,
			0x71DC8B75835A1A5CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBA5F185AA3365D7EULL,
			0x6FFFB162DFDF3D0AULL,
			0xF7C62FC568177F5DULL,
			0x25D12D40944DDDBAULL}
		},
		.Z = {.key64 = {
			0xA73942847A3E1301ULL,
			0xA70E5C0B91BF3143ULL,
			0xE4513C95939CAE08ULL,
			0x0A16045C4F26F26DULL}
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

	steps = 56;
	X1 = (curve25519_key_t){.key64 = {
		0x503BA1A041CDF910ULL,
		0x5EF9963F7C980A2EULL,
		0x8953646E5B977CD0ULL,
		0x6255C44266B045EBULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x503BA1A041CDF910ULL,
			0x5EF9963F7C980A2EULL,
			0x8953646E5B977CD0ULL,
			0x6255C44266B045EBULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7360BB73D3090F03ULL,
			0xBEDBC6C91D083E14ULL,
			0x75F5EA857A7DAC3FULL,
			0x3F6B58061BAE7CB5ULL}
		},
		.Z = {.key64 = {
			0x7042E7977349639DULL,
			0x4D3DB3A0F23EB0BCULL,
			0x5FAFA14F61B2A616ULL,
			0x25F53CB0A7901A4FULL}
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

	steps = 6;
	X1 = (curve25519_key_t){.key64 = {
		0x79185D64A5B51990ULL,
		0xAB14BC17AD003F90ULL,
		0x350E585AD8982993ULL,
		0x4A421ECB5980F9EDULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x79185D64A5B51990ULL,
			0xAB14BC17AD003F90ULL,
			0x350E585AD8982993ULL,
			0x4A421ECB5980F9EDULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8B028BC01362FAD0ULL,
			0x412BFF9AA8E0BF5AULL,
			0xE7701087B17F3219ULL,
			0x6427D8BA36528017ULL}
		},
		.Z = {.key64 = {
			0x093788494FB778A5ULL,
			0xF42714A3C507AC38ULL,
			0xFB5DD9D012319019ULL,
			0x63983574A5D5D546ULL}
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
		0xEA6A582BD22ECD78ULL,
		0x01776EFFA778955EULL,
		0x44A42A03B9F6D298ULL,
		0x7F012FF9CB7455FEULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEA6A582BD22ECD78ULL,
			0x01776EFFA778955EULL,
			0x44A42A03B9F6D298ULL,
			0x7F012FF9CB7455FEULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE41F6601F7807E26ULL,
			0x8FBA39AC380D130CULL,
			0x192DE8D1B863556DULL,
			0x67AA3ECEA5C366A8ULL}
		},
		.Z = {.key64 = {
			0x8B27A34C7417447DULL,
			0xA6AF80791FB562A6ULL,
			0x55F3786429C79850ULL,
			0x09844A05BE1CF514ULL}
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

	steps = 38;
	X1 = (curve25519_key_t){.key64 = {
		0x54C1E76DB0F6C540ULL,
		0xAE0A5AF287D05299ULL,
		0x08619859ED717F3BULL,
		0x63ED978BBF8B6B13ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x54C1E76DB0F6C540ULL,
			0xAE0A5AF287D05299ULL,
			0x08619859ED717F3BULL,
			0x63ED978BBF8B6B13ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB9621F9C59B3250EULL,
			0x51DFA8AF4829C331ULL,
			0x49B94FF10CDA85D1ULL,
			0x16FA07E2D67C4D2CULL}
		},
		.Z = {.key64 = {
			0x39787FD9991FC13AULL,
			0xDD1F0BB4A465C4C6ULL,
			0xDFE04B4082C283EEULL,
			0x05BEE3B60710B0FCULL}
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

	steps = 37;
	X1 = (curve25519_key_t){.key64 = {
		0xB712194A7F5540C8ULL,
		0xF450B784BB866C86ULL,
		0x162065921E793347ULL,
		0x6D404A4C4431D32CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB712194A7F5540C8ULL,
			0xF450B784BB866C86ULL,
			0x162065921E793347ULL,
			0x6D404A4C4431D32CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x39A673BEA3B5958DULL,
			0x66249CFCED15BE89ULL,
			0x73F55A199BCF4AC4ULL,
			0x0689483286B61431ULL}
		},
		.Z = {.key64 = {
			0x4874B4D41AAD0F64ULL,
			0x80511A9CD69B3F4EULL,
			0xBE1480B7C1A7368EULL,
			0x043414E374A1456FULL}
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

	steps = 16;
	X1 = (curve25519_key_t){.key64 = {
		0xBA99207B4E4A75F0ULL,
		0x6C8E3538157E5287ULL,
		0xA710B1B438663E57ULL,
		0x6E12A5AF7D927716ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBA99207B4E4A75F0ULL,
			0x6C8E3538157E5287ULL,
			0xA710B1B438663E57ULL,
			0x6E12A5AF7D927716ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x17EA8AA12D765DCAULL,
			0x9A96062F165F3632ULL,
			0xB60CFB4EF32650CDULL,
			0x4FA2B3A0C46F0388ULL}
		},
		.Z = {.key64 = {
			0x575F80EC04392E75ULL,
			0x19479934E23A7B4EULL,
			0xA779BBBE064B98E7ULL,
			0x150CCFD8F351C0F2ULL}
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

	steps = 54;
	X1 = (curve25519_key_t){.key64 = {
		0x19310211FA8BEF08ULL,
		0xB100A344058347A5ULL,
		0x6839FCEC1DC2B44EULL,
		0x70207669566B4F42ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x19310211FA8BEF08ULL,
			0xB100A344058347A5ULL,
			0x6839FCEC1DC2B44EULL,
			0x70207669566B4F42ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2C9037EAE1056174ULL,
			0x71B1031C60476D7BULL,
			0x5118412FA95B4194ULL,
			0x5A71C7551F8337F3ULL}
		},
		.Z = {.key64 = {
			0xBB7FAA38FADC5610ULL,
			0x3CCEF9E58C0A69F0ULL,
			0x1A07DFC2FE593184ULL,
			0x5FA0B1EF24C554E4ULL}
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

	steps = 22;
	X1 = (curve25519_key_t){.key64 = {
		0x30B69F082DD35628ULL,
		0x78C903C21104C7DFULL,
		0xBE816A7C2D7E6A70ULL,
		0x5F1A64D0093E81FFULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x30B69F082DD35628ULL,
			0x78C903C21104C7DFULL,
			0xBE816A7C2D7E6A70ULL,
			0x5F1A64D0093E81FFULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0ED4200763F2F13CULL,
			0xBD8518B8AF911D60ULL,
			0xCCAE7E662D82D1F8ULL,
			0x40C639D422B4454EULL}
		},
		.Z = {.key64 = {
			0xB4AA50F68937876CULL,
			0x297A55B99982BA77ULL,
			0x3DAF6B080F194AF6ULL,
			0x516F0665579561C7ULL}
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

	steps = 1;
	X1 = (curve25519_key_t){.key64 = {
		0x9CDD727EF346D9F0ULL,
		0x973107BEB9049D9FULL,
		0x3A5AF7714A2223ABULL,
		0x4070083E944C58D5ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9CDD727EF346D9F0ULL,
			0x973107BEB9049D9FULL,
			0x3A5AF7714A2223ABULL,
			0x4070083E944C58D5ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x187AE43FB0816ECAULL,
			0xBB0939F90A2C7936ULL,
			0xA011F6F4FC404BC5ULL,
			0x78FE6FF3F22DC9A0ULL}
		},
		.Z = {.key64 = {
			0x7375C9FBCD1B67E6ULL,
			0x5CC41EFAE412767EULL,
			0xE96BDDC528888EAEULL,
			0x01C020FA51316354ULL}
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

	steps = 50;
	X1 = (curve25519_key_t){.key64 = {
		0x33FD774624EF53C0ULL,
		0x1E1ADE952BEEC99BULL,
		0x3C121079635734D5ULL,
		0x52733CDAEAD02781ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x33FD774624EF53C0ULL,
			0x1E1ADE952BEEC99BULL,
			0x3C121079635734D5ULL,
			0x52733CDAEAD02781ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6E41803922CCD0A4ULL,
			0x9420798E548A85B4ULL,
			0xD4BDCD7DE74CF0B7ULL,
			0x3419522572F14D11ULL}
		},
		.Z = {.key64 = {
			0x8213752692DCD176ULL,
			0x4FF5542882DB4EA6ULL,
			0x5CA1F0528EA455B4ULL,
			0x667E13D01AC41F64ULL}
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

	steps = 43;
	X1 = (curve25519_key_t){.key64 = {
		0xC61553E2A5836F48ULL,
		0x6A180E278011ECF1ULL,
		0xFE639B2179C4C410ULL,
		0x7CFE1DDF2D37AF61ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC61553E2A5836F48ULL,
			0x6A180E278011ECF1ULL,
			0xFE639B2179C4C410ULL,
			0x7CFE1DDF2D37AF61ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x92D18C87DE08FF34ULL,
			0x3C0FDF920BE5F1E2ULL,
			0x8DE397E47EDEF725ULL,
			0x5E215643ED284AF1ULL}
		},
		.Z = {.key64 = {
			0xD2047A8D1D2F1D0AULL,
			0x4A339826BA3B909CULL,
			0x8293DE4FB1A19564ULL,
			0x3A94FB8547386147ULL}
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

	steps = 9;
	X1 = (curve25519_key_t){.key64 = {
		0xD11693481E4FFD00ULL,
		0x62F18F02616C6644ULL,
		0xB3819815EFCEA5F8ULL,
		0x6B969F69C83F4313ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD11693481E4FFD00ULL,
			0x62F18F02616C6644ULL,
			0xB3819815EFCEA5F8ULL,
			0x6B969F69C83F4313ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4D265FE38C260157ULL,
			0x4A44271CEBC3440FULL,
			0xF126F6064EFEB1A2ULL,
			0x47846E3411275BF8ULL}
		},
		.Z = {.key64 = {
			0xA4ECC7FF074389A2ULL,
			0x16E2DFAC9D08CB31ULL,
			0x766D7182058B84F1ULL,
			0x7A5478BFB162664CULL}
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

	steps = 42;
	X1 = (curve25519_key_t){.key64 = {
		0x5DEC99CD0C75D418ULL,
		0xA8F3F0653F2109D2ULL,
		0xBDC29C2C1036B69AULL,
		0x75180AA7E9C08FDBULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5DEC99CD0C75D418ULL,
			0xA8F3F0653F2109D2ULL,
			0xBDC29C2C1036B69AULL,
			0x75180AA7E9C08FDBULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB94BF2E398EB1595ULL,
			0x37629BA5B20A6B78ULL,
			0x487E28ACA8F87B1AULL,
			0x51E52B8DC06FB7BDULL}
		},
		.Z = {.key64 = {
			0xB7892C0C81B2973AULL,
			0xA2022B9A2BE8AF5FULL,
			0x6D81C4372DFD23B5ULL,
			0x766AA2449D5C2623ULL}
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

	steps = 51;
	X1 = (curve25519_key_t){.key64 = {
		0x110394EFEB20D750ULL,
		0x83F43DC05E5568BCULL,
		0xE884CD11B4AD88E4ULL,
		0x446BE3245941AF35ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x110394EFEB20D750ULL,
			0x83F43DC05E5568BCULL,
			0xE884CD11B4AD88E4ULL,
			0x446BE3245941AF35ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC65254089DC758DCULL,
			0x4DCAE4D52A18166AULL,
			0x1C2BE6DF972D7993ULL,
			0x4B69A850CFDAF3F7ULL}
		},
		.Z = {.key64 = {
			0x2F90A5B6BC7D3752ULL,
			0xBC11BE118A0C698AULL,
			0x2D0C7E5C505C3EAEULL,
			0x5F4FA0CA2BD5A789ULL}
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

	steps = 47;
	X1 = (curve25519_key_t){.key64 = {
		0xB21E23204F618DD8ULL,
		0xF5029B9170125410ULL,
		0xCF29859FD6034F60ULL,
		0x58976827073BA5E8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB21E23204F618DD8ULL,
			0xF5029B9170125410ULL,
			0xCF29859FD6034F60ULL,
			0x58976827073BA5E8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x16B8365E29A1DD07ULL,
			0xE88B92244AAB0A05ULL,
			0xE1F712DE1D0ED67FULL,
			0x15F902E2D1FA766BULL}
		},
		.Z = {.key64 = {
			0x6D8F0028639D968DULL,
			0xBB5D31DA0DAA8C86ULL,
			0x53C82087EAAD068AULL,
			0x343A14E2DB3ED4B0ULL}
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

	steps = 35;
	X1 = (curve25519_key_t){.key64 = {
		0x5E25233DDB8A6FF0ULL,
		0xB36D9954146986EBULL,
		0xD726155B9ECAFBF4ULL,
		0x5B7F35167E3808D8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5E25233DDB8A6FF0ULL,
			0xB36D9954146986EBULL,
			0xD726155B9ECAFBF4ULL,
			0x5B7F35167E3808D8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD810A540A9C07813ULL,
			0xC1E9B43CAAD4AB01ULL,
			0x381BBEAD1FCFD00CULL,
			0x675AA8C097F786EFULL}
		},
		.Z = {.key64 = {
			0xB0C3EB6FCE0361BEULL,
			0x6C5C39B14188B299ULL,
			0xB461A76A371F7DBDULL,
			0x3D79AD84608420DFULL}
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

	steps = 3;
	X1 = (curve25519_key_t){.key64 = {
		0x96BD510C2C066A58ULL,
		0xB59BCBE358325ECAULL,
		0xB5EAFC0BF1001C48ULL,
		0x4A2E960CB6F3198FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x96BD510C2C066A58ULL,
			0xB59BCBE358325ECAULL,
			0xB5EAFC0BF1001C48ULL,
			0x4A2E960CB6F3198FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6965B5F8922666A6ULL,
			0x4672C5895971816AULL,
			0x7F82BB6818F7C5B4ULL,
			0x058F53A2A4AA9CDDULL}
		},
		.Z = {.key64 = {
			0x0C3F74409F8D4E2DULL,
			0x5A3E1E852ED510B2ULL,
			0xB6CAB8815E8ADBF5ULL,
			0x750596CB54049541ULL}
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
		0x16A3311B51BDDA40ULL,
		0x812B7EB39A8C2888ULL,
		0x2502A48920BAD7A4ULL,
		0x49973CB8D1B82F78ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x16A3311B51BDDA40ULL,
			0x812B7EB39A8C2888ULL,
			0x2502A48920BAD7A4ULL,
			0x49973CB8D1B82F78ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x82E0301256AA294CULL,
			0x8C61B94B39183279ULL,
			0x64A2220994C3FFA7ULL,
			0x13F87C9EF41FAA6AULL}
		},
		.Z = {.key64 = {
			0x6F4E82AA27CAC880ULL,
			0x9D6A8543DCAA1CCAULL,
			0x93A8F836D09B0F42ULL,
			0x2D2A18FC62E8EF89ULL}
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

	steps = 48;
	X1 = (curve25519_key_t){.key64 = {
		0x73F68AD54E1A8A38ULL,
		0xDC32EDEAB55C5D2DULL,
		0xAB67B9E0417770CEULL,
		0x7E25538EC2C62828ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x73F68AD54E1A8A38ULL,
			0xDC32EDEAB55C5D2DULL,
			0xAB67B9E0417770CEULL,
			0x7E25538EC2C62828ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBDDB062FA391FB84ULL,
			0xBB525B3D53834741ULL,
			0xC77866F94C04AEC5ULL,
			0x58C8F8FA4E990A2FULL}
		},
		.Z = {.key64 = {
			0x66BB90DF1A3B405FULL,
			0xE835C0D442A7CA18ULL,
			0xDCB228640C3478D8ULL,
			0x3526B48E564EB8ACULL}
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

	steps = 64;
	X1 = (curve25519_key_t){.key64 = {
		0xC7B8A26553D724B8ULL,
		0xAFF4218B9DEC2435ULL,
		0x4D1D32A95A7D2394ULL,
		0x6C061E03338D9DEBULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC7B8A26553D724B8ULL,
			0xAFF4218B9DEC2435ULL,
			0x4D1D32A95A7D2394ULL,
			0x6C061E03338D9DEBULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5BD8458545A9A4DEULL,
			0x6D185ABF6C6347D4ULL,
			0xCB13F35DB42BCF9EULL,
			0x7DD170C9D307F674ULL}
		},
		.Z = {.key64 = {
			0x8D257A7955CAD2A4ULL,
			0xF32594F13F227019ULL,
			0xAEB3D1C4BCFE162EULL,
			0x2F60F95618ECC4BEULL}
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

	steps = 45;
	X1 = (curve25519_key_t){.key64 = {
		0x745286FF8F506140ULL,
		0x2B6D02F8257FFC30ULL,
		0xC74769E12D932AE0ULL,
		0x5335B6CAC196B32DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x745286FF8F506140ULL,
			0x2B6D02F8257FFC30ULL,
			0xC74769E12D932AE0ULL,
			0x5335B6CAC196B32DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2E5CB07BB4EF77FCULL,
			0x837A1685BB2F31A5ULL,
			0x0F675C30A5D53AE5ULL,
			0x599664B6D9702970ULL}
		},
		.Z = {.key64 = {
			0x1350F8A44A32CFF5ULL,
			0xA621301AEB93F518ULL,
			0xF8BD404E37BD13EFULL,
			0x608F91782EA9148DULL}
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

	steps = 24;
	X1 = (curve25519_key_t){.key64 = {
		0x70A9A4366FF4EF00ULL,
		0xB98AC5421014336EULL,
		0x833488EFFAA99D52ULL,
		0x6186695C9A9F54B8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x70A9A4366FF4EF00ULL,
			0xB98AC5421014336EULL,
			0x833488EFFAA99D52ULL,
			0x6186695C9A9F54B8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1AE42CB6F0E0A8A8ULL,
			0xA79A3FF79554E14EULL,
			0x13144B2E8F1CBDBFULL,
			0x276B50A22CF91498ULL}
		},
		.Z = {.key64 = {
			0x9F045336863790F6ULL,
			0x3CF0F2C80F55D6CBULL,
			0x10BFE24D97A3C15DULL,
			0x16A7B5E349CFE6E8ULL}
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

	steps = 35;
	X1 = (curve25519_key_t){.key64 = {
		0x780C39C36E529E48ULL,
		0xEB93972CA9D2A5C5ULL,
		0xBA1FAB2B7659CA85ULL,
		0x473C2E424AA1723DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x780C39C36E529E48ULL,
			0xEB93972CA9D2A5C5ULL,
			0xBA1FAB2B7659CA85ULL,
			0x473C2E424AA1723DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7F7C03E022D1D069ULL,
			0x4CD1878110A08780ULL,
			0x6029FBCDD76164CDULL,
			0x6AF91E4E2C952D3FULL}
		},
		.Z = {.key64 = {
			0xA810783A1C9EA5C2ULL,
			0x3B73490567A81584ULL,
			0x6B4218DDFD753AD9ULL,
			0x18A7D8E86994551BULL}
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

	steps = 39;
	X1 = (curve25519_key_t){.key64 = {
		0xC77CABEB7608F5A8ULL,
		0xE49B71AE07A615F5ULL,
		0x8B1749F352368799ULL,
		0x5A30133470072AD6ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC77CABEB7608F5A8ULL,
			0xE49B71AE07A615F5ULL,
			0x8B1749F352368799ULL,
			0x5A30133470072AD6ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCD18EE43EAAB13E4ULL,
			0xC84B62E514A05BC0ULL,
			0x72B791F254808F4FULL,
			0x2A0B4D2E06FB2647ULL}
		},
		.Z = {.key64 = {
			0xF8DE3EE3FBE00502ULL,
			0x52AEC82C6F8267E0ULL,
			0xA1AD861C2F2C8E8BULL,
			0x2926CAEADEFE25C9ULL}
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

	steps = 48;
	X1 = (curve25519_key_t){.key64 = {
		0x67ED7645A00A4968ULL,
		0x7AA4422652E585B5ULL,
		0x8E76BDA8886DFCFDULL,
		0x50DD68ADB071EE11ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x67ED7645A00A4968ULL,
			0x7AA4422652E585B5ULL,
			0x8E76BDA8886DFCFDULL,
			0x50DD68ADB071EE11ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7E1AEE0038BDEC21ULL,
			0x538481577074B525ULL,
			0x36A0BED50C7DC810ULL,
			0x1DE7CB9D5C9DD7C0ULL}
		},
		.Z = {.key64 = {
			0x13EE32D24A430F7AULL,
			0x8F496C53EC108146ULL,
			0x187B297F134D13ABULL,
			0x692CB1A1983BFD92ULL}
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

	steps = 14;
	X1 = (curve25519_key_t){.key64 = {
		0x159198BE046793F0ULL,
		0x060594C5C15F778BULL,
		0x9E7D58782D4E00ECULL,
		0x5A9A59FDB2477D0CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x159198BE046793F0ULL,
			0x060594C5C15F778BULL,
			0x9E7D58782D4E00ECULL,
			0x5A9A59FDB2477D0CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD200CDF079442BAAULL,
			0xF96DA8760BC81A09ULL,
			0x1E5F1B1E56D5257BULL,
			0x5C43E13758644640ULL}
		},
		.Z = {.key64 = {
			0x0DDEE17BFA275D57ULL,
			0x557DE6B6786BB7A1ULL,
			0x71DC583FDC73C5D1ULL,
			0x54D290E72C1E5F22ULL}
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

	steps = 10;
	X1 = (curve25519_key_t){.key64 = {
		0x103B3998DB7AD560ULL,
		0x29D4DE71F985301BULL,
		0x64E964EF06B072DEULL,
		0x75E710DEF3EB1FCDULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x103B3998DB7AD560ULL,
			0x29D4DE71F985301BULL,
			0x64E964EF06B072DEULL,
			0x75E710DEF3EB1FCDULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4887D48C96D937F8ULL,
			0x647738C4E7DBD697ULL,
			0xEBB73194BCB33E4CULL,
			0x6BB63DF4CD624D35ULL}
		},
		.Z = {.key64 = {
			0x80EC746434E4D673ULL,
			0x3FA1B8D7D7385AADULL,
			0x1D77D5608AB99FEFULL,
			0x7E44917976334F45ULL}
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

	steps = 2;
	X1 = (curve25519_key_t){.key64 = {
		0x87B2F3A79465A420ULL,
		0x2991D30F5466B864ULL,
		0xFE0516D050344409ULL,
		0x6A64D004FA89B862ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x87B2F3A79465A420ULL,
			0x2991D30F5466B864ULL,
			0xFE0516D050344409ULL,
			0x6A64D004FA89B862ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x865A00128F296F6EULL,
			0x54E196528257BBF0ULL,
			0x6F7D9FE5A031B800ULL,
			0x0786B465AD3D13BBULL}
		},
		.Z = {.key64 = {
			0x4742CBCC87571263ULL,
			0xC8431BA386B784BDULL,
			0xB02C1686B0E16671ULL,
			0x6B9502F102C0C34FULL}
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

	steps = 55;
	X1 = (curve25519_key_t){.key64 = {
		0x9A584ECB8D952E98ULL,
		0x24B3EA38DC0922DCULL,
		0x4EFD2FF9582F466AULL,
		0x5D5B772409934429ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9A584ECB8D952E98ULL,
			0x24B3EA38DC0922DCULL,
			0x4EFD2FF9582F466AULL,
			0x5D5B772409934429ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xECE7850819CACEDEULL,
			0xD252022F4F2181E7ULL,
			0x7EA155678077DACDULL,
			0x07282ECE154F7ABAULL}
		},
		.Z = {.key64 = {
			0xAB8C60BFEAE4F990ULL,
			0x94E957D86116B61DULL,
			0x819722467EE80816ULL,
			0x1C4B2BC95A234B91ULL}
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

	steps = 32;
	X1 = (curve25519_key_t){.key64 = {
		0x22491F9ADCF47F48ULL,
		0xB1D28E5294753987ULL,
		0x842DD04D933D25B9ULL,
		0x543EEFB811FE9CDAULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x22491F9ADCF47F48ULL,
			0xB1D28E5294753987ULL,
			0x842DD04D933D25B9ULL,
			0x543EEFB811FE9CDAULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7F84858970ABFFA6ULL,
			0xD09C8C51DBDEBB74ULL,
			0x8E186090488D1C9AULL,
			0x3969036669E24A7BULL}
		},
		.Z = {.key64 = {
			0x4C716328E586894FULL,
			0xB6AC2C3F72D56429ULL,
			0xE4190364107D64A9ULL,
			0x734B45C39958DA09ULL}
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

	steps = 16;
	X1 = (curve25519_key_t){.key64 = {
		0x5A830D4C2FFF1F10ULL,
		0xE80B6BAB3D6C6EE3ULL,
		0x705BE97D37ED3963ULL,
		0x4618923EE4A37019ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5A830D4C2FFF1F10ULL,
			0xE80B6BAB3D6C6EE3ULL,
			0x705BE97D37ED3963ULL,
			0x4618923EE4A37019ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC532698544F4812BULL,
			0x654EF8EA829875CCULL,
			0x97491BA219724691ULL,
			0x30A5EDC2A00D5C1CULL}
		},
		.Z = {.key64 = {
			0x9D9C6D25B6BEF27AULL,
			0x59C59C5BA0244091ULL,
			0x8B18DAC3CC3E884CULL,
			0x7088FF80C0A52C83ULL}
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
		0xCA192FD0FDE25B08ULL,
		0x75F68284AA9E4330ULL,
		0x077875CAA2DDD8C3ULL,
		0x636B323381769ADBULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCA192FD0FDE25B08ULL,
			0x75F68284AA9E4330ULL,
			0x077875CAA2DDD8C3ULL,
			0x636B323381769ADBULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA6929ACC5A2427C4ULL,
			0x8693833DAD407E4DULL,
			0x2CF4054045BCCD3FULL,
			0x0151BC6439A78207ULL}
		},
		.Z = {.key64 = {
			0x3B038E0B3FDB7746ULL,
			0x34CD52DC6B269235ULL,
			0x1D1D4A97AD519894ULL,
			0x599F1B5083185E02ULL}
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

	steps = 24;
	X1 = (curve25519_key_t){.key64 = {
		0x529743CA120A08C8ULL,
		0xCF334B8DF8436807ULL,
		0xBF4ABA48260A0367ULL,
		0x693EE24CE369B915ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x529743CA120A08C8ULL,
			0xCF334B8DF8436807ULL,
			0xBF4ABA48260A0367ULL,
			0x693EE24CE369B915ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC3FEF8B630647B41ULL,
			0x84DE1B2F7920608BULL,
			0x18C904D1BED90D62ULL,
			0x58B73204B202F9C2ULL}
		},
		.Z = {.key64 = {
			0x4C8645A4C9D5052BULL,
			0xE0A1A1D1DC9DB6E1ULL,
			0x65EAF48BFF9F9B91ULL,
			0x54EAAC54F8BAA77FULL}
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

	steps = 40;
	X1 = (curve25519_key_t){.key64 = {
		0x57AD640E40586D40ULL,
		0x55049976C4C1C6A9ULL,
		0x44B8880812FE7FCBULL,
		0x4A2052D0D3FBCA3DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x57AD640E40586D40ULL,
			0x55049976C4C1C6A9ULL,
			0x44B8880812FE7FCBULL,
			0x4A2052D0D3FBCA3DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9127A6950594D937ULL,
			0x34C0015C88883ECDULL,
			0x594EB84AA8F3AA0DULL,
			0x102D2A86009B545DULL}
		},
		.Z = {.key64 = {
			0x05256307199F9A34ULL,
			0x0AE31B3562AB768DULL,
			0x1A1715814A1D9DEBULL,
			0x11BECA83EDB05A6DULL}
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

	steps = 28;
	X1 = (curve25519_key_t){.key64 = {
		0x26BFC5DFC2592060ULL,
		0xADD9D050FD0754CDULL,
		0xA7F2033406EBC27EULL,
		0x45E08192FD8CF931ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x26BFC5DFC2592060ULL,
			0xADD9D050FD0754CDULL,
			0xA7F2033406EBC27EULL,
			0x45E08192FD8CF931ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x654B9BABB5658443ULL,
			0x9B985AC0D125BDCCULL,
			0xB416DBECA5C28F1CULL,
			0x22B4119A37BA547AULL}
		},
		.Z = {.key64 = {
			0x9384625C9B579274ULL,
			0xCE557317E825D5FAULL,
			0xEBF171FFDB803D3DULL,
			0x39DFA1FF154C63BEULL}
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

	steps = 8;
	X1 = (curve25519_key_t){.key64 = {
		0xFDD1D18D6FC53980ULL,
		0x4EE47FB6FDDF6031ULL,
		0x4425F6CDF9F61846ULL,
		0x75FF4446E90E619FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFDD1D18D6FC53980ULL,
			0x4EE47FB6FDDF6031ULL,
			0x4425F6CDF9F61846ULL,
			0x75FF4446E90E619FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBE4362524BDBE81FULL,
			0x3127AD2A25DD919BULL,
			0x7D6A90B816363CE1ULL,
			0x5AF5F96C9A79A0C0ULL}
		},
		.Z = {.key64 = {
			0x820D535DA159920EULL,
			0x2F1FD253B02DFB73ULL,
			0x948BF62860961CD5ULL,
			0x605D5B39F3C1071EULL}
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

	steps = 47;
	X1 = (curve25519_key_t){.key64 = {
		0xB07C7D6D804A2E18ULL,
		0xB287EB71E805D78EULL,
		0x697884B8CA6BD739ULL,
		0x49B9CBEAD5126571ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB07C7D6D804A2E18ULL,
			0xB287EB71E805D78EULL,
			0x697884B8CA6BD739ULL,
			0x49B9CBEAD5126571ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF6E47FE1B5359AF3ULL,
			0xAC5E262BDAED1B0CULL,
			0x06EB02CDC4BEE177ULL,
			0x7FD2C9C7FCCFB342ULL}
		},
		.Z = {.key64 = {
			0x4C2A384AE5A985BCULL,
			0x2D700A4EADE5FC07ULL,
			0xAFB5906B2E75A80CULL,
			0x3548352D2441F97AULL}
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

	steps = 32;
	X1 = (curve25519_key_t){.key64 = {
		0xF12F2067B69B5340ULL,
		0xC0C6E317F7F186A7ULL,
		0x1AE8DAD0D661130BULL,
		0x532F921143452ACDULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF12F2067B69B5340ULL,
			0xC0C6E317F7F186A7ULL,
			0x1AE8DAD0D661130BULL,
			0x532F921143452ACDULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x01CBDD9E37C85252ULL,
			0x520AAAEE2A957972ULL,
			0xD26CA99D5321AE47ULL,
			0x2CA24F3AFE5D2B14ULL}
		},
		.Z = {.key64 = {
			0xEF658CA9AF67413FULL,
			0x2A22A4126B5AF2F1ULL,
			0x9EDE227D2E4622D2ULL,
			0x107400FE349284F2ULL}
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

	steps = 14;
	X1 = (curve25519_key_t){.key64 = {
		0xAB9866B61D091A38ULL,
		0x2C2CB588E333366FULL,
		0x240FA9160349D600ULL,
		0x5D2232D8B472F417ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAB9866B61D091A38ULL,
			0x2C2CB588E333366FULL,
			0x240FA9160349D600ULL,
			0x5D2232D8B472F417ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x426D060921C7EA47ULL,
			0x5D9C3B8A8B8EFCADULL,
			0x99C6D105293DD5B0ULL,
			0x1CAA4CC4F32C8E52ULL}
		},
		.Z = {.key64 = {
			0xFEBE2751B571283AULL,
			0xF7260BDDD85978D6ULL,
			0x51B1124CE1BD855BULL,
			0x6BF021EB40BDEE61ULL}
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

	steps = 63;
	X1 = (curve25519_key_t){.key64 = {
		0x4E786BF6AD1BDDD0ULL,
		0x62D76EE5E061F987ULL,
		0x52F636B328C5D983ULL,
		0x7D10262DBC753BCBULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4E786BF6AD1BDDD0ULL,
			0x62D76EE5E061F987ULL,
			0x52F636B328C5D983ULL,
			0x7D10262DBC753BCBULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3D01506E855F085AULL,
			0xCF97EC0CAC72E43BULL,
			0x66BC586436268357ULL,
			0x35E23F80E6E5EE56ULL}
		},
		.Z = {.key64 = {
			0x1D4E93DF5971D778ULL,
			0xB136ACB12B3F31D0ULL,
			0x130E10F186E8E705ULL,
			0x554A75C5622819EBULL}
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

	steps = 21;
	X1 = (curve25519_key_t){.key64 = {
		0x9505186EB06A5300ULL,
		0xF1DF0190051A39A7ULL,
		0x2267AE09D5790AD3ULL,
		0x7C542942A1151824ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9505186EB06A5300ULL,
			0xF1DF0190051A39A7ULL,
			0x2267AE09D5790AD3ULL,
			0x7C542942A1151824ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x08FB7FFCAE5CF35FULL,
			0x5745AF3D09C44E77ULL,
			0x96E5790ED6BB0F67ULL,
			0x34CC266641D9DD2CULL}
		},
		.Z = {.key64 = {
			0xA4DB4C4C315E423DULL,
			0xDB519DAB1294971EULL,
			0xA2DBC3977A9166F0ULL,
			0x49D67FF4FFD8A22FULL}
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

	steps = 59;
	X1 = (curve25519_key_t){.key64 = {
		0xA0E21CFE521BEBE0ULL,
		0x2E69E0F43EF9D7E9ULL,
		0xB1E2B603F0D9438DULL,
		0x4D0068F762573231ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA0E21CFE521BEBE0ULL,
			0x2E69E0F43EF9D7E9ULL,
			0xB1E2B603F0D9438DULL,
			0x4D0068F762573231ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6556FC8F70DCE9DCULL,
			0xBE618BFE882D3F0AULL,
			0x412808B1A5875586ULL,
			0x25F072ADF0AF4993ULL}
		},
		.Z = {.key64 = {
			0x995069C6705CC73BULL,
			0x86C03D258A0343C3ULL,
			0x8203CD7128AC2361ULL,
			0x55EBBE079A9DBC92ULL}
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

	steps = 25;
	X1 = (curve25519_key_t){.key64 = {
		0x06734B07CAECE810ULL,
		0x0C2A311DC8A42759ULL,
		0x7F6D1E47118209DBULL,
		0x714D55A24A7AE15DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x06734B07CAECE810ULL,
			0x0C2A311DC8A42759ULL,
			0x7F6D1E47118209DBULL,
			0x714D55A24A7AE15DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x67FF9391F70C0F79ULL,
			0xB3C3FC17FB5829DBULL,
			0xFA127D329E9181CEULL,
			0x4CEC7A6D14EC80D9ULL}
		},
		.Z = {.key64 = {
			0x7CE8CD1925427C37ULL,
			0x84FA023DD5B01411ULL,
			0x8A72E7E3C1F574A0ULL,
			0x5B80435AC7AD90A5ULL}
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

	steps = 3;
	X1 = (curve25519_key_t){.key64 = {
		0xDA6AB0C612798968ULL,
		0xF62294D359047AEDULL,
		0x9751A46F833F1B18ULL,
		0x4C7F69E2980678B4ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDA6AB0C612798968ULL,
			0xF62294D359047AEDULL,
			0x9751A46F833F1B18ULL,
			0x4C7F69E2980678B4ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x532D669AD33A8908ULL,
			0xC8872C4E0B91DED8ULL,
			0xFB426020282895F5ULL,
			0x65FA60A8502E6636ULL}
		},
		.Z = {.key64 = {
			0x96747FB077F9F8EDULL,
			0x9955142BE653B251ULL,
			0x8817019DFF3B7C13ULL,
			0x478BFF9B4F0A8188ULL}
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

	steps = 29;
	X1 = (curve25519_key_t){.key64 = {
		0xD968D7E659C02758ULL,
		0xE46F7CE3CA109F70ULL,
		0xBA9B881909BAAB82ULL,
		0x4002978D793F9CA4ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD968D7E659C02758ULL,
			0xE46F7CE3CA109F70ULL,
			0xBA9B881909BAAB82ULL,
			0x4002978D793F9CA4ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4D404FA76AA853F9ULL,
			0xD6C68CEEAC8FA5CEULL,
			0xEC9FF8CFBB5DADAAULL,
			0x1DEEA0CBE8FA8004ULL}
		},
		.Z = {.key64 = {
			0x5BDC90FF438ED4C0ULL,
			0x2581D62E57324D68ULL,
			0xEB486055F4B022E1ULL,
			0x166FEA5BA279A88CULL}
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

	steps = 20;
	X1 = (curve25519_key_t){.key64 = {
		0x602F2023C7FCC250ULL,
		0x0C7C167276E5AB93ULL,
		0x3941A7DDAF9FCB5BULL,
		0x6DB8127527DA74FDULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x602F2023C7FCC250ULL,
			0x0C7C167276E5AB93ULL,
			0x3941A7DDAF9FCB5BULL,
			0x6DB8127527DA74FDULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x27D53EB9335D7C2FULL,
			0x84DFAD1D0A4EE1CAULL,
			0x6DC60F1E87CC1F3EULL,
			0x7A1D665BE8A8B453ULL}
		},
		.Z = {.key64 = {
			0x605B94CD3107140CULL,
			0x4248A1949D009CB1ULL,
			0x40732DDD350EBA81ULL,
			0x7379F44E8B4D1B4BULL}
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

	steps = 13;
	X1 = (curve25519_key_t){.key64 = {
		0xF3815CE9C4939620ULL,
		0x625F0C22B42890ADULL,
		0x70EBC530802AF732ULL,
		0x749DF9368E7BC0E2ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF3815CE9C4939620ULL,
			0x625F0C22B42890ADULL,
			0x70EBC530802AF732ULL,
			0x749DF9368E7BC0E2ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xACB0B30B56C6AA59ULL,
			0xB679E0062024904AULL,
			0x1E5D43372AC59A56ULL,
			0x429C306F6E17D6BBULL}
		},
		.Z = {.key64 = {
			0xA56D85300B203DAEULL,
			0x44C6286D00467206ULL,
			0x3F37AA70DE68AC0DULL,
			0x5E4CACFCD765D74BULL}
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

	steps = 45;
	X1 = (curve25519_key_t){.key64 = {
		0xB8FA8AC8E0F67600ULL,
		0x09FEE8EB7B92021DULL,
		0x18F8B57DFC0FFCE0ULL,
		0x43D90246A8D0C23CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB8FA8AC8E0F67600ULL,
			0x09FEE8EB7B92021DULL,
			0x18F8B57DFC0FFCE0ULL,
			0x43D90246A8D0C23CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x90F2498D90C916F4ULL,
			0xCF60A63A96608A1FULL,
			0x1227B960EDBEE79FULL,
			0x6EB26894DFC8203BULL}
		},
		.Z = {.key64 = {
			0xDEB5C3708DE619B0ULL,
			0x7D2EBB1E30E32017ULL,
			0x05284085F3C4765EULL,
			0x7EF5B55880CD4532ULL}
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

	steps = 61;
	X1 = (curve25519_key_t){.key64 = {
		0x90772422A1E9D250ULL,
		0x5CF75B757EE2562BULL,
		0x8221D8F7D92D8EFDULL,
		0x559318909D604453ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x90772422A1E9D250ULL,
			0x5CF75B757EE2562BULL,
			0x8221D8F7D92D8EFDULL,
			0x559318909D604453ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2B28D6518C1EA6F7ULL,
			0x327CBB5F640DB06EULL,
			0x20B30F16D62274A1ULL,
			0x73EAE254F818051DULL}
		},
		.Z = {.key64 = {
			0x7603F61AD48A3D86ULL,
			0x44759AF74459C205ULL,
			0xA3808C6F619C548DULL,
			0x62A355EF3405862AULL}
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

	steps = 35;
	X1 = (curve25519_key_t){.key64 = {
		0x973E3D7B762CBF10ULL,
		0x2CCAAEF404B0C156ULL,
		0xEAC86F2FAAA89A49ULL,
		0x5B4525FE3C04D77DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x973E3D7B762CBF10ULL,
			0x2CCAAEF404B0C156ULL,
			0xEAC86F2FAAA89A49ULL,
			0x5B4525FE3C04D77DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4B9E28DD56FC570FULL,
			0x737D590EB7CF0949ULL,
			0x84C2EFFDE9CFC710ULL,
			0x6AE56F1D3FCD7216ULL}
		},
		.Z = {.key64 = {
			0xA6807D147845D964ULL,
			0xD0221B72FE73CCEBULL,
			0x4251DB3E0D0691FBULL,
			0x0E7A1E63C4AFB006ULL}
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

	steps = 53;
	X1 = (curve25519_key_t){.key64 = {
		0xA4F166A61EEA9818ULL,
		0x864C19CCD078CCF7ULL,
		0xFE7CE148E432DA09ULL,
		0x77D37CCD1E2B959EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA4F166A61EEA9818ULL,
			0x864C19CCD078CCF7ULL,
			0xFE7CE148E432DA09ULL,
			0x77D37CCD1E2B959EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE435E8E7FC889363ULL,
			0xE81351F6D07E23C3ULL,
			0x9E14697ACF59CF34ULL,
			0x46006378C03AA389ULL}
		},
		.Z = {.key64 = {
			0x42C7615885806584ULL,
			0xBBD0E7FEC714385FULL,
			0x0BE8F9AC62C197C7ULL,
			0x484E97AB1BAA2789ULL}
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

	steps = 22;
	X1 = (curve25519_key_t){.key64 = {
		0x5AB80097356ECC80ULL,
		0x2181AA1C59560C22ULL,
		0x979C34D1F7FF0B4EULL,
		0x7359B14773245D8AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5AB80097356ECC80ULL,
			0x2181AA1C59560C22ULL,
			0x979C34D1F7FF0B4EULL,
			0x7359B14773245D8AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5E41503CA5491FCBULL,
			0x5CAC907389B11721ULL,
			0xAD27770EC1A51FE6ULL,
			0x3CB034A831133EB0ULL}
		},
		.Z = {.key64 = {
			0x4A305D82830CBD0EULL,
			0xC1B39BC9E8A5D3F4ULL,
			0xD5E70DE4EBFBB1D8ULL,
			0x017860CF8FC48039ULL}
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

	steps = 63;
	X1 = (curve25519_key_t){.key64 = {
		0x61011AE96A70C968ULL,
		0x6ED5B6F80BFCEF04ULL,
		0xA8DEA7CCF7C0E2CCULL,
		0x5659B13A85063E66ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x61011AE96A70C968ULL,
			0x6ED5B6F80BFCEF04ULL,
			0xA8DEA7CCF7C0E2CCULL,
			0x5659B13A85063E66ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2AF2376053F3E523ULL,
			0x116C008502146449ULL,
			0x8236B9ECC1CA3307ULL,
			0x46DB05C3DB75134AULL}
		},
		.Z = {.key64 = {
			0xB57A080CE380151EULL,
			0x90A03C666460F81CULL,
			0x92209510DFBFA723ULL,
			0x56298AB4708305EAULL}
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

	steps = 10;
	X1 = (curve25519_key_t){.key64 = {
		0xD326F5633EF81A08ULL,
		0xE7E7E134492B05F8ULL,
		0x8FB1062F7931B4EDULL,
		0x41013E3E3187F89EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD326F5633EF81A08ULL,
			0xE7E7E134492B05F8ULL,
			0x8FB1062F7931B4EDULL,
			0x41013E3E3187F89EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x06AD82A2F309205DULL,
			0xE64CDBB0AE6E8D97ULL,
			0xA2C505A1C59FE3F0ULL,
			0x20E173B7FD0EA049ULL}
		},
		.Z = {.key64 = {
			0xE37DEA79C2E74D14ULL,
			0x81D6E97CDEFB6C58ULL,
			0xB4567C19704A56A8ULL,
			0x0B07C12BF7C31B7EULL}
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

	steps = 27;
	X1 = (curve25519_key_t){.key64 = {
		0xD7C967801FDFF2B8ULL,
		0x4851230039B8E79DULL,
		0xD9E96FC2FD595370ULL,
		0x7764638A9223099FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD7C967801FDFF2B8ULL,
			0x4851230039B8E79DULL,
			0xD9E96FC2FD595370ULL,
			0x7764638A9223099FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xED659962667C37FAULL,
			0x4A78ACABFEF5C8BAULL,
			0x95171F1016A5ABC6ULL,
			0x30A7FC379CBF45DCULL}
		},
		.Z = {.key64 = {
			0x5837CAAA4D4A12B1ULL,
			0x517AD9DE35B8D089ULL,
			0xBCF181467FD656B3ULL,
			0x6AF390E4A6C7675BULL}
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

	steps = 12;
	X1 = (curve25519_key_t){.key64 = {
		0x21C5A3DC7D356FD8ULL,
		0x8B4F197657C9182BULL,
		0x996FF55DC770381EULL,
		0x57A0BE1BF5B52FD5ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x21C5A3DC7D356FD8ULL,
			0x8B4F197657C9182BULL,
			0x996FF55DC770381EULL,
			0x57A0BE1BF5B52FD5ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8994878011ECAD19ULL,
			0x38E4F0C8552EE816ULL,
			0xE84F27D2B9E07AECULL,
			0x4948A38264CA6AB8ULL}
		},
		.Z = {.key64 = {
			0x6D213E74CA3FDABDULL,
			0xF3BE8E1B8940083AULL,
			0x13285C90FE4FBAE6ULL,
			0x73D71F0E143AD51DULL}
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

	steps = 58;
	X1 = (curve25519_key_t){.key64 = {
		0x9BF37FBD340347D8ULL,
		0xA3504AF9E0E25FCEULL,
		0xBA0BD7993CF1F04BULL,
		0x456614AA03C96A0CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9BF37FBD340347D8ULL,
			0xA3504AF9E0E25FCEULL,
			0xBA0BD7993CF1F04BULL,
			0x456614AA03C96A0CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9BE154CC9694F6D3ULL,
			0x297B3F57A84EF018ULL,
			0x7EF84002FD7325C8ULL,
			0x3A010C75E6C1F69DULL}
		},
		.Z = {.key64 = {
			0x85CE3A4690507E42ULL,
			0x2791846DB22D5CC4ULL,
			0xDB40F96E786612FAULL,
			0x6637339784E0B26BULL}
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
		0xBE13BE7CFCF084F8ULL,
		0xAD1572F44BA8CE07ULL,
		0x1057EC5A3F907263ULL,
		0x519CE95B5DF35E21ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBE13BE7CFCF084F8ULL,
			0xAD1572F44BA8CE07ULL,
			0x1057EC5A3F907263ULL,
			0x519CE95B5DF35E21ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA20BF64EE3AB0D54ULL,
			0x12D7E17745822894ULL,
			0xA07895FE0EFD3FF8ULL,
			0x5988FC4E8850C58FULL}
		},
		.Z = {.key64 = {
			0xCF0C1F79D719274BULL,
			0x0996E471F718DF55ULL,
			0xC1F56081D1B100A2ULL,
			0x5602EA0E2D6EE38FULL}
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

	steps = 27;
	X1 = (curve25519_key_t){.key64 = {
		0xA8113BCA97F5DBD0ULL,
		0x468E49B9E6C0C826ULL,
		0xB9687B562AD455F6ULL,
		0x6CFBF6178251D168ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA8113BCA97F5DBD0ULL,
			0x468E49B9E6C0C826ULL,
			0xB9687B562AD455F6ULL,
			0x6CFBF6178251D168ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC0572C56450E4805ULL,
			0xE12B899323230F3BULL,
			0x1C79E138D36EC38EULL,
			0x53898AA6B0DC65B9ULL}
		},
		.Z = {.key64 = {
			0x1E59DE4FAE93BB51ULL,
			0x060E296B87FDF368ULL,
			0x26DDFF44516690C3ULL,
			0x21E2C5E18244C589ULL}
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

	steps = 41;
	X1 = (curve25519_key_t){.key64 = {
		0x7A1FB5219FA34328ULL,
		0x1AECC79818CFBFB9ULL,
		0x9A8ACC1DB8D7ACA9ULL,
		0x7CD2F2FCFC1C2600ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7A1FB5219FA34328ULL,
			0x1AECC79818CFBFB9ULL,
			0x9A8ACC1DB8D7ACA9ULL,
			0x7CD2F2FCFC1C2600ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB1DBC2676C68176BULL,
			0xD75CE5F05A2EF12FULL,
			0xE680C5E11AC79DDFULL,
			0x1EF3BDB9B1A801C6ULL}
		},
		.Z = {.key64 = {
			0x2C68A3A41AC0F9E1ULL,
			0x2DAE3803D6944446ULL,
			0x14C41D400E85B23FULL,
			0x6C56FE227B760FBDULL}
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

	steps = 59;
	X1 = (curve25519_key_t){.key64 = {
		0x36EE538BDA82C758ULL,
		0xC7729E772D5C85CCULL,
		0x7E1A09139FED9F0FULL,
		0x47827D8995BD9B51ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x36EE538BDA82C758ULL,
			0xC7729E772D5C85CCULL,
			0x7E1A09139FED9F0FULL,
			0x47827D8995BD9B51ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x80F46E44CAB5B689ULL,
			0x6C9DBFCB2AE5A534ULL,
			0x2A0A1DC37EA2023DULL,
			0x68C683959987ED6CULL}
		},
		.Z = {.key64 = {
			0x2603EA81A667F79CULL,
			0x14B93B7BF2C463AFULL,
			0xB86F0A15FB027523ULL,
			0x73299D2CD34D8E1CULL}
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

	steps = 46;
	X1 = (curve25519_key_t){.key64 = {
		0x93A266209EF73DD8ULL,
		0xC6618A56B754FAB4ULL,
		0x83DD61D550519419ULL,
		0x4D32EB79E6462EEBULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x93A266209EF73DD8ULL,
			0xC6618A56B754FAB4ULL,
			0x83DD61D550519419ULL,
			0x4D32EB79E6462EEBULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8F47C0CB37A1A838ULL,
			0x9333CB037AC4783CULL,
			0x28B0ECB8B6DAE2EBULL,
			0x6D06DD78D934F90EULL}
		},
		.Z = {.key64 = {
			0x86C5632402CA6CB2ULL,
			0xD02BED5C9503193FULL,
			0x2551525C9026B6ECULL,
			0x418A6D360B878D3FULL}
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

	steps = 60;
	X1 = (curve25519_key_t){.key64 = {
		0x0E1D844DE3205D08ULL,
		0x77D6CA1C0A9E047BULL,
		0xC894A8A7AABD9863ULL,
		0x42F30BC772280AA5ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0E1D844DE3205D08ULL,
			0x77D6CA1C0A9E047BULL,
			0xC894A8A7AABD9863ULL,
			0x42F30BC772280AA5ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x61E6B68A188F651EULL,
			0xBBA85DAEE760AB9FULL,
			0xC1062E8F69143B00ULL,
			0x604F871661800941ULL}
		},
		.Z = {.key64 = {
			0x2B1548A3D5A763E3ULL,
			0xB6F613A111DAE936ULL,
			0xEC3E28EC82209338ULL,
			0x4E53351AF2AA6AD2ULL}
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

	steps = 40;
	X1 = (curve25519_key_t){.key64 = {
		0xA49FE68BE1CE26C0ULL,
		0x56917CA156F1F6DBULL,
		0xE56CEBC5A536E3CFULL,
		0x42DC6938785F970BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA49FE68BE1CE26C0ULL,
			0x56917CA156F1F6DBULL,
			0xE56CEBC5A536E3CFULL,
			0x42DC6938785F970BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC170475A836FDC1AULL,
			0x48249DB2D56E1B11ULL,
			0xBC848576834054D9ULL,
			0x2A9A03E058F353CDULL}
		},
		.Z = {.key64 = {
			0x6E15D93FFA203A0FULL,
			0x397BC9288DB1DC42ULL,
			0x2BDD2006987BA2C3ULL,
			0x68A5EA9BC8675B71ULL}
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

	steps = 40;
	X1 = (curve25519_key_t){.key64 = {
		0x409BB59B32F96190ULL,
		0xCA7C8BEC2A934FFDULL,
		0xA8876F6C2E60C852ULL,
		0x56AC5F76100EE71DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x409BB59B32F96190ULL,
			0xCA7C8BEC2A934FFDULL,
			0xA8876F6C2E60C852ULL,
			0x56AC5F76100EE71DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x25363E3E5E5305E8ULL,
			0x5A886DDDF3BB09D2ULL,
			0x0034516255842BB8ULL,
			0x0AD0401DB502E935ULL}
		},
		.Z = {.key64 = {
			0x7F8849FFEC2FDC53ULL,
			0x5CDA51F09B3899FFULL,
			0xDF4D307B3671B042ULL,
			0x13E2BB1FD422B993ULL}
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

	steps = 48;
	X1 = (curve25519_key_t){.key64 = {
		0x5725FDA1D82877C0ULL,
		0x9C13EE6F237E0921ULL,
		0x0F625BB062609C8BULL,
		0x4F5F9BB50FCE56DAULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5725FDA1D82877C0ULL,
			0x9C13EE6F237E0921ULL,
			0x0F625BB062609C8BULL,
			0x4F5F9BB50FCE56DAULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD81E519C9BE8D48FULL,
			0xD4A5A156B88EAB64ULL,
			0x4D20CBF9E848862EULL,
			0x194FCE3D43E77725ULL}
		},
		.Z = {.key64 = {
			0x5F8AFADA2E7BCCA8ULL,
			0x4CA05B1EED6611C0ULL,
			0xDD4D8EAFAE8F0F8DULL,
			0x4A592850A7682A36ULL}
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

	steps = 55;
	X1 = (curve25519_key_t){.key64 = {
		0x6A2A8AB8D5FE7D58ULL,
		0x3D239A648E130E2DULL,
		0x79817ACE46D878F0ULL,
		0x4729C9CE743667F3ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6A2A8AB8D5FE7D58ULL,
			0x3D239A648E130E2DULL,
			0x79817ACE46D878F0ULL,
			0x4729C9CE743667F3ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE939C3908B9B5A94ULL,
			0x6994F6F732132F25ULL,
			0x5B6E46CD97DD0CFDULL,
			0x2EF17B87CAF7468DULL}
		},
		.Z = {.key64 = {
			0xBDD7E9AF5D8E69B0ULL,
			0xE44C0FD8B9E303D7ULL,
			0xD3A5BCCD0067A91BULL,
			0x336F6583F9446755ULL}
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

	steps = 20;
	X1 = (curve25519_key_t){.key64 = {
		0x5219E0502067DB58ULL,
		0xA293350B31E0E537ULL,
		0x27531EB7F8917AA1ULL,
		0x71E94C3AE6E781D6ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5219E0502067DB58ULL,
			0xA293350B31E0E537ULL,
			0x27531EB7F8917AA1ULL,
			0x71E94C3AE6E781D6ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x04E45F56A68F60C3ULL,
			0x29F13BD47FC0B8A7ULL,
			0x8AFE7ADB5C2BD6DEULL,
			0x0A1AA9F36549E5C3ULL}
		},
		.Z = {.key64 = {
			0x27E19864732C3C19ULL,
			0x711BD7F052963AB4ULL,
			0x98E8A2CF3531670DULL,
			0x6793A592D91A29A6ULL}
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

	steps = 2;
	X1 = (curve25519_key_t){.key64 = {
		0x67CEE80AB28D4CE8ULL,
		0x6EDF8985BF35DD44ULL,
		0xA92035020D1768BEULL,
		0x4C457C135DC594B3ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x67CEE80AB28D4CE8ULL,
			0x6EDF8985BF35DD44ULL,
			0xA92035020D1768BEULL,
			0x4C457C135DC594B3ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0D601AB47B335A9AULL,
			0xB0EC3F243853E20CULL,
			0x7BEFADA552BD7CB3ULL,
			0x3A34CFF535FB0BF0ULL}
		},
		.Z = {.key64 = {
			0x99C6A59614781F5BULL,
			0x766053C0978DAC0BULL,
			0xB557D97018E07947ULL,
			0x13BBA9DE3FC50E5FULL}
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

	steps = 61;
	X1 = (curve25519_key_t){.key64 = {
		0x386F449A0911F308ULL,
		0xC92C4728D40EE672ULL,
		0x3838FAE545E3E902ULL,
		0x65618F823F30CC79ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x386F449A0911F308ULL,
			0xC92C4728D40EE672ULL,
			0x3838FAE545E3E902ULL,
			0x65618F823F30CC79ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8BA6BD98E0B94E00ULL,
			0x074226708EA5B130ULL,
			0xBA3BF4A867303226ULL,
			0x7746BD21CEACC5C9ULL}
		},
		.Z = {.key64 = {
			0xE93FB11207551BC8ULL,
			0xDF1F01AE4B137A33ULL,
			0x7201780D4817EB82ULL,
			0x101D7A32DD46AD85ULL}
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

	steps = 1;
	X1 = (curve25519_key_t){.key64 = {
		0x371463A979F1CC50ULL,
		0x8EE9EA3AADC4FE92ULL,
		0xE161D654FBE7ABD6ULL,
		0x69FBD9D2C03E773CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x371463A979F1CC50ULL,
			0x8EE9EA3AADC4FE92ULL,
			0xE161D654FBE7ABD6ULL,
			0x69FBD9D2C03E773CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE92E3C2887FA8292ULL,
			0x173C2367FA58CE4EULL,
			0x5385318FC916D53BULL,
			0x7DBE8037E737BA7FULL}
		},
		.Z = {.key64 = {
			0xDC518EA5E7C73179ULL,
			0x3BA7A8EAB713FA48ULL,
			0x85875953EF9EAF5AULL,
			0x27EF674B00F9DCF3ULL}
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

	steps = 50;
	X1 = (curve25519_key_t){.key64 = {
		0xF1930716430CF8F0ULL,
		0x398887CBEBA0FDA0ULL,
		0x2BD21FD4D5D22D14ULL,
		0x6E3D6C180B19EB3EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF1930716430CF8F0ULL,
			0x398887CBEBA0FDA0ULL,
			0x2BD21FD4D5D22D14ULL,
			0x6E3D6C180B19EB3EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x40DE3EFF1AD1C9D7ULL,
			0xE110A42917AB314FULL,
			0x0FC1832BA8811BB3ULL,
			0x72569A84FF152B96ULL}
		},
		.Z = {.key64 = {
			0xBAE5264CE7E5AE4FULL,
			0x1B97FA84448DC5C4ULL,
			0xA01D08CC7DE5DFAEULL,
			0x754EFB6C2653279BULL}
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

	steps = 52;
	X1 = (curve25519_key_t){.key64 = {
		0x982DF069901C48A0ULL,
		0x6A21304DCE5787B2ULL,
		0x355BD13E96E8F60EULL,
		0x445AF86C1F02A860ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x982DF069901C48A0ULL,
			0x6A21304DCE5787B2ULL,
			0x355BD13E96E8F60EULL,
			0x445AF86C1F02A860ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x81B56079E1357221ULL,
			0x1AF3F804F4EAB8D6ULL,
			0xF131B7D1AB310909ULL,
			0x7A873A78DF1F5A64ULL}
		},
		.Z = {.key64 = {
			0x2B8366DF8A630FEEULL,
			0xE331BC4BE74C6621ULL,
			0x68D04FC4BB7691D2ULL,
			0x5AA85FE15384F6DDULL}
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

	steps = 54;
	X1 = (curve25519_key_t){.key64 = {
		0xF23014E93C5079F8ULL,
		0xF05E3F1C44D0D073ULL,
		0x15994BF383DAA697ULL,
		0x79CE83C2F22FF878ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF23014E93C5079F8ULL,
			0xF05E3F1C44D0D073ULL,
			0x15994BF383DAA697ULL,
			0x79CE83C2F22FF878ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6F81BBFE04337B86ULL,
			0xA61B1AE37CBCF1C9ULL,
			0x7EBE7BA67DB6FF2DULL,
			0x449173D65E2B5314ULL}
		},
		.Z = {.key64 = {
			0x261D54F2523AE1C1ULL,
			0xA7677E3450AF6F96ULL,
			0x36BDFA41A61D68EFULL,
			0x5069CC44F416D072ULL}
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

	steps = 35;
	X1 = (curve25519_key_t){.key64 = {
		0x1A76E5D4D85AC5A8ULL,
		0xC05C030379FDDC0AULL,
		0x98A46A921EF84E24ULL,
		0x7000225A12BB2608ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1A76E5D4D85AC5A8ULL,
			0xC05C030379FDDC0AULL,
			0x98A46A921EF84E24ULL,
			0x7000225A12BB2608ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC0ACECA908E7AB05ULL,
			0x5086442E39A300A5ULL,
			0x95CBA22ECBBFED31ULL,
			0x0A5633854C5210C4ULL}
		},
		.Z = {.key64 = {
			0x841CC810E04337FCULL,
			0xEF94ED1FCC9D655AULL,
			0x40F701D37BA9B74CULL,
			0x1D4300DC28574D04ULL}
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

	steps = 4;
	X1 = (curve25519_key_t){.key64 = {
		0xA97DE160EE4C5ED0ULL,
		0x30C348F66859FDAFULL,
		0x081C7AC9A7FB25DCULL,
		0x76A449D1BC4571FDULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA97DE160EE4C5ED0ULL,
			0x30C348F66859FDAFULL,
			0x081C7AC9A7FB25DCULL,
			0x76A449D1BC4571FDULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x22AAC3C0A758DE5DULL,
			0x4B95ED868D15C186ULL,
			0x6ED235C576133B32ULL,
			0x023D6AB3433400A0ULL}
		},
		.Z = {.key64 = {
			0xFA37FD6D91F097EDULL,
			0xF30CB736E149252DULL,
			0x702E61C2CA868F65ULL,
			0x4B7162E49A77E601ULL}
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

	steps = 56;
	X1 = (curve25519_key_t){.key64 = {
		0xFF0E4B691E22B6F8ULL,
		0x2C72D557D4F72D5DULL,
		0x10B148C7A2BE5B8BULL,
		0x63B8CCCF9CA44B19ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFF0E4B691E22B6F8ULL,
			0x2C72D557D4F72D5DULL,
			0x10B148C7A2BE5B8BULL,
			0x63B8CCCF9CA44B19ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9B7FD65A769F579CULL,
			0x01A3314380CACD2FULL,
			0x6FCEE0851EFDA93FULL,
			0x01E7F5C0EA7C27BFULL}
		},
		.Z = {.key64 = {
			0xB1987F6A51D86317ULL,
			0x9D9DE45229111698ULL,
			0xA80B06B0457273C0ULL,
			0x6C1A57009F3B90C3ULL}
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

	steps = 2;
	X1 = (curve25519_key_t){.key64 = {
		0xCFF868140559A070ULL,
		0xACB57E55B647B0A8ULL,
		0x5367B5F4CAD0FF9DULL,
		0x48AC4C3B276BF628ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCFF868140559A070ULL,
			0xACB57E55B647B0A8ULL,
			0x5367B5F4CAD0FF9DULL,
			0x48AC4C3B276BF628ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3D5C5E5548AD2A5EULL,
			0x062093DB017AAAE7ULL,
			0x5CBB782DA7439260ULL,
			0x496DA19AAC2A6959ULL}
		},
		.Z = {.key64 = {
			0xB82574111095F55FULL,
			0x1B8A5DF81AFC74CBULL,
			0x7574B7A0C7C4638BULL,
			0x4CDFEB5FE85DFB12ULL}
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

	steps = 45;
	X1 = (curve25519_key_t){.key64 = {
		0x26FABDDA11B5AAB0ULL,
		0xD295B68EE26F6F9EULL,
		0x24239B853C2D40D4ULL,
		0x738D0E65AB1DB67BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x26FABDDA11B5AAB0ULL,
			0xD295B68EE26F6F9EULL,
			0x24239B853C2D40D4ULL,
			0x738D0E65AB1DB67BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5359C83C5D997358ULL,
			0x5B3C6B2787B73FDDULL,
			0x4CB637D1AB71F9BAULL,
			0x7FEB1B29BFB00A75ULL}
		},
		.Z = {.key64 = {
			0x8E5FDEC5DB1C235CULL,
			0x1B984B4EB42B8686ULL,
			0x6C549BAA64C99020ULL,
			0x5CDE918F469A5F40ULL}
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

	steps = 33;
	X1 = (curve25519_key_t){.key64 = {
		0x4988FA2089D16670ULL,
		0x663517D8483E9F22ULL,
		0x3BBDF70002B26C53ULL,
		0x45E3F99CDE104906ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4988FA2089D16670ULL,
			0x663517D8483E9F22ULL,
			0x3BBDF70002B26C53ULL,
			0x45E3F99CDE104906ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x740005C5CAB376FEULL,
			0xF0DE1263F215B719ULL,
			0xF7B1B5871D714639ULL,
			0x260944A6B75DD674ULL}
		},
		.Z = {.key64 = {
			0x8719E25B56651FDBULL,
			0x42D2CBB1CECA561FULL,
			0x0AB6234B9BADD5B7ULL,
			0x1D5F11674C6537EFULL}
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

	steps = 1;
	X1 = (curve25519_key_t){.key64 = {
		0x793487C523DB0810ULL,
		0xDA1D7CF3FD28946EULL,
		0x892C39B9A5015F24ULL,
		0x416FBAEB64C0FE3AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x793487C523DB0810ULL,
			0xDA1D7CF3FD28946EULL,
			0x892C39B9A5015F24ULL,
			0x416FBAEB64C0FE3AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x205E732FF366438BULL,
			0x2EF0B285A617A93DULL,
			0x0B695483408E71EFULL,
			0x5F4D485F9D43A129ULL}
		},
		.Z = {.key64 = {
			0xE4D21F148F6C2066ULL,
			0x6875F3CFF4A251B9ULL,
			0x24B0E6E694057C93ULL,
			0x05BEEBAD9303F8EAULL}
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

	steps = 11;
	X1 = (curve25519_key_t){.key64 = {
		0x7FC32F61652A4500ULL,
		0xE2E39156B1044B8AULL,
		0xB8B01AE0090E09F3ULL,
		0x4836E728A1567C75ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7FC32F61652A4500ULL,
			0xE2E39156B1044B8AULL,
			0xB8B01AE0090E09F3ULL,
			0x4836E728A1567C75ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE557B46C8573A0EEULL,
			0x0DF168037A3A7C87ULL,
			0x79577E6DFA968BE5ULL,
			0x65E700DE2FC36293ULL}
		},
		.Z = {.key64 = {
			0xB7DE0DF19D34ED46ULL,
			0xE30BB4201EB2E99AULL,
			0xE4E5A531CB2407DDULL,
			0x5B6A41FC1C8E451DULL}
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

	steps = 26;
	X1 = (curve25519_key_t){.key64 = {
		0xCBE42203B36AB6F8ULL,
		0xC13C5503907C0126ULL,
		0x7B80363460A76BDDULL,
		0x7FBFA441A72A7233ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCBE42203B36AB6F8ULL,
			0xC13C5503907C0126ULL,
			0x7B80363460A76BDDULL,
			0x7FBFA441A72A7233ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xADE05A9501228A58ULL,
			0x0DDEF468344410C0ULL,
			0x80FB27C53F879B04ULL,
			0x5E35FA329D1DCBD2ULL}
		},
		.Z = {.key64 = {
			0xD0F152D7BB637FE1ULL,
			0x99061CDB4A3628B5ULL,
			0xA278F147FDF7D7F0ULL,
			0x6D0E47F451C1FB3FULL}
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

	steps = 52;
	X1 = (curve25519_key_t){.key64 = {
		0xEEFD09A1A09EE948ULL,
		0xCFE94E37F0882204ULL,
		0x60474F64C53F566BULL,
		0x516EBA30C7F37702ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEEFD09A1A09EE948ULL,
			0xCFE94E37F0882204ULL,
			0x60474F64C53F566BULL,
			0x516EBA30C7F37702ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFEB7347659C6BBB8ULL,
			0x432BE25B8F2E14B4ULL,
			0x499F633574754D00ULL,
			0x6BF867F5F11E62D5ULL}
		},
		.Z = {.key64 = {
			0x30281226635E7DA3ULL,
			0xF52E0553C254C006ULL,
			0xC6CE52CF97DB568EULL,
			0x54FFF1A648F3D125ULL}
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

	steps = 50;
	X1 = (curve25519_key_t){.key64 = {
		0xD510C25A5CBD9B60ULL,
		0x3DE59FF9FDA6C0CAULL,
		0xCE3D1FCD6ECDF73CULL,
		0x7AFC8DAE90C43B6CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD510C25A5CBD9B60ULL,
			0x3DE59FF9FDA6C0CAULL,
			0xCE3D1FCD6ECDF73CULL,
			0x7AFC8DAE90C43B6CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBE39DD2C6F12BBA0ULL,
			0x9AC17F42F734BFDDULL,
			0x562D4E79713153C4ULL,
			0x147A1F4296F64153ULL}
		},
		.Z = {.key64 = {
			0xB33E2010B8F25EB7ULL,
			0x98EA509B12EF6C43ULL,
			0xAB6DCCD1E2EDA1C8ULL,
			0x18A97687DB57AC8CULL}
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

	steps = 6;
	X1 = (curve25519_key_t){.key64 = {
		0x10D9F832902DEFD8ULL,
		0x3C60D29506882941ULL,
		0xB9C978368831F048ULL,
		0x5097480E4A2D4C60ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x10D9F832902DEFD8ULL,
			0x3C60D29506882941ULL,
			0xB9C978368831F048ULL,
			0x5097480E4A2D4C60ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB177A139A111F24DULL,
			0x8FE232153A678AD0ULL,
			0x13659C94959DCAE6ULL,
			0x0107B03443E956C3ULL}
		},
		.Z = {.key64 = {
			0x2F7D3BED5F61158FULL,
			0xD395A102B7693407ULL,
			0x6F3016DBCAE55329ULL,
			0x1EA992A3D0F4F930ULL}
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

	steps = 33;
	X1 = (curve25519_key_t){.key64 = {
		0x70D3F2D3212CCAE8ULL,
		0x4DFC0BF156C057ADULL,
		0x293EC68BB9EDD712ULL,
		0x58B0D9B81868C713ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x70D3F2D3212CCAE8ULL,
			0x4DFC0BF156C057ADULL,
			0x293EC68BB9EDD712ULL,
			0x58B0D9B81868C713ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFE89DBADA2FA86C3ULL,
			0x51A76AD978F0942DULL,
			0x7DFC224DE9C2145BULL,
			0x076DA51E8C57A003ULL}
		},
		.Z = {.key64 = {
			0x61871F6F5C4D79B1ULL,
			0xDBCC03098833B33BULL,
			0xB9EC3B3E48099A4FULL,
			0x095D5623C8635F22ULL}
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

	steps = 46;
	X1 = (curve25519_key_t){.key64 = {
		0x18962047A461B1F8ULL,
		0x11700AB40C3F76DAULL,
		0x26DE776A39D79BD1ULL,
		0x60D5DA0FEF886030ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x18962047A461B1F8ULL,
			0x11700AB40C3F76DAULL,
			0x26DE776A39D79BD1ULL,
			0x60D5DA0FEF886030ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x02A537FB2A78290EULL,
			0xA436F0C0BD92AADCULL,
			0xC365137F76F6DA75ULL,
			0x11F3F693ED94D4EFULL}
		},
		.Z = {.key64 = {
			0xCBCCA94A1670F2E7ULL,
			0x8E76826D8D976578ULL,
			0xE486CC9D73C3F4C8ULL,
			0x5D1AA1CAA96825E7ULL}
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

	steps = 50;
	X1 = (curve25519_key_t){.key64 = {
		0xF37EA851B26BE118ULL,
		0x8BB50DAC00F0DC60ULL,
		0x91A2DB649ED2981CULL,
		0x7E6C11AC457623BCULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF37EA851B26BE118ULL,
			0x8BB50DAC00F0DC60ULL,
			0x91A2DB649ED2981CULL,
			0x7E6C11AC457623BCULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE212C0B397047FE1ULL,
			0xD6D0DE0947188285ULL,
			0x8BCBA1B486ADA07AULL,
			0x0ED0E24F00714974ULL}
		},
		.Z = {.key64 = {
			0x8A7DF2E44ABE2451ULL,
			0xC0DD9DB183A7124FULL,
			0xBB83CF2B3FDE429BULL,
			0x5B305E0E885B70E7ULL}
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

	steps = 7;
	X1 = (curve25519_key_t){.key64 = {
		0xA7D8DC67914643B0ULL,
		0xB38A26931171E2B8ULL,
		0x57EBC8ACCE1F9AAFULL,
		0x5F6FCDF174AAA6C0ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA7D8DC67914643B0ULL,
			0xB38A26931171E2B8ULL,
			0x57EBC8ACCE1F9AAFULL,
			0x5F6FCDF174AAA6C0ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB9DE2B83151C2D2AULL,
			0x1EABC62AF5863E27ULL,
			0x49F40FB7EFB47AFFULL,
			0x470B7F333537EAECULL}
		},
		.Z = {.key64 = {
			0xDAF460890CD73847ULL,
			0x00B81BB4C00339DCULL,
			0xDE11009BB6F805A1ULL,
			0x2B095F85DDC23A18ULL}
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

	steps = 25;
	X1 = (curve25519_key_t){.key64 = {
		0xC896205DC1CC9708ULL,
		0x324C3589648027F1ULL,
		0xDE2E3BB581605D0DULL,
		0x72146E7C067507DAULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC896205DC1CC9708ULL,
			0x324C3589648027F1ULL,
			0xDE2E3BB581605D0DULL,
			0x72146E7C067507DAULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFE464DAA26457DDAULL,
			0x09F95714D4F0F944ULL,
			0x18FA4F706D4D838BULL,
			0x1D8FC0D99B37965AULL}
		},
		.Z = {.key64 = {
			0x850E7544907A5F4EULL,
			0xB12E77559D58C707ULL,
			0x28B3A42A819B6484ULL,
			0x2D462C0E74F4AD75ULL}
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

	steps = 13;
	X1 = (curve25519_key_t){.key64 = {
		0x2E680496C00E95E8ULL,
		0xC823CD33B1AF3BADULL,
		0x7BE0E7AFCBDBAC50ULL,
		0x48E3AF7BE5C0F899ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2E680496C00E95E8ULL,
			0xC823CD33B1AF3BADULL,
			0x7BE0E7AFCBDBAC50ULL,
			0x48E3AF7BE5C0F899ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6406F894272958C7ULL,
			0x1E2E522B587E9DD8ULL,
			0x7BECAACB650E2B9DULL,
			0x2DC1A4E07F5ED515ULL}
		},
		.Z = {.key64 = {
			0x991F3EDAA139A36FULL,
			0x5A79931EF752E5EEULL,
			0x766A456440CA6ECDULL,
			0x33D6D951D780B206ULL}
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

	steps = 45;
	X1 = (curve25519_key_t){.key64 = {
		0xB3623BD69D87F048ULL,
		0xE742F5369FA4DB77ULL,
		0x515B4C6F02CF115BULL,
		0x4C803F2CAC3A3FB5ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB3623BD69D87F048ULL,
			0xE742F5369FA4DB77ULL,
			0x515B4C6F02CF115BULL,
			0x4C803F2CAC3A3FB5ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDB003F83DF04FB01ULL,
			0x1EBD738540B56871ULL,
			0x1165EE8EDA16CCE8ULL,
			0x478BF390882292C7ULL}
		},
		.Z = {.key64 = {
			0x891278AC8D3F3EAEULL,
			0x6C204CDECC73B5F8ULL,
			0xA45A5D7CBE7202BDULL,
			0x6BAE415E9B33434AULL}
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

	steps = 10;
	X1 = (curve25519_key_t){.key64 = {
		0x46AB50EB1BD127E0ULL,
		0xF3ADE370615C739EULL,
		0x56CE43CC925181AEULL,
		0x687F058FAE569292ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x46AB50EB1BD127E0ULL,
			0xF3ADE370615C739EULL,
			0x56CE43CC925181AEULL,
			0x687F058FAE569292ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB9C82C6E557D389CULL,
			0x7B8324E6367FF006ULL,
			0x65CFD15179D3E380ULL,
			0x691E5929163E9AF5ULL}
		},
		.Z = {.key64 = {
			0x0A21B78A1E898A82ULL,
			0x0B07E3AACF569338ULL,
			0xA07F31865D17CF03ULL,
			0x42F83CBF8766594FULL}
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

	steps = 61;
	X1 = (curve25519_key_t){.key64 = {
		0xEB20D4997702B108ULL,
		0x6D1AC8937BC5F96BULL,
		0x7AD84265365CBB0CULL,
		0x7EA81207AB1316E5ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEB20D4997702B108ULL,
			0x6D1AC8937BC5F96BULL,
			0x7AD84265365CBB0CULL,
			0x7EA81207AB1316E5ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3788591366288327ULL,
			0x96B235C7E11A76F6ULL,
			0xAFCAE1B0C971B782ULL,
			0x795A0A54CB28E102ULL}
		},
		.Z = {.key64 = {
			0xC0A4E38479FC726DULL,
			0x5B06B9656FAAB1A1ULL,
			0x5F6CB75C989406BBULL,
			0x26100C0DE481A192ULL}
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

	steps = 9;
	X1 = (curve25519_key_t){.key64 = {
		0x10C85BBEDDC11610ULL,
		0x8385EF7E187749C3ULL,
		0x9F4CC35230183FA2ULL,
		0x4609C09C0C4BF99BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x10C85BBEDDC11610ULL,
			0x8385EF7E187749C3ULL,
			0x9F4CC35230183FA2ULL,
			0x4609C09C0C4BF99BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA0E44BB2E027C64DULL,
			0x484AB1F6028F54B4ULL,
			0x98A74645C8363BC0ULL,
			0x76BCEFC533CED110ULL}
		},
		.Z = {.key64 = {
			0xAC94F2D8AA2676FBULL,
			0x1BFFB7F3910AA68DULL,
			0x88AFDBD7EA706B0BULL,
			0x28984C7F522349EEULL}
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

	steps = 59;
	X1 = (curve25519_key_t){.key64 = {
		0x258C71C12FAFD148ULL,
		0x7D49BBCBA22D4691ULL,
		0x929B26FD2180BB6CULL,
		0x75123E8359059E23ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x258C71C12FAFD148ULL,
			0x7D49BBCBA22D4691ULL,
			0x929B26FD2180BB6CULL,
			0x75123E8359059E23ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x55886EB050D6D6C4ULL,
			0x678412D61EE67619ULL,
			0x1E9B108C234E79BAULL,
			0x0D76BF5F97221F10ULL}
		},
		.Z = {.key64 = {
			0x470E2D03797FAA41ULL,
			0x9B275743E547C74BULL,
			0x965848034E2E8B93ULL,
			0x6048F1CE25FD4381ULL}
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

	steps = 14;
	X1 = (curve25519_key_t){.key64 = {
		0x2913F8B8314C2050ULL,
		0x18999A6C0827E3F2ULL,
		0xB9DB0A4168230B54ULL,
		0x7F713CA39A03C2CEULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2913F8B8314C2050ULL,
			0x18999A6C0827E3F2ULL,
			0xB9DB0A4168230B54ULL,
			0x7F713CA39A03C2CEULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD7D75B73ADFBB1CBULL,
			0xFAD2F968C2F70195ULL,
			0x81E6522E43C1620BULL,
			0x3D219AEC8381AF64ULL}
		},
		.Z = {.key64 = {
			0x572514AC9B42F1E8ULL,
			0x0FAAE9524A53A3C4ULL,
			0x19580736C553254EULL,
			0x403C2D2B5D203148ULL}
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

	steps = 23;
	X1 = (curve25519_key_t){.key64 = {
		0x1FFF2EBAE5C8B190ULL,
		0xB4FD3B09150431CCULL,
		0x15F89AE838D5133FULL,
		0x78D402F002CBE6F1ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1FFF2EBAE5C8B190ULL,
			0xB4FD3B09150431CCULL,
			0x15F89AE838D5133FULL,
			0x78D402F002CBE6F1ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCD5D6D034D5F7B46ULL,
			0xB247EC842C6E07FEULL,
			0x2871EAC2A7896884ULL,
			0x76CDCCF15021284EULL}
		},
		.Z = {.key64 = {
			0xB6305D829938BFF4ULL,
			0x1BBF6D14C3D136DAULL,
			0x4981B17A238E894FULL,
			0x1B8208057101DD2CULL}
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

	steps = 52;
	X1 = (curve25519_key_t){.key64 = {
		0x13B6A24D976058F0ULL,
		0x5589EA154405EB9BULL,
		0xE9A29819E4ED2EE2ULL,
		0x61F8079FD61F3710ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x13B6A24D976058F0ULL,
			0x5589EA154405EB9BULL,
			0xE9A29819E4ED2EE2ULL,
			0x61F8079FD61F3710ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x00DFE33FCBD9E190ULL,
			0x8560901E3487DFAFULL,
			0x7EA40235B47A70A2ULL,
			0x724A9F75D7E62E23ULL}
		},
		.Z = {.key64 = {
			0x97AD35C1C8BA156EULL,
			0xD006536FAD3651E7ULL,
			0x6BD7BA04604DE968ULL,
			0x1A187BCE64668640ULL}
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

	steps = 63;
	X1 = (curve25519_key_t){.key64 = {
		0x77DDC1559211FB88ULL,
		0x93760FFC2371EEE7ULL,
		0xA7EE24E429907D15ULL,
		0x53B0305E632DFCF3ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x77DDC1559211FB88ULL,
			0x93760FFC2371EEE7ULL,
			0xA7EE24E429907D15ULL,
			0x53B0305E632DFCF3ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB244CF43F3972B05ULL,
			0xAAF04F049418E128ULL,
			0xB1B0C176A6C89E5CULL,
			0x569F2BF9D4DF97ADULL}
		},
		.Z = {.key64 = {
			0x23C51C29D778168DULL,
			0xF756C1BDB0305848ULL,
			0x56D8B03A35A260DEULL,
			0x6119A8DCCD31B66FULL}
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

	steps = 7;
	X1 = (curve25519_key_t){.key64 = {
		0x130F6D28C2C05B90ULL,
		0xFFCD30D055855711ULL,
		0x56FE912254DAC2C3ULL,
		0x5E90EE481952B542ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x130F6D28C2C05B90ULL,
			0xFFCD30D055855711ULL,
			0x56FE912254DAC2C3ULL,
			0x5E90EE481952B542ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7EAAA2E713623807ULL,
			0x25E16E8AC86FEFAEULL,
			0x8B15CC668866106AULL,
			0x28F5A267FC0B5FAFULL}
		},
		.Z = {.key64 = {
			0x64E34735C5F88417ULL,
			0x2877E9A217779FADULL,
			0x6214DFAC6A8081D5ULL,
			0x310D569A4B435285ULL}
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

	steps = 49;
	X1 = (curve25519_key_t){.key64 = {
		0x4B656E0B0F414F08ULL,
		0x6EADD680B4FCDFC3ULL,
		0x0EA3EAE3886A2C5AULL,
		0x721950C004F58482ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4B656E0B0F414F08ULL,
			0x6EADD680B4FCDFC3ULL,
			0x0EA3EAE3886A2C5AULL,
			0x721950C004F58482ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x499207C84354A8A4ULL,
			0xAE870C78B7BADA45ULL,
			0x571923C04CBD7B96ULL,
			0x48049B402510D135ULL}
		},
		.Z = {.key64 = {
			0x2134699DA765FD07ULL,
			0x96DCB1F08FE6CD28ULL,
			0x5B4C5E1A8F41DB28ULL,
			0x4718E2581DC35A6DULL}
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

	steps = 10;
	X1 = (curve25519_key_t){.key64 = {
		0x0319109B7FCE7E08ULL,
		0x7E9C98EAEADF717EULL,
		0xFF8594E503DAB91FULL,
		0x747B6C3E94C66099ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0319109B7FCE7E08ULL,
			0x7E9C98EAEADF717EULL,
			0xFF8594E503DAB91FULL,
			0x747B6C3E94C66099ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6B1B7C6F36C47EEEULL,
			0x5DF55DEE434FF025ULL,
			0x6E56B3D1851D855AULL,
			0x574A2583680037AFULL}
		},
		.Z = {.key64 = {
			0x70A5E341267A77A0ULL,
			0x5A87014B1F6B3F9BULL,
			0x9F874B9117397E44ULL,
			0x79D35C7149F059B1ULL}
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

	steps = 13;
	X1 = (curve25519_key_t){.key64 = {
		0x6A3805A1696E6390ULL,
		0x7F7156CE4FD24B76ULL,
		0x9281BF2E7DFF979AULL,
		0x79333B91FAE4A169ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6A3805A1696E6390ULL,
			0x7F7156CE4FD24B76ULL,
			0x9281BF2E7DFF979AULL,
			0x79333B91FAE4A169ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7124ABB1E30A8B13ULL,
			0xB5A8C569117B15D0ULL,
			0xF0E26D329CA6A46CULL,
			0x5F749E274AC636EEULL}
		},
		.Z = {.key64 = {
			0x5215E389AC4BFAF0ULL,
			0xD6F5B811158BD451ULL,
			0x6E89DDB768524CE9ULL,
			0x2BB67081575B4200ULL}
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

	steps = 33;
	X1 = (curve25519_key_t){.key64 = {
		0x8B04BDD7C9158270ULL,
		0x2C04E869517FE8C7ULL,
		0x6C7C165E2E4782C8ULL,
		0x759C9EEF4DE06154ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8B04BDD7C9158270ULL,
			0x2C04E869517FE8C7ULL,
			0x6C7C165E2E4782C8ULL,
			0x759C9EEF4DE06154ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5A1C25605B45CE20ULL,
			0x10CF135151EEAA52ULL,
			0xF8878E823223B4B5ULL,
			0x3A0F48E79D2C7B20ULL}
		},
		.Z = {.key64 = {
			0x835BD1E255EC2C36ULL,
			0xCE31A54B0D922C31ULL,
			0xE0F45C2028A29744ULL,
			0x24ED7A6F6F103ACAULL}
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

	steps = 7;
	X1 = (curve25519_key_t){.key64 = {
		0xA38473DABA18D818ULL,
		0x5E88C78E3CB2FBD7ULL,
		0x1B690BD62188D5A7ULL,
		0x4552BD73447FF278ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA38473DABA18D818ULL,
			0x5E88C78E3CB2FBD7ULL,
			0x1B690BD62188D5A7ULL,
			0x4552BD73447FF278ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7339633130215DFAULL,
			0x8477FFF03E53730EULL,
			0xCEECCF54678DC14CULL,
			0x507B0996FA86E76CULL}
		},
		.Z = {.key64 = {
			0xA089BEB144F6C866ULL,
			0x551894B8E359233CULL,
			0x6BDF33F01C5236A5ULL,
			0x568398D5C391177EULL}
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

	steps = 43;
	X1 = (curve25519_key_t){.key64 = {
		0x52ACE17C334D5860ULL,
		0x6D4DB59CFFFAA4FDULL,
		0xD5D5E9E21D1987EFULL,
		0x52AD31E5125316C8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x52ACE17C334D5860ULL,
			0x6D4DB59CFFFAA4FDULL,
			0xD5D5E9E21D1987EFULL,
			0x52AD31E5125316C8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC143AE4EA9162E6AULL,
			0xF29D306DBC93FE27ULL,
			0xD327473BB8363746ULL,
			0x03C15AB41E7E263EULL}
		},
		.Z = {.key64 = {
			0xA78FCBFC5F3558F1ULL,
			0xF6D74C8FB35C2400ULL,
			0xA64AA4CB70F958E7ULL,
			0x1E0CBDC31D54164BULL}
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

	steps = 34;
	X1 = (curve25519_key_t){.key64 = {
		0xD3A06CDFFCCB2828ULL,
		0xF7DEECE6ECB034F1ULL,
		0xDA2C7B4109A7B817ULL,
		0x63E7246818BA01FCULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD3A06CDFFCCB2828ULL,
			0xF7DEECE6ECB034F1ULL,
			0xDA2C7B4109A7B817ULL,
			0x63E7246818BA01FCULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCA5773AD75277442ULL,
			0x9F718917C6AE6422ULL,
			0x87073E9199537411ULL,
			0x26BD4998627AA3DDULL}
		},
		.Z = {.key64 = {
			0x3DEB4C9D8A96B54FULL,
			0x507699FBE3EFE465ULL,
			0x853A92352A3BE1D5ULL,
			0x7993AB73673EAF4FULL}
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

	steps = 32;
	X1 = (curve25519_key_t){.key64 = {
		0xB6FE2321A3BA9488ULL,
		0xAD11E34C967DB6C5ULL,
		0x5BCFBC7849E8E9F0ULL,
		0x7ABDE689F994A587ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB6FE2321A3BA9488ULL,
			0xAD11E34C967DB6C5ULL,
			0x5BCFBC7849E8E9F0ULL,
			0x7ABDE689F994A587ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x302CE40CD4496165ULL,
			0x90173F65BD0B86ACULL,
			0x56F2727253F795EFULL,
			0x18306183EF5B97D4ULL}
		},
		.Z = {.key64 = {
			0x7A5EE611841AD28CULL,
			0xCA566646B692B91DULL,
			0x329EA631ECE65AD8ULL,
			0x54E1D6DF0E4461D4ULL}
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

	steps = 52;
	X1 = (curve25519_key_t){.key64 = {
		0x330257CB0D6FDD88ULL,
		0x073B7ED3AE4A4AD7ULL,
		0x9BAFA48735B36DB5ULL,
		0x553ADE98E12559FAULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x330257CB0D6FDD88ULL,
			0x073B7ED3AE4A4AD7ULL,
			0x9BAFA48735B36DB5ULL,
			0x553ADE98E12559FAULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB19DD8FE05496BB0ULL,
			0xFCFC68F28928F00BULL,
			0x1636AA81FF54A7C6ULL,
			0x42BA95B810407C60ULL}
		},
		.Z = {.key64 = {
			0xB181D6CB5ACC3037ULL,
			0x0B380D2511E21AE7ULL,
			0x90D46B05DF4F7AD4ULL,
			0x6B13A8FBA14960A1ULL}
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

	steps = 18;
	X1 = (curve25519_key_t){.key64 = {
		0xC40C7EFFCEA5DC40ULL,
		0xFDD2ED169FB5D107ULL,
		0x1F73B35D72232E86ULL,
		0x68AA31010CAC454BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC40C7EFFCEA5DC40ULL,
			0xFDD2ED169FB5D107ULL,
			0x1F73B35D72232E86ULL,
			0x68AA31010CAC454BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x045CAA3038ABD8C1ULL,
			0xBF87C05D04B63631ULL,
			0xADA53B8BE8D87E1CULL,
			0x7E1400437E732DB3ULL}
		},
		.Z = {.key64 = {
			0xE420B9E7E30609B5ULL,
			0x8797BE23925498CEULL,
			0x8F7E03C5C7AE55EDULL,
			0x3103A62216AE112FULL}
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

	steps = 10;
	X1 = (curve25519_key_t){.key64 = {
		0xD83F712776932020ULL,
		0xCC770A5C64C3DE08ULL,
		0xFF4626B028CD252DULL,
		0x7252FF5874C8EDAAULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD83F712776932020ULL,
			0xCC770A5C64C3DE08ULL,
			0xFF4626B028CD252DULL,
			0x7252FF5874C8EDAAULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC9C45B790F793C90ULL,
			0xA37D96DB4FC6B1A4ULL,
			0x953D57ABCA18763FULL,
			0x38A6C35A768BF921ULL}
		},
		.Z = {.key64 = {
			0x206A8B2A7C56A3BEULL,
			0xBB418A11D39E114FULL,
			0x7C6F485BE5FF28CFULL,
			0x18A99B137B1918BAULL}
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

	steps = 20;
	X1 = (curve25519_key_t){.key64 = {
		0x9E634EAFB98C1DC8ULL,
		0xD39D36CFD65CE506ULL,
		0x43386BDA5EFC1A91ULL,
		0x690CB9FBAE0D1EEAULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9E634EAFB98C1DC8ULL,
			0xD39D36CFD65CE506ULL,
			0x43386BDA5EFC1A91ULL,
			0x690CB9FBAE0D1EEAULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4F0FCD1F8BD321D2ULL,
			0xD0ABB46B1F2E77E5ULL,
			0xF8AA337FB72045F5ULL,
			0x058840795D40EC7AULL}
		},
		.Z = {.key64 = {
			0x5192F07D91C27D23ULL,
			0xC434F7D25034F873ULL,
			0xB3D29E1B951206E5ULL,
			0x05592E2129F320FDULL}
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

	steps = 25;
	X1 = (curve25519_key_t){.key64 = {
		0x224D0681F148C230ULL,
		0xB9394136705AA9FEULL,
		0x84EA64C82E1616E8ULL,
		0x6D9521F3706F27CEULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x224D0681F148C230ULL,
			0xB9394136705AA9FEULL,
			0x84EA64C82E1616E8ULL,
			0x6D9521F3706F27CEULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x26E5F04CAC0C0C10ULL,
			0xEA05DAA7EF2DD470ULL,
			0x04E9824A739FED64ULL,
			0x56A07FD255BF5344ULL}
		},
		.Z = {.key64 = {
			0x4A6912A266FBED4FULL,
			0x6FE94114F745B466ULL,
			0x1B29F2A72BEA260DULL,
			0x5D4FC984CECEF27FULL}
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

	steps = 20;
	X1 = (curve25519_key_t){.key64 = {
		0x0D45CE1C37292BF8ULL,
		0x9F009E68D45434A2ULL,
		0xD09882F3F9AA1870ULL,
		0x7E3947921953EBDFULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0D45CE1C37292BF8ULL,
			0x9F009E68D45434A2ULL,
			0xD09882F3F9AA1870ULL,
			0x7E3947921953EBDFULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9C40D90E7838CD16ULL,
			0x45E14AC691911E65ULL,
			0x35D312FE8645273CULL,
			0x7447F3E063291BDEULL}
		},
		.Z = {.key64 = {
			0x923317789D9C48DAULL,
			0xCA747E5C74671995ULL,
			0x0D41B1DF966723B6ULL,
			0x27D199945E92FF15ULL}
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

	steps = 11;
	X1 = (curve25519_key_t){.key64 = {
		0x50E6AA61AC0705A0ULL,
		0x095E2BE3092FE10BULL,
		0x925D4DC6186EE8FDULL,
		0x6367DA5F6E938DFBULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x50E6AA61AC0705A0ULL,
			0x095E2BE3092FE10BULL,
			0x925D4DC6186EE8FDULL,
			0x6367DA5F6E938DFBULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2B46AF741FA0CDE6ULL,
			0x3BE85F00739BA148ULL,
			0xC849B822790742DBULL,
			0x7655ACE9CF436FA8ULL}
		},
		.Z = {.key64 = {
			0x1DFBE1446D265FB6ULL,
			0x0592A7E5299DE673ULL,
			0xC2623D97C4038E38ULL,
			0x7A471A443FBF58C9ULL}
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

	steps = 10;
	X1 = (curve25519_key_t){.key64 = {
		0xD10CEA6CD8A80550ULL,
		0xBD605E537F49559DULL,
		0x63E8A43526B129CDULL,
		0x7570B74AA208CCBCULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD10CEA6CD8A80550ULL,
			0xBD605E537F49559DULL,
			0x63E8A43526B129CDULL,
			0x7570B74AA208CCBCULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBE82284D88366A84ULL,
			0x72812CA24A1600B1ULL,
			0x530D46F9618605B1ULL,
			0x57A010E1594763C1ULL}
		},
		.Z = {.key64 = {
			0x36BA9F3319F7E71DULL,
			0xE39E34B12F2B620EULL,
			0x1C3BBDEA588F38C1ULL,
			0x60648ADDAB4601A2ULL}
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

	steps = 8;
	X1 = (curve25519_key_t){.key64 = {
		0x384B5E91EF467660ULL,
		0x16B533AD8204F4ABULL,
		0x473A315EDB7C372DULL,
		0x5937D47F7D650DC0ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x384B5E91EF467660ULL,
			0x16B533AD8204F4ABULL,
			0x473A315EDB7C372DULL,
			0x5937D47F7D650DC0ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x34919F6EA067EC85ULL,
			0xF720AE40E260CA24ULL,
			0xA892587B35B88520ULL,
			0x77250CCC89247D34ULL}
		},
		.Z = {.key64 = {
			0x21BA49F4AB700F72ULL,
			0x364FEEFDD8C5DAE7ULL,
			0xD6381CB2B754A8D6ULL,
			0x3F473F62C9183361ULL}
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

	steps = 34;
	X1 = (curve25519_key_t){.key64 = {
		0xD5F1E1FDAAEDBF10ULL,
		0x37CFA50A94BB9B8BULL,
		0xF5B0E9670EF09B48ULL,
		0x73B4B30A7A6E7B4CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD5F1E1FDAAEDBF10ULL,
			0x37CFA50A94BB9B8BULL,
			0xF5B0E9670EF09B48ULL,
			0x73B4B30A7A6E7B4CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9A9DE6C9684EA22EULL,
			0xF647530B3AA605CCULL,
			0x3A9F1C9534C1A04EULL,
			0x092824626F5FCFE6ULL}
		},
		.Z = {.key64 = {
			0xD971361728C6FF6BULL,
			0x86CCF501919CD77CULL,
			0xCBE2BA5047349730ULL,
			0x3C1BAB1025504BADULL}
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

	steps = 60;
	X1 = (curve25519_key_t){.key64 = {
		0x6B92266BB21F5EC8ULL,
		0xAE65FB6576A02052ULL,
		0xB07905298DEBE899ULL,
		0x50F7C2D09D18998BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6B92266BB21F5EC8ULL,
			0xAE65FB6576A02052ULL,
			0xB07905298DEBE899ULL,
			0x50F7C2D09D18998BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2D9662E532691057ULL,
			0x43BF539039D47329ULL,
			0x7552B4016346C80AULL,
			0x5EE32BE2092DD596ULL}
		},
		.Z = {.key64 = {
			0x0E6E3E612A158A7FULL,
			0xCEEDF7599DE6DD36ULL,
			0x2527D515A3540DB0ULL,
			0x1C306C321C134D90ULL}
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

	steps = 45;
	X1 = (curve25519_key_t){.key64 = {
		0x2C8B3BD641F75160ULL,
		0xBBB1FFEAD205FB60ULL,
		0xD232DCC38EFBF8CAULL,
		0x7E21ED4805AF7BD4ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2C8B3BD641F75160ULL,
			0xBBB1FFEAD205FB60ULL,
			0xD232DCC38EFBF8CAULL,
			0x7E21ED4805AF7BD4ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x66993818D97897F0ULL,
			0x2FD928C4D5068C06ULL,
			0xC326BF885877F827ULL,
			0x085D780F3026BBDBULL}
		},
		.Z = {.key64 = {
			0x71E2C9E2AF9064C8ULL,
			0xC247C437DEAB99FCULL,
			0xF87E611DECD61C01ULL,
			0x0499518A4485F17EULL}
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

	steps = 18;
	X1 = (curve25519_key_t){.key64 = {
		0x2844778D51AFE3A0ULL,
		0xDCE161458540F034ULL,
		0x0EB31886207FE380ULL,
		0x7BF45FA35E468A90ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2844778D51AFE3A0ULL,
			0xDCE161458540F034ULL,
			0x0EB31886207FE380ULL,
			0x7BF45FA35E468A90ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x01803AD5D432FD98ULL,
			0xE79CD58C74DC9216ULL,
			0xE73DBDE15FE9A894ULL,
			0x63425EFDE580CD37ULL}
		},
		.Z = {.key64 = {
			0xF157FAB871E5E0EEULL,
			0x395010F191FCCFC8ULL,
			0x9C46DD3088346DF0ULL,
			0x417C00787D0FEEAAULL}
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

	steps = 38;
	X1 = (curve25519_key_t){.key64 = {
		0x4F93A8A53B410070ULL,
		0x300F41EAEE556373ULL,
		0x3FA68F7F20623220ULL,
		0x52BE54D203B261D4ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4F93A8A53B410070ULL,
			0x300F41EAEE556373ULL,
			0x3FA68F7F20623220ULL,
			0x52BE54D203B261D4ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4BD81F0731903F61ULL,
			0x8A38B1FBE68E060FULL,
			0x8B76286360340806ULL,
			0x16EB5BA2011AAFC8ULL}
		},
		.Z = {.key64 = {
			0xA7C34F43CCCFFD7EULL,
			0x659BCFFC72A472C7ULL,
			0xA8D3B7F853F15E56ULL,
			0x2D5E7D41E215C0D6ULL}
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

	steps = 62;
	X1 = (curve25519_key_t){.key64 = {
		0x16014631C90F9D48ULL,
		0xE3DE0EF6E8CB4206ULL,
		0xE15C20849BB193B1ULL,
		0x545A7B225788AFAEULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x16014631C90F9D48ULL,
			0xE3DE0EF6E8CB4206ULL,
			0xE15C20849BB193B1ULL,
			0x545A7B225788AFAEULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0D639E4AD9BEB370ULL,
			0x5CF049517F2C8311ULL,
			0x20E33AE9560ADA42ULL,
			0x751E6CD4B998769DULL}
		},
		.Z = {.key64 = {
			0x6DD02CFBD57050F0ULL,
			0xFB2328EE93B53908ULL,
			0x50976BDD4723AE2BULL,
			0x22F93AFCD511344FULL}
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

	steps = 38;
	X1 = (curve25519_key_t){.key64 = {
		0x2698B4D7A2267F00ULL,
		0x6A47ABDCDF90B34BULL,
		0x429BDD9A62E5D149ULL,
		0x69C3EC817FC0AE68ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2698B4D7A2267F00ULL,
			0x6A47ABDCDF90B34BULL,
			0x429BDD9A62E5D149ULL,
			0x69C3EC817FC0AE68ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF314F0A636A8D94DULL,
			0xF5D2EB4F4C8FECC9ULL,
			0x9ABE293A336711FCULL,
			0x29D1E1D506E9DD69ULL}
		},
		.Z = {.key64 = {
			0xF510003488344880ULL,
			0x65F344E58B47E113ULL,
			0xCA03B0FDE442646BULL,
			0x46C9D1F1D0BC0407ULL}
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

	steps = 37;
	X1 = (curve25519_key_t){.key64 = {
		0xCB34414EDE7F4488ULL,
		0xB6504113B8F3461DULL,
		0xFB1AEE4E0E5566C4ULL,
		0x697398D85DF5B08CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCB34414EDE7F4488ULL,
			0xB6504113B8F3461DULL,
			0xFB1AEE4E0E5566C4ULL,
			0x697398D85DF5B08CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCAA29F7669B25802ULL,
			0x4FA6E46324DACD75ULL,
			0xD5B90916261E424EULL,
			0x5EAA81D2E1CA734DULL}
		},
		.Z = {.key64 = {
			0xA876BBBC15C4FE72ULL,
			0x8B4144DDE39BC713ULL,
			0x7F9612FCE073C429ULL,
			0x4064425ED166FB6DULL}
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

	steps = 31;
	X1 = (curve25519_key_t){.key64 = {
		0x86E105E578A2E338ULL,
		0x3ABC925381B7C650ULL,
		0x3DEE97E886AF3071ULL,
		0x6784140A0F56C95BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x86E105E578A2E338ULL,
			0x3ABC925381B7C650ULL,
			0x3DEE97E886AF3071ULL,
			0x6784140A0F56C95BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xED3BF1B1670EA40DULL,
			0x01372F15563A741CULL,
			0x285F76ECFF11E933ULL,
			0x2A062EF1C112E616ULL}
		},
		.Z = {.key64 = {
			0xC88DA02FD8E0AC3DULL,
			0xA455AE83FE7D41F1ULL,
			0x1C620D69D4CBB701ULL,
			0x183AB2821E85C08AULL}
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

	steps = 42;
	X1 = (curve25519_key_t){.key64 = {
		0xC0E8EAF8EE2364D8ULL,
		0x7671DD3767A6D277ULL,
		0xC12D4AC551A0F26AULL,
		0x66DBA9292A421443ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC0E8EAF8EE2364D8ULL,
			0x7671DD3767A6D277ULL,
			0xC12D4AC551A0F26AULL,
			0x66DBA9292A421443ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x385F0C183158D512ULL,
			0x43DA44395A5E1D45ULL,
			0x632092BDF52092F9ULL,
			0x29EA201B74DE56B1ULL}
		},
		.Z = {.key64 = {
			0xA299F5CC8AAF7B8FULL,
			0xA3C9B3DF6E6582A2ULL,
			0x717DC905AE01CA62ULL,
			0x4728EBF2D21474C2ULL}
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

	steps = 50;
	X1 = (curve25519_key_t){.key64 = {
		0xC7D1DAAC68313768ULL,
		0xED64229C0AB90730ULL,
		0xD71DB016DB4D86DAULL,
		0x42515F69DFB7037CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC7D1DAAC68313768ULL,
			0xED64229C0AB90730ULL,
			0xD71DB016DB4D86DAULL,
			0x42515F69DFB7037CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x20546D8DBECA830DULL,
			0xCBAE894BAF150E16ULL,
			0x587193A52901EABCULL,
			0x40B562C73ACE10A6ULL}
		},
		.Z = {.key64 = {
			0xEC103DE61EA1DF9AULL,
			0xE1D3E93F7A7DB23BULL,
			0x7B5E92BBBAB37A55ULL,
			0x71F40426C6188BA5ULL}
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

	steps = 3;
	X1 = (curve25519_key_t){.key64 = {
		0x20E6257FDEEA2618ULL,
		0xC7F6549A3A2BA3FDULL,
		0x58E2CD429C620713ULL,
		0x7723F8DCEA689885ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x20E6257FDEEA2618ULL,
			0xC7F6549A3A2BA3FDULL,
			0x58E2CD429C620713ULL,
			0x7723F8DCEA689885ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAEE9B63AA5D8109AULL,
			0x426B26EF641A5E68ULL,
			0x83EF71183569CF11ULL,
			0x40201F89E84486DAULL}
		},
		.Z = {.key64 = {
			0x2BE81C70C6E21F07ULL,
			0x8A91DC2AC83CA6D5ULL,
			0x70FF52E4C5CE6C9CULL,
			0x58DDFAB3A87BA2C2ULL}
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

	steps = 42;
	X1 = (curve25519_key_t){.key64 = {
		0x50D815C463444458ULL,
		0xC94A2CC319C16E80ULL,
		0xDD8EA81607BEF34DULL,
		0x768FABAB09BDF090ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x50D815C463444458ULL,
			0xC94A2CC319C16E80ULL,
			0xDD8EA81607BEF34DULL,
			0x768FABAB09BDF090ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x164262495D6E2212ULL,
			0xE6D1A85055ECBAD0ULL,
			0x67C91665548B4D40ULL,
			0x00A7BB8483FC5162ULL}
		},
		.Z = {.key64 = {
			0x06C88DC9B7FB4644ULL,
			0x682CA05C9C1ECFF4ULL,
			0xAF49AA8B502404D1ULL,
			0x286B43F474CD594DULL}
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

	steps = 46;
	X1 = (curve25519_key_t){.key64 = {
		0x916A829AE2AA6A48ULL,
		0x805935A3C2D8445FULL,
		0xCD51168902A7E9E6ULL,
		0x5D099617E74A45BFULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x916A829AE2AA6A48ULL,
			0x805935A3C2D8445FULL,
			0xCD51168902A7E9E6ULL,
			0x5D099617E74A45BFULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBE800103AE696697ULL,
			0x5780CACAFB84BA99ULL,
			0xCF30AAAEE7D4D601ULL,
			0x698F988BFD49E80CULL}
		},
		.Z = {.key64 = {
			0xD58C339C7923A472ULL,
			0x53C570A612EDADACULL,
			0x659D3EEE846580ABULL,
			0x6DA1649FE0F061D1ULL}
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

	steps = 63;
	X1 = (curve25519_key_t){.key64 = {
		0xE9CD1E25E0C4CA00ULL,
		0xF9A0AAD482382D50ULL,
		0x71BFC7A8C7C11C14ULL,
		0x595CF510A0BC0BC7ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE9CD1E25E0C4CA00ULL,
			0xF9A0AAD482382D50ULL,
			0x71BFC7A8C7C11C14ULL,
			0x595CF510A0BC0BC7ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9A851DA842697615ULL,
			0x4595FA26676912F0ULL,
			0x149C233C7541DCF0ULL,
			0x2194DEF34EB73BAFULL}
		},
		.Z = {.key64 = {
			0x72506F3E39DED235ULL,
			0x46FA766B1452274CULL,
			0xD99BDA77A81338A6ULL,
			0x2AC5F266AE35968BULL}
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

	steps = 1;
	X1 = (curve25519_key_t){.key64 = {
		0xAFC66D02E95E2BF8ULL,
		0x96081C036D532B3FULL,
		0x45DBC430901E1FDEULL,
		0x595BE72AEEE63606ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAFC66D02E95E2BF8ULL,
			0x96081C036D532B3FULL,
			0x45DBC430901E1FDEULL,
			0x595BE72AEEE63606ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x92A5E51563554697ULL,
			0xDD21E831F7A7F0EFULL,
			0xCC8D4F1CD9913DE7ULL,
			0x57EDD5F9CF37C1F8ULL}
		},
		.Z = {.key64 = {
			0xBF19B40BA578B006ULL,
			0x5820700DB54CACFEULL,
			0x176F10C240787F7AULL,
			0x656F9CABBB98D819ULL}
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

	steps = 44;
	X1 = (curve25519_key_t){.key64 = {
		0xBC0989AE72C9AD20ULL,
		0xB9679352EDD8AD95ULL,
		0xB9D7E2E8BF4CEB1FULL,
		0x40EDA338D90DD4A3ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBC0989AE72C9AD20ULL,
			0xB9679352EDD8AD95ULL,
			0xB9D7E2E8BF4CEB1FULL,
			0x40EDA338D90DD4A3ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7C03CEB89FF05C4CULL,
			0x53459219A63C8479ULL,
			0x955E096A0B6D3183ULL,
			0x479321E18BF0FE35ULL}
		},
		.Z = {.key64 = {
			0xD244E6A4178E9FE8ULL,
			0x4A17740A06C0E922ULL,
			0x275005B9AC4F66E8ULL,
			0x4462C99E25BD7A97ULL}
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

	steps = 49;
	X1 = (curve25519_key_t){.key64 = {
		0xA07AA89D35C060F0ULL,
		0x40A73C6EF1378442ULL,
		0xB9EE18860B502985ULL,
		0x626DE5915DDA281BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA07AA89D35C060F0ULL,
			0x40A73C6EF1378442ULL,
			0xB9EE18860B502985ULL,
			0x626DE5915DDA281BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x840B44C1F4714749ULL,
			0x667EA8E8C3FFAB6CULL,
			0x28EA613D65825B97ULL,
			0x7427CBA4524AC439ULL}
		},
		.Z = {.key64 = {
			0x64D2A8F69B87ED6AULL,
			0x39990433995C0A48ULL,
			0x6F76CEBE53BBCEADULL,
			0x6477145F08D00CE2ULL}
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

	steps = 32;
	X1 = (curve25519_key_t){.key64 = {
		0xE3CE6CAA29AAE5A8ULL,
		0xD9C91FC15930CE6CULL,
		0x4BBC215D35A080F2ULL,
		0x6666679E165D828BULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE3CE6CAA29AAE5A8ULL,
			0xD9C91FC15930CE6CULL,
			0x4BBC215D35A080F2ULL,
			0x6666679E165D828BULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3AB15DC8192B65A7ULL,
			0x0CFC722B1DB32D06ULL,
			0xE6EF57B4750B8424ULL,
			0x62A5DE9B19C7D54BULL}
		},
		.Z = {.key64 = {
			0x1819017FB2FD9022ULL,
			0x71F6C9DDE7017F2AULL,
			0x5DFF1A7C637FC1DAULL,
			0x78B7CEF0DF4E82EDULL}
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

	steps = 40;
	X1 = (curve25519_key_t){.key64 = {
		0xEFAD13C8C9040A00ULL,
		0x58F303145D913EE6ULL,
		0x97C584A6D198FDE6ULL,
		0x7547825DAE0A5E83ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEFAD13C8C9040A00ULL,
			0x58F303145D913EE6ULL,
			0x97C584A6D198FDE6ULL,
			0x7547825DAE0A5E83ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8B2F40EB6292AA27ULL,
			0x100704D737C367D8ULL,
			0x743ADAC19E99C604ULL,
			0x71E53FB0078E6562ULL}
		},
		.Z = {.key64 = {
			0x0FEFD860E61647EFULL,
			0x8D9A094F7C73F66EULL,
			0x6C6C98E465F72102ULL,
			0x1DB985780D1D3CBBULL}
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

	steps = 63;
	X1 = (curve25519_key_t){.key64 = {
		0x2630FDCD253298B0ULL,
		0xE975193C5A3EBE9AULL,
		0x5116BA146791D468ULL,
		0x7A8D77931F235246ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2630FDCD253298B0ULL,
			0xE975193C5A3EBE9AULL,
			0x5116BA146791D468ULL,
			0x7A8D77931F235246ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x153A8301A78D5D02ULL,
			0xE047901F8AA9F763ULL,
			0x74032B659991C448ULL,
			0x7908B674F0B9A4F8ULL}
		},
		.Z = {.key64 = {
			0x81AC3F3A7AD3C726ULL,
			0x2E99B3EF0FC7A50DULL,
			0x2FB2F7519936C5D1ULL,
			0x4418D1288E272511ULL}
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

	steps = 56;
	X1 = (curve25519_key_t){.key64 = {
		0xFC4520D5BFC30C10ULL,
		0x0D1D3D590A5E09CEULL,
		0x3F2A331AA7CCC518ULL,
		0x4666B5F61879F130ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFC4520D5BFC30C10ULL,
			0x0D1D3D590A5E09CEULL,
			0x3F2A331AA7CCC518ULL,
			0x4666B5F61879F130ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8D75009AA735DB65ULL,
			0x48D71CD6FC1900DFULL,
			0x6B99A954FA64C57DULL,
			0x59A1A7F8E8BC6F3AULL}
		},
		.Z = {.key64 = {
			0x5870E57F3B27174AULL,
			0x0E4289938E0A73A1ULL,
			0x053E7D71A9695791ULL,
			0x1810B495C6B01C74ULL}
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

	steps = 18;
	X1 = (curve25519_key_t){.key64 = {
		0x3D8C1BE2FEF3D800ULL,
		0xFDD80733B67002BAULL,
		0xC63BC8219F4DCAFCULL,
		0x78C4828E5217E208ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3D8C1BE2FEF3D800ULL,
			0xFDD80733B67002BAULL,
			0xC63BC8219F4DCAFCULL,
			0x78C4828E5217E208ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCDC191905158C8BDULL,
			0x42D2670573B3F7FBULL,
			0x9DEBFF5A8FB60A49ULL,
			0x040FBE119FAFF9D9ULL}
		},
		.Z = {.key64 = {
			0x0FB1B400D657F47CULL,
			0xAF3A42AE898934A4ULL,
			0x6F17306D328603F9ULL,
			0x5691364C5B1A8D79ULL}
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

	steps = 36;
	X1 = (curve25519_key_t){.key64 = {
		0xE15457F882317658ULL,
		0xCD21422AF49D27B7ULL,
		0x13F3CABAB2699529ULL,
		0x6DF93497E660471AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE15457F882317658ULL,
			0xCD21422AF49D27B7ULL,
			0x13F3CABAB2699529ULL,
			0x6DF93497E660471AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xBDB73AE54B270014ULL,
			0xD451A60DA57D4F0CULL,
			0x3C3A220CF32FF536ULL,
			0x6BEB55F63169EEFEULL}
		},
		.Z = {.key64 = {
			0x5D28E20B48BA7531ULL,
			0xC994E584D3A69111ULL,
			0x3483D8C0F5E56422ULL,
			0x7857D4DD634AD3F2ULL}
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

	steps = 55;
	X1 = (curve25519_key_t){.key64 = {
		0x3FC1BACF41EBF478ULL,
		0x7079B360E2FE722EULL,
		0xB7F708613E08E805ULL,
		0x66263A1389FBC733ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3FC1BACF41EBF478ULL,
			0x7079B360E2FE722EULL,
			0xB7F708613E08E805ULL,
			0x66263A1389FBC733ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD884FC389A250557ULL,
			0xF061F73086B451DDULL,
			0xEBA1D0EFB87C1F33ULL,
			0x022FAABA42B81943ULL}
		},
		.Z = {.key64 = {
			0xA8AE783F6D293941ULL,
			0xE47C0C025864C2F5ULL,
			0xA237FD00E7ED6D5CULL,
			0x42FF8243AC1C862EULL}
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

	steps = 42;
	X1 = (curve25519_key_t){.key64 = {
		0x41F517944B631A70ULL,
		0xE1870C5BDAA9B687ULL,
		0x9A7D7BEB27145E08ULL,
		0x5AE3F4306B96E068ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x41F517944B631A70ULL,
			0xE1870C5BDAA9B687ULL,
			0x9A7D7BEB27145E08ULL,
			0x5AE3F4306B96E068ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9649335CDB597453ULL,
			0xA8B0F56CE6FBBDD3ULL,
			0x8CB51AD86A6081B3ULL,
			0x4C3AC546B381A68CULL}
		},
		.Z = {.key64 = {
			0x17BBABB4BCF0BC22ULL,
			0x4BE2E9A91C237C30ULL,
			0x1B14AB7A52B64891ULL,
			0x604DFE6B063670F9ULL}
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

	steps = 45;
	X1 = (curve25519_key_t){.key64 = {
		0xE0372ABBB27B4618ULL,
		0x3C7D62E65AD55BA3ULL,
		0xB1FB8F2A61010638ULL,
		0x550CEAE37731E43DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE0372ABBB27B4618ULL,
			0x3C7D62E65AD55BA3ULL,
			0xB1FB8F2A61010638ULL,
			0x550CEAE37731E43DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8A32374319926AD7ULL,
			0x8CA858D2BB2A6464ULL,
			0x50C0E22F945BB982ULL,
			0x3986BC90B17865EFULL}
		},
		.Z = {.key64 = {
			0x001147D3055BD1C9ULL,
			0x9F43EFD8D7384675ULL,
			0x306A45015ED8DEADULL,
			0x555FD872A3E544F5ULL}
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

	steps = 35;
	X1 = (curve25519_key_t){.key64 = {
		0xA58751D5084917A8ULL,
		0xC2450210ADD82525ULL,
		0x89FD0235D1C9BB20ULL,
		0x4815C61E64BFDDDDULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA58751D5084917A8ULL,
			0xC2450210ADD82525ULL,
			0x89FD0235D1C9BB20ULL,
			0x4815C61E64BFDDDDULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFB6883C67BA70DFDULL,
			0xE8C3DEA3D8422A0AULL,
			0x5EC2A4F7C24F42E4ULL,
			0x3E17C2FE7E14FFC0ULL}
		},
		.Z = {.key64 = {
			0x84666167A89E56A1ULL,
			0xA1CA00B752C729E4ULL,
			0xA742A433F5246017ULL,
			0x1847C4A48529D342ULL}
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

	steps = 16;
	X1 = (curve25519_key_t){.key64 = {
		0x740346EEF6586280ULL,
		0x0E924166C9392ED3ULL,
		0xA4AA2A8515190ACFULL,
		0x65C7A6CAC93A6505ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x740346EEF6586280ULL,
			0x0E924166C9392ED3ULL,
			0xA4AA2A8515190ACFULL,
			0x65C7A6CAC93A6505ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD1199021C1090132ULL,
			0x9078028212205641ULL,
			0xE3A84C2C0067DF40ULL,
			0x48AFCC4609717A4CULL}
		},
		.Z = {.key64 = {
			0xFA96004A72208FE5ULL,
			0xCAB7BD95F5FAC63AULL,
			0x4FA928147D9A299BULL,
			0x11B10EC3CBEF931CULL}
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

	steps = 62;
	X1 = (curve25519_key_t){.key64 = {
		0x4918D4CB799F0320ULL,
		0x15D609B99E6A79A8ULL,
		0xDAA76F93B3758CAAULL,
		0x7A725E6917962F0FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4918D4CB799F0320ULL,
			0x15D609B99E6A79A8ULL,
			0xDAA76F93B3758CAAULL,
			0x7A725E6917962F0FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE55729F69F15CE20ULL,
			0xCCCA90C0AC5FAB11ULL,
			0x70EF0D0EFE75FCEDULL,
			0x566739CC0B60D177ULL}
		},
		.Z = {.key64 = {
			0x8A07CD1B80481924ULL,
			0x5E4B725B8BF8C118ULL,
			0xDCFF85C8F8DCE6D7ULL,
			0x7D0914804633188EULL}
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

	steps = 13;
	X1 = (curve25519_key_t){.key64 = {
		0x51BD62676D604A88ULL,
		0x6534E0E72093C412ULL,
		0x10B3F1BEF28C5594ULL,
		0x5F65D7FD745F0BCEULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x51BD62676D604A88ULL,
			0x6534E0E72093C412ULL,
			0x10B3F1BEF28C5594ULL,
			0x5F65D7FD745F0BCEULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x68D0A92725444626ULL,
			0xA839106EAB7CEC59ULL,
			0xD8CA831A62858F7DULL,
			0x78A4C88EDDCF71F3ULL}
		},
		.Z = {.key64 = {
			0x9D374804A41622A4ULL,
			0x8D1841ED7D6099B4ULL,
			0x3D4F8075468B1915ULL,
			0x47C7125F4361967CULL}
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

	steps = 31;
	X1 = (curve25519_key_t){.key64 = {
		0xB582CD3F6C5F4590ULL,
		0xB0E3CA12301D8DF8ULL,
		0x2A5D738ADEE5E299ULL,
		0x44E250D15E19010DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB582CD3F6C5F4590ULL,
			0xB0E3CA12301D8DF8ULL,
			0x2A5D738ADEE5E299ULL,
			0x44E250D15E19010DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x51CC32453E7948AFULL,
			0xB1B1D93C681E4279ULL,
			0xA5E956A2C62207ABULL,
			0x31EA8ABA6A4F13C1ULL}
		},
		.Z = {.key64 = {
			0x35FEC9B95EB8F173ULL,
			0x05DA8B8555FAB680ULL,
			0xB793B3EBE9742237ULL,
			0x6696D3F0AB856D65ULL}
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

	steps = 31;
	X1 = (curve25519_key_t){.key64 = {
		0x93BE701EAE237C70ULL,
		0x7B22703684852ACEULL,
		0xB3119F05B46E5418ULL,
		0x50D29349519621EBULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x93BE701EAE237C70ULL,
			0x7B22703684852ACEULL,
			0xB3119F05B46E5418ULL,
			0x50D29349519621EBULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x52E403C9D3042B0DULL,
			0x0AACD7E8B67FDE62ULL,
			0x457C5F6870E3FA05ULL,
			0x00E3D234CF4B1216ULL}
		},
		.Z = {.key64 = {
			0x6AFD41DCAD0A1B7FULL,
			0x9056AD4A5B5C191AULL,
			0x182CD5D97450BB47ULL,
			0x14CAD98221BADA58ULL}
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

	steps = 20;
	X1 = (curve25519_key_t){.key64 = {
		0x87DAAE126B15BD98ULL,
		0x5DE077AF7A806CB7ULL,
		0xFE9CA6E08461B6DDULL,
		0x5381F45B3CE2C2BAULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x87DAAE126B15BD98ULL,
			0x5DE077AF7A806CB7ULL,
			0xFE9CA6E08461B6DDULL,
			0x5381F45B3CE2C2BAULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8EE109B6939806EDULL,
			0x9625CAC4E9DFCDB4ULL,
			0x768E176780A46D25ULL,
			0x71F001FA771E0EA3ULL}
		},
		.Z = {.key64 = {
			0x14DA76A11467AEE0ULL,
			0x36F77C002B0C03D5ULL,
			0x35CAB4856FDD16A5ULL,
			0x68AD4EEBAE029783ULL}
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

	steps = 9;
	X1 = (curve25519_key_t){.key64 = {
		0x71BE92B47E8F22F0ULL,
		0xEB2F3FDE0CDFF43CULL,
		0xE001A71C91E4054EULL,
		0x63323107F236AE1FULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x71BE92B47E8F22F0ULL,
			0xEB2F3FDE0CDFF43CULL,
			0xE001A71C91E4054EULL,
			0x63323107F236AE1FULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7B222C65B7AC541FULL,
			0x0353C0650C46D00FULL,
			0x62ACDB8167DABB7DULL,
			0x79BEB925604FD4C3ULL}
		},
		.Z = {.key64 = {
			0xB4B989DA403B5799ULL,
			0xA3764A8F43EBC8CEULL,
			0x5B10D4E2DDE96584ULL,
			0x20DBF0A7392F752DULL}
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

	steps = 3;
	X1 = (curve25519_key_t){.key64 = {
		0x042A960C6E0800B8ULL,
		0x836E99707999FF57ULL,
		0x41D5B7049525B5BEULL,
		0x627C5BC128B46E4DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x042A960C6E0800B8ULL,
			0x836E99707999FF57ULL,
			0x41D5B7049525B5BEULL,
			0x627C5BC128B46E4DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDAC8A975A62C38E4ULL,
			0x4F1D9DA9D8D745D1ULL,
			0xB22BABD8BB5E35D5ULL,
			0x29F73252E666627DULL}
		},
		.Z = {.key64 = {
			0x5E116EF05CC34142ULL,
			0xB16D2A0048372A46ULL,
			0x31FE56736DE0BFBEULL,
			0x00F9AA43CD8247C1ULL}
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

	steps = 62;
	X1 = (curve25519_key_t){.key64 = {
		0x0CB7F58495413C20ULL,
		0x2DE2CA5C3F1BB43AULL,
		0xEC2AFB6CA397A605ULL,
		0x6F1DB41E82B2CE67ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0CB7F58495413C20ULL,
			0x2DE2CA5C3F1BB43AULL,
			0xEC2AFB6CA397A605ULL,
			0x6F1DB41E82B2CE67ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB13E8F3DDC7DA8FEULL,
			0x75E07EA85D2C4B7AULL,
			0x298B7CB22EE01E4BULL,
			0x3AE5AA6FBB960FF9ULL}
		},
		.Z = {.key64 = {
			0xC025DD8D26C94BCAULL,
			0x130C41EB92804E9BULL,
			0x7F542E64873CF42EULL,
			0x0D7B9C3C99B16E3CULL}
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

	steps = 11;
	X1 = (curve25519_key_t){.key64 = {
		0x270281B4A3254E80ULL,
		0xFE93BC0764DA8725ULL,
		0x60D7477075F739C7ULL,
		0x7A3AF34EDD290FD6ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x270281B4A3254E80ULL,
			0xFE93BC0764DA8725ULL,
			0x60D7477075F739C7ULL,
			0x7A3AF34EDD290FD6ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2AB6B72EC4287811ULL,
			0x3D460329CCFBB2B8ULL,
			0x895E8EF4BA20A12FULL,
			0x66AE611BB31874A7ULL}
		},
		.Z = {.key64 = {
			0xFD17639F538CDEE6ULL,
			0x4C8E533280BBC1FDULL,
			0x4428A4D30D4A3D84ULL,
			0x563F092EB11D6DA9ULL}
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

	steps = 2;
	X1 = (curve25519_key_t){.key64 = {
		0x0BE95D6FC52CC9C8ULL,
		0x3984DCE4763381FCULL,
		0x54F4B90195FB5094ULL,
		0x4766E6A81B8B6E13ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0BE95D6FC52CC9C8ULL,
			0x3984DCE4763381FCULL,
			0x54F4B90195FB5094ULL,
			0x4766E6A81B8B6E13ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xACAF56F4175D5B4FULL,
			0x74BF0C3FF1D5BA7CULL,
			0x091BCDECE67FCD5EULL,
			0x2346681B65ECD7CFULL}
		},
		.Z = {.key64 = {
			0x50D5D8126D91DBF6ULL,
			0xA94A4C2CF13BA719ULL,
			0x3CE17A2F3CB57DD2ULL,
			0x6C6D2268F6F1A23BULL}
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

	steps = 3;
	X1 = (curve25519_key_t){.key64 = {
		0x3F22793AF8BA0320ULL,
		0x33E3721B7AECCB5BULL,
		0x43540C39CE91D71AULL,
		0x4842673F1BFB36A9ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3F22793AF8BA0320ULL,
			0x33E3721B7AECCB5BULL,
			0x43540C39CE91D71AULL,
			0x4842673F1BFB36A9ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4B670AC01B90D517ULL,
			0x2F814FE67EB32400ULL,
			0xDC3F7AC1DAAB425EULL,
			0x03F5E4DC7132048CULL}
		},
		.Z = {.key64 = {
			0x384F92008D465385ULL,
			0x41702C5C0C2E5675ULL,
			0x847C25558B20C244ULL,
			0x5B6C85663A2BF313ULL}
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

	steps = 12;
	X1 = (curve25519_key_t){.key64 = {
		0x7662CF32E7248A70ULL,
		0xF8FB926168EE7899ULL,
		0x0E409A42FAF25B2CULL,
		0x76741C708F12D984ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7662CF32E7248A70ULL,
			0xF8FB926168EE7899ULL,
			0x0E409A42FAF25B2CULL,
			0x76741C708F12D984ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xED75613D7CDF1473ULL,
			0xFAEDB174427FE383ULL,
			0x8EBC97130C1E6980ULL,
			0x567BF25A9BEA9942ULL}
		},
		.Z = {.key64 = {
			0xF5F35F0302737372ULL,
			0xFD527011C4D66070ULL,
			0x87097755203DACF9ULL,
			0x3E095411060376F4ULL}
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
		0xE8BF39B8414E9BD0ULL,
		0x669B32FA13B0155BULL,
		0x5A3F3D563A128D79ULL,
		0x502FB510B771DA22ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE8BF39B8414E9BD0ULL,
			0x669B32FA13B0155BULL,
			0x5A3F3D563A128D79ULL,
			0x502FB510B771DA22ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC4D2CD44A2F66CD3ULL,
			0x81CFFC43A4FB8CDFULL,
			0x0582939E1D376292ULL,
			0x47AB2DABCBD5AB82ULL}
		},
		.Z = {.key64 = {
			0xAB937E9844770259ULL,
			0xC591AEA3046E70B6ULL,
			0x3206D9E12816A2DAULL,
			0x420F1DA57F5DC2BCULL}
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
		0xF86F61500D2F7CC8ULL,
		0xEFBCE13B6D3195DDULL,
		0x9C88E76657F9BECAULL,
		0x571BFB9F12E4287DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF86F61500D2F7CC8ULL,
			0xEFBCE13B6D3195DDULL,
			0x9C88E76657F9BECAULL,
			0x571BFB9F12E4287DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x45E2ACD28000F74CULL,
			0xF55724D12FC0B646ULL,
			0x95CAFF7F2B7BCDFEULL,
			0x1B41464E2411E007ULL}
		},
		.Z = {.key64 = {
			0x5286014EFD3988A5ULL,
			0x924B6411EDE8BB84ULL,
			0x4AAC35B22FA4F1ADULL,
			0x6F6ED1BAC715E9D8ULL}
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

	steps = 5;
	X1 = (curve25519_key_t){.key64 = {
		0xAD422F9E7810AF20ULL,
		0x1D58609F525DAF30ULL,
		0xA461A9A59C2096CAULL,
		0x763E463570806061ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xAD422F9E7810AF20ULL,
			0x1D58609F525DAF30ULL,
			0xA461A9A59C2096CAULL,
			0x763E463570806061ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFD8922C128386643ULL,
			0x6EEE8878606942C7ULL,
			0xEBBA44039DDA9B73ULL,
			0x48384155C06BA92DULL}
		},
		.Z = {.key64 = {
			0xE4C950A5CE674E7AULL,
			0xB799399F120CF3FFULL,
			0xCC0E58A8FE18F573ULL,
			0x3D606ADA477818CEULL}
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

	steps = 6;
	X1 = (curve25519_key_t){.key64 = {
		0x947F4D9152AA3D90ULL,
		0x26B19468A7824F66ULL,
		0xEF38B17E4723DB49ULL,
		0x5D90F8EA13759957ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x947F4D9152AA3D90ULL,
			0x26B19468A7824F66ULL,
			0xEF38B17E4723DB49ULL,
			0x5D90F8EA13759957ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x04B34DC3B49F8BB4ULL,
			0x4F7BC067CE1F9770ULL,
			0x6FF4A7A4B058D8B4ULL,
			0x78C35BD68C08C621ULL}
		},
		.Z = {.key64 = {
			0x17726E2330191611ULL,
			0x89B92F9F472B9759ULL,
			0x917AC419C1AB505DULL,
			0x493636D6F4B77007ULL}
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

	steps = 9;
	X1 = (curve25519_key_t){.key64 = {
		0xDD98FFEF3759ECF0ULL,
		0x323BA06ADABF0A5EULL,
		0x7425DE5DBEF09CC7ULL,
		0x590858924B1EA747ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDD98FFEF3759ECF0ULL,
			0x323BA06ADABF0A5EULL,
			0x7425DE5DBEF09CC7ULL,
			0x590858924B1EA747ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x971DB78571FCFFC0ULL,
			0xB9C96220FBEE53AFULL,
			0x05D306A043B1742BULL,
			0x329EDD84AE9A7D5CULL}
		},
		.Z = {.key64 = {
			0x68E149D28FDE852AULL,
			0x03FFEE331C3AC60BULL,
			0x96505ACBD6C6F3E3ULL,
			0x0505BB985CC9FC82ULL}
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
		0x2873F0852BC8BCD0ULL,
		0xC97A27AABF5D8387ULL,
		0x0754A0F9F8001EE7ULL,
		0x60034913E807FBF3ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2873F0852BC8BCD0ULL,
			0xC97A27AABF5D8387ULL,
			0x0754A0F9F8001EE7ULL,
			0x60034913E807FBF3ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x144F9D10A49B465CULL,
			0x3683EE618FC575BEULL,
			0x0F58D7D209FDFF5CULL,
			0x1D0188A5F2E977D7ULL}
		},
		.Z = {.key64 = {
			0x60BCFDB52DCB57FDULL,
			0xFBB9C700BA572D86ULL,
			0x91749AD0ADEA4E76ULL,
			0x2D8FF34AD3CAA527ULL}
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

	steps = 50;
	X1 = (curve25519_key_t){.key64 = {
		0x104382DA6B505F40ULL,
		0xC54CB766E802B822ULL,
		0x3A67F18ED88D3631ULL,
		0x6EBEBC9D2696906AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x104382DA6B505F40ULL,
			0xC54CB766E802B822ULL,
			0x3A67F18ED88D3631ULL,
			0x6EBEBC9D2696906AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xC5E42E2E952666B1ULL,
			0x980E248B90548A75ULL,
			0x2C8E4EB3290B0CD6ULL,
			0x1905F58CFF88FC3DULL}
		},
		.Z = {.key64 = {
			0x53645F1A5DEC0349ULL,
			0xE5A5BA30CD346EE0ULL,
			0xF3939DDDABFCA90EULL,
			0x4C65CFCEFA007D95ULL}
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

	steps = 2;
	X1 = (curve25519_key_t){.key64 = {
		0x832CC65BA7716F68ULL,
		0xA45C943199F27350ULL,
		0x684868EC61C28282ULL,
		0x62D8A8FADD2E4F59ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x832CC65BA7716F68ULL,
			0xA45C943199F27350ULL,
			0x684868EC61C28282ULL,
			0x62D8A8FADD2E4F59ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x13ACC4B8AACE6B14ULL,
			0xB6EFB79DE3BB8018ULL,
			0x6475067A94142EDBULL,
			0x4AE87EF1EA5F3BE6ULL}
		},
		.Z = {.key64 = {
			0xD26B747A0B627E85ULL,
			0x21D9BC1FF1287B27ULL,
			0x59A95B14B86813A7ULL,
			0x5A5002FB3A5E27E8ULL}
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

	steps = 25;
	X1 = (curve25519_key_t){.key64 = {
		0x447608CADADD77B8ULL,
		0xEE458E8F6E342610ULL,
		0x3A8DD8CF4990B93AULL,
		0x590AA6D4CB467A0EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x447608CADADD77B8ULL,
			0xEE458E8F6E342610ULL,
			0x3A8DD8CF4990B93AULL,
			0x590AA6D4CB467A0EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x706E86B10C8AF8A3ULL,
			0x5676C6E742BE3130ULL,
			0xB38A9F750E6050D1ULL,
			0x2E1971A76FE63E23ULL}
		},
		.Z = {.key64 = {
			0xD8FF50AABC0CC1E9ULL,
			0x944957704A83FCDAULL,
			0xF97FE7A671756DE4ULL,
			0x7DA8A0352AF4F03FULL}
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

	steps = 40;
	X1 = (curve25519_key_t){.key64 = {
		0x522DA4E88AE9DBC0ULL,
		0x38E8F346873D5760ULL,
		0xF8DA0D6CE029D995ULL,
		0x51B618EF6321107DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x522DA4E88AE9DBC0ULL,
			0x38E8F346873D5760ULL,
			0xF8DA0D6CE029D995ULL,
			0x51B618EF6321107DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x56FB83876C8FAF1EULL,
			0xCF2F837EE099A2A7ULL,
			0x976745D8E9ABAD71ULL,
			0x4D0DDDFB5B52340EULL}
		},
		.Z = {.key64 = {
			0x115DC37EBEAE15ABULL,
			0xF87035A214550D0CULL,
			0xC52DF742894021E3ULL,
			0x3A331BCF1D6EE8A1ULL}
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

	steps = 14;
	X1 = (curve25519_key_t){.key64 = {
		0x250DD45ACA9C9EB8ULL,
		0xAC70F64F5A6D52FEULL,
		0xFDF8A28C4E7BD55BULL,
		0x42FF2F9040B5E404ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x250DD45ACA9C9EB8ULL,
			0xAC70F64F5A6D52FEULL,
			0xFDF8A28C4E7BD55BULL,
			0x42FF2F9040B5E404ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x893233431ECA822CULL,
			0x024DA177FB6A59D7ULL,
			0xB1E1EBF8DC8AE6F9ULL,
			0x58B39B2B34626EBCULL}
		},
		.Z = {.key64 = {
			0x03BB69038EDF4D68ULL,
			0x2C60BD2FD607171CULL,
			0xFCCC02007537C73EULL,
			0x132498AFB0BE1F7AULL}
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

	steps = 43;
	X1 = (curve25519_key_t){.key64 = {
		0x7D0F377379289B70ULL,
		0xC2F4DB6AB2A2C2FFULL,
		0xF9BE83BE91465DA3ULL,
		0x4BB7C32FFAAA5344ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7D0F377379289B70ULL,
			0xC2F4DB6AB2A2C2FFULL,
			0xF9BE83BE91465DA3ULL,
			0x4BB7C32FFAAA5344ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x59EEC7F21E22BFACULL,
			0x198C60D1BA0F9715ULL,
			0xEA4E8AD99A64F632ULL,
			0x27A808C737F932E6ULL}
		},
		.Z = {.key64 = {
			0x1927D7EFEE994D59ULL,
			0xD237F2020EDEC261ULL,
			0x4A45BE3F66087FA1ULL,
			0x7A88F6B330284AA3ULL}
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

	steps = 27;
	X1 = (curve25519_key_t){.key64 = {
		0x54729E068E4C23E0ULL,
		0xA5ED3D7BC8D8E012ULL,
		0x97DE54AB3CD20A87ULL,
		0x58FAAE25E6632DB8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x54729E068E4C23E0ULL,
			0xA5ED3D7BC8D8E012ULL,
			0x97DE54AB3CD20A87ULL,
			0x58FAAE25E6632DB8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDFD5590F93C710FAULL,
			0xC52AD6961D5F77CDULL,
			0xED29CCC0E5D2611CULL,
			0x0C8828A2E03900DCULL}
		},
		.Z = {.key64 = {
			0x80A973037389CB7DULL,
			0xBB857A9093EB1D93ULL,
			0xA6517A5AF2117AC3ULL,
			0x77F7F16E0ABF6FC4ULL}
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

	steps = 1;
	X1 = (curve25519_key_t){.key64 = {
		0x9D526F6C1145F0D8ULL,
		0xC2C529C9F90C7AE4ULL,
		0x05A3EF788F4DCAB0ULL,
		0x521D9D86F6DA39FEULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9D526F6C1145F0D8ULL,
			0xC2C529C9F90C7AE4ULL,
			0x05A3EF788F4DCAB0ULL,
			0x521D9D86F6DA39FEULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE7F53A13D0A924B4ULL,
			0xC3C65C11A43C0359ULL,
			0xDCA457185C424C39ULL,
			0x69526D85471BDFDAULL}
		},
		.Z = {.key64 = {
			0x7549BDB04517C386ULL,
			0x0B14A727E431EB92ULL,
			0x168FBDE23D372AC3ULL,
			0x4876761BDB68E7F8ULL}
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

	steps = 27;
	X1 = (curve25519_key_t){.key64 = {
		0x6CD5973DE118DFC0ULL,
		0xCB318DA9D41F69B7ULL,
		0x1114531229CF7B49ULL,
		0x4EB711D599478D5DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6CD5973DE118DFC0ULL,
			0xCB318DA9D41F69B7ULL,
			0x1114531229CF7B49ULL,
			0x4EB711D599478D5DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFAF160EFCF5A3125ULL,
			0xAB298F14CC359920ULL,
			0xE50576B2809B889AULL,
			0x3E9253BBC507F567ULL}
		},
		.Z = {.key64 = {
			0x45E375F98B2576B2ULL,
			0x4F5D0483888B89D3ULL,
			0x330A9277F0310B20ULL,
			0x5FC822AD164FD881ULL}
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

	steps = 22;
	X1 = (curve25519_key_t){.key64 = {
		0xE5A69539107AA380ULL,
		0xDFBBB418B3742F18ULL,
		0xF426D4CA3825C55FULL,
		0x5A8822261A54DE47ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE5A69539107AA380ULL,
			0xDFBBB418B3742F18ULL,
			0xF426D4CA3825C55FULL,
			0x5A8822261A54DE47ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3DD1E6384BED4E52ULL,
			0x5FEBC162D0A92C8EULL,
			0x8183B67C88CC4A51ULL,
			0x0B0FA5422F4AEED3ULL}
		},
		.Z = {.key64 = {
			0x699FCA817FC9B7ACULL,
			0xCA0FA095CB27A88CULL,
			0x28345511824BF59AULL,
			0x5E3734A8178F35BAULL}
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

	steps = 47;
	X1 = (curve25519_key_t){.key64 = {
		0x546B2FA04635AFF8ULL,
		0x3D6455C2D7AD70A4ULL,
		0x4B26EBE42E920800ULL,
		0x71B7E1D2304EA561ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x546B2FA04635AFF8ULL,
			0x3D6455C2D7AD70A4ULL,
			0x4B26EBE42E920800ULL,
			0x71B7E1D2304EA561ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDFF2557131EA8784ULL,
			0xB526DE2C66E2C1EAULL,
			0xD1F413703AD1DACFULL,
			0x29DB6038ADDAF3ABULL}
		},
		.Z = {.key64 = {
			0x02CF9F9333E4705AULL,
			0x7A083F5B2EFE9574ULL,
			0x32BE7D1FDFB0DB62ULL,
			0x2FDFBDC80584CD20ULL}
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
		0x5D21EFCBA7EE04B0ULL,
		0xA7BB8C37722447EDULL,
		0x5B111A71A36875BEULL,
		0x4DEA444E3A63D7B4ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5D21EFCBA7EE04B0ULL,
			0xA7BB8C37722447EDULL,
			0x5B111A71A36875BEULL,
			0x4DEA444E3A63D7B4ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x149E2CC22B4D8A25ULL,
			0xBB05803CC296BE7FULL,
			0x9EEF4152662411B2ULL,
			0x266CB6246A04A026ULL}
		},
		.Z = {.key64 = {
			0xE26E7710DF755D95ULL,
			0x41DE39DB2FC13128ULL,
			0xEA979EE2A2D602CEULL,
			0x2D201379137A209EULL}
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
		0x65F5CA1FD71303A0ULL,
		0xDFBE1E1DC37C5C21ULL,
		0x4619B7CC15183F93ULL,
		0x67767BF1550BA53CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x65F5CA1FD71303A0ULL,
			0xDFBE1E1DC37C5C21ULL,
			0x4619B7CC15183F93ULL,
			0x67767BF1550BA53CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5B536D8C12D474D5ULL,
			0x8EE7BA75542AF37BULL,
			0x3A1BFB4A1A474A2DULL,
			0x1DE7DFE8509FE978ULL}
		},
		.Z = {.key64 = {
			0xA4C5FFE7E7931FA7ULL,
			0xC82C84496CED6214ULL,
			0xE211E7A19B7DDF25ULL,
			0x2DCF9DB3018B0BC0ULL}
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

	steps = 8;
	X1 = (curve25519_key_t){.key64 = {
		0xFD6D52ECC8342850ULL,
		0xBF95FA2285FC3425ULL,
		0xC7675EC30299C5CBULL,
		0x4DC0C79AA0081B5EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFD6D52ECC8342850ULL,
			0xBF95FA2285FC3425ULL,
			0xC7675EC30299C5CBULL,
			0x4DC0C79AA0081B5EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD7B25736F7C554B6ULL,
			0xD6B1DFD2594253F2ULL,
			0x865C5D7F472CD9D3ULL,
			0x5E5A661E2267CA58ULL}
		},
		.Z = {.key64 = {
			0x78C1F44752463435ULL,
			0x1F9505874F6594EAULL,
			0xF4A54D32AC0B44A1ULL,
			0x653B7FA364A478A7ULL}
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

	steps = 21;
	X1 = (curve25519_key_t){.key64 = {
		0x8B0EEF0ECD26A550ULL,
		0x2E1AC6CF9A6D6896ULL,
		0x75E3DF755B3FCE0BULL,
		0x4F0831BE400F6CFCULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8B0EEF0ECD26A550ULL,
			0x2E1AC6CF9A6D6896ULL,
			0x75E3DF755B3FCE0BULL,
			0x4F0831BE400F6CFCULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4FE4751A053188BDULL,
			0xE3D67E45157E9707ULL,
			0x46900732BB72D781ULL,
			0x2997658A18155AD7ULL}
		},
		.Z = {.key64 = {
			0x894A8BC7FBD19506ULL,
			0x18A497C303FDF776ULL,
			0x6FDC38E67F5CCFA1ULL,
			0x09752087D682AF58ULL}
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

	steps = 6;
	X1 = (curve25519_key_t){.key64 = {
		0x9F3F025F7443AF48ULL,
		0x404F1E1D4DBEA148ULL,
		0x34A59F907A437DF8ULL,
		0x66B6C8592C60E061ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9F3F025F7443AF48ULL,
			0x404F1E1D4DBEA148ULL,
			0x34A59F907A437DF8ULL,
			0x66B6C8592C60E061ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1F5E1940281A607AULL,
			0x3761A895E870E8B7ULL,
			0x9490973E503EBC8FULL,
			0x3B768653A246A709ULL}
		},
		.Z = {.key64 = {
			0x6E5DD1B8A83F3DADULL,
			0xE7680DF6D7AC7439ULL,
			0xE08EC5DEF2EB4DEDULL,
			0x62B4BB20C2238B6EULL}
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

	steps = 33;
	X1 = (curve25519_key_t){.key64 = {
		0x465352A3833C7CB8ULL,
		0x7CB37A60C76BEC03ULL,
		0xDA9165ADAC45A87AULL,
		0x79FF7815314A9346ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x465352A3833C7CB8ULL,
			0x7CB37A60C76BEC03ULL,
			0xDA9165ADAC45A87AULL,
			0x79FF7815314A9346ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x17BC3CA9040B2766ULL,
			0xCB3937C9FFF73EC4ULL,
			0xBC0244A805230BC0ULL,
			0x565954BB3E86D5EDULL}
		},
		.Z = {.key64 = {
			0x7B766C5885E6916DULL,
			0xAC9346219C33D320ULL,
			0x0533CF18EE85A1FAULL,
			0x32B25C62D5B9BE69ULL}
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

	steps = 53;
	X1 = (curve25519_key_t){.key64 = {
		0x142BA81970BA2F20ULL,
		0xA676A4190002555BULL,
		0xB02A4CCFF6C4EE27ULL,
		0x6570E3D8CD84311EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x142BA81970BA2F20ULL,
			0xA676A4190002555BULL,
			0xB02A4CCFF6C4EE27ULL,
			0x6570E3D8CD84311EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE2608321217C078CULL,
			0x96527D0ABF9ADCA7ULL,
			0xD6E50E8C16D1F1CFULL,
			0x02DD906F18E05A01ULL}
		},
		.Z = {.key64 = {
			0x48B9EAAEBC7318CBULL,
			0x208413A27427CECFULL,
			0x9A0A2001066BC7C5ULL,
			0x5F8D96B57B529EBAULL}
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

	steps = 9;
	X1 = (curve25519_key_t){.key64 = {
		0x437F5C73B3D42B18ULL,
		0x2F80261F34354A7CULL,
		0x3F10A7C4227A3839ULL,
		0x500F06D005DF3200ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x437F5C73B3D42B18ULL,
			0x2F80261F34354A7CULL,
			0x3F10A7C4227A3839ULL,
			0x500F06D005DF3200ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x9B1DD556ABF7BD51ULL,
			0x760AF90DE2B7EFE7ULL,
			0x6EDCFE704AFCE1ADULL,
			0x1BEC84F82525B13EULL}
		},
		.Z = {.key64 = {
			0x7C311625C30ECF76ULL,
			0x488C04FFC81FDBE0ULL,
			0xD45346EE70FCFF5AULL,
			0x4560D0ECFA486B26ULL}
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

	steps = 58;
	X1 = (curve25519_key_t){.key64 = {
		0x4E83A1B9B4FDB658ULL,
		0x61278BF92190ECA9ULL,
		0x0AAF034DEC42B9C6ULL,
		0x7FBA01C1BAA32EBEULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x4E83A1B9B4FDB658ULL,
			0x61278BF92190ECA9ULL,
			0x0AAF034DEC42B9C6ULL,
			0x7FBA01C1BAA32EBEULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x670C46F298690094ULL,
			0x7B68078F157DCD66ULL,
			0x9689E9FB7D410DE7ULL,
			0x7B43D1909D6A5FB9ULL}
		},
		.Z = {.key64 = {
			0x8D5E32775D1F6DEBULL,
			0x569FC1CB8778BAA5ULL,
			0x199FFD6652D64913ULL,
			0x5FACB7F77C7702D0ULL}
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

	steps = 19;
	X1 = (curve25519_key_t){.key64 = {
		0x8BE01E60F5684D10ULL,
		0x9B69CD5AF41D08D7ULL,
		0x7B4A4B0DBB1B62F8ULL,
		0x6003FF90E56A2C7CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8BE01E60F5684D10ULL,
			0x9B69CD5AF41D08D7ULL,
			0x7B4A4B0DBB1B62F8ULL,
			0x6003FF90E56A2C7CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3275C2691A0C0732ULL,
			0xCA94432C1130E2DEULL,
			0xA00014D35BBCA9E3ULL,
			0x1A464DAE33CA2A5CULL}
		},
		.Z = {.key64 = {
			0x7D36FA89EB7F24CFULL,
			0x35BFD9614FE22783ULL,
			0xBE9B5EE362007D7EULL,
			0x4247A51387466DA7ULL}
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

	steps = 19;
	X1 = (curve25519_key_t){.key64 = {
		0xCCCF9582EC322F18ULL,
		0x0EEC307395F2F5BBULL,
		0xFC414F02DEC3FE4EULL,
		0x628A9C7B646A578EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xCCCF9582EC322F18ULL,
			0x0EEC307395F2F5BBULL,
			0xFC414F02DEC3FE4EULL,
			0x628A9C7B646A578EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x486326D7EB94EAC8ULL,
			0xE85D727E1EE05A11ULL,
			0xE7A820F50C2EDD76ULL,
			0x4C26E0A6ED14CA72ULL}
		},
		.Z = {.key64 = {
			0x2A64619C49CAA354ULL,
			0xC1200F7461BCECB1ULL,
			0x75A1252A8CEAFD66ULL,
			0x1F61067FE1F43F5CULL}
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

	steps = 45;
	X1 = (curve25519_key_t){.key64 = {
		0x0BCFA76DE750E9F0ULL,
		0x891AAA1BF989B09CULL,
		0x7D6C882347C7B8A2ULL,
		0x56E4BCDEE5893C25ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0BCFA76DE750E9F0ULL,
			0x891AAA1BF989B09CULL,
			0x7D6C882347C7B8A2ULL,
			0x56E4BCDEE5893C25ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE61800EE04242A17ULL,
			0xEB90493B47CA5221ULL,
			0x4E4F67F96C0B868EULL,
			0x44B5B26C33FF5EB0ULL}
		},
		.Z = {.key64 = {
			0x3F2BD8F222E9D9B6ULL,
			0xDDA33BB5F2397A63ULL,
			0x9C4557D06E3DC4B9ULL,
			0x22CFC6C0B30D7168ULL}
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

	steps = 3;
	X1 = (curve25519_key_t){.key64 = {
		0x69A18AF4C11EB408ULL,
		0x28A6E25C33982363ULL,
		0x26E5B14A396986B5ULL,
		0x685F0C0E0D671B53ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x69A18AF4C11EB408ULL,
			0x28A6E25C33982363ULL,
			0x26E5B14A396986B5ULL,
			0x685F0C0E0D671B53ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD781D8BC7AA562B3ULL,
			0xDB32C15F44121DCFULL,
			0x50F9CE5BE9780439ULL,
			0x61AC85A03BCD6CD0ULL}
		},
		.Z = {.key64 = {
			0xA1FBD48F10B8040BULL,
			0x3C8BBC3F70B6E099ULL,
			0x1403C0D16FC15759ULL,
			0x7CFC785074D65EDCULL}
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

	steps = 49;
	X1 = (curve25519_key_t){.key64 = {
		0x6522C573E9CAE2E8ULL,
		0x22A1DC36DC2A556AULL,
		0x0556100008BBE87BULL,
		0x4857AE30F2F3021DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6522C573E9CAE2E8ULL,
			0x22A1DC36DC2A556AULL,
			0x0556100008BBE87BULL,
			0x4857AE30F2F3021DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x6C6A079E0A574722ULL,
			0x053BBB79CA18A89DULL,
			0x656426459108BF51ULL,
			0x337651D4F2DE0FCAULL}
		},
		.Z = {.key64 = {
			0xED9BD5E7D2F77387ULL,
			0x82B9BBE7DB011F2CULL,
			0x0C6866F52497028BULL,
			0x0224D841B47D39C5ULL}
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

	steps = 28;
	X1 = (curve25519_key_t){.key64 = {
		0xF10DF8E15B15B8D8ULL,
		0x9DA6E6B2526322C2ULL,
		0x69774D2D95599B93ULL,
		0x53C5368B217100B8ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF10DF8E15B15B8D8ULL,
			0x9DA6E6B2526322C2ULL,
			0x69774D2D95599B93ULL,
			0x53C5368B217100B8ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x1264031286106C3CULL,
			0x2FFAFBC90BB5E58AULL,
			0xA6D4ACA09D2AA607ULL,
			0x4EE912B205A7034CULL}
		},
		.Z = {.key64 = {
			0x983A3A1B393D63ACULL,
			0xF570A84631DEBF94ULL,
			0xDA69D588C0DFAB33ULL,
			0x0190E6A3403F4CA9ULL}
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

	steps = 29;
	X1 = (curve25519_key_t){.key64 = {
		0xFD4BB8394BAFB170ULL,
		0xDCD4260FE28B6B05ULL,
		0x1270A0423AAD382AULL,
		0x55B7C56AE7B371CBULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFD4BB8394BAFB170ULL,
			0xDCD4260FE28B6B05ULL,
			0x1270A0423AAD382AULL,
			0x55B7C56AE7B371CBULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x67A236028FD841D7ULL,
			0xF1086B4EAAC98BBBULL,
			0xF11E010DFD88D911ULL,
			0x00349F28F59F0C1FULL}
		},
		.Z = {.key64 = {
			0x8AABA7D646B76D34ULL,
			0x9A3830637173ED1AULL,
			0xAC97315BCBCF5371ULL,
			0x6C095FDD17866FCBULL}
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

	steps = 51;
	X1 = (curve25519_key_t){.key64 = {
		0xFBAB2338FDBEFF30ULL,
		0x39AC984C9C7B6B4CULL,
		0x8AA6C5C130833525ULL,
		0x58EA4362B2E4C165ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xFBAB2338FDBEFF30ULL,
			0x39AC984C9C7B6B4CULL,
			0x8AA6C5C130833525ULL,
			0x58EA4362B2E4C165ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x21F4A48C17E3D3A2ULL,
			0x70293F02836759DEULL,
			0xFB2C6989BB1ED0F1ULL,
			0x48A5A51978C72D14ULL}
		},
		.Z = {.key64 = {
			0xF373D3A63913E0BBULL,
			0x1838B9F0688D62CDULL,
			0x06B8996A46549A11ULL,
			0x24A9AAC85BE1717DULL}
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

	steps = 52;
	X1 = (curve25519_key_t){.key64 = {
		0x0E4E0043E5C80350ULL,
		0x6D1089327790E513ULL,
		0xDBB99CD701AA4AA9ULL,
		0x55FBB6187B174A8CULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0E4E0043E5C80350ULL,
			0x6D1089327790E513ULL,
			0xDBB99CD701AA4AA9ULL,
			0x55FBB6187B174A8CULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDA437C649022FEE4ULL,
			0x7C4F051804770AABULL,
			0x9B5F455BADA020F6ULL,
			0x37C426D6E0188630ULL}
		},
		.Z = {.key64 = {
			0xE557CA46882E349FULL,
			0xEE5C1EE29C84C692ULL,
			0xFB9E7C15918306D5ULL,
			0x0636895FEAD1A23AULL}
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

	steps = 53;
	X1 = (curve25519_key_t){.key64 = {
		0x7E2196D93BCE81D8ULL,
		0xC0B666E092503652ULL,
		0x1A57EEEFB5A11C2FULL,
		0x7F73190F0413245DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7E2196D93BCE81D8ULL,
			0xC0B666E092503652ULL,
			0x1A57EEEFB5A11C2FULL,
			0x7F73190F0413245DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xDD38015561690FBCULL,
			0xE9CE4501F2EC0F56ULL,
			0x3779D5B7963A8F9FULL,
			0x5EAC902200D200DCULL}
		},
		.Z = {.key64 = {
			0xBDC4AC8CCDA6360BULL,
			0x617D1182334D1982ULL,
			0x39DF6BF63DD586B4ULL,
			0x3BEA25DD86BCF597ULL}
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

	steps = 48;
	X1 = (curve25519_key_t){.key64 = {
		0x64D4C18D2DDACD68ULL,
		0x636FF11457DD0502ULL,
		0x5C9BFF4F51E13F30ULL,
		0x7BAE74FC62300EC9ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x64D4C18D2DDACD68ULL,
			0x636FF11457DD0502ULL,
			0x5C9BFF4F51E13F30ULL,
			0x7BAE74FC62300EC9ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x7868BD0B3D85082CULL,
			0x060E3BD46F2A2B05ULL,
			0x6125AC08E833685EULL,
			0x1F4396CF2ECA629FULL}
		},
		.Z = {.key64 = {
			0x1F9C36CEC465D04BULL,
			0x8DCF03055B281159ULL,
			0xD4F05FBEB1FA286BULL,
			0x6A4E8756A9AF8A77ULL}
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

	steps = 19;
	X1 = (curve25519_key_t){.key64 = {
		0x5C497A307BE7CA50ULL,
		0xA4B657B40CE40685ULL,
		0xFAC2D26CFEEEF468ULL,
		0x6C481482E4978F65ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x5C497A307BE7CA50ULL,
			0xA4B657B40CE40685ULL,
			0xFAC2D26CFEEEF468ULL,
			0x6C481482E4978F65ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x77319CC8EB21A091ULL,
			0xDDADADDB29A60D51ULL,
			0x097403F4C9D6769DULL,
			0x76EA376E0A96B8C6ULL}
		},
		.Z = {.key64 = {
			0xAB0BC2AB72B7928AULL,
			0x262BE0A0FDF0A9B4ULL,
			0x8F8A27BD3B7C4CE3ULL,
			0x3C04A5D0E1045F1EULL}
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

	steps = 59;
	X1 = (curve25519_key_t){.key64 = {
		0xE9C4FF171422CEB8ULL,
		0xC77928EB182B5F6DULL,
		0xCC51D68565C95CB2ULL,
		0x5D88226C4AF63E67ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xE9C4FF171422CEB8ULL,
			0xC77928EB182B5F6DULL,
			0xCC51D68565C95CB2ULL,
			0x5D88226C4AF63E67ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB11ADB48C9FE017AULL,
			0x239B458197E26153ULL,
			0x8885280645EE1F7AULL,
			0x0D5F6CC7B1BCFB3EULL}
		},
		.Z = {.key64 = {
			0xCCDDE172013CFF18ULL,
			0x8267B5A514236FCFULL,
			0x444A383B707A51E9ULL,
			0x0AD93ED72A4F6BCFULL}
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

	steps = 36;
	X1 = (curve25519_key_t){.key64 = {
		0x89990ADB95281E90ULL,
		0x37F5A64D806D7B65ULL,
		0xB7F1614755C8B64EULL,
		0x4A0CB5DFFFCFEF74ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x89990ADB95281E90ULL,
			0x37F5A64D806D7B65ULL,
			0xB7F1614755C8B64EULL,
			0x4A0CB5DFFFCFEF74ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x54D26F34070BC6ADULL,
			0xDA7EA2FB31E76429ULL,
			0x22C563BD43B2A6CDULL,
			0x3362894CF5490A47ULL}
		},
		.Z = {.key64 = {
			0xB000DECBF4791213ULL,
			0x633A6687D1515BAEULL,
			0xBCE6EE48B8B5B96EULL,
			0x1B0C14EDC92B4687ULL}
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

	steps = 41;
	X1 = (curve25519_key_t){.key64 = {
		0x935E5AD7528B6EA0ULL,
		0x15C6893C23152F3CULL,
		0xE9B53F6F1C982CABULL,
		0x59A609786D16EE30ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x935E5AD7528B6EA0ULL,
			0x15C6893C23152F3CULL,
			0xE9B53F6F1C982CABULL,
			0x59A609786D16EE30ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x493E168BF6142CD7ULL,
			0x77E33A1D968C40E9ULL,
			0xD951262BA338056BULL,
			0x02504CBF1BD342DFULL}
		},
		.Z = {.key64 = {
			0x4B9EECF1F8501E7DULL,
			0xBA6052BF5967D6D3ULL,
			0xB5CE1A89D6F00D1AULL,
			0x1C668518B6505223ULL}
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

	steps = 43;
	X1 = (curve25519_key_t){.key64 = {
		0xF28175F837F227B8ULL,
		0xD499DB5BD3C74044ULL,
		0xE141F4BE8D73D273ULL,
		0x5E77C6C2DE2A4DBFULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF28175F837F227B8ULL,
			0xD499DB5BD3C74044ULL,
			0xE141F4BE8D73D273ULL,
			0x5E77C6C2DE2A4DBFULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x594CDCC21339B12CULL,
			0x947C720924DCA8BEULL,
			0x0847F3FE297DD3B4ULL,
			0x7329E2B8EF03E6FCULL}
		},
		.Z = {.key64 = {
			0x0373A49961DC2092ULL,
			0xB7073B8C9E5C97FEULL,
			0x42EAA6156EE6CBD6ULL,
			0x0F7A96E912CC47F2ULL}
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

	steps = 6;
	X1 = (curve25519_key_t){.key64 = {
		0x81EE5E37ECB52E80ULL,
		0xDB8ED8FE8EE622EDULL,
		0x8E3232165A036CEAULL,
		0x53835E04C70A416EULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x81EE5E37ECB52E80ULL,
			0xDB8ED8FE8EE622EDULL,
			0x8E3232165A036CEAULL,
			0x53835E04C70A416EULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8AF590F371D69145ULL,
			0x7E4E23ED680A7420ULL,
			0xE93E5AB380C3C3ACULL,
			0x6B4ABC29709B9542ULL}
		},
		.Z = {.key64 = {
			0x189BA0CE874D2C15ULL,
			0xE9D231D0EE767629ULL,
			0x71AF12B07C14FD39ULL,
			0x4F2FBEA2AA822ECFULL}
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

	steps = 46;
	X1 = (curve25519_key_t){.key64 = {
		0x044FE5658DE388B0ULL,
		0x768914919C0F71D0ULL,
		0xD9CF918E2EAEB72CULL,
		0x710AB7EEF9D974F9ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x044FE5658DE388B0ULL,
			0x768914919C0F71D0ULL,
			0xD9CF918E2EAEB72CULL,
			0x710AB7EEF9D974F9ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD41D86DA6114F2BCULL,
			0x5DE734A90774490FULL,
			0x8FC2A062638B1DE6ULL,
			0x0BB61ED3A245ED32ULL}
		},
		.Z = {.key64 = {
			0x65DC9FF114572E34ULL,
			0x0700767DD0E2ECEDULL,
			0xECCEB070AA93645CULL,
			0x6CF71553A686DC25ULL}
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

	steps = 41;
	X1 = (curve25519_key_t){.key64 = {
		0xEF4050129A1B59F0ULL,
		0x5D1196719ACDBF47ULL,
		0x46F37107FEE8C25BULL,
		0x6D7FDEB8F668749AULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xEF4050129A1B59F0ULL,
			0x5D1196719ACDBF47ULL,
			0x46F37107FEE8C25BULL,
			0x6D7FDEB8F668749AULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xD94B1B2ED6B171CDULL,
			0xB1C4C3ACE10DE095ULL,
			0x21501039CE85C431ULL,
			0x7CEF84FCF378F156ULL}
		},
		.Z = {.key64 = {
			0x72C147163EC9C62DULL,
			0x46900D75705158F9ULL,
			0x41891885B5DB8298ULL,
			0x3029282C74E9E3CBULL}
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

	steps = 2;
	X1 = (curve25519_key_t){.key64 = {
		0xB2A799C124FDEF78ULL,
		0x00EFDD539C1AA48BULL,
		0x98C01D6F088DD5FAULL,
		0x42C339A7BD255409ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xB2A799C124FDEF78ULL,
			0x00EFDD539C1AA48BULL,
			0x98C01D6F088DD5FAULL,
			0x42C339A7BD255409ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA47F176B8AB3092BULL,
			0x2FB866361BCDD00FULL,
			0xCD39E76B5DC55BEDULL,
			0x35739E6C97065207ULL}
		},
		.Z = {.key64 = {
			0xE0D382F16CDBCE0BULL,
			0x4B0ED8013D0506D1ULL,
			0x3BFB7B700F092A88ULL,
			0x59C692F3E2E7DBFFULL}
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

	steps = 28;
	X1 = (curve25519_key_t){.key64 = {
		0x500E6C399A6D9AF0ULL,
		0x67C9FF43A4C1D98BULL,
		0xCA06164D0F932829ULL,
		0x4058F0CAE40C0AA4ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x500E6C399A6D9AF0ULL,
			0x67C9FF43A4C1D98BULL,
			0xCA06164D0F932829ULL,
			0x4058F0CAE40C0AA4ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x54DCD1324829904DULL,
			0xB9EDEF722ACC941FULL,
			0xE26854E27E1D1173ULL,
			0x09AD7AD7A4430954ULL}
		},
		.Z = {.key64 = {
			0x3B8347CF56EFC77BULL,
			0xC8EEADCDA8610756ULL,
			0xBF36C4A08B56328CULL,
			0x2E6B5FFB933C41D3ULL}
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

	steps = 60;
	X1 = (curve25519_key_t){.key64 = {
		0x8FCEFA2EBF9086C0ULL,
		0x94A8D504692284A4ULL,
		0x2C29B1924E491F65ULL,
		0x7091D89DCE45A992ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x8FCEFA2EBF9086C0ULL,
			0x94A8D504692284A4ULL,
			0x2C29B1924E491F65ULL,
			0x7091D89DCE45A992ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x3735BC55E6E21A6CULL,
			0x402B23CFD68C32F7ULL,
			0x4AEE3E6559838BB7ULL,
			0x5F1E676AF477E32FULL}
		},
		.Z = {.key64 = {
			0x2BF21983845C41DEULL,
			0xF61CFABBB3DEBCC7ULL,
			0x54702E04763EE4A3ULL,
			0x25D626F15C1A92FBULL}
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

	steps = 16;
	X1 = (curve25519_key_t){.key64 = {
		0xA288A7EC72AFC528ULL,
		0xED20D8B53FAFD975ULL,
		0xF762E50A7AC6A255ULL,
		0x51F1EC0C5B2013E5ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xA288A7EC72AFC528ULL,
			0xED20D8B53FAFD975ULL,
			0xF762E50A7AC6A255ULL,
			0x51F1EC0C5B2013E5ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x10EA125418A0C3A3ULL,
			0xC96568305E7AF007ULL,
			0x3EC597BA0D91CB84ULL,
			0x66AFF1D41905D21FULL}
		},
		.Z = {.key64 = {
			0xCDD140E7C361D355ULL,
			0x962804150DD153A2ULL,
			0x04DC1DB3003A2B74ULL,
			0x359149735126B51EULL}
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

	steps = 53;
	X1 = (curve25519_key_t){.key64 = {
		0xF9A7768D3E73AAF0ULL,
		0x42108A96885C564DULL,
		0x96429AF3302EA33EULL,
		0x72CC9AC0A57B7A0DULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0xF9A7768D3E73AAF0ULL,
			0x42108A96885C564DULL,
			0x96429AF3302EA33EULL,
			0x72CC9AC0A57B7A0DULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x05348EBF3BE65DACULL,
			0x9F0200FF1DDEAC1BULL,
			0x6B610A3F77C4C720ULL,
			0x409DD7B4A01628A8ULL}
		},
		.Z = {.key64 = {
			0xCB1A7CA5E32DB699ULL,
			0x324220588225CD71ULL,
			0x3DB53A5234F060DFULL,
			0x49DD997C69E6BCECULL}
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

	steps = 13;
	X1 = (curve25519_key_t){.key64 = {
		0x2A6CC1DD5EDDD4F0ULL,
		0x7C5717F3A38C5BACULL,
		0x9852CCECDD1FC5F5ULL,
		0x62C54E95007843F0ULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x2A6CC1DD5EDDD4F0ULL,
			0x7C5717F3A38C5BACULL,
			0x9852CCECDD1FC5F5ULL,
			0x62C54E95007843F0ULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x647E519EFD4E749CULL,
			0x58E24C1E0BB69E12ULL,
			0x9DB3DEC4A0CEFD63ULL,
			0x104A782A9FCE30E1ULL}
		},
		.Z = {.key64 = {
			0x90A52308EE0A2B72ULL,
			0xB21BFCCC9B7BD4C0ULL,
			0xAE393DEB3845C4BCULL,
			0x302D895268250615ULL}
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

	steps = 2;
	X1 = (curve25519_key_t){.key64 = {
		0x04E16471D0B057B8ULL,
		0x73C9530744373B55ULL,
		0xFAF15F8A6F7C95B8ULL,
		0x6AA6FAE3FBB8A2DDULL
		}
	};
	XZ2 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		},
		.Z = {.key64 = {
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3 = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x04E16471D0B057B8ULL,
			0x73C9530744373B55ULL,
			0xFAF15F8A6F7C95B8ULL,
			0x6AA6FAE3FBB8A2DDULL}
		},
		.Z = {.key64 = {
			0x0000000000000001ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL,
			0x0000000000000000ULL}
		}
	};
	XZ3n = (curve25519_proj_point_t){
		.X = {.key64 = {
			0x90744E3FB05269D1ULL,
			0x67F875E0175AAFFCULL,
			0x62CF808F9D5E8EB4ULL,
			0x75015E3B21333C3FULL}
		},
		.Z = {.key64 = {
			0x034CF2F654E6FF20ULL,
			0x860C66C63202F853ULL,
			0x12F62F2F211DD8FEULL,
			0x0DBCA3CE0DF30F49ULL}
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