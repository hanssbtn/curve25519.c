#include "../../curve25519.h"
#include "../tests.h"

int32_t curve25519_shared_key_gen_test(void) {
	printf("Public Key Generation Test\n");
	curve25519_key_t priv_key1 = {
		.key64 = {
			0x63D3BF56A59780C0ULL,
			0x0F0F77BE6383F4ACULL,
			0xBAE108196C0A0C48ULL,
			0x5FCB62D1BCB6FC3DULL
		}
	};
	curve25519_key_t pub_key1 = {
		.key64 = {
			0xF4C62E4D3A90E599ULL,
			0xB71950E2BD052A97ULL,
			0x57A158ACFE150BB1ULL,
			0x02AED64C391E97F3ULL
		}
	};
	curve25519_key_t priv_key2 = {
		.key64 = {
			0xDEC950F4ACCAF320ULL,
			0xB3778AE8DF3CF1C7ULL,
			0x74D3DFCC853E3E8EULL,
			0x70E98561A8D51B0EULL
		}
	};
	curve25519_key_t pub_key2 = {
		.key64 = {
			0x4E4FFF43C1680D3EULL,
			0x2FD445A5121DC24FULL,
			0xA11FC2AD6C056866ULL,
			0x6B42B9D3C40972B4ULL
		}
	};
	curve25519_key_t shared_key = {
		.key64 = {
			0x3DF2F2DD1BDCFA42ULL,
			0x3A46B76DABD6F03EULL,
			0xEED792204CBA3850ULL,
			0x3E884D40CB0AB773ULL
		}
	};
	curve25519_key_t r1 = { .key64 = { } };
	curve25519_key_t r2 = { .key64 = { } };
	printf("Test Case 1\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	int res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 1 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xF9B8831E790D62E0ULL,
			0x3B1E5CAE9D4AA62DULL,
			0x76D55C6493731D81ULL,
			0x7025D1F04296F9BAULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xAC72281AB355534CULL,
			0x77C2BF4CA948C8FDULL,
			0x99ACEDFE1683D232ULL,
			0x4BD3F2381DF52189ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xAEF41608A0F10158ULL,
			0x4B82189B06F8FA5CULL,
			0x41B1FF8321B3FD58ULL,
			0x6A08EF4562A4969CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x975C0E499BEF7C12ULL,
			0x7E2E2388C55759C9ULL,
			0x86B3B2D379CADA51ULL,
			0x270589C1470C0A2BULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x8582436EA01E4C05ULL,
			0x85473E48A176197FULL,
			0xCB83022ACD479EFEULL,
			0x72A8BE70C0D45A82ULL
		}
	};
	printf("Test Case 2\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 2 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xC2D31C44E3E9BF30ULL,
			0x47E18BBDF2415C1AULL,
			0xB66F3AB3B5CC4757ULL,
			0x4E6801FD4FF99517ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x81A0A34882A938CAULL,
			0x16EE7B6D1A018283ULL,
			0x029B7E0C4DC53EF6ULL,
			0x5FB4AC211D82C5E1ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x13EE50641B91F300ULL,
			0xE3BF8D06058DDE44ULL,
			0xF31B15547CD0F3B9ULL,
			0x5F1FFF412040A6E2ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x073B802E15BB7429ULL,
			0x56EA1CA0453853F4ULL,
			0xCAD36DEE9F199DEFULL,
			0x11D30F5CA4E8CDC7ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xCE1316B3307B3B99ULL,
			0x9A5ECB494F07A1BBULL,
			0xE4B329A7A7923849ULL,
			0x113355CCADAFD392ULL
		}
	};
	printf("Test Case 3\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 3 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x890332A5DDA890A8ULL,
			0x8A9610F9B4FD55CBULL,
			0x888DC3C7D8972555ULL,
			0x52B5E97043AB1E37ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x623DFA35A6B0A1F0ULL,
			0xC7C50349B8149C58ULL,
			0x8B1DE5C2ED697593ULL,
			0x7EC4ECC64686331FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x1C3B178040E01BE0ULL,
			0x81E8586C009A91DDULL,
			0x4E20F58AB6A2AB17ULL,
			0x7B4813C07DB3F27EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xEC3F12EB5FAEA511ULL,
			0xF173DB93E379B441ULL,
			0x3316EE00BA2752DEULL,
			0x050382759B9DF021ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xFD3942661C21C6C1ULL,
			0xAD235C8E954FB543ULL,
			0x2D0AC6CF836579B2ULL,
			0x339B4AD753BED982ULL
		}
	};
	printf("Test Case 4\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 4 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xF47B13C41B468360ULL,
			0x6A13BA7CCBB4E94EULL,
			0x56E1F8897F076C65ULL,
			0x5CF61EB38B713595ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x0E5AE33EA2679DD1ULL,
			0xE17AE83C76D5B618ULL,
			0xF1FCE774D2D21568ULL,
			0x2B0556302F6F31C9ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x3D516B72EC169F50ULL,
			0xD412A823F181D0C7ULL,
			0xCAA304A37F6E83A6ULL,
			0x7647CDEF1204DD9AULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xC5E1836973F304B0ULL,
			0xC04C915E8611C28DULL,
			0x110C86AED234F918ULL,
			0x61DEC8B4BDB143D6ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x243908A14CCA6CE2ULL,
			0x6A93B3E33E8507FFULL,
			0x3DD2497EBFBB7513ULL,
			0x5592536B2D71F23BULL
		}
	};
	printf("Test Case 5\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 5 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x84A5C425A3F66D10ULL,
			0xE66A177A9217132AULL,
			0x2283E898FBD9B495ULL,
			0x408600754A365140ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x8E07279D940055A8ULL,
			0x1D6B9E97ADD931AAULL,
			0xCADC6DD5B0977A18ULL,
			0x399E76203565187FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9F5171CA7A2CCF58ULL,
			0xE5764F1E905CB7E5ULL,
			0xD8E3F790971FD1FDULL,
			0x40E609B3209DA245ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF22B84DC5E386906ULL,
			0x5F6F1237E60B44E4ULL,
			0xF3D8513341229A06ULL,
			0x5CAE042727134985ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x5F7C8A48A2CABB1BULL,
			0xF239E7FEB11C2CA3ULL,
			0x552E39F889B10C58ULL,
			0x4152672D975280F0ULL
		}
	};
	printf("Test Case 6\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 6 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x8E5CCCD37590FA20ULL,
			0xCD220FFF56E14292ULL,
			0x83A5237A22F84097ULL,
			0x7C12012091ED5D5FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x2E7F2938F6C66602ULL,
			0x90233E3A96E7D6ECULL,
			0xA95E72459E691D3CULL,
			0x05512A372CF74B10ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x8DDC5B8655C95320ULL,
			0xAC08F9EE02934A97ULL,
			0x0958E4D27A3F8E70ULL,
			0x54FCFE1239FE3286ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x77D90D56025BB8A9ULL,
			0x4A5CE085C1D67489ULL,
			0x712ABBE2E3981D8BULL,
			0x78127B5E441C3024ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x5FB9EC12BB19D7ABULL,
			0x5DD21761C42F011AULL,
			0xCDE6419284563261ULL,
			0x0B23203AFB87A3DAULL
		}
	};
	printf("Test Case 7\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 7 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xCAFB4096856303C0ULL,
			0x76AF67DCECFC3A91ULL,
			0x8C1FAD944BF0032BULL,
			0x5770A44CA6F7207FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7C32AB3793EC59D6ULL,
			0xB865EC04BAA7E834ULL,
			0x7658273CF8BE6F3FULL,
			0x631F7164658B22BEULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xEB2D54E0380B52B0ULL,
			0x3493024DD1A3B4A9ULL,
			0x7553AC1AE4747D6CULL,
			0x50DB6EB35B26236BULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x4C90CBD6AA6C396CULL,
			0xC718E64C1FC37A94ULL,
			0x7DA0E13E0CA1F887ULL,
			0x528C9F4E324A93A2ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE683AF2BCCA1BC80ULL,
			0xDFA7B66E5EB93C23ULL,
			0x9D593C1C09BDA5A1ULL,
			0x496C75B123F0FF0FULL
		}
	};
	printf("Test Case 8\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 8 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x95EE0995B58754B8ULL,
			0xA7DA19AA9168DA82ULL,
			0x93856E78282135D5ULL,
			0x7FD24C3B790064CCULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x204859A843D92CA3ULL,
			0x991F62C8E99989E0ULL,
			0x019C8610EE575C62ULL,
			0x053FCBE6095635E2ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xA4473D1B7282AE18ULL,
			0x1A38848C8C61AA7AULL,
			0x72040B00A9A782E2ULL,
			0x4A14459BE7B256AEULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x34290CBA9467AAB4ULL,
			0x17C9D2E5F68B896EULL,
			0x6D834F96FC2F295BULL,
			0x5AB61CC85155B1B8ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC6E480879BC0E653ULL,
			0xCF11B97BDACACCD1ULL,
			0xC9CA357F3AAC6CCFULL,
			0x5C9A414395DAE86CULL
		}
	};
	printf("Test Case 9\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 9 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xEE5414E3F5FA6B38ULL,
			0x5475F5F5AA7199A8ULL,
			0xB04B2AC87C139E45ULL,
			0x5D8EA6EDE08B4C98ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA0CC6A27679B29D8ULL,
			0x66DA10AFE20C6A32ULL,
			0x64D5CC7DF86B05BFULL,
			0x3367299E4CD0441DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xD811BC06AB53E250ULL,
			0x39D7CDDABF29D0DEULL,
			0xAC4736F6F837F24BULL,
			0x6ECA1C753C3CA8F8ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x6B1EF86A5A0A35C8ULL,
			0x9989162043882CEAULL,
			0xCEF5CE1DEB0B7CB1ULL,
			0x7F4EFD75016DBD71ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x3F29F0F4EAAFCFF0ULL,
			0xEFDA10BF446CDA45ULL,
			0xE2787E0F260DFCA6ULL,
			0x4E1C31C2F996724BULL
		}
	};
	printf("Test Case 10\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 10 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x4FAE629B164085B0ULL,
			0x2068AA8E52FFA277ULL,
			0xB7D99971BE4A61F6ULL,
			0x7940B31F7A1DECA5ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x0E6CD1C72F8C9121ULL,
			0xD881BD1E7B2FF2A2ULL,
			0xEFAFABC8B085D77BULL,
			0x4034FD8690E131C6ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC5E6DBE869CC8500ULL,
			0x74D6EA9E5D57C177ULL,
			0x4CBB92A721092D3FULL,
			0x55A626FDC12CFAB5ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x2931DB83E6BB8EBEULL,
			0x0FFA352981BF1541ULL,
			0xDA1CD98461A1951DULL,
			0x5F7EAE43A7F7FF05ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC99293A304CF33E1ULL,
			0xD24BE5C4C362D187ULL,
			0x7A34D6B13D5D3F3FULL,
			0x1874CC4BA25022ABULL
		}
	};
	printf("Test Case 11\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 11 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xD0277322BEA42CB8ULL,
			0x9C6EF13157A4D704ULL,
			0x4399248A5834E259ULL,
			0x70D9684FC14F2DF8ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xBB7F406FB020AE78ULL,
			0xBD5649E4DB64CC15ULL,
			0x06F464C0B38C5FECULL,
			0x6475FEE3B00896BEULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x321A0DA53D1D6368ULL,
			0x72E49FE25FC2360DULL,
			0x8BB61E955478B713ULL,
			0x5C5796B18BD68E24ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x94948C12A384BB6AULL,
			0xA00912B5661CB9E0ULL,
			0x2E08E088A8F39E51ULL,
			0x6A18F82AA68FAE13ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x3F9747E7311C639EULL,
			0x26581F407696EC01ULL,
			0xB690DD9AA0B4E98BULL,
			0x22AD5428EDBF14D0ULL
		}
	};
	printf("Test Case 12\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 12 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xFC890A81FCA29788ULL,
			0xF3C4098E54EFF373ULL,
			0x5ADE8F76BE339361ULL,
			0x5A173211509A0775ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xDB1B41E64A9F2177ULL,
			0x3AC568C9C9EC394AULL,
			0xA657E7A15D089EABULL,
			0x69AA1D4C698C2B55ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x0F15BACA9A18AD90ULL,
			0x90EDA590B0F8BB5EULL,
			0x50AFC84B8B850735ULL,
			0x4BC1B080DE8B6DC9ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xCDF36A3E302C445CULL,
			0xB949AD4161CCB135ULL,
			0x000011044E0A11B2ULL,
			0x6B5CF15D33DFEEF7ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x2D3C34F9DC0A745EULL,
			0x01F683C4C9096910ULL,
			0x72C87ABD87164374ULL,
			0x6595A94DD91842A7ULL
		}
	};
	printf("Test Case 13\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 13 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x58551533E91ACBD8ULL,
			0x5C58554CDE44D9D3ULL,
			0xAE7F76C7A21BECFBULL,
			0x52433E776DD7AC5AULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xDEFC27279B2D8BAAULL,
			0x073BEF65FFDC6382ULL,
			0xC2CBE5D928F3858BULL,
			0x0049B5A5B2087D06ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x01B368E5AC259DF0ULL,
			0x4BE00B1AAD4DA640ULL,
			0x34701F6A175CA281ULL,
			0x644C7B6921E62CACULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x18934F5B204833B6ULL,
			0x8D533F060B454840ULL,
			0x3A7D992C5BFF6DF4ULL,
			0x4A948D2FAB9A1DEEULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x681B70C9880D6DCBULL,
			0x1989452236A25308ULL,
			0xBE999081CF743B42ULL,
			0x5590F2EE20B3FA16ULL
		}
	};
	printf("Test Case 14\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 14 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x697BACD358F1F958ULL,
			0x21D80A1D061B8737ULL,
			0xE6015A674867F263ULL,
			0x547D2D9B772A85B1ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x6BE11B243F21C8F5ULL,
			0x28FEF1AF3F111C05ULL,
			0xDFBD8D7071FEA088ULL,
			0x7B7D6708087128DAULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xDA4E0D1A9EF67948ULL,
			0x4049D73AD4EB17B5ULL,
			0x4A142A076F059936ULL,
			0x44C451C257A6C4CBULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x910A5189224EEB84ULL,
			0x565D129BAAF83161ULL,
			0x3836699CFFDC5E5EULL,
			0x5DBFF7BB6C9385B1ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x9F585752ECD77A73ULL,
			0xAFE419B09B22A6ADULL,
			0xBA22E5B3396BF152ULL,
			0x2EB4F28166981F9BULL
		}
	};
	printf("Test Case 15\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 15 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x19394100D8F68AD8ULL,
			0xEF82ED83E13F3CC7ULL,
			0xF00F59BD5CDD8D0CULL,
			0x78B9F02C570C4CA5ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x664421B2773040ECULL,
			0xCDC62BF9F379BBAFULL,
			0x4C77463FBB70673FULL,
			0x4FF05068A8ED6253ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x3329562005B3F648ULL,
			0xA56867B4E2B8DB4CULL,
			0x1817457BFC12CFFAULL,
			0x6579ECFA0C50E528ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x751AC10C8AE6D843ULL,
			0x2F95CDC45B24142BULL,
			0xE66AEC63B7014F4BULL,
			0x35655A4B9E86BAAAULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x4A8CA14AF5CF30ACULL,
			0x300FC870D578FEA8ULL,
			0x1F3913AC8959BC43ULL,
			0x0EE92C721151942DULL
		}
	};
	printf("Test Case 16\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 16 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xE91A5DF0AF98AF28ULL,
			0x22A30C13A7FF1E6FULL,
			0x1E7524E078FF27E2ULL,
			0x6A55FE2F63472D07ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xC56A77A31E617B6BULL,
			0xB76D55781717B0C5ULL,
			0xD097574E841DBCF1ULL,
			0x7D2A56EB9B856DA8ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB10BE411B2250F80ULL,
			0x7A509EDE87B68B8BULL,
			0x0ABEBFE1120BDD78ULL,
			0x572C4EE9BEB26438ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD0A89C30218C64F2ULL,
			0x3ADAFBE852C9BD08ULL,
			0x72699AD573C00B70ULL,
			0x1CD437C4756F1AE7ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC7D544233B665A97ULL,
			0xE49700F60AA86195ULL,
			0x71750B4D251F831FULL,
			0x1044FFF7452A5550ULL
		}
	};
	printf("Test Case 17\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 17 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xFA840E4C76D34948ULL,
			0xF022EFB5BFB1C936ULL,
			0x690C685BA5A8C644ULL,
			0x68C42F0C05607366ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE327CEA7E907B79AULL,
			0x9E74F88E3DBBBA93ULL,
			0x91D7C0D4ACC04324ULL,
			0x3387A049551D9656ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2A0D05C5842BE0A0ULL,
			0x07BAD6C61E0F0CA6ULL,
			0x79D034BE520C8F37ULL,
			0x45EBFA425E7284EAULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xC1E521BB5416AA42ULL,
			0x1D8D8556839487DDULL,
			0x1CE2DD1492BF764EULL,
			0x3237FFC5332C586FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xCF0551E93469FF1AULL,
			0x2527310D1AAF5E09ULL,
			0xCCB65867CB89CA1BULL,
			0x72BD9D913EF832A9ULL
		}
	};
	printf("Test Case 18\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 18 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x1EF46D1F839CFA68ULL,
			0xDDEDFFB1CFB68960ULL,
			0x1B7875A19F8CF18EULL,
			0x4C8CAD755794A5E7ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x60F21751CA675E92ULL,
			0xF54FCFA1983BCDA4ULL,
			0x1C1DAE8504B16945ULL,
			0x73822DEF8C7065B4ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x5DA9EA8527FD0858ULL,
			0x8B7F1390DF507D80ULL,
			0xFE8AE6AAE8520219ULL,
			0x74BF5B2206D9F157ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x310B03089A15558EULL,
			0xB4C38F06D462F73AULL,
			0xCBA50E97E8C670A4ULL,
			0x6BDB217AF8293538ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x6783C0AB53D977DEULL,
			0xE64FEF4DF2A7D393ULL,
			0x0D59E1A23F84E554ULL,
			0x1164C97B6D6CC3A7ULL
		}
	};
	printf("Test Case 19\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 19 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xEA1CE6F327624D60ULL,
			0xA981CFC82FDD7C4FULL,
			0x618C6774DE2241D5ULL,
			0x506B4FFA0A3D342EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xEC0DE6012405C0E7ULL,
			0x776BE5F847AEBFA7ULL,
			0x1D057FFEB5514282ULL,
			0x26E3C47C312FBBD5ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC2AEF461DCEE5E10ULL,
			0x1243CF70B4C708C6ULL,
			0x16FD50ADAAEC03A5ULL,
			0x5E2C8951A692CF69ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF1EEA5F4A2CE77AFULL,
			0x85229FD14FBEFE86ULL,
			0xF218879B302E42AEULL,
			0x666B26447CF6A8F6ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x141CAC7497807CC0ULL,
			0xDA7D7D3B5A6F3E9EULL,
			0x3224CDAF68AEAE20ULL,
			0x0152F167C5E1F509ULL
		}
	};
	printf("Test Case 20\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 20 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x1FC5B8738BB91CA0ULL,
			0x3F4E88363D32F431ULL,
			0x17C38F74B5CF5F38ULL,
			0x4FDFE40D7E30F9FFULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4FCC6E1DF322934BULL,
			0xC10FC98F9A044913ULL,
			0xE6A2EA19DCDCFC55ULL,
			0x4386A67E27C2DCE4ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x1F08C507A9DEBA78ULL,
			0x9F916A4E7EF009C6ULL,
			0x307E547B43688CC0ULL,
			0x55C2B2B8963D264CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xCBA87B79D3E9B383ULL,
			0x20CFF1EE5819DF12ULL,
			0xCD85998FD5C3F4E2ULL,
			0x46A6AB5A5DE0A201ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x6BC22FA537E3E3DBULL,
			0xB62CC17EADA3B58DULL,
			0xEEF266662CAD61CAULL,
			0x7E9537B5FFAD67FDULL
		}
	};
	printf("Test Case 21\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 21 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xFDC74B088ECF4638ULL,
			0x2797107E0EACD502ULL,
			0xB2DA019EF0A9610DULL,
			0x6B871722DFF19E65ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x86AB85E7ADB84BA7ULL,
			0x4CB0C88389373E55ULL,
			0xEB8D61022319D33CULL,
			0x02B6CE70ED71E250ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC9F710E65B0F1130ULL,
			0xE8F6F05FC30C295BULL,
			0xE45B940D144CE26CULL,
			0x41917A297F715FE3ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xAA4C96F99AB4CC8FULL,
			0xDA0BF8395D773BD8ULL,
			0xC0296DDA7CB1C8DDULL,
			0x1924BCC66FB94A6EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x00CC7F85FAD2B8C8ULL,
			0xB77D2FE49A6645ECULL,
			0x7BE0524918F4EB5EULL,
			0x49DB29B3A7CEFAEDULL
		}
	};
	printf("Test Case 22\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 22 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x6CF85521DD0E9F20ULL,
			0x592C9BFBFC35716CULL,
			0xAA3B5E7FCEB75059ULL,
			0x4F64A32A83207553ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA5769540FF65A243ULL,
			0xC2BBA5CF4A8782B0ULL,
			0xC0043CA427AD2A30ULL,
			0x7CAA6FF7C8920A0BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x0354C7AB5E501FB0ULL,
			0xDD5A220835ECA9F0ULL,
			0x6BFEBE75E29DE4D9ULL,
			0x6137359AD4AF57CAULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x04537CEC00C389A1ULL,
			0x9DCC6CFDD83BCDEEULL,
			0xF7BAFB9BB8B21B2EULL,
			0x55D8F7DD1B044C0CULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xFABB846739BB10B6ULL,
			0xE68531317268A8F7ULL,
			0x94A41D03901F5A07ULL,
			0x4AF8BAF81B3D8BA1ULL
		}
	};
	printf("Test Case 23\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 23 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xEAB2A18C5D66FAF8ULL,
			0x028C33FB6CC8CA1BULL,
			0x7AD31474BD57603CULL,
			0x54B865F0B863A147ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x79914585AA1B44ABULL,
			0x8B9F73BFCCBD45E5ULL,
			0x6948DE799C5CCF61ULL,
			0x58D50AFF35C33047ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xFBE475E45983BD28ULL,
			0x53D57B6006AAAFEAULL,
			0x3A75032131666352ULL,
			0x543B4C404E65B175ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x7F117854A238800EULL,
			0xCE2D4E14C387B7B1ULL,
			0x8B3CA4F0A20E6FC4ULL,
			0x1FA068C61F075B60ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x4E2180119E18683EULL,
			0xD57C69B214DD1737ULL,
			0x47CF5472A5876A44ULL,
			0x2EAD5866C9D5BFFEULL
		}
	};
	printf("Test Case 24\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 24 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xD91108C743BC87B8ULL,
			0xD0CAFCEF315EBB62ULL,
			0x76D2E70FBB1F7F4DULL,
			0x40FAE97FE80D35DFULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x1A91780E289F8C38ULL,
			0x8308760E6F20E89FULL,
			0x838EB16CB1ACD657ULL,
			0x2BFEA89C5393FA85ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9B112ECF134DB1B8ULL,
			0x80A4B40CBCBFD92AULL,
			0xAB82658708B9C070ULL,
			0x400CEB68BCF2EDD0ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xC860FE0E474A2B88ULL,
			0x335060BAEE8D32C9ULL,
			0xA736911337EE42FDULL,
			0x19C3FA1B1F727A03ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x39338220381E297CULL,
			0x535D1A00137356BDULL,
			0xD41C3E3029BEE9B1ULL,
			0x5AFA6D21FEB34E49ULL
		}
	};
	printf("Test Case 25\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 25 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xDBE92AE03C7C4368ULL,
			0x3FA0885F5FC80547ULL,
			0xB1A49F23EC28A191ULL,
			0x5AE1A3012C9E1F74ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x6739FC92772DCE9CULL,
			0xC12114DA9331E254ULL,
			0xEC296DDB3079FD69ULL,
			0x59BC00383FCF6963ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x70A8CE67C90421D0ULL,
			0x72A8E38CE79EC9BFULL,
			0xA2AE5C27C5D8F504ULL,
			0x77BFE3EEC62A489EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xB597D0298913C650ULL,
			0xAFD05071C3908B5FULL,
			0x1CBCFAF60B13F753ULL,
			0x361C6E438824BBBBULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xFF4036BF59E9E143ULL,
			0x5842084A64B65DD9ULL,
			0x7B81A01AA6A2D0D5ULL,
			0x60FF28B38229574FULL
		}
	};
	printf("Test Case 26\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 26 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x60C67BCD21952FB8ULL,
			0xF18A4B2D2342CF51ULL,
			0xDE293C60DFE5C664ULL,
			0x472845575517E3E1ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x0A422CB40EC8A875ULL,
			0xA74A9EA3A0092E4EULL,
			0x2019BCB66F07432AULL,
			0x5D5C2AB2B050987DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE623DBC1DF35D248ULL,
			0x047A03BEADD9ADFFULL,
			0xB9F6A24D9C16DDE1ULL,
			0x612A4D2386DC3935ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x3D49F8DB27B1FEF4ULL,
			0x3276D48740481F6AULL,
			0x946BB35EBA4046E0ULL,
			0x1CF93C7DBADB6F30ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF9904E6525006016ULL,
			0x24E2C57BC23AB877ULL,
			0x2323EC036B512946ULL,
			0x27DFBB5EA6736D98ULL
		}
	};
	printf("Test Case 27\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 27 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x81CA6E14E19CF880ULL,
			0x4C305AD4E6F02E5FULL,
			0x4F16A1E7876AE023ULL,
			0x638DE2D50363430DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE642FFF9B4EF1884ULL,
			0xBC1749F91E4F5DCDULL,
			0x209EA3EDA954A92CULL,
			0x48F26CB8A3F48C00ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x07E009677250C388ULL,
			0x1DCC711E4F21C38BULL,
			0x87C874B64CCBD92FULL,
			0x7F0C7089CBE1168EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xB58D3A9149DEB4F7ULL,
			0x10E9C8C36DF9E1B9ULL,
			0x0504B417181F4A7EULL,
			0x1059CA043006F5AFULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xCD1D80DE0171DE4AULL,
			0x019E19C40A87F860ULL,
			0xD1DB3A6ABF15FA49ULL,
			0x78A38086C7831EDAULL
		}
	};
	printf("Test Case 28\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 28 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xBE7AC818485F10D8ULL,
			0x94501C4C29E23267ULL,
			0xF10B02A4A240D5F4ULL,
			0x720808140CEF16A3ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x2C340F90A62CC8DAULL,
			0x4BFBBD2F869AAA50ULL,
			0xDBE3AE1DBA52C1C2ULL,
			0x3AFB3293F272F045ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2D8858BEBE93D3C8ULL,
			0x16C3A73A1E618501ULL,
			0xA9A055EE95135E45ULL,
			0x50C37BF3618E21C7ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x685F209A9C7658A8ULL,
			0xE24004E8BC60A08AULL,
			0xDE3C2590352D5798ULL,
			0x57F2AF4E5328D5E2ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x1AE2330F65B34FF5ULL,
			0xB9EF3AA03A8F208AULL,
			0x566F08A5A5CEBAF8ULL,
			0x3DEE4E79A75A0ED6ULL
		}
	};
	printf("Test Case 29\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 29 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x787D22C726E99C20ULL,
			0x092358DC9D9E813AULL,
			0x33A1D97849A2DDA3ULL,
			0x52B40DBAA9A23A5BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE14791AE418DEB8DULL,
			0x5785E0B75264F44FULL,
			0xB158B02111B5C04EULL,
			0x27B8844B5FA30B74ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x86FABF6357A29F60ULL,
			0x17523019673D0B74ULL,
			0xB83C97189B978BDDULL,
			0x4D4A397DDD349D31ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x4729E8FECDD89E93ULL,
			0x568650B872BC4FB0ULL,
			0x2846477AA7D435C8ULL,
			0x11D6D19D07102E25ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7641F14586D2D45CULL,
			0x69041872F3CDC8E7ULL,
			0x1D4C8C61EAF8CBF1ULL,
			0x53496EB4BFBE24B7ULL
		}
	};
	printf("Test Case 30\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 30 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xBBDFB74D3E7414E0ULL,
			0x4A7B3F26824C6387ULL,
			0xA4BAF0D9C8516832ULL,
			0x4B6C989E0A017BCBULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x1292C68A71CCCD5AULL,
			0x87C25FC78C9E9AFEULL,
			0x057ED1A7B24444D1ULL,
			0x7042D06534B63611ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x5AEBFE98E8920E40ULL,
			0xE177FAE866368ED5ULL,
			0x377C9D8F81D417A9ULL,
			0x7F123409D0F5846DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xBED4CE412539D897ULL,
			0x01A2626BE1D0E523ULL,
			0x6A9B78164DDA3E87ULL,
			0x7812F755D467667BULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x4A4E7ABB609B5CBEULL,
			0xDA0E2304B5C71268ULL,
			0x9EF7268E2CD402C2ULL,
			0x4F6F04608B046447ULL
		}
	};
	printf("Test Case 31\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 31 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xB5B4A527C1F24C78ULL,
			0x37D370B32FEB7B7DULL,
			0x310DC23D5BC93D77ULL,
			0x6DDAAC1D484400B2ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x6E651F9EB0168C84ULL,
			0xCDF5657F1158B9DFULL,
			0xE5839A061D6E618FULL,
			0x12333DD8D818F9C8ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF1F45908932A66D0ULL,
			0xD34DB8129C28370CULL,
			0x19FDE9977DAA35EFULL,
			0x4DE79A57B0E65C5BULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x91B9554470B9B27CULL,
			0x1241D7C07217FD72ULL,
			0xBB8D035B9950F2F4ULL,
			0x35A2B950025A900EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB2E5927275D050D1ULL,
			0x046458F2CDF5D712ULL,
			0xCDD03829E381C6D5ULL,
			0x23F7D721B1273473ULL
		}
	};
	printf("Test Case 32\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 32 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x1CF9D1401464BCC8ULL,
			0x5A256C8F91E37185ULL,
			0x24FED51C2B767E3DULL,
			0x503E8FA359CF241EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x83507D556EF356B3ULL,
			0x52602A7BDB60FF36ULL,
			0xECC27722E47BCA40ULL,
			0x5F42969DEC51852EULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x587101F5C868B2D8ULL,
			0x66E8A68C2EA50C2BULL,
			0xF965952D87797F40ULL,
			0x4A2E7F50A80E100CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x515AD29FA6FC3C23ULL,
			0x0A4C6429BADF7997ULL,
			0x3C23FA86DD265F08ULL,
			0x222E6BBDD05DBA21ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD65616E2EACB7343ULL,
			0x567EDD72D5768122ULL,
			0x093FA07001F99BD4ULL,
			0x7952D568E3A86B20ULL
		}
	};
	printf("Test Case 33\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 33 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x0053F33CEFA84700ULL,
			0x330FCBB0DA1E6981ULL,
			0xA936B5CE2FCE6E27ULL,
			0x75B39F13C4E1E194ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x6D7EFE90929EBD1AULL,
			0x3AC54F3364CB90A7ULL,
			0x25F018EA8EB2456BULL,
			0x1C98CFD71F046245ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x364B403430C16FE0ULL,
			0xBFF9E0219839FB44ULL,
			0x0D940C737E583534ULL,
			0x5464E3FAE52BFC76ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x89B0EF0A2BAF338DULL,
			0x373AF5467D30A757ULL,
			0xB7559EF7B6A0FD6CULL,
			0x68F119ABDB0EDB32ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x1F6121A2F627C9AEULL,
			0x97FB51595E37CD91ULL,
			0x6A19E33D3D3E2C4CULL,
			0x0170DC4110AE13D0ULL
		}
	};
	printf("Test Case 34\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 34 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xBC332123FCEEEC88ULL,
			0xFB33780D90AD4370ULL,
			0x981440C80958C29FULL,
			0x543EFC0BBE5BE72AULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x471BFAE26069484AULL,
			0x841816FE82836764ULL,
			0x47E66A5A5EC9507BULL,
			0x4007173E6B607A80ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x1EEFBE813A07B120ULL,
			0x8C78152102AC15BAULL,
			0x9703B50EA250CFB6ULL,
			0x5555C13AC03295C0ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x0D4F16CDD2E1EC7FULL,
			0x5848C30E7C9FDFE8ULL,
			0x8CD912A61CA10352ULL,
			0x052962298A7487D5ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x22501F1D4B13220AULL,
			0xF5527FE93587E4F8ULL,
			0x12725E1821F0750FULL,
			0x18FCE23543DE702DULL
		}
	};
	printf("Test Case 35\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 35 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x2147C55ABF23E7D8ULL,
			0xC91A7087821C7D93ULL,
			0xCE3F1B8549532F3AULL,
			0x68D3A8D740290DA6ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xD1A6FBDB4A814417ULL,
			0x46BACCDF42F6E6DEULL,
			0x1EC623F5CCD01FEAULL,
			0x3DB33F992DB9B4ADULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xDD10E6E49D3A8560ULL,
			0x2F6834DEA0879D6DULL,
			0xEDA74103B9C34BADULL,
			0x66DCECEB1C2410B9ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x412466CDCB8FE45CULL,
			0x490298FBDECA8629ULL,
			0x133A88D82E75B36CULL,
			0x31383D2E5BB4A96BULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE4EB6C861ACB3E79ULL,
			0x1D2F3C1427B2FD5CULL,
			0x8AC2CBA2D1365830ULL,
			0x0C42F5E37474C3D6ULL
		}
	};
	printf("Test Case 36\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 36 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x8EC7453564D2ADF8ULL,
			0x20CF14E2C8B75022ULL,
			0x7D11EF48B8D2B648ULL,
			0x6A1BBC76766490E3ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4FEF6BE333B83E9FULL,
			0x00602FF399E237CBULL,
			0x1EC3951F607DC8D7ULL,
			0x00EB27DA5877DF76ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x92267D1765D40028ULL,
			0x334BE2A6ADF2A8BDULL,
			0x8AA38B90E185B6AFULL,
			0x4EF49C79A5F71E90ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF2A43F612614B0A4ULL,
			0x32899DAC00AA0BFBULL,
			0xFD5C9EBC30EFAA21ULL,
			0x4EA9430C76123E72ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB268D3EF8F2CA0F7ULL,
			0xAE611235A1A7D630ULL,
			0x34AE46BAE7BB9BA1ULL,
			0x2209BCCAB0648AB7ULL
		}
	};
	printf("Test Case 37\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 37 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xE4405330EA08B600ULL,
			0x6EAEED31935973C8ULL,
			0xD3DF3EACA29CCCDCULL,
			0x72510B981390401CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE03776E0172399B6ULL,
			0x9E3725121117DBDEULL,
			0x2B89CF05BAD68CD1ULL,
			0x0AAC49551BE0625BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xA2F47EBB5D18AA50ULL,
			0x802D43912369AF3FULL,
			0xA2D25AE8A1615FC5ULL,
			0x7EA3C53B6A6CB6C1ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA6D55AA562C016D0ULL,
			0x476683F862773F08ULL,
			0xB15B74D2353593BCULL,
			0x73F876DADF97D2AAULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x2E2E1156B8D72ABAULL,
			0x921615A189C571A7ULL,
			0x9E3453FD7A954754ULL,
			0x4DC4B959954EE551ULL
		}
	};
	printf("Test Case 38\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 38 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xF34D088073B209E0ULL,
			0x22BBA2365B35A9D4ULL,
			0x12C71F9CB12A8BBEULL,
			0x733BA4335B78656AULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x0438D99896A6915EULL,
			0xD6AE020A2CA37FA9ULL,
			0x17DF5C26E300089FULL,
			0x2EF12712AE446507ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB3ED4646B6F67248ULL,
			0xB701E3C68F4B5A55ULL,
			0x0B9E20B2DE562BAFULL,
			0x60E056B64B0FE127ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xE3B43CD8D5B5AD24ULL,
			0x9735D4D26FA6F154ULL,
			0xBE8120C8E5947266ULL,
			0x79D381D6DD7FB197ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x42D4F8AE0522D191ULL,
			0x31FAA51DB1A13620ULL,
			0x9CCFA38CF719A853ULL,
			0x77C76A2C593AF994ULL
		}
	};
	printf("Test Case 39\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 39 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x231FF84474B3E918ULL,
			0x23B91FBE6D919238ULL,
			0xB0271334722E4EC8ULL,
			0x477D1747BE8D7A45ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4E1E5272685ED718ULL,
			0x8157BF447ABB53B8ULL,
			0x0C03622463D87E19ULL,
			0x0563C5DBE073FA98ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x15387219C606B5A0ULL,
			0x0DAE9A109AEF5D58ULL,
			0xC9A0366D934D2BE2ULL,
			0x77345F6EE435B30FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xB7CD5123D8A60E52ULL,
			0x7A3D3EFF8AEDAEEAULL,
			0xF458D1FBC643B2C2ULL,
			0x729DDC4431442EC4ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x4C1085DE686D5C56ULL,
			0x550E7AF7FC6D246BULL,
			0xDEF3D6072DA852A1ULL,
			0x6E8BB1F55AA82E75ULL
		}
	};
	printf("Test Case 40\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 40 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xF77A79B5C5CB9208ULL,
			0x662402F7CE2F19B7ULL,
			0xFDEEE9B51E0F459EULL,
			0x4258C833FC112FBEULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7382B8212780C043ULL,
			0xB6BDC662016403F3ULL,
			0x1EA73CEEAA11E494ULL,
			0x01BF14F9CF12AE22ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x1BBE2073677C41A8ULL,
			0x75594F496E3F66EFULL,
			0x18BCEAFC5E378EBAULL,
			0x78348387B72F0C48ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x94A1B4528921CD35ULL,
			0x980761ED553BA6F0ULL,
			0xE177FF45DE437DCFULL,
			0x24B2288B821D3E72ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x5CA2D181715AD097ULL,
			0xBDF7520FE62F8B7DULL,
			0xC623A72FEEFA32B7ULL,
			0x344A41D11087F98BULL
		}
	};
	printf("Test Case 41\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 41 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x229C80E0E3B6CBE8ULL,
			0x7761E12CA77E459DULL,
			0x7693043A92EA7C01ULL,
			0x503CA34D1F5D66FCULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xD969ADDE0ED330E7ULL,
			0xBB09CBEB93799E40ULL,
			0xE636DD77C7681F2FULL,
			0x53DB20F6A4205891ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x33CEC975EA837240ULL,
			0x502BBC1624DA51B4ULL,
			0x20C066C3039BF830ULL,
			0x541ECDB892809F0EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x70050C475243C829ULL,
			0xCAB0D881F0B911FAULL,
			0xAC6C84A0698F287BULL,
			0x0FD631679C870B7EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x674C27149672A39EULL,
			0xCE4A294B9E77C564ULL,
			0x21D6235B814CC851ULL,
			0x6179C249D9ECDCB2ULL
		}
	};
	printf("Test Case 42\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 42 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xBB275E8CDBE0F288ULL,
			0x8B90F590BEC24CD4ULL,
			0xEE0744F9A5AA9257ULL,
			0x6C5FB65CC88A6D9DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x3244C499BF59F61EULL,
			0x5904D9809EA4F539ULL,
			0xEE1C8E2E9C92486DULL,
			0x47EFC6B6A53F245EULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF1663DFC54785770ULL,
			0xF40F8FF7B9A30375ULL,
			0xE5D1DCAD16E825E7ULL,
			0x7D645A017421E58BULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x3E6ECD231558063EULL,
			0x6280247E8E0BA18AULL,
			0x5F3FBBFCDA026166ULL,
			0x287C4713399733CAULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x57BFE59B34185958ULL,
			0x9F78F08D0E74D8BAULL,
			0x4D63548CFB7EA69EULL,
			0x1DB6D67750CE3CFCULL
		}
	};
	printf("Test Case 43\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 43 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x1A99CF5A2DF40258ULL,
			0x0E5C93924AC97444ULL,
			0xA73E747680B45364ULL,
			0x780D87E0D63CC715ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE6CD83EE96CD573AULL,
			0x94054B90D0FE6152ULL,
			0x5E6515DB855D1D6CULL,
			0x7FA4BEADFD0A5555ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x64A623C099CF9D38ULL,
			0xCB351E7099460815ULL,
			0xDF592D20D2ECC4EAULL,
			0x4E0331C4361B00BDULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x87264C026B207884ULL,
			0x79018717369B6B97ULL,
			0x42BF8734A706BBD0ULL,
			0x7DE5AFDC6E5E6993ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF10D3DD7F0E82E38ULL,
			0x4376F67562A52C8EULL,
			0x5B8C32B45B138F64ULL,
			0x516632950FD81946ULL
		}
	};
	printf("Test Case 44\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 44 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xE8D6425E82572A00ULL,
			0x64752ADE8552C142ULL,
			0x0BEE3149F722586EULL,
			0x60958A2109B52AFFULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x0E43B6940C43FF3EULL,
			0xED174FA83561247EULL,
			0x0328DCE32B345A8DULL,
			0x5498B0A2C4846CD9ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x6B7356EED4D09700ULL,
			0x3FE1CD02FA1F9F23ULL,
			0x888DAD83851241B2ULL,
			0x4B2527B7BA695D23ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xEB808DF33EF3C1A4ULL,
			0x4DCA024895896DEAULL,
			0x4B7257566530247AULL,
			0x31FEC3D8D0791BC0ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x6AF5C02290CB809CULL,
			0x0A9E78CBF7B44020ULL,
			0x1644DF5DB5E238C9ULL,
			0x639532EE59697512ULL
		}
	};
	printf("Test Case 45\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 45 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x244A8F1ED2698268ULL,
			0xAA1B8F98F8FBE321ULL,
			0xC906B75447025C83ULL,
			0x47AE480F54C6B32DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x2D2A6CE75F7117C1ULL,
			0x2490539B997A65AEULL,
			0xA6B9C50D926F1FE1ULL,
			0x4A45714101E9A92AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x18C39D4A67D5F7B0ULL,
			0x32F09B1C0A4820C6ULL,
			0xC1712266AF511CE3ULL,
			0x70AE82E0848F7C7DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x8655B84BD03E6599ULL,
			0xE0F57FBD5446B769ULL,
			0x6C65189F7FB6575BULL,
			0x6C7B2A0D4F59B410ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x83B2EF861C594F1DULL,
			0x5A4BD65210087D75ULL,
			0x3FA708154857A56EULL,
			0x541BE9B348994D43ULL
		}
	};
	printf("Test Case 46\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 46 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x22E9118F8D8FA8D0ULL,
			0xE76E086C627F214AULL,
			0x10F570E8B4A7ED97ULL,
			0x485B00A5958173AEULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x96FC5391B0858D08ULL,
			0x0EB12AD79BBC11C1ULL,
			0xD3010763D26A3D25ULL,
			0x2F2E1AAB04EBF400ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xA99EC82A082A41F8ULL,
			0x37569369A0ED6C63ULL,
			0x4059B08CABAE616CULL,
			0x7C148977173E06FBULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x73BE525BE50836CCULL,
			0xC853042E42170D26ULL,
			0xEC2C921EAD260076ULL,
			0x4ECB244D8684C96CULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x4519D54E4B10195BULL,
			0x2AD7120F64AA6924ULL,
			0xC59B4AA6863033C1ULL,
			0x1B8A6C5D4D013F18ULL
		}
	};
	printf("Test Case 47\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 47 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xC82B962088FE73F0ULL,
			0x71087F4A30D1A988ULL,
			0x68BD596F70389B63ULL,
			0x4D0A12880D88697FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x96AA5627D6263E75ULL,
			0xD5C71017D57E1853ULL,
			0xB9F3DA1EEF54AE38ULL,
			0x6AB9161420F9E322ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF9BB72F35742D598ULL,
			0x474773C9FEC7FC4FULL,
			0xA0A5470B3861083EULL,
			0x76EAF9F026A6B879ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xB056847864CA6263ULL,
			0xDD69D55B6956F567ULL,
			0x43BF8151E5BB4912ULL,
			0x48CD929043AC5BBFULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x3D75AC092EBF6947ULL,
			0x88B7B733EC66914DULL,
			0xAE45CBBA02FCC837ULL,
			0x082FB3157C99A55FULL
		}
	};
	printf("Test Case 48\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 48 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x34A189C78AF96790ULL,
			0x90C8922F6C5E3580ULL,
			0x179B2129EDE282BAULL,
			0x77ECEC3B53BABE21ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7970815D80815429ULL,
			0x5A9874FEA74D9464ULL,
			0xD606985D1EF13D1BULL,
			0x787090978315A231ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE4679E660FE175F8ULL,
			0x647084564093B47EULL,
			0x2BFF11D5E42F5702ULL,
			0x7F0080334563B80DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xE9794BBAB19F5669ULL,
			0xF02B4200D8EDC13AULL,
			0xCB156DF04DFA7ABFULL,
			0x3E337E5842D7161BULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x1F51701296448CB1ULL,
			0xDB1868A6BC1B10E3ULL,
			0x697141ADC52D6B14ULL,
			0x77A308127E696812ULL
		}
	};
	printf("Test Case 49\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 49 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x2DDD45DF8548D520ULL,
			0xAD95DD4749748278ULL,
			0x606AB49F0C75C0DCULL,
			0x41D31E233B56BE3AULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x0BFD8C150E533B39ULL,
			0x252C04C839124F2AULL,
			0x290D5E20357E87D2ULL,
			0x0D55002174677D8BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xD5E51E0D76524490ULL,
			0x103C9C93D0F77082ULL,
			0x0F56EE664CC54215ULL,
			0x7B53DA0BCE91B523ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x7A1337EE12C875B0ULL,
			0xB3FAA4A5B731E33EULL,
			0xCC5437989C2AF9C5ULL,
			0x65463971BC190227ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x1B8C3CC47EEFD31FULL,
			0x36F5BFF4352B689BULL,
			0xB12EA63C27E09A05ULL,
			0x544E6E328F765AD5ULL
		}
	};
	printf("Test Case 50\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 50 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x3DEF60FD09EB6608ULL,
			0x19F5DD9CD08C77A3ULL,
			0xCBFA96E42802EFB2ULL,
			0x7F5E09FFFBA7AC44ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x417EC552D0DFB01DULL,
			0x31F9E862404320D9ULL,
			0xF90A12475AF78CCEULL,
			0x26ACA7E8E3BFBE07ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x42BF0522BA536380ULL,
			0x90D94D2AE91DB9DAULL,
			0x6A97DB4CEAECB450ULL,
			0x7EC9282514F15A9AULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x0C8E54BF4F5CC200ULL,
			0x8A5ED1547CF17760ULL,
			0x154E20784AA3106FULL,
			0x79BFD742CA1296E2ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x13DF0A3303C972FDULL,
			0xF738B7AE505F3FDAULL,
			0xAB2D565C7AA2E4F7ULL,
			0x78D5AC850C3BBD77ULL
		}
	};
	printf("Test Case 51\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 51 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -51;
	} else {
		printf("Test Case 51 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x37A70C694A8F6988ULL,
			0x1B05983C414BC8E9ULL,
			0xAB5FD5E9E5A54FE9ULL,
			0x4AEED789E287AC38ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x850C326417B8D9A5ULL,
			0xAC47D3FB11147260ULL,
			0xE37FFAE038D6D8A6ULL,
			0x59DD39DFB34FD7FEULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x0F5381D5BB2699D0ULL,
			0x55709AEBE0F0726CULL,
			0x52EE26AB2A867FDEULL,
			0x40B79EB4A97E59B4ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x22A8B88D3F3ECD3CULL,
			0xC49F96AD43815DF7ULL,
			0x1B5A20EEC2D9B25EULL,
			0x2EA00A1408C59320ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xBC25087BD69B2872ULL,
			0x10E697B31179EB34ULL,
			0x947AFDA23A4AF40EULL,
			0x45516EA9AB263E16ULL
		}
	};
	printf("Test Case 52\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 52 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -52;
	} else {
		printf("Test Case 52 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x013CCBB4C72E5EC8ULL,
			0x87853EDFA34412A6ULL,
			0xD12739070BECCC04ULL,
			0x753D4C8584791735ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xB2DD30DFCCAB430CULL,
			0xA140F0F61B7265DBULL,
			0x598E6F398B896925ULL,
			0x552E7ACE0AF26915ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x033F047B203B7268ULL,
			0xB2A2A038C52E088EULL,
			0xE68A92468D0F880CULL,
			0x6B937C6713EC2A09ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD10138E0B848ABF7ULL,
			0x15C8317104328F24ULL,
			0x5DFE002E825FCD07ULL,
			0x07AA8B299E61D7FBULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xADA72072A712ECB3ULL,
			0xA648AAE0486D1A2AULL,
			0x3D25AD8BE9936202ULL,
			0x51AF0AD942A06271ULL
		}
	};
	printf("Test Case 53\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 53 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -53;
	} else {
		printf("Test Case 53 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xDE860B5D0C352E10ULL,
			0x6AEBD778E9547D2EULL,
			0x5AF2EF1D76660529ULL,
			0x67AA6912112B6311ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA1120D6188888E88ULL,
			0xBDC4E730E2DD49EAULL,
			0x71385861460BE00DULL,
			0x0DCF1686104CF223ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x61860849B0A24E90ULL,
			0xACC173AB38F67678ULL,
			0x84CC7AC1AA486104ULL,
			0x7BFC677FEE2F4300ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x782E1AADFA2FDB5EULL,
			0xB072806D28A7FAB0ULL,
			0x157E91042885C847ULL,
			0x54D7A62B2B8FC2DBULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x9E470C866283675BULL,
			0x3A252327104E79E1ULL,
			0x56F1CEFB8DDDD17CULL,
			0x1779EE4326384330ULL
		}
	};
	printf("Test Case 54\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 54 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -54;
	} else {
		printf("Test Case 54 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x788DE32CBE6DD9B8ULL,
			0x404487F86282CCBBULL,
			0x256D831DDF0779BCULL,
			0x606FD894519535D3ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x0970C690801F2249ULL,
			0x46DEA9B02B026F04ULL,
			0x15D343186DB1292BULL,
			0x4D09728175A6E281ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xD39AF8646A1859B8ULL,
			0xA427E1CFF2183F9DULL,
			0x9BBDF0D82F68D179ULL,
			0x56F3CEAF1FE4CE34ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x2B0ED21C0EB8871EULL,
			0xF3069CF0751AAA9EULL,
			0x87DF78F008F4324AULL,
			0x4460E2D5B58F3F48ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xDCD395B8AE0DC8ABULL,
			0x1998D0F405017073ULL,
			0xC772D41FDDEE83EBULL,
			0x0A79D0E1A5B74116ULL
		}
	};
	printf("Test Case 55\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 55 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -55;
	} else {
		printf("Test Case 55 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x0F6CDD90784379D0ULL,
			0xB86E14B478892D35ULL,
			0xB328AFE319BB62D7ULL,
			0x5D374BFA1A0F24AAULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x2B29C84E676DA574ULL,
			0xA8352B62354273F3ULL,
			0xBC5D4158F495C455ULL,
			0x6129A8D1AEBB819DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x60F2E0EDF3F8F588ULL,
			0x8F40FB49CEEB2114ULL,
			0x98243E41E9ED2593ULL,
			0x59919D463378149AULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xCB69452A60D2FD87ULL,
			0x2F418B2C3696002AULL,
			0x188025B7266FB8F9ULL,
			0x6B2F719334DDBB9DULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7931BDFC812E693FULL,
			0xE3E65824E46BF981ULL,
			0x6C77C2ECC7DD8403ULL,
			0x69BC48E32E8E0D8FULL
		}
	};
	printf("Test Case 56\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 56 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -56;
	} else {
		printf("Test Case 56 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x3083A52A09AB6DA8ULL,
			0x0BD82DDE0B9AEEC7ULL,
			0xC9B0B0DE95BD6826ULL,
			0x46263322C1EF90D1ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x6CA9839B8B3754DEULL,
			0x62587EFCD139D1C3ULL,
			0x1506AE585EED9921ULL,
			0x1390E066DF45758FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x6716AAA8EBDD46E0ULL,
			0x0D6161EADC3AB9D1ULL,
			0xD2E0D8D73363FDD1ULL,
			0x6CEB83AB5E4C14FBULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x56C1D3E9B34A6343ULL,
			0xD47EC49CA68E8C92ULL,
			0x6C647D2CCD607F29ULL,
			0x420234E432EF78A0ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x43EF501405AF0F50ULL,
			0x54B6A4FB52511246ULL,
			0xBD03BDD939DC7920ULL,
			0x37FD1A6B8D5B2FA1ULL
		}
	};
	printf("Test Case 57\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 57 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -57;
	} else {
		printf("Test Case 57 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x76E66C75CA561FD0ULL,
			0x068C8FBEF6476965ULL,
			0xAA6B14ED3660801BULL,
			0x4CB46C3E90EA2BDDULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x568618D382360FA3ULL,
			0x16E5381B413F24AEULL,
			0x002F3DB29747DC3AULL,
			0x31757E527D5C7AB1ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB68BEF1251263B88ULL,
			0x09EA513FC96352DCULL,
			0xB6AD3696D1CEF757ULL,
			0x50F1FA3195744EEFULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x3B8B0C017CB3C478ULL,
			0xD38D58C625C48E28ULL,
			0x521133DDFEE29E64ULL,
			0x78C89B47DE5C6C20ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x106C88EEF3B9DC7EULL,
			0x5951C7B26DFB0426ULL,
			0xB13D35F7E0A2D0E2ULL,
			0x45557B678D9DD53AULL
		}
	};
	printf("Test Case 58\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 58 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -58;
	} else {
		printf("Test Case 58 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x59D1CC9388F79EB8ULL,
			0x0654D0238B5C6F0EULL,
			0x9B6C55DDE6571BB5ULL,
			0x70C715036B7D21A5ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xCB7C5BC0728F86C9ULL,
			0x1D5DC752DF5BD139ULL,
			0x3E69DBE4DF54506EULL,
			0x6145EED650144440ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x08AC30CB5EEEA3A0ULL,
			0xBCE1DC06ECA9E197ULL,
			0xACC7E8B3F9C64903ULL,
			0x449DDF3621A9A97DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xAC49D9B8F4156ED7ULL,
			0x9FF2EFACCB85B152ULL,
			0x9A91CD5E7B423282ULL,
			0x329246AC1EC71691ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x224AF53D346F5341ULL,
			0xC87BD417BA647024ULL,
			0xAFC7412F68388D1BULL,
			0x4E702581319EC2C7ULL
		}
	};
	printf("Test Case 59\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 59 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -59;
	} else {
		printf("Test Case 59 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xD65746D253A2F140ULL,
			0x0C4E3C040794DB60ULL,
			0x6D185CE950AFA32CULL,
			0x7D9BFEEB3D302D2FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xC286B5A4F95346EBULL,
			0x986F71F2E3CBB297ULL,
			0xD87F91996874BE7BULL,
			0x6BCD3DFE82D09920ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xCA6D5673C89BC710ULL,
			0x1407A1CA2E048C30ULL,
			0xFE3ECCFA4A67BCD1ULL,
			0x6C192BFC5B89AAA6ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x8BCCD36008FCED4DULL,
			0x47EC7D5337CE13CBULL,
			0x3FF22AFE1F446B47ULL,
			0x0C6F8A7FD9456947ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x2B3F5BAEB1A991E7ULL,
			0xD13DCFBAB33A51C9ULL,
			0x34219EBAC6AD5D1CULL,
			0x1BCD5AA24435B41CULL
		}
	};
	printf("Test Case 60\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 60 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -60;
	} else {
		printf("Test Case 60 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x81C11E3AFD16AB00ULL,
			0x82986C40AC14A88AULL,
			0xA38181B9C3067760ULL,
			0x66C53734B6D81769ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xEB5AB795DE0787A1ULL,
			0xFDCF86456845DE4FULL,
			0xF4A6343FF95CF78FULL,
			0x66675051FD3ED994ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x43392ECC40752408ULL,
			0x60695593B6DA52B4ULL,
			0x9A10EF0319D2833DULL,
			0x45DA17028F9D293DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD0E0C46A502F78DCULL,
			0x3A0ACEE3EE175A4EULL,
			0x26865FDC90330421ULL,
			0x0CD882CBC47DCB11ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x170F2384E1A5373CULL,
			0xE4AEE582F0C57B6EULL,
			0x4D1A6ECE86344364ULL,
			0x59E1031FA97F006FULL
		}
	};
	printf("Test Case 61\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 61 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -61;
	} else {
		printf("Test Case 61 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xF32EA08F88F55520ULL,
			0xF49F755EA694950FULL,
			0x543DDEBE598A1470ULL,
			0x76D442422B69F822ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xCE1AB86A9DE2BAC7ULL,
			0x2E7323A9FEE79DF9ULL,
			0xAE609B3ED3BA5B94ULL,
			0x1AD5FF2A5EC86259ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x23A1E5397BF5B6C8ULL,
			0x41E4F6C0A2FD9313ULL,
			0x11286E8402943EFDULL,
			0x568FF89D7BA46A93ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x20196D50D241C8A0ULL,
			0x511428B1BD4A7C15ULL,
			0xF39F5A0AA2930519ULL,
			0x34158731FB00E867ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xDDBB9FC3522A67C4ULL,
			0x12A2E9A261E5EBC5ULL,
			0x8BCCB14E4282910DULL,
			0x7666CC11134A0B5BULL
		}
	};
	printf("Test Case 62\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 62 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -62;
	} else {
		printf("Test Case 62 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x73EAADFE4AC1AD48ULL,
			0x45475EC151A89D8CULL,
			0x340F44B2FEEDDB7DULL,
			0x5F1EDEE8A96E5CE0ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x344C64D2E782AB47ULL,
			0xDD3B018F845B8902ULL,
			0xD2FEA3DB65D3781FULL,
			0x7EEC5CEE191CDE8BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2DD233D2F7F98CB0ULL,
			0xC407C50824392A44ULL,
			0x25B04540A6F5B055ULL,
			0x541BA02D8429842EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x715FF2F8D306E15FULL,
			0xD2C5ABC68268D872ULL,
			0xF1C041D7A07697FEULL,
			0x6417CEF0878101F1ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x282D08DECB9BF88FULL,
			0xB4AA8CE5245C6ECCULL,
			0xDA8833AA029FF8F7ULL,
			0x3C21B46237373C14ULL
		}
	};
	printf("Test Case 63\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 63 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -63;
	} else {
		printf("Test Case 63 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xE071A79366824840ULL,
			0x42B8F9D40BFAFC23ULL,
			0x044563DA086A3D2FULL,
			0x4964A665F4DD1ABCULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x11CBF4761B28986FULL,
			0xAA7BCCEC2CB1380FULL,
			0xA7B89EA48068C3EAULL,
			0x14CB8ADF2C74FA98ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x4237AF69A9B82228ULL,
			0xAF7386717E2F87C7ULL,
			0x95073988BFE75AFEULL,
			0x6663B68F0F588E3FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xE64548A597E18643ULL,
			0xA5C0ECC914DA73ECULL,
			0x647864C002569CD4ULL,
			0x5BFA022C9AFB6705ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x629BB6908F6ABD04ULL,
			0x3FBBC97C3F6A1D63ULL,
			0x0D74A7174B4F1987ULL,
			0x3CDEA5765577244CULL
		}
	};
	printf("Test Case 64\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 64 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -64;
	} else {
		printf("Test Case 64 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x5BC7412530E46B00ULL,
			0x9726DD7BD0C6EEF5ULL,
			0x7380B4C0035D6674ULL,
			0x476B6C68CB1EB2F3ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x9CA463DAE75CDDCAULL,
			0xDBC9E7E6D1994C74ULL,
			0xDC58F491459F5136ULL,
			0x12DDCBF83138C604ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xDEDCC936D0101D30ULL,
			0xE85CDCF303EEE589ULL,
			0xCF001C9EA1DEF3F5ULL,
			0x4C024A4715A4BB35ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x0A494B65C737F415ULL,
			0x928A15721E564CCAULL,
			0xE464E1C2FC843BF1ULL,
			0x769E6433936B2B97ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x391FB74ED48D310EULL,
			0x94CDD5D527B1C738ULL,
			0x6890809035AF0E01ULL,
			0x2821249B76A6E9A9ULL
		}
	};
	printf("Test Case 65\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 65 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -65;
	} else {
		printf("Test Case 65 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x0B57ABBA2E598680ULL,
			0xA7FF3A118952BAEDULL,
			0x18DED997E0C9C4C7ULL,
			0x6326CDCBDDAC8E98ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xF6963820BA89658EULL,
			0x06ECC226662764C5ULL,
			0xBFBF6DCDAE39B5EBULL,
			0x76A520DB6DD9E4D8ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC9FCB0AB3771E6C8ULL,
			0xB1A6DF07CC63DF7AULL,
			0xDD7B84860306C8D8ULL,
			0x6D96E2A0C2FA30B4ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA15071F59E456AF4ULL,
			0x27310E514AD0DFC1ULL,
			0x9AF7B867A698501AULL,
			0x6366E224AC917465ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xCE46085D408523CEULL,
			0x125F2208ACF9BDF3ULL,
			0xE38BCB80A1E35B86ULL,
			0x513DC1186DF36B10ULL
		}
	};
	printf("Test Case 66\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 66 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -66;
	} else {
		printf("Test Case 66 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x0CF9F6AD9FD82B50ULL,
			0x019086978C89CD57ULL,
			0xE6D722216B5F80BDULL,
			0x52B2F15E5CA33DC4ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7F9C25A1B648399AULL,
			0x33764268C4787465ULL,
			0x3D65058A4CC8F2CDULL,
			0x0DC94CE54204EFE1ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x871E1A4494B829E8ULL,
			0xFC66507EB9DA4DCAULL,
			0x8E0C40B45255BECAULL,
			0x639123CD40E92EC6ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xCF1D248154910B8AULL,
			0xA872282C4BB75894ULL,
			0x5A425D276276FAD4ULL,
			0x4C2A18EB14224154ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x8DE2FEAE8AD22473ULL,
			0x4D540BAAB7BE4F76ULL,
			0x4228E6C414F6905CULL,
			0x6B5C5A9E586294F1ULL
		}
	};
	printf("Test Case 67\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 67 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -67;
	} else {
		printf("Test Case 67 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xE55DFB23C37E8978ULL,
			0xFC2635A191B52A42ULL,
			0x8D978AD231F89671ULL,
			0x7DC5E1343B053981ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xC75F19F66779A77FULL,
			0x0ECD0A333823C036ULL,
			0x2E2BEAF98E4B2693ULL,
			0x7EC4CB53A57DCB0AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x67806EFE59846660ULL,
			0x01A1BF11611B897BULL,
			0x328201371A3548E6ULL,
			0x5A69F2439B5A816CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xE311B8FB170DCE6EULL,
			0x49C52962EAE808A1ULL,
			0xDEDEDB963E81F7F2ULL,
			0x2EF5934DAE794CD7ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7775734EA1797729ULL,
			0x1863B1F19D408D36ULL,
			0xA6179568EFEC0D98ULL,
			0x61757435577D7A22ULL
		}
	};
	printf("Test Case 68\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 68 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -68;
	} else {
		printf("Test Case 68 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xDECAFC1E81530480ULL,
			0x0CF91770BECAEE78ULL,
			0x0A18270DBBC6887FULL,
			0x640402B92B49FC70ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xC3BC539EAEFE53F1ULL,
			0x55993D507B586B1FULL,
			0x58213C64E634B190ULL,
			0x301306153DDD779FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB26788B2689FCA48ULL,
			0x30E200D636F863DEULL,
			0xA73AB7A265FBECB7ULL,
			0x719372F34ECE2AEBULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xEAF63D25B20321E6ULL,
			0x56561BC95DFA74B4ULL,
			0xACF067F218A9B5C0ULL,
			0x58A4BF4EC20006D4ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA9FB307507ACD771ULL,
			0xFA8D98BBE5C13CA3ULL,
			0x91661DB31397E6A0ULL,
			0x5E6DCCDCD4BBD5C6ULL
		}
	};
	printf("Test Case 69\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 69 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -69;
	} else {
		printf("Test Case 69 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xC548495C591BB560ULL,
			0x9938E51C67EFFD7DULL,
			0xCFC3CC82CA7908A7ULL,
			0x53B486EE357C86DBULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5146B2457A93B2A1ULL,
			0xA0FC9E1C883BCADEULL,
			0xE7FAB3DAEFE8C4BAULL,
			0x38B1B3FF51D8563BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x81B01DE997AF5A50ULL,
			0xD32F9352468E5447ULL,
			0x0D2208871AF7770DULL,
			0x7C49CB72D0F5654BULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF85C4C7511C0EB28ULL,
			0xF4785D6143CFD612ULL,
			0x157CE608376D6538ULL,
			0x75F092CF77135325ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF0A1FC9DC2CEC4ADULL,
			0xCD875340EA7A764BULL,
			0x0ED49029EBD9624FULL,
			0x764C416012CC8BACULL
		}
	};
	printf("Test Case 70\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 70 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -70;
	} else {
		printf("Test Case 70 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x02E37436310395E0ULL,
			0x4F64A89E9F24A6C1ULL,
			0xD0470CE889E5A485ULL,
			0x737AB01168CD1E6EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x3DF7475360123A52ULL,
			0x428F8C527E19FF62ULL,
			0xE8AA2173795D153AULL,
			0x078B4383927F6B1AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x0BB2ABC59447E858ULL,
			0x743CA056E18AFCE9ULL,
			0xFB0E45E4647DF0CFULL,
			0x595ECEF47271EB39ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xB0450FCFA63C4AFCULL,
			0x81231B584A135514ULL,
			0x0721CDCAE5E50F4CULL,
			0x3FFE81353FCA1993ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x72F34F7A5DFC510AULL,
			0x428AE7E6E042A976ULL,
			0xEB3A16D6899BB9AFULL,
			0x38EAFF0E3A58A778ULL
		}
	};
	printf("Test Case 71\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 71 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -71;
	} else {
		printf("Test Case 71 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x179F24782F7EC440ULL,
			0x0E4D2CA2A535D816ULL,
			0xCC39C78C98E4C46DULL,
			0x5845DAF05500AF8BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x2919D880567CB8EDULL,
			0x9A84D3B7FC8A1193ULL,
			0x2D9BAFDEF60BAF03ULL,
			0x1DF765248094CF51ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x085F3BF895E41DF0ULL,
			0x7A626ED982AF5DA3ULL,
			0x90B7786E3E16458FULL,
			0x5EF60667559CF946ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x766BACDE43F5CE09ULL,
			0x796E4AC4C7CFD26DULL,
			0xB7BD6170CDBB31AFULL,
			0x53DD118D716F3320ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x31C5DBE0175D6CDAULL,
			0xCF31D4110FA84D9FULL,
			0x0ACAB3249996E61DULL,
			0x16C9F1630F56453DULL
		}
	};
	printf("Test Case 72\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 72 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -72;
	} else {
		printf("Test Case 72 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x3237DC75E5AB4688ULL,
			0xAAB5D1C20805B63CULL,
			0x78259286C51731EAULL,
			0x4C1AF5CCCFEFCBFBULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x55D63B4A6EC77340ULL,
			0xE1C09C53CE0E04E2ULL,
			0xCB58E3A9E0A55D71ULL,
			0x4EC1180F9FE59A40ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x258C59754B3D7BD0ULL,
			0x522F480DD3649FC4ULL,
			0x69896F4192B6810FULL,
			0x763C5E279F1C6A01ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x620B800FE93845E5ULL,
			0xC14B4CAE36A700F8ULL,
			0xFAD39650BCE8D0D2ULL,
			0x1D1DE653FAB3F824ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x17DB5AC2EB86866FULL,
			0x5281D4ED8A05F697ULL,
			0x5E86C109BE447EDFULL,
			0x0D1263FD59228AAAULL
		}
	};
	printf("Test Case 73\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 73 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -73;
	} else {
		printf("Test Case 73 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x6724AAFA70057150ULL,
			0xF2897C67F1B4415CULL,
			0x74A1DBBA9A6477F8ULL,
			0x71363C9ACC7DF4C3ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE997F2AEA4B2AA7AULL,
			0xE1EAD94A34C41229ULL,
			0x426851BCDF6989D5ULL,
			0x232F1FEDDB4297C6ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE1E5A19B5B89C150ULL,
			0x4D54083AA2F2CFEEULL,
			0x0113715AE0A2706EULL,
			0x78D7A53C1CCC680FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x77DB946E6DA66035ULL,
			0xFE4ABEC62A2DA68CULL,
			0xFDA7E270306275B9ULL,
			0x2D32402B40FBEED7ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x112FA610DC25D517ULL,
			0xA020786AD944A959ULL,
			0xCBFC9D87C72C715AULL,
			0x3B98353C77690BD3ULL
		}
	};
	printf("Test Case 74\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 74 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -74;
	} else {
		printf("Test Case 74 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x520F160475E0BD00ULL,
			0x2D74582C42243153ULL,
			0xBE3B4BD7178B7A64ULL,
			0x7AFCD582AAA67AB7ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x717A1D8A6A9A4CB7ULL,
			0xC7BC617ED6E33797ULL,
			0x9DB171A661831618ULL,
			0x3E1B702629BF103CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x4432A075579E6920ULL,
			0x11BE02990C72431BULL,
			0xB16BE1C91EA74957ULL,
			0x56E43F1C4FADA485ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x11ED79A891F70E3EULL,
			0xB147618B6C48500AULL,
			0x7472D5077DAA2797ULL,
			0x638A71B8397A3EF2ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x075FE87C9D2C7538ULL,
			0x748982B8C0B86752ULL,
			0xE3E8EC19FD64626EULL,
			0x033498D1D4D59DCEULL
		}
	};
	printf("Test Case 75\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 75 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -75;
	} else {
		printf("Test Case 75 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x4D985C3284DA7AF0ULL,
			0x8E3305AEDB138A98ULL,
			0xE4C89FA5569F70E5ULL,
			0x52265EB6CF9149ACULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x62CE168758368B6BULL,
			0x6D44A3962837735FULL,
			0xA0D440F894C79454ULL,
			0x1BF27BCF32D3275CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2F8F3DF2BCC9ADC8ULL,
			0x52644A48ACC6BEFCULL,
			0xEE3097DFF4C99D36ULL,
			0x64C241A91E1A1A94ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF5E5D714DF3305AEULL,
			0x438772777CDDDBCEULL,
			0x930397BC6F666F54ULL,
			0x3016C23567A8FBA1ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x304273C82BE65B58ULL,
			0x1277CF3989C846B1ULL,
			0x203CC94C1055E243ULL,
			0x54608FD291BC5B09ULL
		}
	};
	printf("Test Case 76\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 76 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -76;
	} else {
		printf("Test Case 76 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x6BC255CC681A4DD8ULL,
			0xB77C0990D18B73D8ULL,
			0xEBD37827BD44FAF1ULL,
			0x41D13A7131F95C21ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xF5078E43FBAFCBE9ULL,
			0xF10A841BB40A5637ULL,
			0x65B40EAAFE735ADCULL,
			0x3F4A89204B6A7318ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE64C10D35CBBA150ULL,
			0x20E392B74DFBFA55ULL,
			0x006161FF07B9C02FULL,
			0x462307ED401FD8CEULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xBB76C5D95FB1591CULL,
			0xC46E4B667C04C5ADULL,
			0x7ABE0A2E3B769603ULL,
			0x083664BE90D4062EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x3084645C63FE6CF1ULL,
			0x4E8F15FC7E091E46ULL,
			0xA55EF3E712C79F60ULL,
			0x15B0A4C4E405F80EULL
		}
	};
	printf("Test Case 77\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 77 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -77;
	} else {
		printf("Test Case 77 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x808D3ECB4B42F010ULL,
			0x761DB7D69DD85311ULL,
			0x1E63AD9FA61E8797ULL,
			0x5360BDDD1935EB40ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x563FEE76E338525EULL,
			0xD6DAC4ED219E8596ULL,
			0x2FDC9B4BADF822C8ULL,
			0x78D490B06B0234B5ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x4A83C828028CDA70ULL,
			0x555D1F8ABD0088B6ULL,
			0x46BEDC5838F240FBULL,
			0x5B43844C1BFF60DCULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x57EE8A55E19F9C64ULL,
			0xE55E3E6422F8CC8FULL,
			0x36959CDC7B7969DDULL,
			0x298CC3DA60C16758ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE9B3BF627D44AC9CULL,
			0x3209259E7BDD0278ULL,
			0x4870A13FFD456516ULL,
			0x6811DEDDBBA31D30ULL
		}
	};
	printf("Test Case 78\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 78 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -78;
	} else {
		printf("Test Case 78 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x6D20D2468D50C718ULL,
			0xAAAC813D9DBB67D1ULL,
			0x9E76FB63A8438F1AULL,
			0x63F6144EB4AC72D5ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7DECC111AD589B90ULL,
			0x7941489950E438DCULL,
			0x47DD769DCE2D732EULL,
			0x4183BD2A70E4F168ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF49B5823B1CE1F70ULL,
			0x513703E96C4A76DDULL,
			0xCF01C67A008208AAULL,
			0x74864A5D32BECBDAULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x8274A9CC221B051CULL,
			0x131581709DB2081DULL,
			0x745AFC778796FDD0ULL,
			0x41AE1C0F81A6574FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xEEC40034A3CAC607ULL,
			0x7F685D229052409CULL,
			0x1DC5934582E6D15CULL,
			0x202540DCA6BA9884ULL
		}
	};
	printf("Test Case 79\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 79 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -79;
	} else {
		printf("Test Case 79 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x43ABE3E17D752AF0ULL,
			0x0F4CDFC3AAC8E683ULL,
			0x5AB1FF81A969D9D2ULL,
			0x5F61CB15B7C8530EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA90124F545A5F09FULL,
			0x71203C654DAD0E2DULL,
			0xD074CDE69C410C24ULL,
			0x2D40138134BFAC55ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE2BEB2A5B7231168ULL,
			0xFA9574EDDACF7F7EULL,
			0xAC1C1764FF630AECULL,
			0x73EA286A32EEC190ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xE143E359DA775332ULL,
			0xB97D0E07D055C997ULL,
			0x94A6ABE6B51B7AAAULL,
			0x246BF614E8F5D25CULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD3B3E562FDA3FEC1ULL,
			0xF16A3908805B119FULL,
			0x62E6B542D9C55ACDULL,
			0x47DF3668C247881CULL
		}
	};
	printf("Test Case 80\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 80 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -80;
	} else {
		printf("Test Case 80 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x139F224CC24EF6A8ULL,
			0xC6531DAA3FBEE019ULL,
			0x2B673CF9C34F2C0FULL,
			0x51BD237780EEBDE9ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x85F8ECE9D94E1665ULL,
			0xA4CC7367B6106667ULL,
			0x07882A63B9FF918FULL,
			0x3670C6540C405596ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x61BBEB0AC8F92AE8ULL,
			0x12B2C1868C9FC292ULL,
			0xCCC164DB060811B8ULL,
			0x494F02FE4B21C179ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x9455902997C9C533ULL,
			0xA73148E5B544661DULL,
			0x708531817F0FE426ULL,
			0x61D387A0A073C088ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x08B915055D7EAC76ULL,
			0x9483C31EA25019D5ULL,
			0x16569510DEBAC639ULL,
			0x5211EF9802EBC570ULL
		}
	};
	printf("Test Case 81\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 81 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -81;
	} else {
		printf("Test Case 81 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x438E93E4FE8100B8ULL,
			0xF91CB73E586C3B88ULL,
			0xEF90829D9F5FD356ULL,
			0x6C4B4D604764685DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x0A79DE244EA859D3ULL,
			0xFC4F1E2104C23590ULL,
			0x54D375589D174063ULL,
			0x55133DE5E061AC26ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC943F6DE281A3F68ULL,
			0x03ED55932CC8E444ULL,
			0xAEC6934418E302C3ULL,
			0x7A8D1CD9099016F8ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x6E6C41AE3B19EF30ULL,
			0x03CC4995F55B2E55ULL,
			0xC992EB796F18C198ULL,
			0x6A01BE7D5BB30B5BULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA915C8F70DB46592ULL,
			0xADAC6E46E6F667FBULL,
			0x89A72D39CDF27329ULL,
			0x314475B55F3DB987ULL
		}
	};
	printf("Test Case 82\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 82 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -82;
	} else {
		printf("Test Case 82 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x6C5B325715C19118ULL,
			0x099EBA1D0C768E86ULL,
			0xA507600F927C58E6ULL,
			0x46CB2A19962278BEULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA01CC40285E872DBULL,
			0x8FDF3D281DE7D567ULL,
			0x89164605519839E5ULL,
			0x006CF3EB4B88E651ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB369DC5A177EF028ULL,
			0xC6CDADB3E62E5C64ULL,
			0x8F2BA7F76E2BDA13ULL,
			0x627E6C5EDB6AAA16ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xEFB08DA9AC6EF31CULL,
			0x866C97AF55F8CDD4ULL,
			0x8C6D238C6F516846ULL,
			0x16D9C20681861B82ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x1F4C579F14E47A2BULL,
			0x8AAC2D584A6EC4C8ULL,
			0x2EDEA9B67269DE6BULL,
			0x20FFF351B9E53FD6ULL
		}
	};
	printf("Test Case 83\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 83 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -83;
	} else {
		printf("Test Case 83 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xB80DB799E80C75D0ULL,
			0xB2F401849E56456AULL,
			0x7D434B1FE94B3705ULL,
			0x782569686E5B10C6ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5FCA39B55D4C3D0DULL,
			0x2EB8C911FD98401EULL,
			0x903FEE6642E49487ULL,
			0x44C4AD1E7CD38CCEULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x4F75F4C23BA45B00ULL,
			0x2B54ADDF95086ABCULL,
			0x1811633575EC8F2EULL,
			0x73978AAC5CF0679AULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x3B0306F39809FC66ULL,
			0x6E40B933B14C331EULL,
			0xBE0F07B9E98D4272ULL,
			0x2A11006DE2E678C8ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xCCD811436244FE43ULL,
			0x2FCD87E4634C4D1BULL,
			0xD5C960298020A97FULL,
			0x3A9A8BF9839AE9C6ULL
		}
	};
	printf("Test Case 84\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 84 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -84;
	} else {
		printf("Test Case 84 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xB4F0224C32319008ULL,
			0xAB40E51500A94345ULL,
			0xD57537127B4298DDULL,
			0x7E7C6FC0A010CEB1ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x83D49DE72CB4081DULL,
			0x814D978994A71F43ULL,
			0x8FC60C0D9242DDDFULL,
			0x71A57BE42560FD0EULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC77BE4E026C8A070ULL,
			0x3DB2347F8A1A9D99ULL,
			0xE68DD34EC6D1C849ULL,
			0x6AAA8EA9AB3E1D7AULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x42E3DF07FF4529CAULL,
			0xF0FAB4E501FA1B73ULL,
			0x167C9EBAB90C2C12ULL,
			0x2AC36DADB011CED8ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xEDA9173713AECAEFULL,
			0x0DC2ED6AEF55AA6DULL,
			0x5F21A04C2CC86BFDULL,
			0x4B47FCF57F22365DULL
		}
	};
	printf("Test Case 85\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 85 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -85;
	} else {
		printf("Test Case 85 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xA5E9177561FA57C8ULL,
			0x8F7FF4D0FD9B4797ULL,
			0x1E0BB977B04F77EFULL,
			0x4C83684672136B65ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x096A66F5EE6594EAULL,
			0xB17550A1B27E02B1ULL,
			0x68718706A78886CFULL,
			0x4B92FB3954DA0E27ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x37FDD45174C87C98ULL,
			0xD85FBFD77AEE554DULL,
			0x6ABD2B3D212FC569ULL,
			0x468123CFCF041439ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x6EF2914E88650B5EULL,
			0x017581E9B662296BULL,
			0xC9E50032881E887DULL,
			0x02E22FAFCC908BBCULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x6B622D0534AC700EULL,
			0xC31D3147430EECA9ULL,
			0xB34A9783C715524AULL,
			0x4EEB6B7C3630D27EULL
		}
	};
	printf("Test Case 86\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 86 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -86;
	} else {
		printf("Test Case 86 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x64E14AC7FD42B980ULL,
			0x0E1193DBDD6A7704ULL,
			0x92C680C27D793E06ULL,
			0x6757589DA35F6E94ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xAE41B5FE3B5AAE61ULL,
			0xCCE1A5AD5AC44EE8ULL,
			0xF7C0147D1646A192ULL,
			0x33C4F402AFE1ACFBULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x4C49776D3AD8F478ULL,
			0xFBD308329FBAA161ULL,
			0x4F3C41737513670AULL,
			0x76C373C45835ED67ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x811E471E552DF4B3ULL,
			0xFA4D85A7E93C1F95ULL,
			0x7221C81C01A6221AULL,
			0x39BEBEEC0BA48B27ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x982A00E08F294369ULL,
			0x1DC788AAE16D293DULL,
			0x3620D6F9B72CFE63ULL,
			0x06A971CC09A1F374ULL
		}
	};
	printf("Test Case 87\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 87 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -87;
	} else {
		printf("Test Case 87 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x25D456386890B4B0ULL,
			0x5BB98293E56534BFULL,
			0xB435C1D27B082E56ULL,
			0x579DDEC4707F443AULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xF12FEA284EE6DA25ULL,
			0x8B2D4CDF0328D499ULL,
			0x52E73D1BD4794D7DULL,
			0x2398AC6A8E84AE4CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xEBD03B85B6674570ULL,
			0x32144C73796C00A9ULL,
			0x0D6B90AB83D87C01ULL,
			0x5CE4FD8D9105F15EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x81F1F3580DBF4F4DULL,
			0x8089727FFA53118EULL,
			0x712BDD2E782D8D3AULL,
			0x1C81DCBB278724ADULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x42FBB64659EA701DULL,
			0x28F36310F02A946CULL,
			0x843777C0C3CBF215ULL,
			0x15FEFB6CEFF68A39ULL
		}
	};
	printf("Test Case 88\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 88 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -88;
	} else {
		printf("Test Case 88 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xE94F343D7C483410ULL,
			0xF45DF98733656441ULL,
			0x21D9BD52E9B16FE9ULL,
			0x4B78115964DD3DE4ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x97CAEADB51E03115ULL,
			0x16BEC60BDB06DDD7ULL,
			0x9E775AE03CCE0D11ULL,
			0x2A13B34116BF1D66ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xECB711E520C6A4D0ULL,
			0x2E72438765FD9B0CULL,
			0xFB7BBC5AFF47B4B1ULL,
			0x62183C8AAB5506C5ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x42D9D9363BA32691ULL,
			0x2C80B08C53251ECBULL,
			0xF8DD0C326C8CAA51ULL,
			0x459A48D109A057B0ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC2A4127C5BE30DC4ULL,
			0x2520561A9BA26DBFULL,
			0xC14B93889157B83AULL,
			0x05B61622790F001EULL
		}
	};
	printf("Test Case 89\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 89 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -89;
	} else {
		printf("Test Case 89 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xFE541C72AFE8E560ULL,
			0x02809075E2049794ULL,
			0x764961D84F1EDF57ULL,
			0x6C299DC2FF83C79FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x9305D6AE6ED1C796ULL,
			0x7B884DA73FE814B6ULL,
			0xBFEDCA9836C7DA29ULL,
			0x3931F69638286A19ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x4B1AEC00B13E4158ULL,
			0xC0F5ED76B2558724ULL,
			0x29428C87745493B0ULL,
			0x6A0C5F5317FA486DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF59AA2FF343E08EAULL,
			0x7E6BA8545839AD4FULL,
			0x349E3309DD58D0D3ULL,
			0x369A4BC563F92F85ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x27131F6DA90245D9ULL,
			0x600431F1C921DA26ULL,
			0x7555F3CD953AC6CDULL,
			0x71E64D029CB50FBDULL
		}
	};
	printf("Test Case 90\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 90 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -90;
	} else {
		printf("Test Case 90 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xAA69D7153AC49768ULL,
			0x6F77020A0CD85CD8ULL,
			0x344484A71392F9C7ULL,
			0x487AF9308B68FDC5ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xD8F11994164FB529ULL,
			0xC4C0243FF1C7F06AULL,
			0x836DC81B38D5BE87ULL,
			0x7AA9FBC3D0E775D7ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x0A9763D2F8C29DA0ULL,
			0xC5AA15274A263297ULL,
			0x112B591D2A20EB89ULL,
			0x646A5B9187A1B522ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x4F9DB2053904C279ULL,
			0x33C4815EAF20F6ABULL,
			0xB1448292C52EAA43ULL,
			0x094F83B65532BC79ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x561B56771E63F098ULL,
			0xD362AAB3A19E142DULL,
			0xFE1103DF204814EEULL,
			0x6D5B056542FD7405ULL
		}
	};
	printf("Test Case 91\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 91 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -91;
	} else {
		printf("Test Case 91 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xB97513269536A8D8ULL,
			0x91E3BC029839173DULL,
			0x00BCC79DFF4A2354ULL,
			0x5F0EE9AAB07C9362ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x3D2029F065AB0C8CULL,
			0x01384105D45A54F2ULL,
			0x4CA72578AA8CD3C4ULL,
			0x7A469903469D818CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF59E4881F2D6ECA0ULL,
			0x67F0674E99A7FD24ULL,
			0x4C1F4A41CC5DC56DULL,
			0x6B31534FA46C8047ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x5E7D09BBF1480970ULL,
			0x95705126C74339A1ULL,
			0x5FC924500B17D8C8ULL,
			0x7AC7FEA6C9864476ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x5C62E9E5D397D529ULL,
			0x576FE6E44A6DB5EAULL,
			0x19B58E4D7A5C74E4ULL,
			0x43BDB5D96AE2A4D1ULL
		}
	};
	printf("Test Case 92\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 92 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -92;
	} else {
		printf("Test Case 92 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xC311099A3E42E118ULL,
			0x4A4A03CB6F6BDA6EULL,
			0x5E7D45043DC3F2EEULL,
			0x79A6967F404262B3ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE8F1B0365B64F8A2ULL,
			0x5B4838561899D204ULL,
			0x8A9BC7F6DD39C7F8ULL,
			0x3271B017EEB579FAULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x54CB92E76E3DC760ULL,
			0x6F12BDC4A5E0AD46ULL,
			0xE8383E0D7004FD34ULL,
			0x6A5304C644749730ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x60190CA186C7BEF6ULL,
			0x5CF25B25E29EB255ULL,
			0x1BF6A31CDF60168CULL,
			0x7AC0F3C11AA912F8ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x6372D72790C476D3ULL,
			0x9EAFAC551C41061CULL,
			0xD970A2DF73ABA7E0ULL,
			0x72AB1F53E8016373ULL
		}
	};
	printf("Test Case 93\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 93 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -93;
	} else {
		printf("Test Case 93 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x688446D0CE245970ULL,
			0x4B79BD0BC633800DULL,
			0x85E0C55B8B7E0577ULL,
			0x51BE5FF3FD3DCF91ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x1D947013C703467CULL,
			0x2491890B53072F27ULL,
			0x07E4A1B357F1F184ULL,
			0x2C4954C410094B89ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x950FEBBBB0BE83C0ULL,
			0x37C554C745B10842ULL,
			0xA8265662C09AA9BEULL,
			0x4D6D00866895046DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x04A6B43117EA3BCEULL,
			0xC4B4984C2C5C917DULL,
			0x33F5A02111E5621DULL,
			0x7F7BE640C18F761DULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x4DD3870A953EAF34ULL,
			0xBE6685516F7268BCULL,
			0xC1C4FE6D2BE6202CULL,
			0x1BCEC5A5774184A2ULL
		}
	};
	printf("Test Case 94\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 94 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -94;
	} else {
		printf("Test Case 94 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x1E68E3B31857B0D8ULL,
			0x8527596EE43E2908ULL,
			0xC0B6B3C611ACDE5DULL,
			0x6B43CA3E98A06CC4ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x759E976EC134084FULL,
			0xDD30E82CA4E94246ULL,
			0x958663A4F3EB4B72ULL,
			0x191BA9F81A9F00CBULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x206A351FCA806CA8ULL,
			0xEDAA010042037F94ULL,
			0xC828CE9D9C341D04ULL,
			0x5FF1342D8187B513ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x470DC74AD6D8919DULL,
			0xBBD712246C358FC2ULL,
			0x4039CC9F6665DDB0ULL,
			0x2F3142784B0C880AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x98E11E90764DB95CULL,
			0x9BB9986FC69B3532ULL,
			0x94B3EDF9F4DE15BBULL,
			0x204ECF505B10579DULL
		}
	};
	printf("Test Case 95\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 95 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -95;
	} else {
		printf("Test Case 95 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xD346B93086F53718ULL,
			0x0B55EB2D30A95313ULL,
			0xF04BE954CD9508F2ULL,
			0x60EF6633EAE7B255ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4FC9EA6D48C68C61ULL,
			0x7015C2DAAB6104ACULL,
			0xAE3F2420E7DEC24BULL,
			0x072DBECB99826D43ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x0F29FDA8C23D7C48ULL,
			0x1A03AB28B29FC70CULL,
			0x457172D7DCC76901ULL,
			0x73C5ABA3B216B1E5ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xC6213A9DB8242A9EULL,
			0x046F93FE791E22FEULL,
			0xC70F9081F3854E2AULL,
			0x72ACEB070D4369A2ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x07F47A919D2F8B4EULL,
			0xE573BAB7BEC53F72ULL,
			0x9D1E95AB7A11CE25ULL,
			0x4CB35E679911B250ULL
		}
	};
	printf("Test Case 96\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 96 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -96;
	} else {
		printf("Test Case 96 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x6D1698A3271CF8D0ULL,
			0x2FB39984F8FC5E0BULL,
			0xEDE8E8D2D62E6B78ULL,
			0x709BC335B182C753ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x22B228DF3896D8E2ULL,
			0xC97036203B106265ULL,
			0xE567BE44BECE7845ULL,
			0x615B34E6717CC789ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xEE32F7F8065150C8ULL,
			0xE0B730006EB768E4ULL,
			0x2A65E36689203216ULL,
			0x64D327AF3A09998DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xFBBC20D882C5BBAAULL,
			0x9329CD8D6111DD14ULL,
			0xF529A6F15A9B431FULL,
			0x6ABD808324CE9E36ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xCBD320C409C30073ULL,
			0x1F4B1321E3BEE14AULL,
			0xA24D4B1899442F0BULL,
			0x5E0340E595860415ULL
		}
	};
	printf("Test Case 97\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 97 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -97;
	} else {
		printf("Test Case 97 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xE7F2D79C7E906F28ULL,
			0x3E300C055219651CULL,
			0x5AAEB56962752C4DULL,
			0x62468F001859EB36ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xFC8DF31FE5D13FB8ULL,
			0xFFF91E15EB051638ULL,
			0x9AA43703A39C73ACULL,
			0x522C8C71DED5A1A6ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x268737A694B28558ULL,
			0xDE0CD018B7BF0BD8ULL,
			0x973E0A33A8D64C6BULL,
			0x4D225E809D34430FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD809EAD1FDCAA97FULL,
			0x08F90C6D61C3C6F1ULL,
			0x99C43933B7551DCCULL,
			0x20D5BF0999C037CEULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xCFCC2A3147FD9781ULL,
			0xD2C76E4491507F9EULL,
			0x29003EAFCBD4BB9FULL,
			0x1FD08F69492B2D52ULL
		}
	};
	printf("Test Case 98\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 98 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -98;
	} else {
		printf("Test Case 98 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xE3BEF102D4FB9868ULL,
			0x4900E1CA71F82535ULL,
			0xA2F6976AA3054DA6ULL,
			0x597DC240D0145246ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x07FBCE03AE9AD2E8ULL,
			0xC1D915F94CAAB869ULL,
			0x6B6E161F38CA85B8ULL,
			0x0D8AD2E679C72018ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x861EC8AAA46BA120ULL,
			0xD6595B7620BFAAD5ULL,
			0x9C6A826EF7563958ULL,
			0x73BBBEB0EC5561B2ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x814B12BB7CFD80E4ULL,
			0x1B9C0EE1A1953C96ULL,
			0xCB528DCBDC445A9FULL,
			0x49F444A43B3EED7CULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x2319C2EE66916471ULL,
			0x2A5D84AC90FB3F38ULL,
			0xC34642711EC2D7B8ULL,
			0x4F148C1C854BF868ULL
		}
	};
	printf("Test Case 99\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 99 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -99;
	} else {
		printf("Test Case 99 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x097D35ED34276840ULL,
			0xE7C91DD6228DA353ULL,
			0xA4985978521F8A64ULL,
			0x4D61F6EC1A365F80ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x8177FA52247E0AA1ULL,
			0x7011A91B40A35E80ULL,
			0x9C22F8CCA369C537ULL,
			0x72ADE7A96A2C526CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x80A428C9C84AC628ULL,
			0x0599522F8E85AE43ULL,
			0xA456D30EE53110A8ULL,
			0x77D7DB1096A0771BULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x085DBA5D80336E6AULL,
			0xD51265759ECE7AD5ULL,
			0xC054B6A55ED31789ULL,
			0x2005B27CA5E1D7B9ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x1778BAEFE2AF2FB2ULL,
			0xF655346550D6A818ULL,
			0x75AB28D1983D62FCULL,
			0x4F118E080B611610ULL
		}
	};
	printf("Test Case 100\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 100 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -100;
	} else {
		printf("Test Case 100 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xC51C606AA51E92B8ULL,
			0x1143870F634892C1ULL,
			0x19DA835492760BB3ULL,
			0x5CECEFF8C304C2A5ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x578E1C487DB2F906ULL,
			0xAEF1A32573544590ULL,
			0x1B11CD648FAF41B3ULL,
			0x694D0BF284954D23ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x23AD2F375A97C530ULL,
			0xC00314AD652EE256ULL,
			0xF4349D3F86B64135ULL,
			0x763DF4FC1DFC4FEFULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x25F25AF771A03C8AULL,
			0xB72C4ED9586A9B5CULL,
			0x0C8C1C5BDD48E341ULL,
			0x12556FE2D224F495ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x40A003ED9868EC4FULL,
			0x14AF3E815F823A87ULL,
			0xF519E54991D38ABDULL,
			0x753AFADDDDC53724ULL
		}
	};
	printf("Test Case 101\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 101 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -101;
	} else {
		printf("Test Case 101 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x89BAE47734FF9348ULL,
			0x80A74D5ED8514EE1ULL,
			0x13B9EBDC63FA7A62ULL,
			0x4B437FA9C9DDBB5DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x56D027A696E1D399ULL,
			0xC3F0F97A7EA2D93DULL,
			0x321C6301024BD4B8ULL,
			0x2E948E2064DDE44BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x4523884811B00828ULL,
			0xF29035F4D5A9F144ULL,
			0x135981B6118CFF4DULL,
			0x62EED174E37E0735ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xE125FDA6704E4A9CULL,
			0x502CD9C77D23973FULL,
			0x293B9B1C3C23D559ULL,
			0x1CF393C428FF99FBULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x3C8CB9AF5261000BULL,
			0xD4CF16E2E8A89BD4ULL,
			0xCBFA194525841EC8ULL,
			0x402C67F3634CB5F0ULL
		}
	};
	printf("Test Case 102\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 102 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -102;
	} else {
		printf("Test Case 102 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x86679EA81B181B30ULL,
			0x3F7D834F75511A94ULL,
			0x19FC68AB018A7AE0ULL,
			0x4CF087D0785D48D0ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xC6EC6A71DEF4F555ULL,
			0x4146ABD98E102C8AULL,
			0x2ED0D80055E24506ULL,
			0x3D627586C29BABECULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x68F6368174590EC0ULL,
			0x14FC729F324A8083ULL,
			0x4A5B8E5107096067ULL,
			0x71F73C4BF2230B91ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x62BA1B270C996CA4ULL,
			0x2F1669F1098C1AF8ULL,
			0x7FDBF760F2F354BFULL,
			0x24DA29954E19C160ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x72538DAD0A59EB93ULL,
			0xB9B8E2A14BCB2E7BULL,
			0x4DF85A161EB7FA56ULL,
			0x21674A5001957450ULL
		}
	};
	printf("Test Case 103\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 103 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -103;
	} else {
		printf("Test Case 103 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x232AADF1AB3576A0ULL,
			0x4DA9B32B234D6C06ULL,
			0x0426E306F6299734ULL,
			0x4A0987C82A448D54ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x15959EF45255E6D4ULL,
			0xFDCB9461A1575709ULL,
			0xE9E306E7EAE8B20AULL,
			0x30330336972A97ECULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xA71F2AC8413D1300ULL,
			0xAB8C9FFA4906DEFBULL,
			0x4337241B304265B0ULL,
			0x6C98E381BB3FA6E7ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x7E03346C2DC04512ULL,
			0x73609585348039D5ULL,
			0x62BED40C74BA9B45ULL,
			0x34010BEF283ED83CULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xBB54763AA31426E6ULL,
			0x11C619D7C8FDF918ULL,
			0xB3324E29B2AE437DULL,
			0x6D753F8D97069CC0ULL
		}
	};
	printf("Test Case 104\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 104 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -104;
	} else {
		printf("Test Case 104 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x91DD29F82585F788ULL,
			0x5BB76C0D130A8165ULL,
			0xE8D7B0AB2A1B2590ULL,
			0x59DBBF55CF140813ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x8CF363F40AAB91DEULL,
			0xC483694873EBE9BEULL,
			0x12BE872D9B5249C1ULL,
			0x0E308B78BF1C1F6DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xEEAB0A04DDA7CAB0ULL,
			0xAEEFC864A450C20DULL,
			0xC204C553C3BEFC74ULL,
			0x64A6F6B92B65D67FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xCB6334C270B7FF00ULL,
			0xDBA281256F445F38ULL,
			0x55384EF0621168C5ULL,
			0x3E51B9C573A3FB3DULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x3474F2CA840509F3ULL,
			0x51207025E57D846DULL,
			0x0753BA4651F8D099ULL,
			0x41D378179BDE6ED4ULL
		}
	};
	printf("Test Case 105\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 105 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -105;
	} else {
		printf("Test Case 105 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x92C27A00179433F0ULL,
			0xFF7B67F878E6230BULL,
			0xA4DBB473903624F5ULL,
			0x50A3EBC7E6E97AF0ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x6D049594BEC78CB9ULL,
			0xA02847277C03E16FULL,
			0x2A4EC2469DCD693AULL,
			0x711D22B404AAA430ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9734C66E81466FA8ULL,
			0x721CF935FD697A09ULL,
			0x437BBCA47342E024ULL,
			0x4329F3A3F622A6EEULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x381968C64C753960ULL,
			0xF0EBB46132ACA36CULL,
			0x7EB9AC471C35764CULL,
			0x610C4E052C944681ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA8BCAE08AFB09E80ULL,
			0x9110C046935A2A41ULL,
			0xF729E5421FD5C0A6ULL,
			0x202F2D396261845BULL
		}
	};
	printf("Test Case 106\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 106 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -106;
	} else {
		printf("Test Case 106 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xABE52D724B1B62F0ULL,
			0x085A551182904473ULL,
			0x51E11E6C078274ECULL,
			0x4E50F789801C3A75ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xDA8237C5FAF127D2ULL,
			0xC25DF4AC93C7B849ULL,
			0x2C83C5255E861CA9ULL,
			0x75363804B3D4CBDAULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xAFE529CDD0E818A8ULL,
			0x786D5D04DB400D3AULL,
			0x0791BA8780FA31A9ULL,
			0x4CD7B0E2E9A5AF0CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x6442ACA3FA60B71AULL,
			0x21DE26DA4BFA6C52ULL,
			0x1AD99F70D5C6F0AFULL,
			0x0A4B86DAECFDB789ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF17B46A89E6BF994ULL,
			0x7724E03B5CB676A8ULL,
			0xED7D53E7275C7DF6ULL,
			0x34059BD515CD85E6ULL
		}
	};
	printf("Test Case 107\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 107 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -107;
	} else {
		printf("Test Case 107 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x60D18E7CC941EFC8ULL,
			0xDF162FFF0BF96242ULL,
			0x89D7402512E80A4EULL,
			0x6181CFFC204DDE1AULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xF1F7E789BA71DBE6ULL,
			0x82703394D66A37CAULL,
			0x770C38191A0E54BBULL,
			0x43A45447B359A5B2ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xA35BF73846230F78ULL,
			0x0944D250FDA3BE4AULL,
			0x115855D436A6402EULL,
			0x7A70DB1C586420EDULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x18D001BA42AE9C59ULL,
			0x90222BC0C47ED232ULL,
			0x5A314F21616B3254ULL,
			0x7383390888723E3DULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xAC8F592128D2A32BULL,
			0x11518891FE39A3BEULL,
			0xF4B007C74788749AULL,
			0x249E02C9D0BE3B3BULL
		}
	};
	printf("Test Case 108\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 108 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -108;
	} else {
		printf("Test Case 108 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x44A3DCA306D14058ULL,
			0x5FE2C5223D8D3997ULL,
			0xE204D90D9E77608DULL,
			0x73DD351D9512E1EBULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xD0CB8F159DED7000ULL,
			0x85F05243B6DC1A89ULL,
			0x0314758851952D08ULL,
			0x56922297DEAC9640ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2CD9CF6145D21850ULL,
			0xFC5FB5C7BE5068F6ULL,
			0x7FB3508AE08F8448ULL,
			0x752EB290A32935D9ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xFA3BBC0E24C6395AULL,
			0xE27D0F7A16F887C0ULL,
			0xF75E50C9B84E4BD1ULL,
			0x27081E6B4429F4DEULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x708C1EB8320DC88DULL,
			0x8680ABAAA75FA543ULL,
			0x8F79C054E22FBF69ULL,
			0x0EADAF6FBE6FFF46ULL
		}
	};
	printf("Test Case 109\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 109 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -109;
	} else {
		printf("Test Case 109 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x6A3D8F7996B842F8ULL,
			0x8E12CB5DB0A7F6D2ULL,
			0x18D2EE637CCB12EFULL,
			0x6A0CA7B01A2BB0D5ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x3329DE11B01BC5A0ULL,
			0x11640C3FA988CEB1ULL,
			0xC05D3547E065CDBAULL,
			0x02B9782F92C7D4D8ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xDDFADD179F20CE58ULL,
			0x7A9207C37DC77B95ULL,
			0xC929BE3ACC659928ULL,
			0x7AEE7307E876E324ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x213796EFA334435AULL,
			0x99FB2F3D463F0FE0ULL,
			0xA21CC677B7764E90ULL,
			0x6BBF3EB403127432ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x79651995D168B896ULL,
			0x8C38839D7CB485E2ULL,
			0x393DABE94755D982ULL,
			0x2BF0DCD3C093FF36ULL
		}
	};
	printf("Test Case 110\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 110 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -110;
	} else {
		printf("Test Case 110 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x2A7FCEDBF25B8A10ULL,
			0x52CC54C3B062B5DBULL,
			0x3EA1F77039DD8219ULL,
			0x6931BD33F78B49BAULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x9894B429F6756E40ULL,
			0x207EFD3F02050494ULL,
			0x9F9581914A9D043FULL,
			0x4F2E83A42FAFDE77ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF7D8FD088A243410ULL,
			0xB2178D16CF22D4BBULL,
			0x98530B0DB8A37CBDULL,
			0x5857E1BBAB384E8EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xFBEDB70948BA3EEFULL,
			0xD2838FCF4D493E97ULL,
			0xAE26286192511FF9ULL,
			0x1777063DFF862527ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x0D5CBE9B210D0A13ULL,
			0x1B330F4ACBE62319ULL,
			0x56ED5C3060C9A07AULL,
			0x7AC33E551E8AFAF1ULL
		}
	};
	printf("Test Case 111\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 111 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -111;
	} else {
		printf("Test Case 111 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x8EA196B0C765D910ULL,
			0x0EF2FAA584E2BBD4ULL,
			0x3D5482CF303CF0A1ULL,
			0x446B210DE562AC7DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xBBF26924DE0263BCULL,
			0xA96F88F9991306CCULL,
			0x4DEEBB58BF8BAD69ULL,
			0x3B9343903507DFABULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF44335B79F35A980ULL,
			0x98AE69454FBA1BBCULL,
			0x165A74C2129C3DB8ULL,
			0x62DB9D02D1A5576FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD01C601F2C1EB32FULL,
			0x620578EDA5477946ULL,
			0x9D73361420EBA2F0ULL,
			0x4978BE15C85D792EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC21454C136345BFEULL,
			0x9AF00C1959537040ULL,
			0x0375D49D2D0E5AFCULL,
			0x44B9F12CD02C10BEULL
		}
	};
	printf("Test Case 112\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 112 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -112;
	} else {
		printf("Test Case 112 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x1BE03062F547F2B8ULL,
			0x34C9F0907A5FF27DULL,
			0x2FC3A455A135F320ULL,
			0x501A33716A7EFCBEULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5771AA08AC39706AULL,
			0xEAFC3495103D87D8ULL,
			0x3F53EE0402864342ULL,
			0x5BD49AEF5181237EULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xDD06A36240C1CED8ULL,
			0x337E640E3C136A25ULL,
			0x01C6D815BB423AF2ULL,
			0x5C925FD5E7172FA8ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xE47D285C1BFBB209ULL,
			0xB9F926D4A2CF9904ULL,
			0x8CD070E526F9B998ULL,
			0x116ABB1A99AE3C51ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x3B68A1B42D7D5B03ULL,
			0xCEF2FB691977DDF5ULL,
			0x2C3A2DEEB7386871ULL,
			0x5B459D916D43217BULL
		}
	};
	printf("Test Case 113\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 113 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -113;
	} else {
		printf("Test Case 113 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x81ACCBE822842D50ULL,
			0x5201AF8B4A05E527ULL,
			0xE70BBFBD797B7AC9ULL,
			0x7D72BFDF4B0FFB70ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x12FDDEC84FBA4109ULL,
			0x84C90E8092DC7564ULL,
			0xA317D08B4967CC18ULL,
			0x59C181B054293F7EULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x58C64EFFDBA2B700ULL,
			0x8AFE4C7D24DC0731ULL,
			0x4F3A1C1BE9C79098ULL,
			0x5AE773FF0EC054EBULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x43188C148E0C7F21ULL,
			0xA04A5588CE08452FULL,
			0xFE2528C22EDB9EF9ULL,
			0x5CA74AB471FE488AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xEB6E4AFF27DE4EA9ULL,
			0x8857A48C81B5045FULL,
			0xD80A401702639795ULL,
			0x3FCE93D9F4EF878CULL
		}
	};
	printf("Test Case 114\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 114 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -114;
	} else {
		printf("Test Case 114 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x45115D9041124DB8ULL,
			0x7D8946BA7A0E63F7ULL,
			0x2C05F97F05AAD385ULL,
			0x474FD2028B9FA167ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x1FA9CD7914314C69ULL,
			0xCB1858E7A122B812ULL,
			0x22AC03709C3D53AAULL,
			0x15DCF21458FF3FEDULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x85791DD53B16E1E0ULL,
			0x044DD6CA2DE8C891ULL,
			0x7772798157CB50C7ULL,
			0x67C9C24C22D40414ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1F536D59B9BAD6AEULL,
			0xA6C47A4C5BA3AEC7ULL,
			0xCC3F7F5AEF33E479ULL,
			0x0F1D342363BB9F2FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA34BDFAD7CBF3935ULL,
			0xB85AB08629162E7DULL,
			0x14F17F56E1B9D9BCULL,
			0x7294E5CBC4EEB07CULL
		}
	};
	printf("Test Case 115\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 115 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -115;
	} else {
		printf("Test Case 115 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xA8427894A14AE2F8ULL,
			0xDB55AA72FFDAE562ULL,
			0x4BE8F7E01C38A1F7ULL,
			0x72C46C99C3CB3C8EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x21FE6AEC01CABB5DULL,
			0x67E85C433B3D6AB0ULL,
			0x36475FB8462ED1CCULL,
			0x7B41C4C9A93E0CE8ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xBD5DEF61D2959F30ULL,
			0xF87C82FA5DF9B680ULL,
			0xC0A3D56B4DFDB605ULL,
			0x5E2B49CF4D87650AULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x4D88290BA1430409ULL,
			0x8E5687D9333F3871ULL,
			0xCA6E53FABF34BBC3ULL,
			0x182D88CDDDC0506EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x922E43218CFD16D7ULL,
			0xD35343B37983474AULL,
			0xF8FD1A5AFC52E7C6ULL,
			0x1E8C304652F05AD3ULL
		}
	};
	printf("Test Case 116\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 116 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -116;
	} else {
		printf("Test Case 116 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xABDB16EFC8250018ULL,
			0x7A26853E9DD61FD2ULL,
			0x04E8913CEA32A437ULL,
			0x744CEAF2B76949C1ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x2D07F32001201448ULL,
			0x4F9E9685490BEF12ULL,
			0x768E6EB7CEED858FULL,
			0x3C7128647DE44458ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE81F97F27A37BD18ULL,
			0xF5DB1803AF792F1CULL,
			0xF27D2B5FDFE1F536ULL,
			0x7A06D849DEC0A45EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF64A983C68414ACBULL,
			0x5ABA304CA4DD910FULL,
			0x0C1ECFD20D072273ULL,
			0x0941783D971EE8EAULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x9F8B3BFDD7B0C012ULL,
			0x7967D4A02D0F771BULL,
			0xAB6661455AE0572AULL,
			0x4B62B8B52BACE09EULL
		}
	};
	printf("Test Case 117\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 117 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -117;
	} else {
		printf("Test Case 117 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xBF03B546322F6000ULL,
			0x786B05381CFE1742ULL,
			0x547C23B58D4100DDULL,
			0x6D991D90B0BC96F7ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x2A0457AEEA7732DAULL,
			0x8B6CF9A7E57B87EFULL,
			0x8B625C34746187C5ULL,
			0x394752EDBC662EF3ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xAE9ACB443A75EA18ULL,
			0x918E03ECEDBCB9BEULL,
			0xD16B33535144544AULL,
			0x5C0769FD635ACB71ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xEFB193306E479471ULL,
			0x368A7118F98F9350ULL,
			0x3BAAC29EA5EACDDAULL,
			0x2CD5F23B686BBB49ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x8ED3EB90EC856DEDULL,
			0x398B5F1AB4985A3DULL,
			0xFEA133F23C6D0FBDULL,
			0x20431C5E494014DEULL
		}
	};
	printf("Test Case 118\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 118 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -118;
	} else {
		printf("Test Case 118 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x53E203C1E59D41B8ULL,
			0x0C316421290898EDULL,
			0x62564A05C2AEA0F2ULL,
			0x52F65971881CAFC1ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x705FD41285240E80ULL,
			0x066E1B7E0D621FDEULL,
			0x4E4C35C8EBBA808FULL,
			0x004AECC33C0A4D20ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x5DC8D90264FD0368ULL,
			0x220CF78C071CD889ULL,
			0xA65219913EFF18E0ULL,
			0x647D8A5977AED87CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x5F65B17CB88394DAULL,
			0x8A176C256EF53B29ULL,
			0x86B33A252E9BE111ULL,
			0x620D8968A959BDECULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7BD993B2D9A75BA3ULL,
			0xBE3ACD31F9954EB1ULL,
			0x39AED6AC6A0F2EBDULL,
			0x46424B6C8E2FB00CULL
		}
	};
	printf("Test Case 119\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 119 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -119;
	} else {
		printf("Test Case 119 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x1275D240532B7A88ULL,
			0x871B79F61B4072DFULL,
			0xACD0F926E06620F0ULL,
			0x7B25879A17A19A42ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x8FD890365DB265F4ULL,
			0x5AEF4E4D930C151CULL,
			0x59ED6B8F32CFB8E4ULL,
			0x4371907CEBF0694BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xCB33CC1CA2BF1558ULL,
			0x430E5BA46A02EF7AULL,
			0x7EEDFF70B6BBE871ULL,
			0x5A9AE59588859BCCULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1A4747B5C5FAE9E2ULL,
			0x8995980C6A007CEBULL,
			0x587A6CF71764369BULL,
			0x0E6DC343A4192BAAULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x6CA6BDE7FA8E6BABULL,
			0xD98F59220B685695ULL,
			0x942D11212A9EAEC6ULL,
			0x0F7AA504C7883906ULL
		}
	};
	printf("Test Case 120\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 120 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -120;
	} else {
		printf("Test Case 120 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x727AD5F13FDA5680ULL,
			0x63BB47925091CFB1ULL,
			0x659EF53B3A1329F3ULL,
			0x74061BBB843404FAULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x610DCFB7BAFA96A9ULL,
			0x40A8E6D0F23AF186ULL,
			0x47AA43E5A1AFD018ULL,
			0x4B9719832F9461A8ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF50F0D0AA089E1F0ULL,
			0x6FEA7C9A5F21F428ULL,
			0x7422DCE53A014D8EULL,
			0x572AF6298B6FFC79ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xEA2E451D834FDB50ULL,
			0x29555EC13433616EULL,
			0x645EE55547FB595AULL,
			0x33B7B59F93836D8FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x01057AF25348D3FCULL,
			0x9495463A8DAE94B5ULL,
			0x824F9DA8AE7764D4ULL,
			0x50C5A0755482E58FULL
		}
	};
	printf("Test Case 121\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 121 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -121;
	} else {
		printf("Test Case 121 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xC850A57C3CB185E0ULL,
			0x3FEE055237692BF9ULL,
			0x89A8F484B5169B63ULL,
			0x6C9A12A9F099F909ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xF449E667D0E04F82ULL,
			0x9137E6767494C4E6ULL,
			0xFAFF5974501441ABULL,
			0x56A006091E8794E4ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x77A3A0D6086BB808ULL,
			0x10A2BE5256CD0C2FULL,
			0x621A338B19E4E380ULL,
			0x6E8E25CC535C3BBFULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x66D2EEBB2F548BA8ULL,
			0x681E700352944E2EULL,
			0xE2F36369F6BCB73DULL,
			0x748ACE2C5D279E0FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x2AC5E7A1CAAAB6AAULL,
			0x969BFB10E2F9C654ULL,
			0x037E5A30E135F6CEULL,
			0x45DD3B9702106101ULL
		}
	};
	printf("Test Case 122\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 122 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -122;
	} else {
		printf("Test Case 122 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x3D25C04B7E08E648ULL,
			0x75347A83648B4337ULL,
			0x772EFA97F5CB6B1EULL,
			0x6FD50ED00267DCFAULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x571CAECA2E02D99DULL,
			0x5F9778ACB11776EDULL,
			0x604909556103EDDBULL,
			0x5310CBE8D24A82F0ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB1F1B2AC6BDB6D30ULL,
			0xE0194D4C2088C784ULL,
			0x4C4145A1624AD754ULL,
			0x6E8D7988B5BB8993ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xFDEFE423720D729EULL,
			0xC457A9E9E13BA690ULL,
			0xE1B3A5A80A00B762ULL,
			0x610D7DA427A3499BULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x0DA3F9B2382BC8DCULL,
			0xF5D93E168690E0AEULL,
			0xFE768F68060D7B2AULL,
			0x100FCF44B73571C0ULL
		}
	};
	printf("Test Case 123\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 123 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -123;
	} else {
		printf("Test Case 123 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xA4A339059CC533E8ULL,
			0xBAA82BBC5D95BE1CULL,
			0xECB29FCD9CDE0226ULL,
			0x7223C1FED161D96EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA484011449E9D8FCULL,
			0xC0210607105D9C7EULL,
			0x7ED47A41653DDFC9ULL,
			0x1AD85410383C9044ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x71D19064E00DA200ULL,
			0x8A576AB91903F23AULL,
			0x51FD26011138D758ULL,
			0x75A818C87DA0A987ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x20D9728AA41B81EFULL,
			0x9F3047E9FBB59A57ULL,
			0xBEF48EB4B1781914ULL,
			0x2FFF29A9CD450CDBULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x8435E9E6233C9CC5ULL,
			0x795559489A3DDA40ULL,
			0xF45E2B358F969E2CULL,
			0x58A9B6F90B0A88B5ULL
		}
	};
	printf("Test Case 124\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 124 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -124;
	} else {
		printf("Test Case 124 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xA99A862E7919F9B8ULL,
			0x6D44A8625DB0E097ULL,
			0x69DB6005CA6AE1ADULL,
			0x441F31B699C95F78ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x2C9C67C2B3447F56ULL,
			0x09406517FF07F06CULL,
			0x260509CAD5B14D0BULL,
			0x2309048C20320649ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xCA8CCBC9EC8B93E0ULL,
			0x50D679F2511BC290ULL,
			0x620B4544876DC825ULL,
			0x48DF26496699DD8BULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x86A06858AAD9809FULL,
			0xA67B229396B73D5FULL,
			0x6AA673606A988554ULL,
			0x2F98323EFF5BEC1FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x5C166EC4A1F8437EULL,
			0xAEB924BC89678D51ULL,
			0x7F9E4A5990C70929ULL,
			0x2461E563F9ABD0AAULL
		}
	};
	printf("Test Case 125\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 125 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -125;
	} else {
		printf("Test Case 125 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x36C78917EBC13698ULL,
			0x7642E4BF68BDE527ULL,
			0x5A851FAC123EDF6EULL,
			0x43CD6470C95EE6A3ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE55810D2C8560FEFULL,
			0xA9410C34AB4242DBULL,
			0x953B964424ACB222ULL,
			0x3A5231B5EF2EEFBFULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xFD76E8FF18350468ULL,
			0x0DF8F4D9FF738528ULL,
			0xAC45533F696FC3EBULL,
			0x7DCB4427E650DCC0ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x94F1732E5E4F40EAULL,
			0x504E31D7C07FB610ULL,
			0x80CED703762CF83BULL,
			0x2A907FA0DBAF9D02ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x195CD75735EAFDCBULL,
			0x6DC32C246B745CB9ULL,
			0x7F3E1C18705E4E7BULL,
			0x0CC4FBF0D6B71EF5ULL
		}
	};
	printf("Test Case 126\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 126 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -126;
	} else {
		printf("Test Case 126 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x37FB44C2D52CCFB0ULL,
			0x68613DF7F8ADB9A8ULL,
			0xBA74926CB83A2E72ULL,
			0x69B57C36AB655A2AULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x170D1E54C359AAE3ULL,
			0xE70D170191C624BFULL,
			0xFBACE2E7FB6E5647ULL,
			0x75243D6F3CE4BC55ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2429099BA63FFAD0ULL,
			0x9C5ACA42FEEAC07FULL,
			0xBA6311BF8DA8F7B8ULL,
			0x44A3A5025D94FAA7ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xCF5A9D97427D98E5ULL,
			0x6AE199505EB2FFACULL,
			0xCDEC7242D546D415ULL,
			0x4A06E786F24BD737ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x2A5DE756DE22E474ULL,
			0xB73954AC937D2D3AULL,
			0x5BB84DD029BE1A1DULL,
			0x0893295C05A7251CULL
		}
	};
	printf("Test Case 127\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 127 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -127;
	} else {
		printf("Test Case 127 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xDB1C65AFACAA6DF8ULL,
			0x746DD36E37B8A357ULL,
			0x0790A5A215F6A825ULL,
			0x6FD221D2C94B1413ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xB52050DD45FD363BULL,
			0x2E2552331C817B1BULL,
			0x24C25D35B3A72E47ULL,
			0x61101773E99D1046ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x228D1CE944E23220ULL,
			0xDAA32AF3161A4081ULL,
			0x6F7087D2E3E28074ULL,
			0x6E25E26C52FB617AULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x76C4D659E9B13909ULL,
			0xF7B1BDD7756CE017ULL,
			0x4A504EEE39F9A414ULL,
			0x141C4326C949CA7BULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x22256D014BA23286ULL,
			0x852DA6FEBFD3BDA0ULL,
			0x370F76448C9474BEULL,
			0x1F827A2A4A629F2FULL
		}
	};
	printf("Test Case 128\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 128 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -128;
	} else {
		printf("Test Case 128 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xD5FD50EEE9EEA8D0ULL,
			0xA2133734C3A23884ULL,
			0xD32088433A67ECE8ULL,
			0x61B3884B2A127571ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x179AFD2C0E7005A3ULL,
			0x1D583F97F6F17BA6ULL,
			0xECE90B7F7E94A822ULL,
			0x21BDB54ED54CEF03ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x7AB304B44C4BAF88ULL,
			0x073FA0FE76C8854FULL,
			0x97E3841AE58A860BULL,
			0x5960BE49C8F87E46ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x38402AB04C5B706FULL,
			0x8584DC33ED87CEEFULL,
			0xE55FCF01E2D0D7D3ULL,
			0x27C41049E89C55AFULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x269407C64679C55DULL,
			0xCD04DD33F6DEF17BULL,
			0x4B6A2DA9B2AB6E6BULL,
			0x3C8688AC8D859E4BULL
		}
	};
	printf("Test Case 129\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 129 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -129;
	} else {
		printf("Test Case 129 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xA044A78E9E15FCD8ULL,
			0x1569D9A778952CB0ULL,
			0xE2963D37ECA895BCULL,
			0x700A7ABBDB9B8656ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xD40FC911C178B483ULL,
			0x327B43795B571B91ULL,
			0x4874019D50430F8AULL,
			0x344C448B5D66116DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x281D13F405F9FC50ULL,
			0x813A4E55AD1F8D40ULL,
			0xFFE6B1AB4E0F08DEULL,
			0x4B3740F7EF2663E0ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x5B4ECF1D80D955A8ULL,
			0xADF0EE5D7B4772F3ULL,
			0x48C5BC76A1B90258ULL,
			0x3E0305BB8E443DA3ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA82F784A01FBFD94ULL,
			0xADCBF54923E8BD0AULL,
			0xB36C7A413819AFF9ULL,
			0x6DF0FFB537323372ULL
		}
	};
	printf("Test Case 130\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 130 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -130;
	} else {
		printf("Test Case 130 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x975872AD95D0F700ULL,
			0x08E4CAA7C83CACF7ULL,
			0x0E40CC80F65EDB9EULL,
			0x68730CE48E0BEF41ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x8DB2BD533338BE68ULL,
			0xD8AA1DD844479BB5ULL,
			0x896FAA66056B4B51ULL,
			0x35B86C09363B1010ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC019C8FB23510EE8ULL,
			0x62FA89DA264D18E2ULL,
			0x486817760854878AULL,
			0x585AA3DCDFA623D4ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x7E346556D5575445ULL,
			0xD6E9409F5CE9EC35ULL,
			0xE980A250DD12D052ULL,
			0x485DE467DA69D972ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC0CE66E69A37DB89ULL,
			0x8A073871245FEAD8ULL,
			0x5AD149E258AAFC28ULL,
			0x6800E835578CD9CEULL
		}
	};
	printf("Test Case 131\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 131 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -131;
	} else {
		printf("Test Case 131 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x1FF019C84D2D18E8ULL,
			0x6E9E392820BFA20BULL,
			0x5EB0E309BCDECD75ULL,
			0x751DD83F9EC0A050ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x43EA8FE7298244FBULL,
			0x0AF07B39D7F47E05ULL,
			0x2C7642B4634C40EFULL,
			0x510979F8F25BEF5EULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x4DB633632C037E48ULL,
			0x01CD2C6412B87158ULL,
			0x9DBFCFE8A6413EFAULL,
			0x49F69F115769B1FCULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x5730478EB8B27818ULL,
			0x3B2137C31C7392CFULL,
			0x89EEEED3D0D1E172ULL,
			0x3657085C47957BA0ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA6DB023DCEFDE3C3ULL,
			0x967C779C4A633B64ULL,
			0x4BEFDC13C5D2A857ULL,
			0x61208FD4F29B8117ULL
		}
	};
	printf("Test Case 132\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 132 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -132;
	} else {
		printf("Test Case 132 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x3EC34497D180D418ULL,
			0x4C9A10289CBCCB79ULL,
			0x2B4C80DADF7A7A36ULL,
			0x6B62B477094935B1ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x17FD9E1C40018F1AULL,
			0xB07151A73A881640ULL,
			0x6CA6A91F17CEC017ULL,
			0x72D44AA5E96A8285ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF010A19C235F8138ULL,
			0xB22E1E15EF43B707ULL,
			0x06C392935C11DF81ULL,
			0x4E8A0B133208F26AULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x3C55BA84E02D4927ULL,
			0xF2AA9685505D36ABULL,
			0xCDBDDEA170AFBBDEULL,
			0x1056EA4900BF92DDULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x1427672945087E9CULL,
			0xE43E08AEAB8D5C2CULL,
			0xA5EE709A18914BAFULL,
			0x0B66C96849D543DCULL
		}
	};
	printf("Test Case 133\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 133 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -133;
	} else {
		printf("Test Case 133 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xBEFF16A2A44E4340ULL,
			0x711DC7D23A25181CULL,
			0xD9335E35CCEEFCD3ULL,
			0x69A3E8CC2B73831BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x663AA8FE27CBC917ULL,
			0xEBB00018452383D0ULL,
			0x2E60B84B1D80F33FULL,
			0x238AB37C07F549A4ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB3A89483FBE94660ULL,
			0xA7BF295C35AD44C4ULL,
			0x0525628A1AEF56A9ULL,
			0x4A3FA08A74454697ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xE7039228DA033385ULL,
			0xD2179F158F7EA42FULL,
			0x5D7D32F5B9167762ULL,
			0x30D0E4CCFA4D60FFULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF92216EFBA2D118DULL,
			0x51A5C5C65CED5E39ULL,
			0x5ECFFB21A6E7B830ULL,
			0x02C1AB8AF4DEAD55ULL
		}
	};
	printf("Test Case 134\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 134 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -134;
	} else {
		printf("Test Case 134 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x20DF7206FDC4C108ULL,
			0x1BE052CA54A9BBACULL,
			0x54E6E6931831A109ULL,
			0x556685CD305EF46FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x25FFC926994FCECAULL,
			0x750776BA476C6DF3ULL,
			0xB8189AFBA54ED7BFULL,
			0x1E7E627DD78FA320ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x4A3E5F248BE7FC58ULL,
			0xC87C58D4479D9989ULL,
			0x5017341C54500111ULL,
			0x6C748113DDFB0A7EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x83FD5532CC7B028AULL,
			0xF42B739218586AEBULL,
			0xB18451681EAFD32DULL,
			0x5AEBF0220DC9DB37ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB1D8F967E36D4C0FULL,
			0x2F3E7BAF08C8EF5CULL,
			0x833755EFFF2DD75DULL,
			0x21CA49A5DB85D3DFULL
		}
	};
	printf("Test Case 135\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 135 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -135;
	} else {
		printf("Test Case 135 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xC69B0757C7E71D28ULL,
			0x61CF74490D533183ULL,
			0xD64E0AE989A4B4D5ULL,
			0x5F7B5C975E4D8E73ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xF6644C0F9C430706ULL,
			0xF3A957BBADFA0465ULL,
			0x12C514B16A607E6AULL,
			0x7518887E14CE5654ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x0BDDDB7559996EF8ULL,
			0x81B687D25F5AB30FULL,
			0x5027729B53C600F0ULL,
			0x575A1CA12625387EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x8FE61A7B91F7AA43ULL,
			0xBF38A1A00300B524ULL,
			0x76A40DBBEB778B5BULL,
			0x60B1A93973C450D7ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x37D82C744375DA00ULL,
			0x2BF4038AE8DAEA0BULL,
			0x4072AC7E26BD6F63ULL,
			0x3C0BE09F27D7BFB9ULL
		}
	};
	printf("Test Case 136\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 136 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -136;
	} else {
		printf("Test Case 136 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x6BA33C84925160A8ULL,
			0x4E0E442400B65FC6ULL,
			0x8195C4E099351D67ULL,
			0x7F77240A7D0CAA4CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x632607927A5C8A80ULL,
			0x907B71ABF517D661ULL,
			0xE52C860E71A0677FULL,
			0x5A81B93EE823F308ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xA8F29DCD6ABE4330ULL,
			0x03FA84DBE88F380BULL,
			0xFB42D3D789D9D658ULL,
			0x7DD1429BCC2A18A4ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x507F2832609F138DULL,
			0x04EC7070A2A058BFULL,
			0x1CDFD9AB9EB1AB85ULL,
			0x77606AA3B837752EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x4F1889FF6AF01EA7ULL,
			0xBA20F4D0F0A6A97AULL,
			0x927DA9B5C1FB9EE9ULL,
			0x78620DA063A1B463ULL
		}
	};
	printf("Test Case 137\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 137 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -137;
	} else {
		printf("Test Case 137 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x47820C316A92A4E8ULL,
			0x84992BC21BDA98D1ULL,
			0x1A40794195173F43ULL,
			0x668A2127F27BFE47ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x22F5A9C65844549CULL,
			0x830E2F40331E0FACULL,
			0xE184F47CDDDE02FDULL,
			0x4195315E038F65CDULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xA975FFDF1216BDB0ULL,
			0x6198542832B2ABE3ULL,
			0xBF527F3D33D65A16ULL,
			0x7FBB3E5C766F9118ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xB454C6F152E59053ULL,
			0x7B2285A2F060EF97ULL,
			0x4FA0C0D04BA3AB34ULL,
			0x6BA901992D4BCAE1ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x11CB269AC08C1F5DULL,
			0x0C848FFA1687F82EULL,
			0x08D8D1BE2143DDA8ULL,
			0x2694365A2C859534ULL
		}
	};
	printf("Test Case 138\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 138 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -138;
	} else {
		printf("Test Case 138 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xDEF028ABBC37EA28ULL,
			0x744BF814A4D252CDULL,
			0xE32882F76C839AC7ULL,
			0x63E28C9133F12015ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x10700800BF94EC6DULL,
			0xA13DB5359E8C7D38ULL,
			0xA603827C031699F1ULL,
			0x255DB41F2CBF3872ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xA4D1EE4F37BB4BE8ULL,
			0x6D205E7CC54C1D4FULL,
			0x9837D542ABD65F1BULL,
			0x5EFB0AB5C2336230ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x14F986D9FB06365EULL,
			0x0FD700A98EBE69D4ULL,
			0x11B36978211C7D6FULL,
			0x34889CAAE03D3B35ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA217970ECDB06F93ULL,
			0x2BE9E8781860E2C0ULL,
			0x220E0D2175B4F8A9ULL,
			0x71FC1678D24B4B48ULL
		}
	};
	printf("Test Case 139\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 139 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -139;
	} else {
		printf("Test Case 139 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x7CD46F980C1BCA58ULL,
			0x993974367F838FF1ULL,
			0x5C06883BF05D67E9ULL,
			0x642EAAEA486E8795ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5A0621CCECDAFDB0ULL,
			0xFDE719568CB730B8ULL,
			0xF30E1602B8DCACEEULL,
			0x03CF88029E70A8D2ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC066FC2301F13AD0ULL,
			0xEF55F8B5FC65C08CULL,
			0x5F3C783ACE08B8B9ULL,
			0x5578FB5CA2885F7CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x31872FCA4F9274CAULL,
			0x1EB7CD9DF8E95CD3ULL,
			0x35110D8E1586F881ULL,
			0x52E8EC7F20511601ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xBEC1568CA8F60C86ULL,
			0x07C6C463B318FA85ULL,
			0x992FF2224146275CULL,
			0x0DF6292E55550E59ULL
		}
	};
	printf("Test Case 140\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 140 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -140;
	} else {
		printf("Test Case 140 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x194F423D47ABFBC0ULL,
			0x7D7CF1EA8D5FA379ULL,
			0xE92131DEBBC6099DULL,
			0x7DF9086017D93DACULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7071ABDA091799E8ULL,
			0xAB2EDDBC54950EC4ULL,
			0xEA3386D164D08B59ULL,
			0x2AA6326339DBA844ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x90C8BF5681D8C548ULL,
			0xAF1519C64164E3E3ULL,
			0x96386877EB3A75A6ULL,
			0x7D53A8FD34FEDD4CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x9057D8773C11E562ULL,
			0x89BE03BE8B98CCC2ULL,
			0xF243D07AE35F4B2BULL,
			0x4DE770245D2F22E3ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC3B790CAA2AEAA71ULL,
			0xFA495740B7DD27B9ULL,
			0x58F4E6A33B66E147ULL,
			0x42C5DDF48007AE55ULL
		}
	};
	printf("Test Case 141\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 141 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -141;
	} else {
		printf("Test Case 141 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x8B043CE3B97977E8ULL,
			0x218D5371A194AB4EULL,
			0xEC70FA4F795A9A1DULL,
			0x45AF70581F04BAC2ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x25EEB8B2547448D0ULL,
			0x9320C4F7AEE37474ULL,
			0x9EE0952AD2A803AEULL,
			0x67497B522DC7CB7CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xBB47BF9104CB4B60ULL,
			0x6B5FC05EDA844F57ULL,
			0x7C0870800E63C871ULL,
			0x55BCEF1D410244C9ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xEB733BE7292C90BEULL,
			0x49FE0BDEB1EFFA8AULL,
			0xF3678A5E05771DC3ULL,
			0x60F5B639E8083E54ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x18EC714A80787A95ULL,
			0x195324176F1B0F3AULL,
			0xB82BE3F90AC84633ULL,
			0x31CB6DE00C31D2EBULL
		}
	};
	printf("Test Case 142\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 142 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -142;
	} else {
		printf("Test Case 142 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x68FF1D982F8E7CF8ULL,
			0x8CA549597056E0D9ULL,
			0xC51EFEC03598ED79ULL,
			0x74B12E78E67FAC0AULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x01E51B9A6ACEEE45ULL,
			0xB894292588E7829EULL,
			0x79D1BA88E919DC73ULL,
			0x7602BE9C991EEB9FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x0B5737FD98E1AFB8ULL,
			0x115F3153E0DE5395ULL,
			0xD062B5B8B04A4CA8ULL,
			0x4CC5AE2544B710C6ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xC909B67663C8ADEFULL,
			0x61FD8921330B28E3ULL,
			0xBE15F98070487F8EULL,
			0x15D2F2ED2661EE38ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x861C834E07614DE6ULL,
			0x7531283419E7ADAFULL,
			0x115749EF515859FCULL,
			0x519AFFB51EEE887CULL
		}
	};
	printf("Test Case 143\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 143 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -143;
	} else {
		printf("Test Case 143 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xF1B47B06B86648F8ULL,
			0x1C40DB0874193067ULL,
			0x2B6850242D67B140ULL,
			0x63F43D851CE1BADDULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x2821C85CF117077EULL,
			0xC04022C47CC99CC7ULL,
			0x95414DCDA9B7E12BULL,
			0x61966573C4F06BD4ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x1D0A737790A505A0ULL,
			0x1B674C356D3F0C90ULL,
			0xD279800396C4E762ULL,
			0x7607FD5EDDEF4AA8ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x33EED688DE047F15ULL,
			0xD483235C6FCA0850ULL,
			0x21DBB819FBCF3CEEULL,
			0x6F2F9EF4092A7237ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x5F4A8C01680D734CULL,
			0xCC83186C1EFC359DULL,
			0x3095A56A0F1CF1BEULL,
			0x518A8639223E96B3ULL
		}
	};
	printf("Test Case 144\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 144 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -144;
	} else {
		printf("Test Case 144 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xAD9B2156DFB66FA8ULL,
			0xBBE015BA7359CB7FULL,
			0xEA87803582111D54ULL,
			0x7184745C72F1B75CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4BFFFD8A3736487AULL,
			0x5F46FADB1954FF83ULL,
			0xA112DF8D4FDB70CCULL,
			0x11DCE076E970FEB6ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x18FB1C94AE8ADDA0ULL,
			0xF7E0ADF704AEECC3ULL,
			0x0A20D283774A2F92ULL,
			0x4BCBD77E4CD9DEEFULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA0C0F25CBFD6F105ULL,
			0xA1BB9BBBECA72D21ULL,
			0x21286BDBC650F32DULL,
			0x74E6AACD656AA457ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x3908E6666F9D6B67ULL,
			0x8083820FACC6EFBAULL,
			0x96CB5A8459D63C70ULL,
			0x352AF3E71FDCB63FULL
		}
	};
	printf("Test Case 145\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 145 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -145;
	} else {
		printf("Test Case 145 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x5C9324B2C36D23F8ULL,
			0x35757D7DF8BEC1A6ULL,
			0xD2605A4CA00FB63DULL,
			0x63021C81CA935765ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7C6BDD4C9B47B709ULL,
			0x5EAF673C64A80EAFULL,
			0xB681D770FF6BDEDEULL,
			0x5A793C4EDB92502DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xA98D1DBFE6D89440ULL,
			0xB00CC108296E3B6CULL,
			0xF1C42F3CEB04BFBEULL,
			0x4C714AF198FC534AULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xC30C487FAE4245D7ULL,
			0x8E75C07B7CB81F92ULL,
			0x5000C5314F32563DULL,
			0x4A08E0853320440AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC08AE95AFDF2C027ULL,
			0x09935D691E98E224ULL,
			0x42D3729700829A87ULL,
			0x21FE6CEC1EE2FCB6ULL
		}
	};
	printf("Test Case 146\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 146 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -146;
	} else {
		printf("Test Case 146 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x09B03B148860C4F0ULL,
			0xED5C341C1F2C6F73ULL,
			0x08B2253E032B3B8CULL,
			0x639CD7F4E3C8607BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xDB40A6800542D84AULL,
			0xAD0D28BA615FEF63ULL,
			0x2A3DAFE495F4FFE3ULL,
			0x76861440B0514258ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xD1788BACBAB5E798ULL,
			0xA260133E28E8FCD5ULL,
			0x80448ABCCCD4E6ECULL,
			0x6450086791160C1BULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x93FB2EF6053D2EC5ULL,
			0x9D9A28E96EDF76A5ULL,
			0x2A769D3A7C1318CAULL,
			0x52766DE22F07D1F5ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD5F24F0852CABA2FULL,
			0x21611624459678D8ULL,
			0x881B6438901833C0ULL,
			0x446C715DB7ED392FULL
		}
	};
	printf("Test Case 147\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 147 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -147;
	} else {
		printf("Test Case 147 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x8764AC02BAD7CED8ULL,
			0xF27E640F3CB75A71ULL,
			0xB77D50DD5963EBCAULL,
			0x5D8D841B5F1EE56EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x0DE15E4916A4D7E7ULL,
			0xAA27F66C3732195DULL,
			0x28A77602CBA066A9ULL,
			0x4F9619CDC767D356ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE49C1E98873A9E58ULL,
			0x885CBC7B218DCEE6ULL,
			0x076FA23D4D35805EULL,
			0x61AF3FD13C71C1CBULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x958BB70427BA7AFAULL,
			0xBE47E44D7D34DD1FULL,
			0x3B95E295C05102CDULL,
			0x097C7697121686ECULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF9F788805608CE8BULL,
			0x034E57130C7B9605ULL,
			0xE88374327324D13CULL,
			0x0DC5C48A94226ACEULL
		}
	};
	printf("Test Case 148\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 148 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -148;
	} else {
		printf("Test Case 148 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x5D57682733F90D08ULL,
			0x2F0E2616313F2B2FULL,
			0xE4D6AC1595C6CBE2ULL,
			0x78E789752C98754DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA7109DD8A3A5418EULL,
			0xF15DC6A929DAA66EULL,
			0x1A400E04F7276A06ULL,
			0x5563F39300C7E10DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xD914454F00266B98ULL,
			0x0B74F06845FCD498ULL,
			0x6E9F465C1F1B451CULL,
			0x61ECE63C1633E9D0ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xE4F563A3E7E50A07ULL,
			0x5ECE303FA81A3529ULL,
			0xEEA8A8A70A2E1E4FULL,
			0x7687B4F02CE0A58EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xDCD7E97BCAB3517CULL,
			0xD1DDBD1FCB96E081ULL,
			0x50D1675AA4D6F3C5ULL,
			0x2CD80CAE3649D60EULL
		}
	};
	printf("Test Case 149\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 149 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -149;
	} else {
		printf("Test Case 149 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x2A002BA1B00E2A70ULL,
			0x8262D3F874917E5BULL,
			0xA102B4BB59C5E8ECULL,
			0x58DB9E05ECBD2423ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7D2B739A8270D843ULL,
			0xE271E9F3A73E9910ULL,
			0xBFB9E23B4FEC14B7ULL,
			0x709BD782AAA924F1ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x77AF5E3BB2E74E38ULL,
			0x457DC5C8B9B4D12DULL,
			0x1CD681CCC3FDCEF8ULL,
			0x5FA902475D5432BDULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x89CA91FB9563B403ULL,
			0x4698ED9C7FCC3B55ULL,
			0xB7BF163435A2CC2EULL,
			0x032A5C1CE9A0C5CFULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x841166860603B549ULL,
			0xD95B055D400A7B08ULL,
			0x9F7ABCB4258C6873ULL,
			0x3F60B15FF2053BB3ULL
		}
	};
	printf("Test Case 150\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 150 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -150;
	} else {
		printf("Test Case 150 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xD650A55C7A53E688ULL,
			0xC50422AB0212E476ULL,
			0xC2BE4C9668C8CB5AULL,
			0x5F9DFBA93EEEF5D7ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x8B9AF2E66395F998ULL,
			0xB7EA440197643524ULL,
			0x63F89D29472F3772ULL,
			0x3063B44CEF3407FCULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xAD805B8FFC575600ULL,
			0x4CA733F9B0649CB0ULL,
			0x3D0CFD68BBDD21E5ULL,
			0x726E930A18023DFFULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x4F833D78D6F9350AULL,
			0x40AE6A220379F846ULL,
			0xC6AFAEA95C16EB28ULL,
			0x39295CA36A174F14ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA5D8EF3C2C4D3B24ULL,
			0x606B32C7F905A500ULL,
			0x2EEB17696CF1C3E7ULL,
			0x4AF2B0FEC2110EA8ULL
		}
	};
	printf("Test Case 151\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 151 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -151;
	} else {
		printf("Test Case 151 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xDA580684FFCEED38ULL,
			0xC72B1B722260066FULL,
			0xE745FCA67FE89CB9ULL,
			0x6924C6F8D2D68D63ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x9DAF4756C8E040DFULL,
			0xFD9326CA88F2F140ULL,
			0xADA2DD788664A93CULL,
			0x76BD07C49F135C66ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2865C7598FA4EBA0ULL,
			0x61E87695EF8B034FULL,
			0xF737FDBDE52599F9ULL,
			0x53F13D2434F8BC01ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xC8C26AA039A0FBD2ULL,
			0xC799B9608ED6A23BULL,
			0x86A18D54CB09E31DULL,
			0x01807C64E4F1670BULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x216C22EE62C837DCULL,
			0x6846494C0525F414ULL,
			0x0F13F9FA5257CC51ULL,
			0x120B3D44109E594DULL
		}
	};
	printf("Test Case 152\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 152 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -152;
	} else {
		printf("Test Case 152 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x00B3CBB52B49BA70ULL,
			0xA6E08E5DB8C9A2C5ULL,
			0x151413EC5C1723A4ULL,
			0x7E92967656A56D67ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x3E46D162AEC07B04ULL,
			0xF3FF2985FB349D34ULL,
			0x75377446CD24DB19ULL,
			0x00DAFDF1474417D3ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x33DC269D6E376918ULL,
			0x84D2AA034EE8457BULL,
			0xEF6048A900744085ULL,
			0x65F90E6CB11D4719ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x23A2D4A0404B732EULL,
			0x46856B6765420016ULL,
			0x117752B1E99CF62EULL,
			0x1918662456030512ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE964804FA6ABF654ULL,
			0x457D3336570AF537ULL,
			0x40B326ECE26812A1ULL,
			0x23BCB26C16C69378ULL
		}
	};
	printf("Test Case 153\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 153 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -153;
	} else {
		printf("Test Case 153 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x7134F802F5905D40ULL,
			0x011FB9A98A19C761ULL,
			0xB74BC94AB8A3BA3AULL,
			0x573451625B952C7CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x0AD3A60F11C1F352ULL,
			0x5B43179EEF7C4885ULL,
			0xE6F2C482BDEADB66ULL,
			0x79297040D40F02BEULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xD9554FA7D6D03408ULL,
			0x4C91E654A28BC1A6ULL,
			0xAF25DA4CFC5AF442ULL,
			0x74B90F0A7861906EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD8C26A87085FED8DULL,
			0x712DAEDC69238CF2ULL,
			0xDED4BDE661114061ULL,
			0x1CB168421303E28DULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF82A51B6C9E9C2C4ULL,
			0xB7A3D8976F9341BEULL,
			0x1920784B92C21E1EULL,
			0x08B18F945A3D2259ULL
		}
	};
	printf("Test Case 154\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 154 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -154;
	} else {
		printf("Test Case 154 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xF47DD7C21DB460D8ULL,
			0xDAB393BBB89917B7ULL,
			0xB23D379FAB508DFEULL,
			0x68D29C117E99044EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x46B725342DE4A03DULL,
			0x485B3CDD3BA36126ULL,
			0x444D984F5D437E11ULL,
			0x154E11360D68F988ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xDA70A3B98A6511D8ULL,
			0xAFDD95BB83C450DDULL,
			0x89F0877A3AEEC2F7ULL,
			0x4625D2EBFB839A81ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x3FADE565B308B94CULL,
			0xA9B23DD961E8BC9DULL,
			0xF7FA17F803099066ULL,
			0x09B7A5C81CB06416ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xFF7BDCEA3EACABC9ULL,
			0x690ACD600E8A0340ULL,
			0xC8DD14BFF3F72630ULL,
			0x2934B19F14E208C7ULL
		}
	};
	printf("Test Case 155\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 155 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -155;
	} else {
		printf("Test Case 155 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x36FEC85FA7DC0B08ULL,
			0xA431E66E4C1861FDULL,
			0xB36C393DA786AB09ULL,
			0x4542D59A1E24BA62ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xD7C624337DEBB23DULL,
			0xE875C3B18B465D5FULL,
			0xD76242C80DC61DB7ULL,
			0x335D46772E56128BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x46C01E52946FBAB8ULL,
			0x327A962809DFBCBEULL,
			0x98B56FACAB494072ULL,
			0x6259A03246434534ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x85DFA77FA69ED5B7ULL,
			0x77738170227E3248ULL,
			0x9620ED81C57B70A8ULL,
			0x3FFCED6F3C2E079BULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF70196EF755FA4C3ULL,
			0xBD448B5F6A8B3F32ULL,
			0x152A5D3459465DD9ULL,
			0x453E6CA52A9F0CB0ULL
		}
	};
	printf("Test Case 156\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 156 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -156;
	} else {
		printf("Test Case 156 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x53E8750DB05AAF50ULL,
			0x7E906D711A4319F3ULL,
			0x3F1E9A678CB9175CULL,
			0x75A31E35168B1460ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xEAAF63A7BC7FE84BULL,
			0x1D615B0CBEB3E326ULL,
			0x06DBE89C8540371DULL,
			0x77AD4805F20380D8ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xCDADF3D6280C5838ULL,
			0xF207B1C9869F40F4ULL,
			0xDD3DA9B71072D2F0ULL,
			0x45E2D92FDAF389C6ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x4A3D8C358F7142B7ULL,
			0x3B5DE067322C4F74ULL,
			0xE639A49B2BED08B1ULL,
			0x69010D1935653C62ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x775E7A98F0235925ULL,
			0x4BC6D1674A9458A2ULL,
			0x72EE6ABB98783A2BULL,
			0x7E03D7FD282D2A6CULL
		}
	};
	printf("Test Case 157\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 157 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -157;
	} else {
		printf("Test Case 157 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x877260A00E07E5F8ULL,
			0x291AC5864B43905BULL,
			0x4A440893D13B7E6DULL,
			0x415723E5FE0F7134ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x71387DF073B0FC1DULL,
			0xE898808B533F18E7ULL,
			0x17E40DCC98BAE8C9ULL,
			0x4261C0D504CCB5DCULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xD88B63A98ABA0368ULL,
			0xF50FE2A0CB9909D9ULL,
			0x373D3D1B90B2695BULL,
			0x6C9A6F164CAF1CADULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x35CCA864D494972BULL,
			0x4E9A5068F773BC64ULL,
			0x7536C3939B94F897ULL,
			0x3A37B8D022D7EA42ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x9EFC2F339207F1E3ULL,
			0x134951C1CC542F52ULL,
			0x8A4B4E996BF870FBULL,
			0x1024105FA13E7E85ULL
		}
	};
	printf("Test Case 158\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 158 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -158;
	} else {
		printf("Test Case 158 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x1F0E61D7BDC1B088ULL,
			0x622754FE9E8BA22CULL,
			0x08D372C84510A3B4ULL,
			0x59362DEF2A0C89A8ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xC037F1371B9B72E4ULL,
			0xCB24A041523AFF73ULL,
			0xDBEE014AE690983BULL,
			0x18DEAA0CB2B47AC0ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x5EAB6F7E0A987358ULL,
			0xDC02762EA8C81E7CULL,
			0x4B70AFCB0F4A2C94ULL,
			0x453153B45CDE4728ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD906EAB6556D56CFULL,
			0x8C14A7ACA8F87E8CULL,
			0x34130961270282BCULL,
			0x242CBEEF92BDB6D1ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x3500124B2F486645ULL,
			0x505FBA948C7AC9D0ULL,
			0xA3E882AF7183C92AULL,
			0x7614FDDE4F87F25AULL
		}
	};
	printf("Test Case 159\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 159 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -159;
	} else {
		printf("Test Case 159 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x7F19AFDC61690068ULL,
			0x0026281BB816CC7EULL,
			0x8BC19242057C84AEULL,
			0x6382E3BECB15A071ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x82D6E015D3723D1CULL,
			0x4D3DD77984DCA4BFULL,
			0x543D5075FDF494CCULL,
			0x528E85A283ED71DBULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF994071DD6E82640ULL,
			0xCA897F534EF8A906ULL,
			0x0084238EF805306BULL,
			0x69064ADBFF41FBEAULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xFB46F89A76A8DA21ULL,
			0x3187111A206198F5ULL,
			0xC4B7C5310DA15837ULL,
			0x47FBEA1C1CFB32F0ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x6FCC5899F999F9D4ULL,
			0xA86558472B8D64B2ULL,
			0x7CD1B03102F9A6EAULL,
			0x1F1AD237D2647A86ULL
		}
	};
	printf("Test Case 160\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 160 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -160;
	} else {
		printf("Test Case 160 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xDB18F862965BF020ULL,
			0x5F02A3B956245170ULL,
			0xA89E1C81B8BA90E8ULL,
			0x58B8D460536D8BDEULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x68EB3AD14AB8F386ULL,
			0x8D0B8E390A749C6AULL,
			0xA5497F2F15DFA63FULL,
			0x3A686F0DA23046EDULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x550E714DE7135880ULL,
			0xF8C40CF3D3B45F0AULL,
			0x7044A54A0AEEC98FULL,
			0x691427F29AF42BECULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xB51F4E6D8F6F41ACULL,
			0x0401B315A00165AFULL,
			0x2A527A21A39F9479ULL,
			0x2779727E21F01044ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x169441BEDB1DC5F9ULL,
			0x8582C37EF922CBE2ULL,
			0x93D9FC4634AD4911ULL,
			0x724F15A0C3DEB0EAULL
		}
	};
	printf("Test Case 161\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 161 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -161;
	} else {
		printf("Test Case 161 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xB4DC8D23D033ECE8ULL,
			0xF53CBA5F843CA752ULL,
			0x0FF155188C4E8866ULL,
			0x62E1DB42388DA561ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE8F2A4CB35CA2F26ULL,
			0x89BCAAB9C009DFB5ULL,
			0xF1AB7985A91BF656ULL,
			0x782967ED61590FC2ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x6A19E67C98047520ULL,
			0x77436168DCD95E6BULL,
			0xE8D5338EAE177E6BULL,
			0x4B223E34F7CDF703ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x6A82204FAE6DCFC2ULL,
			0xA8FB03A541BE50F7ULL,
			0x3AD66B1162A6199EULL,
			0x2AADA24097F68ED9ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x5E3FF26C9AC8FFCAULL,
			0x43DC4406BC6972BBULL,
			0x155006300149727EULL,
			0x644794A6843D571EULL
		}
	};
	printf("Test Case 162\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 162 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -162;
	} else {
		printf("Test Case 162 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x77857BCAEA30ED70ULL,
			0x040A763B9CBE579EULL,
			0x74F081477D862A23ULL,
			0x61FA3BAD9F777C7AULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4EF75EF182CBAE31ULL,
			0x38DBA1F2C89ED436ULL,
			0xB37FAD777FFCAED4ULL,
			0x303EE7E28DBD3F6FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x73ED842D4B1045E8ULL,
			0xBEC7682D7E5705CFULL,
			0x6A6D9DCB9F380532ULL,
			0x7A4D377F154750FCULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x696A4B157BBFF453ULL,
			0xBD6B9B84F7C09E24ULL,
			0x482A2FEC36F08557ULL,
			0x598A9CCEFC0CFA56ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xAEF64240184F0F02ULL,
			0x3236791091DD9CA4ULL,
			0x4725F9A5E68C43F3ULL,
			0x32685FD0332503F0ULL
		}
	};
	printf("Test Case 163\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 163 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -163;
	} else {
		printf("Test Case 163 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xDBBFFD8E8267EE08ULL,
			0x31DE0E5E2832D112ULL,
			0x14279A7325B47CFCULL,
			0x7C5B14683BC9618AULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xB8D9CE283CB2E601ULL,
			0x07375DB82B153652ULL,
			0xBFEFC5F8343790CBULL,
			0x23758F7446015D6DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB06238B6C9A15FE8ULL,
			0x38893091C443CE00ULL,
			0xE546D80E2B419663ULL,
			0x52D1B00D6D409531ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x2DF178F6C06A0577ULL,
			0x02CFD5545CC626EAULL,
			0xAAECB773E3C29404ULL,
			0x0017471B344E7FB5ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x9731E436169FA64AULL,
			0x3F733C0E539B5BB0ULL,
			0xDD8B1DBDAB651D99ULL,
			0x1DD3580A82584AEAULL
		}
	};
	printf("Test Case 164\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 164 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -164;
	} else {
		printf("Test Case 164 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x2AAF458E446C7C30ULL,
			0xA349303576F4D80EULL,
			0xBB389D469A01538EULL,
			0x515CA804610D6C61ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE4A154AA7A97DDDEULL,
			0x18CF9E56E93154EEULL,
			0x53206A28D07E826EULL,
			0x13887BBCBB1EDDB8ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x385FC1488DCD5C18ULL,
			0x82F11C3B1DA72C7DULL,
			0x9BEE64B136F9C8C6ULL,
			0x6A82B146C15A1525ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD48945AC681A2266ULL,
			0x297AC60F16A567FAULL,
			0x7E32BFF411FFD702ULL,
			0x68399FC36D61AE12ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x15EAA006A7A62D6DULL,
			0xC67EC13E6F9AF237ULL,
			0x49F6F8797BA08A84ULL,
			0x57766F0090C81FCAULL
		}
	};
	printf("Test Case 165\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 165 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -165;
	} else {
		printf("Test Case 165 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xD31C8C39846E3AA8ULL,
			0xAC56E4E15FA0B707ULL,
			0x5E396889816C5271ULL,
			0x68C5C0D5BD2A5F56ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x145BA01FEBDB8CEBULL,
			0x71A2081C8453B76EULL,
			0x7899186EFBFBB8B8ULL,
			0x29304640D1F531A6ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9830B178E5757820ULL,
			0xB9AB6D8302BECFB4ULL,
			0x210B368EB210C2DEULL,
			0x7F8CA8FA4A59AEECULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x042C6A555400F3EAULL,
			0x4B99D6D52BF174ADULL,
			0x0A41ED8506DD9DD8ULL,
			0x217B124B94EF83ADULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x5CCE6706AB336C9BULL,
			0xBC7D79E063E25173ULL,
			0x639CDB38A8692BDFULL,
			0x15B5CFF22D0D012FULL
		}
	};
	printf("Test Case 166\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 166 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -166;
	} else {
		printf("Test Case 166 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x8BB51D8724A9B8E8ULL,
			0x5614A7881D7F11B4ULL,
			0xCAFC1D288312A8FEULL,
			0x45BA70826ACAA1C4ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x726F964C912F4816ULL,
			0xF25B7AF1435F6095ULL,
			0xDD09016709DF8BE6ULL,
			0x62C28F56774E87B1ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xD5F6DBB9481A9E08ULL,
			0x6FC2C16CDF1D14F8ULL,
			0x133499EE9607406CULL,
			0x4CD5F6734344F31DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF49FA6AFEF90F231ULL,
			0x6B495E05FC88B70FULL,
			0x2E2BC91C0AF6ECBDULL,
			0x42426EF92C92587AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7147C26F85F03A4DULL,
			0x0D630B0938EA2505ULL,
			0x06DDEF1E4076C5F9ULL,
			0x638CEF1B9254AB32ULL
		}
	};
	printf("Test Case 167\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 167 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -167;
	} else {
		printf("Test Case 167 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xA4D08A1582357038ULL,
			0xA907871C4346D41BULL,
			0x42304298F871519FULL,
			0x50015B1CEDA8BE1EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4B21934A38EDF6B7ULL,
			0xE9275E2BF36DF2E9ULL,
			0x2390E606157523EFULL,
			0x2E071DB99BBA4264ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2CF6609A7403A5D8ULL,
			0x86A707E285800C5EULL,
			0x0CE9D002B47CFC9CULL,
			0x74B18A1CC5886113ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA395D6A59026A9E2ULL,
			0x47EBA7EDC1A5DAFFULL,
			0x266A6EE3F61382F0ULL,
			0x423630204A5FDCABULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC073944040E50818ULL,
			0x4152B2424F552601ULL,
			0x851151402267C7A4ULL,
			0x5500F88B1234FBFEULL
		}
	};
	printf("Test Case 168\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 168 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -168;
	} else {
		printf("Test Case 168 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xDD06253DDC40C498ULL,
			0x72BF09D3621AF99CULL,
			0x375F1557CC5D6ACAULL,
			0x4796005BED0AA149ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA8CED958AC4FBE8CULL,
			0x041D259F7E3EC6A2ULL,
			0x7FF4BD0AB15F5B5BULL,
			0x19C20D3BD43EA135ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x19703A3E20CA1650ULL,
			0x46F5DA17308189C8ULL,
			0xA5DD5D0F7F65D955ULL,
			0x7A6BA62D949A2EF7ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x957B9F33D82FA9B8ULL,
			0x948668DDB1CAFBECULL,
			0x502E0513C3C7BD24ULL,
			0x03B9E741DCC581E7ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xFEFAF95523A9B898ULL,
			0xB1657F94A6EEAB2DULL,
			0xF3123B96395ACD4AULL,
			0x760D81859BC2B591ULL
		}
	};
	printf("Test Case 169\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 169 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -169;
	} else {
		printf("Test Case 169 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x0683D6BDAB10D8B8ULL,
			0x565B642E6B8F5D07ULL,
			0x3E585E8552E8F2D2ULL,
			0x5DBCFED0B1BC4C71ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5D666DDFEFFBC363ULL,
			0x57A907839E0EAC67ULL,
			0xDBA9D978BB39A5C0ULL,
			0x285B9C75B9CC95F4ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB0166516ADE00AE8ULL,
			0x489F5FC1F0011C31ULL,
			0x9A066A5FE162B945ULL,
			0x7DA4899A3B87BE32ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xDBFA9E31AF8588C2ULL,
			0xF925B1C4BAB94581ULL,
			0xCC54CFEBA864D1C4ULL,
			0x49BB2300CC24FF8FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB8805A01DADB89D4ULL,
			0xD6D44BDF366EFFC3ULL,
			0x6E60AACE7A7E68F8ULL,
			0x7809A0C0EA3E1D0EULL
		}
	};
	printf("Test Case 170\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 170 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -170;
	} else {
		printf("Test Case 170 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xA02875F504424A88ULL,
			0x935A137F8BF79ADEULL,
			0x7F3B3B5DB0A93ECFULL,
			0x53AF3F34942AF163ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xD3EB4CC7F9A20846ULL,
			0x262B8165A4D2F2E2ULL,
			0x5A9103B4D0C10E47ULL,
			0x4C77B8FBA0959830ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x052D82BB15048160ULL,
			0xF8FB6A7D538D413CULL,
			0xCFD55C7C373EEDB8ULL,
			0x6D8EB1B3075F8B29ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD31C3B4DC4FE9EA5ULL,
			0xCE3F826B1923496FULL,
			0x8DC35F90707088FFULL,
			0x5FDE03C6BC240E16ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF50A7090C40925D6ULL,
			0x1E58956552176FF3ULL,
			0xDF1386758C7B1B9BULL,
			0x345B479E13B206B4ULL
		}
	};
	printf("Test Case 171\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 171 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -171;
	} else {
		printf("Test Case 171 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x3A450709DB08B120ULL,
			0x238F6522C4669949ULL,
			0x53108037BB79DFAFULL,
			0x539016787468844DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x346944A74A6C0180ULL,
			0xBC29CDCB228D4746ULL,
			0x1984D50F2B1BC032ULL,
			0x59EB94C7AA95BD9FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC269AD86C6520158ULL,
			0x9B3637403822C43EULL,
			0x9497596EAB12DE1EULL,
			0x7C8CB6755B7B146CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xE7731D1863660CCEULL,
			0xFBD7848AA869251DULL,
			0x3BE2A433585105E9ULL,
			0x19924651813B4B23ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x2558311E31302266ULL,
			0x907D204E41ADB6B7ULL,
			0x561A3798277CBA1DULL,
			0x3ACE1D625CEDFA2AULL
		}
	};
	printf("Test Case 172\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 172 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -172;
	} else {
		printf("Test Case 172 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x8490A0A869420600ULL,
			0x5CAB426DCC9C0AD4ULL,
			0x62F10811A311C6ACULL,
			0x62DA324AC2E071D4ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7DAE96D8A8878386ULL,
			0xC24D5068B10CA7EFULL,
			0x8BC0C32D19E98C59ULL,
			0x3F45BB28DFBA27EAULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2F36B0B8D3352040ULL,
			0xBAAC26971905A17AULL,
			0xDE1E1AC3394997A7ULL,
			0x4851BBE6863B5DABULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x4F02AEACE9A4E4C4ULL,
			0x19AA90C42D42372FULL,
			0xB22A4BB6C3D0DEBBULL,
			0x0EA23022298FA7D3ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x9C0172A7B997E0D6ULL,
			0x0BC0A73D87D30415ULL,
			0x18139BE35FA0A64CULL,
			0x664B3D81540A2782ULL
		}
	};
	printf("Test Case 173\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 173 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -173;
	} else {
		printf("Test Case 173 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x6DD1BDA82906F340ULL,
			0xBBDF5149F0028D28ULL,
			0x218F8A24ADAA8A25ULL,
			0x6A9BBC4C67004C98ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7029D1E37D678C86ULL,
			0x5E9B34C0E3E62898ULL,
			0xEC19AB6336D1880EULL,
			0x2651EBD845E7A747ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x1B2F9C81F1B33780ULL,
			0xEAD9020D10CEDAC8ULL,
			0x198F625BA19C701AULL,
			0x5D11AA854DD01A02ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1550850F5569FE88ULL,
			0x0C7919BA76F3268EULL,
			0x4DF0ADED2A87B117ULL,
			0x43971FCC6C3CB631ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB3648550DB416B3FULL,
			0x77AE844B25FA2DF1ULL,
			0xD28B16521E6941BFULL,
			0x0D5C56891EAF5BA0ULL
		}
	};
	printf("Test Case 174\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 174 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -174;
	} else {
		printf("Test Case 174 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x439A8D3EB36D8848ULL,
			0x3E036927D63FFF88ULL,
			0x29872F2141F99DE7ULL,
			0x60DEEAB6ACA28FFCULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4428BE92C1EAA4D7ULL,
			0x6058F19AE3B5D073ULL,
			0xED4D6BA36D24CCD1ULL,
			0x75658C18321AF246ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x03DB0C96E7AD5640ULL,
			0x19684D5E60A6E478ULL,
			0xF3C3922CCC6E1595ULL,
			0x42CB74D89A21A878ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xE2FBFF994ED53452ULL,
			0xEA0E58FD896629C1ULL,
			0xEDA505525C513EB4ULL,
			0x7D4803CC598A499BULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x79F11634120F06F2ULL,
			0xA3EE923FC34EFC67ULL,
			0x1565E983E94DACB1ULL,
			0x489FB1E2DBFFBE43ULL
		}
	};
	printf("Test Case 175\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 175 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -175;
	} else {
		printf("Test Case 175 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x0DC2AC5D421C23E8ULL,
			0x0B7CDA662DEA44DEULL,
			0x6C547346FD0F6C55ULL,
			0x64712E2F226057A3ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7D8DBAFCCCF6E51AULL,
			0xC7E550F0A9C77030ULL,
			0x0DD6CEE0A9EF043CULL,
			0x7ACD6CB9A0AF2D57ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x8C420146C79BB5F0ULL,
			0x690E6FBE73A5B441ULL,
			0xC637248780C41EC1ULL,
			0x6722C7C813D0877BULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA835371379F03900ULL,
			0xDE42466D44F69AF7ULL,
			0x8568A0B12C374660ULL,
			0x79C33F284AC95C81ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7E573A8281B62310ULL,
			0x0DD1ED5507DCDBFFULL,
			0x9261592C076CA8A7ULL,
			0x4708FCE45DF7BA0EULL
		}
	};
	printf("Test Case 176\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 176 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -176;
	} else {
		printf("Test Case 176 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x13447DBBC82DB450ULL,
			0x5CEF9908945DB599ULL,
			0x468841764F931E67ULL,
			0x5E7A23875C73B86EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x687380489503C823ULL,
			0x4ED1B3E657712F71ULL,
			0xE0611E6EC609A283ULL,
			0x004B9D4400AC165FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x1940AAD9970233F8ULL,
			0x3594BCB571FAFD43ULL,
			0xC3AAEC31CF634E73ULL,
			0x4C5D4FF127796F52ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x77771D7712F35EBDULL,
			0x2B7ECB18B2563BDDULL,
			0x71BB317DF40245D9ULL,
			0x527082B7E88B6A8BULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE26020897BF1EA14ULL,
			0x3D2D32E398CC3D50ULL,
			0xA59253A5C2F8410EULL,
			0x551BA7DC28C73CCEULL
		}
	};
	printf("Test Case 177\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 177 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -177;
	} else {
		printf("Test Case 177 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xF19008750EDD3BE0ULL,
			0x8AE7751CD4064AA7ULL,
			0x77E048D2A21C93B8ULL,
			0x523E2796BF9F57BAULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x54FE5F2E0DB16BEBULL,
			0xC7715F31F48A1BEBULL,
			0xE1D39DB9BF83E221ULL,
			0x60204B67C97474BDULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x40606C6EEF233BC8ULL,
			0xE8A314D87AD66A51ULL,
			0x9C68891D340F4483ULL,
			0x51E2282751B901D1ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x846DCE9DDA281828ULL,
			0xE48262C150A748B8ULL,
			0x0BB95AAD76CB50D3ULL,
			0x33619C4110FD0124ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x50FBB84EDDF69D69ULL,
			0xA5EE47F864AD54DDULL,
			0x33BB842E2ECBFDA9ULL,
			0x55967B78181AAA12ULL
		}
	};
	printf("Test Case 178\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 178 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -178;
	} else {
		printf("Test Case 178 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xACA29C48BD8A2A60ULL,
			0x7FB277F087510051ULL,
			0xF212D270DDDDAE06ULL,
			0x68140F9708D60362ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xDE3A154D6B39AC0BULL,
			0x31EA411327EC2975ULL,
			0x84695B0227EA9D88ULL,
			0x7FCD2B192329FA60ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2720C760DAF5EFA8ULL,
			0x0CBF551A7751CD7EULL,
			0x1119B4744B616274ULL,
			0x49C60ADC453F5249ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xFB0F2EAB97D4B256ULL,
			0x2EC0545C7019B823ULL,
			0xF2A07BC760FD102CULL,
			0x38D59329A75F8955ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE1E7D601ADA5982DULL,
			0x452D8EC76F14BCDCULL,
			0xDFF2A67827376D77ULL,
			0x7C4354CC1B2FA1C1ULL
		}
	};
	printf("Test Case 179\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 179 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -179;
	} else {
		printf("Test Case 179 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x698B23CFA50F05F0ULL,
			0x1193802E4A23D374ULL,
			0xC20A18C054FB4D8BULL,
			0x5423BCF71378C06CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5C79A6F98BDAB60DULL,
			0x47C9F46D6A4DD316ULL,
			0x39AD177D466B591AULL,
			0x7D9270F6FEF6F6DBULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE7DC5CB6ED7650E8ULL,
			0x92EDCF390A80A4CCULL,
			0xD525AEAB47852960ULL,
			0x655CD31F721511B1ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xFB3317A7DC08A09AULL,
			0x9EE5C2832C390811ULL,
			0x622C6561B110FD20ULL,
			0x37EA1739869EAE0CULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x699C9452C5614061ULL,
			0x4AD8425954FE1B29ULL,
			0xCADC85EE605ACA53ULL,
			0x30A94D445EE0BB35ULL
		}
	};
	printf("Test Case 180\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 180 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -180;
	} else {
		printf("Test Case 180 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xC27470FBDA54DA80ULL,
			0x47FCD2DE238BA3BBULL,
			0x7887368B93E10FFBULL,
			0x726EE0801B98A5FBULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4484EA635CCCCABDULL,
			0xF148219D41F16FCEULL,
			0x7394E5D7B683DC01ULL,
			0x42C5F5B38FDA3DADULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x61E7E274166067E0ULL,
			0x35B13CD4A1878489ULL,
			0xB82427320098B9A3ULL,
			0x7B1C0427A3F55691ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x13CFE4525FAAEE8BULL,
			0xBF558E94CF3EABD1ULL,
			0x4457F5E85DDAF839ULL,
			0x232FEC53908F9F4EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xFAFBE8BA7964D406ULL,
			0x98649939E92538B2ULL,
			0xFCF40D3892FC1A53ULL,
			0x6E0FC5C37E0ED0EBULL
		}
	};
	printf("Test Case 181\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 181 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -181;
	} else {
		printf("Test Case 181 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x16737C7F78359C70ULL,
			0xBB0BFEF42406A036ULL,
			0xA963B451DE1367EFULL,
			0x5502FF41775A7C21ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE2A794CFA97E46F0ULL,
			0xFF223982117D7FB9ULL,
			0x1B384E7F3764F199ULL,
			0x738B534BE6CB3864ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xDFBA3A82058454A8ULL,
			0xF3CA98F21BB84739ULL,
			0x593BE345A2576BE2ULL,
			0x45690FA2F6EA987BULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD85BAAC1BF097AB4ULL,
			0x8A6F100286F57D51ULL,
			0x2094389A7E6A8F1BULL,
			0x68DAD4EA5060F9B2ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x062F15916B101FB2ULL,
			0x4F9DE47C959E2009ULL,
			0xCC58BBE6AD833F40ULL,
			0x5F2DBBEF244A5463ULL
		}
	};
	printf("Test Case 182\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 182 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -182;
	} else {
		printf("Test Case 182 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x5A9EA82670EC4138ULL,
			0xEDDAE4F97EAFD297ULL,
			0x4D6975F22E4ADC58ULL,
			0x42A15DFA8DD6ADFCULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x706162C7F4463644ULL,
			0xB93B1FFF5535793BULL,
			0xC1717AD757BD67A7ULL,
			0x77BFF5C7777EB8C9ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x61705C781BC0DC60ULL,
			0x0A63BC182B115245ULL,
			0x288065E101DE3652ULL,
			0x4A7CD8F29923004DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x8E2343B638DDD2A5ULL,
			0xED674EEFBE5C82D9ULL,
			0x5BAEABFA198AFF00ULL,
			0x551FA31DC2D7FB0FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC6AB7CB3A7528B41ULL,
			0x97BD6C230DBA7693ULL,
			0x80A0820035B4EE31ULL,
			0x0571C595320AD415ULL
		}
	};
	printf("Test Case 183\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 183 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -183;
	} else {
		printf("Test Case 183 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x64B16420CA011AA8ULL,
			0x9F2E3F5814D1D0A2ULL,
			0x0F723C81EF571482ULL,
			0x679A6187F3965403ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xC455C8D3B2CE7529ULL,
			0xCAE7636D83269C4FULL,
			0x14CA8D1C4F712E44ULL,
			0x1A99C63E70572D00ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xD6615B724A403318ULL,
			0x385AF3EEF53D8D37ULL,
			0x2A7398019CF9F3A1ULL,
			0x4943A7945AF3D89CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1AAE80BD5FD67C2EULL,
			0xDAE2C77C64BE30E0ULL,
			0x4AE5FED0743FF3E0ULL,
			0x168C3417A6A83833ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC171E8B092807BCDULL,
			0xD40F82A24BBA063AULL,
			0x29B6B9E48C66E8E7ULL,
			0x1B206779B3126F61ULL
		}
	};
	printf("Test Case 184\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 184 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -184;
	} else {
		printf("Test Case 184 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xD4DD6F2932256950ULL,
			0x2B3D5682D099D78CULL,
			0x0E065902A4A0A3F4ULL,
			0x5A0DDA5490D4F4B5ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xC0EF665E21549D4EULL,
			0xD40706ACEEB9BC39ULL,
			0x8D82EE4DA9F18B6CULL,
			0x45B2808549561175ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xFD409E62E35F27E0ULL,
			0x32646288B0C311AAULL,
			0x7AFE0C9AC3D6CBE3ULL,
			0x6446829300F0A9C9ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1A62B0FDAB0BF2FCULL,
			0x311D3AC22A8D6CE0ULL,
			0xD8AD04A07BFB375FULL,
			0x133D5905978411F9ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x308689BADFD717A3ULL,
			0x64C5D12EA7B2D0C7ULL,
			0x560F380BDC203F8AULL,
			0x5A12ADBB0214750CULL
		}
	};
	printf("Test Case 185\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 185 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -185;
	} else {
		printf("Test Case 185 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xC7E7A35B179CFF98ULL,
			0x85C1BFF81EE51F45ULL,
			0x65B09D3850D84AA7ULL,
			0x52445CBB0C277581ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE8FB1F929EAB1E97ULL,
			0xBA6672679AD00012ULL,
			0xA3C4A2781B4B2CF2ULL,
			0x59C751A60F4FD0B6ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xCDDA1DDF60657AD8ULL,
			0xE6BBE285154486D7ULL,
			0x89F93CAE0D40C25AULL,
			0x70902109974A4026ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x224A83C4D4086C21ULL,
			0xC0B65488AE812FBEULL,
			0xD4AB3977E0F7F75AULL,
			0x4566DD2FFD07704CULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA70A8DC7BFC002D2ULL,
			0x3AE5AD81FA8C36A0ULL,
			0xAEA43C6358F099CEULL,
			0x6579CF88168EC87EULL
		}
	};
	printf("Test Case 186\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 186 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -186;
	} else {
		printf("Test Case 186 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xB9BDD373BC634178ULL,
			0xC6A262FB2D8A4F35ULL,
			0xAD8B6385B7745250ULL,
			0x5F5AC2F77C49D7E9ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x167268A0C9D755FFULL,
			0x7401FDB138B9AFE3ULL,
			0x2513C450E169544AULL,
			0x16D3D6F496DEF4CBULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xD53F96216ADA5400ULL,
			0x2A4C661BFDDF63BDULL,
			0x1C6A528A89583150ULL,
			0x70069C056C18312EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD30A0E834BC0FA4BULL,
			0x1CDFD3708A6F079EULL,
			0xC93D374CB2142A9BULL,
			0x4B3C1D6C5DA598B6ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xDA77579975B71A6BULL,
			0x6097CBAD306CCA9BULL,
			0xCBC80D68A90F349BULL,
			0x724507B7AF6CABECULL
		}
	};
	printf("Test Case 187\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 187 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -187;
	} else {
		printf("Test Case 187 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xFB2C895E966BEBE0ULL,
			0x7D3395C3D5E61A68ULL,
			0x740CABDE948D5426ULL,
			0x79D10A79CB9212B5ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x2B12F2AFFE4DE267ULL,
			0x5EEEA9190DF6F3C9ULL,
			0x48A874990A92730DULL,
			0x2A8B40B8D71D4002ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC2308BAE775DE690ULL,
			0x0D45481B4AA32511ULL,
			0xB3F7C4613F01B2FEULL,
			0x765F7A5346D3BAA5ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xFF86670FC6DA1D8EULL,
			0x84A034DB4FA025E1ULL,
			0x67BBEF702AEA1F70ULL,
			0x69606D1F20A45CCDULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x8D1CE21272139F40ULL,
			0xED80564A71B4D33CULL,
			0x211310C1DA8C749FULL,
			0x52B6A5AF330FDFFCULL
		}
	};
	printf("Test Case 188\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 188 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -188;
	} else {
		printf("Test Case 188 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x784A0E521808CFA0ULL,
			0x82987E3F060F78BBULL,
			0x3BFDDF37B74237FCULL,
			0x7BACF639190F5574ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE75E57A695C8B6CEULL,
			0x50444FE844430FA0ULL,
			0x7383D222681A4A79ULL,
			0x4E9BC8A2960F27C3ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF8DD600AC16B15B8ULL,
			0xB0AF480F2FA2E3ABULL,
			0xEC3CADAABBABA8FFULL,
			0x79B8C16FA39DA875ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x832354D9085D12F6ULL,
			0xDD84FFE73BECF08CULL,
			0x3D73694043175742ULL,
			0x1BBB6DAC4BF0825CULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x62234C05777A96B5ULL,
			0xE3D8E56BCDB8177AULL,
			0x2FD57C8DD26147A8ULL,
			0x127FB6E731C6714DULL
		}
	};
	printf("Test Case 189\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 189 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -189;
	} else {
		printf("Test Case 189 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xA1733D1C13FBD240ULL,
			0xE3D7EE6562AEF8FDULL,
			0xB12E07D9B1139135ULL,
			0x69FB8863455EEB00ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7B28462A98C4CF9EULL,
			0xAE7B439857EB96BCULL,
			0xE63BF04F521274C7ULL,
			0x02BC13B82B980C20ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x88CDF855FBE57718ULL,
			0xAA336D90AB014CD2ULL,
			0xB3D4112B723BBA44ULL,
			0x63EB5FEF9AB748D8ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x7A4EB726030F32B1ULL,
			0xF5311F07B89FC33CULL,
			0x514C4A0C67DAE0F7ULL,
			0x525265B53667FE94ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x101A33AB05B0CD2FULL,
			0xDFFDEFCD151F85C0ULL,
			0x25263A60F1F086AEULL,
			0x1882CC775493B659ULL
		}
	};
	printf("Test Case 190\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 190 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -190;
	} else {
		printf("Test Case 190 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xCB8FABD78BC8FE38ULL,
			0x09A1B5535E0160DCULL,
			0xE7765571CD83D571ULL,
			0x51636DBF7EFC3EDDULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5B4C0B071E220575ULL,
			0x1BC83B0555294F0DULL,
			0x878CDF68776C3522ULL,
			0x7625CB36DD1E53BFULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x0B8AEDCFBE80C9D0ULL,
			0x461B2EADFAF51413ULL,
			0xD2F3E0DE3B675E68ULL,
			0x6E5053666ACD86C6ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x996969EC1E66C3CFULL,
			0x9740E764395DC95AULL,
			0xB77FB2C1753A724CULL,
			0x322E2E6E6F6FC365ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x9A8E3264B1B874DBULL,
			0x3C786EB3BAB0C338ULL,
			0xF289B43AF086C1DBULL,
			0x5A6DD1F3501165BCULL
		}
	};
	printf("Test Case 191\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 191 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -191;
	} else {
		printf("Test Case 191 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x345AB021DBFA9EE0ULL,
			0x3976A41FC7B392F1ULL,
			0xBC3FDD4E6F3A2CCBULL,
			0x5CFB2188A87045D0ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xAE5ABF30090A258AULL,
			0xF54F74367099B2E2ULL,
			0x17416C03F779B00FULL,
			0x613E74CF51E1C465ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x7A4488A5BF4C7748ULL,
			0xFD3D3B049F3FF9C4ULL,
			0x2D904AE6D5D40CFBULL,
			0x6A519F0FB88C0293ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA3902BC34F3A1A03ULL,
			0x8070C0C81E29018BULL,
			0x6388DE15B683927CULL,
			0x43DEDB8DC006A03DULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xDAEC88CF6E7BB4F8ULL,
			0xF231816572FABAFAULL,
			0xF846CC02097AC62BULL,
			0x0976D34AF958BA48ULL
		}
	};
	printf("Test Case 192\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 192 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -192;
	} else {
		printf("Test Case 192 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xB4E493B50E043B28ULL,
			0xE537F2C4A2BE8187ULL,
			0x892A4F8A2A836B8CULL,
			0x6D470A769651661FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x1B10C0A2FF50ED58ULL,
			0x512FC553A6FCD4F4ULL,
			0x0E593CCEC736F185ULL,
			0x7243E0CE61C88E07ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x58B777B15249EF50ULL,
			0x8967CBE6BC689C30ULL,
			0x120E0E925BAB61C0ULL,
			0x68C60486B0E2FA1FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x22E771CC547C08F1ULL,
			0x5D532A284AA2259AULL,
			0xF4E31BC133D71809ULL,
			0x7EE26FC7FCC20EC3ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x0D1F3785419C00BEULL,
			0xDAF5628C4B16D9B4ULL,
			0x25C001B45F9C6B0BULL,
			0x6B1EC0F10E5923A7ULL
		}
	};
	printf("Test Case 193\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 193 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -193;
	} else {
		printf("Test Case 193 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xDCCA79F5BE307F90ULL,
			0x7550FFBCF0F54692ULL,
			0xCF5507DD2C042E6DULL,
			0x585F63499543C348ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xFE9E274E2ABCFFAAULL,
			0x8FE31B7430E56FA7ULL,
			0xB34F95268DA47B11ULL,
			0x4CAC55FE4A4CE66EULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE41C19EA5B031D50ULL,
			0xBFBA337D12E65360ULL,
			0x4B668B8C21D2AB7FULL,
			0x5256006A6C8F4190ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xB59E5AA88D5D3747ULL,
			0xE0C1CF2982F37F79ULL,
			0xB5A40B838DB6B1F3ULL,
			0x46EA48901550C307ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x44B682EE8F0645A9ULL,
			0xD007DA7679C248CBULL,
			0x61536D7804285EA7ULL,
			0x1BB1B3980B73F9B0ULL
		}
	};
	printf("Test Case 194\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 194 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -194;
	} else {
		printf("Test Case 194 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x11652CD077D29CE0ULL,
			0x6D985B4FF6A1AD98ULL,
			0xA34C50F670BB2F3BULL,
			0x45DB48EC709D9DE3ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xD54E114A26968086ULL,
			0xE13ECDD1CFF3D850ULL,
			0xC0FD0BA6A0760415ULL,
			0x237DE864296FB9FCULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x1AF56A848E0AA110ULL,
			0x6471337BD41B4C8FULL,
			0xD20F1B39F318F702ULL,
			0x660DA1E6D3192D65ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA15B79864A8AA108ULL,
			0x4BCB08E3F49AB4BCULL,
			0x85202715AB2C5012ULL,
			0x398842BACFEA7091ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x8EC4EA9026FD2728ULL,
			0x7B3393459FA4FB3FULL,
			0x4D5392A0999B34F1ULL,
			0x2E4EB8FDA8494CB1ULL
		}
	};
	printf("Test Case 195\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 195 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -195;
	} else {
		printf("Test Case 195 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xA99976321D32B600ULL,
			0xBA252A49006136D2ULL,
			0xA924AE5640FB9E44ULL,
			0x60C7A9CC3ED0E625ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x37A6048194B0D7A4ULL,
			0x9FBC7AE8CD4D8CB1ULL,
			0x7C7E5178E4ECA4D9ULL,
			0x16B477E0D7CCD869ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xFF464F0649A06178ULL,
			0xD03C33B03B34A721ULL,
			0xC02FF2E1683AE41EULL,
			0x71E991332C433BB2ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xFDB68B71856E6E95ULL,
			0xED9EDC2A283E7490ULL,
			0xDA648EBC5E20C68CULL,
			0x5B436B8D3CB320BBULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x1BA1DB2A8160047AULL,
			0x8F8359CEFCBBE57CULL,
			0xA4CB73B7F19BB6C2ULL,
			0x0B05DE25D12E3717ULL
		}
	};
	printf("Test Case 196\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 196 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -196;
	} else {
		printf("Test Case 196 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x6C1CAA0A09805F98ULL,
			0xCDB3E3B9BE6E1683ULL,
			0xB9C89C9CADFE987FULL,
			0x63717B3C44C53366ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xFA0EFCC80B0B64CBULL,
			0x78E5A00480BEB528ULL,
			0x9BAE67653FE01083ULL,
			0x6A84294AAC24B48BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x84455FC740DC9C98ULL,
			0xEE5EBA7F68630532ULL,
			0xBBBD902D974419D6ULL,
			0x4FFF53EE0ABA9236ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x16769059EFCA8084ULL,
			0x721E22CD1BD8DA00ULL,
			0x9B3481F49055CB20ULL,
			0x4BA999C21F39723EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x0BE0C06D00D3604BULL,
			0x1FAE36907B5F1A70ULL,
			0x04492875B96D8533ULL,
			0x326D261C6E77E9A9ULL
		}
	};
	printf("Test Case 197\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 197 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -197;
	} else {
		printf("Test Case 197 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x1B2056C33E9A5668ULL,
			0x440A891A63A0597EULL,
			0x1B302F46337DF4ADULL,
			0x71A1A3886D4F7E91ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xACDD8F1AA55FBC6BULL,
			0x3366E8EDD674A8BEULL,
			0xB0E52E9EA723A2D1ULL,
			0x156BB62CA05B9D6AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x4C24A501A3889ED0ULL,
			0x3A2669253A420FE6ULL,
			0xD9978BD2B431ADE4ULL,
			0x47CD917FAD799E93ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xE91DD84F8C662576ULL,
			0xB0954C66BE53AD3AULL,
			0x372257A2F3F71467ULL,
			0x73B19BF0AD62F86DULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x4112B00C08E797D9ULL,
			0x513EE8298B512275ULL,
			0x0059CCE059D2CAF6ULL,
			0x3A1E6779BEE22DA5ULL
		}
	};
	printf("Test Case 198\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 198 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -198;
	} else {
		printf("Test Case 198 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x288B5CB69A9B68B0ULL,
			0x2108A66FFD096F46ULL,
			0x1C91D59D5F61B91FULL,
			0x5C673D30109CA50CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x6D8A10F47AFD9CEBULL,
			0x9FA6B9D2FA56D999ULL,
			0xFC586CD219D10B49ULL,
			0x229C9367BAF0D7C7ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC12944DFEB55F5A0ULL,
			0xEA806F682AE0C99EULL,
			0x30880A6C0763F8FDULL,
			0x7C7F62D1309CABB2ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x0933EE2EEF6ACEB0ULL,
			0x493310B6A74E5306ULL,
			0x4153AA67AAF26B8EULL,
			0x3E10291AD96BA3ABULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x410310770DB26CEEULL,
			0x5E35DACABC89A812ULL,
			0x6C6E12A7DBB62312ULL,
			0x03D9E2CB08A66FD2ULL
		}
	};
	printf("Test Case 199\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 199 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -199;
	} else {
		printf("Test Case 199 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x27D69E3C967979E8ULL,
			0x9A1AB219F2EC240CULL,
			0x39F76D0AB2C65989ULL,
			0x53C88BC13EECF194ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x39904DE6DA82A1BFULL,
			0xA693066685753C53ULL,
			0xB1EA8438AD314EEAULL,
			0x14D83D07E1BB42BFULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB919E1B495EE92A8ULL,
			0xC7AD7BB2AD5E7A9CULL,
			0xD8B7120A7E19CC0BULL,
			0x565DC4E674C14849ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x488A496C017EC141ULL,
			0x3CBACEBF85227777ULL,
			0x66480CA41E31443DULL,
			0x6A7623ABAD4A048DULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE3A44F83BABFFF37ULL,
			0x9D91DBEDB7CCECF7ULL,
			0x99FCA53E82D35A70ULL,
			0x0DA23E0CC249BE02ULL
		}
	};
	printf("Test Case 200\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 200 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -200;
	} else {
		printf("Test Case 200 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x67FEDF2CF42DA398ULL,
			0x36649E4CAB2A106FULL,
			0xAD313F73626477F7ULL,
			0x70A1F7BD0A96CC8BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x512EA78623E23294ULL,
			0xF48A88274014D5E3ULL,
			0x4D0A28DB9535E501ULL,
			0x5DFD5F51082F29C8ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x0CBDDF73D8C1BC28ULL,
			0xABAF626704C29304ULL,
			0xE6A8695184334A7FULL,
			0x575C116D1F6A402CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xC92CA583C808C501ULL,
			0x128807170B0D6751ULL,
			0x4AA639B0E534FCAFULL,
			0x492E5E89A5BDB515ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x4A8A1EB7F16B160AULL,
			0x6D6E60E69B6D5727ULL,
			0x50449418E24A2E29ULL,
			0x208F0E7C8A299CDBULL
		}
	};
	printf("Test Case 201\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 201 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -201;
	} else {
		printf("Test Case 201 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xABF334CC837F3BD0ULL,
			0x8B60A684F1182ED7ULL,
			0x2EAEC0A9A1B5384CULL,
			0x441533941BBD0C00ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xB21C6C4BF38E86D5ULL,
			0x85560C837086390AULL,
			0xF689798B9348E41CULL,
			0x06FABD56C1AC139CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xED7F82A3FD32A530ULL,
			0xD563372D1417C7C6ULL,
			0x4A2613EF70B5E5EEULL,
			0x52629E2485CF4A86ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x3D271FB89AB43623ULL,
			0x037C1EB9AD5D015DULL,
			0xEB9AE38C5170B833ULL,
			0x326990A4540C1D78ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x6D6808DB438601D5ULL,
			0x4CECCE8BA4A71BFAULL,
			0xE1AD8DEBD4103AF1ULL,
			0x1B46C49CB1AA3949ULL
		}
	};
	printf("Test Case 202\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 202 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -202;
	} else {
		printf("Test Case 202 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xDCAA617DA28A5DC8ULL,
			0xE3EE8FD23A206018ULL,
			0x3DF59DF9A3287EFEULL,
			0x447E3979A47AA7B8ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE63A398A01AC47D9ULL,
			0x8A5681D840D65AF7ULL,
			0x301DF827C9C37518ULL,
			0x04E8EFF7C50343C6ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x1698ED19A235DA90ULL,
			0x938DC39B4411BF06ULL,
			0x78A75C53E8936176ULL,
			0x74C7F53100547764ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xCD9B729D4A87A376ULL,
			0xEF5FC17A81644E1CULL,
			0xF6FBA381B5358544ULL,
			0x1DBA646B1363D842ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x24836D8A5B93D88DULL,
			0x34948034831E7640ULL,
			0x8F0F2CFA50AFACB2ULL,
			0x78A282BC0A747023ULL
		}
	};
	printf("Test Case 203\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 203 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -203;
	} else {
		printf("Test Case 203 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x53246F0B8DE87B08ULL,
			0xE1AA15D5277F436DULL,
			0xC9786099BB60D715ULL,
			0x54E75FFCA39841D6ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xFB6561F2D2CA1019ULL,
			0x870B35D2953FC78CULL,
			0x3E4BDC8D35D68484ULL,
			0x7F4EBE65BBA2D426ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xDB9DC973BA714228ULL,
			0x313A2E5F23E83564ULL,
			0xB9782635357533D7ULL,
			0x50A3E2784AA971C5ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x330301FE57016347ULL,
			0x1DA45C318AECCA07ULL,
			0x6DA70ADE116EDABEULL,
			0x22D1B27EFC88F531ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x2EF2DBE71D501E02ULL,
			0x8EE878D78C311A25ULL,
			0x77B1ECD615CE77A7ULL,
			0x5E7810E55919E7A7ULL
		}
	};
	printf("Test Case 204\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 204 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -204;
	} else {
		printf("Test Case 204 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xE6261E4B8B0D7EE0ULL,
			0x7FB927F8B7D08552ULL,
			0x1F014D925DD85001ULL,
			0x57742EB3395FB057ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x72E771280E1B5204ULL,
			0x3FC23A1A8EEC7883ULL,
			0xB127E021994576A6ULL,
			0x4296F756297792DEULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x8A4D00BCC1434A40ULL,
			0x0F69534A240EA950ULL,
			0xCBB7DAFECFBC72A4ULL,
			0x63B534F7E57EFCF1ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x67C5AEFFFDB37564ULL,
			0xF67DC41B5EB8EBB8ULL,
			0x7F81A7377DDFE276ULL,
			0x4ED77B419F8462F3ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x626E82A7BE43E89EULL,
			0x646FC6218C902E9BULL,
			0x3DF2230BA4E03FE0ULL,
			0x57BBB40DFC84892DULL
		}
	};
	printf("Test Case 205\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 205 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -205;
	} else {
		printf("Test Case 205 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xD405EF884CF4D520ULL,
			0x240A3CC871F4C980ULL,
			0x0739A2E8F94BD16EULL,
			0x7703A88A8C9505D8ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4BE5E1B7A9436812ULL,
			0x8AD4629CDE86F81EULL,
			0xE0D2C3264A761466ULL,
			0x55E548046007D111ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x57345317FCD05E58ULL,
			0xD2F687948102BBF1ULL,
			0xCE94ED4853A4A48CULL,
			0x697542C22EB1618DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x008819B107B11670ULL,
			0x1F70437094279A1AULL,
			0x6DE4A7EBF86DB216ULL,
			0x627E65EB7053CB36ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x4B680C34769A84BFULL,
			0xB08548B957322E9AULL,
			0xDC9A18B8F6F6DED8ULL,
			0x6ABC1814DE883DCBULL
		}
	};
	printf("Test Case 206\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 206 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -206;
	} else {
		printf("Test Case 206 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x01EF7E2E01C07820ULL,
			0x8B46ED799965002CULL,
			0xBE479903C1E1A2FEULL,
			0x7E9A42ED01B7FC23ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4E87EE91C187C082ULL,
			0x21685CF19E7777A9ULL,
			0x723E2E66FB239A08ULL,
			0x425095AA5DB2A35FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x0649CC4FE1AA29B8ULL,
			0x83B826625453629FULL,
			0x7C3F6D1481683113ULL,
			0x4ACB6CDD7B1B68E1ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x08223B1F62459751ULL,
			0xB925C19C44EEBF4DULL,
			0xCCC64AE1DA6C8678ULL,
			0x0271E9BAD8597C18ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x470AD878FA09444AULL,
			0xC97784E0095C2CD2ULL,
			0xE1ED0A119E15CA23ULL,
			0x7FAB6A3E5B7CE585ULL
		}
	};
	printf("Test Case 207\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 207 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -207;
	} else {
		printf("Test Case 207 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xF813DC2E360013A8ULL,
			0x2329A1783D1CD64EULL,
			0x028A17C83940399EULL,
			0x67EB2BA61AF15442ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x97DB0DD76DAEC2BBULL,
			0x20931898FFEBA9C1ULL,
			0x1E5EF98B8798F460ULL,
			0x41B1C2B5B7E4FC9DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xCC84BA8452AF2610ULL,
			0xB4B0E4FAF6F820FCULL,
			0x1F9AD4DEC8716184ULL,
			0x59A925D50340DDD8ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x0349D3A594B09CE9ULL,
			0x2CEC109042FD5EBFULL,
			0x6200211FDF0F1D49ULL,
			0x5AB0A7CF523AEA92ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x6D6491FEF14149DCULL,
			0xFDFC8CA48385C0BDULL,
			0x01B57EF7259C2FFCULL,
			0x722936F55ED0324AULL
		}
	};
	printf("Test Case 208\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 208 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -208;
	} else {
		printf("Test Case 208 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xCE766695831DE210ULL,
			0xA101172F40DFD014ULL,
			0x722AB935E8055EC1ULL,
			0x76F88F6A7886AA5EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4F1217494AED67BFULL,
			0x47E45281F5020C71ULL,
			0x940A2F42515E4324ULL,
			0x774C80EFB6E061E9ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xFA16D65009813A08ULL,
			0xC906951D897FA4B6ULL,
			0xD8148325181979D0ULL,
			0x43CFBA3AA3EF5D25ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x142D8D783A13D08FULL,
			0xCF699D707FF0545EULL,
			0x9D88223FC5796BD4ULL,
			0x0CE59ED3E9355051ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x54B6A4E0C8556923ULL,
			0xB6E4F1CEFB9A9D52ULL,
			0x8C86C1C4BE4D5D80ULL,
			0x5D9A914B3FD00FBDULL
		}
	};
	printf("Test Case 209\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 209 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -209;
	} else {
		printf("Test Case 209 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x748F251810FB8DF0ULL,
			0xDB4717AAFE9F311FULL,
			0xAF4B9A254AE0D865ULL,
			0x77970D0598823786ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x862BC7A65F081C4DULL,
			0x15E532C34A5889A8ULL,
			0x294BDD990662FBD2ULL,
			0x46205F3BF512A527ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xBD6339E62E39E720ULL,
			0x7B45F574947A3E02ULL,
			0x0DD3872EE59EBE34ULL,
			0x477921F614656BCEULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xDB3555EE4130B853ULL,
			0xB43937182241810CULL,
			0x27F724BFF44D115CULL,
			0x5EB34974B2FFD3F2ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x47B1790AA49DD158ULL,
			0xA65C487968E960CFULL,
			0x435D405AB518C807ULL,
			0x03FF7E2AD5F799F0ULL
		}
	};
	printf("Test Case 210\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 210 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -210;
	} else {
		printf("Test Case 210 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xD8D646BF80ACD740ULL,
			0xB010F500F80BA0A2ULL,
			0x81BAF5541BD0E140ULL,
			0x492698AE45D920A4ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE9BA83B82F53D2ACULL,
			0x8A4BB01AF0F2DA34ULL,
			0xE160593B8650FA8BULL,
			0x3E20703C1B3BADC1ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF3B4A3682ADB33D0ULL,
			0x2E061C8898430C76ULL,
			0x4722A33B9DC4D742ULL,
			0x44A4C28EA4E864B0ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xB75C544196BC92CBULL,
			0xE61D8C72A9D560DBULL,
			0x1D79397A2D25C562ULL,
			0x1F1FFC55804B0A31ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x03AC7A656871A4F0ULL,
			0xF8B7DC613AB5F075ULL,
			0x17F97D528398E8BDULL,
			0x2ACBB93E3761E321ULL
		}
	};
	printf("Test Case 211\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 211 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -211;
	} else {
		printf("Test Case 211 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xE2053D69F67377D0ULL,
			0xC3B7535B67FC47C4ULL,
			0x9356C9BC91EE202FULL,
			0x7248ABED0547747EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x2DA496D72C5C3D06ULL,
			0xC6AEAB180E194D39ULL,
			0x06B38123B5A4D6EFULL,
			0x1D83102458FBC17AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x772E121DEE1C32F0ULL,
			0x56233205D16F57ECULL,
			0x22DC9E93FF371B2EULL,
			0x64DE6195A3CF3A6FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xBF40663CE322FE46ULL,
			0x9A282B92228D66F9ULL,
			0x25010DCFD293480AULL,
			0x165577A40FE85EB9ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD78939280AC91ED0ULL,
			0x26C73108A7D6CFE2ULL,
			0x64E65F87371A5E1FULL,
			0x25D8E14984A22CFCULL
		}
	};
	printf("Test Case 212\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 212 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -212;
	} else {
		printf("Test Case 212 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x38D0AB6DE86A61C0ULL,
			0x5120AE76595AB1CCULL,
			0xB79D034F89225176ULL,
			0x594B54E2510A9CD3ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x848198458769A947ULL,
			0xB5EC858F3434BFE6ULL,
			0x9B01FD85B934929BULL,
			0x49534C225C6FEE1AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x052DD3DDA673F3C8ULL,
			0x6294C6AD256593EDULL,
			0xF547A74CD372FE55ULL,
			0x6D07E0A6E7952FC4ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x72376E43323029CDULL,
			0xF146A5B03C2FDE0EULL,
			0x78814F6FD8067BC0ULL,
			0x1A003BE15F3CA836ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xCF3D561B150BFE72ULL,
			0xE3A5661B60FD20C7ULL,
			0x4F236371D6FC242DULL,
			0x366CA1B92A16C12CULL
		}
	};
	printf("Test Case 213\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 213 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -213;
	} else {
		printf("Test Case 213 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xCD68500CABD31650ULL,
			0x5683CB5B698FDD3EULL,
			0xC8B798B9569540CCULL,
			0x6C7BA0718572098AULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x90E260FC38E025BBULL,
			0xA0AE3C6CE550CF1BULL,
			0x46580D88068B4AD3ULL,
			0x4516AAD7C2AAEE2DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x5E11A3C3A598D420ULL,
			0x7D289A5E3C6FD4AAULL,
			0xF95094E73CF0F7E9ULL,
			0x439156D6958F00C6ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD2D55A7798594E65ULL,
			0xA4D6FCB0DBAFBD8AULL,
			0xEA6519D2A72CAB50ULL,
			0x60F9E73EF488DD20ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA3FB3D5D6B707920ULL,
			0xD26F0ACDB59F168EULL,
			0x1B6E824A4BF4CE7EULL,
			0x53DA086FEF3D93E6ULL
		}
	};
	printf("Test Case 214\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 214 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -214;
	} else {
		printf("Test Case 214 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x2900C4A29E7AE820ULL,
			0xFD774DC502FD81D2ULL,
			0x66C3B501AD0D3830ULL,
			0x7F8B728FB208580EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7275570A9EAB7E83ULL,
			0x8AD5B0DE86688268ULL,
			0x82EF8937A3609850ULL,
			0x76CBE40618AF51E8ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xEC5E096D0342C508ULL,
			0xE402452BE493B50FULL,
			0x92FC63C5C96E2402ULL,
			0x6841B6CE971BDF03ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x5547AFB8FCA385BBULL,
			0x98D38EE54BCAC5B3ULL,
			0x8CDAEDEB548BBB3DULL,
			0x24A77CF3204DB281ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF485C75A1B5D493FULL,
			0x275533D74E33EED6ULL,
			0xF80DEE2EC2732E6AULL,
			0x6B96A39CE7706917ULL
		}
	};
	printf("Test Case 215\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 215 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -215;
	} else {
		printf("Test Case 215 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x95158B740A503658ULL,
			0xEBC332B4114A1E78ULL,
			0xEACFA31B3C05D912ULL,
			0x6DF01CC051C1B660ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x3F20A4128D834F81ULL,
			0x2A2D2C66E43ECFF0ULL,
			0xAC29526DD33EEA9DULL,
			0x2A3C97A317175BFCULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x4CED040AAE0CB680ULL,
			0x627174F61154EF65ULL,
			0x988A76A7BCE33920ULL,
			0x6595480F5FB94721ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x680C7D977B3B864BULL,
			0xFE7A52F2DA4749F7ULL,
			0x446BB2C1D4D4A948ULL,
			0x4EFAAB2F7BBE8278ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE49A83BDE1C474BBULL,
			0x71AA17037807E98CULL,
			0xEA2252A54E63A6E1ULL,
			0x72AC1E43333ABD40ULL
		}
	};
	printf("Test Case 216\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 216 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -216;
	} else {
		printf("Test Case 216 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x03273D6F406DFA78ULL,
			0xDEFB728D583F8B68ULL,
			0xB660CA667C9DFE2CULL,
			0x6EF7090378F20990ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x0CA652EE0819DF30ULL,
			0xBC9F2566A094D946ULL,
			0xBB3FB502D159F9D6ULL,
			0x736804F45A4A59FDULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC8B0BFF85A9AA798ULL,
			0x5A90207B65918A7AULL,
			0x59A87F77F9487567ULL,
			0x50DE2DE5BB342F13ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x9CE57E2BA4A56059ULL,
			0x36A07385780BE44EULL,
			0xF22F08C9E53E7009ULL,
			0x54EED291E814175BULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x5C1F28101806F6C3ULL,
			0xFF0F1D972537EE56ULL,
			0x2E85263DA0FA314EULL,
			0x489E91855E6181C0ULL
		}
	};
	printf("Test Case 217\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 217 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -217;
	} else {
		printf("Test Case 217 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xD14A47E80A5E4358ULL,
			0x61A725AF6B1E0680ULL,
			0x18C139E92BAA3B52ULL,
			0x4CA2A6669A43B02FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x3EECDFE98899F28AULL,
			0x82D777B0FAD20C31ULL,
			0x3AA694E262C3424DULL,
			0x5E3DCFCA1460A439ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x4D70BAB998E23BA8ULL,
			0xC6E0CC5A39AA07BCULL,
			0x76AEC036DB751DD0ULL,
			0x794DAB83507A3319ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x5A5E219DF9242DD6ULL,
			0xC29FA16003BFDE79ULL,
			0x04E1E7BE4BEC3213ULL,
			0x598ECF538EB35B58ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xEBE3A6583A1664ACULL,
			0x4E585003D5E70942ULL,
			0x555F2C4A98B6A97AULL,
			0x20F5CC315BC4B8F2ULL
		}
	};
	printf("Test Case 218\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 218 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -218;
	} else {
		printf("Test Case 218 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x78A235F049891AD0ULL,
			0xB4C7D00A118A3097ULL,
			0xAC20CD777E76E9B7ULL,
			0x53D42B18B1F0501CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x2C78374D950AA224ULL,
			0x09A231572FF76901ULL,
			0x44781E2CE6118177ULL,
			0x38302113E74B254AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xBB36DAFB4BEF1A48ULL,
			0x823413D25ED76CD3ULL,
			0x0794BF65DC8DA07DULL,
			0x6CA1396918F53B89ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x90E4818707CA4D9DULL,
			0xB93C20E48736F0C5ULL,
			0x2810652661125C53ULL,
			0x38F496F6217B6228ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC2DCD7937EAFF67CULL,
			0x1D15FA500C4B0129ULL,
			0x6110AD638F6AC534ULL,
			0x25FFC2A3DAC695BAULL
		}
	};
	printf("Test Case 219\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 219 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -219;
	} else {
		printf("Test Case 219 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x940541431B4B0238ULL,
			0x42C9F6A4E56B1C90ULL,
			0xAF9A1F9C37BC6BB3ULL,
			0x49B114A60644A3DFULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5A40AC4997BB64CAULL,
			0x3C988C5D3BDA2744ULL,
			0xB62D0F77DA816B1CULL,
			0x22B8480096484261ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x8FC4EB7886FE8B90ULL,
			0xBF088663AC70AFC3ULL,
			0x15E338FF2E70251BULL,
			0x5D1DAF1735428B09ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x522470A6C1C786A9ULL,
			0x2141618A7AF7BAF8ULL,
			0xD94ED36A5400BA13ULL,
			0x18B0D45661993FFEULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xDEFD6A5FD5A322E1ULL,
			0xFF70B45F9B2863DEULL,
			0x18278D2E227FDAE9ULL,
			0x55EE48103CA28C11ULL
		}
	};
	printf("Test Case 220\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 220 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -220;
	} else {
		printf("Test Case 220 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x104D5769B05716C8ULL,
			0xCD9E0E89640D9407ULL,
			0xAAA2B4AFF97B7A06ULL,
			0x6913E266786D84F3ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x0AEE1BFEBAD34B04ULL,
			0x3EDC4506D88FEE60ULL,
			0xB7810F3CCBC3254AULL,
			0x1B5D6BDCDF488DF8ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x241E806207863D88ULL,
			0x5D44DAF9A748D3D0ULL,
			0x7731BDAEEDABB9BBULL,
			0x5D05598AB9A556D0ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x13D42341ACDCA932ULL,
			0x2FE85D3122B4ABDDULL,
			0xF87BC828EB01944BULL,
			0x159C2CF4CED62E0CULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB7ADFABFD5CC9CBAULL,
			0xE3A6BDEE47FD5AD9ULL,
			0x21687BCA6F5ED8F0ULL,
			0x5FD388408B9B8B35ULL
		}
	};
	printf("Test Case 221\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 221 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -221;
	} else {
		printf("Test Case 221 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xC9643AA97365E488ULL,
			0xDCED3271CCF57355ULL,
			0x7E7D81920787789FULL,
			0x65F6773AADB0BDBEULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x0E6F5C7D0FB82CA7ULL,
			0x6A8FD4A4DE2B21D0ULL,
			0x03D5B283174C4B82ULL,
			0x3BED250EA35CE4EDULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x32DC2700CAB4DB98ULL,
			0x89D1229F53DF0CA2ULL,
			0x886F585283611B94ULL,
			0x636BE716403A58E7ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x7AC65B80AEBCDB0EULL,
			0xD8B05B40C0E07CC2ULL,
			0xD51A68086E869FF2ULL,
			0x4DE7533F16CF7F3EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF74923E7B6B08D40ULL,
			0xCBE8928A832BE0F2ULL,
			0xB9B3F9E6D3092A88ULL,
			0x680F2D71898F0681ULL
		}
	};
	printf("Test Case 222\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 222 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -222;
	} else {
		printf("Test Case 222 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x796D4C18A94ED3A0ULL,
			0x7CF6EACDBE47C1EEULL,
			0xFFFFF22F07C7EB5EULL,
			0x5ED3E73AA7461ACEULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5A6BF8499E165092ULL,
			0x9D7C8397B6B0548EULL,
			0xE392E9AE9B22439AULL,
			0x769FD16806932316ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x463461CEB1E7D378ULL,
			0xEA3F382560CC7D52ULL,
			0x67BC70169435D49FULL,
			0x59B97B1F47360D73ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x4EDBAF04CBDA399BULL,
			0xA86F0F9E7F74399EULL,
			0xBA8F665DA4E23E0EULL,
			0x1C92521F54C8D4A2ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD7AC151DDB2F25DEULL,
			0x97BB66904391215FULL,
			0xF9485CA1EFDB4319ULL,
			0x3652DF0D23407898ULL
		}
	};
	printf("Test Case 223\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 223 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -223;
	} else {
		printf("Test Case 223 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x1C743EDF312D11E0ULL,
			0xD8BCCF8DCF52067BULL,
			0xE1FD7E87CBE1F20BULL,
			0x4BC01AB7888935BBULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x9ED8DDE3679DE2CCULL,
			0x932196C86528BF59ULL,
			0x9F4E76EF0C77B33CULL,
			0x4DBD47B1E1CA500DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x12823A0253106C60ULL,
			0xE72DED6E5A3CE06EULL,
			0x710D0EE5578D230FULL,
			0x45F8235A7F2B1467ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xFFF8DDFC8A231439ULL,
			0x0A2927271E118785ULL,
			0xDC6B60DD6D10BDADULL,
			0x7130B2B4564ED2C0ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xDBA471DDD7516DC2ULL,
			0xF1C3C543C09605E4ULL,
			0xBB346962E9EFDA89ULL,
			0x705BF0FAF93896AAULL
		}
	};
	printf("Test Case 224\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 224 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -224;
	} else {
		printf("Test Case 224 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xEEBF314F2BF06F70ULL,
			0x3FFED398F91C1462ULL,
			0x4E2FC326A4230EA8ULL,
			0x4005A35D7468F08BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x91443B4081B7E2E6ULL,
			0x2E16F21908AD28B4ULL,
			0xE174E53D0DAA136FULL,
			0x485788A2A4F7DAF2ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xEA222B19ABFDE0D0ULL,
			0xF794F1C908911D96ULL,
			0xA54B4CCE86E1D01CULL,
			0x442E5F8B3E5D6F48ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x3EDEDEC69DC54DB0ULL,
			0x8EB9BB91873E181DULL,
			0x351C9C6D60D52805ULL,
			0x48105DBD09C15628ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB107EA385E339BB0ULL,
			0x12F77AD6474FA09AULL,
			0x0812AD7234331D53ULL,
			0x16E92BD9C8F6F8F8ULL
		}
	};
	printf("Test Case 225\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 225 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -225;
	} else {
		printf("Test Case 225 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xD077BB359A5CFAA0ULL,
			0x12FA3075E1A663EEULL,
			0x478EB76543AC7DF9ULL,
			0x4DF2E9B80EB262CAULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xAE0878C882985E86ULL,
			0x7A9D9758EC6078EBULL,
			0xE3D638BB920E5450ULL,
			0x425142CAA4433ECDULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9CDD19B4DD205210ULL,
			0xA466BD2342D354C6ULL,
			0x55FEBE954FB752F3ULL,
			0x403A3BDA09896CEDULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF989DDAEF99A35F2ULL,
			0x69F6563BFCD488ADULL,
			0x5D77FD227A6BC2EAULL,
			0x14893866CBBFFD6AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE990F4FE34E433D1ULL,
			0xBAEEDC40A659D397ULL,
			0xC6A674C656667ED5ULL,
			0x1AF68CABB9BED706ULL
		}
	};
	printf("Test Case 226\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 226 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -226;
	} else {
		printf("Test Case 226 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x4D35A750E04FB0B8ULL,
			0xA5B27E3EB01B556AULL,
			0x8490779F54D3FE43ULL,
			0x52F6DAA25CD90E4EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xF304BCE71DB21183ULL,
			0xE3DA604CFFFAB16FULL,
			0x0702433E9D1F0C7DULL,
			0x71C02F84F7C576A2ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x8FFF7CF28170CEA8ULL,
			0xE90BA64136BBAA3BULL,
			0xC325CEFC79CEC8E2ULL,
			0x40FB236E621A146CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xFE0D8E7E6C845655ULL,
			0xF2449A49C2359B2EULL,
			0x460B4904FE8B5215ULL,
			0x01D1E466885F4E32ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE5F1DB99F3AF0B1DULL,
			0xBC3FCFA46C1257C8ULL,
			0xF991F587E13F8DE6ULL,
			0x027FC7991036C2A1ULL
		}
	};
	printf("Test Case 227\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 227 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -227;
	} else {
		printf("Test Case 227 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x23933B10AB7D7DA8ULL,
			0x20F9308A90EA2198ULL,
			0xEA52ECDB6C9EE095ULL,
			0x68176095AB1BB4D4ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE5608ADABB1AEF94ULL,
			0x4D6D80EA287E920FULL,
			0x2714E1F3EBC15748ULL,
			0x54B304677AC5BB3BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x83494CE54F49EE50ULL,
			0x066FCFDFE9B52A10ULL,
			0x4262FAA97B06E894ULL,
			0x608907ABB4DEA7E3ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x739917D4C43BED61ULL,
			0xC19EAC977EDBCE4EULL,
			0x05C3BC0E726294FDULL,
			0x5D2C6F5BF8185639ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x0C86C1CFD57E65F4ULL,
			0x2EDF4399BD3B4B50ULL,
			0x65EB83DC725DA594ULL,
			0x2202A2AD61D8305CULL
		}
	};
	printf("Test Case 228\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 228 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -228;
	} else {
		printf("Test Case 228 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x35254D476DFEBE20ULL,
			0xA545441127F6A087ULL,
			0xDC2A2BC589699DF1ULL,
			0x504B1FDAB037AADBULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xEF338B3928681B04ULL,
			0x52A41DE351976CC8ULL,
			0x91BB0F6DA36428D8ULL,
			0x7B4A2597BC6626FDULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xFDD4FC70ACD67330ULL,
			0x5710E6B5DD0F8CA0ULL,
			0xFD473900EA5CB6CBULL,
			0x6A5F9762F97294BDULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA90164706112CDF3ULL,
			0x49300C25204A44EDULL,
			0x2C45E5C1C9E4A1E5ULL,
			0x2F6C4FFEEF7C9C1FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB9D1A41426FF993DULL,
			0x4DC89ADB3BDA2B17ULL,
			0xF70492181E59BD6AULL,
			0x21D56505FE7D6575ULL
		}
	};
	printf("Test Case 229\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 229 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -229;
	} else {
		printf("Test Case 229 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x0906162AA90339E8ULL,
			0xC8AA04E57D7AC194ULL,
			0x65EB9E28039A64C8ULL,
			0x777885F7BA89D3D5ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x23E5AED2175C4EBCULL,
			0x44A138D905526ABCULL,
			0x32512C46DF2B8045ULL,
			0x3646745920D59FA4ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xDD57FCDB97A9A290ULL,
			0x5A9CFAF0E42FD9E2ULL,
			0x429ADDA517F33535ULL,
			0x4DF954E918A8BFF0ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x9468368AD20349FBULL,
			0xC0A1FB747256A8B2ULL,
			0x10AB3A3D8E3FDDCEULL,
			0x67693FB5050CBF8FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x65A033385D796C88ULL,
			0xC41ABCB61C634C7BULL,
			0x36AE9FC1E9989825ULL,
			0x719200878386D039ULL
		}
	};
	printf("Test Case 230\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 230 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -230;
	} else {
		printf("Test Case 230 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x694A2B1AC1CF86E0ULL,
			0xE5F67C916DCC2FB8ULL,
			0x86B32F6432072D0EULL,
			0x704CC4975673FE74ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xF1CDD20DEC5D1F32ULL,
			0xC45531FA91ADB28EULL,
			0x9F937AA6E0F4F993ULL,
			0x6B7F8F697A28C805ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xA287F0C8A6F85D10ULL,
			0x659C0056E4AE7C39ULL,
			0xA7E980BC408F08FFULL,
			0x59FFBC17B26B4901ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1510C68A7F0A52E1ULL,
			0xA638CB79E1EB9A4EULL,
			0x83A887D64E04BA5BULL,
			0x08292492CA976E2BULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x2059437133131CB9ULL,
			0xCBFDF5D64FD160D1ULL,
			0xBA56B081D9C53CE1ULL,
			0x687C7261B7220D31ULL
		}
	};
	printf("Test Case 231\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 231 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -231;
	} else {
		printf("Test Case 231 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x3D5EC754B25EEE80ULL,
			0xA086907DF948574DULL,
			0x2FD123FFB67518C7ULL,
			0x491A4A5544DDC5A2ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x983D15B2FFE9AFE6ULL,
			0x0487A0F627CE8B4FULL,
			0x177CCFC98405CD2FULL,
			0x15C679C63D588337ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x01805283E0A00770ULL,
			0x0EE7ED3F71C60020ULL,
			0xA53A624B44E19995ULL,
			0x5170225F526CE3E2ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x0BE05FC795ADA67EULL,
			0xF07FAC83BF35B521ULL,
			0x9A4A7E0CDD04E829ULL,
			0x61E024F37284DA47ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x9742677EFF67E9F8ULL,
			0x79ADE078CD1699CFULL,
			0xF7301CEC49E6EF86ULL,
			0x3BBD107E6D834CD8ULL
		}
	};
	printf("Test Case 232\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 232 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -232;
	} else {
		printf("Test Case 232 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xB57BBECEC338DBF0ULL,
			0x7D8A5C6094EDE99FULL,
			0xEE002D30BB974A70ULL,
			0x60411FF2EAA2E5F5ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x3B3AD0C09468082DULL,
			0xF8B6F6B051D59659ULL,
			0x2669F813B055D71BULL,
			0x374BF52559030816ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xFEA0E92D0A07EDC8ULL,
			0xA2FE11482570E971ULL,
			0x12F10B0A98A53EBCULL,
			0x6B174CDB1F65F670ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xEA3987D4507F7405ULL,
			0x8B1850F3F198739BULL,
			0x6EFC63EB57D1C416ULL,
			0x73ECE1F1375D6BD1ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x875C13BA077B06FFULL,
			0x6B99B36B1D2937E9ULL,
			0xEC46EBC78817D681ULL,
			0x163884DDB53BFC8EULL
		}
	};
	printf("Test Case 233\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 233 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -233;
	} else {
		printf("Test Case 233 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xE581C0CC460C3B00ULL,
			0xF31411AFF5F2D220ULL,
			0x9CAB664B7137B814ULL,
			0x5EFAF162685DE105ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4B902FEECA1054A3ULL,
			0x12C39943BE193A17ULL,
			0xF5182BE18067D5F5ULL,
			0x15BD483D68578C28ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x7A64951A51796F30ULL,
			0xD0798AD552457BE1ULL,
			0x8801B787593D259BULL,
			0x79CEDD59A03D7CDCULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xB9C447F89D1E2480ULL,
			0xD6CC9CA7253A5818ULL,
			0x8855D6FB10C03AC5ULL,
			0x251DC1C3700E6692ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD607ADA8131CCD5AULL,
			0x9640B3D7C0C8976AULL,
			0x4220360F77F6950FULL,
			0x16A6FA0A7D8C7F4CULL
		}
	};
	printf("Test Case 234\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 234 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -234;
	} else {
		printf("Test Case 234 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xF60A103EA4AF7AC8ULL,
			0xCAC4D3D067A8E693ULL,
			0x84739C90B83DCFF3ULL,
			0x5F79EA844FEF66E2ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xFFA6EA1D9A5CA795ULL,
			0x7B776A5EBB74B724ULL,
			0xB9952964AFDDF243ULL,
			0x2DBA3E1C17238A3CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x52ECA3A5BE634978ULL,
			0x92BAB6823360AAE5ULL,
			0x7D9155B7365E884EULL,
			0x4344F1FE6D15A540ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xCB61397A8DF925C3ULL,
			0x2DD54640318640A6ULL,
			0xBA0DDCBCA50D404FULL,
			0x6D047F5A8F57D1F4ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xEAF002B6AB7036FAULL,
			0xB126480BE1EF2A71ULL,
			0xA6B513EB6BD0FEA1ULL,
			0x46C8DCF12D187B88ULL
		}
	};
	printf("Test Case 235\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 235 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -235;
	} else {
		printf("Test Case 235 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xD914167013994808ULL,
			0x66AD2D30F741BE31ULL,
			0x39C2EAF352D97CB1ULL,
			0x62EA2ED25B7DDA65ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xF0A95A9493DA4BBBULL,
			0x1AD87FECD5DB9CB6ULL,
			0x72DB4A9D4724A328ULL,
			0x60D774B700510FDBULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE94B6B9596AFE400ULL,
			0xA1D22BCFFA415823ULL,
			0xBF898EB23B50CA82ULL,
			0x4A4990B28DAAAFC9ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x19B44666BE46A9E7ULL,
			0x2942D0E1FBE32031ULL,
			0x62AA538A47B3A8ACULL,
			0x21B54D03746C4F53ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF7429226AB3F28E3ULL,
			0x1D5A3C2D087DB61AULL,
			0xFABC041D58E7AC80ULL,
			0x08BB49CC18A4E193ULL
		}
	};
	printf("Test Case 236\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 236 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -236;
	} else {
		printf("Test Case 236 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xE910E2AFA8288DC8ULL,
			0x3086156F79576CDCULL,
			0xBB0802DCC8871427ULL,
			0x60E14105F13C6E4FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x8F708E27F57B568DULL,
			0x042629D9275CAC17ULL,
			0x62288BA87E8A4A66ULL,
			0x2344148C7CEACEB1ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xBC3D946257CD8320ULL,
			0x4E70C1A2D7F65AECULL,
			0xADE610F76EAF2DBAULL,
			0x7679AA4D83C0D31CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x832F23F0F03E1680ULL,
			0x4F4C07B8596BAED2ULL,
			0x15EC8E82EA107D0BULL,
			0x737CCC7B9837AF7AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x61333F568C2BF8F1ULL,
			0xF4CF730AC437045DULL,
			0x2D33BC516563B63DULL,
			0x1124CB255568C9E6ULL
		}
	};
	printf("Test Case 237\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 237 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -237;
	} else {
		printf("Test Case 237 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xA9A39FD44FCB2108ULL,
			0x9BDEFDFB410E0364ULL,
			0x15F3DDCF5528C994ULL,
			0x56347F45DF8AB65DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x6516EFAD1A8084C1ULL,
			0xE1C8E968BE4C03B4ULL,
			0x1724285312A3EACCULL,
			0x28CF3CEBB86E205DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x451FFB84CF5CCA20ULL,
			0x079539D9AF3FAC25ULL,
			0x7B7FFEB401872C64ULL,
			0x6F617B86D266FA12ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x0CC27E72E5066284ULL,
			0x9226AE3BEB530FC6ULL,
			0xBC94345D2BF0CB62ULL,
			0x74FDB600CF7C5CD7ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x90AA5183F80329F3ULL,
			0x59EFD397C50D3A17ULL,
			0xFEE8478B06CE8DC8ULL,
			0x539BB86997DD5930ULL
		}
	};
	printf("Test Case 238\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 238 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -238;
	} else {
		printf("Test Case 238 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x06320BBA76F1C1F0ULL,
			0x2690CFFA5F386A65ULL,
			0xD39E9D5C9381E27BULL,
			0x7787F021D1FB0E09ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xEB9C9124DE7C3A84ULL,
			0x26B563EF831169D5ULL,
			0x359C7F897C400AEBULL,
			0x4C2958A44247C313ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x20A848D7BDE564A8ULL,
			0xF1E85ED27EDD1D87ULL,
			0xD9FDFF31B33F53C4ULL,
			0x542ECA6F5F9E5733ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x9B943255D189FF42ULL,
			0x95BF964F3C974671ULL,
			0xA0BE923214CFE582ULL,
			0x0511C56D0417D717ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x981669F632C8F667ULL,
			0x8805C909FBB4FEBAULL,
			0x9ED832B2A32D4B90ULL,
			0x2165CBC736C70D85ULL
		}
	};
	printf("Test Case 239\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 239 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -239;
	} else {
		printf("Test Case 239 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x0AF4A339B1F7EB00ULL,
			0x0C35B10E8C86B442ULL,
			0x0981E2397F2DE275ULL,
			0x7DAAB3F57F224EC0ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x0325CAA067C32F87ULL,
			0x150D323888D6F528ULL,
			0x6ECE6D901F29710FULL,
			0x63CA7A0E9D5FE89DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE0E9C80FA078A0F8ULL,
			0x6EFFB7985B864963ULL,
			0x378B17EB26F50383ULL,
			0x7F8BA27A81B48A8AULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x87AF94AE4EE098E9ULL,
			0x92A9B9E6802937E1ULL,
			0x31B44E188B60A9B8ULL,
			0x5C9AFE3BA29D9E2DULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x017401C2A01BBBF3ULL,
			0x04C9076C1A57545CULL,
			0x8B912D37C9C765B3ULL,
			0x51460CD7CFB6F445ULL
		}
	};
	printf("Test Case 240\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 240 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -240;
	} else {
		printf("Test Case 240 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x63217B4F93890C10ULL,
			0x0B12FF736038B1BDULL,
			0x1E31371ED20F70D6ULL,
			0x64BD92A7F294E6FFULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE23E285C66DC136DULL,
			0xC7ADBBDD3B22D216ULL,
			0x4874B5057B68AC3AULL,
			0x2B29CA9AC85041B8ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xDF02DF1969273840ULL,
			0x21EF9FE320DA6A53ULL,
			0x42E35F9741251677ULL,
			0x5B1AA3E1B2321D98ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x67B88E08DC635A6BULL,
			0x6EECE028F2013E8EULL,
			0x3B8762F867ADAC89ULL,
			0x113A56155FF91B55ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x24A7A98FE26734F1ULL,
			0x973C163CB588A1ACULL,
			0x06017A07E1BF9671ULL,
			0x0547A598C8FB7CDFULL
		}
	};
	printf("Test Case 241\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 241 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -241;
	} else {
		printf("Test Case 241 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x702C03A9CD2A06D8ULL,
			0x2EFC7AD18BBC226BULL,
			0xF993805CFE78E428ULL,
			0x5B7EC4EB340D3004ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x267598382358FDDAULL,
			0x7F1BF4A9D004089EULL,
			0x91459813015F517BULL,
			0x3112B9A1F4CFD461ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xFAE6A26315DE7FE8ULL,
			0x7C41CEF3D7EDD0D7ULL,
			0x0E93542167C6C87BULL,
			0x4A2A306D92BE16EBULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x74B3D1420FB1CE4CULL,
			0xF749E21D74D9DF3BULL,
			0xA674EB0C52D0B764ULL,
			0x0722E86D4F9163B1ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x942FB8DA4D2D8371ULL,
			0xCFF5458C60BD1124ULL,
			0x110F5A36B1904016ULL,
			0x63616E13A96321A2ULL
		}
	};
	printf("Test Case 242\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 242 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -242;
	} else {
		printf("Test Case 242 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x0F10D5808D928430ULL,
			0x465D996B902495D6ULL,
			0x77B319473377A139ULL,
			0x73E1DD40F585EC03ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xEC61A83D26CB0ED3ULL,
			0xD3D8E7F620B14727ULL,
			0x4272A564B9AA622CULL,
			0x195E137FD8394981ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB12304985BEB90F8ULL,
			0xC381026E7AD5E57CULL,
			0x778DBB3E47A53B50ULL,
			0x79D8347A4DFD0726ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1BE21CF649E75B75ULL,
			0xFA302AB06D05B1F2ULL,
			0x7760268AE4D791BEULL,
			0x28AA61050ACDE9DBULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x3D3C61BB748B2A6DULL,
			0xC950B5414DF82B96ULL,
			0x56435E2558125CC7ULL,
			0x2F103386AE2295E8ULL
		}
	};
	printf("Test Case 243\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 243 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -243;
	} else {
		printf("Test Case 243 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x535616AEC13B8030ULL,
			0xE9AA77B8E05BE921ULL,
			0x7D771E976347685AULL,
			0x6EECD71ED253466CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x702372A9117501D0ULL,
			0x89AEB6977DF13DBEULL,
			0xC411768B719E7922ULL,
			0x25FCC8F2A81B0BEDULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xD3ED782C3C9430A0ULL,
			0xF4A03F7A66E02DD9ULL,
			0x6251F32AA26233DFULL,
			0x4D6BB055DE9F9C34ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF32290994E72972FULL,
			0x4AB982A79A90FDBAULL,
			0x41B27685E50C17BBULL,
			0x5FD1C48B14E17E48ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA94384326D6387F1ULL,
			0x8AB1C39C581F26DCULL,
			0xFE122FC81262656CULL,
			0x66FE156BDC2C052BULL
		}
	};
	printf("Test Case 244\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 244 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -244;
	} else {
		printf("Test Case 244 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xA4D8721BD115C108ULL,
			0x57DD19FE949BDD9DULL,
			0x3FABB51F06BFA8F4ULL,
			0x55A0B99B1B97C12CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xB817297BC1F44B64ULL,
			0xB0B1654108A95523ULL,
			0x8E71CC7EA5AFF157ULL,
			0x1C6A0CF96C65E53EULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x1FE338C11DD2CB18ULL,
			0x308CCCB52187F131ULL,
			0x68F4C27FF2414786ULL,
			0x4539213BAA598228ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x77F8BAC4DAFDFD66ULL,
			0x559F9DD52956F4DCULL,
			0x88D4F68AB69635A5ULL,
			0x766D930CEFE0A983ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7396B310D3F99EE3ULL,
			0x4071414737D26C13ULL,
			0x8917C716104AEFB8ULL,
			0x3E9A8FCD4B279A6CULL
		}
	};
	printf("Test Case 245\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 245 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -245;
	} else {
		printf("Test Case 245 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xABC4E110DB06C0A0ULL,
			0x54F73FECD14164A5ULL,
			0xD4FF66CEAFA91C20ULL,
			0x784C67602F01FDF9ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x121253C5D93D99AAULL,
			0x1BF579B197E58BA1ULL,
			0x47CD2971422601C7ULL,
			0x051865E74D8D9050ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xEF93C13D90EABF98ULL,
			0xD90471FBA168B746ULL,
			0xAC1570CE1FCC1D94ULL,
			0x5BB29896F5D6884DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x5A4E424383067DB1ULL,
			0x5E9532A96BA5926CULL,
			0xD3030DD550A28355ULL,
			0x4B546917DD29509BULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x98A4721FF46AEF70ULL,
			0xBE792263DF85DE8AULL,
			0x0F2D674B9E70AFC9ULL,
			0x3AECB054EB16AAB4ULL
		}
	};
	printf("Test Case 246\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 246 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -246;
	} else {
		printf("Test Case 246 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x79C8E5CF46CBA320ULL,
			0xF8E9BF633BB2B0B6ULL,
			0xC2F868E55FF6D758ULL,
			0x4E6CD212236512BCULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x59576BBD46FFE60FULL,
			0xF2D8B26DAF6599F5ULL,
			0x1E5643003304618AULL,
			0x275C1043E52E0568ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xEC94BA59C4DEFF58ULL,
			0x5B133441D55633DCULL,
			0x46E2DF1184D9D22FULL,
			0x6EF8338B374FE03BULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x9B3605F505497C94ULL,
			0x0AC96968193F4F0BULL,
			0x12D37F5BDB0A9C0EULL,
			0x1144085DF70D0EE1ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x4B830917C0A8DD6CULL,
			0x0E85DD648B3C0363ULL,
			0x6EAB343C316EA504ULL,
			0x52BC22A52584BE0AULL
		}
	};
	printf("Test Case 247\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 247 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -247;
	} else {
		printf("Test Case 247 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xFAEA07C269CDAA08ULL,
			0x09B97FC35BC4B698ULL,
			0xB1DB719CE359DE65ULL,
			0x4F6BF7FCCE7D729FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x6B568F8B96C73A1BULL,
			0x73CFF2F9A8A8EDE2ULL,
			0x8A3F8E42BFF9F703ULL,
			0x3CA19182455BA85FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9EF5D2D29DA8D268ULL,
			0x7E1AAE8258D4C647ULL,
			0x715FBC48BB46B7C2ULL,
			0x414C6328F61C4668ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x2734F58688D15B7BULL,
			0x939D79F838B11F83ULL,
			0xF687F55D5AC6C1C6ULL,
			0x10C761BA831548A7ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xFF1DEA0594A8F3B2ULL,
			0xA4033A0BBD1D6CA3ULL,
			0x696C63B8BFA60EFCULL,
			0x62D1F7C1C9A0905CULL
		}
	};
	printf("Test Case 248\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 248 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -248;
	} else {
		printf("Test Case 248 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x48C4EDBE3B902BB8ULL,
			0x9BC8053860B1277BULL,
			0xE18F7300FFFD4231ULL,
			0x636A26F11E2893D2ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xAF61BD02FDB33BA5ULL,
			0xDA04276F2E39ACFAULL,
			0x746139ABAB531A01ULL,
			0x5B7668B4D3C88CB0ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x775520425D370C18ULL,
			0x5BCF9236DCC046F8ULL,
			0x2B2D0E5DF57E89A5ULL,
			0x7EF67D5AD891F155ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x257B1E116083CA6CULL,
			0x551A6B67816AB91BULL,
			0x3DA8C2DD24E027E3ULL,
			0x7D8BA8B60FA9390BULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x64D92AD53A159826ULL,
			0x2A9CB8B642C9416FULL,
			0x27685FADAAED008AULL,
			0x1BACA2CB6DE7B78DULL
		}
	};
	printf("Test Case 249\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 249 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -249;
	} else {
		printf("Test Case 249 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x068258F58F1A71D0ULL,
			0xA6747BAAD6E81C5EULL,
			0xF3D9537EAC3D2D27ULL,
			0x703EA0B8806A957BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x87927BBA234BE377ULL,
			0xB8303E94691C9C96ULL,
			0x1CBB8D0684CE2931ULL,
			0x2222406AF7E04989ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x049F412E4C8C2C68ULL,
			0x9721B0BE6DE6939CULL,
			0xE4C0CC8FD81E2279ULL,
			0x727589E462D93B1EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x18572A2F3DC4C2C9ULL,
			0x6E7117EDB93F78EAULL,
			0x545D00769B0D39A5ULL,
			0x75EC168E25638042ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD766060A0CEE399AULL,
			0x327938601CEAB0C4ULL,
			0x1D6B2DBBCFFD432BULL,
			0x2AC0FEB805E94C02ULL
		}
	};
	printf("Test Case 250\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 250 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -250;
	} else {
		printf("Test Case 250 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x45854B564A249C60ULL,
			0xC7CD545538E89508ULL,
			0xD3359513BD8E2C35ULL,
			0x6F18903192DF0386ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xCBEC89B48F472CE8ULL,
			0xA32E1DA098CCA903ULL,
			0x9BC10542DDED7F4DULL,
			0x4275B15D97873948ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x58E16D6AFC606168ULL,
			0xBFBE338A7259872DULL,
			0x04A4C276C4E51D0FULL,
			0x602C67B63A6A153CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x8353AD9F0853F6A2ULL,
			0x251F112024372678ULL,
			0x11E008DA8AF6014BULL,
			0x2BF67CFC3FB8EC57ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC4C469BE7902C173ULL,
			0xCDBC9110F421113FULL,
			0x598C0C86343E5EE7ULL,
			0x58EDBC7159E2DAB3ULL
		}
	};
	printf("Test Case 251\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 251 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -251;
	} else {
		printf("Test Case 251 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x82B9E40F46BA0CC8ULL,
			0x34874BC4AE112981ULL,
			0x069A87C0AB5F203FULL,
			0x7529CCB743DF4EA3ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xFA5F9DF8BC044200ULL,
			0x7C8B966D9C18097AULL,
			0x158FD25F9FF10304ULL,
			0x763D545B495DF025ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF5B889C26EBFDA98ULL,
			0xB27FB069CED3F331ULL,
			0x2772F82FD09CE3E3ULL,
			0x630B575FAF526292ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x5D1F0B35A12A7E1DULL,
			0x3FCCBF3CE22A039EULL,
			0x15395B1B52B87398ULL,
			0x6C284EFA2BAF02C1ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x62F36C23F0AAD767ULL,
			0xBD5206F5983C9A21ULL,
			0x7C4B6ADE256EAD9BULL,
			0x5CDFEBD12B96908BULL
		}
	};
	printf("Test Case 252\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 252 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -252;
	} else {
		printf("Test Case 252 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xE49BB40A030151C8ULL,
			0x9F2CFC3D74614BB2ULL,
			0xE4E1B03138F6F441ULL,
			0x742EE4F3BAC191D0ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4D29C7445EA71772ULL,
			0x1C545634AE02BBB4ULL,
			0xE8F00595DC3F56DFULL,
			0x0B51AA6B570CFAA9ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x3F52943B8470B608ULL,
			0x368A2F5C6D3EE105ULL,
			0xC9B3EBCE514E0D37ULL,
			0x701B9D98C874EF2CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x2386BA6691C6AD27ULL,
			0xDFDAC4A2C36F3B87ULL,
			0x2E4BC339C98F2744ULL,
			0x6401A813070CA497ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x87B53F62AE6DC69DULL,
			0x7741BFCC22C40979ULL,
			0x28BD3CA335C53A0DULL,
			0x305CBDF22AA93F55ULL
		}
	};
	printf("Test Case 253\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 253 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -253;
	} else {
		printf("Test Case 253 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x22D1F19606379730ULL,
			0x70BAFB6276316FA4ULL,
			0xE23C61E3F41B469AULL,
			0x7B8E21BA697B7FABULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xCDCE9E8D3B871AEDULL,
			0x5BB96AC3B0298D1EULL,
			0x736E0A36B2A85350ULL,
			0x4D1FE16EB2918137ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x4B99AD3B15F535D0ULL,
			0x9E5B901B1769BF90ULL,
			0x6F077D2839545414ULL,
			0x64AC08F2C417A384ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xB4AC056A75B0A0DBULL,
			0x4881C8C9E71F1A14ULL,
			0x2C3A12B24CA9A5EBULL,
			0x28181D05A746D2DCULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC61097A51FCF9B09ULL,
			0xEEEFF4997B403F3FULL,
			0x5A1C47B2E83E21E0ULL,
			0x0AD058EAF09C4E97ULL
		}
	};
	printf("Test Case 254\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 254 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -254;
	} else {
		printf("Test Case 254 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x1BDBA984B537CC18ULL,
			0xE6700BEE13E91C40ULL,
			0xAC6382EACB4B20C8ULL,
			0x5FF5A9E27ADF85DEULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xC45E49762488532AULL,
			0x43B235669D9CFA6FULL,
			0x71591C9117F3FCE0ULL,
			0x650C4D15A9F3DFD4ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xD600D642CD53E418ULL,
			0x9C4D5F5A57D720C8ULL,
			0x0677DA5FD7FEF424ULL,
			0x5BEF197F277D7E72ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x56BDA23E7088D252ULL,
			0xC2306131E0AE82E5ULL,
			0x1499E9D2B276687BULL,
			0x00384C0F50B6BEFEULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xDB8DF86E5E93A300ULL,
			0xFA129472545231A6ULL,
			0x4BC7CD9B483ABC50ULL,
			0x1CE62C09BE8A6FABULL
		}
	};
	printf("Test Case 255\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 255 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -255;
	} else {
		printf("Test Case 255 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x74D69B527B83A698ULL,
			0x379B7D7DD2A34FD6ULL,
			0x527476CF9E513649ULL,
			0x44570AB5B57AE0EFULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xF8E22F1115A5EFBCULL,
			0xC507A1C09197971DULL,
			0x22315F48A3E0A973ULL,
			0x365937CD7CDA4E2BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE7A088E0E6DCB460ULL,
			0x70EAFB30675BE54DULL,
			0x0A9D47AD6E3DD69BULL,
			0x5C0196EF44476DD2ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x0EAE95E2EA71BC3EULL,
			0xD36CD899738D96D8ULL,
			0xD5EE8D554D517FEEULL,
			0x4FF55F49C2C44AA5ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB59F6DE6591084F0ULL,
			0x9A06B7CF32CC0F28ULL,
			0x6587880B734CF92EULL,
			0x6130086FD345F820ULL
		}
	};
	printf("Test Case 256\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 256 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -256;
	} else {
		printf("Test Case 256 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xABEA275DDFD23528ULL,
			0x5B6C101E8C0AFE86ULL,
			0x205FAA1EE35E253FULL,
			0x5EE0E055A5EDA2A0ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x177DD37CD24BE067ULL,
			0x9A1C014C41332F43ULL,
			0x6F329EF90AA9E43BULL,
			0x20DC8656D1B95E14ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xD4AF9522F6003498ULL,
			0xB1DD8BFD1B4C2453ULL,
			0xEC39B284137CD2C8ULL,
			0x7456BEF6763399EAULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xC4E9D79641BFB0D9ULL,
			0xEB3103955A4B290CULL,
			0x39C5B1218E737E99ULL,
			0x1E5866DDCE0D02D4ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x41AF667B05C6B495ULL,
			0x2F5AED0784222A81ULL,
			0x252703A5E2ED1A77ULL,
			0x1C8F11783AE3B4BAULL
		}
	};
	printf("Test Case 257\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 257 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -257;
	} else {
		printf("Test Case 257 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xD59D2604BD6AE868ULL,
			0xC86724BC32C241A8ULL,
			0x39B1F96BAAB4B360ULL,
			0x7ED122AF6163133CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x2F22A12278AE12C1ULL,
			0x5DFB4E77D0E8B248ULL,
			0x054608C5A7D20EF2ULL,
			0x1C7994EED2C58B1FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x19E390B33B197890ULL,
			0x3CBFAE85F53458CEULL,
			0xFA322C7ECA3D0118ULL,
			0x58F872045E7F69E4ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x41A54F209378065AULL,
			0x24343DC6036C00E5ULL,
			0xC6C0F9898F12AD95ULL,
			0x6D3CAB7B47AF3DE5ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xBFF53255078CB616ULL,
			0xAA96AC77CA86B8EBULL,
			0x2D42DE1E83AFC86AULL,
			0x1EA416871B9C3C37ULL
		}
	};
	printf("Test Case 258\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 258 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -258;
	} else {
		printf("Test Case 258 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x8FD26A02FD037658ULL,
			0x1AD6D5D5DEED9776ULL,
			0x3D4F620676D94026ULL,
			0x66ED28FD72EA7E1FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x04D60D899DFE37D1ULL,
			0x116884B3E7FAB5E1ULL,
			0xE905EE59E4C5A964ULL,
			0x1BF9E5B349C5DFC1ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF87D7B30ED53E5A0ULL,
			0x8381FA0FC9B96744ULL,
			0x249A871AFEF9DF84ULL,
			0x55420361EAB3F75BULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x7E88CA7D08F291F3ULL,
			0x5ED3325CA1F24C2BULL,
			0xB665E4A00E83AAE8ULL,
			0x163F93942C409C3FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF0A99D1958EF2C26ULL,
			0x1D6F362D06CD4AF9ULL,
			0xEC294079DAC2542DULL,
			0x72A2BFDB0B25F2D9ULL
		}
	};
	printf("Test Case 259\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 259 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -259;
	} else {
		printf("Test Case 259 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x04EBFB4FB619D5B0ULL,
			0x50B8812ED40D6201ULL,
			0x5CF267F4BD668A7BULL,
			0x69F12AC0651B1A4FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xEC1642EA8F28833AULL,
			0x6C5634025823EC18ULL,
			0x0E70AEAC59E1D54CULL,
			0x1C93734D0DE7C89CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB1D7A7CDAE4B4590ULL,
			0x3EBB41231F7BB530ULL,
			0x081BF84F566B27F2ULL,
			0x6600CB4EAE6316CEULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x82007F789C7D4C52ULL,
			0x1D21A51A41D7FF4FULL,
			0x84325BFBD5D90239ULL,
			0x5EDFB5E4752C0243ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC75546114716D5B9ULL,
			0x740CB20200BBE865ULL,
			0xE419D60F32E58668ULL,
			0x534B726E34A26DA0ULL
		}
	};
	printf("Test Case 260\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 260 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -260;
	} else {
		printf("Test Case 260 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x632BC08F7A06A878ULL,
			0x4C4095F6F1139552ULL,
			0x0BA916106D5ADBE4ULL,
			0x4682F9DDDE467D62ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xBFB34E8724993F66ULL,
			0xCFB4E0EF19C8D9AAULL,
			0x5158A611F36275D1ULL,
			0x25A0E57EBA4E680FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2E8A7DE4B1F12C38ULL,
			0xF7653F143F7BB3ABULL,
			0x8366CF2D93B6FDBCULL,
			0x60A9EA0886BA5084ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x94FDE2A7FE26187FULL,
			0xDC1E1E99C1D278E3ULL,
			0x30C23D2E07A5E553ULL,
			0x20AACA8E40124F30ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x3AA1985082F990F1ULL,
			0x251EFAF6E05E3D49ULL,
			0x1AE7521A4D9B4402ULL,
			0x180F0B3832B5B8A6ULL
		}
	};
	printf("Test Case 261\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 261 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -261;
	} else {
		printf("Test Case 261 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xD314C69B371C5A88ULL,
			0xF5F57191E70F270EULL,
			0xF4B2E10A870C5F1AULL,
			0x6FD7A74E9F198BACULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4220E373EAFD5D51ULL,
			0xEA2AD171FF5ACC07ULL,
			0x1F41914C3D57EB69ULL,
			0x1481570571291155ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x5B131D34BB16AE80ULL,
			0x0069BC189013ACBEULL,
			0x2CB8F883F08A74B8ULL,
			0x6E2C80C6E1C0438CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x4D7A8ED058503F34ULL,
			0xB2B44151398E2C6DULL,
			0x69A83263BFD7EBC3ULL,
			0x12AB645EAC14B2AAULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x535813ADA847310FULL,
			0xEBCC4A55E2646353ULL,
			0x48B9036EF5AC9C61ULL,
			0x3A9658CAEF85AE1EULL
		}
	};
	printf("Test Case 262\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 262 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -262;
	} else {
		printf("Test Case 262 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x02CBFD03E78020D0ULL,
			0x7CA31382C75076FEULL,
			0x93D9D42DE2165876ULL,
			0x659994721DE4C419ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x709D9296900140BDULL,
			0x01910B13B8B8996BULL,
			0xA99ED8A7E59BDA9DULL,
			0x273D52A7073261B0ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x3026FB61753461F8ULL,
			0x5E5F7BFBD3E5E9C0ULL,
			0xED69534D66355180ULL,
			0x67690A6C59AD57F5ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x642EF117BCFA1E57ULL,
			0xE98EBFC03D040DB2ULL,
			0x02041E62B4E6B430ULL,
			0x21B8C4C0E3C0DA3AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x2F9DF785518AEA08ULL,
			0xC1CF13EE67B8659BULL,
			0x6B99AFADF58E8E82ULL,
			0x5F950F12FF05F15FULL
		}
	};
	printf("Test Case 263\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 263 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -263;
	} else {
		printf("Test Case 263 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x6804E12204C8B8D0ULL,
			0x592C6AC45575C500ULL,
			0x11CA1F1EE30C8080ULL,
			0x78B8D4916E53D50DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x3D64A686022D126DULL,
			0x59AD14C4ACA6A595ULL,
			0x09C290277BC3F5AAULL,
			0x57A3357067A7A72EULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x73544AEDB2640F98ULL,
			0x73F5B26766580F7EULL,
			0x982ADE09AF97BC22ULL,
			0x510763259594BF53ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xC46A493811809D21ULL,
			0xCDBE5106DD4E0380ULL,
			0x97954D4112E5FA24ULL,
			0x1FB7E5EE188630A1ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x654D1062FD04AC63ULL,
			0xD43DD6AC71EC299EULL,
			0x726B4EAA2C527703ULL,
			0x66218EE09A4B0C53ULL
		}
	};
	printf("Test Case 264\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 264 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -264;
	} else {
		printf("Test Case 264 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x8A66B87BBB5954F8ULL,
			0xED3B12E304775B88ULL,
			0x8968D05BC704CC7CULL,
			0x60435C690028EC87ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE5524CE5909B00B1ULL,
			0xD3322DB2077BB155ULL,
			0x2AA5001189AC8B71ULL,
			0x53F938A706C4E519ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC5FD7DBE55312B10ULL,
			0x296EB12115583D75ULL,
			0x8679D9EB2D5B8838ULL,
			0x4B8E164BAA14560AULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x482D654701855174ULL,
			0xB333385BB8028F63ULL,
			0x69B83DA068B75D25ULL,
			0x01D9FFB230226F7FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x517B28A606B5086CULL,
			0x64632BF0BAD5A3FAULL,
			0xFC08268555801A5EULL,
			0x4CFAE9AE6EE759F1ULL
		}
	};
	printf("Test Case 265\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 265 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -265;
	} else {
		printf("Test Case 265 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xEE6310C1909CCD78ULL,
			0xF7AB7DBA8A21121CULL,
			0xF873ECA50785E2DDULL,
			0x407EB4C6828CF9C0ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x1C549F2A80E963F1ULL,
			0xF9012BF2682ADFB7ULL,
			0x579B324C81B50B0FULL,
			0x1D46007AB33055D8ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x200FC0DDDA79AB70ULL,
			0xBB5355A4005E3F2BULL,
			0x232CF6BB4A057477ULL,
			0x56A0D19FDE19B391ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x305A3698FD9C8000ULL,
			0x4460A11AC9939D00ULL,
			0x0C30E6686B3C6226ULL,
			0x79DEFAAEF926B539ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x810510F51A476C25ULL,
			0xA488FF50F8676781ULL,
			0xC54831CF6CC9D73CULL,
			0x067AB0E9851A272BULL
		}
	};
	printf("Test Case 266\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 266 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -266;
	} else {
		printf("Test Case 266 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xC7DF12E07E91DFE0ULL,
			0x9980663040DF3BB9ULL,
			0x58955E4FDA53E15FULL,
			0x66085DFF0D8959DCULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x691F55B0EA0EE347ULL,
			0x704E6C93B8EC10ACULL,
			0x91EC7ED1A8B1BA38ULL,
			0x68AE152646311143ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xBE99F0F1D49DF2B8ULL,
			0x56C91980FDAA00B0ULL,
			0x81517F3DED5A2CA8ULL,
			0x6DC2F170047B292DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x75DCF8D6EB2EC8F5ULL,
			0xD251762A20EB8947ULL,
			0xE6889352BDB92405ULL,
			0x36D27A03575F4231ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x49E8B7AB7C27512EULL,
			0x0E76F90D4D379389ULL,
			0x354EDA18381E855BULL,
			0x535AE8FCEDCA02FCULL
		}
	};
	printf("Test Case 267\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 267 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -267;
	} else {
		printf("Test Case 267 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xAA69FF96077879F8ULL,
			0xA8C12B9A06AB4694ULL,
			0x0B6853506EB82862ULL,
			0x64AA5E372EBAC44FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5E44901481BF6B51ULL,
			0x8B5F2B3AA6023D32ULL,
			0x8A540BA4F3E7808BULL,
			0x489A92F248E74A52ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x4BA927677DF746D0ULL,
			0xB9FC4DFCDCB5F8C5ULL,
			0xE852CD6E2AA6021CULL,
			0x5875BDC8E3FB1CC9ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x58B9DE863BA928D7ULL,
			0xB2FA9919B4211506ULL,
			0x84D058BE7EBBBCAFULL,
			0x224A47AE655830BCULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7AB7D23E07FD6846ULL,
			0x9EF28B2D340C0217ULL,
			0x748777C5F1DC4692ULL,
			0x3B38162664F75414ULL
		}
	};
	printf("Test Case 268\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 268 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -268;
	} else {
		printf("Test Case 268 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x18F71E10DDCBB620ULL,
			0xAD2BF18C55183E38ULL,
			0xFFCAA433EB55D7C7ULL,
			0x6BF286D9F969AD35ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xACA202E13755AC69ULL,
			0xD97B06506478586EULL,
			0x8FD6A614934376D9ULL,
			0x6A99FE21AD55D6F5ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x8858514B4994EA98ULL,
			0x3B9584C222D4D541ULL,
			0x2DD5162504AFE4A8ULL,
			0x4243FA893453461FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x56942657B9C35EBAULL,
			0xBC18F1E6CBFB74F2ULL,
			0xB639F741B81C7823ULL,
			0x06DCC9F3D3297633ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x63120049AFA05AF1ULL,
			0x587CC2E97CA1C8FEULL,
			0x67B1CC6997984D05ULL,
			0x5BA35D0E4046FDC7ULL
		}
	};
	printf("Test Case 269\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 269 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -269;
	} else {
		printf("Test Case 269 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x6B6CB29A7DCD5958ULL,
			0x9E614EE3D3BD709DULL,
			0x758F3EA0EB350BCEULL,
			0x688BDDA00329E05AULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xFE2B2C011569BEF6ULL,
			0xF2DFE46D0B6911B2ULL,
			0xA2AA3C5106A97879ULL,
			0x04F92F8D78A8D0CBULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF2F197041A9DB080ULL,
			0xDD2C03F7D6876ED9ULL,
			0x7D0DC09CC33704E6ULL,
			0x48714FC8C1B70A53ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x583CCB744018EBACULL,
			0xD33D0CBA946AB1C8ULL,
			0xC4A712743EBA1683ULL,
			0x7A8DF97A420DB9ADULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x4BFD0BCC39B7E142ULL,
			0xA6D2E5EEBBB38003ULL,
			0x3435229E644F19D2ULL,
			0x05F7067F3EDE64B6ULL
		}
	};
	printf("Test Case 270\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 270 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -270;
	} else {
		printf("Test Case 270 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x2A33F2492C4FDF90ULL,
			0x0E3B1A32F37A2156ULL,
			0x03E6E73E9ACF4A98ULL,
			0x4DD691FBC2272685ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7FF6EEE569A43216ULL,
			0xD0F9485D9AA77E0EULL,
			0x453A01AFD97110D3ULL,
			0x70ABAF03D3D988CDULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x7B0F7A3968E78980ULL,
			0x1273C093BFCFCB94ULL,
			0x565630E9F1B9D8A5ULL,
			0x760016C169359E06ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xCF0DDE7EC1BFDD84ULL,
			0x1752CAA7ADC4B1F3ULL,
			0x9CD6676146F1F943ULL,
			0x1F097816DC449CD4ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x467207F6298F456DULL,
			0x3B372974FB22E14CULL,
			0x1F289F49D6975852ULL,
			0x406508A33CD155E2ULL
		}
	};
	printf("Test Case 271\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 271 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -271;
	} else {
		printf("Test Case 271 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x96D1BBC910182040ULL,
			0xAB1C5AFC3843ECF2ULL,
			0x3F34583B4E36F2FFULL,
			0x5A1508AC3437E8D9ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x84C8C5878086DD29ULL,
			0x3E51B5F704C64010ULL,
			0x23C188DA59320079ULL,
			0x0533E5DEBF60243FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB8FA7C0CC4F0AC38ULL,
			0x59FB3C6C0F494FF2ULL,
			0xBC012F5E4B7BBB07ULL,
			0x77082A177FE918DFULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x5F4C6031BBAB4280ULL,
			0x642305592E3EB43CULL,
			0x0F0F710E3AE4CF5EULL,
			0x17D1685C4206FCF6ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x1A5E92DAC416BA23ULL,
			0x7332841DA4A8BB89ULL,
			0xA2DB9E2E68D1EE08ULL,
			0x5EDB9D18D96874D8ULL
		}
	};
	printf("Test Case 272\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 272 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -272;
	} else {
		printf("Test Case 272 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xC2316C5924F98E18ULL,
			0x7DBB65543CA7C06FULL,
			0xC4B528E9C39074ABULL,
			0x46B95D000E2E8E85ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x9DC60F16E05B3273ULL,
			0x182EEBA5731C2350ULL,
			0x7BFA210AC58EE83CULL,
			0x77F29D2C90A5C825ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x7BDE97EAA4374158ULL,
			0x886FC5494A93DC47ULL,
			0x56DBFE358A34ECA1ULL,
			0x7D98EAE7C3091E71ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xECB1D996DBF4B438ULL,
			0x9D1B75D02289327FULL,
			0xFD6C68BC61B4F839ULL,
			0x72C5DCD16846C452ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA69635A739292909ULL,
			0xB101500005762689ULL,
			0x919A017F2306EA4EULL,
			0x5618DCC67772C452ULL
		}
	};
	printf("Test Case 273\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 273 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -273;
	} else {
		printf("Test Case 273 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xA941E45B6120EDA8ULL,
			0xF29D9C2693002A01ULL,
			0x1D7E8E9156D6854FULL,
			0x4A79C8C777723AF1ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x53BAC631F6ECC12CULL,
			0xE46B5DD308B764DFULL,
			0x1528B41B3B23624BULL,
			0x145906510A7EE2E5ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE59E44307576A6D0ULL,
			0xE77F94392305586BULL,
			0x27C2455C7AFEF1E7ULL,
			0x6D0353571F704806ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x4FCF2D1F36F208D2ULL,
			0xF138F71A7CE655EDULL,
			0xBFA7756CA424B2C3ULL,
			0x3E7E73087E8AA8D2ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC38F89AC8741C85DULL,
			0x62603324D5A76DBCULL,
			0x091050895B54EB83ULL,
			0x6A1CD9D3A7D5A277ULL
		}
	};
	printf("Test Case 274\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 274 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -274;
	} else {
		printf("Test Case 274 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xC15C41F8171B1798ULL,
			0xA2BEDEDF8B324E8FULL,
			0x757CABDD998559ECULL,
			0x42DC4912142A5591ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x1A05140E423596C0ULL,
			0x14936D620EE782ABULL,
			0xAF8BA405C43E5C8FULL,
			0x6686312F02F71B1BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x018D2040BD6217C8ULL,
			0xD8BB948C8910626DULL,
			0x92FB0313D56AC7B4ULL,
			0x71A3F79B9EFE312BULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x5D4E65BD8E97307FULL,
			0x0E18FDFF4A80BBD8ULL,
			0x9A7E531178A8EADAULL,
			0x0A9474CD727FE174ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE3F5A6925076B9CDULL,
			0x03B395C2DCE29D70ULL,
			0x61E85F04FF02FF96ULL,
			0x2A7EBB315779EF8AULL
		}
	};
	printf("Test Case 275\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 275 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -275;
	} else {
		printf("Test Case 275 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x9E3E3AE801234E40ULL,
			0xDE9EF26C2DBE5123ULL,
			0x8E81146DF8480A8AULL,
			0x67FF994CBB1D7EBCULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x72D9AD2FDDF9C262ULL,
			0x1456D51F2C4CDAD1ULL,
			0x94460C386F18696CULL,
			0x197F1431A5F2EF8FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE0FB12D50D977BB0ULL,
			0xBD42C513F10D212EULL,
			0xE0F2B070D88C94DDULL,
			0x569BD8C1898EDC01ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xC959B5F87420E03CULL,
			0x1305B23F11638EEBULL,
			0xACFD512FAA5FBDB4ULL,
			0x176426E1213B0B6AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA5485FC3A88EF060ULL,
			0x77F12D0BAC69A3B8ULL,
			0x9CE5CE98603B22E0ULL,
			0x23C21639EE6AA3A3ULL
		}
	};
	printf("Test Case 276\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 276 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -276;
	} else {
		printf("Test Case 276 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x5C09D9E43D6B9E60ULL,
			0x835B620E86788655ULL,
			0x1B584CE3DBEC2BD3ULL,
			0x4B698719F09B3DE8ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5EE8CCF86FB0B7F2ULL,
			0x49C398DDB0B03724ULL,
			0x89E7C840211478D8ULL,
			0x370A80426A64EEC2ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x0C34AE518D1BE370ULL,
			0xF964F5A9D7CBECB1ULL,
			0x2B04B07D4D792CC3ULL,
			0x69B869CFB6253903ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x5DA12A74AEFB0FFCULL,
			0x2AE5ECB5882FC8F6ULL,
			0xE8C5B8E52AC29DD7ULL,
			0x09EDC96B6ACB67EDULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x3EA6979049ABB0CDULL,
			0xF52723481B431F2DULL,
			0x406F916A89BDA6FFULL,
			0x246CADAEA1FE7B95ULL
		}
	};
	printf("Test Case 277\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 277 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -277;
	} else {
		printf("Test Case 277 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xE6DCDB75D5208088ULL,
			0x4E5C4DFCAB5C4FCEULL,
			0x92C8815D849A1751ULL,
			0x794E93B3A46DDB74ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE9A937E0FDF566D2ULL,
			0xEA373848EC18E72DULL,
			0xE25B7519F7510111ULL,
			0x53B8B196179F6215ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x3CA699E1CEAB15F8ULL,
			0x1231F8C9D96CC5B0ULL,
			0x3AADD860F0D1DF2BULL,
			0x654ED56377C64890ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x9EA20F63C3F66554ULL,
			0x344E32074B419851ULL,
			0x2F700C7678A6245FULL,
			0x3652175AA99D69DAULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x3143987DDC08744EULL,
			0xC3C54CA73DBB7745ULL,
			0xA2509A08391CDCD0ULL,
			0x4A3B692B5C7BE693ULL
		}
	};
	printf("Test Case 278\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 278 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -278;
	} else {
		printf("Test Case 278 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x00B07C22B041E5D0ULL,
			0x6D88F216A6FA7252ULL,
			0x0876300C67159202ULL,
			0x5A3A8703B1BE8304ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xBD7183F8B93E8997ULL,
			0xC995BFB3635CE067ULL,
			0x8BC441063E063625ULL,
			0x7462DDDAEEF02016ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xCF09900E35312A10ULL,
			0x530CA203355043B7ULL,
			0x7D5EBE8EDAA2D72DULL,
			0x77E9166DC63D2839ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x7A140EC829C833A0ULL,
			0xFB4C3232C3DF8735ULL,
			0xE989F515A86B1398ULL,
			0x0EE5CB4381AA8027ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xAEB44B6A33491CF9ULL,
			0x42CBA36AA0A62898ULL,
			0x69BE9E2BE0D5246AULL,
			0x09FC0256BCE17140ULL
		}
	};
	printf("Test Case 279\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 279 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -279;
	} else {
		printf("Test Case 279 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x5BD1A72B9B982E90ULL,
			0x5A81BDDBDB47C42BULL,
			0x9082B850C398723FULL,
			0x7F976CDF94E7C8ADULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xDAF2E6EC368E2D5CULL,
			0x6045E76CE1BBE6EDULL,
			0x92CC11DD8921DE61ULL,
			0x253770227E9896DBULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xD668E48B6BFB7D20ULL,
			0xBEAE3CDDB6151690ULL,
			0xB5C24FC6992AF58AULL,
			0x52751D6006B09CC6ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xE6C73CEB9F1095BCULL,
			0xC58D1EE2DEF69B1AULL,
			0x50BA6C732463EAA3ULL,
			0x3312CCB5E469C879ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x8D14741D3B8F46A6ULL,
			0xA2B59112AF10A013ULL,
			0x6DC8C2E77D98524FULL,
			0x037B09A275D9409FULL
		}
	};
	printf("Test Case 280\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 280 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -280;
	} else {
		printf("Test Case 280 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x76616D84A940B370ULL,
			0xCA7D27CD1910460DULL,
			0x768AC96F0B2F2789ULL,
			0x4B02EC07C31DD1C4ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x6B36866984D19AABULL,
			0x26D29EA844174A0BULL,
			0x597C611F3F388F61ULL,
			0x779170F3CCC5E82DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x34D1395556AFF260ULL,
			0x91B6EBB3DEE716BCULL,
			0x757C2AA7DB61030DULL,
			0x4D37331BC13D3CCEULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x9B002098A5AE5523ULL,
			0x539DCDF13B8DD7D0ULL,
			0xA5220D3E027EF288ULL,
			0x06647A9160270807ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xEDC4BBF3560B6F1BULL,
			0x36C81C4A1AA4B743ULL,
			0xF9072CCA4BE7DDA7ULL,
			0x175A9E0E87BC3ECAULL
		}
	};
	printf("Test Case 281\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 281 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -281;
	} else {
		printf("Test Case 281 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xF82C1B1718E02370ULL,
			0x86CF232D7F6CF9ECULL,
			0x0119F74942584F0FULL,
			0x51FCC5F10E3D96F9ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xCBB375B8084CFD0DULL,
			0xDF0E65E3D3FBF408ULL,
			0xB87D294787611D1AULL,
			0x72953CEA40F2E152ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE0CA5A77844FD0F0ULL,
			0x3D9C1A9CA48C13B0ULL,
			0x205F7993E46ACAB9ULL,
			0x711035C417136241ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x87FDA24C04618DF3ULL,
			0x1F20A0CFDD4ADA73ULL,
			0x5ABE23F68AC207FAULL,
			0x4DD9AFE5D0BE344FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x4E1ADCB3FB979F53ULL,
			0xC7651A2C959F6F65ULL,
			0x898B9E8272CC0418ULL,
			0x77A1522F0B2A4145ULL
		}
	};
	printf("Test Case 282\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 282 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -282;
	} else {
		printf("Test Case 282 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xF33B9DA2D925FCC8ULL,
			0x0807EE98814EE9EFULL,
			0x6F95B5E78EBCCBE7ULL,
			0x75AB7BB32846B7C5ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xD249800229AEED57ULL,
			0x3B31FBC812EC825EULL,
			0xEC7FC4C1A748B3EBULL,
			0x57EA3E736411F841ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xDE01869F0E4B2BF8ULL,
			0x1DE156AE1BE69F75ULL,
			0xCFCAAA463FA031A3ULL,
			0x5E5C59336ED131D4ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x7084132BC77707DDULL,
			0xAEFCD04DB1AAF91CULL,
			0x4FDED6F8B6E9C56DULL,
			0x429DFF6EB02AB63CULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x1BB3E46339978F16ULL,
			0xBAA51104F43EFAB5ULL,
			0xA9D48C5FAB1E2092ULL,
			0x26380A8B36FB21CCULL
		}
	};
	printf("Test Case 283\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 283 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -283;
	} else {
		printf("Test Case 283 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x4C577DCA63259400ULL,
			0x1F6CE1990020B91CULL,
			0x72EEEB6D5BA9ABD8ULL,
			0x6F6755ECF560D3D3ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xCB16D8C7DF87F51AULL,
			0xA6A61281F5FE65B8ULL,
			0x0F3669052E3300B6ULL,
			0x526CEF42AF922E7AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x19CB9B033E7F0AC8ULL,
			0x0EEA4D978F1F44C7ULL,
			0x776B6A34CCF9E427ULL,
			0x458AB272853A65C1ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA6C5F028BBF54DF1ULL,
			0x7DFFA1334030BA5CULL,
			0x954AD06E97EFF36DULL,
			0x4EAF59A142D3A2ACULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x61CF60ACA2F1C3E3ULL,
			0x6933F1AC5B50C01BULL,
			0x5AC5184143781F7AULL,
			0x39E35A070A4207BDULL
		}
	};
	printf("Test Case 284\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 284 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -284;
	} else {
		printf("Test Case 284 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x8DBD792296FDC7D0ULL,
			0xF07CD6B124ACF5D7ULL,
			0x41490FCF036FD8EFULL,
			0x753945F78ECCA73FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA366FF4E473E3245ULL,
			0xB41577BCF33815FCULL,
			0xCFEB6F998E7CF567ULL,
			0x2D12CAF8C8DBFF69ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xA4BC35AD8E2EF828ULL,
			0xC7C543F33FAF1771ULL,
			0x051F26F5B8E062AEULL,
			0x5C483E9101DB5A8DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x92E19AB7935F64FBULL,
			0x84B6DDCDD47E93E9ULL,
			0x81F4C2DD3945042DULL,
			0x5ADD2441E45DDF4BULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xBAB32C34C450CC80ULL,
			0x4ACE2E6B045704DCULL,
			0x36654EB20A371968ULL,
			0x187AA432811D74CEULL
		}
	};
	printf("Test Case 285\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 285 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -285;
	} else {
		printf("Test Case 285 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x4A95080A96AD3048ULL,
			0x52ED8CA2B748A27FULL,
			0xCF7DB006837C7306ULL,
			0x5F2C5C05EEADA65DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA2C97E2DC5C62E5DULL,
			0x8C645538AA63B94CULL,
			0xCE205E5C6CBFAD50ULL,
			0x428153A5B1EA0C0DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE0AB0BB3E1537218ULL,
			0xEDB03BA5AB3DA4E4ULL,
			0x1BFB116349112F62ULL,
			0x6BE147DCE10FE642ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x5AE07D9045FE9F9BULL,
			0xE09EB4B0B83780D5ULL,
			0xDA690284F7D4013BULL,
			0x38165AB6A79EF9DBULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x2AA0DA562CFFC115ULL,
			0x99DE289180E0BBA2ULL,
			0xE181787F3E5D6E77ULL,
			0x17035DC973914099ULL
		}
	};
	printf("Test Case 286\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 286 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -286;
	} else {
		printf("Test Case 286 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xC03B5F5FB5FA6D98ULL,
			0xF196919163783DD4ULL,
			0x061EFB085AA94943ULL,
			0x753C6301CA606E78ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x09528E22A4B0629DULL,
			0xFB7DE1A15FF57752ULL,
			0x9A49EBD24CE6126BULL,
			0x253CFBF4D03AC494ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x97AF09152BAE9058ULL,
			0x73FD89ABD11D616BULL,
			0xAC7954835F846B33ULL,
			0x74B0B52DC48D830CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA1A5E777AEC5A130ULL,
			0x4E71A7281AE46444ULL,
			0x3B0D496A1F4567F3ULL,
			0x7C32EC73B49C81D9ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x3A9825273F30F5AFULL,
			0x21AB8CB1A8E9E257ULL,
			0x39A647C7E3E79F9EULL,
			0x78E9FEAAA153FDCCULL
		}
	};
	printf("Test Case 287\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 287 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -287;
	} else {
		printf("Test Case 287 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x9606E1590DEAD6F8ULL,
			0x152AEA86D304B025ULL,
			0xD3386423614C0B29ULL,
			0x54935CB7A76D6BC6ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4968F0CBFF8C6E09ULL,
			0xD48D5DBA3391EF98ULL,
			0xFB4205C968311740ULL,
			0x68758686AB9EC111ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2A3A6547CAB36068ULL,
			0x4F1DCEB49680F992ULL,
			0x4DFE09649FEA282FULL,
			0x6BAEF938DF6A7FC6ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xB88422C9314D4255ULL,
			0x0F6722DA087A0321ULL,
			0x4DE32424F850A813ULL,
			0x1C078528647ED32EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xAE6999DC8448A31CULL,
			0xB8AEC94351ED4BA3ULL,
			0x5456FE1A2E62BE76ULL,
			0x7E1709600AC17455ULL
		}
	};
	printf("Test Case 288\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 288 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -288;
	} else {
		printf("Test Case 288 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xEFA8CC8BD90C2300ULL,
			0x8505B80F3D745391ULL,
			0xBDBF61DC38057D23ULL,
			0x6456DC75DAF94E1CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x444D772E34939FACULL,
			0x2F9BC35D4A406DCCULL,
			0x70B8F435E9B6A8D0ULL,
			0x492B1E5575035B04ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x285207BD1F2CE440ULL,
			0x19A029472321F656ULL,
			0x5544ACACB62FEFFEULL,
			0x55E44CE8B9BD3231ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xAE69A55CCDBE1DECULL,
			0xEE8A0273B38A60C6ULL,
			0x498E6B5D420E6F4CULL,
			0x6FA103886D7D0BE0ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x1CE0C760B852FDFAULL,
			0x2C164321BAB840B5ULL,
			0xEAFF032F13FE3848ULL,
			0x45A6EBD3C26411A7ULL
		}
	};
	printf("Test Case 289\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 289 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -289;
	} else {
		printf("Test Case 289 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xB3E43B74667EBEE8ULL,
			0x322916A92B240A69ULL,
			0xDB4D93477F667298ULL,
			0x73E0FF5320CA108BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x993689AEB999BC94ULL,
			0xF5B6FDF732F526C1ULL,
			0x39C1F3572F6CC4D4ULL,
			0x21ADEE44975EFD5EULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x6677C8FB87A7FF08ULL,
			0x77A2FEA376B3AA6DULL,
			0xB1548022E253D359ULL,
			0x6A841B2734F458A9ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x98949AE84450C7F3ULL,
			0x289077BDE9E9D005ULL,
			0x8671A3CCA4196212ULL,
			0x792ECF8D01502334ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xFAD40DBEE7DABFA9ULL,
			0x78B3098180CF38A3ULL,
			0xAB120C4F8C040AB1ULL,
			0x6D474DEEBF322457ULL
		}
	};
	printf("Test Case 290\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 290 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -290;
	} else {
		printf("Test Case 290 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x20008369E1B65A30ULL,
			0x9FE9DEFD0369578FULL,
			0xAD0036A113A590BCULL,
			0x61884CDB14DAF250ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x996AB00C68B4A6EDULL,
			0x0B0124203E72A0EBULL,
			0x0CE2700A9DEDC60AULL,
			0x3C93CFCCDF728049ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xBDFC1AFAC402DD28ULL,
			0x76CB122A60168B74ULL,
			0x69B1B60C93CE78DFULL,
			0x4566234952C9E885ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x139E069A8AFC35EBULL,
			0x20F993438E8D2316ULL,
			0x0ABF5715303E92C9ULL,
			0x5C432B86A1D999BFULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x06516DF613D5B29BULL,
			0x8BEC60850EB491E5ULL,
			0x3183232EA00A6B48ULL,
			0x323472D5C58257D6ULL
		}
	};
	printf("Test Case 291\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 291 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -291;
	} else {
		printf("Test Case 291 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x59758102037DE0B8ULL,
			0xCAECE7408A697140ULL,
			0xC71ED36E1E0194CFULL,
			0x7696141ABFC56966ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xEFE0A998B5339F5CULL,
			0xC6947AD7D4268E70ULL,
			0x6A880288E8FC2F43ULL,
			0x6B0D8869961EB37CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF99774E621A2B9B0ULL,
			0x988F55C38B61668EULL,
			0xA1EF0C01B9B53CF4ULL,
			0x650F0CC3E97EA61CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF1075B16E3DF99DFULL,
			0x840D270952BD4B4FULL,
			0x01CD70CBFAB35288ULL,
			0x198CA821A2331456ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x4C530653E34E5EAEULL,
			0xBB7443BDCBA68872ULL,
			0x5995E524338E2BCAULL,
			0x61FAA7EEE6480377ULL
		}
	};
	printf("Test Case 292\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 292 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -292;
	} else {
		printf("Test Case 292 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xD5CED106C2B75270ULL,
			0xA0E339372AA2D43EULL,
			0x9A6D4784B422F1F9ULL,
			0x5B59D94EFBD9AC6EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x692B454F5398E781ULL,
			0xF7AC3E6DF6C39DD8ULL,
			0x511AC5432A269E40ULL,
			0x6661567F5D075E41ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x6E687954652A74B8ULL,
			0x9906C9334209FEC0ULL,
			0xC4DBB6D53E320774ULL,
			0x490A9266757EEF33ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD108A80E97CD7D72ULL,
			0xFF3803A4DE7FC7CDULL,
			0x338FDFA4B099502BULL,
			0x7C18CC20E770E06FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xBD018DDC1855A612ULL,
			0x3BDB5432551A16FEULL,
			0x6D68DB448C9AB07FULL,
			0x46D2102FCEFF36AEULL
		}
	};
	printf("Test Case 293\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 293 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -293;
	} else {
		printf("Test Case 293 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xF5285168875D0B30ULL,
			0x1766556BAC0AD065ULL,
			0x270D9B8416A9C945ULL,
			0x705620A01A9B925BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x8F7A116BD77A46C9ULL,
			0x9A505D7F633800FAULL,
			0x969B2B6FE6AB736EULL,
			0x3221E960CE43EA07ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC1912A2EA1556008ULL,
			0x824FA62BCE2C199CULL,
			0xE10D248911069D78ULL,
			0x58DBF181297522A0ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xBF87FA594E10DB68ULL,
			0x226E9F4452C89184ULL,
			0xE4E676A21DAD3FA6ULL,
			0x70854E6D11B05E49ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x52B53EF35B913DB4ULL,
			0x42BBEEF5F1EA51DDULL,
			0xD3F84C92A2ABC993ULL,
			0x657FB3DED2E7EC10ULL
		}
	};
	printf("Test Case 294\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 294 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -294;
	} else {
		printf("Test Case 294 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x67A9B1F614501D50ULL,
			0x71DA8DB08244A5E1ULL,
			0x743B77DF62909858ULL,
			0x6A88F8C0BE731A57ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4804E336A56B2D98ULL,
			0xD6DB9E41B4377827ULL,
			0x208ED4F9F26FB36CULL,
			0x4978AEED79F64186ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2E661017AA7AE6D0ULL,
			0x6F118AC9A210200FULL,
			0xEA36B52947C7C795ULL,
			0x7F3C3F7640F746D4ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xBD021D6D35349E70ULL,
			0x329EB5E69DFCC4C6ULL,
			0x4786EFBAFF8C406EULL,
			0x2BE608C2D7B9D34EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC02772ACA32D119AULL,
			0x27C47CF993A8E2F4ULL,
			0x6D1298306E15F610ULL,
			0x4CC226E35631B6C2ULL
		}
	};
	printf("Test Case 295\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 295 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -295;
	} else {
		printf("Test Case 295 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x62B31BEF456A69B0ULL,
			0x386A88EC9537F270ULL,
			0x40D4672F72BBC8F6ULL,
			0x5F460884C031CD6DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xD8004580E2E6830BULL,
			0x1D23E6A0EEB43838ULL,
			0x21F89293DD75D93DULL,
			0x4E9E59D136ACF93AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xCCAB971C5F61C5D8ULL,
			0x0A9CBD8EA34A4A19ULL,
			0xD57CD47FE08CFE23ULL,
			0x5873DA6716E0DC3BULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x7B6ABFE158568885ULL,
			0xFDD3D6AAC7DA5256ULL,
			0xA44B09267AA5DD33ULL,
			0x04B22BF3115A3528ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x336AB93084375317ULL,
			0xABFAF376B09B0919ULL,
			0xB2286D23BDCB359AULL,
			0x4B25CE62847F4280ULL
		}
	};
	printf("Test Case 296\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 296 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -296;
	} else {
		printf("Test Case 296 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xA8EC2F329B567368ULL,
			0x4DE311106E15755EULL,
			0xCA7427936B1DF4A1ULL,
			0x7BA3BC81DFA6EC74ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4FC3D43B102E1AFFULL,
			0xF908F162371F094DULL,
			0xF88E00D64F5A7B6AULL,
			0x17B1CB45E17F90E6ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xBBA4E13C923B8460ULL,
			0x5038E06F69BB11ABULL,
			0x4F80DCD807735073ULL,
			0x73E6F3FD2A5EA895ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x0737DFFDFE62EB9CULL,
			0x76DD136EAC092F65ULL,
			0x8DE751CD49A44C5DULL,
			0x1DEC0394DCEEA618ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x9E33A3BCCA61D6FCULL,
			0x55445B07ADE225EFULL,
			0xA576B956A2A0A238ULL,
			0x1BFA51701AF55DECULL
		}
	};
	printf("Test Case 297\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 297 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -297;
	} else {
		printf("Test Case 297 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xF9310043CF5B2650ULL,
			0xD1F0A732C4189B5BULL,
			0x5F73439308E07A44ULL,
			0x729652AFC9CCD05BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x576B09FAD7435C06ULL,
			0x54FB35167BB03FCFULL,
			0x53E8C77FF29421B4ULL,
			0x261443CB4F1F7DACULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x66EC15256A912620ULL,
			0x74E031BA9C6348D3ULL,
			0x6D0E123177BE1FC9ULL,
			0x741DFECC14D76440ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xEE39DAEDB21B0AAAULL,
			0x9F16E453F1B6D745ULL,
			0x5EA3170640A8F447ULL,
			0x2F4529FA2DA36C87ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xABCE9DC8D64F192EULL,
			0x0A94F3B20DAC243FULL,
			0x15A4B7B1CB723016ULL,
			0x0FD7EF944A3AA44AULL
		}
	};
	printf("Test Case 298\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 298 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -298;
	} else {
		printf("Test Case 298 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x5A64B9178A2E4050ULL,
			0x4D393E7989FE8BEFULL,
			0x4F2EDBBA706C4E32ULL,
			0x611792F903B14F1CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x1FE09729A2951094ULL,
			0x8A3EE5B61ACED8ADULL,
			0xE0FD223315418FF6ULL,
			0x6E4BD46AE06F4024ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x06A865D146AB72A0ULL,
			0x080C8DDC52480F64ULL,
			0x1D59D4E7301BDDE0ULL,
			0x69A0D44A0D13ECE8ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x2AFA67D9DB3E80D7ULL,
			0x4A5C0028E8FCCCE5ULL,
			0xE11ED87C33508FD1ULL,
			0x6769E86829AE9BC8ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD44CC1E35F7F94E5ULL,
			0xB675BE829129CC5AULL,
			0x7223AE5C11FD410CULL,
			0x6DF54B05EF909B71ULL
		}
	};
	printf("Test Case 299\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 299 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -299;
	} else {
		printf("Test Case 299 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xA82234B1ED29C198ULL,
			0x36C4548AF0315F7CULL,
			0x80959631ECA24233ULL,
			0x7D1309F48F0BEAA5ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x6FA95A52D487CCDAULL,
			0xBA4F7C4CCF5FD6A6ULL,
			0xF79CFC3CB3B039BDULL,
			0x32ABF51CAD330247ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x1E30AC4988E18B40ULL,
			0x902E76AB56203B29ULL,
			0xD3B0CAD26B00F6EAULL,
			0x6E874D238F9CC2BFULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x5D106DDE559E34CDULL,
			0x51B16D5B30A239D5ULL,
			0x42FEE6DECF573720ULL,
			0x59781FAC36CBFB89ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x68498246E4D11D02ULL,
			0x91D4F6D9F68CEF70ULL,
			0x68BD84D244F9A4A7ULL,
			0x29F04329B033BEE0ULL
		}
	};
	printf("Test Case 300\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 300 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -300;
	} else {
		printf("Test Case 300 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x75BC8801220C73B0ULL,
			0x4FDDAD70B0AF2B30ULL,
			0x96091B74D106E9CAULL,
			0x4EC20CF86BB36D85ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x134C19EA47EDCEB6ULL,
			0x91DEEBEE8A6F479AULL,
			0x61682FD8204E271FULL,
			0x41E51AAC932AEEAFULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x12B7B090122907F8ULL,
			0xD705AFBFEC629BD7ULL,
			0xA945EACA2EEA17D2ULL,
			0x4F1B0E4F4FD8B244ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x9DDE237031DBF5D1ULL,
			0xEA1D19A5035C2DADULL,
			0x796C5F4AE30A9526ULL,
			0x3F07350EF2B87F1AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xAA42FE7F9CDF5DC4ULL,
			0x3AB9B49DD5E01CA2ULL,
			0xE1FAF3FD9C29C1CEULL,
			0x0EC6C9B5B0665D5FULL
		}
	};
	printf("Test Case 301\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 301 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -301;
	} else {
		printf("Test Case 301 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x3AEA02C9148AC820ULL,
			0x391DF77AD81B10D2ULL,
			0x48597A0BB629D0B6ULL,
			0x55B824CD9E5E9698ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE6BD9664CEAC32DDULL,
			0x3755FE673E64574AULL,
			0xA90B030F7BCEEC8FULL,
			0x5A390BB410BF8FA8ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x13261141BB9B5DB8ULL,
			0xECA2ECABFE27F92CULL,
			0xA0ACE41F2B56219EULL,
			0x404ACFFD5CD42E1DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x0C1957E69C696080ULL,
			0x8989D27D77F18A0EULL,
			0x0D7B7E14203FBB9BULL,
			0x34F13D0F61DDC863ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x21E0C0774711112EULL,
			0x1ED9419D6B716582ULL,
			0x4122554F84CCB7C6ULL,
			0x79748B23A927FD7CULL
		}
	};
	printf("Test Case 302\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 302 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -302;
	} else {
		printf("Test Case 302 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x7DF58A0F05960E28ULL,
			0x68F0639B74DC342AULL,
			0xDCC388F0D9CE95A4ULL,
			0x62A0FF43899116FCULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x2A6D9DCB1FAA69F8ULL,
			0xDDB545DB69C7450FULL,
			0x3F3A40A765BB81C6ULL,
			0x47927DEC2910E655ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE2ED736D7C96A3C0ULL,
			0x372E74672865C9FDULL,
			0x511B7F0ABDAD7E03ULL,
			0x5F56B53CC0B2FDB1ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xDBA563091B01DEECULL,
			0xA5B2B6CF9AB03C13ULL,
			0xF566917CBA8F2FB0ULL,
			0x7760B5A2889F3FB9ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xEF94A5CB9395620CULL,
			0x79ECDC2969DE3F72ULL,
			0x8BF425C01A559AF5ULL,
			0x2B6F32F4738759D2ULL
		}
	};
	printf("Test Case 303\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 303 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -303;
	} else {
		printf("Test Case 303 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xAF399F9AA63A30C8ULL,
			0x547454BC654D681DULL,
			0x9FBC8500FF787113ULL,
			0x51A9D3C4078495BEULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x023DB3CEE1D2204FULL,
			0x6F68F2C9E8E63A8FULL,
			0x821FC5DFF868DE8BULL,
			0x4E80E07EE19AF911ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x8BABDBCB27891A50ULL,
			0x527C8705D2B9C638ULL,
			0x525D49989EF3E2E9ULL,
			0x61BC16471A4212C6ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF398A500755B9DFCULL,
			0xC9A9B4278C2B0542ULL,
			0xA29039E845551C53ULL,
			0x130A655598DC0C3DULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF38B1BD3043C2CE8ULL,
			0xF70082AEB962AC2DULL,
			0x1B1930A5EADDD9A2ULL,
			0x397F68DE79BBF85AULL
		}
	};
	printf("Test Case 304\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 304 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -304;
	} else {
		printf("Test Case 304 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x934619464E648B48ULL,
			0x9E49F950CDCDA6DDULL,
			0xB8456D35353AB672ULL,
			0x509B16C72FCD7991ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x9FFA8D5982E95FD3ULL,
			0x38407BA32C245254ULL,
			0xF21C3749CFDC1651ULL,
			0x1D6DB5DF5B25CA0AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE97A9FA6F0C8F038ULL,
			0x9AFA91261BBFA3EEULL,
			0x75F0BC8F02CB8346ULL,
			0x70BEB02359699B50ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x2C7080B2CD284A76ULL,
			0x8B50B21DBE96A9B2ULL,
			0x83332B50B7B065D3ULL,
			0x2F2367BB17E1FB48ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x734669846E7CD805ULL,
			0x568CEF6E8D2306F6ULL,
			0x320AD9BA2963178CULL,
			0x6D43EB766F810FFBULL
		}
	};
	printf("Test Case 305\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 305 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -305;
	} else {
		printf("Test Case 305 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xE7CAE4CBF78B65C8ULL,
			0x2B1384CB13B212D4ULL,
			0x0CC2D035D0F2CA9FULL,
			0x541B11449C7238D0ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x01A9E83B90246967ULL,
			0x418F6552272EC17FULL,
			0x46C77CB06FEA4C36ULL,
			0x4BE425843EE8BABBULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB3EE0101673D6108ULL,
			0xFAFAF9194EBC8089ULL,
			0xA81503C3AFA263D6ULL,
			0x4B95C0672FDC1D17ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x9B5B5D410114418CULL,
			0xF758F5BAE67271E2ULL,
			0x0FFA621AE2D66619ULL,
			0x47FBF49E85F4326DULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x30E1053405AC693BULL,
			0x3EDF33C08683D10FULL,
			0x17C93A0DFF0AD75AULL,
			0x597B2A98A2A431E9ULL
		}
	};
	printf("Test Case 306\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 306 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -306;
	} else {
		printf("Test Case 306 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xD9F64421AF757168ULL,
			0x3A45D1E4D61FF852ULL,
			0x2AF23ED36512B574ULL,
			0x45A5DD86FBACB463ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xB37809C428D72ACAULL,
			0x9F24CCEC2D58AA4EULL,
			0x0BA5E8D3F2AF4B40ULL,
			0x15C842027FF22E44ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x7A8113CC4298AA38ULL,
			0x5E41A635C2485B42ULL,
			0x6D294AD38722B172ULL,
			0x6C6AA60839337994ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xCD176CF320CF152DULL,
			0x579D187A20E39DFAULL,
			0xBC3A48B69B1BB766ULL,
			0x562A69E12D21B27CULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x66CAC40FA8FEA44CULL,
			0x69BB17798F63E9EAULL,
			0xB7585301ABF08190ULL,
			0x360E7B619AEE46CAULL
		}
	};
	printf("Test Case 307\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 307 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -307;
	} else {
		printf("Test Case 307 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x472A7ED023A4FF10ULL,
			0xDC81AFC992544852ULL,
			0x6BC751E1A7475853ULL,
			0x7164B1C8ABBBC047ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA0B392B93E7847AEULL,
			0xC41046C536AE8209ULL,
			0x3EE729E2DAED00F1ULL,
			0x10F950CD00DE1D3AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x0B6150968424FFA0ULL,
			0xC8DAC86F2FE7CB9FULL,
			0xCE58098D2F7DCB3DULL,
			0x6BA109065B578468ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x0C82409D66A97387ULL,
			0xEAB002CC31A43EA6ULL,
			0x53721CED42A3B95FULL,
			0x001BC797EAACE75AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x81087DCD56A67F80ULL,
			0x0D139C8056D0A632ULL,
			0xF32E40B4D44690DBULL,
			0x6B100F98E5604E07ULL
		}
	};
	printf("Test Case 308\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 308 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -308;
	} else {
		printf("Test Case 308 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x1FFF91BBBC1E82E0ULL,
			0x300D394E893AF8CDULL,
			0xB54BA923EA8E539EULL,
			0x64BF7B40F3C0E33EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x03A872385E8F7E6AULL,
			0x02F04550C607835EULL,
			0x6310396474990111ULL,
			0x0715B48C492A6EABULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x503905301FCA01B0ULL,
			0xFDA694BC22BC28DAULL,
			0x339341B9852055A0ULL,
			0x44280DAFC099BF88ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x4BBD314237429C3BULL,
			0xD22CE71CC8CC7FE0ULL,
			0x9F074AA20BFD7364ULL,
			0x3B8014A134171FFFULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x598A6AA1B89EB517ULL,
			0xB8520383A401A093ULL,
			0x145541A4E1E9E8F6ULL,
			0x6E845D7A10F68348ULL
		}
	};
	printf("Test Case 309\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 309 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -309;
	} else {
		printf("Test Case 309 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x676FF4BFC62B8640ULL,
			0x3B503DA34C96F242ULL,
			0xF2AD6190E806CE28ULL,
			0x645458915A58F0A7ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xB43035AD9B925445ULL,
			0xAC577A06D09CECAFULL,
			0xA6CE2CBEE4AE9E13ULL,
			0x1DCCF24002611B88ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xDA3F001D05282DE0ULL,
			0xE4E5099ED79EC975ULL,
			0xA1376D2A699224A5ULL,
			0x6AC8DE13B286FE68ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x8975EF5D2DA1B5F2ULL,
			0x2AE61DD54F75DB04ULL,
			0xEE0FECA4203EE35EULL,
			0x75FF8704328B6800ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x46CD317E0818D1EAULL,
			0xE6B8236864596BA0ULL,
			0xDD3BDE02B6FE3762ULL,
			0x28FE0C9429E904AFULL
		}
	};
	printf("Test Case 310\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 310 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -310;
	} else {
		printf("Test Case 310 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xD8012672FEB4F9B8ULL,
			0x8DB95AEBAB2E1724ULL,
			0x2914363DA684AF9AULL,
			0x44C135DD61F3BD40ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x257F4ED9C3342839ULL,
			0xEF68ACC0CF9ED2C5ULL,
			0x148DF28917AA41C9ULL,
			0x1FC09499322B72B7ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xD91843CBA842CFC8ULL,
			0xD3001482CE901044ULL,
			0xE656D8822EE151C2ULL,
			0x5BB12898F3999E2DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x2D4D307CB3FC80F8ULL,
			0xD9A24A3566143D7CULL,
			0xF69F2EE2D399D8F5ULL,
			0x10A364E5073450FCULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x8B1A8C9CA8FB456FULL,
			0xFD494A48C7217193ULL,
			0x12E4375F9968C587ULL,
			0x0CBEED3992868467ULL
		}
	};
	printf("Test Case 311\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 311 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -311;
	} else {
		printf("Test Case 311 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x7661DCF01938A710ULL,
			0x8D4DF07B2F72900CULL,
			0x5A736E8F6158DBBBULL,
			0x76F321A336CF112AULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x02830F34657888ADULL,
			0xEB1EC4928F72A335ULL,
			0x8B822D0B80BF35C7ULL,
			0x124905973CB61A45ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9DC0EFA029B4AAA0ULL,
			0x02278757ADC2171AULL,
			0x5816371E765BA409ULL,
			0x5DF1C262C43C2F0DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1998599385815494ULL,
			0xAAF102D366A074B8ULL,
			0xEC8E3F10CD2CBFE2ULL,
			0x417FF23AB7F3E4BEULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x0AF6DEDC1876F070ULL,
			0x8B1A7B7482BFF540ULL,
			0x467A2F69FAC23B87ULL,
			0x11DEEC015F55B618ULL
		}
	};
	printf("Test Case 312\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 312 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -312;
	} else {
		printf("Test Case 312 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xFEEA9CA603531B28ULL,
			0xAB993CC69253075FULL,
			0xC9D6E133C19F7FC7ULL,
			0x5F9B9CC15CB4363FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xDB1EB57DB5225DADULL,
			0xB711F89CAD83B085ULL,
			0xB37F32E2B3825BB5ULL,
			0x616EC8EAF3C51210ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x28C4105DCF2EB0D0ULL,
			0x9E62673C8CECC3BDULL,
			0xDD09AA90F9758039ULL,
			0x7052505F4F4A15C6ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD69813864137C7BCULL,
			0x613BD5D9E2EB7906ULL,
			0x4CC757B27EAA9359ULL,
			0x1AADB9C5BD08B12AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x122976A99A72C6BBULL,
			0xBB8E5BA324871DC1ULL,
			0x5FA90B83B9D24582ULL,
			0x11C28FB1304A7A35ULL
		}
	};
	printf("Test Case 313\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 313 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -313;
	} else {
		printf("Test Case 313 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xD940DF1D791169A8ULL,
			0x3447DC0E6D43824AULL,
			0x7DD8508B5FCC728BULL,
			0x4132B4564F99374FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xD8C72535D472F280ULL,
			0xA2E01BA4A830DEACULL,
			0x3E6FBBDACF394CCCULL,
			0x450F143C4851A6DCULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x62140CFF7794C668ULL,
			0xB195C5E8730126E8ULL,
			0x1EE20753C4739506ULL,
			0x419CBE009DB611BDULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x77E969B5E1C82313ULL,
			0xA0347466B2D2D0ADULL,
			0xADDF00338DBA2664ULL,
			0x2DCC814DB4DB1C86ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x69746887E0440CEEULL,
			0x4CA798C6405F46D3ULL,
			0x9BD4C5B61A881723ULL,
			0x10DC76A4CBC01591ULL
		}
	};
	printf("Test Case 314\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 314 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -314;
	} else {
		printf("Test Case 314 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x3A4F06A4F674B4D0ULL,
			0x911C6139AB185E61ULL,
			0x8BFA6451C5DD6EBFULL,
			0x5763403B8571860BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x0ABE7AF86427368FULL,
			0x0876CD843C25FEA6ULL,
			0xBDF2FB470FF8B4C8ULL,
			0x62663C45D02C1C6AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x3C268F962696BAE0ULL,
			0x52ADAE6A6F1E8427ULL,
			0x44C003077A6DFF80ULL,
			0x7F2442F589A33765ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x33C59093ABE41337ULL,
			0x9A1BAC5BA554D69DULL,
			0x412717FFBBF5AD7CULL,
			0x0931AA856A87326EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x41F43EB6BB49A351ULL,
			0x6AE37A82282751EBULL,
			0x8D403E68438D1290ULL,
			0x16497C32E2977EFEULL
		}
	};
	printf("Test Case 315\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 315 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -315;
	} else {
		printf("Test Case 315 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xD53342928A023CE8ULL,
			0x4A76990C131A8C23ULL,
			0x21380AB4CADEE3D7ULL,
			0x5CDFD39B867E87CAULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x96D0143FD85ECCECULL,
			0x347EF196BD925966ULL,
			0x9AF7E1AAEED78ED0ULL,
			0x7BF658B4DEAD4E4BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x66C6E19697F39B00ULL,
			0xB30085176F93D6F6ULL,
			0x0DDABA5F1DB362BAULL,
			0x73CF3C1AD8468802ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x52327B4D03240891ULL,
			0x3C55EAC86FAD00E8ULL,
			0x7C9FC88E999EFC04ULL,
			0x1CE849C3F25D3C41ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x538AC535122EA6EBULL,
			0xF95FC7C2BDDE379AULL,
			0x105772E1DA789396ULL,
			0x7C528C1A6D135108ULL
		}
	};
	printf("Test Case 316\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 316 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -316;
	} else {
		printf("Test Case 316 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x617677B944829CF0ULL,
			0x3999F29E12B939FDULL,
			0xA083C1CA2F4F40DFULL,
			0x7A5F3AE9A852A00AULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xC2FEB96C6748F05FULL,
			0xA9617416F5807387ULL,
			0x268BA742FD100AC0ULL,
			0x69B9E85673E8C307ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x69E0DA9C26971848ULL,
			0xAF93034DBC9B17AFULL,
			0xBE06BE95B7EB9D89ULL,
			0x5897C3ED2D3F00FBULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xEEA421958FD9BC44ULL,
			0xBD28EEBE013B1633ULL,
			0xF9A7545DFC906FB9ULL,
			0x60436E78937DF5D1ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF1F97D6A169B2DBDULL,
			0x2FF518D3C2C5E431ULL,
			0x8F024AE34ACE46B6ULL,
			0x607E42ED3F3C5F85ULL
		}
	};
	printf("Test Case 317\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 317 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -317;
	} else {
		printf("Test Case 317 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xD7F379DEB187ADE0ULL,
			0x13645CF6A03A5614ULL,
			0x58684821329E85BBULL,
			0x782B52E3E6E8699DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x6709CC9F6C2E5079ULL,
			0x2893066C739CA5CFULL,
			0x1E7AFE980DE8340FULL,
			0x6461921D8C6CE49DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC6569A7B75B6CA28ULL,
			0xA6490BA497A05C6FULL,
			0x81D833BBAF170301ULL,
			0x62EF011C40E753A8ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x3F54EB510779E81AULL,
			0x88C51E07AD0E8E06ULL,
			0x3AA6A41ABD10BF1DULL,
			0x23B401D9F45A0C28ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x150C72160F4780EBULL,
			0xFB634230E2CF90B3ULL,
			0xDAD1A8E4C7BF6E82ULL,
			0x2782E22991EB8C69ULL
		}
	};
	printf("Test Case 318\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 318 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -318;
	} else {
		printf("Test Case 318 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x212DD9E0A06F2D70ULL,
			0xE294955BAC8A9C77ULL,
			0xC3A6E3C42E3EB169ULL,
			0x7562608ADF5E1C08ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x3F5EA7ACAA17AF8DULL,
			0x928851D4D5D20925ULL,
			0x38B12C8B2D4305E0ULL,
			0x19AB9F4DBD8F8FD4ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x18D08C9C715553B8ULL,
			0xAA4A2A35E2096E58ULL,
			0x8E1A45FBEB7E83FCULL,
			0x59C6541CF0E74A1FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF5B484FF5C8F0081ULL,
			0xB8A075A9F3EABF39ULL,
			0x65547AA237C7AAD2ULL,
			0x782DA4A12E179F3DULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xAB55D059452F89B6ULL,
			0x4F4258F9BE44BC0EULL,
			0x9CD675C7984A26C3ULL,
			0x094ED317F68A1AE5ULL
		}
	};
	printf("Test Case 319\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 319 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -319;
	} else {
		printf("Test Case 319 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xB67E65B8F94AF7E0ULL,
			0x15DC9F7D945B827AULL,
			0x33CB5FC29116825AULL,
			0x67FBB07395D61890ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x10E93502B919DB0EULL,
			0x5143D2F8453ECAFAULL,
			0x9B81C01A87AA6155ULL,
			0x44313C306F5EFBB5ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x0E90EDAAC6BA40D8ULL,
			0x103F662E330F2AEEULL,
			0x469FD1C82D6C415DULL,
			0x56823FFBF5A46765ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x4EEFB7640A57CE9BULL,
			0x5A8679F796FD187CULL,
			0x515433BB6F127CA1ULL,
			0x3E9C5BDAAA37020BULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x534BEDE8C2B64DDFULL,
			0x397FA2B47663303BULL,
			0x471CFEF2A9C5C4E3ULL,
			0x30ABA751426D3C9BULL
		}
	};
	printf("Test Case 320\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 320 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -320;
	} else {
		printf("Test Case 320 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x9B0F6EF8BC0E5148ULL,
			0xFC6F0E22C807444CULL,
			0x3C6455F71A8C3BF1ULL,
			0x54F5097CA2FAFE8CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xCC95D7D8FD96E5D8ULL,
			0x866F15BCA90C97C2ULL,
			0xE8EDBC5AF46C4289ULL,
			0x3D002794A623DDF1ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x0D13450C5C162308ULL,
			0x70E242F9E307A213ULL,
			0xE178A10C5307C06FULL,
			0x5574942D3DF3C219ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x4E4C7DD5DA15C45EULL,
			0xCE86A30C351E7E3CULL,
			0xCE0F3B8960D8858AULL,
			0x482538D7C5AA33CEULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xBBB083B7095DF07FULL,
			0x94559CCBE0A60F8BULL,
			0x14D01012999155EDULL,
			0x0D1EE73C1AAD21FAULL
		}
	};
	printf("Test Case 321\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 321 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -321;
	} else {
		printf("Test Case 321 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xB48C866CF11DE468ULL,
			0x4D5F55C6DD60AD0FULL,
			0x9C77B579861D4C55ULL,
			0x74A8C01DA7E8163FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x1C036754BC5F60D3ULL,
			0xF71753B0CA9C2986ULL,
			0x976308DF35897E84ULL,
			0x4A01D8D50396880BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xBB4C3CF5D72516D8ULL,
			0xDDA6C62547F14106ULL,
			0xCF857EB77784BB3CULL,
			0x7D33CD408D400212ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF6FB8034485C314BULL,
			0x3A66F3833F0B8780ULL,
			0xC77AD53C51CA837BULL,
			0x0387F88514731F16ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xEA53B29A3C269B2FULL,
			0x1680E075D692DFE3ULL,
			0x5DC3B8852C6913D5ULL,
			0x52C8E3A11B7E3B16ULL
		}
	};
	printf("Test Case 322\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 322 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -322;
	} else {
		printf("Test Case 322 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x08F75C437F848750ULL,
			0x0233EA3FDDF0927AULL,
			0x6BD0B7F2114D9C7CULL,
			0x72E367E7FDAE5535ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x8FD5C4945D8B91EDULL,
			0x457A6BDEC592ABA3ULL,
			0x44C2F1BC42FAF898ULL,
			0x700EB0AD9FA5C68AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x4FD73FBB7A8FFD60ULL,
			0x9A92AF2C19DE8F07ULL,
			0xE7D83A045C65C450ULL,
			0x4E3F9F9073C7A2ACULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x5205CB8204F1AE41ULL,
			0xC8564BE6168EDD43ULL,
			0xB44730F7A422E4A5ULL,
			0x1B5904C0889B54B6ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xAABFCDF75E0FC6C1ULL,
			0x9A8374417FEA3D6BULL,
			0x19CE508B79B577D0ULL,
			0x0EE5CA8B362B8578ULL
		}
	};
	printf("Test Case 323\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 323 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -323;
	} else {
		printf("Test Case 323 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x97C0E920E846EB28ULL,
			0x4723471D5FCA82C9ULL,
			0xC9E1B05925EC2E91ULL,
			0x49D3D30C956D7B79ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x2A7C1BA11540059DULL,
			0x13267F6B8EBEAEEAULL,
			0xCE6B737CDE4F8EAAULL,
			0x4D964156287327CDULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x56795B6230817FD8ULL,
			0xF4A8C706F67120D0ULL,
			0x0B854FCE59DB0AF4ULL,
			0x672B3033CFAB4F4CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xE2FE90A83C65079DULL,
			0x16B733997BD9171FULL,
			0x80F712C1031F18B3ULL,
			0x45B41E57E03CC334ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x9C8F18DD62CE1913ULL,
			0x49F177607D8ADEA3ULL,
			0x125521DF7A8C0E2FULL,
			0x76E7C509753DBD34ULL
		}
	};
	printf("Test Case 324\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 324 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -324;
	} else {
		printf("Test Case 324 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x4929CE152B811E58ULL,
			0xFBA950186A17E321ULL,
			0x6427979DAD247BDEULL,
			0x5AB725B2C54C0CB1ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x2B100C4B9157DDB8ULL,
			0x852BCD8215BE9EC8ULL,
			0x77FE228260867D36ULL,
			0x202955CB22D09D5CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x311F46AEA6E5C848ULL,
			0x1B1EE143AB392E07ULL,
			0xEEB5D70D09D76C3FULL,
			0x68FC78B461E3D7A8ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x07FBCC54F526C661ULL,
			0xDEE15DB27FEE2613ULL,
			0x88CCBA3424A55C10ULL,
			0x6FAE6E94D5B81606ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x682009916CC4DAD8ULL,
			0x8925CF02E6412308ULL,
			0x33AD1CE594E39A9CULL,
			0x62631EB22984E17AULL
		}
	};
	printf("Test Case 325\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 325 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -325;
	} else {
		printf("Test Case 325 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x03F2257BF3CD1E08ULL,
			0xA4C9AA9453ED3175ULL,
			0xA9F77294062A692CULL,
			0x5EDE608A181F2EC1ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x1D8AAB4E7C394904ULL,
			0xBE0A28451DE5E1E2ULL,
			0x49E482773D24C805ULL,
			0x75EF7E8919D55C21ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2C58F419465BC278ULL,
			0x4618BBA78EB76551ULL,
			0xBF6A362EB5CB1F2CULL,
			0x402F92563D45ECCFULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x7F102FC16D4B7AE9ULL,
			0x7C6AA55E51F3BAA7ULL,
			0xF6778014CB9B88FCULL,
			0x07E24A52D8D0BA5EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x697FB6FF701A2D1BULL,
			0x26F28A31C9D09FADULL,
			0xDE0AFFA112598B63ULL,
			0x6FD6733D39F2C47FULL
		}
	};
	printf("Test Case 326\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 326 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -326;
	} else {
		printf("Test Case 326 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x88309235630EBAF8ULL,
			0xF126A7C3B1E7FF81ULL,
			0x81E087FDDC4FA539ULL,
			0x6E77EC1FD4B9064EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x246F05F43CEF8416ULL,
			0x043287C5C53209B3ULL,
			0xA7144D2423C6724FULL,
			0x5B37038D27F8387AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xBA1DB845C4EE5090ULL,
			0xED74EAED807B0940ULL,
			0x67C6D879237AEE36ULL,
			0x78BADB6982615515ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x22A6FD6834EBEA59ULL,
			0xBC253CEFC32BBC62ULL,
			0x0A0654F780E941DDULL,
			0x2CE9812138334D05ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x571FEB730A40C563ULL,
			0x9280D8079E172D44ULL,
			0xC4967D4F9BB64899ULL,
			0x09A01BD2C5F58C03ULL
		}
	};
	printf("Test Case 327\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 327 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -327;
	} else {
		printf("Test Case 327 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xF04CF028626253F0ULL,
			0x184B80EC67241DECULL,
			0x25CAD1F07BF68960ULL,
			0x7E0B4AFDDF431936ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x8F9C2D0A1B455BB4ULL,
			0xDBE79F1BB5866800ULL,
			0x1800A1186C940C5DULL,
			0x3A6DE849F0F56250ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xD24ECAF50F5302B8ULL,
			0x0DB1D1D3A7B1C3A1ULL,
			0xDA0F424DABB13F28ULL,
			0x7A3E71E7A359B9D3ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x45D020BB0D8BADEBULL,
			0x0720B83DB278400AULL,
			0x811F381054D03FACULL,
			0x7759D3EB2836A3BDULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x95A7CAC8F258F4ECULL,
			0xDA190FE3EF40332FULL,
			0x4DAF1DB63993540EULL,
			0x6D9DA659D007A114ULL
		}
	};
	printf("Test Case 328\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 328 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -328;
	} else {
		printf("Test Case 328 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xE58BF2AB1FAE98C8ULL,
			0x97DA3F121BD23D42ULL,
			0x3BD37A4FFEF48040ULL,
			0x4A8DAB198F2B82E8ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xBB24875D57DEEDD5ULL,
			0x59A6B196B5105056ULL,
			0x8BC0E75A7C5C019AULL,
			0x7CB6D0BF9382481AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x0CA02FDFAFAF0938ULL,
			0xA7243E2CE3CDB93CULL,
			0x0441D13A8E641DB4ULL,
			0x5C23D23DE40927C9ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x44706D4AD5070D55ULL,
			0x8E016591E44999CCULL,
			0x7E01DDB1D4840EDCULL,
			0x44B47962968DDA27ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x05665A26ACC794FDULL,
			0xEB62C29D2D16BD36ULL,
			0x61A63472A9F3F958ULL,
			0x377C3F2F38CC008FULL
		}
	};
	printf("Test Case 329\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 329 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -329;
	} else {
		printf("Test Case 329 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x261AC2613AF22178ULL,
			0xB07A1855A72C2CFDULL,
			0x45116EDBC40EC524ULL,
			0x4CBA69929D8682ECULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xD87B022761F6E5DAULL,
			0x7CFD66C4EAEAEDFFULL,
			0x4DECAF8AB3E31BBBULL,
			0x6D1995B3B9152D13ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xA35E6E33EC70B728ULL,
			0xDD8FAE8FFD93ED4DULL,
			0x750FD6C36BA3F9B6ULL,
			0x5D6D8A7CD0A05DBEULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA7EF45D11A770DEAULL,
			0xBEEB5F21195470C5ULL,
			0xF8183CF73CF62343ULL,
			0x099E42C974B484DBULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE2F415C48793DDBFULL,
			0x197AD108C6AF08C2ULL,
			0xAAEF5AD10886485BULL,
			0x10E7BE5684FECC24ULL
		}
	};
	printf("Test Case 330\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 330 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -330;
	} else {
		printf("Test Case 330 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x221E6BF959151100ULL,
			0x9E64C762D47AF683ULL,
			0x24B147BD0A69146AULL,
			0x7095AE8C2FAA6344ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x41FA8336D2693A69ULL,
			0x3F16039C9494715FULL,
			0x70BAE20DA7531075ULL,
			0x1352C4FBF3A72CC0ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xDD28DFB6A625B0A8ULL,
			0x6A69867B6F272B0EULL,
			0x6A4989B3D14CAF43ULL,
			0x6ACBEA657C33102CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x648D8D3118D5B042ULL,
			0x24F93938EC82C064ULL,
			0xF0C859055E19A56AULL,
			0x7CB2CA6FC3860330ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x8F099EAF05B11B23ULL,
			0x32F3A9F30188549EULL,
			0x7A135F9234326DFAULL,
			0x18FC9F88DC717A73ULL
		}
	};
	printf("Test Case 331\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 331 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -331;
	} else {
		printf("Test Case 331 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x3DA14E17134CDAB8ULL,
			0x5A973056BF3F2340ULL,
			0x1ACA95E4B680B4CDULL,
			0x67E4FB9EB45123BEULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x56AE4E383D4CA7E2ULL,
			0xDA1ED8308FFE890FULL,
			0xA2D5DDD4EDFF6F70ULL,
			0x3924E4AD91AE4937ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x6A01784F383D50D0ULL,
			0x7211F3B87EC19D29ULL,
			0x5531D9B43264E90FULL,
			0x56147578AC65583DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xCBF24F077BD15AAFULL,
			0x2D46AF6A8DAF1F32ULL,
			0xB42F1D6A8EB5E7C2ULL,
			0x265305E8C6659F39ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x0B019368A71A45C7ULL,
			0x5245288DBF75B31CULL,
			0x35A84BF3B112627BULL,
			0x1634D0371FC9DD2CULL
		}
	};
	printf("Test Case 332\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 332 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -332;
	} else {
		printf("Test Case 332 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x61095FA0D881CE30ULL,
			0x99FF09E83EB802D0ULL,
			0xF84A5E79854DDD52ULL,
			0x718A16A83218BA62ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x97F5CD95468E920CULL,
			0x3FE6B7E3E0BEBC4EULL,
			0x60A53D4FF6E61B49ULL,
			0x4DB630BBE7AF7A89ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF41F261313B39F28ULL,
			0xDE6058A8F6D9AF38ULL,
			0x739CC303F52C0906ULL,
			0x44D2603CCE65486CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD1313D19B0E96F5CULL,
			0x796C2ECEF9B5299AULL,
			0xF313E218412724AAULL,
			0x300FAE8F5FE0358FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x53853C5ACA7AD41CULL,
			0x56BABCF14FBE3478ULL,
			0x1A5C344B023F2C50ULL,
			0x54715A97C46A5A52ULL
		}
	};
	printf("Test Case 333\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 333 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -333;
	} else {
		printf("Test Case 333 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x7276A14A4B7670E0ULL,
			0x6B807B63C9FA7970ULL,
			0xD61D8D87F34A0094ULL,
			0x701E1935F8E0DD83ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x505D7837B10F740FULL,
			0xAA64598E2D5DF9B5ULL,
			0x0766997228E36B30ULL,
			0x48BE4A2ED4706294ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xAA2BC6A37D94F558ULL,
			0x167F53918DD5F677ULL,
			0xB55B6D064910D298ULL,
			0x592348FBFD8D515EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x0A702BF5C2970D69ULL,
			0x42FDC14BEF418FAEULL,
			0xF4DD2C1007BEBB26ULL,
			0x65E708E94A7A3457ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xBF7BF31E2A869463ULL,
			0x5544077B28D0BF50ULL,
			0x9A8FD60123118FD6ULL,
			0x25A8A56D89EADBEAULL
		}
	};
	printf("Test Case 334\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 334 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -334;
	} else {
		printf("Test Case 334 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xB305255AE589DD20ULL,
			0x1AEF86DFC06A64BAULL,
			0x593DE6F2E9A6D816ULL,
			0x49DB13EC19CC88E9ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x989FDDDEBCBBFD7CULL,
			0x7F647D78202E304AULL,
			0x701D1203956A0E9CULL,
			0x4E2835084F4D3205ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x5E30355290D4A140ULL,
			0xBB6879D7BA893537ULL,
			0x5B25A01AF4029691ULL,
			0x6C019870C0AA795FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF06EF91C0C5072C6ULL,
			0x6426583F97EDDF87ULL,
			0x92B932D58288FE78ULL,
			0x0ABC01AF6BD1E84CULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x1D5D07153C7D39CBULL,
			0x0AF351940D1BA878ULL,
			0xC90B35AE4830EFCDULL,
			0x733F3DE5FF930E5EULL
		}
	};
	printf("Test Case 335\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 335 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -335;
	} else {
		printf("Test Case 335 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xF31887474316EB50ULL,
			0xEE7FD84AD292D9A9ULL,
			0xA9BB4DFEDD600259ULL,
			0x644E787FAFA95946ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xD33FBE91C32A4E31ULL,
			0xDB68CC63259A4207ULL,
			0xF5B5AB0852D940C3ULL,
			0x5B0E040966FF5270ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x12093AACD52540C8ULL,
			0xDFFA20B6F003560EULL,
			0xB7A1F9DA562DF978ULL,
			0x74D040AAEEEEF475ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x59BDFCA5D343B763ULL,
			0x15D854689E2B9D40ULL,
			0x1893DB108DC4AC2DULL,
			0x0F255332A0D3CD68ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD6953F151E1C5D4CULL,
			0xCD41D63AEA71D7EAULL,
			0xF83A6623F308B3C5ULL,
			0x1A393A460E0C1FBBULL
		}
	};
	printf("Test Case 336\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 336 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -336;
	} else {
		printf("Test Case 336 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x6F735AF0F946CDC0ULL,
			0xF9E387F214350A6FULL,
			0x0FB10AB72887CFB8ULL,
			0x45B0F20A10351C72ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xD1B4BE6FE48E202BULL,
			0x73109CEF814BAA77ULL,
			0x9AAAF4E705B9582BULL,
			0x00D557BFF44C09BBULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC76DBCA067464250ULL,
			0xC491DA777F7E9708ULL,
			0x723058062901AB7EULL,
			0x59CFC114A4CC099EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xDBDB68FD272FDDA0ULL,
			0xE5122F7CA68B8D20ULL,
			0x407D168DF75C59A4ULL,
			0x4A31165FEC95F948ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xFA99C32B1E994AF7ULL,
			0x5C0A0C1D50FAA538ULL,
			0x965108F58207C331ULL,
			0x7F53CC8C60B53A23ULL
		}
	};
	printf("Test Case 337\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 337 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -337;
	} else {
		printf("Test Case 337 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x253952929D26C7B0ULL,
			0x9670F5F387FC66BBULL,
			0x373C430CEAF9AE16ULL,
			0x7D21D926403FA684ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA1ECE43F35B5E320ULL,
			0x34B072CE524E93CFULL,
			0x90BFD0062FCE6587ULL,
			0x28779975CDFB4BC9ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x6FA9E0FA67664048ULL,
			0xBCD218F44A05249FULL,
			0x5E73940692561AB8ULL,
			0x6849CFF8C3956811ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x249ED09742D017F2ULL,
			0x04458B885402A7D2ULL,
			0x259D04CC28652ADCULL,
			0x2B987CD1B5B06503ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x37A5BBFDDD8D5EDAULL,
			0x6D65112E48A802D8ULL,
			0xA2C441B38B94AB28ULL,
			0x1AF80B433E9D3AB5ULL
		}
	};
	printf("Test Case 338\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 338 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -338;
	} else {
		printf("Test Case 338 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xC3AFA1F5F3ADA790ULL,
			0xA51E65B3A190A489ULL,
			0x947941C9004E0246ULL,
			0x5D3AEFE4290B16A1ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xFFC2E05CC51B66DCULL,
			0x7B1B4D5075D09082ULL,
			0x7069D4526581A988ULL,
			0x2B12BFFC33855646ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x0BE9F541A4A37650ULL,
			0x338846CA6B97FDE3ULL,
			0x1CCB27573C27E236ULL,
			0x5A18CC9C3722BCC4ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x17C8C707782C481BULL,
			0x982CC673BA572B01ULL,
			0x67CC24E573955846ULL,
			0x139E7930051395BDULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x587F99CD689EC2A3ULL,
			0x43A54A9241D0C5BAULL,
			0xE037047BF2B142ADULL,
			0x0E0E3A9C10AB1813ULL
		}
	};
	printf("Test Case 339\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 339 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -339;
	} else {
		printf("Test Case 339 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xE7F7C429BE02D010ULL,
			0x0203D93307599DDEULL,
			0x6D2B28799981A11CULL,
			0x5BF467691B2AD2C8ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5F579E02CD9FB244ULL,
			0x9F7DDE855E52BD24ULL,
			0x5E1CC1B254E3DA5BULL,
			0x1BEECD93A971E4C1ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9170987450866ED8ULL,
			0x8FACE63304AC53E0ULL,
			0x47076B64D439FBC5ULL,
			0x482527952FA0BA04ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x89A09C7E98E7C9CFULL,
			0xBACCEFC8D4932D28ULL,
			0x712DF7BB1F1B63D2ULL,
			0x3EA28BD011E27018ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x26DAF2D13DFDE5C9ULL,
			0x22E113006F44C06FULL,
			0xA859B161F9115E1AULL,
			0x34778E50FB6374C7ULL
		}
	};
	printf("Test Case 340\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 340 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -340;
	} else {
		printf("Test Case 340 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x7F628F65C756C790ULL,
			0x3AB2CA45218E2BE0ULL,
			0x0239EA31DE8CC39DULL,
			0x489198AB8B92F17FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xDB03F7001F92A430ULL,
			0x84A40533898885C3ULL,
			0xE9159E995C16E409ULL,
			0x0C87F1D64DA67396ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xA833F37E805C3818ULL,
			0x5E08C6053AF6D23EULL,
			0x931B590C06E32929ULL,
			0x72EC583F7B8AE965ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xFB64BD06CD853AD3ULL,
			0x17A5AEBD8ECFE5A7ULL,
			0xEF0CFAF9F565B1ADULL,
			0x5F69A584F28C1C60ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x00003BE7B74E11DFULL,
			0x83BFA00D923107B6ULL,
			0x95887B19847B61C8ULL,
			0x6E70A0584E444977ULL
		}
	};
	printf("Test Case 341\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 341 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -341;
	} else {
		printf("Test Case 341 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xFB8FEFE91CC785C8ULL,
			0xD1DFAE7E31B99C3AULL,
			0x404F7F330728B758ULL,
			0x556ED5356C43BEDBULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x6393ED9E77CE8965ULL,
			0xDC396B40C33C292AULL,
			0xD992E41A345C4934ULL,
			0x795D9FE870234129ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x3078BA0A924CF930ULL,
			0x2F95FA388A372224ULL,
			0x9BE83A7036CFC23AULL,
			0x55376D6B96057B43ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x7FBAECDC5DF35C05ULL,
			0x0E886FEDFC845D76ULL,
			0x8B3C259A72BFCF72ULL,
			0x55FE78A20CAE756DULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x85C1E24D78BBF4EFULL,
			0x2BB1A3412EDE6B07ULL,
			0x22CCB475FFF2D2AEULL,
			0x4E71628BC5476C74ULL
		}
	};
	printf("Test Case 342\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 342 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -342;
	} else {
		printf("Test Case 342 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x8B398FA54BB6A908ULL,
			0xBA21878A9DABE5DBULL,
			0x6EF28AACFE1CBCF9ULL,
			0x6792978A24D84CCCULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x2ED85454B4612FD2ULL,
			0x35CD8254AD77A2BBULL,
			0x45317D553718906FULL,
			0x2D0DEB3EE3A0F638ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x12ADAC0B41ACF000ULL,
			0x8E7B96A105EFA58CULL,
			0x08BE49023A5A386FULL,
			0x5F97A468CE6FF623ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x80F8D8897076F80BULL,
			0xA3ED87CD967048E8ULL,
			0xB5BADE65DF85042CULL,
			0x44E36C62F416DC97ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x5D5D414B45F42E82ULL,
			0x5A2DD1F6B35144BAULL,
			0xFB592A028567565DULL,
			0x235FB6D018DE4A49ULL
		}
	};
	printf("Test Case 343\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 343 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -343;
	} else {
		printf("Test Case 343 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xA4BE94B3250D8260ULL,
			0xB65FC783F0DAF3ABULL,
			0x8D0D528D23BEFED3ULL,
			0x7A11BD240497AC5EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x1E17813573815EE8ULL,
			0xE231872B04DA4135ULL,
			0x4B5D8F3CA05E8260ULL,
			0x20BE6EC7D30BEE58ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC576F359523845E8ULL,
			0x47882129AA5B6FE6ULL,
			0x674D4DFF47758E49ULL,
			0x46A4662290EC3F98ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1F60FB8D2A434D20ULL,
			0x8D09CAEA22603D99ULL,
			0x25FCE5C3260F03B6ULL,
			0x370CF26F02111DDCULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x2E51336E7F107D2FULL,
			0x51465ADC53CC997FULL,
			0x791E5E2348F2803EULL,
			0x6F50F2F708D48E8CULL
		}
	};
	printf("Test Case 344\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 344 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -344;
	} else {
		printf("Test Case 344 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x1EFD693518D31A20ULL,
			0x2CB67BFA881769E5ULL,
			0xCA6F5AA946DE7A0BULL,
			0x7D95B574D0A95E70ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7D934EE5D90C6F77ULL,
			0x2E6CFA3FA3EF2482ULL,
			0xB632C7E43D4DDF90ULL,
			0x2AFAC2358FAF1375ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x6B9D725A6027E9A8ULL,
			0xDBB4531987AE6C18ULL,
			0x33F10F4B3D5102CBULL,
			0x50C10F3A767C9DF6ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x5D4D14EDFC03745EULL,
			0x01E8C7DAA9BB85A1ULL,
			0x0D2816EA574BF4DFULL,
			0x7244C51CE2D4C078ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x32020C799CE8CBEEULL,
			0x24B58F622EC3D7BCULL,
			0xBC847DBBFF803B35ULL,
			0x593CC0274839A917ULL
		}
	};
	printf("Test Case 345\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 345 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -345;
	} else {
		printf("Test Case 345 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x8534488EF8B85468ULL,
			0x96F474822351AFB0ULL,
			0x15F36CB73D016DC8ULL,
			0x735539FD89812E6DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x63C9A03F66E636E9ULL,
			0xEF5D16411041DC02ULL,
			0xFB1FF4041C498732ULL,
			0x7BA664A245AD5769ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xDACCACB873168568ULL,
			0xD6E7DAF15A5A902AULL,
			0xFD63A7647BA990A9ULL,
			0x7B2C38EA7BC2EBC5ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x0C16BA0D471A84D8ULL,
			0x53C48C936CE13CE6ULL,
			0x4AF6087D7904B97CULL,
			0x54E0FB7C975F460DULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x46FC6CC3F6BAE167ULL,
			0x4F97D3C8CCEA7446ULL,
			0xDEC8E438B13197CAULL,
			0x0A41B0DF229A7094ULL
		}
	};
	printf("Test Case 346\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 346 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -346;
	} else {
		printf("Test Case 346 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x713C48C870ED7680ULL,
			0xB0CA0C661AC15730ULL,
			0x9D60027B367CABF5ULL,
			0x7CDA716A47433CCFULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xBBAEC1ABDCDDD4C3ULL,
			0x1DDB6372496C1840ULL,
			0x936FBE2877C0D93BULL,
			0x2C5CAA39453EDF7EULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x148D9F3D483C1F88ULL,
			0x9D4564612DD69D9AULL,
			0xE768BA03B7FADA6EULL,
			0x617EE76A2C5E4119ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x0F72961492F47806ULL,
			0x8CCAA76C9EC8673BULL,
			0x2D0CD0CB42C018A2ULL,
			0x166A4688F185E55FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x4B5A100CD6437735ULL,
			0x590C5D76544F40A8ULL,
			0xACD952CC441E212BULL,
			0x34FC959EA4B448B0ULL
		}
	};
	printf("Test Case 347\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 347 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -347;
	} else {
		printf("Test Case 347 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xF1B5FF50DF5DE758ULL,
			0xC5B60A89425A7F31ULL,
			0xB4CEAD13726F5F34ULL,
			0x5CB1EC01DD81135DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x3774D86086E6EAFEULL,
			0x7B98D98C2A314E0FULL,
			0x6CAA4D3353C3FBFEULL,
			0x56BABF74F7343120ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x143C1E871B447BC8ULL,
			0x40B32D2F42D5E064ULL,
			0xD9CA4D27C9650D9EULL,
			0x5BCC5C08D9D7B220ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xCEDC75AF642F0D5FULL,
			0xE4815A61BAA42569ULL,
			0x566971A7E3F71D19ULL,
			0x3B4D153748CFA9B2ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF035A3AC8BBB4F90ULL,
			0x4A17D751C7467F59ULL,
			0x7B9C693BCAAECE63ULL,
			0x1F8BE83A54993370ULL
		}
	};
	printf("Test Case 348\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 348 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -348;
	} else {
		printf("Test Case 348 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x12B8B6A9A65FC670ULL,
			0x77BD7EB5B6DE277FULL,
			0xE7623220FF15F403ULL,
			0x7749E07AF7E4E45FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA2435325CB31D768ULL,
			0xAC045DE31788944AULL,
			0x1C0111D12E61200BULL,
			0x23F3F903B95ADE77ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xBCC5FB6251498E68ULL,
			0x09205D5408574755ULL,
			0xE95A58E70FFD2F1BULL,
			0x62A210BB2083E074ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xEA4FEBDC700E79B8ULL,
			0x0263A4F23A389450ULL,
			0x9F2A39C4E4742489ULL,
			0x75296861749617D0ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x6170B391784FA220ULL,
			0xB478BA57555116C9ULL,
			0xAE9309D4E26B046CULL,
			0x4EF04E70820CF636ULL
		}
	};
	printf("Test Case 349\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 349 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -349;
	} else {
		printf("Test Case 349 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x1C41DC1B7D693D30ULL,
			0xAAB76BAF3D71B4E7ULL,
			0xA5598E8C9A034A74ULL,
			0x7A8C3CCD5BA1B342ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x2C1B41A3966B7F9CULL,
			0xCC9A6DD93422D212ULL,
			0x75085A2E3A79948DULL,
			0x2470EACB208CE5F9ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x8446EF04EC0E2710ULL,
			0x0C03C73A0D8652ACULL,
			0x5E8FBC088EC708D4ULL,
			0x455A2C81E5BA6155ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x614B18F430468553ULL,
			0x3315F94D14F53E44ULL,
			0xF1C4AE2253E14E89ULL,
			0x56DC8DF9898F1B8CULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE62C790E7146EEBBULL,
			0xA72EFC79A8CA84ACULL,
			0xBBFA74124D29425BULL,
			0x40B052C314D448C6ULL
		}
	};
	printf("Test Case 350\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 350 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -350;
	} else {
		printf("Test Case 350 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x6E5638FADD368E80ULL,
			0x8E643DF7EED902F5ULL,
			0xCCF4B653B11B20EAULL,
			0x56DA45024EDADCBAULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7CBA097222BE1C86ULL,
			0x465B8A1CC5CD7CEDULL,
			0xD7B48234ADA25460ULL,
			0x6B6BF5B1D87D4508ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x16161B4FA0C8A448ULL,
			0xB2ACEE2444E9A17AULL,
			0x67BD4BF0FF2D13B4ULL,
			0x78C89A3A71838D75ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xE844402F305FC060ULL,
			0x51A65F85D7AE6982ULL,
			0xA8B393D7538D0376ULL,
			0x1DFA2760CA82D829ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD60D2DE6DC6623ECULL,
			0xB4A14DA3DEA0A599ULL,
			0xE08AB33BE8553BFBULL,
			0x676527AD01C25182ULL
		}
	};
	printf("Test Case 351\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 351 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -351;
	} else {
		printf("Test Case 351 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x329A38674E7796D0ULL,
			0xDD43187C8A0356F7ULL,
			0xC6E222F594B4939BULL,
			0x6D8AAAC7764679ADULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xC21B5DE286D39FA1ULL,
			0x2BE63696DB842E35ULL,
			0xE831FC2524464930ULL,
			0x1024375B4B42C133ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xDD00D008BE5D7560ULL,
			0x4FF78C5AA0B9F712ULL,
			0xC7BAD4B3FA7B7FE7ULL,
			0x4FAFFFF176A6E9C5ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x00873CB08B5A313CULL,
			0xD4FE9D0B5EB8181FULL,
			0x49469F87ACB5220EULL,
			0x698D6A85501DA4B2ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7B671F43DAB91483ULL,
			0x1A1CE55F584AB5FBULL,
			0x11B96715EB0BA30CULL,
			0x3B2E9C5DF7562EFAULL
		}
	};
	printf("Test Case 352\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 352 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -352;
	} else {
		printf("Test Case 352 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x45D2C18D28675928ULL,
			0x44C031BF528F4C06ULL,
			0x9F7C31268374CB7DULL,
			0x588718B2A06B2A63ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x19513E9E60BE355BULL,
			0xF9B41149AF4A6243ULL,
			0x8131F9B9F6350389ULL,
			0x77C5835DC7FD73A3ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x261E5539EF3F49A0ULL,
			0x27E9554196749DF8ULL,
			0xCE6F2EBCB5EF173CULL,
			0x40B93DBE3D353396ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x3D3CF4500252C0DDULL,
			0x9631DBE1E7ABD337ULL,
			0x1B14E25EBBBC6D5EULL,
			0x12AB200493F82934ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE1A45EEBC7213DFBULL,
			0xCDF08A3FB5D08107ULL,
			0x11381FC93D15140EULL,
			0x0C7BB982844C9778ULL
		}
	};
	printf("Test Case 353\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 353 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -353;
	} else {
		printf("Test Case 353 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xECD7B9AA2DA45798ULL,
			0xDF51C2EE6CC3AE15ULL,
			0x379C37840D640153ULL,
			0x53AD7FBF6BD5E43EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x87432337318F83BFULL,
			0x8D77046DE93252D4ULL,
			0x9B73BD49EC09C72FULL,
			0x76D878A2921B926AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x963FC67D61FD6EC0ULL,
			0x81D4CEC6D8376FF0ULL,
			0x19736A18614D80A0ULL,
			0x6725257F9FB65CE2ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x2F5B70F1EFE70502ULL,
			0x04095C93DC7DBD87ULL,
			0xED29ABED14D8C1AEULL,
			0x3DED519BA6D826DCULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB83B684AD901D2BEULL,
			0xAD57D7F5A67F800CULL,
			0xC611FC7034886A42ULL,
			0x12D9F7F1688146F6ULL
		}
	};
	printf("Test Case 354\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 354 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -354;
	} else {
		printf("Test Case 354 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x413129DB36EC6C38ULL,
			0x331E1F7A0B9036F0ULL,
			0x330C492A8E1D5B8EULL,
			0x6934F8C7C8542DAAULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA1DC8D14DA6711A4ULL,
			0x55BCFBCA522B5F54ULL,
			0x96BC95B762F7C147ULL,
			0x52C5059FF15CB2ACULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB5328997072E6BE8ULL,
			0xD6F73F97DCC969DFULL,
			0xF4B44F2EEEF30353ULL,
			0x65BAE71C9DD0AB8EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x209DACB5CADE1A9CULL,
			0x7FAA8E2849B2A941ULL,
			0x01C46647004CE4A4ULL,
			0x6C87FCE6CF48E7F6ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA41BAAA9562C8CA1ULL,
			0xD354EAC2EA08F22BULL,
			0xF9B12D63B306F9A9ULL,
			0x36F4B78489FA453DULL
		}
	};
	printf("Test Case 355\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 355 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -355;
	} else {
		printf("Test Case 355 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x1580188EEB9CDC90ULL,
			0xECFB5D406E26BD71ULL,
			0x737FCC044D044E3EULL,
			0x68C24D1440A2D0D7ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xB1B4A6F4535003D9ULL,
			0x5AF5D8562A15CCE3ULL,
			0x390172DA1BF4479AULL,
			0x6448C511BE615DD7ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x503BF888AEB61DF8ULL,
			0xDD450E086692A097ULL,
			0xAA1FC2F48AD6992BULL,
			0x6543A3D1FDC19900ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x32A70F5FB6979047ULL,
			0x7B0C5AACC120A9F9ULL,
			0x258F52ABAEF51AFDULL,
			0x60AE9D339F2EE395ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x049B2A535750B6B4ULL,
			0x0C663C2BD97AFD89ULL,
			0x528195004E8A2F8CULL,
			0x006DE3BD6BEB94BFULL
		}
	};
	printf("Test Case 356\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 356 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -356;
	} else {
		printf("Test Case 356 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x6659A99077C3AFE8ULL,
			0x0DC96C51A359906EULL,
			0xEC96F847D9D44D8AULL,
			0x7F7797031A11DCFBULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xDEA7D22181D6B285ULL,
			0x4B329E92716DC8A7ULL,
			0x4E9BED0044BC8940ULL,
			0x31373134551C647CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xFEECD20B509D7C08ULL,
			0x829465AC9064E3A5ULL,
			0x2CB79F1B01FF2530ULL,
			0x56FDC9B23BEF76D7ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x72D06AF0D35048DEULL,
			0x0BCA44F356F88276ULL,
			0xECB46757C62B55E3ULL,
			0x1744E01CCBE0102FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x0EF17378AA0CC7E9ULL,
			0x2663D05C161F0A17ULL,
			0x3B9692BB8E1AD618ULL,
			0x4FB4F17359A4E471ULL
		}
	};
	printf("Test Case 357\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 357 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -357;
	} else {
		printf("Test Case 357 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x84001F1B3A70E5A0ULL,
			0xA0C1C7E25B82AE12ULL,
			0x3E9A80148F5B4BD5ULL,
			0x5AA0DB2B079F74D3ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7CFB4237DDD35C3FULL,
			0xA2D3E971D52F8B2FULL,
			0x11A0ACBD6B36D138ULL,
			0x7B3713392190773CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC060D7C77DE8D6A8ULL,
			0xE7EA898195426A2AULL,
			0xA56E0BF16F6902E9ULL,
			0x76C87EB50FE23345ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x6D0BDC3EA3EC43F3ULL,
			0x4AD149E127DB0AD2ULL,
			0x18ECDBD2D97C322BULL,
			0x22B954847AD66FBBULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD10BE46F0465DE2DULL,
			0xADDC2CBCCE25E12CULL,
			0x2B46A80F457A74B4ULL,
			0x0624BD23B39E9A73ULL
		}
	};
	printf("Test Case 358\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 358 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -358;
	} else {
		printf("Test Case 358 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xD1FF7023022E8C38ULL,
			0x603AA79D59203C46ULL,
			0x265705C7D913681FULL,
			0x6B91F1EBF5C0D821ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4BE144B4D163CFF4ULL,
			0x8A556FB8FB987C22ULL,
			0xA083A26459B1EB5FULL,
			0x5ADED11AEABB5F05ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x7F281A8FEFC3F008ULL,
			0xB4C2F816D695E3ADULL,
			0x94F091802AA46EAAULL,
			0x4853C5E6F22B7893ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xC43548952F03C592ULL,
			0x91F583A3C547D09DULL,
			0xE8CEDBAB48D5B17EULL,
			0x0CA37A5F12823032ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x936109E479DD977FULL,
			0x88A428D1951628E9ULL,
			0x19187EBE6D755746ULL,
			0x530ADAD36DA16CEDULL
		}
	};
	printf("Test Case 359\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 359 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -359;
	} else {
		printf("Test Case 359 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x7A69C1DC2DB88000ULL,
			0x6D2FEE6D526ADB4CULL,
			0x4C4706A5F8F29641ULL,
			0x67049546F60B1F94ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x6DD55B630F904844ULL,
			0x3256518902262EF4ULL,
			0xB38106CFD5FE2C22ULL,
			0x5663F59AA5F9263BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE4DCCCD34AEAC850ULL,
			0xE0C3B707D49E1F2FULL,
			0x5597D962D116B667ULL,
			0x54446E8537E63B40ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xDEDA4114A33CA5D0ULL,
			0x05AF87A55E79B083ULL,
			0xDA90DF8F49FFAFF4ULL,
			0x24D42813CFA2240CULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x8CB2280090E07DFEULL,
			0xAAE0404258328FFBULL,
			0x2E2C161CDC680936ULL,
			0x3B149B0DDB018ACFULL
		}
	};
	printf("Test Case 360\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 360 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -360;
	} else {
		printf("Test Case 360 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x769A45314056AC48ULL,
			0x138DAC36B2A068C8ULL,
			0xEC162427D83967F2ULL,
			0x72AB6ECBB7F11EF3ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE647C265BC6F7BE4ULL,
			0xDDBC9C7B885BE2E3ULL,
			0x96CB34822844DB1FULL,
			0x04E73BE8A2A3D627ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xBBDF97152D18FBB8ULL,
			0xE5FB72D5E0B05FD6ULL,
			0xE5A93AED7387A09DULL,
			0x5A27A043D66596AFULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x274858A49A69E890ULL,
			0xB2EE2B4B6D2409D8ULL,
			0xAD44111135B7C775ULL,
			0x2D1A42AA5ED3EFA7ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC227F4A2BA638BA0ULL,
			0x86E1903F80B514A9ULL,
			0x2DAB84C4AA08D6FEULL,
			0x76E0B6934F34AD68ULL
		}
	};
	printf("Test Case 361\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 361 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -361;
	} else {
		printf("Test Case 361 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xC050BC502CC43A50ULL,
			0xBE1FCF96D32EF72EULL,
			0x97CDBFB2393EDA71ULL,
			0x563F228984970FE7ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xC88F2275FADCC071ULL,
			0x77762AA06C73C3E0ULL,
			0x5450D73BE3EAB0CCULL,
			0x325AFE5D050E05DCULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x6FC8277786E62638ULL,
			0x5F56F32E616AC7B3ULL,
			0x941EEAF18DAC459AULL,
			0x5BA22D72485BD4DAULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x13668C485BC198AFULL,
			0xEEB1383FE9A4CA80ULL,
			0x9EE98BA21C96F28BULL,
			0x27D853DBB824DAD6ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x45B0815AC5CF3FDAULL,
			0xDC8E1A07EB824D9DULL,
			0xA91DCA47BED9B607ULL,
			0x36EEF2F61E2DD930ULL
		}
	};
	printf("Test Case 362\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 362 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -362;
	} else {
		printf("Test Case 362 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x43C6B2F937BBF198ULL,
			0x54D991A134E0F9E9ULL,
			0x7A3AB3D760784349ULL,
			0x7EAEC4596A7F0830ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x2C9A5F6B002930F2ULL,
			0x4ED5373C5DF0CFD2ULL,
			0xF9C8853F3FDB6E49ULL,
			0x3AEE6BD498E4606BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x76DF1BB7E8E67EF0ULL,
			0x82C1C105EDB1479BULL,
			0x2069DA890E441895ULL,
			0x4D19B9BEDC8C6DCAULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD623D1AF7F90C191ULL,
			0x6F45852DF8672117ULL,
			0xFF20E7290D7DEE56ULL,
			0x074D1E064F4FBAC7ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE6307612F76830F9ULL,
			0xCCF267FCEC07C7B6ULL,
			0x167D6294FE62499AULL,
			0x1B02BB70D60FECECULL
		}
	};
	printf("Test Case 363\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 363 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -363;
	} else {
		printf("Test Case 363 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xB90353C693A19DB0ULL,
			0xEE8634409C1094EEULL,
			0x473A194DB8CD1772ULL,
			0x7874DF1391A64C6DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x55B8262C421145E2ULL,
			0x8FB5830092C00DC1ULL,
			0x4803A58857C5D28DULL,
			0x7773CF40F37C2102ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x111533CBCAFBFD18ULL,
			0xA93F91FCA615DC60ULL,
			0xB8663975FD162F00ULL,
			0x4BD37067D49A05D0ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xFFFA525C398561B8ULL,
			0xC1CAFEF20F36EDF2ULL,
			0x76FB7715F58F9236ULL,
			0x1530BE73D5CD6A23ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x6753EDD595D6D65DULL,
			0x8498F6EAAB8C92FDULL,
			0xDFA736E47DCED3F2ULL,
			0x0641CE4FF63224BCULL
		}
	};
	printf("Test Case 364\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 364 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -364;
	} else {
		printf("Test Case 364 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x6635B2F1C9081FA0ULL,
			0x53C8B0EE7767A85DULL,
			0xB425B1A9A71FBE9CULL,
			0x6DB78737C18668D1ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x3A44FE72CBD258E2ULL,
			0x45DFA03CC101A1A3ULL,
			0x303271D98E9593A7ULL,
			0x6F604422934125FBULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xFFBBBBD50C244D68ULL,
			0x537FC14338EC03DFULL,
			0xA0060C0E5A83ACD9ULL,
			0x444F71F30A99F90EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1B4B4C6B0CFE114EULL,
			0xCC350845B568EEA2ULL,
			0x2623DE990E04E844ULL,
			0x62C5CF7B3CB74232ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x9EF0DC117C0568ADULL,
			0x7F1F3804B8799980ULL,
			0x406EEC82465BAF4BULL,
			0x05532DF644A19BDDULL
		}
	};
	printf("Test Case 365\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 365 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -365;
	} else {
		printf("Test Case 365 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xD7F431149606D688ULL,
			0x48278398B78184ADULL,
			0xC25F8550E4F4CA37ULL,
			0x70A437C351B0A001ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x6D5313867799BD57ULL,
			0x00B4B3476459A9E6ULL,
			0xF6C1220710DE4292ULL,
			0x330C606E77D1734CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x42BCB5BC782323E8ULL,
			0x3E601E19EC34AE70ULL,
			0xA02FD9F89A6BC116ULL,
			0x5F17DE807FD45678ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x45115F6BB05D31DAULL,
			0x33BF7F48054B39CCULL,
			0xC7231E25F81805E9ULL,
			0x3F5E84C5DE519A8DULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x293B3F010135C899ULL,
			0x4060B04F26C78D4CULL,
			0x056C36C5FA78C883ULL,
			0x626834EB2D027F33ULL
		}
	};
	printf("Test Case 366\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 366 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -366;
	} else {
		printf("Test Case 366 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x78BA145982655A50ULL,
			0xCB8EBA114C5F31F2ULL,
			0xC442120F38624769ULL,
			0x7B4D3D87FC9F1D9EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4C0CE6C1D637119CULL,
			0xA29B516F6A68CEDBULL,
			0xCC1EED36F45715DFULL,
			0x36756CC0A3EC58EDULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE790FFFBF4A84D60ULL,
			0xFE416351DD02DD4CULL,
			0xF7E92C5DB5672F49ULL,
			0x620CF11F73FBF2B8ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xDF5171E7324F2E57ULL,
			0x0B964AD65CE27563ULL,
			0xFA283EBBF2A46BD5ULL,
			0x13456B86B6F69DAAULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x0D2DE0A02C8F5171ULL,
			0xE812C43FDE2F6948ULL,
			0x6898594D1AE5BECCULL,
			0x26DD5CDCE1FB008CULL
		}
	};
	printf("Test Case 367\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 367 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -367;
	} else {
		printf("Test Case 367 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x25BC90A6ECA746E0ULL,
			0xF5D1633DBE78C335ULL,
			0x43B63DD99055C55EULL,
			0x4B1EB4E72D415637ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x19AE6F8CC8377408ULL,
			0xA125BF4DEEA6ADD3ULL,
			0x0EEBF1241F9B3C95ULL,
			0x28DD731187FF74F8ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x8AED981EDE3CD318ULL,
			0x014B95F1BD1E06A1ULL,
			0x8CC630206FF8CDD0ULL,
			0x59D6F9A7E5F78D5DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x068555F7CD6814C0ULL,
			0xB32B6A0BF69474E6ULL,
			0x7BBCC41243E002C8ULL,
			0x702EBDC8E7D2A234ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xDC28A3703EE77901ULL,
			0x12E71836C25586ECULL,
			0x5061FC4CE1FC5DD2ULL,
			0x79540CA0478A5884ULL
		}
	};
	printf("Test Case 368\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 368 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -368;
	} else {
		printf("Test Case 368 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x6B652ECD5D329270ULL,
			0x719DFB7EEAC81CE1ULL,
			0xBDDA08E4B1593A87ULL,
			0x5384E3F91DE4049AULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x04D2171705DF4F07ULL,
			0xE3176A33FF5B80ABULL,
			0x2A918697630D2163ULL,
			0x478F5FDA609C8D83ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9DAA2CC87F024058ULL,
			0x8102EE4AF8604964ULL,
			0x5FF6185B293F2B54ULL,
			0x6B38C0025AAD769BULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x4818714590E23279ULL,
			0x017C6911E76522E6ULL,
			0x2216758B94502B8FULL,
			0x29402AF72AF5554CULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x905ACC36686DE9ECULL,
			0x69B99AED14FD530CULL,
			0x7B77AC4B94BF22FBULL,
			0x669AC8D04E395679ULL
		}
	};
	printf("Test Case 369\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 369 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -369;
	} else {
		printf("Test Case 369 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x3CE77204576E0BE0ULL,
			0xE69468AC444B4694ULL,
			0xF110876B3A796531ULL,
			0x44E31D1FCCB18446ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xBE1BF8B7D9D98477ULL,
			0x863A26E00323DE56ULL,
			0x7459BB2B0A7DB869ULL,
			0x1EB4D30E557D9EECULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE0D07168DFECAE58ULL,
			0xF43602D7D6FC84ABULL,
			0xC596928FD727789FULL,
			0x4C03DE29A66A2021ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1B49D602A36CDEB8ULL,
			0xB0E796731D615A49ULL,
			0x33D85B80B4C4CD87ULL,
			0x25B46E100CAA4ABEULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x8D6AE099CB281812ULL,
			0xB166C0BC8194D63BULL,
			0x3707C09C58F6D6E9ULL,
			0x53DDC1CE3D3BEFE9ULL
		}
	};
	printf("Test Case 370\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 370 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -370;
	} else {
		printf("Test Case 370 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x0F2AF774F71DDD80ULL,
			0x04B886C3DDE40241ULL,
			0xC194F2412B4673B5ULL,
			0x4AE5C32875522A84ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE1231CB0A49F1CD8ULL,
			0x3056A3CB2BE7991FULL,
			0x0E6E2ED24ABCC62AULL,
			0x4ACA518435E1AF21ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x5CEADD00D8EF55F8ULL,
			0xB2E253DD80DFF73EULL,
			0x95D8C7115C7A20D2ULL,
			0x7098C02387AB51DDULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x0601E24F822D069EULL,
			0x4D9FFA4701743075ULL,
			0xF9CB9F94F804C069ULL,
			0x0B5BA747447F69A4ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xBCDF52F150F81266ULL,
			0xA21A0403AE128FB3ULL,
			0xD4714D0BC4B169BAULL,
			0x2FA1DC91A30B2680ULL
		}
	};
	printf("Test Case 371\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 371 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -371;
	} else {
		printf("Test Case 371 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x3463FB424EC489B8ULL,
			0x0A63E2A9B6E533BFULL,
			0x2A00054979E52897ULL,
			0x479F310D06FEDB88ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5EFEC20CE492DC18ULL,
			0xE168A4CCE802C951ULL,
			0x1B3DBA739661CF0BULL,
			0x7B2D490824F37CD5ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x39AA93999C8DB550ULL,
			0xBDF81882988EA038ULL,
			0x80478FD117ADF4C6ULL,
			0x7C91DEC398842B97ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xDB7EAA086C3560DFULL,
			0x8F172F2ED7CAB72DULL,
			0x676E4F88E5BCAD02ULL,
			0x28C8FABC98718A33ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF4E770955BF4FF98ULL,
			0xEFF9F73AB5DE247BULL,
			0x2A7AEFE1B135273DULL,
			0x326EEB9C33EE681EULL
		}
	};
	printf("Test Case 372\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 372 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -372;
	} else {
		printf("Test Case 372 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x0DC457CBF89217A0ULL,
			0x6E4898872B7039DAULL,
			0xA69BEBFCCC4C7E06ULL,
			0x4039D38377F9FC74ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x1F4C933F07ACAB4CULL,
			0x14F55FA6043BFFB4ULL,
			0x30A3303B5D0E9FD3ULL,
			0x36D81A2BA4BB8DA4ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xAECDB1AAAFE8F9F8ULL,
			0xBED9646DDAE0B279ULL,
			0xB3546083538670C5ULL,
			0x70964E8C4B3AA938ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xCCD03F4655C8162AULL,
			0x6979CD094B208B24ULL,
			0x1459650000FBE6D5ULL,
			0x0DD1E0F0E51476EDULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xDF0D2D4D08B47F22ULL,
			0xCC1243A37191EDD0ULL,
			0xA216F4F775C3A335ULL,
			0x68DA911338FB796BULL
		}
	};
	printf("Test Case 373\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 373 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -373;
	} else {
		printf("Test Case 373 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x80B66664848B80D8ULL,
			0xB3113E18E21AC30FULL,
			0x65456003DAEA1CE2ULL,
			0x49A5B5EEAC3E3A64ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xC15A046E06009909ULL,
			0xD2E2EF3E3772FA44ULL,
			0xC865C0C0E653D882ULL,
			0x4D0A560911327A9EULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x66FF266A8EB5C7B8ULL,
			0x31FA1250DBB1F0ADULL,
			0x8B4C5121D8020C4DULL,
			0x58528C7DDCEF2DB4ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xCCBA257F664337F6ULL,
			0xB58E9E0736EDBDF0ULL,
			0xA7E129D95DC6B3ABULL,
			0x5DF22F888337505EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x96F6A7E8B7B1C9BDULL,
			0x0AAAD5E0CF17D3A7ULL,
			0xF323E84BAC4563F4ULL,
			0x3AF11819AE0F6CAFULL
		}
	};
	printf("Test Case 374\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 374 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -374;
	} else {
		printf("Test Case 374 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x660438FE2F8E0F28ULL,
			0x90F6E2A6EC71016BULL,
			0x54CA144DF074660BULL,
			0x5DDA9D8991AC2841ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE07C3686F2E6DA48ULL,
			0x9288C98DB8DFB558ULL,
			0x1E8BC5627D3A2756ULL,
			0x18CF06A849FD705FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x69BC48AED1C66888ULL,
			0xBACFE1BA5E49EB1EULL,
			0x569BB172B67B72E5ULL,
			0x4C2747B4376BD077ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xDC95E04E13992A15ULL,
			0x436472607FA734FCULL,
			0x15F10DA373CEC575ULL,
			0x61DC8EC9596A7020ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC5642EB95E819F51ULL,
			0x7A7817BE424D6240ULL,
			0xC973C673BA391EABULL,
			0x5D07470B42A43434ULL
		}
	};
	printf("Test Case 375\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 375 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -375;
	} else {
		printf("Test Case 375 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xCCAA9A64CB160D98ULL,
			0x5A13816EF29BC360ULL,
			0x146377022DDE775EULL,
			0x42A07C1F00B6D00FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x741AA9F5FF8E5C11ULL,
			0x1DE7938237020FABULL,
			0x0EDB8D8310727499ULL,
			0x36863821101B2183ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x73EF6392759AE810ULL,
			0x3F0B955AC719A7A9ULL,
			0x01B213DAED2FD042ULL,
			0x7925E08F9458439EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD32C36350BC91346ULL,
			0x2651914663BDFB33ULL,
			0x2121F1B2BF961FF8ULL,
			0x6848C527B63A2BF4ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD494FA0926C255E4ULL,
			0xD360BFD08722299DULL,
			0x8C4B426BE7E077ACULL,
			0x1781D97638084679ULL
		}
	};
	printf("Test Case 376\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 376 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -376;
	} else {
		printf("Test Case 376 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x1E2366AF6CA50C30ULL,
			0x45D70F555DFB7D13ULL,
			0x483F3D5BACBD6BCFULL,
			0x67740B00533062ECULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x2F0BE09B5E9FFFF6ULL,
			0x8BDF5BCEA57B2D0AULL,
			0x4862FCED59BF0088ULL,
			0x336333A59AD346DBULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC730BDEC0847C388ULL,
			0x46C9B662027FB08DULL,
			0xC654DC183E3AACC3ULL,
			0x606B476A4DAD60ABULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xE706E099851DCA11ULL,
			0x8B82C3E5653CEB45ULL,
			0xF0AF6D71062EFC4DULL,
			0x6FD3173283D403EBULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE0315009A495D6B1ULL,
			0x16DA90126B386CBAULL,
			0x8E8629F49B40F7C3ULL,
			0x47F458F57EDA63D6ULL
		}
	};
	printf("Test Case 377\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 377 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -377;
	} else {
		printf("Test Case 377 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x6CD0CBA2E7536648ULL,
			0x8E1BAEB2953994CCULL,
			0x69E0EA6A5DD51811ULL,
			0x545BEE2806D94A82ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x00412C155CFAA58DULL,
			0x86D7137B62C06561ULL,
			0xA647137108E68C3AULL,
			0x7F0F25DACA457138ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9D94FD6281054A90ULL,
			0x2D0F5FBBCF3D2A9CULL,
			0x562DF9E80BE99C06ULL,
			0x7157E3528AD22DC3ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x2EC8480B30A07D50ULL,
			0x7BC6CBD9C124C0B8ULL,
			0xB6F7F586CC0E0183ULL,
			0x15C1DCE00F696CE5ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x1D20AC7234F4E1C5ULL,
			0x83EB2F3970EC2376ULL,
			0x7DE1E6C2F46463C4ULL,
			0x57AA321EB04994FEULL
		}
	};
	printf("Test Case 378\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 378 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -378;
	} else {
		printf("Test Case 378 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xC31CCE35018D49A8ULL,
			0xACE5986693932327ULL,
			0xEA02E58506E38AD4ULL,
			0x48B3A588691FFB91ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x2F3BBAC9BDE5A95AULL,
			0x329774F56695971BULL,
			0xE872DCFE1E7F139CULL,
			0x559BD284791B4B8FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xCFA852FF64BFD398ULL,
			0x16F56931F8FA61C1ULL,
			0xA0BAD175AE14CEE5ULL,
			0x400E2511F1C7C36AULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1F2172A8D41BFFFCULL,
			0xE5E6CF62A16B48A3ULL,
			0xF6A7FFC57B165D3BULL,
			0x06259FFFB3548B58ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x5D3CF47A93ACC882ULL,
			0x31815A00E44B497CULL,
			0xBE09E6243C087FC4ULL,
			0x639B7921161B3ACEULL
		}
	};
	printf("Test Case 379\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 379 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -379;
	} else {
		printf("Test Case 379 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xE1B692C4A6A59DF0ULL,
			0x61359CD8D6863F75ULL,
			0xD794B1A5622831B5ULL,
			0x75D8D27846B391F3ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x13CAC8FFAF5B21DAULL,
			0x11424E387FB7A7BCULL,
			0xAE53FA10DE520D93ULL,
			0x0BECEB875C4DC14CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9E19FD6A9727F578ULL,
			0x74F4B0D0FFF10D15ULL,
			0xF9289134ABDB4180ULL,
			0x5C940DD59C3F25CCULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD49D08ACA419C965ULL,
			0x35DD407710A0F124ULL,
			0xAFD9162FC18AB398ULL,
			0x2040B0D11DB99C73ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x2579CBF936AA101AULL,
			0x66A7EB3B646B9FD4ULL,
			0x504CB02C3886DC54ULL,
			0x675718B5B9AD7C4FULL
		}
	};
	printf("Test Case 380\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 380 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -380;
	} else {
		printf("Test Case 380 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xA925BEEEA91073B0ULL,
			0x2132D80518DDF77FULL,
			0xA1295DC3300FF9E4ULL,
			0x7DD9A59E39573259ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x3B1E803619A10B7FULL,
			0xD82025994C78FE2DULL,
			0x64B5D9E62009A42FULL,
			0x251544468A9904CBULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xAB2C80667CCCB768ULL,
			0x5C5DC0D98C9A9DDCULL,
			0x986A53F7508929B1ULL,
			0x64272FEB109E303CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x897C2000057FE281ULL,
			0x4B3766FA0060BCF9ULL,
			0xC49F56986CFDDFFBULL,
			0x6673AEDDE092C8B9ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x21599AF8C41CF35CULL,
			0x2199BCB6AB1C1E5EULL,
			0xD63AF228FA0AD50BULL,
			0x25D414005ED7B427ULL
		}
	};
	printf("Test Case 381\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 381 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -381;
	} else {
		printf("Test Case 381 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xFBBA3DB092079B50ULL,
			0xF9C45F842CE9A3EEULL,
			0x5778A7089CF66735ULL,
			0x5E746B6A366CD82CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x2B5EC6DC68D8C129ULL,
			0x8E272AD6653F472AULL,
			0x1F0878071CB7FBD6ULL,
			0x5ED0248178B02D86ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x52E4532CD6FAE4D8ULL,
			0xB82A18EEB1DE1D08ULL,
			0x2CADAC11BF39D9BDULL,
			0x5D447CAF98093B27ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x182A2A41F2AA0D30ULL,
			0x5FE545243DA25D96ULL,
			0x194DBAA7AC33EF87ULL,
			0x26063690033277E9ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x01296C16D7558C62ULL,
			0xC505930D90EB071CULL,
			0xFFE0C33C1336B9D0ULL,
			0x323517D22DDBB0DDULL
		}
	};
	printf("Test Case 382\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 382 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -382;
	} else {
		printf("Test Case 382 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x29059CEF65063198ULL,
			0x1458F6364E4E3C4BULL,
			0x8D7DAF71731D34FDULL,
			0x5C9AB4CF621A8B06ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7C34F2529DF2C3A4ULL,
			0x4717B684AA7BAB22ULL,
			0xD02729E21BDC5C87ULL,
			0x505BE3AF3174253BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x58CA3E20644F8BC8ULL,
			0x063021946128D7F7ULL,
			0x927C16F29282595DULL,
			0x4A564D8DAE209687ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xE0EAD475DE8C251BULL,
			0x0AFDF1641B18FB72ULL,
			0x44F1182516AE3DC5ULL,
			0x5DB3421C5EE0F117ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x51AC68CB75C0AA16ULL,
			0xB95396B47845C6C8ULL,
			0xD7299C8E9FA4DF55ULL,
			0x45ADEDD6B788CE59ULL
		}
	};
	printf("Test Case 383\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 383 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -383;
	} else {
		printf("Test Case 383 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xB00491C1B17D6170ULL,
			0x31319FE7BC9EE840ULL,
			0x82D603D7170EC067ULL,
			0x63FBC2C3FC608759ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x856819414F97E9CAULL,
			0x5647C1CB39D2AF52ULL,
			0x2E847ECB77557D26ULL,
			0x5F4EC9204B8B61FBULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xDF072FDB3576DA20ULL,
			0xE323626272838A34ULL,
			0x71F2D51C27D259FAULL,
			0x46B78D11A214CA5AULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x8FA8DF2E21D8ABC0ULL,
			0xAB003B5AF21816E1ULL,
			0xB1DC5FB60951FDB4ULL,
			0x2F7240DB3E2EA654ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x03B575B8046B02BDULL,
			0x1EC0DF67F5729B7BULL,
			0x854443758E4CC40FULL,
			0x3FD7F4A8A44A1D80ULL
		}
	};
	printf("Test Case 384\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 384 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -384;
	} else {
		printf("Test Case 384 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xBF7C799F5DE905F8ULL,
			0x5A2AB2C2613C9039ULL,
			0xDD3FA531B5293DD1ULL,
			0x5DD08FCD938DB4D3ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4050633685D28C55ULL,
			0x7686C4D721F90DCAULL,
			0x02ECEC8A050BBA16ULL,
			0x03FC3F6A119A851FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x5BE24F7683175A68ULL,
			0xAA41BEB40424473CULL,
			0xD393F43774FC161BULL,
			0x41BC6AB41AF39FC0ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xBAD873F1A9298EF4ULL,
			0x07EC5D46EB17B98EULL,
			0x78678F5ACA9AA3FAULL,
			0x7D348D1CC3BAC1D0ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x9FC5A344295A1B85ULL,
			0x044D6AB5F7E70AFDULL,
			0xE94853E09A00B425ULL,
			0x52061FE0731D0D4CULL
		}
	};
	printf("Test Case 385\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 385 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -385;
	} else {
		printf("Test Case 385 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x7CE3A7CFE83FF3E8ULL,
			0xFF053B3346E73DDFULL,
			0x110C3C43C083BC2BULL,
			0x55478174BC99FD39ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x738C687F80D8266EULL,
			0xBD7FA9E6AD096314ULL,
			0xFB5529583C773BC0ULL,
			0x2379CB2964B9A686ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x264B545B5DB60560ULL,
			0x3DFC82C6D2BE2C94ULL,
			0xCD7291C059854B77ULL,
			0x56C5E852B977D632ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x986C9DB6BF043249ULL,
			0xB6C49A27CEC4394FULL,
			0xCA217462296AADACULL,
			0x5A18EF317AA6057FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x9E1706B34F5E83C6ULL,
			0xDC1D3F2066AC3C18ULL,
			0x44650006EB0E9FE6ULL,
			0x76CA656FDBA766C6ULL
		}
	};
	printf("Test Case 386\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 386 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -386;
	} else {
		printf("Test Case 386 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xC45242B1B627DBD8ULL,
			0x8FCB372DEAF1AFA9ULL,
			0xB63A749F7C94D6C6ULL,
			0x523EF79CB83339CFULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xDBFCD38895310CE8ULL,
			0x50400826E6F9D878ULL,
			0xF7279C9ECBF55A5EULL,
			0x794B36C35E159699ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x3918D6AD99BF89F0ULL,
			0xED39276B8FB22E20ULL,
			0x6DBE68C41F300076ULL,
			0x4AF42CA148416076ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x18C432B129858D81ULL,
			0x2E7515B04D3A6E21ULL,
			0xF99AFF60A2F2D405ULL,
			0x24BD49C48674D5A4ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7650C953A4F1442EULL,
			0x6E1CDC9788AAFF95ULL,
			0x59E31216D3963670ULL,
			0x71FEFFBCDAD387E7ULL
		}
	};
	printf("Test Case 387\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 387 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -387;
	} else {
		printf("Test Case 387 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xA17873854CE6F2E0ULL,
			0x9342114B7B148941ULL,
			0x17342E5E252EE3B7ULL,
			0x5CE6387640205149ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA046554313F8C0C4ULL,
			0xD77B71EF6037F9ACULL,
			0x83CD9520B2578A9EULL,
			0x5A7EDD900818B94CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x3F123946B2438B28ULL,
			0xF3E7A2D047BD39AFULL,
			0x62D0EA967671CA18ULL,
			0x496174E96D7D3DB8ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x92D2C6EDDD7485A7ULL,
			0xAE89C6B72AE0CBF2ULL,
			0xB1E342B3C609BB97ULL,
			0x3A3B986E54096EC0ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE3D65AC88F81C5B4ULL,
			0x2214A9C475D234ECULL,
			0xB057F6D4DA825FAFULL,
			0x4ED5829E179553EEULL
		}
	};
	printf("Test Case 388\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 388 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -388;
	} else {
		printf("Test Case 388 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xA811A1965D913C98ULL,
			0x2328877E7CD9655EULL,
			0x406E457095F4A36FULL,
			0x7E2BAB5E8BF9E4D2ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x104FAAA3D6971BF7ULL,
			0x0CD0F40856767456ULL,
			0x2986A74F2E59F272ULL,
			0x2252678A82D33354ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB9D65BF96ED18DC8ULL,
			0xDAA153EFCA2776EBULL,
			0xB852D24585A63BF4ULL,
			0x55BC927A778D89C1ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA66A5D68C0768CB8ULL,
			0x41B05C87E842A360ULL,
			0xA92E06FDB18C11CAULL,
			0x211AEF40529683F9ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x3A70A18701C5BC42ULL,
			0x569E4C905C3BA1CCULL,
			0x4A4B98B9CE450D3BULL,
			0x12D17AA616888472ULL
		}
	};
	printf("Test Case 389\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 389 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -389;
	} else {
		printf("Test Case 389 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x4BC2F675D361F878ULL,
			0x472881C4D25E769DULL,
			0xF34DE5936E2E7CBBULL,
			0x63DC1E63ADD3A9C4ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xFB5D09568404CC08ULL,
			0xDDE7F9DE07EACFA9ULL,
			0xD0730985DC135417ULL,
			0x6411BA0BB1505650ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x8875EF56C0927DD8ULL,
			0xC95B6CDC99A70A59ULL,
			0x61FAF692ECE31DD7ULL,
			0x76AD75446ED81663ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD1D625B3933CCD8DULL,
			0xFC689AECA01444A3ULL,
			0xE183FC1001DA19DEULL,
			0x738BDAB2926F413DULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC6A1E30C95D1D8A2ULL,
			0xE8D69FAFE547B56CULL,
			0x0DD859E02336661CULL,
			0x314046B06DE2DC72ULL
		}
	};
	printf("Test Case 390\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 390 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -390;
	} else {
		printf("Test Case 390 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x7D0B2B78C8572B80ULL,
			0x833D9445A90F0A13ULL,
			0x94D2A50EC2CB2973ULL,
			0x6FA4CB3345930ED6ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5806B0D0F9835B5EULL,
			0x4CBFF2ABA21C42F2ULL,
			0x2DAE8D9326F95B3CULL,
			0x7D42B9EF3AD60831ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x8DC42286D38F3810ULL,
			0x1AFE1BDBA0449CDFULL,
			0x2D95D8416FDF4570ULL,
			0x4D8C74F46C7F830BULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x2EC61430A964DC8BULL,
			0x87F20E7F81245F97ULL,
			0x95DABFAC17698B16ULL,
			0x52B530A86B72FFCCULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x956700DD0B7BDBB1ULL,
			0xF6F9BE13EB307DD4ULL,
			0x078D6CC8501DE65CULL,
			0x46525CACAE4BBEBDULL
		}
	};
	printf("Test Case 391\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 391 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -391;
	} else {
		printf("Test Case 391 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x58C615AA85BE6D90ULL,
			0xE674AE9875F586C3ULL,
			0x1E900B5AD1DD2694ULL,
			0x7C92B1F50A21D97CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x6686AB7E1CCE34D1ULL,
			0x8CC919A2217A9366ULL,
			0xFE534D722A53FACEULL,
			0x66842F27AFCC6D81ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE74FC2DC3B00FD08ULL,
			0x35BE1E1253D95D55ULL,
			0xFE5E792032E7E4A4ULL,
			0x6DDB4378FC658929ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xCF2043ADD1FA5A7FULL,
			0x7533F7B82CF7B9EAULL,
			0x7EE97479CB61D9E0ULL,
			0x2B9E2F812B380DEDULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x63195CC8614A7662ULL,
			0x388E5ACDF2BDCD89ULL,
			0x015B51DC62D67117ULL,
			0x3FD2363E80EA6FEBULL
		}
	};
	printf("Test Case 392\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 392 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -392;
	} else {
		printf("Test Case 392 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x000ABCA7D81CCBA0ULL,
			0xADE0B67B8F14BF96ULL,
			0xF12BD42C5E88CCA1ULL,
			0x6A3007BE6DB395D0ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA453CFC4376F26B2ULL,
			0x5F778283224C32A1ULL,
			0x3A293AFAEB06D0D0ULL,
			0x5CCC12D9F1A057C8ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xD424F02878469920ULL,
			0x5C570D18500FF83EULL,
			0x48E21180028AC695ULL,
			0x708D7C0B9518E211ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x7904276FE5E87A9BULL,
			0xAC9A1BB53B5DE59AULL,
			0x097F1EE4228C66DCULL,
			0x1C5FD5897147EE20ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x1646AB2FF541D8A0ULL,
			0xF32C4231B34E9A12ULL,
			0x24FBDCEFBF794BC7ULL,
			0x43726E1F5006709CULL
		}
	};
	printf("Test Case 393\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 393 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -393;
	} else {
		printf("Test Case 393 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x380AEE1383D2D5E8ULL,
			0x78A136342D244AC5ULL,
			0x95CB6DB9D008E41FULL,
			0x793C1B22EB782AC7ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE9AB04338255030DULL,
			0xE1D66521A16749EFULL,
			0xDABBD3ADD3D0A914ULL,
			0x6580FBE71E0FFD58ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x72EC2AD2DAC9F458ULL,
			0x64B54C2DC96140C3ULL,
			0x83D8BDAB419C0603ULL,
			0x77AEFCAC8B4831CFULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x11D150586FC30DBDULL,
			0x19BF2CCE5AC9605BULL,
			0x3E42BCFD89891F39ULL,
			0x7EA239B96693E23CULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x4B2D0EFEFE0E22C7ULL,
			0x9B2705C9D857874CULL,
			0xE4A75CD4422FC1A9ULL,
			0x1333727D2CDB2866ULL
		}
	};
	printf("Test Case 394\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 394 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -394;
	} else {
		printf("Test Case 394 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xC12788BF8B93FAE8ULL,
			0xF4DD37BE57AB74ECULL,
			0x715190A330D1B177ULL,
			0x6290D2EA655D66C5ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xBE78CCE15C8E74EEULL,
			0x8817166CF65C0384ULL,
			0xC80D46FCFC1C2E3EULL,
			0x7CEC47AD8B0AB8D3ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x65E0152D02FFA2F0ULL,
			0x6AE75FE31CF2A071ULL,
			0xDCC993B9ECC55965ULL,
			0x7294CCFBA5762393ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xC18420B55085592AULL,
			0x86B61E8C3415D292ULL,
			0x74CD92A794B514CEULL,
			0x49CD1EEEE53B4A17ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x4F68A1ECA351A9DFULL,
			0x087CDF026707C8D7ULL,
			0x074177DDDEE35209ULL,
			0x534FBCF7DC1D2D23ULL
		}
	};
	printf("Test Case 395\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 395 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -395;
	} else {
		printf("Test Case 395 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x37B31CE20DB87A48ULL,
			0x4D9ACC8B711E30BDULL,
			0x3F8677CA760927EDULL,
			0x537C1C0999377B1EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA5C8B02753C61CDCULL,
			0x8314A86839AE0226ULL,
			0xA133D8CE607F607BULL,
			0x22B957A729292A91ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x4A5BC9FFAC9F5660ULL,
			0x60D42A36D1A9DF10ULL,
			0x27BA8D878752A1DAULL,
			0x4A37CD628EE00753ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x9DAF43B56DD88DE2ULL,
			0xB05FD03C56AD3E78ULL,
			0x2FF05AA8B515D130ULL,
			0x2D52C29385E75A36ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA90B30CD416D7291ULL,
			0xAA26D30C21D09757ULL,
			0x90210B552E6D71C8ULL,
			0x2EF57A603F9468AEULL
		}
	};
	printf("Test Case 396\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 396 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -396;
	} else {
		printf("Test Case 396 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xA2165559E2FBA448ULL,
			0x93FE4DA804F52CE3ULL,
			0x301CD445819E9D90ULL,
			0x74BF153CC8CD2A5BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE36742007F476947ULL,
			0x74CA9210E3962C6DULL,
			0x73A6E0E1FCEB03D8ULL,
			0x30872470E4BAB90CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x0065E8A420877768ULL,
			0x1C32A0C5BE9BD8B2ULL,
			0x13EB0B10C6852066ULL,
			0x414A26745F15779EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x11319F3065A1437BULL,
			0xA3636A6B1E6B3D66ULL,
			0x54D5CC2E2FBB9A56ULL,
			0x7381227674809B3CULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB0EBEE4D3AD96584ULL,
			0x4B0A674385208C5CULL,
			0x9E41AEB6404B6420ULL,
			0x3949321E963044F7ULL
		}
	};
	printf("Test Case 397\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 397 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -397;
	} else {
		printf("Test Case 397 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xB46C51DA88897228ULL,
			0xC13AE689FB1AAF9EULL,
			0x2452C89B3DE12011ULL,
			0x62FF80AC5E921848ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xAADF72352CA573ACULL,
			0xB040C3055AA21E87ULL,
			0x177F6BBDF5F1B99EULL,
			0x5ED40A942ADE79E9ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x81127301E9C4BFB8ULL,
			0x83F3300C63FC3498ULL,
			0x608DDDB2DA6259DCULL,
			0x63FBA08CF5CEE0A0ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x3089D05E970F79E1ULL,
			0x154F712655C23A5AULL,
			0xAA301D98D1650454ULL,
			0x0AD8D09011E0353AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE07C5EFC10CF5406ULL,
			0xC110BF0F01F5147CULL,
			0x7EFF83CB43DA5FADULL,
			0x059A33729B5DB79FULL
		}
	};
	printf("Test Case 398\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 398 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -398;
	} else {
		printf("Test Case 398 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x0C7126E1A1BD5F28ULL,
			0x8FB08D594BD11D5BULL,
			0xD2F428403EEABE20ULL,
			0x4A87668D4374265FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5BC40A830549E0F7ULL,
			0x83B579C3A7FE16F5ULL,
			0x8E584C5F87905564ULL,
			0x79B1E7613568B29CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC8D762489C50B698ULL,
			0x68742924E6D1EE1FULL,
			0x6BE49E99A1CAB63FULL,
			0x7BBE8A6FACD32A93ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xE97165BC24DA52D0ULL,
			0x3D67CC6BCB798EC2ULL,
			0x086302E18E6B37F0ULL,
			0x6A04DB38ED400019ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x2B024AE1DB983931ULL,
			0x2823AAA76D8FF6ECULL,
			0x14DB1465370BC44CULL,
			0x384BB299C1465D04ULL
		}
	};
	printf("Test Case 399\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 399 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -399;
	} else {
		printf("Test Case 399 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x19BBA522D1B60878ULL,
			0x9791ECB7A6E24700ULL,
			0x6646CDB0D0BD1E80ULL,
			0x5313CCF32E4F5B58ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x496135D98C6C2FFAULL,
			0xD0B3B6F1FAC5345AULL,
			0xF64FBA6EAE0EE65CULL,
			0x76AFF5824621B2A8ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xD73A7DE5D0A67D10ULL,
			0x9945222957405CE0ULL,
			0x3E7E5EF6E2F6A577ULL,
			0x4031C96034A8AE3FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x9E21BF72D26B47A2ULL,
			0x745D759077921132ULL,
			0x205A00A3C6E9B465ULL,
			0x43A6C4DD2A7A3C31ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x0A5243E29A50E9A0ULL,
			0xD57216BE8563C3DCULL,
			0xD60A20F9F26B93D0ULL,
			0x06CFC2857E3CC4D9ULL
		}
	};
	printf("Test Case 400\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 400 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -400;
	} else {
		printf("Test Case 400 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x3979CE83B071D9A0ULL,
			0x7E4D8E5B6EF1D75EULL,
			0xB8401CE4AD1970CAULL,
			0x6499678FC11DEE9BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5A5CF1B4427B6340ULL,
			0xF41A803A2B820070ULL,
			0x2BA6D0917526AEE3ULL,
			0x5CC02717E0A676C8ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB21C0CF008F54428ULL,
			0x1C5D87B1D3D64C12ULL,
			0x701EC3ADD9D8F4E6ULL,
			0x6BCD0B3AFC1E5A6FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF9ABB23B8EF3764FULL,
			0x5BDD710F9C8B55B5ULL,
			0x5488BE6467E68A71ULL,
			0x6FEC53E48A096142ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xCCE2FD39229F4CCAULL,
			0x3102CEB8836008D1ULL,
			0x52E145DBEEA36EF0ULL,
			0x5D6B56B40049A73BULL
		}
	};
	printf("Test Case 401\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 401 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -401;
	} else {
		printf("Test Case 401 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x78B2D72BAE6ADC78ULL,
			0x290A66BCDE4A1B4CULL,
			0x3255CECF38D37703ULL,
			0x733310DE80D304D6ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x664C736783503A92ULL,
			0x9D90E40A95BDA86BULL,
			0x5B1F1E4A1E2B276FULL,
			0x4F4A37B9C3C32B8DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x8B181575414C6D88ULL,
			0xC36ADBE31B04715DULL,
			0x985EEE2A83E52EBBULL,
			0x6551A2B6877D568AULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x6A2A6F91320B079AULL,
			0xF7E0CAC3E12E20E5ULL,
			0xC61F54979DD1503AULL,
			0x43EF45726CF3B411ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x721CDEA054C0C37AULL,
			0x92E3029BEF860FA2ULL,
			0x5ED6E466A6F07292ULL,
			0x72C6A83228E37B86ULL
		}
	};
	printf("Test Case 402\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 402 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -402;
	} else {
		printf("Test Case 402 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xECB2E9F791B20908ULL,
			0x8B72308B3A1FE2CFULL,
			0x9206BEA266F943E4ULL,
			0x4152185549FC7985ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x21A75380827BAD81ULL,
			0xDBCD10B69EF0D32BULL,
			0x60C1E126EFD99ECFULL,
			0x56CAE6B795BF9E2AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x79E27BE688025860ULL,
			0xE1544202E8EDFABFULL,
			0x0E08B752E7F3CB8FULL,
			0x6A9FBBC33D2B02CDULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x3971FA5521F353F0ULL,
			0xF101D0F289E0D02CULL,
			0xA9756DC44A8894C8ULL,
			0x565BFC775799B46BULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x5B7DE750CDF32603ULL,
			0xF15F93E1AB6E5AC9ULL,
			0xA8476B2DF14FFB38ULL,
			0x36EC8416C7047B92ULL
		}
	};
	printf("Test Case 403\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 403 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -403;
	} else {
		printf("Test Case 403 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x63AF370B14F8A498ULL,
			0xD08592A61BE203AAULL,
			0x70335E5EC1CA32A7ULL,
			0x48B99F678682BE4AULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x33D919D71313DCB7ULL,
			0x79D48BCF9639D1DFULL,
			0xCFFE785AAC7277D9ULL,
			0x39E1183D5853E60AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x670931C9B1FBCEA8ULL,
			0xAF65875AFCEE9661ULL,
			0x36E9B45EAE38004BULL,
			0x591029AE1CD4D9CFULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x219E6DE8448D4688ULL,
			0xA76B98B72277311BULL,
			0x8DCA431256C8FD3CULL,
			0x7354A51C719F6D4EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE70E2777CF416741ULL,
			0xC1287D930B8A86F8ULL,
			0x0391655F714D8EE1ULL,
			0x478C02E6617C6434ULL
		}
	};
	printf("Test Case 404\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 404 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -404;
	} else {
		printf("Test Case 404 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x1523AD7BFEBF1E38ULL,
			0x2EC2FE6A633ACCA9ULL,
			0x7A7988F1C37A5A8EULL,
			0x71EE3741A61DE878ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xB71C33310CAC853CULL,
			0xE15B89757021F4F1ULL,
			0x01901C64C5D93921ULL,
			0x0F509882AF36175DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xA32BD5CF266F6AA0ULL,
			0xA13BB678AC23461BULL,
			0xEA95EBED380FABCDULL,
			0x79DFDDD4CDD6BBF3ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x0A44D471046686DFULL,
			0xB6791A9C1D6C69CCULL,
			0x83F120D9434D3470ULL,
			0x1C631BB65DA8A94AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x482671BFA051DAADULL,
			0xD9740D33D0BD831FULL,
			0x8BCE82215943477FULL,
			0x5ACB9F7B9EBC3845ULL
		}
	};
	printf("Test Case 405\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 405 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -405;
	} else {
		printf("Test Case 405 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xB566E8365E1FFC58ULL,
			0x8A9EE3EE729503CBULL,
			0x951623E705327698ULL,
			0x7AD114F27A488074ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x36878159F7EAD068ULL,
			0x119CD9D900C279EFULL,
			0x44B853608CD34B20ULL,
			0x265A3CC43245AA9DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC6844B1A04A29E50ULL,
			0x08A8A1A65C8807D3ULL,
			0x2DD7A4750045EF44ULL,
			0x675E2FAF6DB719DEULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x7F06A35E080AE2D8ULL,
			0x9C8F905A56BEB036ULL,
			0x8849E0FF7CCC2E55ULL,
			0x3FD6BF82BFFFD7C2ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x3C71473D5D536003ULL,
			0xC9E7C2CF79BEDB93ULL,
			0x3A2BE88F99EEAE05ULL,
			0x3D711BEB0CBB0BADULL
		}
	};
	printf("Test Case 406\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 406 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -406;
	} else {
		printf("Test Case 406 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xBF03E7656B159598ULL,
			0xB05E51D7A7AE1BC8ULL,
			0x4A608CF1F7C10F86ULL,
			0x7C82B22B49C7C462ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x760C9BA45457ED02ULL,
			0x0A2A9B2A63F7C318ULL,
			0x34D9D984CA1F5714ULL,
			0x4A117EA26CC23DE9ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x47C7F23EFE5E03E0ULL,
			0x765C2D7CF6CA77D8ULL,
			0x85C3CA1423D3A01DULL,
			0x4DFEEA5796EDF196ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA075FB7A1F577486ULL,
			0x51DB29021219353CULL,
			0x100281B020CC1332ULL,
			0x39F29294B9CEC775ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x42962F4E34A7C1EDULL,
			0xAA4B03AB6F97C8F9ULL,
			0xAAD652FE68F92B13ULL,
			0x05959A1C94257834ULL
		}
	};
	printf("Test Case 407\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 407 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -407;
	} else {
		printf("Test Case 407 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xF428DDB41ACA4F48ULL,
			0xEBC58589CAF03011ULL,
			0xF221F17C0E1B94DEULL,
			0x71E85223475F1E47ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5158C92D81040D2BULL,
			0x7C309ECFAE2FA714ULL,
			0x8A52FA565D8B356BULL,
			0x3DB196063501B1C4ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x0ACAA15C6AE43F20ULL,
			0xDC15D4EC13D08355ULL,
			0x3F23C14BC17BBD2DULL,
			0x7FAC0B91372A1CACULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x43A240649A31C03FULL,
			0xB4AA30F303FC4D69ULL,
			0x6B74BB02DD48B74BULL,
			0x5CB7EE113D4F01DCULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x695C2A7E9590986DULL,
			0x41023285A9C4C6C2ULL,
			0x524729D30FD7DEEDULL,
			0x48AB37C5840ED240ULL
		}
	};
	printf("Test Case 408\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 408 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -408;
	} else {
		printf("Test Case 408 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x1D84DE3F88BBB9E0ULL,
			0xAAD40EAB4C7B7FD4ULL,
			0x9093C61711DC88D6ULL,
			0x7924A698BFE85FE9ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4B866B31C42DA4EFULL,
			0x49AF0AB0FE8AE3EEULL,
			0xD770D21F77FAF143ULL,
			0x281049106B025B87ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x8B9995B7AF26D690ULL,
			0xED2CBF63AD7DBA7CULL,
			0x2921E5184B6CE2B2ULL,
			0x7AF568C23A44C51FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x6F16FF1ED846DF94ULL,
			0x09D4F8FE53EDEB4AULL,
			0xC0A38F38FCCAB76AULL,
			0x385EAEF2608B44D5ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x62CBDF577A081572ULL,
			0xFB401B70719365FAULL,
			0x2CFAC088B479F425ULL,
			0x06F6261EAA9B72C1ULL
		}
	};
	printf("Test Case 409\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 409 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -409;
	} else {
		printf("Test Case 409 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x8F17AADE2C0E2D18ULL,
			0xB88832B70DC9D99AULL,
			0x6F0358D2C440480CULL,
			0x53583B52096BBC76ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xB1E584555E6E1FC1ULL,
			0xE4A2EFCBE16D8F44ULL,
			0x270E77BD20009E6BULL,
			0x1889E46C471B35E4ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF9F8E8E9D30D2570ULL,
			0x27131E651111BF29ULL,
			0xF42E96E380D6B3AFULL,
			0x7353E05D05BB6C2FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA9A612F9B9A884D8ULL,
			0x98B2FE844602B543ULL,
			0x5D7B52F0673B3319ULL,
			0x51134D6F7A1FE1A9ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB3938FDCFC7171BDULL,
			0x7B38C73255F433CDULL,
			0x8C06BD6146C3B2BEULL,
			0x12F21F40E1907E6AULL
		}
	};
	printf("Test Case 410\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 410 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -410;
	} else {
		printf("Test Case 410 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x03D9AA9E86E89F30ULL,
			0x9A70189C43AA035DULL,
			0x3DFAB73275ABE25BULL,
			0x7C7B82D85A5E027CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xBC60CB2AD94B5EBEULL,
			0x3FF3874D697E681CULL,
			0x1AD031F737CB0D76ULL,
			0x393A054CA96BD6B4ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x3EE1A554AB9035D0ULL,
			0xAFE7102E4B766C30ULL,
			0x86AEBDE4DA43AC84ULL,
			0x79F9AE70E22B3E70ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xAF68C35B9EDB5C2DULL,
			0x2C2576A892D0952DULL,
			0x7B3937DF1D6B3480ULL,
			0x6F3CFA4514B84E72ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xABF35FBD53F012B3ULL,
			0xC29AE9910C429A8BULL,
			0x7E243B5F6B5F7F91ULL,
			0x4021B10CB7D09BE3ULL
		}
	};
	printf("Test Case 411\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 411 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -411;
	} else {
		printf("Test Case 411 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xCE73DE8D876528E8ULL,
			0x703FDA8682531278ULL,
			0x3BAE0FF6FED5B6D9ULL,
			0x54F3A79F283F644EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x68D944B67C79FB14ULL,
			0x0AEA0B2B3715ECF0ULL,
			0x84099A970980B053ULL,
			0x512D254130D18C1CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC575B9D81A9DFB28ULL,
			0x9F9E993C85E55847ULL,
			0xB7B621F152EF7455ULL,
			0x512C32BA33082D26ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x162D7918618C1B9CULL,
			0xA5073FD228C11617ULL,
			0xC09944D6FA578CAFULL,
			0x4E89EE3A8985DF32ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x4928D83219967E8CULL,
			0xFD393BAF7559DF9CULL,
			0x7CB303ECAD963E0AULL,
			0x082A19358980AD9BULL
		}
	};
	printf("Test Case 412\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 412 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -412;
	} else {
		printf("Test Case 412 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x52CE21ADC6C13208ULL,
			0xDC46417E1DD1F621ULL,
			0x0D89A9F11A85CB75ULL,
			0x66C44EA2FC2B1BBCULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xBA554963BF8044CFULL,
			0xC09B02701DF90ABCULL,
			0x890FE248025DF6E7ULL,
			0x2E9D7061F27DF1B9ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC81B02AD8324F698ULL,
			0xB2CA915884B94395ULL,
			0xC945697D7C150A01ULL,
			0x56636D7B62708B98ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x9C8B10ADD4396738ULL,
			0xA5CA8E708C2FDEE9ULL,
			0x9C670FA795F006BCULL,
			0x7EF1DF9D5703FFA9ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x67A87B9124BED8F0ULL,
			0x278771E2366C4C43ULL,
			0xFA3ED2ABFA4A1CA1ULL,
			0x6F9F144F4AB4E804ULL
		}
	};
	printf("Test Case 413\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 413 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -413;
	} else {
		printf("Test Case 413 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xF72B49DFC22C0CD8ULL,
			0x29DB1EEC1B8E00A7ULL,
			0xD5E1801C4803CC33ULL,
			0x5D66DBC1BBBBAF02ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x12B58B8296494E6FULL,
			0xDBE055E795D02C33ULL,
			0x0FFB574349E08693ULL,
			0x2BC49970F6F1BD84ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x27F753395BA8FBE8ULL,
			0xD9CA797E93419E6AULL,
			0x7E6EF13D56756F95ULL,
			0x5C6C34347DEBBC1CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x6F4B5F01E6941463ULL,
			0x316821458D5B450AULL,
			0xD140708A3DFC5F6FULL,
			0x14FC424EFC913266ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xAD2736312607B3FAULL,
			0xB0AA8603330AABFAULL,
			0xCD9F764C3C5C0B16ULL,
			0x110685D42823BCC2ULL
		}
	};
	printf("Test Case 414\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 414 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -414;
	} else {
		printf("Test Case 414 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x2C2E267DC05FB110ULL,
			0x138B32416E7FB4CFULL,
			0xBB5A82A5000BA81BULL,
			0x59E6BF4660F57727ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x219FBF1DE701B02DULL,
			0x1C27655396182050ULL,
			0x0D49A3E2AB91EAFEULL,
			0x34C2DDA8E4414B80ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xD77FCCBDDCA21760ULL,
			0xC1C0E3A7ED828C85ULL,
			0x42D27B173EAF9ECEULL,
			0x4F8E0EFF628456E4ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x53DF5B98FCDE66CCULL,
			0xEFF676CAC7287C5AULL,
			0x6A62FD2F2052406DULL,
			0x301F22035E8CB0E7ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xDC5CD23EECFAA6CDULL,
			0xDC4154D938C5CB98ULL,
			0x6C46161F03B2D50BULL,
			0x32A6FBBDD553AD1BULL
		}
	};
	printf("Test Case 415\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 415 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -415;
	} else {
		printf("Test Case 415 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x28FF36687B59CD60ULL,
			0x0B83B83FD9AC80B2ULL,
			0xEBCA253C42B5CE49ULL,
			0x4E74CE66E40A8C9BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x54669D0098F7DFDCULL,
			0x6A720BB1347B3E03ULL,
			0x9F57E724D950AABAULL,
			0x4B94BFD688A82875ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x24972407E8786318ULL,
			0x077789A8304BA7E8ULL,
			0xA66542AC5521157DULL,
			0x7A740F58DEC92F33ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x5BC099045917542BULL,
			0x7A2235AFFF2A4122ULL,
			0xF60E7A2782F84656ULL,
			0x4B7335BFDABD7AB0ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7E4FB162A16438F2ULL,
			0x2FDEAFC7BBECA89AULL,
			0x762ED3623CB51F2EULL,
			0x2EEBA9FDE1EFBA1EULL
		}
	};
	printf("Test Case 416\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 416 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -416;
	} else {
		printf("Test Case 416 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x4B2E08963A7B8B68ULL,
			0xC15BC3857F64CAE8ULL,
			0x1E64034B2AA171B3ULL,
			0x5E9B381EABA880A2ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x97BA0366885EC7C9ULL,
			0xD99D1EDE2235A0B5ULL,
			0x0E1CC7F32017DCEEULL,
			0x618D0ECAEB718232ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x803CB39C4AA7C448ULL,
			0xFB7E638D25E6624DULL,
			0x6ACC75050296ABCAULL,
			0x72D1FEA9C98B033FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF44D2EFCE2A96F08ULL,
			0xEB240AEB1E6EEC06ULL,
			0xFE15A072FEFA8CB4ULL,
			0x45B3DFEB65D904A6ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x81CC71294336E310ULL,
			0xA9426078ED319951ULL,
			0xDB603584BB70D878ULL,
			0x25241AE1B10986DFULL
		}
	};
	printf("Test Case 417\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 417 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -417;
	} else {
		printf("Test Case 417 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x8C02FDA66BC8EDD8ULL,
			0xE92A075A48983F2DULL,
			0xB037797D650D3861ULL,
			0x711AF6C9FAD2EFA8ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xB5AC0F5E6F2AE207ULL,
			0xFFF1C839E594124DULL,
			0x255C7518F79FDC92ULL,
			0x35D7D8C735082D2CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x4200FD559575E788ULL,
			0x95C1ED14647FD659ULL,
			0x577CF28181B2000AULL,
			0x7D46DAB8CAAED821ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xC2E0962441E1F3B2ULL,
			0xDABDB32E912889F7ULL,
			0xC0ABA4504FCF5D0DULL,
			0x6415DAAFF5859D23ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x5B23CAD7AF0CEBAAULL,
			0xF54016E270C7FDD4ULL,
			0x5ACE59780BC1DDD8ULL,
			0x3440FF869FED42D5ULL
		}
	};
	printf("Test Case 418\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 418 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -418;
	} else {
		printf("Test Case 418 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xAD20C5D8672F2870ULL,
			0xA1F470B3BE87F741ULL,
			0x7109E88373C1E6E3ULL,
			0x4B348D06585DDDCAULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x09A700770C46F983ULL,
			0x7758264693867F34ULL,
			0xA9DD03598B2C65A3ULL,
			0x0F9105CB14AC13CBULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xA25ABD147F7E5DC0ULL,
			0x9055AF14E8973EA9ULL,
			0x79DCE2C5474733A2ULL,
			0x43E0C44D954F8A1DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1E0EFB2FE45FF100ULL,
			0x6084ED797EA50B69ULL,
			0x0BD7C4CACFE9EF2AULL,
			0x769596C7F2C9C29AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x700F2D4A508C7B26ULL,
			0xFE9B66C9A05F2299ULL,
			0xBE276D4296D21BA5ULL,
			0x11EEDB9A6BC27AF8ULL
		}
	};
	printf("Test Case 419\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 419 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -419;
	} else {
		printf("Test Case 419 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x5B1FE3ACEF4E2908ULL,
			0xA5C9619E88795C90ULL,
			0xF1BDBC070CCA3CD9ULL,
			0x6E731D6604F7E049ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xB601585CBDC719EAULL,
			0x4E66C2678520852FULL,
			0x5B83945E94BD383DULL,
			0x24E95963DA502A95ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x6CD3E62F27148638ULL,
			0x691F8A7FACBE8B0EULL,
			0xE08CC356C39FFCA3ULL,
			0x7D906B58F3D4E1C1ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x101065F74EC7887AULL,
			0x99FB17660EA8E022ULL,
			0x8BA256FA760ACD9DULL,
			0x78E3461C4B4ED94EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC73726A8C1984D4CULL,
			0xE83729FDB8B1840AULL,
			0xA636D45CE4A5BF45ULL,
			0x196615DAF43A9309ULL
		}
	};
	printf("Test Case 420\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 420 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -420;
	} else {
		printf("Test Case 420 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x00433680BDC7D458ULL,
			0x5F616DCF541E8B8CULL,
			0xB75AEDA792EA80F4ULL,
			0x4C9AE5AB491B4C3DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x8C94519662B584B1ULL,
			0x642CDE13A961DB95ULL,
			0x72DA228A3F15B022ULL,
			0x2C0563BED2F25A11ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x65F5AA116AB83700ULL,
			0x4B393C0A08B9581EULL,
			0x99D58BCDBFFD532DULL,
			0x7C2853057106B99CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xC604E8123389DB9CULL,
			0x10587ADF5D00D445ULL,
			0x250A7E48D9883038ULL,
			0x1A90CD4960C50D09ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB2E68676AEB34E2FULL,
			0xD8F9D3578C163FC2ULL,
			0x623D63192E75B2A8ULL,
			0x743B1376C5D4E4DFULL
		}
	};
	printf("Test Case 421\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 421 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -421;
	} else {
		printf("Test Case 421 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xEEE359307F8FC318ULL,
			0x5695118A5375392CULL,
			0x35FAF35AA7F506D4ULL,
			0x482F8D365E00B94CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xAE85088B65A73735ULL,
			0x8C62ED0CAF1BB9A4ULL,
			0x6C35253BB84D994BULL,
			0x464E826DFF3770D4ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xEF4BCB95078ADC98ULL,
			0xBF85BC8C3DF47528ULL,
			0xEAB3824A55ED96E3ULL,
			0x789F6D4158A89E4FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x5CCDE2170504A668ULL,
			0x1AB138C10DAC45FCULL,
			0x16C68E3A9767DFB7ULL,
			0x0E84D2F517BB43F9ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x8E704A15A7C12615ULL,
			0xBADEE62934568EBDULL,
			0xF58CE0564AC0EF62ULL,
			0x2F87324472D1CF6FULL
		}
	};
	printf("Test Case 422\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 422 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -422;
	} else {
		printf("Test Case 422 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x2E1BD5DAD53BD528ULL,
			0x182A435B167C90F0ULL,
			0xDFE6E21A95B0604AULL,
			0x5B444885E119094FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xCA9D38A2CF418C8FULL,
			0x68574AA6DDCE3CE9ULL,
			0x5C0133F7E0DD3D17ULL,
			0x554B66D9A6A3A32AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x28AB413A4449AEE0ULL,
			0x818921F5085F3F13ULL,
			0xBA22DB0458DA9DD7ULL,
			0x61E051D0D5E0420EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA88D68E16B812E29ULL,
			0x3D58D45C418FA186ULL,
			0xED8FC7B4775E6051ULL,
			0x6618103D4B08C420ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x4B06F9793AE07DCDULL,
			0x23A67D8AC183F0CAULL,
			0x4F1507FD8332DAC7ULL,
			0x2776AF08EE4645B0ULL
		}
	};
	printf("Test Case 423\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 423 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -423;
	} else {
		printf("Test Case 423 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x3E2248F481182178ULL,
			0x25FEA3EFD040004BULL,
			0xC5232FB8A96577FDULL,
			0x4C69CF52FE667B10ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xCA14AD1EC1B34D19ULL,
			0x309723E4FCD257BDULL,
			0x58AD1E99920735C1ULL,
			0x2EADB2F7473C1FCDULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xA4E34C074E86C8B8ULL,
			0x19785B7AE8C623EEULL,
			0xE6C713629AE50487ULL,
			0x584A387ABE2CC4CEULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF5352093163854E4ULL,
			0x7AF0BCA2C0320E96ULL,
			0x322F1A9BC47A0F31ULL,
			0x67049EAC7230C3B0ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xFAA4ED18F4D1BDC2ULL,
			0x552622A7E872BE90ULL,
			0x11969E5B5961F867ULL,
			0x4A58CEEEB7EA3AF1ULL
		}
	};
	printf("Test Case 424\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 424 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -424;
	} else {
		printf("Test Case 424 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x3003EEF289984830ULL,
			0xA65B71DE6F32BCF5ULL,
			0x341C0736BDC24C51ULL,
			0x633E3A704B62D78AULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x28906D00C5B077EEULL,
			0x874560A5493EACC0ULL,
			0xB2EDBA1F1713C2E1ULL,
			0x6C6B856DD9A5C687ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x76D72983D66D7370ULL,
			0x49923314C18BA738ULL,
			0xACB1457F53C5CA53ULL,
			0x6A229B3E9EDFA251ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xBB2632B21A73AA58ULL,
			0x3BDDEF06972E24D2ULL,
			0xD1BC3B0D29C26D7EULL,
			0x1525348B41061FDBULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x91794B6F6F04FB9BULL,
			0x7250B0EFE6C6E1F3ULL,
			0x9266817BAE5B8E50ULL,
			0x00DC7CBB388526E2ULL
		}
	};
	printf("Test Case 425\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 425 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -425;
	} else {
		printf("Test Case 425 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x236EA1EB22A13138ULL,
			0x2DE2EB370B6ED833ULL,
			0xE4AAD0E7E6E89C63ULL,
			0x4FDD28D4925B321FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x26F34E46A33A9404ULL,
			0xCB20A47CE3BB159EULL,
			0xD04C7DCF0A6DDA22ULL,
			0x39849F5D6B2C1A63ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x535D0D70D3EF9418ULL,
			0xDEE67027A57C1CAEULL,
			0xDB0B3A06595AEFC6ULL,
			0x4611748467E3BD2DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x5C1A79A99B3B7169ULL,
			0xDD145D33615C3C38ULL,
			0x81697835A41284A2ULL,
			0x22F51A27EF558993ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x93C4A1C0EE44B241ULL,
			0xA7AB7F091B21DCAAULL,
			0x2EDA7FE6A4A44AB3ULL,
			0x3CAC7E2BF912AA78ULL
		}
	};
	printf("Test Case 426\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 426 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -426;
	} else {
		printf("Test Case 426 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x0304DEAE99745368ULL,
			0x97D16E368FF6BE48ULL,
			0xFB564A291DADB635ULL,
			0x50FF83BF9771F89DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x65E5E52747B8AA82ULL,
			0x5A0A5880B3707649ULL,
			0x3A8AF113C84CD289ULL,
			0x4CA647CCF7A45544ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xA7605C0772675880ULL,
			0x0A1D5E12301A7908ULL,
			0x4DF12E3DCB9CA694ULL,
			0x62AAC5D1B0D9FB8DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x83DF74BF8B80C637ULL,
			0xAD04D8DEF32D3688ULL,
			0xB26E5E135FDEE679ULL,
			0x24BE15902F5252A1ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x3D0F72D8FB3024D0ULL,
			0x4D2E8B25DFB51297ULL,
			0xA9C00445B88971E9ULL,
			0x6D41F666C21DBD33ULL
		}
	};
	printf("Test Case 427\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 427 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -427;
	} else {
		printf("Test Case 427 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x5E0E21B3AA13D0E0ULL,
			0xE52597DFF4E86F03ULL,
			0x65D4206EB9DC0817ULL,
			0x5AD1CBF0D4C40388ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x80F7162927ECF125ULL,
			0x05E2E8F558E3D4D7ULL,
			0x3E6226961679A9A4ULL,
			0x560DCEC5B213645DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x45702A0137ABE348ULL,
			0xF64B0DD4BEE8D508ULL,
			0xEFE743D280EFE5DEULL,
			0x68978EBC28BEB6A0ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x42E18AEAF23EBCFFULL,
			0x8B492070A149958DULL,
			0x091E2F22D8422193ULL,
			0x019E22285E5E11CEULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF636597CD57B0DBDULL,
			0xCBC8B6848BB88C24ULL,
			0x8457B395EE662ACCULL,
			0x62EC31451EA335F3ULL
		}
	};
	printf("Test Case 428\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 428 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -428;
	} else {
		printf("Test Case 428 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xE8836D8AFD817788ULL,
			0x48D4ECAABA91640CULL,
			0xFC027D08F9B2AFBAULL,
			0x762A1BE5EF503B3DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xFBB13F45D633616BULL,
			0xBAEB547BD4241BE6ULL,
			0x6D6645E6777DF315ULL,
			0x38DA1F118ACCEA2CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xDE3F17C4EC9DD478ULL,
			0x93AD5B5C5736C67EULL,
			0x77C1F9BFC9965038ULL,
			0x40EC9D5C2B72B9F5ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x6EA801D111F72874ULL,
			0x87E8AA5F2A6740B4ULL,
			0xCC8527AD4EC4EACEULL,
			0x09284B4C28A64DFFULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x50E997A6AC029BC7ULL,
			0xEA30EC74EA350143ULL,
			0x6472639328D33B10ULL,
			0x3A70994B708F5A7FULL
		}
	};
	printf("Test Case 429\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 429 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -429;
	} else {
		printf("Test Case 429 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xF387F68C3593F058ULL,
			0x739E13F7ACD709A5ULL,
			0x8C9376A40DEDA6F8ULL,
			0x75C449ED428A33D9ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5B5094BF7C0DDC4AULL,
			0xDE3DC338404FB9B4ULL,
			0x960FBC69EB6E8200ULL,
			0x705B527B8C317A66ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB279F2E0BAD2B908ULL,
			0x8B6CD55BFD88952BULL,
			0x50DB76C68364AD69ULL,
			0x58581C5F48CCEC4DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xBF45FF41632928DAULL,
			0x360D99D56EBA58CAULL,
			0xB416D83F491BD9B7ULL,
			0x697A20FA3C53CF56ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7201D965C9C5EB5DULL,
			0x2C2202893CA22E33ULL,
			0x086366D28CFD7D68ULL,
			0x151D60B700D5835DULL
		}
	};
	printf("Test Case 430\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 430 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -430;
	} else {
		printf("Test Case 430 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xFDF352EB927DDFE8ULL,
			0xE76AF8D4FE77049AULL,
			0x55735097DC1916A4ULL,
			0x503057B156037032ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x3321207877420BE1ULL,
			0x216D00BDC821FF32ULL,
			0x470CE1A3478977D0ULL,
			0x1D0E5ADB8139BA30ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x77365B947EB75270ULL,
			0x62E4CA5E9646AB9EULL,
			0x3E6766FC12796CDFULL,
			0x7A1C6733C548D187ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xE22E72C77533267CULL,
			0xA46442C0697DAED3ULL,
			0xD03F6B9B6E18C828ULL,
			0x3CF0CEEA57B359E5ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x9983416C8B5B465BULL,
			0xFC49BFF5BAEBEA9AULL,
			0xB5C18AC26252EBB5ULL,
			0x1B65889F2FB5250EULL
		}
	};
	printf("Test Case 431\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 431 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -431;
	} else {
		printf("Test Case 431 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xC6777A290BD5EF18ULL,
			0xF1E6C611E9C41364ULL,
			0xEAD6FDE05FFBF1A2ULL,
			0x689335DC41EBBA3AULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE2DDFAAB547FD723ULL,
			0x56B35A9282906EE4ULL,
			0x785A599AAC532B50ULL,
			0x49D986C5942E2A58ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x4D7A191C9392AE08ULL,
			0x784A4751363DBE0FULL,
			0xA801266487CDA1FAULL,
			0x6DFF35D5F9975E15ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xDC1556D8F98F4EE3ULL,
			0xE4B5CBC5A328A82DULL,
			0x7E4855D4A1E3BA85ULL,
			0x3F64624EC778EF9FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE93755B5B649A4C8ULL,
			0xBE209667CFA13080ULL,
			0xBA24DA2FFE2B6A24ULL,
			0x1C55C595C59EF771ULL
		}
	};
	printf("Test Case 432\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 432 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -432;
	} else {
		printf("Test Case 432 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xC6824FA56D427D08ULL,
			0x2299A118F58E9CCDULL,
			0x182FF2A77D374578ULL,
			0x792BF92661ECF60AULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE79780502CC16B54ULL,
			0x540426E47DF18D9AULL,
			0x354EEE38066FE3BCULL,
			0x0D356CB6033B9071ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9F0E84DA5A6FC128ULL,
			0x10B15407CE7656D6ULL,
			0x9A2E4EC9A71652E0ULL,
			0x5424FB3EC0F46716ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x6E7C6C9F2209173AULL,
			0x7D3A98BA11AED094ULL,
			0x6BD01D01C903E446ULL,
			0x31C12A9B7EA6CECFULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB7F3DA66F46CE3EEULL,
			0x09E3E12958E318FAULL,
			0x5CED7A28F3F0D71EULL,
			0x65C8B9C908031609ULL
		}
	};
	printf("Test Case 433\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 433 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -433;
	} else {
		printf("Test Case 433 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x004B5E5F0B981FA8ULL,
			0xBACB4741BEA45E18ULL,
			0xFE2E4F056EF0356CULL,
			0x61CA1375186DF719ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x617344F4004A6204ULL,
			0x83AFD4DC1D3FA97CULL,
			0xC82F2861C8994807ULL,
			0x49F206C5C5C023D5ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xBF3FEC5D62C57EF8ULL,
			0x2CFCF5A1CB4B274CULL,
			0x4D6952D57768E70DULL,
			0x7E0096972A20EF1FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x80B7D263D9C7AF9EULL,
			0x0F7A8C8882A23A76ULL,
			0x96B9CECB2E8C8A51ULL,
			0x11E012542E61362EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x0897C6AFBD55EFBCULL,
			0x1C9379D157F02D92ULL,
			0x2C5F8F6895113071ULL,
			0x21CE6730E2220DFFULL
		}
	};
	printf("Test Case 434\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 434 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -434;
	} else {
		printf("Test Case 434 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xDCA5C0E018943450ULL,
			0xC4906EFCCB599515ULL,
			0x20434CF2464233D5ULL,
			0x706667348C3FADBAULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5B955565701841C8ULL,
			0x65D8F1AAAA6BCB82ULL,
			0xF6548E1BAF1610B8ULL,
			0x0F69C4FEA50C22EFULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xAD2E0944064A8158ULL,
			0x426FA9FFE3A0D7A4ULL,
			0xF23EB943050F1D12ULL,
			0x43479FB89B6E6361ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xCFD9DCDD47A54A0DULL,
			0x4B2FA56329D2B256ULL,
			0xCFADB53C82B52FFCULL,
			0x63175A773BF95991ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x5D07C5952544DBCBULL,
			0xECF7D714BA72D948ULL,
			0x85227084D2EEA54AULL,
			0x78D3D774A08587FDULL
		}
	};
	printf("Test Case 435\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 435 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -435;
	} else {
		printf("Test Case 435 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xAA9CB95CAD79CD08ULL,
			0x351807CEEB8FD2CEULL,
			0x2811B3C11008CF62ULL,
			0x7EB31A688E1C8F61ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x14EE2AE25984FAE2ULL,
			0xF5DF3579E8EDB3DFULL,
			0x5DB0E523023B89FBULL,
			0x19CBD6750D9A02BCULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x3FF81FB8ACDF2C08ULL,
			0x5BA112B633B69074ULL,
			0x3EA52458B0D3F64FULL,
			0x44F13A21F37E7868ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x2BCCAA1D6ACC2AA4ULL,
			0x44BF0159AAC063CFULL,
			0x492E760BA21B5E31ULL,
			0x1FD764D322AAE9D7ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7B4D85FBA530D6CBULL,
			0xEE05E47551F83E3EULL,
			0x7DEFBBB14DAF0317ULL,
			0x25DCD421525E8A09ULL
		}
	};
	printf("Test Case 436\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 436 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -436;
	} else {
		printf("Test Case 436 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x0E81976964B78FE8ULL,
			0x8346FA0FD0D32DF1ULL,
			0x038EEB7AB77C07CDULL,
			0x77C5BF3AE33C481EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xECAABE4B4CB59544ULL,
			0x2407239EB25414EEULL,
			0x76DEB68570C99758ULL,
			0x6DFE833C38B682B9ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xFE23F43B1F715F90ULL,
			0x48E3CB6DD409EF2EULL,
			0x486E1536FDF1D2E4ULL,
			0x47DB843FA99AFB48ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xE3C6F1A9098DC41CULL,
			0x5382A63749EEA48AULL,
			0x6C4933B2BFE17A2EULL,
			0x5AF61953A247E762ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x23F6E1959F9445CDULL,
			0x16C8CD0192E43CE0ULL,
			0x04923D62F5032FC2ULL,
			0x41CE062718ED0531ULL
		}
	};
	printf("Test Case 437\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 437 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -437;
	} else {
		printf("Test Case 437 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x166BBCFB27A0E690ULL,
			0xB1B9111A45A0C793ULL,
			0xFA82313ADC77635FULL,
			0x405464777A2C0F0DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xC2DB059F1C702802ULL,
			0xA4B94EEB4EDD6B23ULL,
			0x8BA7BE193869FD18ULL,
			0x255352F709BF06ADULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x42C12265AFCDA078ULL,
			0x78476E22C64FA807ULL,
			0x22D10D3130A6E66FULL,
			0x7AA026DE47A0E3C5ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x93A60DA258ABF8F8ULL,
			0x32B200D27F178774ULL,
			0x27ACAE3C93210E67ULL,
			0x7F3C24EA570E7701ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x6B7412427DA61537ULL,
			0x2B4AACA0E8BD9894ULL,
			0xAECF835869F19845ULL,
			0x3D9A0DA6B6BA0E65ULL
		}
	};
	printf("Test Case 438\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 438 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -438;
	} else {
		printf("Test Case 438 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x8F640689C9B39818ULL,
			0xC632120168E48438ULL,
			0x9A7AEC4B82888000ULL,
			0x5A98F85276359C1EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x3783C243254B8E81ULL,
			0x465FD33E0C3E642BULL,
			0x74EF7651987125C7ULL,
			0x1678FFC49585BB2BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x85D48CBF0F4B0530ULL,
			0xF65B90528D0F6A89ULL,
			0xC97D44864360741AULL,
			0x70B845D3492E5BC4ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x51761083E080AC95ULL,
			0xCD16C8CB6B43741EULL,
			0x5FD9DB8A6864D8DCULL,
			0x167418D43F484A5EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7919AF16A3E20889ULL,
			0x42C9CEF5D1F3939BULL,
			0x3DD226D028BA4E62ULL,
			0x41F3F0D7324DB1AAULL
		}
	};
	printf("Test Case 439\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 439 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -439;
	} else {
		printf("Test Case 439 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x48729C42D78F7BD0ULL,
			0x940ED051FD140617ULL,
			0x20E708BFF973B316ULL,
			0x65DE3B67670B8BD0ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x425D944A4B19E54AULL,
			0x948218D216BBB5B9ULL,
			0x6CACA36EE994D556ULL,
			0x785BF8575A3769DEULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2F4B38E8046E1060ULL,
			0xEB0FDF6A84A2F3D8ULL,
			0xAFEB74BF08981CD4ULL,
			0x7CAEF4C8F1B7661EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x94157A64697BE7D9ULL,
			0xE019177904F2397DULL,
			0xF8CC4710910ED45DULL,
			0x59D79BC676E3B07FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA8253F1356FBC966ULL,
			0xFF9C9CAA37B3669FULL,
			0x68F233A4EC261FEAULL,
			0x447F0E8D0371C25BULL
		}
	};
	printf("Test Case 440\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 440 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -440;
	} else {
		printf("Test Case 440 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xB2A67EDAD6B13C28ULL,
			0x54456432947B4BE1ULL,
			0xCD6F041F6AC5E43AULL,
			0x70F22246D31928C4ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x8910363799254BBBULL,
			0x9EFF26F3C6FFB67CULL,
			0x955642FC2EC003A9ULL,
			0x436DD1CCE4E2FC2AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x8C4975D482B60348ULL,
			0x2BD7D94FA57B624BULL,
			0x90A99FCE5677FC55ULL,
			0x60D7C2B6CD7807F3ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA33EC3EC0FB9B933ULL,
			0x5BC99DE87FA9EC77ULL,
			0x84137B21E5A75C8FULL,
			0x34EB203F214DDA27ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD249DBAAACBB76F5ULL,
			0x3C6B477ED5B5095EULL,
			0xD1DB4B10DABE51B1ULL,
			0x49C5B012C6667758ULL
		}
	};
	printf("Test Case 441\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 441 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -441;
	} else {
		printf("Test Case 441 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xC4F3D5EAB27C6C70ULL,
			0x173146047BCEDF63ULL,
			0x5DE7D97457F7461CULL,
			0x6C5E1905A689663DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x6D0736CD361C53F1ULL,
			0x467758AE1731B3C6ULL,
			0x4A015B370DEB486FULL,
			0x1CDF49A8BF313EEDULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x73B3EB17E6C057E0ULL,
			0x46B63AF650AB14CCULL,
			0xAD09C3BAEAF7BAC1ULL,
			0x62C2F4062EA5A25DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x60AACEEE8C9D564EULL,
			0xA8430493B24D4C75ULL,
			0x0225981A8FE4D12AULL,
			0x43AF207C308F2765ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x772E5915478A0982ULL,
			0x64D6EDC5B0F6CE6DULL,
			0xF806874F13695026ULL,
			0x599A0066E0B335BFULL
		}
	};
	printf("Test Case 442\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 442 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -442;
	} else {
		printf("Test Case 442 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x611C27A86E828C78ULL,
			0x2F5E8259199C407DULL,
			0x45026C9D4A4EF090ULL,
			0x75CA68CEC6BA79D5ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5700EF5BCF0DAE82ULL,
			0x38FA713E7C3E24CBULL,
			0x2AF3582B0E946F08ULL,
			0x3016E5539FE7565DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x60C918F605DCF7B8ULL,
			0x763D633B2DDADB98ULL,
			0x3C855A2618CF56C3ULL,
			0x4F65850C43571817ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x6768F1034D5D05D0ULL,
			0x6370B47AB883024DULL,
			0xBCF5874B71381B06ULL,
			0x585EAE63914CF49AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x017E3F235A2B3BE4ULL,
			0x73414EDDAD094BBDULL,
			0xC591E9DE9066DD33ULL,
			0x0A7334B9262E414AULL
		}
	};
	printf("Test Case 443\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 443 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -443;
	} else {
		printf("Test Case 443 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xBA991B35F0AE20B8ULL,
			0x51B8C8782641AA9AULL,
			0x918CBBCC15C23DEAULL,
			0x4A99AF71B8A76824ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xAF8194AAEE75916BULL,
			0xC83BC5F306F8C62FULL,
			0x60CFAF93BB46D202ULL,
			0x660DA1D720EAF87CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x6F55EAE7A4ADE368ULL,
			0xAE93CA36DA2145C6ULL,
			0x2527138A390B6898ULL,
			0x772BC51C92C4B769ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1E85B60A96EB8F4BULL,
			0x2B12BC273D73AAD5ULL,
			0x6869C84801489772ULL,
			0x033D1BA3AE5EB87EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE315C2380619D869ULL,
			0x04AC3E8CFE14CECFULL,
			0xCE85EE6279F3E5ABULL,
			0x48AB5294B03026B2ULL
		}
	};
	printf("Test Case 444\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 444 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -444;
	} else {
		printf("Test Case 444 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x665AE496E48940A0ULL,
			0xCEDE53659D28F8AEULL,
			0xB297B4181E1F9488ULL,
			0x4E79E4C9A94967FFULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x0851B2FEF37ABA40ULL,
			0x9830102156FDF089ULL,
			0xA1F0B6019444669BULL,
			0x4E8846046BA9EF28ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x6463689207D8A0E8ULL,
			0xE62523F651EAA248ULL,
			0x75791EC85D7FC686ULL,
			0x720212A51D580FC4ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x5FFFB4F143C907EDULL,
			0x9FA89B6332B8DC59ULL,
			0xCCBDF17AE4DF1163ULL,
			0x0D27B197E4AB6341ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xDCAC703D344D6913ULL,
			0x8BC7DB0E563D0063ULL,
			0x4CD5BD676D2EFAA7ULL,
			0x670B95263155E283ULL
		}
	};
	printf("Test Case 445\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 445 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -445;
	} else {
		printf("Test Case 445 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x63D81CBB58E24700ULL,
			0x9CE79B266C0EC91EULL,
			0xC8CBD4EE41E2F9F1ULL,
			0x745BE870E355F4F8ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x202B011AB12D9DF0ULL,
			0x1CCD923955D872A8ULL,
			0xFACBE1D35FC1638BULL,
			0x50D017965592E5D0ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x365C9A62877B93E0ULL,
			0xC0F976E3EF4AE1D6ULL,
			0xFF624F0E6C28BDFAULL,
			0x745EC5239B075316ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA7DCE6DDF719DA31ULL,
			0xA34A6845AAEDF378ULL,
			0xBEC66CEFED13B025ULL,
			0x3F07BB664203C7D3ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x32700C375FEEC57AULL,
			0xFFC2637A2976A3CAULL,
			0x63BED5FC10C04410ULL,
			0x789C3CA868C65CADULL
		}
	};
	printf("Test Case 446\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 446 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -446;
	} else {
		printf("Test Case 446 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x2151B57BA7C7AD00ULL,
			0x85E3D88B2B3BB7D8ULL,
			0x8C08B42D5295F15AULL,
			0x663125F460FC67A4ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xDEC753C60F60238CULL,
			0x722E61E730F1F52AULL,
			0xA3EF7A3460894780ULL,
			0x16890504D586A80CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF49B0D8EBC9BF3F8ULL,
			0xBFBB976BF5314394ULL,
			0x7F2A2BB2BFDABE27ULL,
			0x5F91C1A463235E5EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x564C2530C338270BULL,
			0xFF5F7ED261E21713ULL,
			0xA8EA4D9A40843B35ULL,
			0x64FDABFCE57BE2A0ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA9CC083660A7117EULL,
			0xBE704243DD464FC2ULL,
			0x1745DA5F7ABBDC1FULL,
			0x22D7F1854EB6DACFULL
		}
	};
	printf("Test Case 447\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 447 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -447;
	} else {
		printf("Test Case 447 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x4AB4162AD30CB0E0ULL,
			0x837C738625942594ULL,
			0x2B1C67BF6E714D41ULL,
			0x48CD060F6CC8EFA0ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xB06CAF82C25D0C0AULL,
			0x88936BBB1F785E5FULL,
			0x730B8CFF92CC77F5ULL,
			0x3ABFB41E037E938FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x7DAB4E39234102F8ULL,
			0xC553176B177464CEULL,
			0x5DB5D3FDE6068CF2ULL,
			0x57650C09D3C34C91ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA368859705B40907ULL,
			0x106AECDF99565939ULL,
			0xF703B6C76234C82DULL,
			0x6F15475B3AC43DA0ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xFF8BC393708DDF38ULL,
			0xD2023F19A4BB70ADULL,
			0x35288C4F5247B4B9ULL,
			0x16E16BFAF40E2A85ULL
		}
	};
	printf("Test Case 448\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 448 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -448;
	} else {
		printf("Test Case 448 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x8859C7BC6D1CFA80ULL,
			0x92AB6F568BFC65ABULL,
			0x154F748699F034BCULL,
			0x64262B5EF490D177ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xD9932D57E6874623ULL,
			0x4702D4A2278FE002ULL,
			0x53AC0A0E38F07A48ULL,
			0x28BC150B88EE8C62ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x608C3260F07DC338ULL,
			0xA2FD853ED74F9D6EULL,
			0xD2F71D1162A31753ULL,
			0x4A7860C9CF5C6CB7ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xACF396806F9BBEECULL,
			0x0AF2644FDA454497ULL,
			0x4BDE3B099DF1039BULL,
			0x57301CB420636B99ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x680B61A5CCF2FD12ULL,
			0x070CA04F4FE4FBCDULL,
			0x9E91091B90543BC9ULL,
			0x5804D9CC7A64F8CDULL
		}
	};
	printf("Test Case 449\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 449 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -449;
	} else {
		printf("Test Case 449 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x4A56133467F85100ULL,
			0xEA024F0ED5758534ULL,
			0xF6D71264A0C2F6EDULL,
			0x5C117A345C6177BAULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA2CC46025D2199C2ULL,
			0xF7A7C0EDF6BD3A15ULL,
			0xF8A7057E346449DCULL,
			0x064C9F8B288E1559ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xFA14B455CFEDB300ULL,
			0x5451DA24C9AFEF84ULL,
			0x67C8EFDF755C72F6ULL,
			0x79A1E80148AB0ABAULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x2DEE31F5895B6C4AULL,
			0x91464E671A109548ULL,
			0x7CB1DA2A4AAB8A56ULL,
			0x255DEADF2AB2C5BFULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x19D3ECED17F34939ULL,
			0x3C939C45E66DEEC0ULL,
			0x634E74A67CCC3E88ULL,
			0x4836CF78F768DCE8ULL
		}
	};
	printf("Test Case 450\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 450 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -450;
	} else {
		printf("Test Case 450 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x77EEF93A08AD6E58ULL,
			0x64FE124F7E7ED786ULL,
			0xD646AB340D54271BULL,
			0x5770818BD760FBDEULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x75FA9C25D2729201ULL,
			0x511953ED056AF683ULL,
			0x71C56F66806911D7ULL,
			0x02497C9EE9452DA9ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x0E91826AA53F07D0ULL,
			0xE6E7E8069553397BULL,
			0x0723675F5CE00ACCULL,
			0x7FAC3EADD959F83BULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xAC8D6AE48A59E42CULL,
			0xB2D7106DFD0AF67EULL,
			0x8C0B0121CD9D3854ULL,
			0x3EF6EDC2E8564F96ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7D1B00949D6B5ADEULL,
			0x0F20907DD66E97CDULL,
			0x63DAEDCCAD66ABD6ULL,
			0x3CA8019E8A5A0551ULL
		}
	};
	printf("Test Case 451\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 451 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -451;
	} else {
		printf("Test Case 451 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x43574C11A553A438ULL,
			0xC0E54CA8A939BD70ULL,
			0x1FD7BB9CB37E917EULL,
			0x7E1FE06785975B58ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x862B3DDB5DDFD3B2ULL,
			0x3C560AD0369D6A70ULL,
			0x0ADCF3156E12D3CDULL,
			0x3B3E07AC8FA61A89ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x770CB1D8056F9E50ULL,
			0xF2C67CBD45749603ULL,
			0x7FC95BAD8778F79DULL,
			0x6D682FFE068CD521ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x26A62C05013EB47BULL,
			0x76AEA9FB85BF8CE6ULL,
			0xD0428120EA0B0AF7ULL,
			0x53CD617ABCD8BFCDULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xECD7E1F0C5F6F38EULL,
			0x41F2A5CC47742ECBULL,
			0x71C110FE85D914FAULL,
			0x7F343971AC106AACULL
		}
	};
	printf("Test Case 452\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 452 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -452;
	} else {
		printf("Test Case 452 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x05EEE174B95661D0ULL,
			0xFA545739A9B19CD7ULL,
			0x7237EE336B226963ULL,
			0x5476837F4D98B7EEULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5476DC037272E7D4ULL,
			0x091CC15DF60C389FULL,
			0xFDBA59D8FE37FDA6ULL,
			0x334A6F2CD298A520ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x0B54A7D2EDB5B890ULL,
			0xAB63913810E6BC4BULL,
			0x79840AD15CB7317DULL,
			0x54B6D0AC2C3CCE9CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x8A3AC0F13A0F14F0ULL,
			0x5A83E74A0B0C9BF1ULL,
			0xCD9FF8BBF299AF7FULL,
			0x33710F2D2E76852EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x50BEA07FBC1C3B60ULL,
			0x4CCAF792D2234010ULL,
			0xE160D87D597D0E12ULL,
			0x0630EAE2586C1503ULL
		}
	};
	printf("Test Case 453\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 453 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -453;
	} else {
		printf("Test Case 453 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x8AB7E88A8732C960ULL,
			0x1F34B9B5A39DF28BULL,
			0x6238D2D138BE3FC1ULL,
			0x682D526C739D15A3ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x16271EB9556B64C0ULL,
			0x3E711AF55537798FULL,
			0x55210ECA8FE124BBULL,
			0x288DDE4DD55B86DFULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE14BA8F26DA2BFD8ULL,
			0x0E17764147F4DA8FULL,
			0x2DE3CFEA75D0535FULL,
			0x4130BB6637D07E9AULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x309875C047DB1EBCULL,
			0x2B81F568B4CB753EULL,
			0x149DA1C18A4F7E43ULL,
			0x23408CF3FD1DC93EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x275D3FE1B4EC33B9ULL,
			0x31332D2C8A2DBD47ULL,
			0x64F46B35A8D728ACULL,
			0x3F0786D0BAB83378ULL
		}
	};
	printf("Test Case 454\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 454 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -454;
	} else {
		printf("Test Case 454 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x0F6D1684D7DC1410ULL,
			0x7BE8C10F5737F3C8ULL,
			0xD9FA460D1127FD14ULL,
			0x412C57C840294314ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xC8317D54A23E5B37ULL,
			0x5A6EF7AB8C5E2874ULL,
			0x0227856E6A87865FULL,
			0x32A670F62DD22661ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xD77D55E90B713EC0ULL,
			0x96AC7E5D55611711ULL,
			0x4B3DD5DA49EB492FULL,
			0x659F4FD4C7536E85ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x37B22F818BEE9A90ULL,
			0xCB86490D894F441CULL,
			0x29C27FDAD6BB84C3ULL,
			0x18A2DC685ABC7873ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x67D131219B955604ULL,
			0x577EFEC35B5320CDULL,
			0x84A8A9916771AAE9ULL,
			0x085BA34E20732E11ULL
		}
	};
	printf("Test Case 455\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 455 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -455;
	} else {
		printf("Test Case 455 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xD1E6060C7AA19D20ULL,
			0x1B6A9F7B8C31A1EFULL,
			0x16AF5456C0B5E212ULL,
			0x41B355B486C299A4ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4752B916576C3EBCULL,
			0x5000B7113C9EA25CULL,
			0x6FEEF847FBD330C1ULL,
			0x4A8CDCBC11D822CFULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x98E5113C2AB5C9A8ULL,
			0x0070423F7F3F47F4ULL,
			0xED6C031A42256860ULL,
			0x703BAFA65AF3F1A9ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x14DA18C375E074CEULL,
			0x62ACC5F48C8F39F3ULL,
			0xA52061254BC19CC9ULL,
			0x21A46E90AE172B13ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC144A87E77DB6B95ULL,
			0x595BE5C100F08919ULL,
			0xF3A12FA98F258394ULL,
			0x562B11923E423A2DULL
		}
	};
	printf("Test Case 456\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 456 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -456;
	} else {
		printf("Test Case 456 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xA0B3F79D2ECBA598ULL,
			0x7544529BC74642A6ULL,
			0x3BD7B028029BC9F1ULL,
			0x617FEA3DAB9712A5ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE0D53ED045BB750DULL,
			0xA8CC994BE113E34DULL,
			0x225FE5F97F10C961ULL,
			0x37878BC54ACD588BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x5A7EE8C73D828458ULL,
			0x03CCFF8D3019A488ULL,
			0x434795FA1195F7C7ULL,
			0x57F48191C091B16DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x90D33779732322D1ULL,
			0xEEDA9D332588107BULL,
			0x1EEE5C83C3B2BA86ULL,
			0x062F91699A5F31D6ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xDFD728DDC1312899ULL,
			0xFA3F3D905A3BDC5FULL,
			0xD3123A5017DF6758ULL,
			0x03257E715687C2CDULL
		}
	};
	printf("Test Case 457\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 457 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -457;
	} else {
		printf("Test Case 457 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x5096C897E11B3E08ULL,
			0xBEB73FBBFA6B40E1ULL,
			0xF7702E78060DDE30ULL,
			0x6EF1366AD7FF2B85ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4D5610095F23AD3BULL,
			0x3287EE3CC736573AULL,
			0x251047E8B877FE08ULL,
			0x1C76D3C6BB20CD66ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xA2CA18B06479ACF0ULL,
			0x96DA420D081EFF59ULL,
			0x6765ECB0356A7BF8ULL,
			0x7ED7818BEBE17939ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1EEDD655F3EF48D0ULL,
			0x9183327A3487FE70ULL,
			0x81DBEB6118ABB8EFULL,
			0x15FB217C5FB83795ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x8429DBCFF669C762ULL,
			0x15024E6335877AFCULL,
			0x93946196BD91D638ULL,
			0x7D8123740528C299ULL
		}
	};
	printf("Test Case 458\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 458 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -458;
	} else {
		printf("Test Case 458 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x740CC55504DF4CC8ULL,
			0xC4060FB3C77B8137ULL,
			0x4479B60916AC209FULL,
			0x4A0D4E7B5A13D1ABULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x0E9D2A0D0BBC51BEULL,
			0x9955EEE3C137EF22ULL,
			0xD783C87A21E31FA6ULL,
			0x7E5E73EFB653E401ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xCC39D3BA568FC218ULL,
			0xC233B3F8FA5A1DDDULL,
			0x8E37B625A00A5972ULL,
			0x54E8B5FDADF81E1FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xEE81D45DA916770DULL,
			0x4B8C54031CC3FF13ULL,
			0x40E83FA7158342A6ULL,
			0x242A91602942BCE3ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x0D5AB03E884EC49BULL,
			0xDE92A02C75244FB1ULL,
			0x2963359BE8998D53ULL,
			0x52B9A55E1A3578FFULL
		}
	};
	printf("Test Case 459\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 459 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -459;
	} else {
		printf("Test Case 459 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x9C0AB55C39ECB2A0ULL,
			0xB8E1E9E86A6A793DULL,
			0x504D55F336D15581ULL,
			0x48C485ED3B3BD8D7ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x8D656C02FC6C99ABULL,
			0x5140791F450F6A56ULL,
			0xC73128F8F2D30AFEULL,
			0x57128234FE9E42F4ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x4C88AB5EF08F8F00ULL,
			0x3074E186C2FC73BBULL,
			0x2544D4FB693FE22FULL,
			0x5A21528582AE79B1ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x9662E42C50F1C0EBULL,
			0x3083AAB601E8C262ULL,
			0xFC594CF2162B252BULL,
			0x33E7EB5541052B2EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x75BB90D6D62677D7ULL,
			0xA1DEF7344764A998ULL,
			0x1A52C9BAFC4C58C2ULL,
			0x37220FD1772A90F1ULL
		}
	};
	printf("Test Case 460\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 460 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -460;
	} else {
		printf("Test Case 460 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xD6938ACBD5B3D4F8ULL,
			0x35B0A303E7D2BF5EULL,
			0x9420FE78B417E638ULL,
			0x69FFEC7E44434A3DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA341FFA79B3A22EDULL,
			0xD224A88A40ABF921ULL,
			0x68216FAF27049973ULL,
			0x1CB53F5EC1DE51E4ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x409EB29F3B445018ULL,
			0xB6795489EB557312ULL,
			0x505E17BD5011C15FULL,
			0x7F38A3A79225743FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x4EB410E1E4DF3498ULL,
			0x06B3473DE38E0B09ULL,
			0xE1BCCC01D39E326EULL,
			0x6BAD2EF6C7B1CFFFULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF467CAE8123AA325ULL,
			0x8E943572A0EE6155ULL,
			0x8291CBE770C32B4DULL,
			0x5AF3BC9849C89F70ULL
		}
	};
	printf("Test Case 461\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 461 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -461;
	} else {
		printf("Test Case 461 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xD2644178CC072818ULL,
			0xAF85C4D695976084ULL,
			0xC29731D96600FA7FULL,
			0x6D12DFA248C96341ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xAB21826BFD77B49CULL,
			0x2F263BE56EB3EF52ULL,
			0x8BF30914823B101BULL,
			0x0054F92DB0E1EF0DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xD06C1F0B704845A8ULL,
			0xA2AE3F343C64EE2EULL,
			0xA146FA30B1ACB3B7ULL,
			0x7B0112261B1EB165ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x153DE82C8103CD50ULL,
			0x0367513DA9B1D437ULL,
			0xDB44985D3AC949E2ULL,
			0x79E1B1C1E4ED3972ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA79AA49D53692782ULL,
			0x052D10E91354C9B0ULL,
			0x47A02514C7C440ECULL,
			0x66C2529915F01650ULL
		}
	};
	printf("Test Case 462\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 462 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -462;
	} else {
		printf("Test Case 462 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x2ABF5C237B39A4E0ULL,
			0xB712DE9D7393A135ULL,
			0x9EE097A1F1766A8FULL,
			0x759BD26156A5B871ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x87290093B92C0A21ULL,
			0x5DA730E099BD612DULL,
			0xC474EF344CF31A26ULL,
			0x23A5A07A36C9E57FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xED1C8E3BAEFB8530ULL,
			0x5FD5A1038B815725ULL,
			0xFE7A93C11101AFAAULL,
			0x772103DAD25A8623ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x21EC01FAA1ADB2C1ULL,
			0xCA9AC0C62A4F0F26ULL,
			0xDA98E83C71CC9A74ULL,
			0x5BF866D47F400337ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x2DDE9CFE469E91AAULL,
			0x8DDC503FD1EE4A6BULL,
			0x1A363AAE6FD79ACBULL,
			0x60AEED596CBB1CABULL
		}
	};
	printf("Test Case 463\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 463 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -463;
	} else {
		printf("Test Case 463 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xEBEE8F0EB0AD1D30ULL,
			0x939935CE91C7DA02ULL,
			0xE0AF6B2252463C68ULL,
			0x57D4605C49706B4DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xC33896EC0FCDB257ULL,
			0x72AA6D9B2A40F354ULL,
			0xC1BA19E745DC2B54ULL,
			0x4D1B4ED5BB32C739ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x5740EA5F2CE66638ULL,
			0x48D28056585C079FULL,
			0xEF195D5A7F0216F9ULL,
			0x5D3391272B023DE2ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x4ADB4D3F3C5F37B3ULL,
			0xC7AB05D72213956BULL,
			0x937CBBF6F107A35BULL,
			0x0BDA5172FC20224BULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF5F8D59837BC894AULL,
			0xD7286917D550D805ULL,
			0x34F7AA555E079141ULL,
			0x46CC43E26BC9E54AULL
		}
	};
	printf("Test Case 464\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 464 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -464;
	} else {
		printf("Test Case 464 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xA801B2AD48D1FC80ULL,
			0xA44296856EB9BC20ULL,
			0x0C6C954FD9B72243ULL,
			0x5BB40FDA47D53A9DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xD5DAE8F14D148184ULL,
			0x4984392BDDEFC211ULL,
			0xC81E5E356297A56EULL,
			0x095E5C5C09F6564AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xDA6D6B6C9D837CD0ULL,
			0xCC8BD038CAE6C0A1ULL,
			0x5EB019E07CAF2987ULL,
			0x7B5E65FBB9FF0D40ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x5188CAA0E18DC492ULL,
			0x967DAE9295513A96ULL,
			0x2CACC65CD4631087ULL,
			0x759D54C97DB4C449ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7787B9F650FB8169ULL,
			0x4EDCF2C237911CA7ULL,
			0x1C9D434F9D597DAFULL,
			0x4AD0BDADF21C2433ULL
		}
	};
	printf("Test Case 465\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 465 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -465;
	} else {
		printf("Test Case 465 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xBC2DE2FC9FCA1790ULL,
			0x4DE0133CF3B13D82ULL,
			0x333CD0582C5950ACULL,
			0x4C81384CEB0AE593ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xF9B4F76790050EB1ULL,
			0x31431C5C0C98F021ULL,
			0x2B305E537BB342BFULL,
			0x4136BB719DFB9345ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x604B1928478517E8ULL,
			0xD342086FC7B1904FULL,
			0x52D3E1BE5C7980ACULL,
			0x43D202C533754EACULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x6BBAD6BA4D9BEB38ULL,
			0x19535C8131B7B45FULL,
			0x979A1CB023C60262ULL,
			0x4CE7661427F4632AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD7A5FC318A263A2AULL,
			0xCC6F339A7A74FF7EULL,
			0xB9AE2083B3544360ULL,
			0x0AFE2ABC77F26639ULL
		}
	};
	printf("Test Case 466\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 466 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -466;
	} else {
		printf("Test Case 466 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x39FCDFA1994A7510ULL,
			0x8E27B27601ADC604ULL,
			0xB7605936B0CD6138ULL,
			0x7D3D83353C0FD90DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4E1BCCE5C28A5634ULL,
			0x2F550B731B87FDC0ULL,
			0xA886F423386E5267ULL,
			0x1896A99508A11D46ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x753D3D571A0F4998ULL,
			0xEEC4D6B4C10DDACBULL,
			0x63E52A458FFAC765ULL,
			0x52D35A9BCFAC4607ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x51E36F94B1F5DFFBULL,
			0xD959C487F63506B2ULL,
			0x895AF7138855B679ULL,
			0x78BD6CBF4939F26FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x9ECB6C788FBA4E20ULL,
			0x4576CC941EB25C58ULL,
			0xC5A37B501ABD34C3ULL,
			0x4E3261FB74594472ULL
		}
	};
	printf("Test Case 467\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 467 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -467;
	} else {
		printf("Test Case 467 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xF35E7410D6B23700ULL,
			0x7DA91FE32D8BB46CULL,
			0xA18A3F73212EE368ULL,
			0x7B97BD64D36F651DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4176BE0E56544C33ULL,
			0xC770A2349D867C0EULL,
			0x31641D0DE09B42DDULL,
			0x6424D30A8F275868ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x3FD223A9F56082A8ULL,
			0xE5734CCCF31363F1ULL,
			0x2FF5F15B5BC245B7ULL,
			0x6F7133A1A085A7DFULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA84921F0D1B630FAULL,
			0xEC62CB48B2376299ULL,
			0x1DA6E74FA9175388ULL,
			0x2F1A4BA3C757F5B4ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x5AC68536A8BFB1ECULL,
			0x3720781DEE107C0EULL,
			0x4CAE0AF8ED6531AAULL,
			0x1AFD6292B3378F9DULL
		}
	};
	printf("Test Case 468\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 468 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -468;
	} else {
		printf("Test Case 468 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xEA07FCA7CB832A00ULL,
			0x80FD4690E2E63552ULL,
			0xEB3164FD911B2E90ULL,
			0x6FD3C4777F2FD770ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x1E7D3C7217E28E7BULL,
			0xACD6C2BC97D5B619ULL,
			0x29F1FA4316135C55ULL,
			0x2B1A8930C2378E76ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x78DF284D0CB181E0ULL,
			0x944AE69FBD925327ULL,
			0x30706CEA2DB4E623ULL,
			0x5A6C097F780DADD8ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x03BE20E4740183AEULL,
			0xDC765FB496C199CCULL,
			0x74C471C4EBB48231ULL,
			0x746107E14DCE48F7ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x919B2D3953AE0D2AULL,
			0xB0047C3C3EFBCDE3ULL,
			0xCEEFBBD39833F1A6ULL,
			0x3C450659D178EDE9ULL
		}
	};
	printf("Test Case 469\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 469 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -469;
	} else {
		printf("Test Case 469 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xBC245952CE3B0790ULL,
			0xD6429B024F44B12CULL,
			0xF143B5A378300B15ULL,
			0x504125C1B447D02EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4CBC6BBFD4AC8395ULL,
			0xB7F708A91C996372ULL,
			0xB1AB0769A727AD91ULL,
			0x487B44596625E739ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x268D023909279190ULL,
			0x1A1C94AAD307C4E3ULL,
			0x7311F49CDFCA184CULL,
			0x74DCFA687F51142DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA1D713CF2FFA6455ULL,
			0x9B4DA6B04810132EULL,
			0x9A8CC66A25027288ULL,
			0x155A5A47DBF4635AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB9A0AC13B03E7F6EULL,
			0x5FF5F3B6088E5ABFULL,
			0x3FBD2F4E87955CE6ULL,
			0x11884D74E3F1AA32ULL
		}
	};
	printf("Test Case 470\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 470 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -470;
	} else {
		printf("Test Case 470 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x6A995930846704C8ULL,
			0xBA14B3C9097AF4C2ULL,
			0x3419BB51FA75F7C6ULL,
			0x6B477BFB3DBBBB58ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x95FBBA023EC49EA1ULL,
			0x9246914FC5F0E775ULL,
			0xDE4700648787D196ULL,
			0x0DFF61C73DF6B3B4ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF30E680A82A08BD0ULL,
			0xAC54406FCE0778CBULL,
			0x9D4623E7BFEA9BD9ULL,
			0x64F9DC73A45EB4F5ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x9CD386FA5EBB7F75ULL,
			0xE84C9D82B0E0AB65ULL,
			0xA7E116A0ADCAB682ULL,
			0x1C9218B445EDB894ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x4F439BD3744CBABAULL,
			0x46321277AC3B6EF3ULL,
			0x66EF3B101EF92278ULL,
			0x504F82E96D563935ULL
		}
	};
	printf("Test Case 471\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 471 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -471;
	} else {
		printf("Test Case 471 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x381863517B8D8588ULL,
			0x8D0FA55678E7230AULL,
			0xF62CDDC12C9FD18AULL,
			0x6038846E5D93B5C4ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE297E952635A0BE8ULL,
			0xB9B85609B5B8D771ULL,
			0x9EDDE62CB53F02E8ULL,
			0x7D3DCFDF223B3501ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x500C481C2EDCF890ULL,
			0x8B79C3E289764A17ULL,
			0x8C249D020798C00CULL,
			0x5CBC0F69A0A71549ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x4B605E78EB87A68BULL,
			0xB829B0AB1E906124ULL,
			0x2F85AB7F7B4F688FULL,
			0x308E3DAF0323603BULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xBBBF3652FCF22B2CULL,
			0xC787D126B9ED75BAULL,
			0x8B50AB6C7D41D491ULL,
			0x057A75C2D1B9B5E4ULL
		}
	};
	printf("Test Case 472\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 472 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -472;
	} else {
		printf("Test Case 472 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x5F8720B8155CBB10ULL,
			0x8E0E985D944C6314ULL,
			0x1CA2DA897D650B81ULL,
			0x638EAE3271AF83D3ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xEDEFBF971D39E5C5ULL,
			0x144681279B993B43ULL,
			0xDD61324F9F55EC65ULL,
			0x0EC3BDF23774AB15ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x5C433F70C0BDC738ULL,
			0x7A6CA189FDA3EC16ULL,
			0x05171505A76BFD20ULL,
			0x6B0C4E0ABC44852EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x04E15E6FB3BA2231ULL,
			0x4259429D2A016BACULL,
			0xF93171E42550198EULL,
			0x0C18119C1D0972F9ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7470B003334923AEULL,
			0x854FCDF0AFA78CD7ULL,
			0x4939D21148CAAE25ULL,
			0x0F99A8145DA2C726ULL
		}
	};
	printf("Test Case 473\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 473 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -473;
	} else {
		printf("Test Case 473 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x50837729027D3E90ULL,
			0x8E5CBF2B1E86CC8AULL,
			0x406D6CEF96C32D1FULL,
			0x7A6D17C831CE423CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x837169408323C1F5ULL,
			0xE02F2B6ECE59899BULL,
			0x3C1E901E4CA165AFULL,
			0x568922D8A9F7B4C2ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x004F25E5B69C89C8ULL,
			0xF89E376C9B5034BAULL,
			0x39AF0332F19162B7ULL,
			0x4169EBD858FA8118ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x40AC0CB4BDF05907ULL,
			0x9A68743684A3B531ULL,
			0xA97DFB3C8A0A256EULL,
			0x0CB53B85790A04BDULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF48B1CD73807429CULL,
			0x2922CF1C878314B6ULL,
			0x01ACC1E63674CFE9ULL,
			0x0BEAABA7564B5E4DULL
		}
	};
	printf("Test Case 474\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 474 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -474;
	} else {
		printf("Test Case 474 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x6ECA9FFEC846FA80ULL,
			0x1A1A0FEDD69764ECULL,
			0x7487F4788B0FC547ULL,
			0x6E23CAE1AAC7AA75ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x1AD21A1100B7583BULL,
			0xB16D9E446E8FB6DCULL,
			0xD5258CE6477E3A6CULL,
			0x711B1A74E9ADF280ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x3289C8CA6D0A0CD8ULL,
			0x57544FAD8B624376ULL,
			0x3B88BDF75575AB14ULL,
			0x4304FA30948179B0ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x3FADE18AED9C0DA3ULL,
			0xD487D123D1F9DD16ULL,
			0x2DF50BD9228C4237ULL,
			0x2E964234D4BC682CULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x8B66864C8D1F168AULL,
			0x676E19E6438290D7ULL,
			0x7ADF597D335909C6ULL,
			0x7644FEEBA8DF2734ULL
		}
	};
	printf("Test Case 475\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 475 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -475;
	} else {
		printf("Test Case 475 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x95E7A86D0816DB88ULL,
			0x0FF7096BDDC336BFULL,
			0x633D710644AA800EULL,
			0x63AA7731A2B0C377ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xAD2329F45BA7C1CEULL,
			0x830D3E19FBEB5248ULL,
			0xC9D90DD878CC8CBDULL,
			0x339606156762884CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x4A6952B666C76498ULL,
			0x0A291CB69A5BBED3ULL,
			0x5B50D6F400CA41F4ULL,
			0x521AA027925C7CE5ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x957C3DADC6D03128ULL,
			0xEC9D3D6326A15F85ULL,
			0x7839E85CA7095C89ULL,
			0x466D702F38A05A47ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x10A793E9241746C0ULL,
			0xB1524B84D359E808ULL,
			0x25C8E3D25D3983D4ULL,
			0x30DCEB32FA28A835ULL
		}
	};
	printf("Test Case 476\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 476 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -476;
	} else {
		printf("Test Case 476 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xB69AEDB9235EAB08ULL,
			0xE44DECD5F8452404ULL,
			0xC1633183E5080C83ULL,
			0x7F5C380BA8FF2E9EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x8F2B72444CD30BD9ULL,
			0x85B142B243C50F6EULL,
			0xE54DC3797E10D102ULL,
			0x2BB9470F4055D1E2ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2D8ADA39413AF930ULL,
			0x5CCC085306747A43ULL,
			0x4FE7E323A6CA8A05ULL,
			0x70675F89D75D47D3ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x5F30021AFFD9EAE0ULL,
			0x1A81FB361E35B358ULL,
			0x33C40297D88CF239ULL,
			0x5E44D897E67A27ABULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC9B096ACCCD52BAFULL,
			0xD12EB17517895D69ULL,
			0x50E4FBE487689F63ULL,
			0x5569DE79C5604C9DULL
		}
	};
	printf("Test Case 477\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 477 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -477;
	} else {
		printf("Test Case 477 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x8E852B1D345332A8ULL,
			0xD72EA94FE99964F2ULL,
			0x5D916D1E3B4CCB0CULL,
			0x595284DF53D257A6ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x23A2CD5325C59F42ULL,
			0x4CC5A9D4CADB63D7ULL,
			0x0EF2D5F485FFB5A2ULL,
			0x42D0D81ABE772159ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xA4158471F9809E40ULL,
			0x193669AF31F53B7FULL,
			0xA5A788AF1B5D833DULL,
			0x78CD5859402E2E9EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x16549B14D330BE90ULL,
			0x8AE6BA35FE0BD84DULL,
			0x806B08DC6C965D0EULL,
			0x3F557DDE2D13C4D8ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x2D6F2DAFE2F55680ULL,
			0xDDDAFBD75CC7D35DULL,
			0x81AB4CE11D48592FULL,
			0x2291118279A46977ULL
		}
	};
	printf("Test Case 478\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 478 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -478;
	} else {
		printf("Test Case 478 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x8F59899455CF2140ULL,
			0x0C8A7BB224C8B170ULL,
			0x5BD07CF3FD8B060CULL,
			0x635D4986F5BE42BBULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE59C82DA2E03EC5FULL,
			0xFC1F28C0F4EC3D7FULL,
			0x1DE620F01C03C005ULL,
			0x4829B873CCFDD110ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x319FA73E9892B020ULL,
			0x00B1686346A3920BULL,
			0x28F369DD1E8451FDULL,
			0x5C0B11E4CE9920C4ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x191AC3817012EA78ULL,
			0xEF187869DF57B4E2ULL,
			0xD9ACC4E0426EAC8EULL,
			0x367CF416B0444720ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x66E62AA877C5C395ULL,
			0xD8C653FB41A06B17ULL,
			0x78BC4B240685F248ULL,
			0x28028A3A38CDD8BAULL
		}
	};
	printf("Test Case 479\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 479 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -479;
	} else {
		printf("Test Case 479 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x253D80CFE6B0F750ULL,
			0xB5FAE29BBC34B470ULL,
			0x61E042DE9584F77DULL,
			0x5AAB35A2055F0AAEULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xFE898D8275AB86C2ULL,
			0xAF03792EFF1540ACULL,
			0x78B7F698D16BD588ULL,
			0x15413515C2D52119ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x66A7D37B6D795D28ULL,
			0xE3A36F4A6FAEA5DAULL,
			0x14BB62D29F048209ULL,
			0x5966989D7DFBDE40ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA735C79947195F9FULL,
			0xFF4826F5C2CB2AA1ULL,
			0xD12423D2E2338C4AULL,
			0x42166438729B50B7ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x14F60D7F0F3D07D5ULL,
			0xA2F27393D66FED4FULL,
			0x1787846EE2CA3786ULL,
			0x38F1D5BD6D5272E2ULL
		}
	};
	printf("Test Case 480\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 480 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -480;
	} else {
		printf("Test Case 480 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x3F16497CA2671A78ULL,
			0x759E6AD95BF50061ULL,
			0x4801E3292C33C9DDULL,
			0x40B27F0DDB5B67E9ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xEC518FE7B0916076ULL,
			0x5CBA33F126D086EEULL,
			0x64FFA7F26CA95F23ULL,
			0x6CF60C0A2ED417A0ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB23496392D6DD888ULL,
			0x0D46443FF9B0F37BULL,
			0xE6487AE021BFE00BULL,
			0x417FFBE91EFD6C28ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x39E3348C4F70FA06ULL,
			0xE7C02749BAB695D8ULL,
			0xCCC3DC56F774EBCAULL,
			0x29FCC78380456068ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x8AC0B2726CB0F3B4ULL,
			0x7BF135F8F828E5A7ULL,
			0x361EBD40EF73BBBDULL,
			0x2E445881E4308F0DULL
		}
	};
	printf("Test Case 481\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 481 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -481;
	} else {
		printf("Test Case 481 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x173E57AE9E9F8660ULL,
			0xBC757C701C30B92DULL,
			0x5418B2F58BFFD4DFULL,
			0x4946661DF2E97BEDULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x91C715055400BBB9ULL,
			0x60F341492B87217BULL,
			0x105F3DAFE5F36678ULL,
			0x49CBD6E9F22552E6ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xDE4B37A31FD7A180ULL,
			0x60AB33A18CA602F2ULL,
			0x60D526A8AC461946ULL,
			0x716254D4BD5B41A5ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x9117D34E4B6F4FB4ULL,
			0x3D2FC7EFB33AFB77ULL,
			0x462B4A78AE272502ULL,
			0x680F5C1A72A8A9EEULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB4201F718CD09CD0ULL,
			0x99C1C5759896C2CDULL,
			0x25A054D477B5D8E8ULL,
			0x4B7119188FA1C6A9ULL
		}
	};
	printf("Test Case 482\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 482 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -482;
	} else {
		printf("Test Case 482 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xB45AE6A40CDD2798ULL,
			0xB70BD8A2AA4DBC2CULL,
			0xD4AB6FCE2B151FBDULL,
			0x67A833D4C2611055ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7537A359C11554B4ULL,
			0xC488F20C43961413ULL,
			0x678B5BDC40D596EAULL,
			0x1FBA37C54DC13677ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x216628C589781D38ULL,
			0xEB47EAB9E8C9A4B1ULL,
			0x1CE446964E396D1CULL,
			0x481CD70368181060ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x3676AD9CA1D0F106ULL,
			0x2D3AAC21A94EA59FULL,
			0x02C3C1BC50B3860EULL,
			0x71E51FE0D18BD34EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x03C90265946EE940ULL,
			0x4E12619E1865E8CFULL,
			0xE3BD26A95D357770ULL,
			0x11C2DB7E5BA3997FULL
		}
	};
	printf("Test Case 483\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 483 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -483;
	} else {
		printf("Test Case 483 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x1D92A24DEAE764C8ULL,
			0xDF527EC42CEF0036ULL,
			0x2FD3469F8C7F4113ULL,
			0x46A921FC351B25BFULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xD45FBA666886F863ULL,
			0x8B75A328279DE4CEULL,
			0x55A1C416427BF252ULL,
			0x0F71AACAF6911430ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x7AC1615F389A5F90ULL,
			0x2793F3D9A80C9B2DULL,
			0x26420C32B84CC1C2ULL,
			0x6AF99556688EB65CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x9C5666A7E02950DCULL,
			0xDE7AE73666590B4FULL,
			0xB1702BC420E3CD04ULL,
			0x36A6BABE6B3C8061ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x179932C39A42567FULL,
			0x65A8E8853ABE4B8CULL,
			0x0C07C4B9A820B42DULL,
			0x34407BCEA23628CDULL
		}
	};
	printf("Test Case 484\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 484 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -484;
	} else {
		printf("Test Case 484 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xA16CBAA5D9ECED40ULL,
			0x1C0C1655D9CFCFAAULL,
			0x456CFDD89B79A326ULL,
			0x6434058BBE5FCCA1ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xD1CAEB8B3396FF27ULL,
			0x4B003249CB3B8D7DULL,
			0x72E9D678D1345002ULL,
			0x0CB7437490605B47ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x8FA5FBDD38AD7B88ULL,
			0xD837274028912869ULL,
			0xA6718DFD185A5F34ULL,
			0x65D543AFDAC42CD1ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD33344449D477C77ULL,
			0x5CE40AE1D02864B5ULL,
			0xA248FC35B8695C54ULL,
			0x7C4731FE020A208EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xBFA269C0ADA1FA89ULL,
			0xACF286428D6C1D05ULL,
			0x850401DCF0EEC2F2ULL,
			0x0A62DA80F8E5B819ULL
		}
	};
	printf("Test Case 485\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 485 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -485;
	} else {
		printf("Test Case 485 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x60B3CB8C0B0A6468ULL,
			0xB69A19F051D64101ULL,
			0xB3E76AC7E3F2A2B5ULL,
			0x4693C4ED648EC043ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x623DAA414D42862EULL,
			0x17B51DF54393C8CEULL,
			0x78FDF2406E3E73F9ULL,
			0x6B0F152182F4AA94ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE32D1107AD4EAE00ULL,
			0xA52213889CF18317ULL,
			0x009D3BEFAE1D71A4ULL,
			0x6B3FB0379C81353CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x550DDB543B528DF8ULL,
			0x629E11986BC64341ULL,
			0x0362F59DB4DC6FD2ULL,
			0x1A05C3DFD4CDAD56ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x47C9FB4777FB5038ULL,
			0xB74F5C01F77B6ED3ULL,
			0xDE18EC68CDBD1FD6ULL,
			0x4E50A5F6D736393DULL
		}
	};
	printf("Test Case 486\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 486 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -486;
	} else {
		printf("Test Case 486 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x98D4C424781FA388ULL,
			0x45C6C450F706686BULL,
			0x7C6C07D5C380B84CULL,
			0x40094D442EFAFA37ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xF2A4ED532BA8FF69ULL,
			0x838D1AC0B4FA1210ULL,
			0xA920F38CBD60463BULL,
			0x67A66FEEF8415F81ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9159EFA7222CDC08ULL,
			0xAAD52E9298F23E32ULL,
			0x6F5F99904F0A28A3ULL,
			0x483213DE477F836CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x8178FDEC136D40B8ULL,
			0xDA2F0629276FFB5AULL,
			0x812037CC9583251BULL,
			0x2B6296570B155CF6ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x8EFEA3A1CBF3215CULL,
			0xC43D99786AE1F7F2ULL,
			0x8ED76544F084E28BULL,
			0x4A651F24C299325EULL
		}
	};
	printf("Test Case 487\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 487 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -487;
	} else {
		printf("Test Case 487 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xEE383252B87BA008ULL,
			0x44B5164108F6AE0AULL,
			0xB3A8A52893067F2BULL,
			0x44CFAE0C0F0576DFULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xECFE17459BDE7603ULL,
			0x7D2D9C0E0996A7C9ULL,
			0x42322D15907E76BAULL,
			0x6E95E2038C8E1872ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x95E6B22832715588ULL,
			0x81B48A77C5118E97ULL,
			0x96E440677C10126DULL,
			0x62DCAB51B5E730D9ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD243180BB458F435ULL,
			0x2B4CFADC0E583F93ULL,
			0xBBF6C9ACC1668CA6ULL,
			0x233DF2948F006987ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x61F7BCB26BA0EDD4ULL,
			0x86C815DCF352AAEDULL,
			0x20A01EB52B76D674ULL,
			0x0D82B51F2B90874FULL
		}
	};
	printf("Test Case 488\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 488 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -488;
	} else {
		printf("Test Case 488 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x66786ECC85B3B1E8ULL,
			0x04B8B39721164DC9ULL,
			0xA2C7E129B70F6A27ULL,
			0x66A502D0599B28DCULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xDA2ED80646322D68ULL,
			0xFB4164435749AD0DULL,
			0x8679DACBE4D2986AULL,
			0x464F12A8C1B12839ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9B5CC46D9793BDD0ULL,
			0xEB9E52EDE53543BCULL,
			0x3889C7C48A4CB4ADULL,
			0x79AACF5266335DC9ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1ED477D48D35CF29ULL,
			0xB3F7AA8EDAC86AA8ULL,
			0x3653DE0CE36537AFULL,
			0x1FF9CCD0ADC0D07CULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD0EF1CAAC02485FDULL,
			0xA9D92CAB23CB44CFULL,
			0x9A31E5D602B3C277ULL,
			0x00032711C82FD5F8ULL
		}
	};
	printf("Test Case 489\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 489 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -489;
	} else {
		printf("Test Case 489 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x5087DDB429780E20ULL,
			0xE0623778CBF591B4ULL,
			0x77007A8CBA47E597ULL,
			0x714CFBB3B03A4973ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x3DB75B9D780A40C6ULL,
			0x8231DC0F5E052840ULL,
			0x5D41C0A1940ACE88ULL,
			0x57C5BD223F2E631DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x8655B8D0A7BB2408ULL,
			0x9D1FFCD8DC9318A9ULL,
			0x4443826A4305E666ULL,
			0x560E1F795EBE58B0ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1EE2A36AAB907C2EULL,
			0xFD41D6AB7967F47FULL,
			0x256D6BEF1825B8A8ULL,
			0x05C651AA8988A659ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x154A329CBCB958FDULL,
			0x63BBD68D4DC8E69AULL,
			0xC021FC59ADD6315FULL,
			0x60475DE1399DECACULL
		}
	};
	printf("Test Case 490\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 490 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -490;
	} else {
		printf("Test Case 490 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xE7ADE786DECFBDB8ULL,
			0x906391506E5E353EULL,
			0xE109B209D25CC7B5ULL,
			0x6CD375FB35C04F46ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xF3531F08C7B249B8ULL,
			0x6F0A4BD11D586F20ULL,
			0xC151A9EABEC4F64EULL,
			0x1B3CBB342850992CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x0EB7C46AB39B5FF0ULL,
			0x0AE6B0227839CD9DULL,
			0xBEEDCBED9B2B607EULL,
			0x701D0CBA64413522ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x0584FA3CD45A3F37ULL,
			0x1E7D1641AFE6FB7AULL,
			0x8743B2BC5613BA34ULL,
			0x2EC5077043521C45ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x9C59E8F0F6B005DBULL,
			0x5552036B60F2CC6FULL,
			0x87AB7D6A8C341425ULL,
			0x58CCF0B881BF6328ULL
		}
	};
	printf("Test Case 491\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 491 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -491;
	} else {
		printf("Test Case 491 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x58C1B3A907F9A0E0ULL,
			0x283244A78CF1E833ULL,
			0xAED2D22DC3CC39D9ULL,
			0x4F54BF3C566A1FE6ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x6B6631E6E6817042ULL,
			0x41E38B02C5FA987BULL,
			0x55DCD5D99DC9F524ULL,
			0x3F92B184C98BEF5EULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC94731BAA54A6068ULL,
			0xD457121897EEC7C9ULL,
			0xC2B721A6B1747238ULL,
			0x6889061416F548DFULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x63F538E0FFBA5539ULL,
			0x7BCF711D5A47B5A9ULL,
			0x51489ADBE0E8C46BULL,
			0x061B4C597C45CBDEULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x6474485A417EC620ULL,
			0x06293993667E6B4AULL,
			0x669BA2C820353C20ULL,
			0x11BEBD9AB9C129C2ULL
		}
	};
	printf("Test Case 492\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 492 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -492;
	} else {
		printf("Test Case 492 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xB04433FB361F6090ULL,
			0x81FEA0720AE6E2A6ULL,
			0x8D9A9BCFA622D325ULL,
			0x579763108ED7DED6ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xBEDCC3E64119F47EULL,
			0x9BD71731E89CA3DDULL,
			0x85EFE2ABE98A2272ULL,
			0x2DBD1F955A5F4B6FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x7A325861E9EDB028ULL,
			0x9EA76B353D6070A2ULL,
			0xC685077C71A271F8ULL,
			0x6E94E1839ADC9EA4ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x2A50C3A2972319C9ULL,
			0x77258FE5944BAF93ULL,
			0xF1EF9BF8B2A1DCD1ULL,
			0x6287AC2FAB43EB11ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB6A16F3B1C13AE57ULL,
			0x7042E962417F3B61ULL,
			0x42336E16F9E587DBULL,
			0x1ADEC6D895DC4D60ULL
		}
	};
	printf("Test Case 493\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 493 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -493;
	} else {
		printf("Test Case 493 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x023C14E69510B9C8ULL,
			0xDB8471F31CE81366ULL,
			0x2F757CAF8904AF38ULL,
			0x48334B1E7E14A361ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x481E22CE0E833DCEULL,
			0x92E4CF3561D7723FULL,
			0xBF41684558D478A2ULL,
			0x382AF43D8016F554ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x72F7A620BF9C1D90ULL,
			0x9C9C6CF0FD9A7C15ULL,
			0x5F1EA75708839B71ULL,
			0x6D93FAA0D090C41FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x514940792A5D09ACULL,
			0x45394C3498D19210ULL,
			0x7C9E3E5131E76104ULL,
			0x121D516CF48C165BULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x1025E0EF0579A9FEULL,
			0xB7DDCB4357F20446ULL,
			0x3B26ED1D1A077F9BULL,
			0x74FE2E4415CCAE92ULL
		}
	};
	printf("Test Case 494\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 494 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -494;
	} else {
		printf("Test Case 494 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x65A301E72FDD4870ULL,
			0xAACF09C437598782ULL,
			0x813B6FD8DCFC8438ULL,
			0x48586045A2745486ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xEA0419C3D7F29F69ULL,
			0x2E272A891E4636DEULL,
			0x0226E637F7AD533AULL,
			0x07EE5AC1FB7AD0F8ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB50AFCA07B621530ULL,
			0x77D2BF5A06CA6742ULL,
			0xBE6474442E07481CULL,
			0x50BFC6D73C5C3CE4ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x24492A486BFCCD32ULL,
			0x6F6F5A4360752D94ULL,
			0xCFDEFCA1C1C39FA2ULL,
			0x35E5D9939B48F332ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x929A310074BFAC15ULL,
			0x0AB338D14494A995ULL,
			0xC01329B7DCF0A37DULL,
			0x1450962C7521F2C5ULL
		}
	};
	printf("Test Case 495\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 495 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -495;
	} else {
		printf("Test Case 495 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x9E9B084A2B183F60ULL,
			0x623D282638207792ULL,
			0xF1EEDB330B5A9A99ULL,
			0x4B4629A79BA5597CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7EBE51BB206E5254ULL,
			0x073B8928E5509960ULL,
			0x6D382AFA382ECA6EULL,
			0x76F950B0E43F8984ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x30BEBEBFFA99F278ULL,
			0xC4C2D35B69D76C06ULL,
			0x7F415BA64918B822ULL,
			0x698D7F9A0BE7A70DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xE75ABA84E9E0D134ULL,
			0x749DA1A5799DEC25ULL,
			0x1943FD093EF4CCE1ULL,
			0x0D8FA721507B4B43ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE5BA9B095017F181ULL,
			0xE89F3DDD5A86221CULL,
			0x1C07FA8355234C69ULL,
			0x7BBB00A1F34E3904ULL
		}
	};
	printf("Test Case 496\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 496 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -496;
	} else {
		printf("Test Case 496 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xFE3F07C84A506ED0ULL,
			0x951A77B96FFCEEF8ULL,
			0x587C131DABD38194ULL,
			0x7E70A993FB93F5A6ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x55CA103BB771F6D6ULL,
			0xF1193B626D2EFA5BULL,
			0x0435866051A1CE14ULL,
			0x60BB0B461D2F8583ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x8B06FC6A23919FC8ULL,
			0xCD251FF929A68A03ULL,
			0xDB9E8C8D32F4AED5ULL,
			0x73A1B945ADCB2185ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x6E8CA7389D599A79ULL,
			0x68172093366A22C9ULL,
			0xD5D39EF9D117C718ULL,
			0x0C68AC4AB5F23B8DULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x3189442A9F176986ULL,
			0x52ACF55A4E8D1992ULL,
			0xAD526C4378E422F0ULL,
			0x091E5949AE663E2BULL
		}
	};
	printf("Test Case 497\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 497 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -497;
	} else {
		printf("Test Case 497 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xB6B232B70202EDC8ULL,
			0x0EBC024370E9EAE7ULL,
			0xCC98673507D31296ULL,
			0x43ACC57BB37AF7B2ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5EEA5D07B96C20B5ULL,
			0xC13AFB6178043E96ULL,
			0x97F93EEBDC07F921ULL,
			0x725A907D80BAC92AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x7BEE576779555B28ULL,
			0xD80B030C8B159E29ULL,
			0x4CE0C0E673D51487ULL,
			0x5972472B5B31601BULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x71827B955A8A9851ULL,
			0x8D852958B537C820ULL,
			0x6B969DB9F44CB075ULL,
			0x68A650C4CFCCD80EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x6258204F0F447F3EULL,
			0xC9B68C0442F3C753ULL,
			0xAF2EF236D173E2A9ULL,
			0x702C3B2D895E892FULL
		}
	};
	printf("Test Case 498\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 498 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -498;
	} else {
		printf("Test Case 498 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x1BDD07D223A251E0ULL,
			0x3F1C80EA8C8D2B23ULL,
			0xAD69C886F0627616ULL,
			0x7251CD74107B2BA6ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xB2D0A7C085403E0FULL,
			0x8065A0DC433D1BDEULL,
			0xAD4247B60706F649ULL,
			0x20E8EDBB685D6A82ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x02A756541D987F90ULL,
			0x20174CD803580E5DULL,
			0xA08FB72A96D22E9CULL,
			0x62D00096F4B1626EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x42945A2E8A0A753AULL,
			0xD7BA5DFFB38F32E6ULL,
			0x8B968AED4F1064F3ULL,
			0x3163EECCC9271873ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x8986995C707A1324ULL,
			0x427FAEF9A7A6CD16ULL,
			0x814C807BF752BBBFULL,
			0x5F5B6DDC69E1958CULL
		}
	};
	printf("Test Case 499\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 499 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -499;
	} else {
		printf("Test Case 499 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x2AF57B08EDCB3960ULL,
			0x24A6E75F3D7E2B72ULL,
			0xE9E37E93EF0A0C93ULL,
			0x5FEC769DCBCDDDE5ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x8752A9D3B37D6A76ULL,
			0x3098DA10F00E5A92ULL,
			0x098E4330E951FF27ULL,
			0x22649FA04A017259ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x29572616B7ABC3C0ULL,
			0xC2B5FEDE4C7FEA54ULL,
			0x2819FEBF2BFA4A67ULL,
			0x6DC1891CF2847815ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x64D0D5E89938DB23ULL,
			0x9910ECF97AB95D76ULL,
			0xFF2F1DFBD2E57778ULL,
			0x1972C3D403E4D859ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x91F3D53A5D59AF5DULL,
			0x82A215FCDDECA528ULL,
			0x567AE3D3BA2060AFULL,
			0x54860812C933A795ULL
		}
	};
	printf("Test Case 500\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 500 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -500;
	} else {
		printf("Test Case 500 PASSED\n");
	}

	return 0;
}