#include "../../curve25519.h"
#include "../tests.h"

int32_t curve25519_ladder_test(void) {
	printf("Montgomery Ladder Test\n");
	curve25519_key_t n = {
		.key64 = {
				0xA195E0969D25A7B8ULL,
				0xA683CFE8087E076BULL,
				0x0E57CE3FA3429BD5ULL,
				0x59739BE720690D94ULL
		}
	};
	curve25519_key_t nBASE = {
		.key64 = {
			0x89CF23C4BE126E65ULL,
			0xAF9DAFA85AC8643AULL,
			0x71C59E09714FF748ULL,
			0x436443FED73CBAF1ULL
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
			0x1674F5E47AD48BB0ULL,
			0x8A08D3FDD90D8099ULL,
			0x1E0BE56B1D0464DCULL,
			0x61A095AD83FA56CBULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x59416D80A1650DCDULL,
			0xBC58E4037CFC1659ULL,
			0x920A27AFABB03A26ULL,
			0x3C789C03B68C767DULL
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
			0x8F4278E096B984F8ULL,
			0x4D8DBB180AE71843ULL,
			0x785E2A8CB9E59415ULL,
			0x57465C4CACAE1594ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xA7DF7A72614209B9ULL,
			0xA4E4F589A7BDA2B2ULL,
			0xE34F9D246839E686ULL,
			0x46728CB0978A3444ULL
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
			0x2973BC5EFB7D2658ULL,
			0x171BD93315EFB739ULL,
			0x1C9C2FA14A2FA792ULL,
			0x72FC545C05E0F3F8ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x306DE5370CE392E5ULL,
			0x3C170E81558C3B2AULL,
			0x4A4E7F644054714FULL,
			0x5EE5A0B49DCF5211ULL
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
			0x7134BB8403A29788ULL,
			0xB121222B72D1B5D3ULL,
			0xB479922A090BD845ULL,
			0x736A4371C1712023ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x259994DD868D01D6ULL,
			0xD6114F4B8F2D98F9ULL,
			0x034265CC1F9427F0ULL,
			0x4C9F688021F12217ULL
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
			0x055E0AEBF015F388ULL,
			0x7B24F50A1505AFB7ULL,
			0xEC961B946B189572ULL,
			0x55385FF449578D0FULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x90D5E10575C8979BULL,
			0x576C3B8CDC8CD612ULL,
			0xEF576FD89F209C88ULL,
			0x1F081AC81261ACD1ULL
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
			0x36A5F1CDDB620478ULL,
			0x735A393006CF3E8CULL,
			0xBED9C01D59E8550EULL,
			0x64DB0865CB4F93B5ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xE10EE4E8DD744579ULL,
			0x8E1757D38973DA00ULL,
			0x41931EA7DE02FE38ULL,
			0x675762B9E64E42C3ULL
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
			0x87A8EC5B823FA520ULL,
			0x4E5530C0D3FAC6BDULL,
			0x1EBB3959DAC8BCFEULL,
			0x453AD627C8624612ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x9F057D785090D843ULL,
			0x8C79B15B05F1B44EULL,
			0xA427D0474ABC5AA6ULL,
			0x40650882C1A40ACEULL
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
			0x54548851C3B1F650ULL,
			0x1168FD6F038FC79EULL,
			0xDFAB76F672EB07CDULL,
			0x6A22473C171F6899ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x768CEEA5ADB24F5EULL,
			0xABD36B64C368EA96ULL,
			0x5933F5B9DB8FFD35ULL,
			0x3EC1F7F25D97BCC6ULL
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
			0x27AC4E62E923D050ULL,
			0xCFC64BB763112DCFULL,
			0xEC362DB2D90ADA6CULL,
			0x638F42663B055C3AULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xD71B59C792CF951FULL,
			0x1649B227455CEC5EULL,
			0xAB4F020CD1CCACD6ULL,
			0x0CEF3BFBD55F9B0DULL
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
			0x8C36252FB82766A8ULL,
			0x723AE49373919FA4ULL,
			0x7F62CC121E61757DULL,
			0x5A576135E53CE4F2ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xE636CE7E56923FC7ULL,
			0xC056F20F9C4FBC3FULL,
			0xBEF288C5EA6449A1ULL,
			0x709FA399FA4A0107ULL
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
			0xAD1E141661C64A28ULL,
			0x4501E2185E47B6DCULL,
			0x7F5BCC50E0894ADEULL,
			0x69EC5E0C4682CFC3ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xC531329BC1CC1727ULL,
			0x2C9CA0BA6845BD82ULL,
			0xE9FE71F04A66B07AULL,
			0x66D6DEACAD595BC1ULL
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
			0xC679D37ED7029A88ULL,
			0xA495EE5ED12D7093ULL,
			0x8165E78DD6AECEEFULL,
			0x75093E917F373BE9ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x6C163B068881B38FULL,
			0xD4E02796E47F2D6CULL,
			0x2E103056D6573302ULL,
			0x10A3FC16E556C8C6ULL
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
			0x673ACCBA38A22A70ULL,
			0xF18F6228362A7C06ULL,
			0x5A96BB6F33C47BC7ULL,
			0x582FC66C981C607FULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x4F100C7CA087D9A9ULL,
			0x17CCF85F649EF825ULL,
			0x2A5DE76344CA86E5ULL,
			0x2310708523181F41ULL
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
			0x510C9FBEF9631F08ULL,
			0x0F309732942A5EBEULL,
			0xC744750611473BC3ULL,
			0x4BB33B5BC489DD86ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xCFDB630F75A9A73EULL,
			0x0AFCD8E90B943F55ULL,
			0x9058B932F501047BULL,
			0x3BCA6CCCEB44AB7FULL
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
			0x6713DEA2D6DCD788ULL,
			0x3C43F75A1825F738ULL,
			0x3CB8407E49A50CB9ULL,
			0x5B9088DA672CD024ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x6D9A95B8040C0780ULL,
			0x10AC4010976D368CULL,
			0x54CA024648441785ULL,
			0x47AF144FAF03B0BAULL
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
			0x79759E07E5C29D30ULL,
			0x63C8725B48311B1CULL,
			0xADFAB46722138FAFULL,
			0x604EC7CAAB575733ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x8AD9FDE972D03FABULL,
			0x6E98E20D913FA89BULL,
			0x1501BA28DEE24D9FULL,
			0x5589EBEBEB421364ULL
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
			0x4C824F8528607098ULL,
			0xD930051D73BEA519ULL,
			0xEFD99F0E903AB15AULL,
			0x76768820C5A2EB37ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x6641F2A227ACB234ULL,
			0xDC7CF5438E7375ADULL,
			0xA2118938F8BDE351ULL,
			0x23FF595E6E372116ULL
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
			0x228171C809AEB480ULL,
			0xA40743EF72673326ULL,
			0xF3B95BCC9D1F8341ULL,
			0x4434F9A4000265A2ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x90E9CC55DF0B6D4FULL,
			0x410E916812632C4EULL,
			0x35AB86015F9AED3EULL,
			0x783FCA87FD99A7FBULL
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
			0x87E5504E141252F8ULL,
			0x17DF8B7DE9B01A59ULL,
			0xCD36938A013C4A4AULL,
			0x62D0D6D0807FAF02ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xF7E4C86E37B159CAULL,
			0x336D60798558383BULL,
			0x6125A359A4983AE2ULL,
			0x5C109F2FF368CE1BULL
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
			0x209F56C3BC91B2E8ULL,
			0x0E8189B27B0050CBULL,
			0x8E45D5F4BE4B03A3ULL,
			0x5F421F16EE17E1B2ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xD7CFDBB57D9F1400ULL,
			0x0BC5CC74DC485AD7ULL,
			0xF248CB4B60B8C848ULL,
			0x2BBDAB862A6D9678ULL
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
			0x0163E38B76868A10ULL,
			0x8046798E18492DEAULL,
			0xEB8CCB6C46A1CC68ULL,
			0x63EFF594CC58B430ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xFB3F1D237CB4C382ULL,
			0x7F7FF9707FF1C3C1ULL,
			0x4DB32BB8B3A6C3C5ULL,
			0x20F6EF1FB928C3C7ULL
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
			0x9CC8C727F4A1F1F8ULL,
			0x1CC330D8F594FDB8ULL,
			0xC9C4794CB67655CDULL,
			0x7CA4DCBB69D05309ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xEA8536CF46373E3BULL,
			0x9D096177C8160DF4ULL,
			0x45F07E40100BDB7EULL,
			0x0FCD50FAA5A61808ULL
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
			0x1A59332A010AAAA0ULL,
			0xF4977A05F9E4A8FBULL,
			0x3ED265DD851CE0C0ULL,
			0x416F4A88FD5B0DE8ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x74F87D86F9A03D5AULL,
			0xAA252504C64D4785ULL,
			0x6D465840440216BBULL,
			0x64AD4E8F51F5DF17ULL
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
			0x7DB4F00E48D7A1C0ULL,
			0x5B2DBB6DEE2E6D67ULL,
			0xAF116F11EF9D214CULL,
			0x480E4FAB698E1B51ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x7B992267FF085886ULL,
			0x2E9D6F0D6DCCAEBFULL,
			0xC09251CC6CD841EBULL,
			0x2281A7DC4CE2A4DFULL
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
			0x36BA197B82800DD0ULL,
			0xAE72419941F6F50EULL,
			0x089095F8260CA8E6ULL,
			0x6076911356F20216ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xB7146ABB78156806ULL,
			0xFDDD2602E5280681ULL,
			0x70F635B57E38A048ULL,
			0x4132F2031C73414DULL
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
			0x7A95E05B7F967D18ULL,
			0x041C2A5F2E6BCA42ULL,
			0xA96458C5445656A8ULL,
			0x52E4645CDA58292BULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x1FD3C12C5E708785ULL,
			0x0749B3741FB31503ULL,
			0xA403CE589EC1B766ULL,
			0x26C4ED4A3AD2DA6DULL
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
			0x167267FCE67CD250ULL,
			0xE19F98F368D10DB0ULL,
			0x2ABD4BE893FEF078ULL,
			0x56855EA23DC2492DULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xBC68E2C687E8C896ULL,
			0x03A83CC6958C6C8FULL,
			0x0F8981426229F152ULL,
			0x55C0C5D6578B7E40ULL
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
			0x4C36076CEC4BFC40ULL,
			0x183D33071FF4AC2AULL,
			0x02E8489F00EB32DFULL,
			0x746FBE35E8359EAEULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xF84F55BEC3D91D83ULL,
			0xECDAE0E2F441C1B7ULL,
			0xECD28437DE543CDEULL,
			0x4C0D7333DAB3ACC3ULL
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
			0x90AFFE440E8D5B38ULL,
			0x8A58FAB8C0CDC2FFULL,
			0xC17EBB7E8FD63954ULL,
			0x45C6C7B712D7F4C7ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x99F013C2D8FE07B2ULL,
			0x7D9CBAFE821AD98FULL,
			0x41FBB1F514954B6CULL,
			0x0A78AFA7ADFA5F5EULL
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
			0x07E0EC9D636AA578ULL,
			0x8B97D4E9724D29B1ULL,
			0x3FF1C5058756D761ULL,
			0x6F076B68F9BFADF8ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x00467CA7F2BABD55ULL,
			0x61162DDA5D98809BULL,
			0x87AA16DD7C692DEDULL,
			0x7C1D200C524537F7ULL
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
			0xD559207AF6692118ULL,
			0xE22E79358D2AAA6BULL,
			0x4B9567CACA83A2E3ULL,
			0x59F71C99F62F5DBEULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xEE4DC1FED903F2D1ULL,
			0xDF31D0961A53204EULL,
			0xEF29BBCECDD3A321ULL,
			0x20C513B1707F8F6CULL
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
			0xE6A00D2CBCC6C0B8ULL,
			0x83011150DC55DDAEULL,
			0xFD891D2737988B7BULL,
			0x44DC5E0C8021BAEDULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x27F7DC5B88456B68ULL,
			0x8480E595BB1C6E86ULL,
			0x033058B678EF2795ULL,
			0x689C39877A75B4D2ULL
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
			0x5A1FC4BCA07F0600ULL,
			0x7A1154E43988E6A8ULL,
			0x09FFCDEB2AC1683EULL,
			0x40E3022C5B720C77ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x3C2D7B03138D6713ULL,
			0x3067AF99DBEFD5FBULL,
			0x65A0FD85929EC0E4ULL,
			0x7E272861783E4B96ULL
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
			0x06969B69A374E660ULL,
			0xBE06FEDB7122A62CULL,
			0x6DC722602AF1924CULL,
			0x428FFE4C7C9E134CULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xA57FE153ACFB21E8ULL,
			0x02D11DA888633B2FULL,
			0x9E80075ABFFD6736ULL,
			0x0403E80766B72C7FULL
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
			0x2586A03E66E1E3C0ULL,
			0x038230B2A74066D5ULL,
			0x48A7C9A2E39CB271ULL,
			0x789902C6B5C3AFDEULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x3D7E88BA7FCF6183ULL,
			0xD7B368098CFF3007ULL,
			0x72D59E39D8849DDAULL,
			0x5BC4A14AD816EBABULL
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
			0x8E5A09CFA4146040ULL,
			0xFB4E4BBA3CB85DD1ULL,
			0x6C8F5E6CC3A8B658ULL,
			0x7AADDB6AB47DB052ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xB0B9D9D3AA56881EULL,
			0xE1F0987F3AC533DBULL,
			0xEC9E7B7CB8B200B3ULL,
			0x25D4DA566DB0E872ULL
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
			0x302BBC37868A08C0ULL,
			0x864B0E318E4E8D82ULL,
			0xB02B06834A19A050ULL,
			0x5DCB2047DC4C8232ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x2FB037203A68AEC6ULL,
			0xE517713089DD32EAULL,
			0xBDDEADDB118B515CULL,
			0x280F596E19AA8FCBULL
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
			0xCF9EDA3FAA1BB758ULL,
			0x7442A6BD61750C67ULL,
			0x8831F3B97F3F5543ULL,
			0x7C1E226FB0D99619ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x8CF12E0492CB4263ULL,
			0xF25800CEE6DE9F11ULL,
			0xBB31CC5DDC600880ULL,
			0x0803BAD436B7A997ULL
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
			0xD59EBBD5AFE11AD8ULL,
			0xC0D2BF0A33F05DB8ULL,
			0x0528D6F1D246CB86ULL,
			0x7295EC4D2588F604ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x9BB817E3F983F9DDULL,
			0xAE3E76382C8C223FULL,
			0x66DFE84C128D4EF4ULL,
			0x311EA0E9CDD47D38ULL
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
			0x4E36EE6F14873A48ULL,
			0x24E620F4BE5DCE7AULL,
			0xD973B798665FC78AULL,
			0x70EF07CC6C1400CBULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xA57A8B3570C5F0B0ULL,
			0x5F47EE9E6DE37A17ULL,
			0x22E3F75F4702E61DULL,
			0x093D08F2FC9E2181ULL
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
			0x26A73FF5DF166C20ULL,
			0xE181A697F2E5C331ULL,
			0x1E78CF67ACF21DEEULL,
			0x5CCE4A8F91506692ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xB6222F143AA3DB84ULL,
			0x986998C7C47F0DC1ULL,
			0xAF45D54ABA2BB53FULL,
			0x460DEDB7F4DB7B33ULL
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
			0x8624BF63D026F738ULL,
			0xDE80A4BBC9FB8A9FULL,
			0x19158F7A9256244CULL,
			0x4BEB0C4A451789F0ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x05347E2E52FF9A35ULL,
			0x4D63871684416A8CULL,
			0x05DF3F6FEC53A6BCULL,
			0x49A59E578837E578ULL
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
			0xB9A553C6D74C98B0ULL,
			0xDB885B211C37ECFBULL,
			0x01ACFBEBED98A61FULL,
			0x68E6D033617B7E62ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x4297E38A3AED9178ULL,
			0x2C5A8529E61AE93BULL,
			0xBA430EB2D70001E1ULL,
			0x54B3F2DB5C781C72ULL
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
			0x501E39935085DA38ULL,
			0x2D8C7EE564732A8BULL,
			0x5417B4EA13CAED3AULL,
			0x727993B0B95324C5ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xA0680B481C496365ULL,
			0x4003E19BB19923FBULL,
			0x98CC508F71D11635ULL,
			0x4745E0B3B49B4507ULL
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
			0x92C729C6F823C230ULL,
			0x2A595C2C1CBABC1CULL,
			0x46B09E8DD71EECE9ULL,
			0x6BC6B74079A7B654ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xBC794BFDB1ACF90CULL,
			0x977650C653211055ULL,
			0xAA787EF4EBBE6644ULL,
			0x0D50FD4B578D4D50ULL
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
			0xF207DD7F1C804CD8ULL,
			0xB86BE622FE5FCAA3ULL,
			0x4C8CAAC69A46F59FULL,
			0x70840C42261529EAULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x2519011026F69CB7ULL,
			0xF196F4792E9385CFULL,
			0x0627CDF40D216EE5ULL,
			0x00683BCDF93E44B1ULL
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
			0x77477ACE65271D80ULL,
			0xFCC3738BB560295BULL,
			0x9B650865E763E9B1ULL,
			0x6F83DD0F80A3A4F3ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x52C1E56EBDF85459ULL,
			0x4BA66551E5F79DF0ULL,
			0x827885F12F31019DULL,
			0x588F92B6E1FD0B5EULL
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
			0xE946F97A6E70D2B8ULL,
			0xE59C73AEEA3B9D2AULL,
			0x9847C55BE65E295FULL,
			0x5371AFA2478E2EA8ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x960133E41CF466D5ULL,
			0xEFDEB7B4B70DF47BULL,
			0xE89E74B10142EF96ULL,
			0x61C2464267AE66F5ULL
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
			0xA62582D0E8DE36A8ULL,
			0x4E8B46E4F4C040D6ULL,
			0xD1DFFFB5A761EC21ULL,
			0x6CCFB554C7DCF0A2ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xC4948570CE71FFEAULL,
			0xFFC9158529B4AABFULL,
			0x52F98783038670C6ULL,
			0x20FC629F2A013709ULL
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
			0xD02830E7F4D6F4B8ULL,
			0x205E1973671BADD3ULL,
			0x60E5546109F422D1ULL,
			0x56A86BB9187896BAULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x6B3D48EB75F3044EULL,
			0x4708B3266953B2EAULL,
			0xCA486F97EB2CBA95ULL,
			0x3FCAAD3D66B80AC3ULL
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
			0x09AF09CB6BBF39D8ULL,
			0x6B80AA858221DA2AULL,
			0xC6D2DADC4FABE63CULL,
			0x4713C258444CC123ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x30BE1C5AB2C6F331ULL,
			0x8492A756D816F57DULL,
			0x9651BC628DFC36F9ULL,
			0x3EAFD3A26429A360ULL
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
			0x8DC8174DB2C2FE38ULL,
			0x0B86AE8B23D3A16BULL,
			0x0A29604B3BDEBB70ULL,
			0x4E2D3BD1508A77A6ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xA20D6D4AB83F2B03ULL,
			0xE26875516424A20BULL,
			0x96FE5565FB3BEFCDULL,
			0x131441501483D0B6ULL
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
			0x04B740EB8A050E68ULL,
			0xDC3C3AD569FC6C3CULL,
			0xFBEB545B3EA94A1BULL,
			0x6151024449A618E9ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x46BCF87DB170DC24ULL,
			0x1EC7037B28E34319ULL,
			0x27619C71305CB068ULL,
			0x78ED9EB4F0F49072ULL
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
			0xF04BBAEC9F245000ULL,
			0xF1FB396FE0000A0EULL,
			0xC3CEF5A1DE8F448EULL,
			0x7E5B0DFBB4CAEAD0ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x6E3E997FCE365EEFULL,
			0x16BFDE0E4C059ACEULL,
			0xDE04D9901CE51A2AULL,
			0x1C80DC34D3B03ED1ULL
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
			0x1C7BE2CA35C1FF48ULL,
			0x434C4C859107C60DULL,
			0x9B3A1AFE25A896C8ULL,
			0x628077C2F17D4A6CULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x7B735B6D072130FDULL,
			0xE9D4DC6D903647E9ULL,
			0x3C848B3A05B5CD10ULL,
			0x7584867906EDC84CULL
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
			0xD63963FDD6B2C520ULL,
			0x86D0930B41A48BF2ULL,
			0xA311D7A88E36831EULL,
			0x6701E2792D8DDE83ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x59EAA797CAFD62B8ULL,
			0x6F8D0E330F559C58ULL,
			0xBB182AB4E7080BAFULL,
			0x581DDC2FF8D4F841ULL
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
			0x2AB6FB741F7C00D0ULL,
			0xDE9849096ADEB97FULL,
			0x54EB571EC22510FAULL,
			0x613438CAC901D28DULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x64A361FF9962B763ULL,
			0xC8EA8C2276FB92E5ULL,
			0x51F525176E7BA0A5ULL,
			0x3E5FDE2358AF3312ULL
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
			0x5A020E4FC76086D0ULL,
			0x68A0E568DAC4D3D2ULL,
			0xC4C4AC470D489B5DULL,
			0x5CAD748A5897A6E6ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x93304E00F467D643ULL,
			0x1DCF32026C04CB3DULL,
			0xCFBD60A778A2436BULL,
			0x4EFC8072C463F537ULL
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
			0x7FDB2946A3A5A260ULL,
			0x4886C2D273F5B9F0ULL,
			0x283293E690C7DE36ULL,
			0x593F91D0CD255704ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x06A4E453F20D0863ULL,
			0x97B511B6354ED528ULL,
			0xFA961E292BB013BAULL,
			0x3E80F79D9F2E1D4AULL
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
			0x94682AF1C8EBB900ULL,
			0xFB67E07C3C85DB80ULL,
			0xE9BE1BF477D9BF55ULL,
			0x77F5DBD9CC8CBC32ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xE50B3DAF534F564DULL,
			0x0462D2638B6DBD52ULL,
			0xFA450A9543FACC43ULL,
			0x1766394161CFB826ULL
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
			0x612D6CD4525E3F88ULL,
			0x4C4B099D770A878AULL,
			0x1B2B8DC192DB246DULL,
			0x47443058260BB446ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xAD1A68CC347D7D26ULL,
			0x4127AA6216413777ULL,
			0x08FB1D183DC8A0BDULL,
			0x6A0ABB6D86ECAE3EULL
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
			0x402A0BFA5275CAE8ULL,
			0x8700A32DB84844E8ULL,
			0x7C59C9E3EBF7500EULL,
			0x657F3B3295583DDBULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x73D066768F5E98E1ULL,
			0x02FF3132CE9B156DULL,
			0xD28A37FADE57B34FULL,
			0x51093AFB27BB682DULL
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
			0xBDBD25AA3D660A80ULL,
			0x62CD2508FDE4773CULL,
			0x26757998D548004FULL,
			0x4E5B1B2F622CE765ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xABC2F6F2B6637E5EULL,
			0x011828924423498AULL,
			0x8499821E9F780511ULL,
			0x4C7A209B00A6F1E0ULL
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
			0x645159BB465F4BD0ULL,
			0xE4510B990728DF99ULL,
			0xF2826AFC085C1A7DULL,
			0x4F69F73BC68F612FULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xA48ED517FBD29833ULL,
			0x8E001352B53A4C6FULL,
			0x8E38DB10ECACDF66ULL,
			0x71AB7766460EC27FULL
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
			0xDB253AD354E49A08ULL,
			0x3410343BAED1E4CBULL,
			0x97538C5BDDFD022DULL,
			0x4B75BE2D7AF70700ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xD698E930C290A0BCULL,
			0x12F9DF29F127B96AULL,
			0x108C01EA47620221ULL,
			0x71A62C6779A8A9ECULL
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
			0xA824CD66B24A86F8ULL,
			0x26692D451A876168ULL,
			0x831FA88F9D250A8EULL,
			0x5904F9E8C9F81C1DULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x9E250D438E9998D7ULL,
			0x4AF8337606272369ULL,
			0x1C29C6F670E46237ULL,
			0x6C02BEF65AA3E86AULL
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
			0xB12229CEF37CD798ULL,
			0x1AE2BD57A404FC30ULL,
			0xD967C39AE163ED1DULL,
			0x53A2853EA2C49359ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xD7648CFE0C96C40CULL,
			0x8656633EF3BA9A68ULL,
			0x02CA6C883A351C04ULL,
			0x45AE6F25F118A97FULL
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
			0x59022BDC0E9FB108ULL,
			0xCB6169024AC87272ULL,
			0xF633FAD13A1C8BF6ULL,
			0x7A718401E0FC7826ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x27329A4A4F90901CULL,
			0xCDDD89E589618549ULL,
			0x5D361375BFBA875CULL,
			0x178DB289B2F11C0BULL
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
			0xE9839D208682D618ULL,
			0x62EDC1E9E1B8C1FBULL,
			0x9D206E745F232112ULL,
			0x6A52B1600FD322AFULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xB43855EEA1327742ULL,
			0x8490C77257A05226ULL,
			0x9998D79D301BE288ULL,
			0x5A57653AB78E3C15ULL
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
			0x9F715918C86FC208ULL,
			0x4A3B168ED7A63239ULL,
			0x3E5896A38D6A5864ULL,
			0x5BA327DE49E7AB33ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xD0497FE57D17E366ULL,
			0xE728B3D77DCACE6BULL,
			0x5090D1749E51B89DULL,
			0x1704A6C0D58F0805ULL
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
			0x8878EAB892385B98ULL,
			0xE99D0D2198CA75ECULL,
			0x6CC4CD15E676C534ULL,
			0x459AFA6923F05C91ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x866DD08A9480DC76ULL,
			0x97CAE43BF96507BAULL,
			0xBF7C25F8AF595E3CULL,
			0x4AE5ABD7B2A2EE42ULL
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
			0x8938DFC99481AF30ULL,
			0x5F4AE14364EC3A7DULL,
			0xE76BBF97ED42F8D8ULL,
			0x52723E3A7459E450ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xBD9AC0876D316111ULL,
			0x8BB530801C10EE16ULL,
			0x51E5C65158474AEFULL,
			0x4D0D67F2E8430632ULL
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
			0x6ED63D9AB7929788ULL,
			0x20CB79AD35161050ULL,
			0x737C47D5A2D99B5EULL,
			0x47811D6BAB2F105FULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x97B94D42004B6614ULL,
			0xAD06A1EABDEB2AE7ULL,
			0x80F6280B73497249ULL,
			0x1968635DDE54E80DULL
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
			0x63827C0071FD1028ULL,
			0x6AF8CC31F9C8FC3EULL,
			0xE0A651DDCAE228A2ULL,
			0x5A0A07B44EC3E152ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x5456C964D0899615ULL,
			0x46B06BE6744A1D95ULL,
			0x54706B748846C682ULL,
			0x1B6EB960FA8530C3ULL
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
			0x4C075C97F4F559B0ULL,
			0xF454F896AA2B6834ULL,
			0x8A2512A909860197ULL,
			0x6D24A39A23DBD963ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x9DE80508270C174EULL,
			0x9C1C82EFDF9DB22FULL,
			0x3F0C0D96DB18626DULL,
			0x22DD0C4C473BDBD6ULL
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
			0xA693314AC6B11F80ULL,
			0x4E9CB5DF16D6BB2DULL,
			0xD699130057CBF337ULL,
			0x795C6AFA46E49994ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x0407FF1815615D1EULL,
			0xC126542FF87DEDEEULL,
			0x4627D24691624390ULL,
			0x3CF703D299DC915DULL
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
			0x16DC91461A9C1F50ULL,
			0x947C4B5C3CC3BC1CULL,
			0x7E0C59538B86F91DULL,
			0x74B6056F6E2F24F6ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x0FD880100341771FULL,
			0x80917DAB1F528630ULL,
			0x3EA6CFB6B09A170EULL,
			0x70BD22C389D50726ULL
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
			0xC6F97A1877DCFBC0ULL,
			0x5BC6E7BB2E3666CEULL,
			0x145E52459A5E7966ULL,
			0x7D60E1BE422993F3ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x6CDB22774002E76AULL,
			0xDBE88FD2FD16BD50ULL,
			0x95A8A554DA156D75ULL,
			0x0722AB47D0A010EFULL
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
			0x1835AC0DA9FB2258ULL,
			0xCB08657D98568830ULL,
			0xCF51DF2C0332E258ULL,
			0x5E55B2E0D8CC44BDULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x9BDF178AEDC2F724ULL,
			0x523B5E431F9B0B82ULL,
			0x0C1F95F5FF809B5DULL,
			0x47E052BB3E3E8F8FULL
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
			0xF4568991A2EDA248ULL,
			0x7F130979A2A323C9ULL,
			0x12F46AF4059CFE9CULL,
			0x7C8CF22EB59AE882ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x0135AECE9B985AEFULL,
			0x00A01F69FF6B880EULL,
			0xC45DE59A855636AAULL,
			0x15450D735FC28926ULL
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
			0x7502622CBAEF42B0ULL,
			0xBB3969A5B6A03381ULL,
			0x350C2240948A5127ULL,
			0x5398626675303C27ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x2B83D63A42AB12B9ULL,
			0x3348B17824D92615ULL,
			0xA36BB862EAE5040FULL,
			0x4957D56639F56330ULL
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
			0xF9224CF2377164D8ULL,
			0xCE4A889EB6938845ULL,
			0x1FED800AD35020B0ULL,
			0x7D483E3376B46FA9ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xD3568B14ABE957D5ULL,
			0xB0DDDC53058F2253ULL,
			0x87461393BA1D2574ULL,
			0x7AE3A460FF6F532CULL
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
			0x6A17359C5C496FD0ULL,
			0xB352F434DD04E544ULL,
			0xCC4A4A73F394C529ULL,
			0x7E6E74E141B65DE6ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x747104AC783E85CFULL,
			0x0113595AD44F23E5ULL,
			0xE64D9E7EA0A23824ULL,
			0x75B99FD7C36A44CEULL
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
			0x71524D71AAC424F8ULL,
			0xEAC463CB7BDC1AE6ULL,
			0x2F7DCC3EF50FD425ULL,
			0x4127CE4506615F4EULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x38B4F5852D12B678ULL,
			0xABA95D84489A4BBFULL,
			0xA1E5551B0366F9F9ULL,
			0x0ECA827CD6AFE9A6ULL
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
			0x04989D2779441EE8ULL,
			0x683B4920F73E129CULL,
			0xBBA062ECCA9B948DULL,
			0x582E2CEC153AAD5CULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x6F3167CA6CCF0C94ULL,
			0xD9D4650B2E255905ULL,
			0x0B8D81F614EDA29BULL,
			0x4AD27804595428FCULL
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
			0x08F4A94740EA4DB8ULL,
			0xFD55AD6C7E30FB98ULL,
			0x1A0BD587804ADD53ULL,
			0x59F98B365416B19FULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x6AC44196A5BC5287ULL,
			0x51B88A9805C80CC7ULL,
			0x7EA4831665504BBAULL,
			0x37B36E81E2B6DE7DULL
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
			0xFCD0A0FBF522C3B8ULL,
			0xED4C1B07F9957067ULL,
			0xA40B39B2DF2507E6ULL,
			0x4A7674CA0765A861ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x0C7A85C288FBEF15ULL,
			0x749090FA3FA5A53DULL,
			0x328B63BAADCE65F1ULL,
			0x733069B2B69A6DF4ULL
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
			0x5CCDE2DE69E98800ULL,
			0x697DE41A3E85F170ULL,
			0x959B0710D0192288ULL,
			0x7138678A45E4040CULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xDF611A8644FA2FE7ULL,
			0x20B90A796CC9C98CULL,
			0x0AF1CCEB0885F9EAULL,
			0x5218BAE4FE943FABULL
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
			0x171E2B30DDAF7D18ULL,
			0x1DA87D41E449729AULL,
			0x8DA1EED1AA49D64EULL,
			0x6727EB7E77F8188AULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x4A23AB176207F6B6ULL,
			0x078826F6C55531FDULL,
			0xF3A7C36F2BC803DCULL,
			0x58AE5968D6201F0EULL
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
			0x782EE0EAE8177878ULL,
			0x73063B5A17FD6E42ULL,
			0x8C52D2FC3F9582FFULL,
			0x4AED8BECEBE0753CULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x988E3E0F4E6B0575ULL,
			0x46D30521C9D5D2ABULL,
			0xC0FB683105E6FDE8ULL,
			0x3B67E26C215B1129ULL
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
			0x9D7BB35C3371ED90ULL,
			0x354EABDA4072BD94ULL,
			0x2BF67D84612C34EBULL,
			0x65A21D15C5A41068ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x7057FAC1AAF56D44ULL,
			0x13489630D3E585B1ULL,
			0x5F1376D7A18BD8CCULL,
			0x05F90A0F511B2B29ULL
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
			0x019EAF534B6BAF28ULL,
			0xD8954261A801A00FULL,
			0x28670B182619ABCBULL,
			0x539895DB8AF80C61ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x8EE2C15820E4C498ULL,
			0xEE678E9CB479EBB3ULL,
			0x132B928E31472399ULL,
			0x43578D5C0CCFF87BULL
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
			0x0B2613D4FFFAD390ULL,
			0xAC081F5BD7BA3DAAULL,
			0x0A8B25A3C2F89A45ULL,
			0x412283716920A4A1ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x664E1CE33538802BULL,
			0x48F62CE29D7F4870ULL,
			0x778EFB1FB29928D8ULL,
			0x2E2BCD40B0FEC573ULL
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
			0xC7763DA10F1AABA8ULL,
			0xBE2CFBFD62A3B94CULL,
			0x815855A536F01456ULL,
			0x68A0FFE64BD00587ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xED4CEA0A722C95E8ULL,
			0x5E07D82631267217ULL,
			0xBD49C0C7DED745FBULL,
			0x49D5AD66B8F9AF6FULL
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
			0x40F01F249A725C88ULL,
			0x11C4F09C6B176DCDULL,
			0xDE32BA5281D2CB8EULL,
			0x49F25087B1C35548ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xF8FD301E2389CA82ULL,
			0xC492C67C6BA50A7DULL,
			0x538E92DEF198404AULL,
			0x1413D1C4A2AE3822ULL
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
			0xB2104D73C6A2F590ULL,
			0x8BF943D182421DB1ULL,
			0x9EBEC877588ED0AEULL,
			0x656E2E1E72FEF638ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x52FD881ECEEBF2A0ULL,
			0xCFE3EF8ED6CBD641ULL,
			0x7FEC681F146DD8D5ULL,
			0x1C306730E6A3E95BULL
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
			0xA2A680A3742BFA00ULL,
			0x1017F7F988D3AA25ULL,
			0xEAAFB4B99AD9C055ULL,
			0x7B39A67198BE814FULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xC6F10D4CAFA4B629ULL,
			0xE7995BB60EE15676ULL,
			0x8F70D4C5DA800B8BULL,
			0x646314DF5C14D449ULL
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
			0x22112E1A43CCCFB8ULL,
			0xF24BA393D0E3AB0CULL,
			0x3242CB9B1972BAEAULL,
			0x45E56D5E52FEF015ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x4E5DC6BDFF48CDEFULL,
			0x580F267D126CE812ULL,
			0x01E6EE447E85DFA3ULL,
			0x43A030303AB0CADAULL
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
			0xDD6AB2A532A2E5F8ULL,
			0x9A6AC76AEE7F43A6ULL,
			0x34108180D5E7C4D8ULL,
			0x69E7E130251E6C3FULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xBEAC9617714CB47BULL,
			0x4518C4A03E6BA18BULL,
			0xA650EC2FE5E32029ULL,
			0x7746F1D02F0567D3ULL
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
			0x9727048AEA8DB9C8ULL,
			0xCB2C90F46E43136BULL,
			0x0294AF54F64A5D82ULL,
			0x469A6AD69AC30821ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x01F013597178F8B2ULL,
			0x33221BD417548633ULL,
			0x4C938221C0EB62E2ULL,
			0x18AF231A2FCF559DULL
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
			0xCFF3A17B43726148ULL,
			0x12459FFB5BA1D7DEULL,
			0x4646B85BCDAACD78ULL,
			0x65660FC8DA8AFE94ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xD6A2578393C01599ULL,
			0x4589EC29619F4A78ULL,
			0xFF96AE69634CF224ULL,
			0x426BF5AEF2ECF4F8ULL
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
			0x6C0EE6A8BFC47B88ULL,
			0x2BCE567B12449749ULL,
			0x6ACB94E7BE3FFC45ULL,
			0x6AB44A4F6155980EULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x201C8BDA267E992EULL,
			0x903DAE28A44D81EAULL,
			0x4D5A148D508B6DB2ULL,
			0x067DB3B6908997DEULL
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
			0x4BD4EE6EA5565F88ULL,
			0x38559622FA2FDEB6ULL,
			0x24A228C3CBC596C0ULL,
			0x483FD84FF98CEEE7ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x1344637C92538BEFULL,
			0x95B6EFC95CFF82C8ULL,
			0xD137F9572C079A3BULL,
			0x04E34150A6B8D399ULL
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
			0x096247217428EFD0ULL,
			0xEEB8AE55B4BB0118ULL,
			0x9BD5DAF36E041F21ULL,
			0x6D611C32C0407213ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x4FE60F7592D69C75ULL,
			0x8AC876A59E2B9AD0ULL,
			0x9DF4C8DADF8BA59BULL,
			0x1AAB42135F59108FULL
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
			0x14B567C261A7C2B0ULL,
			0xB82D89316E997F08ULL,
			0xA9A78F2B8654B14EULL,
			0x554648C6617CAB5DULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xA91CB6D20A875EC9ULL,
			0x10F5B65888F435E7ULL,
			0x76EE018C66153760ULL,
			0x60F85D1C5075BB5BULL
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
			0x039A3FB0EB109B28ULL,
			0x8B9F91AED0A0F6EEULL,
			0x816C978938119DB9ULL,
			0x5E7ED0A3CD8F9777ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xDB96D70D168FD9E9ULL,
			0xCCEDFC7B91A3E7A4ULL,
			0x2E3A9F6C4940D4C6ULL,
			0x3ED1F918AD249167ULL
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
			0xF64E768C03EA8358ULL,
			0xAAB227987E3F84FEULL,
			0x285695C072AF4E32ULL,
			0x638A19EF722A11D6ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xAEA9980AC004E95AULL,
			0x63FA1FCBD25B8CD4ULL,
			0x57817761E2118121ULL,
			0x6FBC51EC09C6234DULL
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
			0x643D6CD9951D1300ULL,
			0xBAC3F21AC52F4E38ULL,
			0xA9B1AD0677B85056ULL,
			0x7FCB5F8A2220A621ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xB603F36EA69EFD0CULL,
			0xFFE980DDAF50E8DAULL,
			0xA32791E2DBFAC3C5ULL,
			0x6EA6714F05AAE5BDULL
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
			0x12B5ED99F5C645E0ULL,
			0x6BC95B53D5E96061ULL,
			0xE8A56C1312167DF7ULL,
			0x4DF584F70DEE352BULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x52B6AE38F1A68A46ULL,
			0x46F7641BF07C8C64ULL,
			0x9647B0915C4C89C4ULL,
			0x09368D4DDBA2C826ULL
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
			0x024CD86562F2D9B0ULL,
			0xFDB8106594B35A2DULL,
			0xD11F90DDBB68294BULL,
			0x5AE090D2B1FD0967ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xBD23AB744CB213E3ULL,
			0xA586A7B13943698EULL,
			0x995E673586BB2BD8ULL,
			0x147EDCC0D1EA0D12ULL
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
			0x283A3CEFD891A140ULL,
			0x1448ED10A5CD406BULL,
			0xB45FFA8720F870A4ULL,
			0x4DF764255B399F6DULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x9FDA637A976A48ECULL,
			0x5F25AC85D3A7CCB5ULL,
			0xBDE069EA1BA84219ULL,
			0x2D9E061B12197EC2ULL
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
			0xC613ED7414920020ULL,
			0x8A3509F799994131ULL,
			0x084138F401B87CCAULL,
			0x7ACFE2E216C76F35ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xAAD47BACB107E93AULL,
			0x511C43D0B2365BC7ULL,
			0x3ACC1437FB2B6F49ULL,
			0x7ADEB70C045CAE67ULL
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
			0x0E5DCECA5E41F118ULL,
			0x58DD7641402AC2AFULL,
			0xEE06FC053986EA2CULL,
			0x649AFAEFAD4DC60DULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x9BE2891FF670934AULL,
			0x0E18B4979AE19F19ULL,
			0x67DBA64357A08229ULL,
			0x451B023AC0DD9342ULL
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
			0xC21BAC2B568CAD80ULL,
			0xC9FDD569C70949D1ULL,
			0xA3AAA6517AE5B3EDULL,
			0x66948916EB131A5DULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x78D49DA24ED40674ULL,
			0xF621839FDCF8F1E5ULL,
			0x9C073BB8928547D8ULL,
			0x60A212ACBA79D7BEULL
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
			0x75181FDDF134CF58ULL,
			0x78ECD96B733E7E96ULL,
			0x6C8367F284F0FEBEULL,
			0x4A714DD77334DA43ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x04C71D889A666179ULL,
			0xB0429E35E9930DF2ULL,
			0xFA505A59B4A01DEFULL,
			0x748FA7E225063CE0ULL
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
			0x5B04ECADE24A28C8ULL,
			0xD5D5234818D464F4ULL,
			0x420DCFCCFEC06FC7ULL,
			0x7FF8D8A28A674F21ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x780734C0F4D44553ULL,
			0xA0F2C1A6A919C3B7ULL,
			0x1C97E8BB94272063ULL,
			0x1CA31C63288C7743ULL
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
			0x889A9BB8A98263C8ULL,
			0x22F48DCC25B648B6ULL,
			0x3B69B628B0DE25DDULL,
			0x45903A4C5E7D7889ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x0D37B9FDAE0805A5ULL,
			0xB2AE187D0C8F5B15ULL,
			0xE0196A40F7C4E247ULL,
			0x2A8F410DE48143C6ULL
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
			0xA258511D4E70D850ULL,
			0x660844FE90F7B32CULL,
			0xDE8C2079380E4100ULL,
			0x7CFDE6562B96ED45ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xE08E97EBA65961BBULL,
			0x6143880F30CCA380ULL,
			0x4A667E9EE75ECC88ULL,
			0x3FF687309B498ACBULL
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
			0x530711889B845920ULL,
			0x65F4D7DB9BFDB85AULL,
			0xD0BB89454859FE28ULL,
			0x78C20E8B5C193718ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xB3E0375380999078ULL,
			0x6F01459ED3BD2DFFULL,
			0x528878883600E567ULL,
			0x06E2945549297C40ULL
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
			0x26D3EC8535B60DE0ULL,
			0xB673510B9501F939ULL,
			0x669287F8EC6B3D71ULL,
			0x47126830C64133C5ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xBF8915EE252C17B6ULL,
			0x562B923D763F9129ULL,
			0x0709FFFD31307CE8ULL,
			0x3DB8E40F7494CE4EULL
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
			0xE02C9EAFA7590A88ULL,
			0x6500C7D363B11AB9ULL,
			0xD205579223FA0423ULL,
			0x799C67D07F81463CULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x7F5EE5187B53F087ULL,
			0x59F433620ED5EAAEULL,
			0x30E0AF4E095F8938ULL,
			0x2ADE9C9272BEB81BULL
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
			0xCD6384F39A3B7240ULL,
			0xCAE24B7E401A3D35ULL,
			0xFDAC1F879FBCA2A4ULL,
			0x540EFF363F7345BDULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xEB5B2C0D6936FE49ULL,
			0x4FBC856FC5B4CE2DULL,
			0x2DF8BAB76C8F8027ULL,
			0x73844E8C9DEF1B87ULL
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
			0x16F4D69E0A7B5958ULL,
			0xF899B46B28E86829ULL,
			0x5E7399CA409230ECULL,
			0x593A6043A6A9DFDFULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x3ADB0137B663B7FEULL,
			0xBCDEFE9898C9E02BULL,
			0x52FDB203ADEB6438ULL,
			0x4C638C21CE324B95ULL
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
			0x1DC61C9AFD6BEAB0ULL,
			0xD3EF0D8B17798F39ULL,
			0x6D8E5AFCD8C2873CULL,
			0x4C3BB3AC627C9408ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x6D9E1E6C9308CF68ULL,
			0xF698E68E9E4E4282ULL,
			0x0FAAB1FA50439AC5ULL,
			0x345A3B2DC6A34FC4ULL
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
			0xBC16E743CBD80B60ULL,
			0x4E3224F7CBF19F24ULL,
			0x93467A6D98B4E130ULL,
			0x741402FE2407104AULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x754FD0F7FD643763ULL,
			0xBA1066BE1FF652B7ULL,
			0x74A7F15E79B5326DULL,
			0x3B050F90D0A59ABDULL
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
			0x2BA5C21278EC9978ULL,
			0x3C5BE83C3C5267C6ULL,
			0x56F6E5EC305D5EE5ULL,
			0x56746EAFE594365BULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xA2D805CA8EF623D0ULL,
			0xBB1DFD8920D2B125ULL,
			0x1B876230592398DCULL,
			0x287BAD9466DA0296ULL
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
			0xE76A4F4AC6665778ULL,
			0xE291BA041E79809AULL,
			0xA4B444FEB1D0E9A3ULL,
			0x64911908CE69F9D0ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xD73DF7610C24C843ULL,
			0xA1173E0755894C6FULL,
			0x55B382CCE26A07EBULL,
			0x381BF6D162945122ULL
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
			0xA2B967D5012597F8ULL,
			0x604EA22B38DE5185ULL,
			0xA46E40B2684B897DULL,
			0x56964D24BB36973BULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xD2B721428481593AULL,
			0x5F1963F8F1C0CB9CULL,
			0xD37D08ED5942D3B3ULL,
			0x0115851C59D21C7EULL
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
			0x5291EFE4F2F17E98ULL,
			0xF8FD158E4DFCFC34ULL,
			0xC62C41ECCE288CB9ULL,
			0x7D844DBF04D6DBD8ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x3822B0E16DBEB94DULL,
			0x11658A7640B31E0FULL,
			0xC68B4D451861D0C4ULL,
			0x1920282ED2559B66ULL
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
			0x65A440501DFF9968ULL,
			0x717D866E19D88B1BULL,
			0xEA372CDEEF2A6741ULL,
			0x6C46772C5101152CULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x6A8DE6D289A13955ULL,
			0x51B759E033AE2E29ULL,
			0x833D640DED010CF4ULL,
			0x4F59B4F596E20F48ULL
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
			0x90EBAF80BFE6A580ULL,
			0x9C36BF4B79D41CFAULL,
			0x0E4EC6EE6B9B5B6DULL,
			0x6226C69F19FB1741ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xC42DD07A1653F442ULL,
			0x388B9949686693CAULL,
			0x7319CE91018B604AULL,
			0x5BD225CA83C3B432ULL
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
			0x02C5C8B2D75AEAC0ULL,
			0x5F79E09E045E3D9FULL,
			0xD21E03C03FE6A9E0ULL,
			0x450F0537640C248EULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xBD84405EFB860DD0ULL,
			0xCEAAB6EE0A7A3202ULL,
			0x03948A0D775C4DCAULL,
			0x69B0645A6DF5A602ULL
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
			0xDC729539256572B0ULL,
			0xC421CC8606900D65ULL,
			0xDF63C4AF6E39BE30ULL,
			0x629DD07844A80C68ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xC8C12081E7340EFCULL,
			0x38373E83CEC7BD39ULL,
			0x5D614164A5AA70ECULL,
			0x3E655432FC91097CULL
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
			0xCA775DDB2460EEE8ULL,
			0xB3CFD993E3FCF4BEULL,
			0x93F9A1811CB64B84ULL,
			0x7B383BBE829EEF3BULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xB0AA5F96D761BAE6ULL,
			0xB9E039522A1E854EULL,
			0x431AFF729899A74DULL,
			0x17BC6F092BF1568EULL
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
			0x9E70A26CB0A3B750ULL,
			0x5D3BED5B45D62597ULL,
			0x9BA65CBE663D2FCBULL,
			0x6E6F724703411C67ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x285A8F6C57049653ULL,
			0xA2D24B5BC9F5104BULL,
			0x0F663170D722CBF9ULL,
			0x210A4424BC2595B0ULL
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
			0x7C281827252B5E70ULL,
			0xB955A0985A77ED79ULL,
			0x3AACB979783878E3ULL,
			0x773885B3F9AD1B51ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x950994741EDA78A9ULL,
			0xBD8469074C34809FULL,
			0xE3A4B521DABD9226ULL,
			0x7C191EB5F4CAEDECULL
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
			0xE7EB24955AE02688ULL,
			0x09D9736A545C11D6ULL,
			0x19ED054FFA7EE3DEULL,
			0x448CE04EBF9BF848ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x426F2BA5CC1776D7ULL,
			0x5D5622AFDDD3C24DULL,
			0xF3B11CFEDF65BB13ULL,
			0x2D85E4B7680D90E9ULL
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
			0xD2B4E0ED0AFB0BB0ULL,
			0x6FC9D622E0DD69AFULL,
			0x56CB497BCE7FBF64ULL,
			0x6BC84DEDF3E43CA9ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xB950CE358D3F40C0ULL,
			0xAB14BE01E2325914ULL,
			0x8753558835177DD6ULL,
			0x090F37E5F71F7171ULL
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
			0x3C4DA266EBF421E8ULL,
			0x6287CE20782E14E6ULL,
			0xC35BF62C03559371ULL,
			0x43FC8B5D2155659AULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xE29190A884728B47ULL,
			0x01D6CAA48F2042FCULL,
			0x0833FBC914FC72D3ULL,
			0x3A4C54D5C0332158ULL
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
			0xAFE47EEE29FCAC10ULL,
			0x719FB0D911763B33ULL,
			0x53167E941ABDF92CULL,
			0x4F70DC1C8E13A888ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x37E8B04469A89D74ULL,
			0x2BDD0CC358806574ULL,
			0xFD7299277ECCF65AULL,
			0x363E963D2093D07FULL
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
			0x1EA1AD0736237600ULL,
			0x0FF89ABE66C737FDULL,
			0xD677E14F12665086ULL,
			0x56327DE33556F53FULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x8794A3DF46FC8A6DULL,
			0xE2B6960B746CBF0BULL,
			0xDADB2FB4425BB3B9ULL,
			0x2583DF47742130F0ULL
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
			0xB5BF9BD8F5C88628ULL,
			0x4DE0BFEC230CB645ULL,
			0xDA781282E2CF9A30ULL,
			0x5E3E544A44C6C95EULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x05594246E907E595ULL,
			0x096CB5FE9D1253D0ULL,
			0xEF92328E0126B5DEULL,
			0x5786F3044BA8DD34ULL
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
			0xAA83450F73E9C580ULL,
			0x9211CCF6D6CBD45EULL,
			0xE9E299BFD67AA202ULL,
			0x493FA0788DD7C314ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xFD6814E4AC813165ULL,
			0xAD090F60FD18ED7AULL,
			0xF26A477C1ADBBA9DULL,
			0x2C604563BDEFA48FULL
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
			0xDECF1299F06F9FF0ULL,
			0x62241ABFA2B70500ULL,
			0x53ED8C82EFBEC0EEULL,
			0x5F8A96BFE0D2D4D4ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x210D0453FD7E6F9DULL,
			0x5D9EA1BA76794CC9ULL,
			0x1CC30D241D8CBACCULL,
			0x3F582DD05447136DULL
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
			0xD5DE8B5E14FA6C78ULL,
			0x3392DEA91642E6FBULL,
			0x6F59AAB06D6EDDADULL,
			0x579F0912456F6C08ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x2E795AFAA356DB55ULL,
			0xFCAE3AAE03104E82ULL,
			0xD83F47FC1928B663ULL,
			0x69368E783E091B46ULL
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
			0xAD394438AB5FE9E8ULL,
			0x82DD00CEA6D13EB8ULL,
			0xE08DAB7E187B3C32ULL,
			0x6A15B690573790BFULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xFD87C6B8735A44E6ULL,
			0xCFA404D46DC5B2F9ULL,
			0xD04C3E2A7F5D48A5ULL,
			0x719B89AEA4370EE8ULL
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
			0x0EC208D38EEDB7C0ULL,
			0xDF7632BF67FD78BFULL,
			0xAFC8513A131FBD59ULL,
			0x5D4DD22C47D532E0ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x960650B64FB6B849ULL,
			0x9C599AD36D117C69ULL,
			0x2C1546191F0D2D66ULL,
			0x610A252877675A21ULL
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
			0x76E19F07B2BFCAE8ULL,
			0x1BD47666DF5FB56CULL,
			0x021850DAB25F3D35ULL,
			0x64F6B1973D67B6D5ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x19BD9C70DB720B40ULL,
			0x4C1896C891FBF94DULL,
			0xC0D3CA6BE3A9B355ULL,
			0x621F0005F1D6CDAFULL
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
			0xF1C1624A097A0498ULL,
			0x4DF04637969DB670ULL,
			0xFF482EF12DE81A85ULL,
			0x6ACDD6A57D26D59DULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x8547752DB08DA46EULL,
			0x6F38C7A6DD2DFCB5ULL,
			0xAC4572399972E3F2ULL,
			0x08DE8C0942525A5BULL
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
			0x4421DDBE055D8808ULL,
			0x5912434B763ADE78ULL,
			0x9B4DA6C3A5676C94ULL,
			0x44C7D10E96BFB5F3ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x92A1A5546986240EULL,
			0xAA900886A9903A95ULL,
			0x5A12AA6F15480C0AULL,
			0x6E141A7F07A7E754ULL
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
			0xC56F10F0D0162E38ULL,
			0xBC0FD5360101E233ULL,
			0xE7C0E3A9CA108CA2ULL,
			0x606BABF879ACD7EAULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x749F6541EF86E5EBULL,
			0x499631126A9C9E6BULL,
			0x774F80C443EDC202ULL,
			0x0A96851E73632395ULL
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
			0xEFEB68E053854588ULL,
			0xCCD4EF50C380C923ULL,
			0x24D04222493A405FULL,
			0x7A911CEE30276862ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xF62B887AA8F2D82BULL,
			0xD2DCEA1D48CB56F9ULL,
			0xE11716D563F31E21ULL,
			0x6A80DA66BCC21D0CULL
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
			0x4A13C785ED62B888ULL,
			0x487182B979D6499FULL,
			0xD61EE09C740C4555ULL,
			0x4F78BF9C92718E07ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x3DFF79C9004EEA1CULL,
			0x5328617AF6558C26ULL,
			0x74754EAFC0223968ULL,
			0x36EE74E67748B889ULL
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
			0x5865A1575CFCFC70ULL,
			0xBF079FEDD17E4498ULL,
			0xF28CEC6E660FBEE2ULL,
			0x452D13418A533BE1ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x3A57EABEAEB327F4ULL,
			0x76ED3A8B57F91646ULL,
			0xB3F81F4750AA634BULL,
			0x6C056AA12ED2EAE7ULL
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
			0x78CB54D3AE0B58A0ULL,
			0x682A6C13E097A1BFULL,
			0x08F967C46FDFAF46ULL,
			0x7FDD60F0A897616DULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x9ACE319AEE48AC97ULL,
			0xE5BD195AF038C7BEULL,
			0xEC59874015EA269EULL,
			0x745CFA9C1AA5B143ULL
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
			0x6DB097470C3C77C0ULL,
			0xB4B4C9275115C905ULL,
			0x0869351D39DDEB6CULL,
			0x69350430B12A05C8ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x9E68D9931902946BULL,
			0x83A364E15A3075BBULL,
			0xE922B775742F260DULL,
			0x4FA10B5BC8529A65ULL
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
			0xD73127215AC17F50ULL,
			0x8772E2FE96670B07ULL,
			0xB9F3D9F0DBA8D29FULL,
			0x6FDFB8F56AE28EF3ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x44198B0F77282773ULL,
			0x4208E3B60816CFD5ULL,
			0xF35FBD0AC344DA81ULL,
			0x074A1D591EC2A255ULL
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
			0x3E1D289A379E06C0ULL,
			0x00F0685D51A0D0A8ULL,
			0x150B4694974BAEC6ULL,
			0x43482F547C1882F1ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x0D80C59EDCF4DE90ULL,
			0xC29BDDCE114907AFULL,
			0x9EDCB5C02A652BC9ULL,
			0x79C61FE250BDAA28ULL
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
			0x4E4335A8DEB29200ULL,
			0xD7B57199B20D5E82ULL,
			0x9E8B9811643FE5F4ULL,
			0x67BF68EF0B4D449CULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x39BECA361E597FCAULL,
			0x58D0FE560849279FULL,
			0x3069DDA1BF9FAC12ULL,
			0x537C54202F726B01ULL
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
			0xF032A78307AC0400ULL,
			0x986C3F74F9A0ECF8ULL,
			0x60151C8FDCA0B5DAULL,
			0x40F93B055DCD98C3ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x24C823F505D7704FULL,
			0xE827D76994B99897ULL,
			0x9A6AEA11962A7069ULL,
			0x04E42DB5DE70D89CULL
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
			0x6330B84A0883C6A8ULL,
			0x7FA469E37BBBBBA3ULL,
			0xF92E81C6E7420A4CULL,
			0x58967137F2C8B001ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x480180304DBAF99CULL,
			0xC857A23059E991C5ULL,
			0x6F021AC943E3FF80ULL,
			0x4EEA2B358DFCA40DULL
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
			0x2852311EC7438370ULL,
			0xD48BAAAA38A996C8ULL,
			0x873CA22C1E4E062CULL,
			0x5EAE9355FE78F1B1ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xBD3B67CE7DBBAAA7ULL,
			0x92B70EEFADC70420ULL,
			0x08E708D8041FEB68ULL,
			0x255C2B4084DDF261ULL
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
			0x19DFAA821087EF18ULL,
			0xA6819C42B8F4CB5AULL,
			0x7C3AAE2CE82C4DB0ULL,
			0x4D34BF039D580CB9ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x5DA88137C9C8854AULL,
			0x56A9F6D50C7486D3ULL,
			0x18E619EC1260F682ULL,
			0x29964B4747E7E04BULL
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
			0xE6645224AEBA58C0ULL,
			0xFA33B21E42F99C3EULL,
			0x903F7C6F7F1B4560ULL,
			0x416F254F25830909ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x5AD7BB3FC47EB5F7ULL,
			0xAA572CE9E957AF0FULL,
			0x24A70A7869F3496FULL,
			0x77CE24787FFD748DULL
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
			0xAFAA7C182A8FA350ULL,
			0x83B47441EA0C429DULL,
			0x006F694FDBC55A8FULL,
			0x53FE1C4309277DBEULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xEEF321334992611BULL,
			0xA30E9551EC862956ULL,
			0x4673F02EBEC1C18FULL,
			0x3A8788E494B58476ULL
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
			0x1E50EE5BFB0D4B08ULL,
			0x8D1155C5CE8ED9E5ULL,
			0xFD3A192C9EB47F56ULL,
			0x7A661B9BDC76AE2FULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xA68FA51D321AFA18ULL,
			0x459154F4CB88CCC2ULL,
			0x3653D6EA483F4C65ULL,
			0x292721196C890050ULL
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
			0x497D0282F134BF70ULL,
			0xD64030A23F5E4D1DULL,
			0x474891CC601CCAA7ULL,
			0x550DDE5396C117AAULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x40F7289E1A3ABED1ULL,
			0xDFBDEB37804221C2ULL,
			0xCF14398CDFC5D6D7ULL,
			0x352181FE0FCC9F13ULL
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
			0x5594803407417550ULL,
			0xEFCFCADF849BFD89ULL,
			0x6332A4091C4552F2ULL,
			0x6664677DD009F49EULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x9891C5315EABA620ULL,
			0xEC47249828C6DD40ULL,
			0x45B407D9A4BCF3BEULL,
			0x70B31A77E392CE6FULL
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
			0x7C2F778AB7D45868ULL,
			0xDA8F737C21C871FFULL,
			0xD792BE21EDD6D626ULL,
			0x6892290B462372FFULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xC1659AE865AB0E7AULL,
			0x5CBEF4539A6540E3ULL,
			0xE579A091E2E983E0ULL,
			0x3C81B3C047073A19ULL
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
			0xE12524E4C2882BA0ULL,
			0x1B6A88AFED69C817ULL,
			0xA21794AC14145372ULL,
			0x634620ECD78679E2ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xD0874646176D5141ULL,
			0x569471D642906C06ULL,
			0x1058A419DB3569EFULL,
			0x74544F21DDA1FCC0ULL
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
			0x5E070F8585E1BDE0ULL,
			0x90D3B4F671B9B48EULL,
			0xCCCE40A2BFC166D6ULL,
			0x550DCE2AC1AB308DULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x23C748DCB4146439ULL,
			0x19BEF6B97589513BULL,
			0x6A01895C27D1E5A4ULL,
			0x49A8046AE05B1793ULL
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
			0xB080B0FAD7DE8D08ULL,
			0xB9F22CAC0F54E659ULL,
			0xB90B74969488B378ULL,
			0x55DE22F68DA2F770ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x0CC16A7916BC5AF0ULL,
			0x5F7CE04B68E97DCEULL,
			0x9EBE95F7FBA9138FULL,
			0x496E93D7C935F44AULL
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
			0x6BC90D968193FB90ULL,
			0x5E4AA2E3BDE6185BULL,
			0xA4353AFAC418BC40ULL,
			0x5FC2BE997C0035B9ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xAF3ECEE8A9D01094ULL,
			0x544EA4D64A628789ULL,
			0x826A8761521F92DBULL,
			0x09EBAEDDB39F5C8FULL
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
			0x0743DF1A1624D9D0ULL,
			0x0181A15AFF2ACA68ULL,
			0x457572D243E87C60ULL,
			0x631865E46BFB4865ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x47778332747709ACULL,
			0x7BC3E7F06EAB295EULL,
			0xF5516CB9E52D4F39ULL,
			0x4D7FDBDD53C61149ULL
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
			0x7A77AEEE06A31338ULL,
			0x2D46A1D33E0CD221ULL,
			0x4A02787041EC0DD8ULL,
			0x5F82A0592E321238ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x812A931F878FF110ULL,
			0x80AFD7B70C9AA0E2ULL,
			0xC88A74D999EC4037ULL,
			0x15A7DCD45DE24B28ULL
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
			0xD803978FDB2A2F80ULL,
			0xCB4672032F45B427ULL,
			0x6EE0C3D68A28A370ULL,
			0x5CA90762CBFA00F7ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xF59B988F6A6CC2E2ULL,
			0xE92E365E9F54CD81ULL,
			0x77F4AB1391EBF307ULL,
			0x716E4CB659A1AEEFULL
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
			0xBD49D3CB7DFF8550ULL,
			0x20866B3E1B47A283ULL,
			0xF686C0CAFED206CCULL,
			0x70C785F9683E07E9ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x670FFE0EFFBE0AA8ULL,
			0xB125DAF81B0B21E4ULL,
			0xF154442CC1A02B68ULL,
			0x17469BD8577784D4ULL
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
			0x06E153D16B943EE8ULL,
			0xC8735A043FB14A6CULL,
			0xF4FD6DC18BFA30B9ULL,
			0x46BDED22BD56DEABULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x9A5942D4AEFD5946ULL,
			0x4235042D746AF649ULL,
			0x0D81D54C82C49E9DULL,
			0x16FE9E7B54B1275CULL
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
			0xCB120F8380E2BDE0ULL,
			0x13AAB011748F6829ULL,
			0x05245FE83D09DFC5ULL,
			0x5FBE8F34318F2C17ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xE98B451AFD57DDD9ULL,
			0xA2E9F5DA0F593A21ULL,
			0x7E30C094DFB41521ULL,
			0x45B8F6EB1CF6D681ULL
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
			0x989AD24B04823820ULL,
			0xDACD2BF05EB17F43ULL,
			0xA95E27797DAE6B52ULL,
			0x4B7C7E2186792843ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x4E020FC5C8E5F6ACULL,
			0xA5BDBB4E58C599B7ULL,
			0xB7CCCCA5F994110FULL,
			0x631DF7039B3D76C5ULL
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
			0x6902763C58642780ULL,
			0x91B459E1CE5B254EULL,
			0x7A86D540AFAAB6DEULL,
			0x494D16AA2A4BB25EULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x9DA5A4A3DD4A76F6ULL,
			0x7D5C5D8CB28A0BD3ULL,
			0x53B88D602BECA298ULL,
			0x0EE5FDB30CDAF446ULL
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
			0xB974CA14FF2BB428ULL,
			0xC65125C6C168AA25ULL,
			0xF11E4D419FF46F30ULL,
			0x6594B3E2A2688ECAULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x025C6E440AE6FBA6ULL,
			0x4F36605986C1E877ULL,
			0x486AF3CDBDD1F141ULL,
			0x07009956C145E522ULL
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
			0xCAE965517EAF67D0ULL,
			0x9BF2DC38335FB1C0ULL,
			0x17D6502749F8DABEULL,
			0x69579650D476200FULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x7773BC61EB4D4C76ULL,
			0x66CF8D1DEC87F644ULL,
			0xA72F6D05ED40F073ULL,
			0x69DCAC5D0A59779AULL
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
			0xF219F264D46CCF80ULL,
			0xA731D99BE43D2AA5ULL,
			0xFE7F35D58E5A80D4ULL,
			0x6636314D21A91FB7ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xD37CB52B6B5C221DULL,
			0x31E3AB40BB23C63FULL,
			0x9F1ED91C42C066B3ULL,
			0x0DE5ACA864B3FE5FULL
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
			0xE68BA1D86C1EB900ULL,
			0x6122DCA4E77CB971ULL,
			0x3D6AA7232B9D02A0ULL,
			0x6AE1B065EFB94C43ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x9AE4651E0C085470ULL,
			0xA6C19839C2559CE6ULL,
			0x974FD03C57C6EDD1ULL,
			0x2EC3488A7AC22DB9ULL
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
			0x38B3591E1617E828ULL,
			0x6A645B60D8EBB6A4ULL,
			0xA425679481AD9C43ULL,
			0x4BD05562E0162111ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x5B0EB199C95A24F8ULL,
			0x7F4873162F5A1427ULL,
			0x90680CB3EB077883ULL,
			0x50BCB1BC6C2763D9ULL
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
			0xB1A07FD29EF908B8ULL,
			0x1BF81622B8030C5FULL,
			0x19E1AE18EC45BAB4ULL,
			0x4E692AAC5F1FE8F6ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xC3BDE351E5803241ULL,
			0x46AC68577E151AF0ULL,
			0x71EBA039B4E43A25ULL,
			0x661D476DAA3AAB4FULL
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
			0x3E96962A3D7D3458ULL,
			0x84ABB60237313B89ULL,
			0xE3CDE9A63AFEB6B4ULL,
			0x6646ECD814EB92A9ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x714A34D771242EECULL,
			0x4F85EAC18C671AA5ULL,
			0x2F59F9D7DA74629BULL,
			0x253EFDCFA2005B7AULL
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
			0x223D77B362A01F10ULL,
			0xFC06360E85AF5ED1ULL,
			0x5DF2EB690A9B2DE8ULL,
			0x734DA945E5547DBAULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x1C87706E88036DD7ULL,
			0x583D36CD58662616ULL,
			0x07B5B30C7D566464ULL,
			0x66943B4E551E0275ULL
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
			0x30DE93A611A96998ULL,
			0x8CBC86D886557AF3ULL,
			0x51FECD9613D64EC4ULL,
			0x6C2FE873D5D5B5DCULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xFCE0051EA991FA1FULL,
			0x361A8BE6478EF221ULL,
			0x8C2419330A088C6DULL,
			0x5219CC1F45534651ULL
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
			0xDCF49900D3AAF1A8ULL,
			0x6672648C4F02FFCCULL,
			0xCF2D7583B5C2560EULL,
			0x4D5010BF15549913ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x1442D9D8973018F5ULL,
			0x1841E994EC48FF1BULL,
			0x57D16132AB23F6F5ULL,
			0x37711326DEFFB757ULL
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
			0x619AAB40F5239E30ULL,
			0x25EFF9BBBE20E084ULL,
			0x2CDC13BB9FE0D291ULL,
			0x7AF579125E3DDF84ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x2AA8A52D6B433DC3ULL,
			0xC000E34A822CC575ULL,
			0x7680247FCEB7EF6EULL,
			0x6E1FBF05DC9E3479ULL
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
			0xF60FEDCFFFDF6218ULL,
			0x212A7BB72ABACD5BULL,
			0xA948C5C2D805EB1AULL,
			0x4FF297E57A515014ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xB198B07A075B37C2ULL,
			0xC81691C5CEE993F4ULL,
			0x7AFB25B703C13DC4ULL,
			0x65A733CDEA73C116ULL
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
			0xAAE2A1268641F9B8ULL,
			0x8E2043B8EF01B522ULL,
			0x8884C7F2C23D4727ULL,
			0x5211F421A94FAF35ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xEB98E64BD04EE415ULL,
			0x2B03111494CEBAA0ULL,
			0x60C09F6ECB3EE7EAULL,
			0x17A25DFAD22F77A2ULL
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
			0x2051E50BC7A02EC0ULL,
			0xBA3E048816282E70ULL,
			0xFC378FCC6F003EADULL,
			0x41B102614E1D8668ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x4E8689ED386840B4ULL,
			0xDC7B95FA19C0A33EULL,
			0x214F9DEF77BD7DADULL,
			0x38C718AAF7C07F70ULL
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
			0xAB06B713AE1ED798ULL,
			0x6D8C28A1608165C7ULL,
			0xC4472327BE3110F9ULL,
			0x73EC377B040CB192ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x68A79C4869F3A202ULL,
			0xC4EB22D7B3FC32A0ULL,
			0x558B2CC4F59D0B58ULL,
			0x71EC8A2BC439F1ADULL
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
			0x5BF4107358BE8D40ULL,
			0x998FA865FC4ADA6CULL,
			0x8281CCA23680C354ULL,
			0x592B0F16B995B26EULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x4C58F7691A285E34ULL,
			0xD5827637EC8B5DC5ULL,
			0xF22B6E0A2160D270ULL,
			0x4E33148FC9127342ULL
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
			0x968D94A86C5F0E08ULL,
			0xA96D8AAF2E5C9333ULL,
			0xD054733220549BDFULL,
			0x72EDAEA39744FA5EULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xBD5ED9251FE91D06ULL,
			0x09DF1BF8150E175FULL,
			0x7A16ACE8CDD8C173ULL,
			0x13E2B4E1C43BC689ULL
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
			0x16D42895318F1F50ULL,
			0x98B3A9992E078D7CULL,
			0x665E689932DE14B3ULL,
			0x7F24EC4A98FD1AAFULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xAD6B08507825F696ULL,
			0x23B09F26B3A7287BULL,
			0xEBFA7CE3C49F7773ULL,
			0x3A4420F6CB33E811ULL
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
			0x8E78592039203B80ULL,
			0x48EF4DEEFD005C03ULL,
			0xE5F094C9E0F058D9ULL,
			0x6C0F50F985526BDEULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x1AC533D528F38941ULL,
			0x8950163C9978B0EDULL,
			0x446A687A46835CD8ULL,
			0x75BD8186323C1289ULL
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
			0xD19AF5B757114E40ULL,
			0xCAFD1C67E7A9FA0DULL,
			0x840805135B1FD308ULL,
			0x41252FFB3BC96C8CULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xEAE644F55EE71937ULL,
			0xA6DCDB41DF5FEBAEULL,
			0xA7D322E92DF15DE1ULL,
			0x473F77459CBEEA8BULL
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
			0x7EF7E9B7033C4608ULL,
			0xFB732E4E02BB697FULL,
			0x0E53B5BD5171AF99ULL,
			0x496327C941DB9CD4ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x1B44DC49ED262B26ULL,
			0x017DC35B8BDA190CULL,
			0xC5523642B62E3996ULL,
			0x79AF2ED7C1F0EE13ULL
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
			0x928A019CFD1AFC20ULL,
			0xC243F1865942D946ULL,
			0x83D50132DAE451DDULL,
			0x46EB3E7A5EB52B5BULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x51C929BE0685F020ULL,
			0x35BE9E284EE31ADBULL,
			0x07E5E14A1FA57F27ULL,
			0x5B54AA7BB5347415ULL
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
			0x596ADA4E6C115C00ULL,
			0xDA68BA2D52C0FD55ULL,
			0x82570035F6DCD050ULL,
			0x40756E1D642A30C1ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x4830263A968E88B4ULL,
			0xB21BD03F69F953D8ULL,
			0x18FE67C1A3BC3A92ULL,
			0x53F9D19764D98296ULL
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
			0xCC7856DCC7F9F6D8ULL,
			0xE1D5403D05662D08ULL,
			0xB6017C77B3FA6707ULL,
			0x778366889DC7DD78ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x6CD24FBDD1D200E2ULL,
			0xA819E2552985BB11ULL,
			0x7C880D77C7574D6CULL,
			0x0A7AADDAD1B2083DULL
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
			0xFA28B57CD99C1070ULL,
			0x20409C6C9D4EFF87ULL,
			0x94F541C6A96C04A6ULL,
			0x7482963739159714ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xDF6FB7639FE1F7AFULL,
			0x1067C158948E1025ULL,
			0x3CF6F848093FABDAULL,
			0x2707B7BE3EC715D8ULL
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
			0xC655124794100D10ULL,
			0xCE809D2350E5212CULL,
			0x6F7F1AE301DAE98BULL,
			0x5FD6F871399A7B3BULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x2EB3CC9EC8BFB261ULL,
			0x7DB4FF1191F7C794ULL,
			0xA44222E5AF28CF74ULL,
			0x249FE12655603AA9ULL
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
			0xBBCFE43840F00E40ULL,
			0x0D72C19509A99EA0ULL,
			0x9D389617DECAA97FULL,
			0x4535D8C2F9FEE52BULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x4323E89F1D6BEBA4ULL,
			0x9D9888520ECF921BULL,
			0xFB7F8A6ABD664F98ULL,
			0x62AB2D595E09BFE4ULL
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
			0xC06DEC08FD624E60ULL,
			0x4E59C2083113D850ULL,
			0xB773DE5B048872A0ULL,
			0x67B08E5268CFD07DULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x1BF99462D4A9C3E1ULL,
			0xA628201D70464532ULL,
			0x1177F16B5EC19720ULL,
			0x0233DC226FE20AA0ULL
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
			0x9F4974130511DB28ULL,
			0x3A64F232785E5407ULL,
			0x30DA1C860B3D59ACULL,
			0x42F269CE435B8BBEULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xF293F567D41BB444ULL,
			0xCF20F8456572BF86ULL,
			0xBD1A75B3ECAF2249ULL,
			0x7F47922CEBB5658AULL
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
			0x4695749CC19E3930ULL,
			0x0C711170A9C73FB1ULL,
			0x46DE27C803B5D37DULL,
			0x6F84EC58117CCA7DULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xE8B586FC15E95351ULL,
			0x019CFF22E6BC0C70ULL,
			0xE7BD73EDC4532134ULL,
			0x2229FFD2DB818B36ULL
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
			0x553583761236B778ULL,
			0x271A0803A99FE19BULL,
			0xC4F52059409861BBULL,
			0x4273E6A8B4A983C5ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x97A326613DAD00A9ULL,
			0x262CD88B6CAFD4DEULL,
			0x4A410A9A625E0957ULL,
			0x69BA393B54ED03E6ULL
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
			0x42B225809D5313E0ULL,
			0xDE091FA1570CF549ULL,
			0x61BB1B5B3B979E74ULL,
			0x765327C7192DD600ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x6F61AA909286B0EDULL,
			0xB5A77BC152591D85ULL,
			0xC46FAD350FDAEDCDULL,
			0x77474087DB29D141ULL
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
			0xC89E1431D8F821D8ULL,
			0x6B3ADD56FB40722BULL,
			0x4A714C1FEC26961BULL,
			0x480E5FFB37C72576ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x807E684C9164419AULL,
			0x16402339FD94F6ADULL,
			0x383B4E50BEDDC533ULL,
			0x7A03443FA111AFB2ULL
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
			0xFB87E09C139C6840ULL,
			0xB1FBC8D25EBE78FEULL,
			0x3E987AE7B4C46758ULL,
			0x657C98F47508D921ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xCBFDDE31F25CFB95ULL,
			0x8DBE299B672F5ECDULL,
			0x152282A04F80024AULL,
			0x46700B05CB9A37E8ULL
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
			0x595D25AA6B8BC8A0ULL,
			0xD18CD5DF3E1C4110ULL,
			0x6B50EDF0894905F9ULL,
			0x458C24EB1602DCE7ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xA5CCCE1AB06849D5ULL,
			0x907E8BEA2DE837DBULL,
			0x0F428A722AC7116EULL,
			0x30A4CA0E5AA83C97ULL
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
			0xCFC06D1C7543B2B0ULL,
			0x4213B7EC94952B6CULL,
			0xA47EB182D85C96D6ULL,
			0x74DAAC05E335C9DAULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xA9615FC8E6C25B38ULL,
			0x531F0DD372E4AC4FULL,
			0xB604786E1816E8DFULL,
			0x69057F8F43807DA8ULL
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
			0x1C2C05D3EF4D8888ULL,
			0x8A3A2533545D6B5EULL,
			0xDF683D730FD39D0DULL,
			0x58A3755706997EF8ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xECF63E2BFD4F450BULL,
			0xEFC9B1EC25158043ULL,
			0x8F39C220E024AAF2ULL,
			0x40E77021D216CC6BULL
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
			0xF3353A42FA7AEEA8ULL,
			0x9E54ED1E56F9DA66ULL,
			0x945BADAF2A037A54ULL,
			0x7D484D01F5A0558FULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xD8F85EDAAE355C24ULL,
			0x400D0D75D256B5F5ULL,
			0x9BB414DADDD9C910ULL,
			0x4322BD70F2291B55ULL
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
			0x9881C4A54C3783D8ULL,
			0x711BBBF3DA209360ULL,
			0x6F37547F2B3C7BAEULL,
			0x74E4AC668749A9B0ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xC8F8668089C78524ULL,
			0xAF87EB17ECB67B2AULL,
			0xB384CBB716A18E12ULL,
			0x2CF00076448349B5ULL
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
			0xC4D970CBE9F109A8ULL,
			0xF7774EFE58144C5AULL,
			0xAFF1247918A8030CULL,
			0x40A355C5BED76DDAULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x4440F4588E07BBF0ULL,
			0xBE4382DA38D33DA7ULL,
			0x67071F92B01F49C3ULL,
			0x33FD9DC3C3206E4EULL
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
			0xAE3E6FD0C470D1D0ULL,
			0x8934E7A6FBA5966BULL,
			0x36751846A0B58686ULL,
			0x5154F356F2CFBC24ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x7D70E8A4BA28B3FFULL,
			0x4171181FE3BB3528ULL,
			0x471D03DCDC8D938CULL,
			0x60DE37665412B025ULL
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
			0x8586AD7243465718ULL,
			0x6ED25A622EEE6631ULL,
			0xE8C60EEB9B0B9FA7ULL,
			0x6685551B59C96206ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x2E94F18B27C8ADE1ULL,
			0x8EECF616ED40F762ULL,
			0x5F3D196F29EBBF8DULL,
			0x7669BBE00B2C6DEFULL
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
			0x14EB8F1A676B9668ULL,
			0xFCA8572796C39BC1ULL,
			0xA2F6CB638FE2D78DULL,
			0x5FBC2B6EDAB1E624ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xA7BD7679FC52D602ULL,
			0xF203AED10F83F369ULL,
			0x256AB58C8A0F393DULL,
			0x073E3844A63F3EB3ULL
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
			0x2A7D8FE70263BA90ULL,
			0xEEE6199ED908A2BAULL,
			0xE0B5299926A5D70AULL,
			0x786F03CFDD442628ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x42D8D3B392D59B69ULL,
			0x4D68DF18D521F3A6ULL,
			0xC2C7F81C54E9C106ULL,
			0x13798CF0F1DDBA5CULL
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
			0x6E699F45062BF458ULL,
			0x5280E1EC732AEC56ULL,
			0xE1EBC851CC94BF00ULL,
			0x6A109BADEE5332FCULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x8A72F86405CD40E1ULL,
			0x7266D047CF832BBDULL,
			0x6857E3A10C207D8FULL,
			0x0E08C6751F076A42ULL
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
			0xE74F7A772EE2EF00ULL,
			0x30819F64FB5DD6AAULL,
			0x1A13D0139F206AB9ULL,
			0x73D9415761A26456ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xA3C4A3E4A7312DEEULL,
			0x7492C27C98E95DB4ULL,
			0x94F32182E0B3C428ULL,
			0x5B40F501A7717357ULL
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
			0xF7BAC84C0109BA90ULL,
			0x6DB5084F5EFB7A33ULL,
			0x78F2A051EC6D50E4ULL,
			0x4B2553F126618B92ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xF8D8D9678E2D97B1ULL,
			0xE82FFAF81F9A891DULL,
			0xBF9A420C762A290DULL,
			0x6D0163FE0BCF9F0AULL
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
			0x2B2158F2913084A0ULL,
			0x41E5C826EEA78009ULL,
			0x47FA23D0D4CB78C6ULL,
			0x700BEDF35C1098ADULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x0D13A6EC9DD717C3ULL,
			0x03D69989D4F430DDULL,
			0xAD0064EEC3384A66ULL,
			0x5438BED629621D34ULL
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
			0x03CC9BE56EBE07F8ULL,
			0x4FBA8D2D15FB98F7ULL,
			0xB2F71AD08BC0B4F1ULL,
			0x4D558C7A037B91E9ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xAD316331F4C4F2CEULL,
			0x5B160CDDA100EBD2ULL,
			0x3144B27BBB26491EULL,
			0x6E145E2AC718833AULL
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
			0x45D8CEA16365F178ULL,
			0xA7D4067213C5253BULL,
			0x9E3C3914B1FED245ULL,
			0x6D6FBC13BA95B912ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x343D2FB57E32E245ULL,
			0x5132F4799E7DE1DAULL,
			0x3980B61C4D2B8164ULL,
			0x58042668AA55918AULL
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
			0xDD6CF74763196668ULL,
			0x043938B391C9DAA4ULL,
			0x56E9D8EC2C35BE3FULL,
			0x5F413BA7B2B6319FULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xDA9D765B5784AAEBULL,
			0xCE2406563D0DC47EULL,
			0x1960C285BF061AEBULL,
			0x1A3748543C0BFCB0ULL
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
			0xE5B7B8EB67888470ULL,
			0xC705F5B6D5738159ULL,
			0x522018347F68B465ULL,
			0x75DC6CAAEAE741FBULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x5F6833EC38D98820ULL,
			0x8410854CEE1F530CULL,
			0x61774D967D3E9BF0ULL,
			0x0756D1F4772F77EBULL
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
			0xF5E0AC9802A33F88ULL,
			0x6916AA1E31A93587ULL,
			0x7E21B31D824D5126ULL,
			0x49B9152A1FC521F3ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x47FFEA2F3F636A4BULL,
			0x553564FA1720EC27ULL,
			0xBA3D2B373C54A103ULL,
			0x4168DA24EEE9B018ULL
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
			0xC74ECF04A24CDC58ULL,
			0xD5768779AB544D9AULL,
			0xFA6C716B652DA05FULL,
			0x7A8EBB8C1618F74DULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x06F919B6203B3578ULL,
			0x023D14EE3F42CFE3ULL,
			0x5CE439175F4E36EAULL,
			0x1859F5B8E84023D1ULL
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
			0x27DDFB8362F33A00ULL,
			0xBAF2B04BE23B0E33ULL,
			0xB47577A52330C325ULL,
			0x74957D77373A740DULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x646C797F42093113ULL,
			0xE359100DBDB9AB70ULL,
			0xC9120F01775C49B3ULL,
			0x11D725AFD6214387ULL
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
			0x8767B684D902CD48ULL,
			0x74345BC3B7F24B49ULL,
			0xFEF4794ECC71A95FULL,
			0x7F7626EB2E163A9BULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x3E5487564178CD8AULL,
			0x9147D43DE4DFEA34ULL,
			0xC34028F2C5A41D01ULL,
			0x5899A556AEED3B65ULL
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
			0xAE8479EE07362B00ULL,
			0xC98240B9EE4A2C12ULL,
			0x0E39370F85AC0526ULL,
			0x4AA4BB4FD2D9F409ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x1EAE113D495375FDULL,
			0xEBF4FF92FA02CCDEULL,
			0x830B335DE786F02EULL,
			0x199C0F84C5393A72ULL
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
			0xE3A8D52DE78C8DD8ULL,
			0x5F8A6278E7785B29ULL,
			0xD7E56AA07D1EB1B1ULL,
			0x5602C34B53EE619EULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xB7CF1E4EC76A6EFEULL,
			0x50E7E41EBBBBDFF2ULL,
			0xE5706AB98FDCF9CCULL,
			0x357A171A1EC5A41DULL
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
			0x56722F4FE83D5170ULL,
			0x45633AFFB15B442BULL,
			0xAC577B77EFE3B4F2ULL,
			0x7534E48F8E0780F2ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x1CC00996299869B4ULL,
			0x369C3344BC7C0D47ULL,
			0xBCA79421028F270BULL,
			0x073F34C984A113FFULL
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
			0x8FBA86720E95D9F8ULL,
			0x053942E19BFCB7F3ULL,
			0xB9C382CDD64F10AEULL,
			0x5F1AF662076FBB16ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xFDEEDBD2C086758BULL,
			0x6C1AD6A76EEAA669ULL,
			0x51D231FFB984CF72ULL,
			0x2692F7F7F0E4C0C4ULL
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
			0xC5D4D2372FB67040ULL,
			0x60968B10589CEEBDULL,
			0x988607E7A0846F4EULL,
			0x7571CCBD289FCF7CULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x55CB5A5D6A5D9440ULL,
			0x1C7B692087801A2AULL,
			0xE947E10F15E9E9EBULL,
			0x310DFF614CD57EE4ULL
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
			0xE709FD834BDFCE40ULL,
			0xBF29E8D6F76A963DULL,
			0x024558B29F27181EULL,
			0x6D329B00AD2423F2ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x9C25EE54291E454DULL,
			0xF696BC0717ABB0DAULL,
			0x53FBBBF4BFE179FCULL,
			0x30494E5DADEDC080ULL
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
			0x7A2B6B0341EB4018ULL,
			0x113833FA69CC10D8ULL,
			0xA6C1673E2700318CULL,
			0x6B30D57385E05F8CULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xEC5B273D6A56BF18ULL,
			0x778CBE8025C418D5ULL,
			0x44C90B5EABD18D93ULL,
			0x2CCC1E998E9E9331ULL
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
			0x534DDC513B5CB190ULL,
			0xFCDA04C9247F97C7ULL,
			0xBC266984479EDFCDULL,
			0x7B1BC1CF8434FAA4ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xA1A60DBFF0A248A4ULL,
			0x38A0738E33736182ULL,
			0xEA12BCC400FADFFFULL,
			0x7DD0796E426121D5ULL
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
			0x9D34E484DD1F4478ULL,
			0xA288BC84571BC02AULL,
			0x03CB6EBC80A9B899ULL,
			0x5292019897BCF169ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x0558D6A1EE587CA2ULL,
			0x0AEF043347E1B39EULL,
			0xCF59F98FD22A4F16ULL,
			0x441E6D749F25A25FULL
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
			0xAE462949D5525EB0ULL,
			0x14E0022F1D119314ULL,
			0x3BBAD804DFE8F09EULL,
			0x6E5D26835F5B7043ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x4269ED9D898567EFULL,
			0x64A352183D5ABEF8ULL,
			0x89EF9EFB260A100FULL,
			0x4ACA48CC54A16DBDULL
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
			0x2635E98C0F7DD938ULL,
			0xA7EF7A9A55D5C815ULL,
			0x2121AB61403804DFULL,
			0x698A918E61B05BCEULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xAF500E85CFEBFB84ULL,
			0x2D79A972A4F3BA73ULL,
			0x80B05FFCFEAF7F82ULL,
			0x572530049663A2B6ULL
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
			0xAE874FB33C2018F0ULL,
			0xD54AEB93B255652BULL,
			0x6420DAE4A39DC1DBULL,
			0x72C149AAEED3CD63ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x8D92146C618D655BULL,
			0x2621F94F43D47417ULL,
			0xC5CD05AD4B440C4EULL,
			0x5304F340A455A649ULL
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
			0x457C40F66FE76E90ULL,
			0x4550AE3516EE453EULL,
			0xE8C8FCBCF91CE272ULL,
			0x7574D60534E4461BULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x8B5F7D570DDDD551ULL,
			0x759FA264583B00C3ULL,
			0xFDDE342AA61AE9FAULL,
			0x55AC698B59ED8661ULL
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
			0x2F630D17030712E0ULL,
			0xF0B6B989CEC5F24AULL,
			0xF65F9C4868F94216ULL,
			0x4D36E146CD168B2EULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x637039550D5038A1ULL,
			0x3146AFFCB905CC25ULL,
			0x1A2FD1AE38083CF7ULL,
			0x0C891D016C8DFBF0ULL
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
			0x320BBFEE8B3A1CB8ULL,
			0xA46E612C0F21C36FULL,
			0x0E5DC52274B7B243ULL,
			0x5C175E7808E1C96DULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xB30D14182BA7F2DEULL,
			0x6CCFF92C9D85071AULL,
			0x7C1B328B2D5E05EEULL,
			0x737441F4532A46EDULL
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
			0xE3F5EE248C392428ULL,
			0xC4F7CD223B5A92DFULL,
			0x79A6EB4B4EDA9FB6ULL,
			0x5D64419454A33893ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x7B8E8E618935A359ULL,
			0xDEFF8618B4061F5FULL,
			0xC06142935C4C3119ULL,
			0x74D930880E958AB4ULL
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
			0xD22E52C0B57DADE8ULL,
			0x02FC1C5F822019B5ULL,
			0x0B47CB09156AF432ULL,
			0x618151D031DC611FULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xCFD803DA431A7C6AULL,
			0x9BC80DB7F2CF9407ULL,
			0x8FC87D244733FFC7ULL,
			0x51F913743524FDB8ULL
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
			0x8E8B392A21590270ULL,
			0x630DBCC57E093FADULL,
			0x71B1836269E65FA8ULL,
			0x582DBCF63FE7FD10ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x9E47CF5615E06592ULL,
			0xC5E2E482A4942139ULL,
			0x6600AF8A6E5F0B67ULL,
			0x1A079ECC98F43751ULL
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
			0xE0CD5384906B63F8ULL,
			0xDC25B53F1976CBF0ULL,
			0x3295645751A17435ULL,
			0x7A5D8A4C5B6727B4ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x2F71FD946DE0885EULL,
			0xC0F047BA8903CAC4ULL,
			0x7D8D45C18AC31F91ULL,
			0x44DDFBF45B7C8F60ULL
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
			0x64FE61307EA0CEA0ULL,
			0x4BED5B91D73C324AULL,
			0xB1ED1AE1171EA5A4ULL,
			0x79191E70A56B64E1ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xB9539DFFE0D6662AULL,
			0x049F6DDE892CFCD2ULL,
			0xD22CF190F9DD1A9AULL,
			0x11E8B8195B29F949ULL
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
			0x8FACD4BC2681ADB0ULL,
			0xB272F3DC1BA8EC33ULL,
			0x7AE8529DA2A0FCA9ULL,
			0x7501120569F44208ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x492AEDCE876C7154ULL,
			0x083ABC871FB1C830ULL,
			0x68EC2A09048BB54FULL,
			0x2D0323778D2A221EULL
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
			0xABEA04A1E876F200ULL,
			0xEB8805912AACDA42ULL,
			0x3CE416DCA89E1D09ULL,
			0x4937850DD9C94A80ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xCBF3BC3B8AC2C8D4ULL,
			0x0D8E1D382A297106ULL,
			0x03538C51955AFCB4ULL,
			0x3F37770D0A71AAB3ULL
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
			0xF8C10C3102AE5C50ULL,
			0x71D857F9A894D68DULL,
			0x6E46772698329F13ULL,
			0x782BEECC5827BE7EULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xA69B91AE01846592ULL,
			0x918575EBAABA4212ULL,
			0xD75035DD52EC44A9ULL,
			0x2DD6B0ABE9FE4C9EULL
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
			0x6B7969EEF672D6B0ULL,
			0xE6E12501FBACBBB7ULL,
			0x301B234313B0DB03ULL,
			0x74CF1A89F38AD29EULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x658D6944650F4A5EULL,
			0xBDBD361651AC7BDEULL,
			0x474DB5F83EB7CFDBULL,
			0x463826A54331D8B7ULL
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
			0x101E4B592266DBD0ULL,
			0xCDF9D834CCB64A52ULL,
			0x5A58F1D5D5153100ULL,
			0x4565F4E56CBF8714ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x57A87FA70A4F2B61ULL,
			0xF22BD72C6F40A9CEULL,
			0xB9B17407E55AFA10ULL,
			0x655DAB3CA456F424ULL
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
			0x682A55DFFB1D97A0ULL,
			0xBDD16E5A883E9B74ULL,
			0x77B98837F5DA7E94ULL,
			0x45E5273ACC095908ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x29A0E4DC3D23A117ULL,
			0x6E7BC043A1180416ULL,
			0xD6931ACAF02B309CULL,
			0x140CAE8E6D9A2701ULL
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
			0x3FB018E8D0E19CD0ULL,
			0x579034028D1F0F9DULL,
			0x0828A874CC67B62AULL,
			0x6DC8F3106D7FC3E3ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x756269E41FEA6AABULL,
			0xA79CAC200E891C19ULL,
			0x3DA66977088F4C6BULL,
			0x52B7FD0DF7B4B8B8ULL
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
			0xD6713DF9715ED6F8ULL,
			0xF2BE9B78765450A9ULL,
			0x64D3EC5998B57D40ULL,
			0x5442B7DA004F8FC6ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xCE11DE09B2C546EAULL,
			0x84E837130C178BDBULL,
			0x6466897AA018138AULL,
			0x19167495D88DAAD9ULL
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
			0x09004C75E8E3A480ULL,
			0xF92CBD0E5A83BC02ULL,
			0x7C6452D9B04FE3B6ULL,
			0x7F1F919E3A097EBFULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x7FFA7D5E844D0E0DULL,
			0x9C84447952AE8909ULL,
			0x7E83A51AFBE70EBBULL,
			0x3AF9A57FF3CCCE00ULL
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
			0xFDE02C9A5CAF0478ULL,
			0x3A95A9F15574C9FCULL,
			0x75349144BE614C5CULL,
			0x686AAA1FE371EA0DULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x776CAAA787462CFBULL,
			0x760667216AD9746DULL,
			0x26066BAA30D1FAD5ULL,
			0x1D00F796FBB538B5ULL
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
			0x3C978E73A9047E90ULL,
			0x1FCFB0986711C034ULL,
			0x272E7CEB85172F22ULL,
			0x7C878389CBC8ACE9ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xB12CD37AC15E678EULL,
			0x1B720779F4E8201EULL,
			0xF2EE82D049984CD3ULL,
			0x3C47727DD084AD27ULL
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
			0x0FAA02D6658DE610ULL,
			0x72ABA6CBEF93A8AEULL,
			0x8B35EC62B6343B35ULL,
			0x77F44177F266F34AULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xDDEB2F253A663110ULL,
			0xFA07EA50600A8AA2ULL,
			0x5B83D2E55D0C2EA8ULL,
			0x65B3A3D4589EB5DEULL
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
			0x52D35DB6A7E79550ULL,
			0x416669069C651EDDULL,
			0xE4E00567A8163148ULL,
			0x60D898EF1D02BB2BULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x881C4E1E0D7643CAULL,
			0x37A4AE8DD8500615ULL,
			0xC151DD45326EE91AULL,
			0x7D13019245A9B6EBULL
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
			0x175FFE363F38D728ULL,
			0x96BB73508451B44BULL,
			0x21FFF191B03C2ECFULL,
			0x62FA16F50764B089ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x987AAB113115406EULL,
			0xACC973C65C010477ULL,
			0x1BEF83BC4B27C203ULL,
			0x523FEDC830CF8140ULL
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
			0xC5F6C6374B74BFF8ULL,
			0xB04A7AE9723680D9ULL,
			0x3E1D4B569D3574EDULL,
			0x60C376AA3221C22EULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xB42C331938F60F7BULL,
			0xD9D3C3E81B7D624CULL,
			0x982B6BE92EB9A2EFULL,
			0x23C97750C5DC1019ULL
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
			0x3C8218A922110008ULL,
			0x555214A8F8FCD543ULL,
			0xB93823A1BAD62E17ULL,
			0x4B7FA638E1847E91ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x84CC451B52971C04ULL,
			0x0F20E66F66539591ULL,
			0x5636A0B93DFEFA8FULL,
			0x0EC0848A4EE60D6BULL
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
			0x6B90F337157B79B8ULL,
			0x25189880C23243ADULL,
			0x0A198B62124D9688ULL,
			0x79CB763CE1D314DBULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x50114017DE09BC77ULL,
			0xB7B4275A7A172B3BULL,
			0xC3D1948646CAC721ULL,
			0x2055E568DF5E863DULL
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
			0xB0F302CCAA486618ULL,
			0x4315215FA6290F7CULL,
			0xC6A14B3D08EB232AULL,
			0x5F5A2F7CE86D31EBULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x15BBFF5CF87821D0ULL,
			0x464D9256E150110BULL,
			0x0FB8D55CA5246B16ULL,
			0x517FA494B646A6FCULL
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
			0xB4F9FAB0621BA360ULL,
			0x310FEFC079FEEE11ULL,
			0xA92CD92C695EB005ULL,
			0x7D3BFE86BA2275ACULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xD3048E692276914BULL,
			0x0A594A0E2419026AULL,
			0x3295306C02121B45ULL,
			0x45EE2275648EF1DEULL
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
			0x2A3697111441F8A8ULL,
			0xF1C4268AAACBCE8DULL,
			0x8A82041FCBE6FAA5ULL,
			0x4C2481934180F7A0ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xF1336209147366ACULL,
			0x440C65F9F958B495ULL,
			0xAB2BD6804A36CD1BULL,
			0x5F2C5D55D31D76C4ULL
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
			0x5E8C755C85EC2700ULL,
			0x373184DFA80995B2ULL,
			0x3E3A9F875E835D93ULL,
			0x4F30F63294B95332ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x5602088CF949EE29ULL,
			0x368A31BE2459BE07ULL,
			0xF137BF969E4D005AULL,
			0x27C3B71761606BBBULL
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
			0x2B61F9C96C99E900ULL,
			0x0051A113AFA39695ULL,
			0x2EE3B3B55FE4F237ULL,
			0x5C90B9A426526F69ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x86E38ABBA2374753ULL,
			0x1D0FE95E99F9E0B6ULL,
			0x530DD075D02FF210ULL,
			0x5882E676FF8F7E83ULL
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
			0x176A8850F943B140ULL,
			0x4089A2F6707B52DCULL,
			0xD489CE1DEC927B1CULL,
			0x480C50D656E4564FULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x7C0D621DBC9DA90CULL,
			0x67BA932CF2320CA6ULL,
			0x5890CD8941260661ULL,
			0x0AE3DDDEBF09B3E6ULL
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
			0xC3BFD9B168D58398ULL,
			0xFCCD87EFA154216AULL,
			0xC27F0F6D39E9CCC9ULL,
			0x48C37CB2FEA7F11FULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xF489CBD9BA66C7C7ULL,
			0x458D1FA01721862FULL,
			0x010CABF3410CAA61ULL,
			0x7AD35F166CC1EAC3ULL
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
			0x0AD802BF94A4B300ULL,
			0x3A48A112B31F3191ULL,
			0xBC48874398B5F836ULL,
			0x6878842CACD488D5ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x4D0E4CDE6FA76C6EULL,
			0xAC829C84540CD8D1ULL,
			0xB5C70D49F64A9576ULL,
			0x0B760B00FF0417C8ULL
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
			0x9B6EBC92DF13BC78ULL,
			0x421A631D1679E00AULL,
			0x05D72957FFF6D04EULL,
			0x486D5141B8C9A2C9ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xD0697534F0E53683ULL,
			0x3CB7C2C35CCED9F8ULL,
			0xA760AF2835B17581ULL,
			0x1767A8892D40F4D9ULL
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
			0x91585A9C77FABA88ULL,
			0xC7FA7C23ADB703E7ULL,
			0x6DCA6E37C05C2054ULL,
			0x54FE74A9E39B929BULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x32E568D15F5B6636ULL,
			0xAABF56E2A1E8399BULL,
			0x893FEDEF3FCB5726ULL,
			0x1A48DE84230ED539ULL
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
			0x4E00DD27F6CBB028ULL,
			0x4CDAEB86FAC038A3ULL,
			0x82E3BD9A1F5B670EULL,
			0x57E672ADE612B365ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x0CBF329678F1029CULL,
			0x0B189426D9798C40ULL,
			0x625C537CE8703FAEULL,
			0x028F2EC3196CD4BAULL
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
			0x3DE5BC27F3D0FFC8ULL,
			0x456FEB6CDCAFA370ULL,
			0x09E8D0095C9B19D4ULL,
			0x4D5A5603ED2C9C45ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x56C7D2EA889B7B46ULL,
			0x11C36263F4CA9955ULL,
			0xB07078EB81770C29ULL,
			0x4A42E55884C96CEDULL
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
			0xA1C89F0D22275B28ULL,
			0x38C54A2361688A50ULL,
			0x55383100F0157F14ULL,
			0x723CDED5999AFA03ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x2FCB3672671EE2A3ULL,
			0x9B8AA941A3CC721BULL,
			0x057C0ACC3B3B14D1ULL,
			0x455A52ACB259632EULL
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
			0x657044A671EF2970ULL,
			0xFD7AB6D0C95FF382ULL,
			0xB39345F824181F5FULL,
			0x6EED26477F77246BULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xFF7D0BF598E4CEBBULL,
			0xBB4B74FBA78B5A52ULL,
			0xFA28912877018EDBULL,
			0x641AB3B7B8439075ULL
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
			0x637C4A48CB9F55C0ULL,
			0xA83B99A5998DA3DAULL,
			0x3368E6171CCB52FDULL,
			0x692FC01CD13F076AULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x81ECE22AD34085FCULL,
			0x518BCA5157C09EB7ULL,
			0x19524E411EFF5CBFULL,
			0x65FC5F48CE89FB40ULL
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
			0xCCCA45B0266A1448ULL,
			0xE917948659EB6062ULL,
			0x38366C8C71F257D9ULL,
			0x554097CC7EEADFA3ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x14131F413DB72816ULL,
			0xDE394AEEBBD9779EULL,
			0x21A1A5AAF8815F2EULL,
			0x51FE15359D3A264DULL
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
			0x37EE144C5688A170ULL,
			0xB35A49BF233361A1ULL,
			0x6657AD4280F5567BULL,
			0x73DF0D6621B925E0ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x7F2862C744E49B38ULL,
			0x19D324880AA637B2ULL,
			0x278F617528B62177ULL,
			0x1097261FE1105109ULL
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
			0xEDDF6BC09E33A4D8ULL,
			0x768372096B63EE1EULL,
			0x5E17AEDC49FAAAFBULL,
			0x734C623876397E94ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xF3243D2C755D23AAULL,
			0x1A53FD034F9962FEULL,
			0x45ED3EC9D68592FDULL,
			0x4CC5B56E2EA56AA3ULL
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
			0xF2AEA7FF2E447390ULL,
			0xDEA13539ACB41819ULL,
			0x2A2FC80F07A29624ULL,
			0x75C09F3D74D77FBEULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x5FF0A5E330931F63ULL,
			0xFC905A04B8EF3E3BULL,
			0x05502CD1367869FEULL,
			0x743C689E4E391D18ULL
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
			0x61A1607F52C7F028ULL,
			0xBBB0BE0D68166058ULL,
			0xA86995CB6A0EB36DULL,
			0x57AA9175B74D191BULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xDC25F6501D2FDB61ULL,
			0xA70A5C6B593D7C01ULL,
			0xE23A5C2247F83779ULL,
			0x66906B6F3BEAEB8CULL
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
			0xFD59F80F7D3891B0ULL,
			0xCD1EB578B9BE3B82ULL,
			0xA71CBD64AC5871FAULL,
			0x453D2BEDB80CBD0EULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xACA90DB2654A7C6BULL,
			0xDA4FD2798B8CA6D1ULL,
			0xA344634622324473ULL,
			0x13CEAC627F6BFB5DULL
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
			0xB2CAA44EDD815B48ULL,
			0x606B9FF7DAD2E82FULL,
			0x2895ECB39309A880ULL,
			0x78C7458DFCCC916EULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x1CBB07E08EF44B21ULL,
			0x27F118687522C484ULL,
			0xB8E20ECECAD973ADULL,
			0x2BFA17499859AE5CULL
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
			0x222DD0358ED5D410ULL,
			0x4ABEB5F962FFC192ULL,
			0xECAF509B8301E9E0ULL,
			0x4DE3C9690E43B418ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x93936FB8B6148C16ULL,
			0x9BDA1B51A18E69A8ULL,
			0xBE14BE1BCAD6D925ULL,
			0x7B18EC69BE53332AULL
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
			0x12F134D24F6C2D70ULL,
			0xBBE607EEF1F4FE6DULL,
			0x46ABF4DFC5A6B332ULL,
			0x789AD8028B6976EAULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x278A45FFC157D453ULL,
			0x0AB6B9A2F17B158AULL,
			0x33E61DD0677DF11CULL,
			0x119EB5EF288EB791ULL
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
			0xEC479F95C3262460ULL,
			0x572D8638F2A35D20ULL,
			0x15FB08D6A1841502ULL,
			0x430D4365375BB89EULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xAF2F9D6B4D655886ULL,
			0x42A58A71AC2D74B8ULL,
			0x0B2087FAC08F96BCULL,
			0x622F4BA95B1D365EULL
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
			0xA2EC6D2AD4BA0E60ULL,
			0x7EFBB8470C381770ULL,
			0x300B8094083FFE21ULL,
			0x447720DA318849D8ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x74F8496EEA59A8D9ULL,
			0x00681041395C436DULL,
			0x8D638E40BE462EB1ULL,
			0x755B8F61F162F793ULL
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
			0x202B45A03A202890ULL,
			0xCC279E73694711A0ULL,
			0x6A9A83A94C152A61ULL,
			0x6AAD81104176937CULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x8017F5DE9CD93322ULL,
			0x838201DF76F72190ULL,
			0xDC50F981E74CF1BAULL,
			0x1D2B074E17ADE61BULL
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
			0x87C4513062E7D840ULL,
			0x14273E976F209A69ULL,
			0xD2FD5A93C826DFB5ULL,
			0x4D9F6DFBE8736093ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x5DE9A03567932271ULL,
			0x673D58E60C6C3722ULL,
			0x947463A6B14F4A07ULL,
			0x4B084CEF79F45246ULL
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
			0xEADCB52D9B9CE4F0ULL,
			0x03DF7EA6116164C5ULL,
			0xF2976EAF8D033D23ULL,
			0x53EC5F48410A177BULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xA2B28534C0B6A8B1ULL,
			0xC8D6A126D4C76005ULL,
			0xEFF487719D9BCC29ULL,
			0x2E672B4E0B98D321ULL
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
			0xA0EAABCD824F58E0ULL,
			0x066AD52EC5233244ULL,
			0x345D21CD4BE415A2ULL,
			0x63E3DC7715A80B74ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xB48E26E4B11DB5B5ULL,
			0xCB9EC9408C7A04DFULL,
			0x84A95F0C0E632748ULL,
			0x29CACE8D8CDF8CEDULL
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
			0x3E34489E2B223178ULL,
			0x62DFBFF64B525BBEULL,
			0xFE5A3D7F67EA6AEDULL,
			0x62F2FD83F712D1AFULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x907BCBDBE609ABECULL,
			0xB964925B47735E98ULL,
			0x2C66C4956819B0CBULL,
			0x23C68E723937CBE2ULL
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
			0x54460557E508D8E0ULL,
			0x00ADEE6E9FBE4464ULL,
			0xD0C69F4D0CD1D2F4ULL,
			0x41131243E6B75C22ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xB6A2962295BA1BDFULL,
			0x2C04B8A025A5F1C4ULL,
			0xA8CFDA92E16E20CAULL,
			0x7969FDD4BCA8933CULL
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
			0x9B78E512F8F60BA8ULL,
			0x03C4FC645C3AFE56ULL,
			0xCD3654ED69C22CBFULL,
			0x6624D72DB6C0300FULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x46AB8468AAF9A2A4ULL,
			0x63985CAD6DF2C3F7ULL,
			0x05BC9145B7BF4AB5ULL,
			0x2C8B201408716709ULL
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
			0x0C2DEB72196AB658ULL,
			0xAE93CFF79C18336EULL,
			0xC13BDBD71A88295EULL,
			0x5DBD3ECECFC7FA3BULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xDB1FA0DF3E5195AAULL,
			0x125D9DCECE2F49F4ULL,
			0x11CEDE93FC4948EEULL,
			0x78B932B73688F57FULL
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
			0xFB769D4EC93AF358ULL,
			0x7DD4F542738D2835ULL,
			0x4B5B9DF221503FCEULL,
			0x7CC08FDE6445FF20ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xE271645379C2C58DULL,
			0x2E88F0C6D33BCB7EULL,
			0x2E9D5444E37E893DULL,
			0x7387A874090A8845ULL
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
			0x1B9BD7F2D26BBB28ULL,
			0x69DA1A470C6F694EULL,
			0xF215B6838CD39016ULL,
			0x5C6FD3C81428CC38ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xF8A1DAEBDFA479C3ULL,
			0x7B4FDD4DACE1F487ULL,
			0xE599AA1C6D5AB96DULL,
			0x6E1FD077B06F197BULL
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
			0x1CD45F9741D5CC28ULL,
			0xCAE0A11E6C009F80ULL,
			0x05D809C36649A885ULL,
			0x69F2D797165EC6EBULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x94ECBDB7B2D9EECAULL,
			0xF66FC9890054BB6CULL,
			0x1DB3EAF02C846ED3ULL,
			0x21F2E517FF7C27B8ULL
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
			0xACA9B72E573F0D18ULL,
			0xF17EBBF90685EB5FULL,
			0x01826E22CFD84B7FULL,
			0x7BFC90D3E32FBFB4ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x98355D0E21EF79FBULL,
			0x0C8DA3351D9A9C01ULL,
			0x82F3D560A9ADD23BULL,
			0x340AEF6F6E95214AULL
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
			0x1270EC8658BA09C0ULL,
			0x90E5E5615973C291ULL,
			0x749C7291F78F7DF5ULL,
			0x5D591F5AEBFB3C50ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xD2D6135D33ED2AEDULL,
			0xA2257A196C2E724AULL,
			0xEA6E7C3C48127828ULL,
			0x6F6536DB4BC5E7FFULL
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
			0x8EAA3F556EAFB7F8ULL,
			0xB2CD0771815035BBULL,
			0x5C573A268A66C5D2ULL,
			0x7436DA300A715402ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x0BAB6D0069489B16ULL,
			0x04642BCD423F74BAULL,
			0x2DE250FD6982C5B3ULL,
			0x4A2F3217CD88B685ULL
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
			0x10F7486036E66120ULL,
			0xA5F2527305BEB394ULL,
			0xDEAEF8AE395953D9ULL,
			0x5CB384509FB93AE7ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xA7C4A598F24AB189ULL,
			0xA8F6632758BE2A86ULL,
			0x3BF2BD743F7A53ADULL,
			0x4DBDFB7F514D60E3ULL
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
			0x4E0FA426E6ACD048ULL,
			0x8BBFE1CC1349CBA4ULL,
			0x09F1FB7F7A44D96BULL,
			0x5FBA572A8C738FE1ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x06573DC640B14DB8ULL,
			0x198AE4D58E4AD39DULL,
			0x72932742C2CFC0A5ULL,
			0x59A8CA73BA169B6DULL
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
			0xE029FA4EDB83AD90ULL,
			0x63CF152A1453B3ECULL,
			0x93FBE2B5DF1F6BF5ULL,
			0x651440FE4CE2DB36ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xA3708404FBA5E0C2ULL,
			0xF67F3EFDB191C1EFULL,
			0x92530807F35E4CF4ULL,
			0x5DB07EF3B12AE005ULL
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
			0x758272725DB7F408ULL,
			0xA179B28A64751F59ULL,
			0x818B2E4AA9A63913ULL,
			0x51584215D7CF9F51ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xFC17C3CE6A2A7C2BULL,
			0x2D24B279CE0DC3D3ULL,
			0x57915C5341F3BA03ULL,
			0x16888FB90BF4B0CDULL
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
			0xB9AA32BCBCE9AF38ULL,
			0x03324BC736A55722ULL,
			0xA10F8D08E388FA4BULL,
			0x4443D70AACC98AC0ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xDA641DD7DB4C2291ULL,
			0x8798CDCF4DE953A3ULL,
			0xD193BADB4ACBA38FULL,
			0x3F329A3C70846B12ULL
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
			0x42B165EFDB527668ULL,
			0x0EA70FC51EBEC7ADULL,
			0xBD5798B76EF2FF21ULL,
			0x78C3642CC2BC2AFFULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x3866362304DE637CULL,
			0x2996307A55DF7698ULL,
			0xA05E9D0415E36665ULL,
			0x74746F223D1A2E9EULL
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
			0xA847453889249C38ULL,
			0xEBA75D8B9DEDEF1EULL,
			0x15DFEB97CD51F998ULL,
			0x5711D6F2E99179D3ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xC2BBD3E7E4F13C80ULL,
			0xD974F672B547D4FFULL,
			0x3BE85DD4A0602D33ULL,
			0x4AE057BD98CE986EULL
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
			0x45537E4AFE8207A0ULL,
			0xF9D302813BFE0F21ULL,
			0x835E8DB95C353C94ULL,
			0x7D456C97F2E05B0FULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x3B7611902FC1B968ULL,
			0x760E2E06FFB1BD78ULL,
			0x63602F6C053BAB24ULL,
			0x65A53071731F790FULL
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
			0x147B1FF3AD1A8518ULL,
			0x319A3845C920C6E8ULL,
			0x6021FD3827F3ECA3ULL,
			0x7E4A91E022310977ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x3EBA194C8E6DBD71ULL,
			0x267C30161F398B36ULL,
			0x54C2394CDECAE97DULL,
			0x7241E0B2293FCEB2ULL
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
			0x469FC415859E8460ULL,
			0x7604647DD2184DB7ULL,
			0xEEDA7BA7F5FC1324ULL,
			0x749539DE26AFD9D8ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xD2F57240C0CAD289ULL,
			0xE7261A4FA31B046EULL,
			0x2F7C0DB7B63EE5B5ULL,
			0x7D20D7C1319613F1ULL
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
			0x7E686FEF310ADFB8ULL,
			0xF38724BD00E22DCFULL,
			0x8B78D8304AAF4CA9ULL,
			0x6063D082CF975F39ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xCD1BDB711BEE49F3ULL,
			0x48CC24ADC7F05E05ULL,
			0x8A777B4286FA22D8ULL,
			0x0B4D3389FABDB099ULL
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
			0x8C93221CDC0259B8ULL,
			0xB15C0CD2759C0686ULL,
			0x5DD3497C97C67902ULL,
			0x6492DCC39DB02A8DULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x7AE4D46E0E7DC630ULL,
			0x783CFBF286F3AB24ULL,
			0xFB9D79B4B220BCECULL,
			0x244DB3B241284404ULL
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
			0x59B35E4ACA346170ULL,
			0x53406CAFCFA5BAEDULL,
			0x6F8841888FC14ACBULL,
			0x4C783980938E8454ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x850DA210371DFAD9ULL,
			0x43D16DACE3F2D770ULL,
			0x1AB843A9D7F0AF9CULL,
			0x32958D8BAFF264F2ULL
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
			0x15024443BFE29788ULL,
			0xF81B46146A08AB9DULL,
			0x70186569C5C93624ULL,
			0x4C3C6E312B7F9C8AULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x8F15397314900390ULL,
			0xF633AD55C44FC2FAULL,
			0xE7B8F83C0DDF2414ULL,
			0x048B0E6059368C4BULL
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
			0x502138C694C4EE48ULL,
			0x084E801FF122C314ULL,
			0xCE3E5C8B41560D99ULL,
			0x72D0D222ECC312C6ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xA6B3D086737D8AD0ULL,
			0xDC13D3876D077D54ULL,
			0x608FD7EEE3EE64A4ULL,
			0x7253C5184801942FULL
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
			0x04BF6B9DD03E2DB0ULL,
			0x05C89AF380CA771BULL,
			0x3EE0CBBAAD6060CAULL,
			0x54FCC79929ABF00AULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x7A1828A644F72E31ULL,
			0x07F007D292DD743BULL,
			0xC3293C9B43AED576ULL,
			0x6BD55846320853C3ULL
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
			0x9BFBC77C45845528ULL,
			0x2B5B8EC7989C663DULL,
			0xB949419BAFFF9674ULL,
			0x6E6E1C28CDC3A24EULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x1539CC284ADA2401ULL,
			0x73826210EF9800FDULL,
			0x68B66CECBB5C4C6EULL,
			0x32A23B7E502DCF3FULL
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
			0x2A0D7C64F7DFB950ULL,
			0xD1D5B9FB62378007ULL,
			0x38D7638D2450CF46ULL,
			0x708C62E21784198DULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x624E79599ED806B4ULL,
			0x48EE99FC2E86A686ULL,
			0x5BCB24B18B8166AFULL,
			0x5CF17876768F31CAULL
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
			0x996244D863AA9970ULL,
			0x9EFABFEA5D04304DULL,
			0xFEAE42BC9A183ADBULL,
			0x69B077036359A2E0ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xD40E66EA2B079BA7ULL,
			0xF0512D4718A7C829ULL,
			0x788FB55520670040ULL,
			0x5E19DA0B79F9AA47ULL
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
			0x4832D1F13043F6E0ULL,
			0xE44A88920D8D1AC7ULL,
			0x029C82DAC962AAE7ULL,
			0x40F0E8FBAF58C677ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x3C33EEFA3578BF73ULL,
			0x9A26B1EA4E48B8BBULL,
			0x9E42F41D09E6A51AULL,
			0x5C4AD914A63EAAB2ULL
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
			0x7E08388F51ED7788ULL,
			0x08168A2989B7DC5FULL,
			0x38790D5B49F26E7DULL,
			0x4A212746D3055DCFULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x05947A9578D38D63ULL,
			0x456400CCC36E60E1ULL,
			0x0E5ECD60EE4FDA97ULL,
			0x7ABE85B95023ABE3ULL
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
			0xC59D98BDC3128C40ULL,
			0xA48D062C90A7C52DULL,
			0x9C7AF7450A8D3040ULL,
			0x6D456420DF002D71ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xA22F319D96E1A311ULL,
			0x0E1778C1E5DCFC29ULL,
			0xF8AE2CA37390739AULL,
			0x198AAE59DDFA09A8ULL
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
			0x5481ACDEBA873398ULL,
			0x37B49EEEC92F5893ULL,
			0x34906E424D2FE56AULL,
			0x576FF4B77AE77F2EULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x597C504A20A02CB0ULL,
			0xEA6DA0E4B1A8B0EAULL,
			0xA8DA9FAFC5178822ULL,
			0x1A9850FAABBABB03ULL
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
			0xBD059F24292B3C28ULL,
			0xB68D9B59765FD97EULL,
			0x608B9B8C744FF79CULL,
			0x5D18A971859125FFULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xB4358B0E7E5ABFA3ULL,
			0x2A1684CEE1BD053AULL,
			0xD6A0A8769AA29EFCULL,
			0x48DC2B3DEDA96E6AULL
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
			0xC1DBEEEA95228F98ULL,
			0x1EC13895AD315D83ULL,
			0xB9E5158EA34A9692ULL,
			0x59D39F85DA735A67ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xC6890754DCCCD0CFULL,
			0x122427FB6E42E185ULL,
			0xC9562868EA3D336BULL,
			0x4AD1C538C613AFE7ULL
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
			0x47CA93F10A97AD70ULL,
			0xCA334C75E97C7291ULL,
			0x3124046AA7E5B69CULL,
			0x5264D0E085C9210AULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x2A8926D8DEE79A9FULL,
			0x74A8CF66AAE1F5ECULL,
			0x72463B932AC42DCBULL,
			0x64C20BA216612531ULL
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
			0x06C6A6B322B7C108ULL,
			0xDEB77132FCD2AD46ULL,
			0xDFB283ED52A8621CULL,
			0x5DFDBB5D034F626AULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x5232A53499CE174CULL,
			0xF36C5469F91A2285ULL,
			0x4153F71BE3D35ACDULL,
			0x7A4D2252EF3A61B5ULL
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
			0xF8829A63CD4D1660ULL,
			0x39600C503E7F9BA9ULL,
			0x1CFF06C7B64EAC9AULL,
			0x5DD57921855B6625ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xA6064B5006315324ULL,
			0xC85B341AF32A8306ULL,
			0x86524E783151284FULL,
			0x190AED0E0E775FACULL
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
			0xD44C0813D2E371B0ULL,
			0xC7BF8984B8ACCF3DULL,
			0xA9160A14C33FFF64ULL,
			0x4FA7AC782C0B19E8ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x43A39F3C0A9CC67AULL,
			0xA4F7086E2F6FBC6AULL,
			0xFFD7ADF910864328ULL,
			0x4D926BE3CA6B3EE9ULL
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
			0xAD22CB908F29E690ULL,
			0x0E1044F6718B6AB5ULL,
			0xADD7A414728028ACULL,
			0x7FD614245F862FAEULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xC2497E97D2106573ULL,
			0x2A90B8CB7C6D4FBBULL,
			0x93D9CB45996DF716ULL,
			0x3E899144077D1C33ULL
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
			0x72DBD65B1F798FA8ULL,
			0xF09267B0E1DDFE19ULL,
			0x47608F415F89B3E2ULL,
			0x46A163B24343744BULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x9FA5C3B5191E3382ULL,
			0x7B604CA20C392872ULL,
			0x0287DF5BD6E92AD7ULL,
			0x49E1B7921F4B9605ULL
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
			0xD4646DEFE25D6BF0ULL,
			0x91EF79EC5C0BDDCCULL,
			0xA978929ED98D2BE1ULL,
			0x6B47BB5182A04C28ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x044F5B9B160F4043ULL,
			0x04F7F43FC0EFA34FULL,
			0xFA7E2650756F162BULL,
			0x49CD63E07FCE1F68ULL
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
			0xCBE6017E25D34AC0ULL,
			0x0B5870C5AFB7A8DEULL,
			0xF54054F281FC0777ULL,
			0x4337E0FA953DB5C8ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x809EB93B69873676ULL,
			0x51148D15CFDD3C5CULL,
			0x9127EA012F22AB5BULL,
			0x03641BF071CD62C3ULL
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
			0xBA5FB7CEADBC6A20ULL,
			0xA0C21469BBA864D6ULL,
			0x14C5A3C69E09AC67ULL,
			0x7E6C9F76E758ACDFULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x6DCCB57649433BBCULL,
			0x901FE9B8E9568E57ULL,
			0xA749970E6CDCD798ULL,
			0x3C7BDC7D3A34850CULL
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
			0xBDE98A45846A3348ULL,
			0x3095567C00EC1991ULL,
			0xD5EC24FF31E4336EULL,
			0x6C4F1B44F697A86BULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x1A8CD3ED9D6B3696ULL,
			0x90A060BA202F990BULL,
			0xE5A80137D8FF7100ULL,
			0x1865278F1521142BULL
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
			0x26BAC47AEB4B2A58ULL,
			0x2FA72770685F0BD5ULL,
			0xA5ADE6661761DCEEULL,
			0x5907A99C03CB6283ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x679CF83023B797F3ULL,
			0x9902BA589B57827AULL,
			0x85FF7418AD2FC0D1ULL,
			0x5F51C0728ED98511ULL
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
			0x6DA95463EAB7DC40ULL,
			0xF389BA6ABA5900AEULL,
			0xCA510C05CE1BA315ULL,
			0x407AA77AE5730B85ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x46F6207D60550A7AULL,
			0x2CAB84953EE2BFE3ULL,
			0x9AE60F659B50F4E7ULL,
			0x73F13A6EFF592434ULL
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
			0x8137A52F0C281358ULL,
			0x5ECC5F79EE0879DAULL,
			0x2812ECA23E8067E0ULL,
			0x72EA24E56232DCD7ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x81CF186CEAD8E2BBULL,
			0x921025DBDE62F92CULL,
			0xA430279F2E4D015FULL,
			0x0B4C8DDA2698EF47ULL
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
			0x1D51AC9509823C40ULL,
			0x3364DEE293F41902ULL,
			0xA07D2959EA902792ULL,
			0x4C79D96F4A4FE353ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x83940F751FF5033BULL,
			0x77B73C6AD1899E67ULL,
			0x9356936406A98A44ULL,
			0x1C7A9D6B47DC3ADDULL
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
			0x0F0EDBE1E04548B8ULL,
			0x7C4B3002D7344C56ULL,
			0x2389A2D895F3F17EULL,
			0x67F0F793B8D6431DULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xCA40465E7A32C710ULL,
			0x3DB0F7B8FFD5E3D8ULL,
			0x2803887B34E0EFBBULL,
			0x49176FC591003189ULL
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
			0xC738E3F03D577A90ULL,
			0x20782ACC171EC19DULL,
			0xB1FA73D3411F46FEULL,
			0x69EC99B4B199F49DULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xC3E98B1EF13C3A42ULL,
			0x6A1AF3CBBA230E26ULL,
			0x918D88A29FDF89DFULL,
			0x72DA27BF09447E19ULL
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
			0x7E9C0CC802BB7678ULL,
			0xC16D01F7709EB6F0ULL,
			0x7F4110C1B538D140ULL,
			0x69F4FDB884598332ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xFF4624A1002040BBULL,
			0x9124214DD623EF07ULL,
			0x3B2E04DD68D50287ULL,
			0x756EE141E485ED2AULL
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
			0x1A11332FCD84D7C0ULL,
			0x0B7FCAC0F065F064ULL,
			0x4921166367741D1CULL,
			0x749E56EBD11CD90BULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xFCB6A1B87FBC9880ULL,
			0xEC9FAFAD786E196BULL,
			0x23F01555357D7638ULL,
			0x73145E2E10D7C1F9ULL
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
			0x7583763EDDC6AB78ULL,
			0x37EB385FBE1EF832ULL,
			0x96DD2EE5D294CE48ULL,
			0x42CF2A3DA4FB9695ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x1FF416F3694BB485ULL,
			0xDAEBDBA3BC38BA01ULL,
			0xCCA0AAB6F91A112BULL,
			0x7D4F81F4CC32D5DFULL
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
			0x32C14AC65057A470ULL,
			0xB1B350F51712EB45ULL,
			0xE700B301E4A5EE9BULL,
			0x6585E7FEE847FC88ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x20386DA0523177AAULL,
			0xA6415F55A365636FULL,
			0x876BE362D9D495A6ULL,
			0x6645F2FF008E68F5ULL
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
			0x44148E592F354440ULL,
			0x6AE355D3E6C7DC8BULL,
			0x174DB4A99B80E526ULL,
			0x41C8AAF55687D3B6ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x20A0587981F77A89ULL,
			0xE6BE5C9AB17CC067ULL,
			0x64687F95B70D5819ULL,
			0x55D9FBF780A36943ULL
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
			0xE4B5B28B964DE000ULL,
			0xE08F82A47A7D1D53ULL,
			0xCB2ECF7A414BEE43ULL,
			0x575817710E0FB3B3ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x635E275A074D9027ULL,
			0xC1ED74448E749A94ULL,
			0x0A9313FEA38CA74BULL,
			0x4A622CFCE5E44FD0ULL
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
			0xE87034EF9CF78080ULL,
			0x0D35C15EB2FA027FULL,
			0xBEF7DE679E5EAF88ULL,
			0x52C10E02D9D8CABDULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x04E7C933091B2582ULL,
			0xCCEB19054B90FFD2ULL,
			0xF68DC76FF0E0E9A8ULL,
			0x68B9BCE1C981FF64ULL
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
			0x806CEA7318503FB0ULL,
			0x4FECF465018C7DB5ULL,
			0x1BAB70A1CA9B93BAULL,
			0x51777403B6E70676ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x16F0E2209CAA2AB1ULL,
			0x44AD84269B408F7DULL,
			0x3695C14B8EFD41C4ULL,
			0x1E9F5FE80DA2D395ULL
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
			0x4D3951E428715038ULL,
			0xF2A93BD11AEE16E7ULL,
			0x8C58D0158905DE62ULL,
			0x7E6FED6B00AD60CEULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x5E41154334E3BC75ULL,
			0xD28E75B8CE2EFB2EULL,
			0xF4D98804292713A6ULL,
			0x297D033420073093ULL
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
			0x0043866DB9E3D858ULL,
			0x4F1E1E7B88EC1E8AULL,
			0x5A412B3A395CB40EULL,
			0x73C6E41F9ED6D11BULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xC2D9D6E1494F617FULL,
			0x39F5293352476A0FULL,
			0xB97C7A77F100EDE6ULL,
			0x7880E61CB7B1A7E1ULL
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
			0x994A272642D1F4E0ULL,
			0x4AACCEEA319E2D05ULL,
			0x198CE798E0C4AC93ULL,
			0x68503B8ADE5BB7DBULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x2FC81E75D12AFC53ULL,
			0x962D1E404214065FULL,
			0x5D49D94F4748F3F1ULL,
			0x63ED9979D3469018ULL
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
			0x3F5385D3FCD74558ULL,
			0x9829A2B332C51393ULL,
			0x50A8477E8A749827ULL,
			0x5BD9F21E74B9FAE0ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xB52D91779AAC9C70ULL,
			0xA687905D74EBD057ULL,
			0x2160856EC1AEDB07ULL,
			0x6CBA14309D19AC68ULL
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
			0x0785075FC76811E8ULL,
			0x41D5D334470DAADAULL,
			0xD3A5386BD2698799ULL,
			0x5AA4D6E60D8601D6ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x11AB23ED7C474985ULL,
			0xCD1D408FD5675119ULL,
			0x70FD485CFB3D9739ULL,
			0x5306E7B5458DBDDFULL
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
			0x26D3C43ACE347AB0ULL,
			0xDB0B8089AA49B41FULL,
			0xD67550A88EBF9E4FULL,
			0x7755EE4A366B42C4ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x9788853734CF439DULL,
			0x66FE9606EF766615ULL,
			0x76EB0269D1DB722EULL,
			0x77E2027701729782ULL
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
			0x203FA1554637D558ULL,
			0xA03B5038F2999A59ULL,
			0xFC3F5E34F23F3020ULL,
			0x6B76B7D435BC20D2ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x1A811B44C74297C6ULL,
			0xA298C56D57711518ULL,
			0x1DE3EE95BB876734ULL,
			0x3444356C47DE1AA5ULL
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
			0x38041DE87198D078ULL,
			0x503CBEA8A0A1D374ULL,
			0xA0A0ADF2FC4D1718ULL,
			0x70901542286ED216ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xA38C47A416AC71C4ULL,
			0x35D2FA20ACF6DA2CULL,
			0x9D047C3335632FE8ULL,
			0x57B1E966DC9E2E40ULL
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
			0x498F08E74481A8B8ULL,
			0x0FF5EBD50A77CD3CULL,
			0x6A15C6365E107CF4ULL,
			0x68C491CB5A000E7DULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x71405F1DBEA3AE23ULL,
			0xC1A2DF2287D09A59ULL,
			0x3AB1CB28A8C86D93ULL,
			0x104A09296C8C5F4AULL
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
			0xFDF854873E571718ULL,
			0x29E143356533B90BULL,
			0xA775123C321D84FBULL,
			0x55CDEB2CCC76DD58ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xEF6C1C056D8552D3ULL,
			0x3C1EF71C8ED7E2E0ULL,
			0x43D8BFE7C8C388E2ULL,
			0x7AE54C090AEAA08EULL
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
			0xBEFC20A92A0D3828ULL,
			0x5A244601618A3587ULL,
			0xCDC54E9835F45609ULL,
			0x5D294D9242B450ADULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x13D7319C35C4137EULL,
			0x1975B93115A01CA4ULL,
			0xADB3FEDFD77832FDULL,
			0x3E501B5A58B08C1DULL
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
			0xAEE317A7FD294650ULL,
			0x6DF62112EFF5AC56ULL,
			0x470629365717FF9AULL,
			0x6D693A4474907B36ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x5C836EE15B6C6831ULL,
			0xAE4EED61AC690655ULL,
			0x278D55C1DE5DFBA2ULL,
			0x7B4228D8D5FFA3F2ULL
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
			0x546C35DD13EE39A0ULL,
			0xFB0CDF2D1E844394ULL,
			0x449F284A1538C6A4ULL,
			0x51B54895663E57C4ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xD620B31863FBE830ULL,
			0x3F2AA1E2CCF0E7B6ULL,
			0xE652C34EFF80AC4DULL,
			0x15BBFD7768E06227ULL
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
			0x4D3E83CBAF777E68ULL,
			0x74FA691D28BE2FFBULL,
			0x547E5358293994ECULL,
			0x41ACB791EEED7CF8ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x382D4696C3EA2B1EULL,
			0xE8F2656A6647888CULL,
			0x4E098A83D672A6CDULL,
			0x78E4BDC7B22784BFULL
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
			0xBDCEAD024B39B088ULL,
			0x8E3811DC8A295828ULL,
			0x6968908CAF6805C5ULL,
			0x4575CF67FEE2174BULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xAA73454279C9ABA6ULL,
			0x47286F67F1C86597ULL,
			0xF8B62FC4C31A370EULL,
			0x0E59479254423845ULL
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
			0xDBCE8D3A95522408ULL,
			0x9229D29B2065D8B0ULL,
			0x295A0DBEF8175C4BULL,
			0x59228E2DAB06F01DULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xE2CFCC1AFB0A4EB6ULL,
			0xC36D0FCB49B27012ULL,
			0xEC9BC3774527521BULL,
			0x572138434414B1C1ULL
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
			0x60EB2273E014FBF8ULL,
			0x81BC2BE1779E52CCULL,
			0x8CCACDED215A3322ULL,
			0x58F5EE7CDDACFDEFULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x61AAAA631865B0ACULL,
			0xC06BC4FA6254C1A4ULL,
			0xD8706F8EFF2F0C94ULL,
			0x42FBFB048940593BULL
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
			0x4B20B6D486B53108ULL,
			0x46D99867CB1464BBULL,
			0x6E7A9CF432C20EF4ULL,
			0x51EE4CFDC6EC9299ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x9B1C2FB381412C69ULL,
			0x9C019F9551BADFF9ULL,
			0xC2F8E1E2B09C3849ULL,
			0x58A2A9EB7F06FCF4ULL
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
			0x095F33112452C120ULL,
			0xFFE3383C9BC99BD9ULL,
			0x6330B6912EC1A436ULL,
			0x4552708588F423E3ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x82F8066749F894D6ULL,
			0xF28246BC3466D780ULL,
			0x0838BB7A80AF9FF5ULL,
			0x17274B331EFC101FULL
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
			0xF7A52CF4F5480568ULL,
			0xE0671194A12F65C4ULL,
			0xFA7DB4300F2A1D89ULL,
			0x5FC2485A56E43034ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x8229BFF3FA9F57A2ULL,
			0xF387B04291E8FF20ULL,
			0xC1F0FC49CC9EC340ULL,
			0x118E4189DDDB412BULL
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
			0x94BE8CD13A879DE0ULL,
			0x3ED3E181BF994A4BULL,
			0x2B3C531F27581207ULL,
			0x60FE9BFB5BAA52CCULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xE380E263F6373425ULL,
			0xA009C657D2FD1EE6ULL,
			0xAD9453276B3ABFE1ULL,
			0x30E648C88C65FFC5ULL
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
			0xE0656FD80DF41C88ULL,
			0x841B1A4FF401B1CFULL,
			0x4D629C3AEDB5805FULL,
			0x49B7AA669C6EA956ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x17F8540E90A614FBULL,
			0xD740A1FFBA2811E8ULL,
			0x88109D0E4410B952ULL,
			0x2992419BB1BE2D42ULL
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
			0x1010FB7C5819DA50ULL,
			0x22B5FE5B8FAC5B87ULL,
			0x5AA08031471F1E5CULL,
			0x42B4FFCA9788099EULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x1010D3F2616C87F9ULL,
			0x7374E5574594421DULL,
			0xC8D93A6086A54F24ULL,
			0x63039557B44CC8FCULL
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
			0xB4DFE83E7E3DD498ULL,
			0xAD8BE44B4EDDA4ABULL,
			0xAC141ADC66C7D155ULL,
			0x6E1F76AF288A1F4CULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xE4277B636D2408B4ULL,
			0x2B8F28E741FB3A36ULL,
			0xC9E1776419AA7CEFULL,
			0x22D37C026129B0B2ULL
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
			0x506887A05C703050ULL,
			0x2B23011DC7FCE338ULL,
			0x25321126C3EABE6CULL,
			0x4893FE46CD9747EEULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xFAE7F05844C46D57ULL,
			0xFB6AB42223508CFCULL,
			0xC648041708E4D618ULL,
			0x3C97EAE5B976A071ULL
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
			0x0E00729EF3D25C10ULL,
			0x9B1C5E19C4E18BECULL,
			0x2578E365617E9AE3ULL,
			0x70225AF0A2ACBC19ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xFFAC72D0714CFBD1ULL,
			0xA4B6F0B5047B09B1ULL,
			0x999CFB3A7A447654ULL,
			0x2B5E00EECE43C20DULL
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
			0x08027ACF22CEEF48ULL,
			0x672982754A360A79ULL,
			0x5707503603F4FCE6ULL,
			0x48F8FC56ADE0B77DULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x70BBB2DC7550FF9AULL,
			0x4C43414EF052A468ULL,
			0xD0B8C5635FF70130ULL,
			0x57BF10DA03A84B15ULL
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
			0xD067E6BD79B99F38ULL,
			0xF64AA1BECE1048D3ULL,
			0x7180CB61D045A422ULL,
			0x7D724C28BB4B5C4AULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xD9D6661AD56F84F2ULL,
			0xE0C6FE1DD26F1D5BULL,
			0x669CDAA5396DF83BULL,
			0x6F9CD0DD68C1ADE1ULL
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
			0x25B9A4DFFA868E18ULL,
			0xCDAA6A2C54FC5549ULL,
			0xCABBAC3DA55344EEULL,
			0x49C9ED5FCE80FF4CULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xD851BB8C75465802ULL,
			0xFD10AC05AAF1E1F4ULL,
			0x3A81481404A478ABULL,
			0x2A927ECEE6A45D2DULL
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
			0xD6BE10F7B53B9868ULL,
			0x953C3C6C78CA45CCULL,
			0xE32AEABF59BF96D0ULL,
			0x6A089C2B4AEA8BB8ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xE17474FC0C7A0FEBULL,
			0xBEE48151D81B17BEULL,
			0x08DF649CC83CC0C0ULL,
			0x3F99F180825BBC6DULL
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
			0x7805529446C7BE88ULL,
			0x03B7FBC2F9669AAFULL,
			0xF328D6964C475B6DULL,
			0x587DF7CF154F1D39ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x78F77CE75AC8BF42ULL,
			0x2F003C08EEA49B5AULL,
			0x8652711D4E3AB903ULL,
			0x11165B9EF689D48CULL
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
			0x97E642C8F3A92D30ULL,
			0xBD1122F83011CF36ULL,
			0x504F6EB6F94667B3ULL,
			0x571E27CF594A3FBFULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x37EEE180D99E2FCAULL,
			0xDE08A67ABEA27B47ULL,
			0xE077F52D779435A9ULL,
			0x58104A6E6A68216AULL
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
			0xA11588E0EF20CED8ULL,
			0x39777B563EE5C672ULL,
			0x9EA7B428B95D72B4ULL,
			0x60EB8FF38B31E26CULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xE1AC6D947545FB6DULL,
			0x6F496B48D0D12442ULL,
			0x87CF50755E54D410ULL,
			0x5B3195C7DFCBA8D3ULL
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
			0x2B3170B7108F3348ULL,
			0x3AE02E942FF79EF7ULL,
			0xDA710468EE33812EULL,
			0x4C7C66296241941FULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x2CAD4ACE925F0155ULL,
			0x9F5A3DCC44798148ULL,
			0x1BB45E8FAD890C18ULL,
			0x0A9E24483405F5FBULL
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
			0x6AC4356E7FFA65E0ULL,
			0xD04C5287C11299A4ULL,
			0xE35E52495F441DFAULL,
			0x4E14A95BD8C5E609ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x206C06F81AD57A27ULL,
			0x3D9AA523E41D5ADDULL,
			0xA44E60F004CF4E60ULL,
			0x1F393C1AEC699894ULL
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
			0x09FE27F93D0964E0ULL,
			0x31A4C15DED756D65ULL,
			0x74140A42DCFE3EEFULL,
			0x7219FDC465C907CEULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x272D44C15CFDBFFEULL,
			0x9648826F8B765720ULL,
			0x4C7F834F5BD65FF9ULL,
			0x1ACC20BF7482E626ULL
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
			0xDD649A3B6CDE6CE0ULL,
			0xAB2A97958BD6B8A9ULL,
			0x75E5798A7DCB0AC1ULL,
			0x4C2B0B168A3612C6ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x26F0265D50052C9EULL,
			0x8993DB05AE298D15ULL,
			0x2F5907492D8B4C64ULL,
			0x56BBB95D4BC1E180ULL
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
			0x0C0F9CE72E8B4320ULL,
			0x4E438C7240464C73ULL,
			0xC94F4E2935DCD816ULL,
			0x61B4661BC12A32BEULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xD465CA89AA33D174ULL,
			0xB763EA2DBD6F94B3ULL,
			0xE531DA8E30D09642ULL,
			0x5891C200588A9DECULL
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
			0x5C7CA9829F694F28ULL,
			0x3F3ACBC4C9E0BDD9ULL,
			0xD1AE183ECD1D3819ULL,
			0x7A2A85CA9E0AE1B7ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x70D4B69F38B4EE8BULL,
			0xF114A699817DFB71ULL,
			0xDE5A774583F2009EULL,
			0x716B50DBA935C3FCULL
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
			0xA32223F3B6FC5528ULL,
			0xB63B2E59D7F20343ULL,
			0x8F993723078BAC43ULL,
			0x4F3727C7359E228CULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xFACCA12248D871A4ULL,
			0x7269DACAA2ED4BAFULL,
			0x0874C64657EB1F9BULL,
			0x77CEED7D2CECF832ULL
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
			0xCAE3D453E4CBCD58ULL,
			0xC6FB3E5B4471E449ULL,
			0x51E9DBB67C1F90C5ULL,
			0x64987B7B4594C3B8ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x4A0F93C791B33E5CULL,
			0xD28B6EAD43692EE8ULL,
			0x2CA8A1687F5AAC57ULL,
			0x3BFE1448A3E3620AULL
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
			0xDF582956850A60F0ULL,
			0xBE46773000CDA87DULL,
			0xBEB457E25E3767F5ULL,
			0x5BE82C6B282E8BAEULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x75E2492E93B12F73ULL,
			0x625A305D8817890EULL,
			0x7DEAAC1F4477955DULL,
			0x6CC644B960E539DAULL
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
			0x0A0BADC710A8D760ULL,
			0xAF0F8AE418E8CC00ULL,
			0x8423A5C07389DBE4ULL,
			0x4C3424AE2BEE9EFFULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x095DED059334FDECULL,
			0x1B0A9ECF00B80868ULL,
			0x8E2961E4DA01740FULL,
			0x378D53FD9BCEA31AULL
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
			0x8C53F40011032970ULL,
			0xA0DD83C0AD64702CULL,
			0x8D6CCFC07CD50737ULL,
			0x5F31C057CA914337ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xD52EB977BA975B41ULL,
			0x2C9BA2649E3409BEULL,
			0x0573343F1EFE85A3ULL,
			0x62EC2F96D62AB2F4ULL
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
			0xCCE3AA30E1E3A648ULL,
			0x3F5D582FBECC9A56ULL,
			0x4A666DCBC574BCDCULL,
			0x6107E4183C83447DULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xCB9C674C7438F7D3ULL,
			0x873D13DBE0054BF7ULL,
			0xF10CDD0AAB994A5AULL,
			0x55D162F84FDED9E7ULL
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
			0xC5BEDF66BFF75160ULL,
			0x3C888185DDEC2972ULL,
			0x608F1E0BA5BE6AD7ULL,
			0x48F4FBAA6C9508A4ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x2650C19C4B87CB79ULL,
			0xA13978B183FE843DULL,
			0x7D2C31FD9B925466ULL,
			0x551DB7CAE0D1ED6CULL
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
			0xE02D77ECFC051AD8ULL,
			0x46917B70A6C01338ULL,
			0xE39F47B3D2050A52ULL,
			0x50565B95BD00D2EDULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x5CD2FE70D00B3A18ULL,
			0x28F30F771D9D9573ULL,
			0xDB38515177CC1C8AULL,
			0x6D5B83BEB8E028F9ULL
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
			0x8A7771C5B32193D0ULL,
			0x365B0EC251881C99ULL,
			0x89E4BF6DF63577DBULL,
			0x7E521567CCF44DC7ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xD8CDC26E01E84651ULL,
			0x87B5ADFE9CDFAD52ULL,
			0xE5F0F5E0C585F222ULL,
			0x0A830E0C9FF5B1FBULL
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
			0xE611F9DBB3F19AE8ULL,
			0x18F1D4E441774737ULL,
			0x952F7E766552199DULL,
			0x78C2D89889F8A1E8ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x242FFA8405C574A2ULL,
			0x32357A63B871FE27ULL,
			0x3536B6FAA0BD1ECCULL,
			0x7FBF3DC07C5D96C1ULL
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
			0xFB105C3205BEFF30ULL,
			0xDC10E3FAD9C92DE9ULL,
			0x1E47AB100240A7B3ULL,
			0x57E6C00AA0E53D5EULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x6CF44D58200D9EABULL,
			0xF46297E6AB7C65BFULL,
			0xF9A4ABC85EF8F09BULL,
			0x4D45BB000815DAA2ULL
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
			0xA98C15AC5EF238B0ULL,
			0x8A376F6BF0AA4266ULL,
			0xCD959F5895C986E7ULL,
			0x7DCBE337628EE0E4ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x568749B281E5D1F7ULL,
			0x2608854CB9FEF198ULL,
			0xD33FD818A0EEC764ULL,
			0x4AC784A135524F85ULL
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
			0x76B9B0BE86BF1648ULL,
			0xF995F36E8081034FULL,
			0x72CC8BED18CEAB09ULL,
			0x74DB77E0F61A9650ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x8A8BF6912860B748ULL,
			0x8505336849ABC41CULL,
			0x36C64F5BF5EB6127ULL,
			0x3D92E9FA5A9D34BBULL
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
			0x31A2367BCD3036A8ULL,
			0x7984CDAD1B9A697AULL,
			0x125850DCEB6BD47EULL,
			0x602B137E66D078BAULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x5A3DFF1116B4BAA5ULL,
			0xEC997128CA6930AFULL,
			0x4C3660EF1E9387F3ULL,
			0x05793617B6094925ULL
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
			0x9C7EF9336DC71C18ULL,
			0x37D52237847FCEE6ULL,
			0x7D260F20F0958D00ULL,
			0x6C64CFC51673F5FAULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x112E97FC19546301ULL,
			0xAF6BACE562153303ULL,
			0x76E36A736249C85EULL,
			0x1904DE1EBBE932FEULL
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
			0xB3E678E5546D9EE0ULL,
			0x379089A5291A3ACBULL,
			0xA9417BD156C241AEULL,
			0x4AAAA7682437C4CEULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xA0AB43BBF6B4451EULL,
			0x643C52599077B101ULL,
			0xC185D52761D16E47ULL,
			0x6A5F18405CEED006ULL
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
			0xF7F22109131B8778ULL,
			0x661F5B42255651B2ULL,
			0x2B9419E78F995E4BULL,
			0x7371963C08DE508AULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xB058F8734D4B8384ULL,
			0xACD993B0B53A79EDULL,
			0xA59BE5AD1B8C7F78ULL,
			0x367B91D84DB70B64ULL
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
			0x0B0E6289B3AE4C40ULL,
			0xD311A4BD8A5DB5AEULL,
			0x3C9D9028C5726011ULL,
			0x572D7FBCC757C2B9ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x4490122D26D63392ULL,
			0x60D1D9014ED58D36ULL,
			0x1B1B88F4985A809CULL,
			0x3653EA9AB60F7E27ULL
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
			0x2FA3F20F1897C630ULL,
			0x8BE9ED82EDEC10A3ULL,
			0x0FA83CA8FF3EEBB6ULL,
			0x5DD1C5EDFCFE78DDULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x9DF327A79012C833ULL,
			0x113F181549EBFCFAULL,
			0x8D5746C868F46D13ULL,
			0x5297B63CA372933EULL
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
			0xF0D20B9D8CA86078ULL,
			0xB48E991DD154FDC5ULL,
			0x157E8C4EAECB0D9EULL,
			0x5895A6E074FABFB9ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x30B54DCD029EC968ULL,
			0xB80DC5D436F903C3ULL,
			0xBFA2AFE8C586F00AULL,
			0x67C7551A9A3AC27EULL
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
			0x934F134716D613D8ULL,
			0x9645E648C59BA87CULL,
			0x30D3ACC2B4500129ULL,
			0x5DE74A622115B074ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x9F63070389D65D70ULL,
			0x7D0DFBDBD5626EA0ULL,
			0x613FE048A70BC9F0ULL,
			0x549B8FCFA411805CULL
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
			0x3D8CF2695E85A9B0ULL,
			0x739407B02916F346ULL,
			0x3297D32E0E2C1A07ULL,
			0x5B59A66E0B4CDF18ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xF89930752ACA08B5ULL,
			0x75AF92DA8557A293ULL,
			0x6600CD608502D245ULL,
			0x10092958BBF509CFULL
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
			0x4789A952AE2A3540ULL,
			0x50E6A59D6B03A0C0ULL,
			0xF42861839464D67AULL,
			0x42BDFA2818012EBEULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xDD7C9E373E0C9DFBULL,
			0x49A11CAE5AF3E571ULL,
			0x75FC2E282E9748F0ULL,
			0x1DC03CC536366AE1ULL
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
			0xD31D451F46774EC8ULL,
			0xF36A0F3C7214A696ULL,
			0x8786A2C5DF7403F0ULL,
			0x7D2ACD8137E4FF12ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x09B177391118552FULL,
			0x8D75A81B83A1F1F5ULL,
			0x38E521CDC20A7270ULL,
			0x013614C4325C88DAULL
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
			0x01566171C6DFE470ULL,
			0xE73BFD6A8F582064ULL,
			0x16703D8AC2397CCAULL,
			0x6CE2ABAE565E7D48ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x2954896557ACDA87ULL,
			0x9D725979B15564BAULL,
			0x47F65EFC65B20F21ULL,
			0x0DE3B4D6D5E7163BULL
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
			0xB816C8D80AC60618ULL,
			0x4019C6C844FBB739ULL,
			0x88B73509FC911480ULL,
			0x70CF173CA2B9D216ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xB9E4CAD69BBF0A29ULL,
			0xD914E3E0E9D7E229ULL,
			0x3B1FC204A5A42B04ULL,
			0x77EC48C5C839E1B6ULL
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
			0x89148912B53B8E78ULL,
			0x5F4A93DEDC600909ULL,
			0x0DC4077620090CEEULL,
			0x7DC4D63866405189ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x319D929EED6FE228ULL,
			0xD3A46404FFE275B9ULL,
			0x63E171314835298FULL,
			0x0DA844F83AF13D54ULL
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
			0x6F3A2C16A634CFC0ULL,
			0xEFA4A2716B27B513ULL,
			0xDD8A3B673C233E0FULL,
			0x7AC1D7B7000F20AFULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x3CEBC89DC03DE480ULL,
			0x85A5986575AE90C7ULL,
			0x7D3BA7B89F908F54ULL,
			0x4BBC1D7693053DF8ULL
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
			0x709F992DFE0C9670ULL,
			0xDA64D858A1F4F6E0ULL,
			0xC7558F8AB2C223E1ULL,
			0x510EFCBF0FB6140BULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x8E95D10C1C15E6A5ULL,
			0x86093B1713A3EF4CULL,
			0xFA22C4908C91B015ULL,
			0x656915199196584BULL
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
			0x49ED90D4607BBD00ULL,
			0x165DCE34CC94E4A7ULL,
			0x33888723EFD6D1CAULL,
			0x555571F489F7B626ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x94532DB9843B1326ULL,
			0xB1C92819EB3EAB16ULL,
			0x39332218EAF8F3B0ULL,
			0x773C4EE026B07C3AULL
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
			0xD6EF91CB6700B290ULL,
			0xA539CFE5F0D05B80ULL,
			0xEAC0B70A751E6551ULL,
			0x5DD7D9279266A956ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x8F263A55CBD14208ULL,
			0xFE10A004549BFC5DULL,
			0x1181D0577F8552ACULL,
			0x110035EB047D0C1DULL
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
			0xFA312ACB513CC938ULL,
			0xE8D043B5916FFF1CULL,
			0x7C72D87DF82AA7CEULL,
			0x5A12BA1172734250ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x38DEDCBE50E54634ULL,
			0xDA4300C84EB609E5ULL,
			0x0D41C21114379341ULL,
			0x0F790E82AC06F461ULL
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
			0xE06CA228B4437BC8ULL,
			0xD106DE19B2F32F99ULL,
			0x4C4EBA89D50C9DCBULL,
			0x459C4761FD31D05DULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x974F3E283B7BD2DBULL,
			0xB396F25380837D38ULL,
			0xACF269B7DFD8FD48ULL,
			0x745EAC3C51CE4BB0ULL
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
			0xB4037A097BE5C700ULL,
			0x372D228554FAE47EULL,
			0x8673036C7FCB57D3ULL,
			0x4269896029563423ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x2177BB937698E039ULL,
			0x22C1FDF7B9B56EE4ULL,
			0x0BCC6F3EA3F913E7ULL,
			0x7867BEBBA281A836ULL
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
			0x0007E91521C41CD0ULL,
			0x907E08918BFFB1E3ULL,
			0x01C42C3DD1AB5A0AULL,
			0x6D805B17B9828F01ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xBE1D6FEE0B741147ULL,
			0xFE4525B32B393829ULL,
			0xB938AE3E4DCCF60CULL,
			0x31BD513548E686FEULL
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
			0x49956AB09535EC80ULL,
			0x631BF8352DD0E8DFULL,
			0x20F12136E17026CFULL,
			0x52A978BAE7361F9AULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xF703E0A6C74F7650ULL,
			0x5FE73EF43FB94802ULL,
			0xC965DC87C05B538BULL,
			0x5518C15184D12B0BULL
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
			0xEE0736CA639ECBE0ULL,
			0x62B5A9B1C64D67D9ULL,
			0x5F2BCB29F9E18AF1ULL,
			0x6A151A87CD09F5CCULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xCC4F94DF27CBE9BCULL,
			0xE265C3DBE0BF05CDULL,
			0x740BA107C9B180D6ULL,
			0x1CDC6FDF54453E81ULL
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
			0x522B6D5030BA8A80ULL,
			0x93BE2678953B3F3DULL,
			0xB9C917BDC9A67E5BULL,
			0x401965DC0870A454ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xAAD5BBAFB56CF849ULL,
			0xD3873DAD48F0E480ULL,
			0x9C2BEE4D9F525F64ULL,
			0x7368B7E4C3001374ULL
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
			0xAB51E229DC231100ULL,
			0x8D564884A371E83BULL,
			0x2759D66AD99A0A3CULL,
			0x6DADDCD02EE9A7A2ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xD06DECE659951C33ULL,
			0x727909F1953DD482ULL,
			0x97F9C8ABA98B2015ULL,
			0x51DA9C177EA0CD6FULL
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
			0x8D88FE628724D1D0ULL,
			0xC61AC858BB79C119ULL,
			0x35C5DA0FC3C0167EULL,
			0x7B16AA0BE884A2BFULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x8F6CA3362937C7D6ULL,
			0x24AF9F4E07F86D0AULL,
			0xA4B5CB346023E341ULL,
			0x2ECE9A069903F1E0ULL
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
			0xEEDED1E810015640ULL,
			0x33B0872F6DF39CE7ULL,
			0xD72B4472CD7CBD53ULL,
			0x454DAF89AF22767DULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x753256C0070721E2ULL,
			0x5ECFC1203626D1DCULL,
			0x83BD155ED68A5037ULL,
			0x6B843B86965D5306ULL
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
			0x4B1DF120FA732130ULL,
			0x7C0A7831C9AF26DDULL,
			0xAB0EB4395B3800E0ULL,
			0x54936FB6CCD98DB5ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x2F09D530B34C50B2ULL,
			0x8D0E5C264C1D698DULL,
			0x49ADE00CE6782721ULL,
			0x33D7D2A970348688ULL
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
			0x4FF8B5E162957D60ULL,
			0x1934A5B4FB3BEBA6ULL,
			0x27F5B12A0E3FA109ULL,
			0x77F3740B0B39E778ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x0FE9BDA6E8EE8F05ULL,
			0xEDF7D3659F53E1BEULL,
			0xB643B25D60DB3F3EULL,
			0x06CFBE73C5785B49ULL
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
			0xDAC37F1A100E6FF8ULL,
			0xC52103F365AE5C57ULL,
			0x7E34239B8A46D04CULL,
			0x7A59F75DDA3C3E60ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x54BA99A45F367180ULL,
			0x75C1061B54FD9423ULL,
			0xFD7B1D04214FC938ULL,
			0x232243A5E201B677ULL
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
			0xB5182E83747C1E90ULL,
			0xA2DE0DF89C489C7CULL,
			0x12BCAE6771C5DF5EULL,
			0x675692D1F97F1DDCULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x24DCE0361291E82EULL,
			0x2CD9E866C9F1331FULL,
			0x34F1805267BDF702ULL,
			0x4D1ED04DB0311C49ULL
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
			0xE6DFA5B524F24F58ULL,
			0x21C532068024DE3BULL,
			0x15331CA23142650EULL,
			0x69D009F483875B15ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x9ACEB3F533F7FEDFULL,
			0x2FC5CED28F8BC3BBULL,
			0x14E57E2CA3FAE1A3ULL,
			0x59A70188D9F9575DULL
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
			0x9DA7A9E25CBFD990ULL,
			0x837C8140DDEFE4D6ULL,
			0x42E7A36E7E38054DULL,
			0x6520557CC47D7E1DULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x62315B259AB84773ULL,
			0x3B1091A44F0DB360ULL,
			0x37A56F68DE1A44B3ULL,
			0x2355AB19EFE05D58ULL
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
			0x4F57FBA73BDC9DF0ULL,
			0xEC21C4A991191ACBULL,
			0x5CE41ADE3D190F3FULL,
			0x764BB6B83D2D4F41ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x98ED1B79C97A066DULL,
			0x5A5340A1C4E2DEE1ULL,
			0x286ABC5D28C967ACULL,
			0x1D526BE8A3822054ULL
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
			0xBC05B92C5DBCF7C0ULL,
			0xFA602485DEF9A7D4ULL,
			0x9D9C2D5664DFEB13ULL,
			0x41B859CD2F5BCFA9ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x2DF363316D3A86D9ULL,
			0x24DE14861B709A8FULL,
			0xB28091D7A981D376ULL,
			0x5E927ACA7A06C981ULL
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
			0x1AEC2471DFEAD500ULL,
			0xEE60F535C84A9204ULL,
			0xDD54EE56AE54302BULL,
			0x4AF7F27E1F2E95F2ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xF9A48F541860951CULL,
			0xEA2C8CA6202F0E3AULL,
			0xA030500ABF516DFAULL,
			0x7F054F88BA2A18C6ULL
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
			0xA661A20F83AE91E0ULL,
			0x5246CAB506EE60BDULL,
			0x8B17AF4C4C727F5EULL,
			0x6E1C834A0388B900ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x2377D3C144D3CD49ULL,
			0x983C5D82245010FBULL,
			0x1C32FD98C6C8BE7AULL,
			0x782236F18119F52CULL
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
			0x3CD1FD991D677A30ULL,
			0xDB34A5A065E50FC0ULL,
			0x9EC18A4692C1B09EULL,
			0x41ED06851896B7BFULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xA615BC506712524FULL,
			0x7431FE9818362FF4ULL,
			0x054A91720C44237CULL,
			0x27323BD85A797DBAULL
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
			0x28994A6E0E1F3CA8ULL,
			0x451123540D97D37FULL,
			0x936EF408E0A84BEDULL,
			0x5B0B6FADCB2E0C5BULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x200DD6DEC3188A5AULL,
			0xFB9797B9B19B855EULL,
			0x4C5FA98926E6726CULL,
			0x524905FAFA6C5B13ULL
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
			0x9828DB04972360A0ULL,
			0x7BBAFDC5EDBA9651ULL,
			0x3A6CA025FF6A7CA5ULL,
			0x732B968B83DD1DA4ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x48491DDDFC55B315ULL,
			0x33B6C3D86873DAD1ULL,
			0x668E8919881DDD06ULL,
			0x182BBB1D7051CEE3ULL
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
			0x1C04C8E4C0D22AB0ULL,
			0x99E925EA9D602656ULL,
			0x00646666F009ECA1ULL,
			0x4290FCFD3268EDE4ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x19DE8552C3D995D9ULL,
			0xD701ED7AD367EB46ULL,
			0x39BCEB3D3FA3C322ULL,
			0x55D8A920C53C1C8CULL
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
			0xA84D2D5F17B479C0ULL,
			0x831686348A618F96ULL,
			0xC7F2DA64F9806B17ULL,
			0x509650BA7B6B9E6BULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x132F96EC4AE95C1DULL,
			0xCFD53FE6AD7EF411ULL,
			0x83C72D0FEE9CB82DULL,
			0x6479F9503AC6E2CBULL
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
			0xBBD038E7733747C0ULL,
			0xC17B5CC0B4A37487ULL,
			0xC17D229A40DD5B41ULL,
			0x61545E1E3AEF30F0ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x60BAC819702A4C1BULL,
			0x1D5E4F07B296D42AULL,
			0x8D907CEB47E68561ULL,
			0x67037E1DA42D1FD1ULL
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
			0x86B755574CA4B118ULL,
			0x64DFDF20C2460A8FULL,
			0x2693AB49BA4ACE53ULL,
			0x4D34D9EF56DF77F5ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x98704126EA3C0AF1ULL,
			0x31D40E962E105F75ULL,
			0x8F612AD7FD79199BULL,
			0x5CD9F0AD78E8C2A1ULL
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
			0x800C861696D896F0ULL,
			0xED4FAFE1C8C5A316ULL,
			0x8914C33EEA9A5241ULL,
			0x7D3B0A72AEAD471CULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x11A861E5F5B80878ULL,
			0x70BFDFF48706032FULL,
			0x02C28048EF339F32ULL,
			0x52B7F194DEC39A3DULL
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
			0x249B7F7FD3489010ULL,
			0xE9B6BEB4B186FD20ULL,
			0xE86BCACE41815CCFULL,
			0x50B7EFD2B33E65ACULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x7A3B8DE2CB377BB0ULL,
			0x00C0142C49E26AE6ULL,
			0xE82CCDA995329B32ULL,
			0x474225A40C33CC39ULL
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
			0xAEA7778B09E7EBF0ULL,
			0x12601615BC8D7E52ULL,
			0x9DE88770FD37BA4FULL,
			0x6067537A142F0B96ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x5ED959E4FF9CA216ULL,
			0xE8927B539A286129ULL,
			0x6EC8C882F0574822ULL,
			0x2DC511F1A33B12EBULL
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
			0x536B0BB408E75D50ULL,
			0x1313CB7D2D1C4EF3ULL,
			0x67A636DE8C5F3B12ULL,
			0x4A3C3EEECA140BB8ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x4A44C1BEC14B2ACCULL,
			0x0599E45E6C9650BAULL,
			0xFCB91E1C69FF5C35ULL,
			0x67773157DADFC891ULL
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
			0x4A826711FAB49E98ULL,
			0x72B30037600E0E2DULL,
			0x7473DD376621BC30ULL,
			0x4ECB0EB78A7C3DCCULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xABF520E45CE7D5E0ULL,
			0x45653EB8C6E83ED1ULL,
			0x544772422DF3E341ULL,
			0x32FE3B779EC6A667ULL
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
			0x39B202E74CA41A38ULL,
			0x0B807CADB9295BDEULL,
			0x41E349566D51A27DULL,
			0x4E7135FEE23FF384ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x7676CD5624FF4698ULL,
			0x3C985B306604ECE0ULL,
			0x82369044C12CA16DULL,
			0x40AF687846521D0FULL
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
			0xBEC634C55EAC43A8ULL,
			0x11BCBB36D84073EFULL,
			0x38D0EBEE0C4282CFULL,
			0x5E4AAC66ED9F404EULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x7C90D4C3F6E9A9CEULL,
			0x3BD8C89E6617D27AULL,
			0x16BA459438AB41CAULL,
			0x68D777BA8DFCBD3CULL
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
			0x76A5EA5DA7460DD8ULL,
			0xC2B13985D3516180ULL,
			0x6A67BAE1505592F4ULL,
			0x639804F651F871DDULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x803B64DE702F7601ULL,
			0x6121557C8379EDCAULL,
			0x4CB3046B8C0FB729ULL,
			0x4DE08A4C4F07786BULL
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
			0x5E37F9AE847BD880ULL,
			0xE77DFB0FAD9F39ABULL,
			0xE17065F7DF2621BDULL,
			0x7E5C76D305E5C35BULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x5C461AAB358ABC7BULL,
			0x3938A040E48E9712ULL,
			0x93610709CA1546C2ULL,
			0x22EAD93BC4377776ULL
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
			0x715D58BD70148C68ULL,
			0x17F4FAF408345DDCULL,
			0x123AB43F8584E2A1ULL,
			0x77F4A8E15C42B551ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xFAEC959ED10C7CA9ULL,
			0x105BF6F1B4090487ULL,
			0x0E104403CDE72199ULL,
			0x4CDF56E8930B517FULL
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
			0x1299190EFA1EAF50ULL,
			0x6A1B855AD3D2D46BULL,
			0x396485C3B9714530ULL,
			0x57B9107E7DB4C7BAULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xA0C6B15A492E260EULL,
			0xDD78270730168248ULL,
			0xD8A1AF4303EAE887ULL,
			0x4B418D1FE33DC370ULL
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
			0x164C37DD13810318ULL,
			0xD1C792E23D7505D0ULL,
			0x18C28633D829608AULL,
			0x5DC0EDF24F38E815ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xFD70C7AECE884B72ULL,
			0x1C6EE966B29DE28EULL,
			0x4A953ADF859B32A0ULL,
			0x6BE08F334F0689B2ULL
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
			0xA0A53BB34979D378ULL,
			0x184BE2EAFE2C9EC7ULL,
			0xF73DA5117D6C0D56ULL,
			0x459ABC6A7633B771ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x09FD9301779DBF39ULL,
			0xCEFCA97BDCADE874ULL,
			0xD86B4A9459EFD6A9ULL,
			0x022AA40E783F52C4ULL
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
			0xE9116BD7AC7E4AD8ULL,
			0x92D2F9FA0180A3D2ULL,
			0x5CA94F0FE218F8ACULL,
			0x5E06C3E10C436746ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x53D312A6E0E3203EULL,
			0xEC394A9891BF002BULL,
			0x38038A8C375A8211ULL,
			0x48530979F44B5D82ULL
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
			0x81B077CFFDE28290ULL,
			0x5AB7E0F3C6B71439ULL,
			0x6D2B67A3DE1D9038ULL,
			0x7A2000A07D228055ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x506F5D0C23E06307ULL,
			0x9C48C5B3213899F7ULL,
			0xEF1A5762862ABB83ULL,
			0x7CEB13D0A2B699F3ULL
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
			0x6A6415EA84B1C9C8ULL,
			0x269DB75D165D98D9ULL,
			0x50EDDB5CB4007484ULL,
			0x46A594A41B90447CULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x3A9D499F2B9FD46AULL,
			0x2DECA309039C3DCCULL,
			0xC807907C8D2EF38FULL,
			0x087F5371B0458B43ULL
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
			0xC9B63BCCBE3D4520ULL,
			0x24E16222BBA2C3BBULL,
			0x55ABB1D0726B3D3BULL,
			0x457DB07F4C0012BEULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xBCFEF82314AAA0E3ULL,
			0x564036F2AEB9A26DULL,
			0x4846A694E206B48FULL,
			0x387EFEB1AF74E0ECULL
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
			0x5C3900229E379A68ULL,
			0x9B42A680964262CBULL,
			0x684DD9321A469513ULL,
			0x577865EC502CBFEDULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xBD03380F277DC84EULL,
			0xC1B8E6B00EE76474ULL,
			0x338F3B39DC30216FULL,
			0x0BCA92EC570BAEEEULL
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
			0x15D473CEE0788308ULL,
			0xA872D841022FC999ULL,
			0x1A467FC8997412CDULL,
			0x7C5565094072F5F3ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x9E2C6FD8132E2A35ULL,
			0xF456603FAE782B10ULL,
			0x0093064E3F14AF6AULL,
			0x7CC8EFCB3EB83EAFULL
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
			0xA8A1E1C7FCA56F10ULL,
			0xEABCDD3489DD0951ULL,
			0x2F7D30DAF6AC3C0BULL,
			0x6B5C29E004400754ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x2CB48F94BEF52F21ULL,
			0x2674D57AA3608489ULL,
			0x9563E946A554BEFAULL,
			0x4BBF145D04DE42EEULL
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
			0xC1A56186AC1B9B58ULL,
			0xC376CA09690F0EABULL,
			0xD354CFAF3D841FD4ULL,
			0x7DF7A1CAD11568E4ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x8AD462E28EBFC929ULL,
			0x8E4D512F6C281260ULL,
			0x9AC0F9A1E3C1567DULL,
			0x5E78E7F0247FACCAULL
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
			0x419D266FC32183B8ULL,
			0x19BACC65A4CA4F4DULL,
			0xCB32585BD4B9842CULL,
			0x72B9C59BCEEA61F0ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x6CC4F3D4B57FA95DULL,
			0x9B8DD2FFC0F485DEULL,
			0xDC52DFB4DBD2790EULL,
			0x05FED429BCF6D79EULL
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
			0x8F9357D94AC04548ULL,
			0x779886F50A7C2071ULL,
			0x2C01D2882488448DULL,
			0x6F0A952BC1CB136AULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x86AD4EEF2DA27748ULL,
			0xFC5C707FDC1B0D3CULL,
			0x9B2B264EB17A3A22ULL,
			0x3D233D8A849CBE4CULL
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
			0xC5246644F5D04B40ULL,
			0x189EE14A1FE2128DULL,
			0x577B26AA3936D46EULL,
			0x5E7D9E38ACC88B08ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x6D363BE129D9A862ULL,
			0xC1E39B31049FA690ULL,
			0x2E891BCF6545C9FFULL,
			0x1944236E5AB7AAC7ULL
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
			0x81F7989D6267CDE0ULL,
			0xA8F2BC3D050A2338ULL,
			0x5054E912C7E48C91ULL,
			0x6DD1FDC6DF2D8B56ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x2FCBB255A5B0F97FULL,
			0xEE9A57C896D3C10AULL,
			0xE4B309FD8F49DB44ULL,
			0x57B013CCD83EB651ULL
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
			0x30983BA394B7CFD0ULL,
			0xD1044EEBA51232E1ULL,
			0xEEA746492DA0670DULL,
			0x450B1BB3E6335511ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xD9013010EA81294EULL,
			0x51A5144CBAF51EA2ULL,
			0x5FC73D2BB9712F00ULL,
			0x2E0F18BA0A1AFE0DULL
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
			0x3E107538FE878378ULL,
			0x39DBCDE8E10EE706ULL,
			0xB5C1BD5FCB1FAFC0ULL,
			0x48FBBFE45B564B40ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xE2D4CC983D38FEEFULL,
			0x5D5D1465AC6FE4DFULL,
			0xBAA0EFABD419BA39ULL,
			0x581A264E75B2D390ULL
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
			0x5D22C10E638F2158ULL,
			0x8B5FDE02853BC76FULL,
			0x0A42DA517F7854C7ULL,
			0x4FED49F4E4C965ACULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x2DA79C486BD90AC5ULL,
			0x9B95C432E3A8A4B9ULL,
			0x38EF9CFE34245B00ULL,
			0x5F1DBDA7CB958B5AULL
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
			0x9AE2890EF1A3B660ULL,
			0x0902D4E4D403CE41ULL,
			0xC34E7740B0D181ABULL,
			0x6B5EBD78DF80BAEBULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x62DD386AD6422CEAULL,
			0x631E9E8C136C3FEDULL,
			0x335629F3FD06EF6AULL,
			0x685165AB4A0A656FULL
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
			0x58595CDD1BE6E720ULL,
			0x96D6441D2847C241ULL,
			0x152FF0415B8BA065ULL,
			0x50B1326CE057FF98ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x4F5CD4E8B015179EULL,
			0xD3E178373FB0E933ULL,
			0xF45B20F977A9AAE4ULL,
			0x070FBE8689D3754EULL
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
			0xFDBCBF012F1922A0ULL,
			0x32B7DE744F6D5A92ULL,
			0xD5A6976B2D068163ULL,
			0x500A220E1ED8FE4BULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x2ED79D09A0836596ULL,
			0xECCE17AE59207377ULL,
			0xD5AD3D5B3DD29C9EULL,
			0x60C94F6C381AE0E5ULL
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
			0x4276E56F02DA3BD0ULL,
			0x10911A88CB9F96F7ULL,
			0x8CB02B7B7C96FB15ULL,
			0x42662FA630CAD1A0ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x6F789DCD7CE72A68ULL,
			0x816734D890D48346ULL,
			0x8C14FCAFFD4FD966ULL,
			0x1E657FC1E2DD14B1ULL
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
			0x979221E78B434A20ULL,
			0x893D9866C39C8AC3ULL,
			0xEADC0CF2731EA210ULL,
			0x44561B95EBA663D0ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xE11CEE9222425481ULL,
			0x56C27E0C3E889BECULL,
			0x8132D63889E8361EULL,
			0x0455E6253E1D8C48ULL
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
			0xEB167758E174C1B8ULL,
			0x9E05258B6297D80FULL,
			0x5987C7BBC759D2B1ULL,
			0x612B6B95CC8D489DULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x404F466B472A3F64ULL,
			0x84DA99B70A2F1C20ULL,
			0x371C70B3B51ACC4DULL,
			0x09D98299CD4F4123ULL
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
			0x979E45508C671C20ULL,
			0x35483DCC0F7E2795ULL,
			0xED1F4A42B65AD3DFULL,
			0x73BDD1047F8BFFD5ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xB8452577752FD280ULL,
			0xC534F60B21C7AB3BULL,
			0x123F8D032BD4A608ULL,
			0x7F2E2BE27C2B71ACULL
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
			0xE4B35B03DF212850ULL,
			0x376DD310F3252014ULL,
			0x130732FDEAAAF097ULL,
			0x6A15207B83A3CEE9ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x5C161C2C8D72E8FEULL,
			0xD367BB205639E0A8ULL,
			0xE5F4A2AFC7220903ULL,
			0x4D470A1399A387AEULL
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
			0x5BA846FA1A31B5C8ULL,
			0x931BFF841F2E9BF9ULL,
			0x47DAF26DE8BD9D0DULL,
			0x4A490CF28D40C1B9ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x8C59B90C7C9E99BFULL,
			0xF0F66F1F3F1C8B4DULL,
			0x333EF2780678200EULL,
			0x7457EF64A461C4E9ULL
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
			0x70F779C3B2275180ULL,
			0x3D24C6C2267741ECULL,
			0x75B937400A68E837ULL,
			0x60B4EA6D442D7EF9ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0x950B9EDFE630E15CULL,
			0x04A1889D22FA7081ULL,
			0x766ACED117BFC886ULL,
			0x5CBCAC616186DCB9ULL
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
			0xB1153AA11EA7C760ULL,
			0xA3BA3A09583E18AFULL,
			0xD4458EFF8E98A466ULL,
			0x43392E0A89708DC5ULL
		}
	};
	nBASE = (curve25519_key_t){
		.key64 = {
			0xADFC76921CFC96AEULL,
			0xF6ADD04D1E88F8CEULL,
			0xB8FF5FF16CA845ABULL,
			0x7794DA9EE3247F94ULL
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