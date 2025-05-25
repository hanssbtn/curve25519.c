#include "../../curve25519.h"
#include "../tests.h"

int32_t curve25519_pub_key_init_test(void) {
	printf("Public Key Generation Test\n");
	curve25519_key_t n = {
		.key64 = {
			0xB484DE5CCB3DF058ULL,
			0x1B4C47E7D6AF9B25ULL,
			0x0B1094C3B9EBFBC4ULL,
			0x50B1DEBC6A69ABC4ULL
		}
	};
	curve25519_key_t base = {
		.key64 = {
			0xFA481153C14853E8ULL,
			0xFAA5366F4F2EB8DDULL,
			0x457ADDA29BC136DAULL,
			0x4F3EDC31384D10C2ULL
		}
	};
	curve25519_key_t nbase = {
		.key64 = {
			0x8A5B0D779605A92CULL,
			0x4471EAD4B370A325ULL,
			0x1A598DC17E767624ULL,
			0x5EE5C99473C82836ULL
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
			0x8AAF2E3BCD7642B8ULL,
			0x900F9F3E697518FDULL,
			0x6A8C2F6A20328325ULL,
			0x74387259758D7DD9ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xAA88A80B897CC4F8ULL,
			0x83BA1E0DC28B3304ULL,
			0xF8C5A6A359C4E090ULL,
			0x404F90781EBFB2FDULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x2509869C6F3E447BULL,
			0xCF6CFC5AE32405BAULL,
			0xBD3498F60A4A1A2EULL,
			0x7D834F0E322E0282ULL
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
			0x1CC33BC2CCBDBCD0ULL,
			0x95743B5073648FFDULL,
			0x47C84FCFE0DEBFDBULL,
			0x4295E02FE7215344ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x31283E38D09B1A80ULL,
			0xFCC4BA745292D325ULL,
			0x0F51EF1BC432BD42ULL,
			0x7D0DF8CABD487977ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x06DF90646637123AULL,
			0xFF3F1E1B62646688ULL,
			0x25E3EBCA0C996700ULL,
			0x192612D974EFB234ULL
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
			0x9B60A90EC4A7ACD8ULL,
			0xBEDE01475C6BF84DULL,
			0x0D2D0FBC2F3C0E59ULL,
			0x6E8C73E29E5AB31BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF43762D3D8CF6FF8ULL,
			0xEE4B3231D1C81B11ULL,
			0x6E8AD67DC876A499ULL,
			0x50419C88EB5C82D5ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x688A897C9D24E867ULL,
			0xB8B11878A8E674ABULL,
			0xB50CFDD576E9C1C4ULL,
			0x57BE98706EBEC504ULL
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
			0xA9B36E55E4571408ULL,
			0x8C513F35B263774AULL,
			0xC11BB8CD4295802CULL,
			0x597EF2262BFCAAB4ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x3FE4E5CFB3AA4A70ULL,
			0x80BA1B3BC9A35BF1ULL,
			0x76EE85C1C5E4040DULL,
			0x4E8A6B7A541BCAC6ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB95EBEFA5F3B8CB0ULL,
			0xD0FD459A88EA7DB2ULL,
			0xBF9E269CC40D4B83ULL,
			0x60683F1717A30A33ULL
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
			0x6807604C53FAACA0ULL,
			0xBD9174F622A565D2ULL,
			0x8A2957127D549092ULL,
			0x7EE678AF0AE094D5ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x6740FD06B3187F90ULL,
			0x3D3D6B3DA6A455B4ULL,
			0x8DD5C1FFD99E6402ULL,
			0x701582DCA43DFCBEULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x5FFEC26EFEE36AB8ULL,
			0x78C543E620D08093ULL,
			0x8F3651F93135820FULL,
			0x15779EC4E4C1D5D3ULL
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
			0x8D6CB69A2F26B2D8ULL,
			0x3E807C32540B59A3ULL,
			0xEF6CBC84D8FEAED9ULL,
			0x66D2C8027D997A28ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x6C53864C0D031ED8ULL,
			0x8198AEBAFAE0526CULL,
			0xA97AFB9DC2690F48ULL,
			0x6E6861414E22377DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB81846714D6BEE48ULL,
			0x41900991B48052DDULL,
			0xF8C9EE830A6EBD10ULL,
			0x6437A47401423954ULL
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
			0x2F072ED1919E5998ULL,
			0xB0EC2FE0B8793146ULL,
			0x55350B461DEA4C62ULL,
			0x6A709C386CBC9C69ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA06F0D95CB8A1450ULL,
			0x1B4D983875942E87ULL,
			0x5F80864E9C727BF7ULL,
			0x64A7049E2163AC0CULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xDF3970277F0A9F4CULL,
			0xAAE98D056BB9980BULL,
			0xC303AE59DC64B488ULL,
			0x365D43683BEF431FULL
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
			0x8FAC37EA4F692848ULL,
			0x875FA8CB37347B7FULL,
			0x4AC37EC200D6D591ULL,
			0x710001020F1F7F64ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x1892BD01D692D5C0ULL,
			0x78564DD803866151ULL,
			0x50A363666E48510DULL,
			0x5C561C9EC96A5968ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x2ACFB655E545ABBFULL,
			0x071F5477B15EFFCEULL,
			0x7959F3F044DCB4F2ULL,
			0x63B4F1AB87F42BCBULL
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
			0x14512305D7CA5270ULL,
			0x2B619159D68947A1ULL,
			0x25868D63B07B1731ULL,
			0x4362C73F174B9040ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x2B52624BFFF91278ULL,
			0x96DF2052F4BB5125ULL,
			0xBAF8743BAC23E62CULL,
			0x63B666375995A764ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x2BEACB623EC7C9DDULL,
			0x2066D734B5F7603BULL,
			0xAD1A5CA75B2A80AEULL,
			0x70502BC0447AB874ULL
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
			0xA6400872EE067EB8ULL,
			0x03E8EE38AA219777ULL,
			0x9FDF35A29E0C139CULL,
			0x4B009DC8C8E942CCULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x8FEF3A545344E5E0ULL,
			0x5BA69B38018AF36DULL,
			0xF95FDA718C5B77C8ULL,
			0x75D0C13C33B67823ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x78A5B32EF9D9524AULL,
			0x408C5E920F14664DULL,
			0xE9FB34009830CC7BULL,
			0x3F9ADC93F140B675ULL
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
			0xE3F7203915FC2E70ULL,
			0x3A0C7FC49FDB3580ULL,
			0x147146A91E1B7C54ULL,
			0x5F90CD4F39A11B19ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xDA86FD84A4F92888ULL,
			0x09929F065669DD32ULL,
			0x2B5944D5A1A623AFULL,
			0x703A73AA930BE7A6ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x674B26A867ABDF00ULL,
			0x6C489864B8191C48ULL,
			0x427A1B6782E1C286ULL,
			0x1A99D9077C68832BULL
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
			0x1B453F644EC491E0ULL,
			0xEC773B9144AF6D33ULL,
			0xF42A379E06960B5EULL,
			0x7342960864BBC5E4ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4A9590C0130023E8ULL,
			0x0DA98C39360D3731ULL,
			0x88BC713B6E692B7FULL,
			0x5F3A1A39F2CFFCCEULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x7E40368CD33514CEULL,
			0xECBC3FADF3E0BD09ULL,
			0xE5425A5E034590A7ULL,
			0x5EF9D5ECBC53E1D6ULL
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
			0x2B4BAA23A3DC28A8ULL,
			0xD67CB38FE581CBD7ULL,
			0x0FDA90F3BE35C865ULL,
			0x6FDCC4A642ACE337ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD2479F48D14F1F60ULL,
			0xD9E34C6E315BD63EULL,
			0x3AE95ED436466097ULL,
			0x6C0A84E460429DB2ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xBA1FAB29639B2F62ULL,
			0x2700F9D72510C0CBULL,
			0x9926DA2B22C72F03ULL,
			0x09C4952EB0FB8ACFULL
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
			0x9F820DEA01BC4AA8ULL,
			0x291A2B53345F0209ULL,
			0xC4399143D9954666ULL,
			0x7874058D3AF3ECF4ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x88CF6CE5AD508F90ULL,
			0xC0EC28BDB14D7620ULL,
			0xA8CF35BEE68F85C6ULL,
			0x7B5340B513AC50ACULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x666E372D05005E6FULL,
			0x434707B05CC061BCULL,
			0x67C80067FB9C53A3ULL,
			0x455D48B90BA405ADULL
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
			0xA02281E1217EA8C8ULL,
			0xC34E4B9BE26E7E6CULL,
			0xF67F2C80D7D9DAECULL,
			0x68F06DD05E40CB92ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x1487BF6A1E030850ULL,
			0x03F3639FEDF80FDCULL,
			0xC20B8AB4C1C8040FULL,
			0x43E4EBEC3A380576ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x1D2B5E5B6D232888ULL,
			0x6E89608EC8A1939FULL,
			0xA5CFFECFE3D52DA2ULL,
			0x7B33888C826D6A49ULL
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
			0xA03B330DD02E7010ULL,
			0xF3B7480E8B270EB9ULL,
			0xDD1208720229C78FULL,
			0x6CA441FBA47C235CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x10684142EA184158ULL,
			0x2334CF7E268EAC04ULL,
			0x1AEBF6E5438476F9ULL,
			0x64122C7309D7246AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x6E5CDC10889D76EAULL,
			0xA3F6DD4C8AFFF658ULL,
			0x474B66CBF48667C2ULL,
			0x6AA3A6006C351E32ULL
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
			0x8231344510087788ULL,
			0x7D54EF3148C62082ULL,
			0xE9076B6CB0401B7BULL,
			0x684016A78619A339ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF1FE5B766C0F47F8ULL,
			0xB43D3492BBC5D67DULL,
			0x07B5ACEEDD5620AFULL,
			0x5EA25035A91A1ED1ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x7D468E208F1F7C69ULL,
			0x3515469BF0456705ULL,
			0x96EB2ED9D1CE291FULL,
			0x466B2705A9EB1ADCULL
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
			0x06C74F2DA6B739D8ULL,
			0x2B07103C129C52ADULL,
			0x8700985FB766CA3EULL,
			0x49BCB54368A08F16ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x92C31A214CD84CF8ULL,
			0xCE6BC4B8CDEC73D6ULL,
			0x223CD492856CCB83ULL,
			0x6CBBB788D9750F25ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x49C926A4CDF19A4EULL,
			0xF504C5A265BA5BC8ULL,
			0xC475EAC628364DAAULL,
			0x65533E75346D804FULL
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
			0xD27274636EE25E68ULL,
			0x66FE2FC807590366ULL,
			0x16D3D9E4FE08CC23ULL,
			0x55D4613B0E0316C1ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xEFAED7DF947D0C20ULL,
			0x923FE92DBB0E41D4ULL,
			0x35650CA3D2195D7CULL,
			0x5ED51B0482A3EF8DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD74075A2878CE8C7ULL,
			0x26E79B8C99298CD5ULL,
			0x0CC99FD2452B4D5DULL,
			0x2ADEC405B52D4559ULL
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
			0x5009DE91C50D7D50ULL,
			0xADB873AB8040F005ULL,
			0x8DC0C12FD3EFC73AULL,
			0x4FCAE91F020EBC44ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x0F2148C64F043688ULL,
			0x933BB3F91B5A68A9ULL,
			0x665C3D8605B833D0ULL,
			0x5D8331AC7427FC2FULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x2779D7F6241B4461ULL,
			0x3E17F12941A17F85ULL,
			0x9679C8C0D94294EAULL,
			0x4F0F2B71414AC9AAULL
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
			0xD3CB87CF0CC27890ULL,
			0x3C77A37520D85810ULL,
			0xCD9DB169EB292E99ULL,
			0x666A75B99CBD8471ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xEE4A8C7E981EEA70ULL,
			0xCFCA777CCB067EF4ULL,
			0x3750B388C76E1DCEULL,
			0x734E1C69196D311FULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x58FAFDC6C44F60C1ULL,
			0x504848061941A83CULL,
			0x6A0E649EEFFD0EFAULL,
			0x066FE282050B8290ULL
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
			0xC2508D80B4D71F60ULL,
			0x54BEE3C670AEFDC6ULL,
			0x29A6694FB4519BE2ULL,
			0x7F38D9F9E409DBB0ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x415FBBEA11B6C1E0ULL,
			0x37D1EE04A7BD30ADULL,
			0x1DF868EDC7B7344FULL,
			0x77C743C42210DF85ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x55F77F1B6D4A3AAEULL,
			0x0FA9EF518A3EBCF8ULL,
			0xD9C8309F0390AC6EULL,
			0x7A6F9672EA0FC729ULL
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
			0xBB86BFE86C070B20ULL,
			0x1D11739F7AAA4898ULL,
			0xAEF89BC687A148CEULL,
			0x7E756BEAB2ADB8A5ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x929BA203F6CE0458ULL,
			0x894263AE8107F6DCULL,
			0xA40CB574177D5A4DULL,
			0x589B30709BDCED6EULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE0DB06EF18ACACF9ULL,
			0x69C9EAC7584783D3ULL,
			0x6036CF2DBF107C54ULL,
			0x31C7963DF7BDBD7BULL
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
			0x7346DCB03FB9F920ULL,
			0xCAEAC2A939F5BFD7ULL,
			0x1A30E07B77CA8618ULL,
			0x5DFCC2444A125AC5ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB8A2A5B18F8E04A0ULL,
			0xE46BDA3BA219F6CAULL,
			0x7F78CE0E8CF678A1ULL,
			0x4BC6EBB4BD4B87B1ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x15750FD2C3C98C8FULL,
			0xA85EF172DCECBDA4ULL,
			0xDECEC42ACD1A894DULL,
			0x00B8CE241F3AD8CEULL
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
			0xD19207DA9F7F7EA8ULL,
			0x902943A2FCB79360ULL,
			0xD5EEB88DD8A438CEULL,
			0x77DEBEFFDA85D14CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x985745A01BCD4CD0ULL,
			0x0C7CC297BDECB6D7ULL,
			0xF8FD92C3205F522CULL,
			0x72393C17BE10D380ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x25324B4A350D5D0CULL,
			0x4E149B2C084A616FULL,
			0x106110C7AA6DDFA9ULL,
			0x46E98BC2977D1941ULL
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
			0xF6E0A4A67CC2FDB8ULL,
			0xE46565526411CD31ULL,
			0xECF5D9520B42CD0DULL,
			0x4E633592B9C505ABULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xAD8537DC71B1B8E8ULL,
			0x49D790F24779C5B2ULL,
			0x1113CDAE60560634ULL,
			0x7A8B0B4860EC12AAULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB27FCD9F335CA113ULL,
			0xF7ED40328D92751FULL,
			0x21225A2C5560CBCCULL,
			0x1439AD3C29F02ACAULL
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
			0x24EF3E3E28D3B488ULL,
			0x7DD86D44055845F4ULL,
			0xF7F4E2D242F33747ULL,
			0x564C1A9122FA61D6ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x5C78FF8F78FAD468ULL,
			0xB025D399A97ED0F8ULL,
			0xB48B8F68FFBB5790ULL,
			0x7786F491DF67420FULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF1B4D8B5FF70146AULL,
			0x6D830883D2F1FB65ULL,
			0x6FF3B8A145D23E91ULL,
			0x68DFC9BCAABD8117ULL
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
			0x3A877653359A59E0ULL,
			0xF731F71D6CE7D77EULL,
			0xE5B363F540DEF42EULL,
			0x7C76E5DB2FC55A08ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xE848B96ECD9E7E78ULL,
			0x5A015B92B5A2DA67ULL,
			0x1C53455137CD4AD0ULL,
			0x4649463F2C5CA92DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x2EAE9E3E5C025C64ULL,
			0x88B32DB6C35AFEA5ULL,
			0x5DB5357F324F1335ULL,
			0x4E2C51029D9D749FULL
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
			0x72F9779D485445E0ULL,
			0x4BD064E2033D4B17ULL,
			0x9C90C2A4E70FBAB9ULL,
			0x51BBEA6CC51898FDULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xCD607CF343B7ED58ULL,
			0x88023DCE69FE8817ULL,
			0x97AA0A0AB99180EDULL,
			0x4DE9DC3F644958D6ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x271B92BAF6F0A980ULL,
			0x4ECFCDF11F0CD431ULL,
			0x6E9C2E13A6EFA1E6ULL,
			0x468C7100B5F2DCB6ULL
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
			0x7AE3D3E42D216F80ULL,
			0xFE0EEF8A1FFEEC00ULL,
			0x9FE6CB32F9DFABDEULL,
			0x4F4A45500BCAD28DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x311E55470EEC76D0ULL,
			0x38883C7F97B7B67BULL,
			0x6C4DA118D398A11BULL,
			0x42A12F76ECBBE5BAULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xFE3940E15C34E7BDULL,
			0x219AF303233453A1ULL,
			0x5D3D2F849FD5D629ULL,
			0x300AC572DBBD72CCULL
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
			0x41236D2217D6C9D0ULL,
			0x372E8E83ADCCE752ULL,
			0xF5B78770D8CD6C55ULL,
			0x5415C3F259716708ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4FBB42B281D0CA50ULL,
			0x7414FEBC8E4825D1ULL,
			0xF93EC37A9E03D8D3ULL,
			0x5BC007933C136F68ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x1E9A641E5CA60E92ULL,
			0xC6F5B930B78DAA63ULL,
			0x040428928991490AULL,
			0x10BCF56D22EF38A7ULL
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
			0xC5FC6D83CC273768ULL,
			0xEAF6771783ADF5B5ULL,
			0x8352541C2391157BULL,
			0x4090B5A04C032389ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF50494064629D548ULL,
			0x684AEC1FFDD02317ULL,
			0xB2746314EA222EC7ULL,
			0x660CA793D9C712A9ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xA3AF7B78F9D82F00ULL,
			0xDFCCF52FA9A451F1ULL,
			0x9C19B8B55B760041ULL,
			0x05DF4E0A0E69C469ULL
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
			0xC3AD7F3BC84C9470ULL,
			0x068DE7EA58BA634DULL,
			0xA135CF0C5D754698ULL,
			0x690A215E73A316B5ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC9F8EEF71DEDBA20ULL,
			0xF2D6323E01D629B9ULL,
			0xDBBE526F9D43D0AEULL,
			0x67CAF7C3526CE662ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x1284399576D99D77ULL,
			0x1A9987D21916FB31ULL,
			0x96271B1D71167B12ULL,
			0x2B0A1D70CF32BB63ULL
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
			0x97792CC03CB87FC8ULL,
			0x04101A65BCA75F38ULL,
			0x60D2EADE24908FE1ULL,
			0x7090408680F366AEULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC91299234A600D78ULL,
			0x51FC744150C38BB1ULL,
			0xE02F7E8BCC9CC096ULL,
			0x79F89D59B48B2424ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xAA14A899498A1DABULL,
			0x899FBCFF37D0E48EULL,
			0x777584F9281FD013ULL,
			0x28D5816B90A1717BULL
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
			0x02C5A40E2EBE70F0ULL,
			0xCB4E8AB3F9FF81AAULL,
			0x7EE6222E5AA0852CULL,
			0x50CAE0F6CF3D6402ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x63F19E4602B422C0ULL,
			0xA63D34D17C587592ULL,
			0x7DD545634A12344FULL,
			0x4744AC127DE22987ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xDED9E46C92815355ULL,
			0xA0D5D104933BDF9EULL,
			0xB55CD92ED8BE2283ULL,
			0x12AC62DC26F3B03BULL
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
			0x59A5783D724EFE60ULL,
			0x24F118FAABDB175CULL,
			0xB4AFA670E0D366C3ULL,
			0x5F1A5C6C891743B7ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x365669127ABF5728ULL,
			0xC97A9F14DBD6C500ULL,
			0xD566590D9C82154AULL,
			0x5E434FB82A5364E8ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x579391CB36014B4CULL,
			0x232C1A58D85BE003ULL,
			0x399873F40F2EE64FULL,
			0x17424A7AD7F5CD0FULL
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
			0x43923CC41B217108ULL,
			0xDF0AC78F3C183FDCULL,
			0x7914C3C473CA6901ULL,
			0x7F4CB24EF193E2BAULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x30EE63AC45116710ULL,
			0xCA4C6DE5490EF25EULL,
			0xEEDA771618063DE2ULL,
			0x67C1E37C30A6BDCCULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x00B7297ECDB4F7EFULL,
			0xAF5477E2B5C5828FULL,
			0x09241351CD64644FULL,
			0x214D868516DEDD2FULL
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
			0x1D5335732EC158D0ULL,
			0x9CBC2374361DA2B5ULL,
			0xDF36753E37E58CEEULL,
			0x6FD6E3F11C620E48ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x366B81663AEAF5C8ULL,
			0xB05F9B8F3B19FBEEULL,
			0x27D3B85FFC97BBD1ULL,
			0x6F3B0C01B7644B11ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x5F1EF3B807CD5AE1ULL,
			0xC173CF4103745DDBULL,
			0x29F05849D5230DB4ULL,
			0x4C8B80C3041CE2E1ULL
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
			0x59C27FE261B96320ULL,
			0x2ADF723B037C56A4ULL,
			0x6CF654890479190DULL,
			0x798609695B883F7EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB05CE8A98E956908ULL,
			0x23172D95F0626F25ULL,
			0xBC328A7C9B3EB9C0ULL,
			0x66654A160BA58BCBULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD173B3379A9D4EBFULL,
			0x178CF9E5FFDC9E98ULL,
			0x90D12DF1BB857E69ULL,
			0x0F53043DAD99650CULL
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
			0xD81FC400029C4B40ULL,
			0x4D1F32A87579DDD9ULL,
			0x902D2B7A161983BAULL,
			0x5665D66ABD845EAEULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x6F6D38307D3AE380ULL,
			0x8AE921A985CD495BULL,
			0x6FC3329A1A124FF1ULL,
			0x46DA77394641C3CDULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD48D1DF1D5BD53C0ULL,
			0x5840341EF0C0DFCEULL,
			0xF3A859CD4792A06EULL,
			0x703E3F2F162104ABULL
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
			0x727E7AB65D797F88ULL,
			0x6D55D1C2289D440CULL,
			0x6C846AAE4ADBC805ULL,
			0x4D125A7ADFC8BC27ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x0BA571DCB1E382E0ULL,
			0xE3AFCE26C0BCE075ULL,
			0x04E102E9C4CEB384ULL,
			0x552E004951BDB90BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xA0B07EABA41CBFD3ULL,
			0x0311C12EBB9D6640ULL,
			0x35669FC73DDF7130ULL,
			0x7F346EE168E8F1EBULL
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
			0x2C819C476DE9A160ULL,
			0x532F9E1105647AD4ULL,
			0x7CFE3CB6A20A1490ULL,
			0x509BA5C7AC4AB5D3ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x461B5A21D80C73B8ULL,
			0xAE5ECE9A833E5412ULL,
			0x7A2A33222B126BE5ULL,
			0x4522F1BE42410CCDULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x4F078D006F628A79ULL,
			0xEFF1B6A4BC34A8E7ULL,
			0x467CA2B9078C9F96ULL,
			0x6A60B4202D027553ULL
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
			0x07DACA6EDFE8E690ULL,
			0x4F33E33FB361D8E2ULL,
			0x56A2DC114EF05134ULL,
			0x6BF1508F9E2B574CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xBF9FC87F48E577D8ULL,
			0x6591D09E7F53B7D9ULL,
			0x02D7B816AF6C9350ULL,
			0x7A59F32C2A48F0B3ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x98CBEFD3B177BEF7ULL,
			0x1094B778F1BD2321ULL,
			0x23812A6B252DE02AULL,
			0x5EDC3670DC822D1BULL
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
			0xA6C10A08B9607B38ULL,
			0x263DA4BFA7F10FA2ULL,
			0x2C405DC56E312BB5ULL,
			0x5A103C5B0ECDBE5EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x32FF8A2B59043C08ULL,
			0x81B5D66B00B95519ULL,
			0x6DF9F55E1E1549A7ULL,
			0x56FBD51887E4E597ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC07A00ACCE4FFAA8ULL,
			0xBC8DE6045B6936A9ULL,
			0x99BFB74ACD3EC02DULL,
			0x3B70EF14CEF131BFULL
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
			0x1F41DF84D1A12468ULL,
			0x147B86A11D49D369ULL,
			0x1643651505FFD22EULL,
			0x5313AA735E554BB3ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x66BC37937D170760ULL,
			0x385B496B32B3601EULL,
			0xD4979940E33FF0C7ULL,
			0x573A56D8ED9FFB50ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x563321297AB75683ULL,
			0x33395DD5F2CC3B14ULL,
			0x7799C7B026EE35E3ULL,
			0x2A6C66ABBAE8847EULL
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
			0x9961A5AB57DC4A40ULL,
			0x5FB376D12E4A88CDULL,
			0x3293366B7DC4A5FDULL,
			0x5DED117A5DBB30E3ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xEC64D996F4F4DEE8ULL,
			0xD900001DB6CF7EDBULL,
			0xAA34B6DB2DF90E65ULL,
			0x45D04C65B8F5EE9CULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xDFC9119469A09D90ULL,
			0xCA1EBB34280175B3ULL,
			0x000EDF037ACAC2BEULL,
			0x7193DD405C85363AULL
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
			0x4399902E778CCEE0ULL,
			0x2CF6A834F6BDC335ULL,
			0x0BB2B9BAB7EB4F03ULL,
			0x52CD2AA508A0E3B6ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x458BD56EC12A31D0ULL,
			0x6193AED878E16C41ULL,
			0xD1430B0AD009C527ULL,
			0x7B758797203EB7F0ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xA572DA69A60368AAULL,
			0xF893B222B7416E5CULL,
			0x00238265B995CE10ULL,
			0x590CF47C73BAC9B7ULL
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
			0xD1B6014A15C7C188ULL,
			0x476FEF5DAC39A847ULL,
			0x4DC8AAB8D102785BULL,
			0x411D1FC81BA94E52ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4FC09941F0AA2108ULL,
			0x7AC77A158F14B49AULL,
			0x2C3BF6A1BFB3C756ULL,
			0x7F73B0DFC12414F3ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF5E272E1F5108C1AULL,
			0x719349B7E74A6926ULL,
			0x0DAE24E5DAFFDF35ULL,
			0x7A1E8E75047F0F04ULL
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
			0xBD119EBEF6111608ULL,
			0xB1D060FCF957D246ULL,
			0x9B4F8B2DFBB92B11ULL,
			0x49706883F9DCE4BBULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xE132AC7CF7F76730ULL,
			0xF169768F5E99917EULL,
			0x90700A8F98DA6ADCULL,
			0x791C31909A97D65EULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x71F526AC5C42675AULL,
			0x88C15CDA9D3ED1C4ULL,
			0xD9D209C292FB2E71ULL,
			0x1ED68D8F85E0F780ULL
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
			0xCC8F176202518550ULL,
			0x48CD4030435F84A4ULL,
			0x72ECA22C93D847DDULL,
			0x7CFAFCBA337113BEULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x761EC4B04C315FB0ULL,
			0x5F28EBBE6DA3B26BULL,
			0x9793190FC7787126ULL,
			0x4D53840823C582EAULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE9DD20E7F1900205ULL,
			0x862787CB5C03FA23ULL,
			0x64B1B7FD81260AA8ULL,
			0x7CC01F661EFB613CULL
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
			0x400035078E49C7D8ULL,
			0xD47B53E842916078ULL,
			0xC7D2C32530BD3F2AULL,
			0x5A30171CBA889041ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x3F05F2DEEEA08A38ULL,
			0x112452402F17BEABULL,
			0x35C11A620F9ACDE7ULL,
			0x7D7B958457958069ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF0DB0509DDB6DC4AULL,
			0xE38E0C9B5C4CC5BEULL,
			0x6961562FB6D3BA49ULL,
			0x503B83F5651597BAULL
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
			0xB2C6D0AFBC89B250ULL,
			0xB4786932165D5A8BULL,
			0x1FB8397DF01EFB0DULL,
			0x7DFB39EDE53DF8E1ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x6FF363E12DE8F2B0ULL,
			0x98F77FF6F46BFF9AULL,
			0xDFF03F9849AF70A2ULL,
			0x4B150DC1BCD300C7ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xBD98E4DC2CC79702ULL,
			0x8F1C3FF7A6348E97ULL,
			0x10317E93C0E49E82ULL,
			0x543CB11A9EC447B3ULL
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
			0xE85491D1FA4DB360ULL,
			0xCA6BCA7698AC6E56ULL,
			0xB1E31F5AE635D9E3ULL,
			0x4E928D34A4E5DBB2ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC387BEAC7E051560ULL,
			0x995EB3C795DAED13ULL,
			0xDD5027073580FFA5ULL,
			0x62F0F81DC79ADCD0ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x3F39C253FFD67CF9ULL,
			0xF16C0B7CED644AACULL,
			0x5C3F1D1E70A04159ULL,
			0x5F430F7DC969360AULL
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
			0x4694683050F9C958ULL,
			0x68002CFABC234A77ULL,
			0xE73D531C1EEBC14DULL,
			0x719EF1DA40FFB64AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x0E227F285E62ECA8ULL,
			0xDBE0F9C6823F36F4ULL,
			0x4181F366B74999F4ULL,
			0x5C28FDAC5395B77FULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x0AEE13C61C33C8B0ULL,
			0xC49BB375F0CDBF84ULL,
			0xE83B0A4BFF27B6ABULL,
			0x0649D65738DF1ACFULL
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
			0xD5BB9041714831C8ULL,
			0xCCAD14900968A95CULL,
			0xC6073E831800E82BULL,
			0x6F3158EFF00FC72EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4A1F1B141B9C6950ULL,
			0xFCD3316602910DB7ULL,
			0x9804FFC8E083E5AAULL,
			0x46EDAC37BE7FA887ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xBF98E278BEF0F218ULL,
			0xA2C9AD89B9712BCDULL,
			0xB00A644287C6C18EULL,
			0x12CE8977A0C807EEULL
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
			0xF337EEE1E788DBE8ULL,
			0x071E58ABC74DDE5FULL,
			0x1912536A1F8F3B58ULL,
			0x42CCE03DDA896A56ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x2C7CD51423863330ULL,
			0xB4D8463C3B3F2CBFULL,
			0x9E79F0EC40B01A25ULL,
			0x7D15E6F62CCC6A6FULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x8EC3C46F5BC62BF1ULL,
			0xFCB1E424A3BD2498ULL,
			0xBB868FBD243C4FA9ULL,
			0x0CF6519F1CB32BBAULL
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
			0x4E082FA535CF2DA0ULL,
			0xCD9E8E9F44605551ULL,
			0x8F311C0974EFFF5AULL,
			0x42DAC7C4242BA6D8ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xE4BCA542B86364F8ULL,
			0x699B74B6D53BEDE6ULL,
			0x09867DEF9E129BF7ULL,
			0x593B9D99E75A8372ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x80852563C2CAC29BULL,
			0xF3230FAB50515BE1ULL,
			0xD972D8DD3042D451ULL,
			0x425BEEF1BE7B4A30ULL
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
			0xB1CCB3169264E800ULL,
			0x2B92049A358BBCDDULL,
			0xF9C8523BE231D7F7ULL,
			0x5D402DB37C6DF3D1ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x8CE67BA00B626A38ULL,
			0x1237B2544CB05DA8ULL,
			0xC26326F824F693E5ULL,
			0x5F8B0E693C1A2ABDULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB2CCB02C344F76A3ULL,
			0xC597DE48F9BA52B8ULL,
			0xAB299F046CC37628ULL,
			0x0A32312FA1AEEEFEULL
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
			0x7F7CC90DEC89D6F8ULL,
			0x94F97AB03B75C062ULL,
			0x6F7130A3D017E263ULL,
			0x61509A05410A9C74ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x9C342B7A68EFC6D8ULL,
			0xC3D65FCBE883B47CULL,
			0x63DDDBB5B382A07CULL,
			0x4644FCA94573897AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x19815D7CF968EA26ULL,
			0x4A2F6DB3192A30FCULL,
			0x97E96C0CD334710EULL,
			0x615F33B2562D4FF0ULL
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
			0xA6BFB05066520C40ULL,
			0xD2998C7445D053F7ULL,
			0x6027DF345154677DULL,
			0x6FC95A212481DA86ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x2EC78072235B3258ULL,
			0x9428CD769130D495ULL,
			0xCA8A6A64D7D36391ULL,
			0x5D5BBE9F81FD4FD9ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE35388DFBA71ACDDULL,
			0xAB5F6A016F1D89B0ULL,
			0xD6F1CDBC2D8A1706ULL,
			0x27BF68B70D505938ULL
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
			0x144DEAD7323CC328ULL,
			0x8D4487045C9AE225ULL,
			0xE8F3F5237BFECF2AULL,
			0x7391032EDC7A4F37ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x23038D18D56B2500ULL,
			0xF728EDCE7676BA4BULL,
			0xB93CD9741184C069ULL,
			0x70C9B014B862BE0AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD473A63A2A007C88ULL,
			0x1D05E3C9B61C0DACULL,
			0xFBAFC5173AE02150ULL,
			0x155B6880F857EEFDULL
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
			0xD2360E3F04F441E8ULL,
			0x2DE9432FC56C0C05ULL,
			0xF51FD03017F3500CULL,
			0x529FA0C4E8414D67ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x7F73171169BBD8F0ULL,
			0x05FBCD7FA2107583ULL,
			0x4B83A94C0980DE48ULL,
			0x7429B83D0A6C8176ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF999EE1114541985ULL,
			0xB5877E33BD1E4F65ULL,
			0x20D1FA3A42725F45ULL,
			0x11F5F05CFB3BC49BULL
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
			0x6039EA330112EAE8ULL,
			0x48920AC359B4D584ULL,
			0xFCB82D2541B20A8FULL,
			0x4711D54F2D970934ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD545288B5ADFA6F8ULL,
			0x83D40D3B895C1A09ULL,
			0xDCE28794997770BCULL,
			0x4D94293E91D3EDA8ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xEE74B97B85BCE224ULL,
			0xB7F8DA7DC32DC087ULL,
			0xFAEBAB43600DC3F8ULL,
			0x5C60CA07591A980DULL
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
			0xF6ADDA46FA7403A0ULL,
			0x72634363EE678ED9ULL,
			0x5FCBE297AE90147EULL,
			0x68265635514E1670ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x0F019AB0C0729B10ULL,
			0xC3971175F87E7171ULL,
			0x310314A3FF58FE24ULL,
			0x72B2E887C3BFD1A7ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x334A3EF3D63EA400ULL,
			0x0C3F5193BDDA8AB6ULL,
			0x22367AA277CD20F1ULL,
			0x6954B1EF34CED199ULL
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
			0xA4C5AC4685D52678ULL,
			0x7FF756D04559DF84ULL,
			0xF4E1770091FAAE68ULL,
			0x487DF1EB83C877E9ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x423866D37C3FF4B0ULL,
			0xD4F798B41C2C7151ULL,
			0xD5E6037005467557ULL,
			0x653FAFA1C862E180ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x15F09309E3EC81D0ULL,
			0x3C0C62CA277D2F69ULL,
			0x62BC45A863C4F177ULL,
			0x22557DB7E5026E5DULL
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
			0xCEC2795B2DEED928ULL,
			0x9F532535F23FE788ULL,
			0xDE0369F1D282E932ULL,
			0x521B82B07B7B6BF9ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x91C4268E211B0450ULL,
			0x7033C09EF5EC1EBDULL,
			0xA0C0FE1D938C1D43ULL,
			0x7A86514469B929EBULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x599ADC7D9FB60B56ULL,
			0x0E904ECFB1D638F7ULL,
			0x0E6075E8D755CFF8ULL,
			0x34411414B9A4DC75ULL
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
			0x95A659B8A8C97060ULL,
			0x41AB05A719A5E1A5ULL,
			0x20E87FFD8BBD1E7CULL,
			0x42AA02C2E8199B05ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x81CF7D5720D07980ULL,
			0x9345444991F87393ULL,
			0x50D3BA0BD687EC10ULL,
			0x5583F667021ECCA3ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x6259CB80450DA857ULL,
			0xA78A2E939C22BDC5ULL,
			0x463B41105625A2C7ULL,
			0x664358BA4491F6E9ULL
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
			0x5516CF2F3FB2AC70ULL,
			0xD3C83EE999538370ULL,
			0xA1238ADFE1E9BDD0ULL,
			0x654A6356E02DB925ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x725FF7E80B57F338ULL,
			0x77D794D891DA0C30ULL,
			0xF75569B1C6270D18ULL,
			0x4FF91C8F916BE8E2ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x5A0FD1B12EFE9357ULL,
			0xC7AD372EB6D58FE3ULL,
			0xB6BD58F87BBD111BULL,
			0x73E6132FDED2A544ULL
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
			0xD14F03FF80639AE8ULL,
			0xB86C72B4341D0E43ULL,
			0xFD673683F38255AEULL,
			0x7AC2C8A24C7210AEULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x0C0BC96C137EC350ULL,
			0x45E90E6293AD0868ULL,
			0x8E097E5AE9BE839FULL,
			0x5579B6A2CE1C0093ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x807E1F23D8F42BBEULL,
			0xAA2E1AD0884AEA81ULL,
			0x92A5EF76201FF791ULL,
			0x466DD9E3DF87B785ULL
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
			0xA6B963453E072460ULL,
			0x917589B22991EE32ULL,
			0x3EF8B2D8340AE57FULL,
			0x41B6C8EA08662E5AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xBA7B6A528B743970ULL,
			0x19586B36D76E9435ULL,
			0x6E9507B627B91F8DULL,
			0x566A6E7090374B50ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x5A40CE4A92331BD1ULL,
			0x9065C55A4D60EBA1ULL,
			0x8C8E2A8F0776A9EAULL,
			0x759E2FB811F1389DULL
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
			0x1A2F8FE81C6C3FD0ULL,
			0xB5F87F1C3ABD3A57ULL,
			0x3636D82BD2434ABAULL,
			0x76B8DA5A6477B2BFULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x5B2B03D4003E4C58ULL,
			0xCE7DE4350244D45FULL,
			0x73EDBF54906E52EDULL,
			0x75F480AD64AE9FBFULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x1BEAFDF5115FD675ULL,
			0x0213A426B91289C6ULL,
			0xB7F98AFE6ACD4731ULL,
			0x4E7E9C3DCDF2B99EULL
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
			0x179CE273AF8AD2C8ULL,
			0x5D7EFC9DC74ED536ULL,
			0x3021E18BE17CCBEAULL,
			0x70CB1A56EF784528ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x2BB287686B308138ULL,
			0x72C8D40BB5BD1A9BULL,
			0x3464275DEC158398ULL,
			0x4CE4562D7E71F8D5ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD081B9081F194D90ULL,
			0x5732ABFB8A83E8E3ULL,
			0xD5B30ED7A05805FAULL,
			0x4CBD419C6BE26F70ULL
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
			0x3B19AB577A6AD280ULL,
			0x9B0E12A0229EFF20ULL,
			0xEDAD21DA35BE41B0ULL,
			0x746980EEC9D865B8ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x46F9152B444D1CF8ULL,
			0xD6EC5450A971FA23ULL,
			0xFFFDC5A8C4124A35ULL,
			0x4A09F39FB24C89F8ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x6C9CCF4089626A7AULL,
			0x52EDCE7153CAA695ULL,
			0xA159365B73D8719FULL,
			0x1357F6BD435F2138ULL
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
			0xD4EFE57D8FE34258ULL,
			0xCBEF68B895A11121ULL,
			0x663AA0198CB80AEAULL,
			0x6D4A44BDFE8AB1EDULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x65D859A8BC76DC78ULL,
			0xCFDA81F07F40F1D5ULL,
			0x30BA28DB4DDDDABCULL,
			0x64A350017B24CD1BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xECBAF708C7A5B2B7ULL,
			0x8489A755CB1076BEULL,
			0x4F4FFF38C8C17B6FULL,
			0x3A35E719727FD820ULL
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
			0x1426302D19591380ULL,
			0x7CB237A37F0FDDC1ULL,
			0x4EF05367F21D3216ULL,
			0x6CBB5A09B1F34B25ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x444A699DEF1C2258ULL,
			0x597F2A1AFE56E3BBULL,
			0x52F724B6DFB9D505ULL,
			0x6E36C5987D95D779ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xDB065DEAE367CABCULL,
			0x3280B0505E36EB0DULL,
			0x2493BB9451AB0D15ULL,
			0x13C230385EF228C1ULL
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
			0x351E1FAE8F390EF0ULL,
			0xB9A7AAED5B6B4F0FULL,
			0x549E15A0998C7788ULL,
			0x5753408CA512480AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xE30D37DCEA50B370ULL,
			0xA4B8B5DC35ADE6CBULL,
			0x16B427CBFCB1ED7AULL,
			0x4135BF0764844C37ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD22155A9A8DFBA3DULL,
			0x68228330D17A82B8ULL,
			0x81ED79F4574DA3C7ULL,
			0x3D2AE4A7AB0AE1C0ULL
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
			0x0C324676D846E3F0ULL,
			0x705928F19029FD66ULL,
			0x27E8E5ED2230C1FCULL,
			0x5CB230DD046C247BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x6D8BEEA0AB3F2288ULL,
			0x16759A755D313674ULL,
			0xFF2E34D370D4150CULL,
			0x58A4DA39CFAE64BEULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x75A27C1BF85BECCFULL,
			0x15791C35FEC461DCULL,
			0x536A4A3BF2B53091ULL,
			0x5EB4CEEAF4A56026ULL
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
			0x6D5DA3D26584D880ULL,
			0x4F603CC7027824F2ULL,
			0x31161D187B2A6FBCULL,
			0x7CEA0FAAE261DDAEULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xE29EC1D140D0C2E0ULL,
			0xC4A1718FE163A635ULL,
			0xBF371B882DD25B12ULL,
			0x4D70AE623262713DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x4EAE8ECABA13F2C9ULL,
			0x5311A2CCCFB6F608ULL,
			0x29C0701366A54285ULL,
			0x289048704A6BC4A2ULL
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
			0xD5E786ED6704AD38ULL,
			0xBD8EB236DFBCB043ULL,
			0xE30F1843C5F8CF03ULL,
			0x5625827EA1A6E5DFULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x0B5730507F360690ULL,
			0x3D075208151D14BAULL,
			0x6CBC6F01D05720D1ULL,
			0x59F6920FE0C35AE2ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD10D5F41A6D13304ULL,
			0x78CB0136EE05277FULL,
			0x99C9D1B99B3D143BULL,
			0x2998F60810886920ULL
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
			0x7E434E33EFF285D8ULL,
			0x804F48D5B01B25F2ULL,
			0x2E00A91D0138FE48ULL,
			0x7613CF50EE012E83ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD3B3DCB87BB62398ULL,
			0x23259754AF30F949ULL,
			0x6B73C1B9EE5722E3ULL,
			0x5FCE33A974CBE07DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x67930DB027F05ACDULL,
			0x11885AC96092B448ULL,
			0x2D0C49AA2116C5CDULL,
			0x5D8FD5A50278FBB3ULL
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
			0xE75C797BC06A2FE0ULL,
			0x893F24770CC658DEULL,
			0x3E80473AB34AC45CULL,
			0x5E9E698FAE08C8CAULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC36D96DB4453E698ULL,
			0x848B3AA473B37DA7ULL,
			0x656836420DD114ACULL,
			0x5FC3CD06AA686FF9ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x51249FE8F2A0AA35ULL,
			0x7BE7F2994F514FF7ULL,
			0x8800FF717115B9B6ULL,
			0x3237F8A09D987934ULL
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
			0x6D0A61D3A6FF66D8ULL,
			0xEC55A31C75DBAF8DULL,
			0xA867FAB75EA37173ULL,
			0x6842B33BE9EE70EDULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB6B4C89873CC17C8ULL,
			0x8C14208B6A37C964ULL,
			0x8707C040A2686608ULL,
			0x7A30551C63F77B9CULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x1CB4D8020EA57A2BULL,
			0xADB23543212094F8ULL,
			0x4A452D4358A0D9D9ULL,
			0x398BA38FBF93854AULL
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
			0x483AFB502617B3A8ULL,
			0xEC9BF39BC2E7EFB0ULL,
			0x7EF95EA7E8183348ULL,
			0x7E5E30B656AD60C6ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x72F3745D6DD534D0ULL,
			0xCE5FA4688955F523ULL,
			0x5A6B1C1385889625ULL,
			0x7BC23F4604759ECCULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xFC7A4106E3FCFD86ULL,
			0x4A974C9EB0ED8C90ULL,
			0x2B54DAE99611B71CULL,
			0x768848C1F5D280B7ULL
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
			0x40EBA2BB6F293E90ULL,
			0x28E368DCDA598E17ULL,
			0x9BF8869A43D1DB76ULL,
			0x60518954D2E205FCULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x95807E3775D1B490ULL,
			0xE4D8A875F8523864ULL,
			0x98524258C7E72C33ULL,
			0x7A9D79B5FE8FA6C2ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x8DED4ED0E063B711ULL,
			0x224F0A1E8C54F218ULL,
			0xF64E25F0A2204374ULL,
			0x14F993D409155B38ULL
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
			0x45B8A1AAA0B623E0ULL,
			0x24C23EC878D1B875ULL,
			0xEF4E26C290583242ULL,
			0x432144C92622EC46ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x3FE77188EF9A36D8ULL,
			0xEFA103A66E75DA7DULL,
			0xA7BC35FB1B1C65C2ULL,
			0x56878BA620DF4C8CULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x0DC836E92123A85EULL,
			0x43164BE119E2785CULL,
			0x27CB145257AEE0F9ULL,
			0x4D1245E277C94940ULL
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
			0xCB7CDD5A855EF690ULL,
			0xF3CFF230B19ADE72ULL,
			0x9C1B3F4EBB10839BULL,
			0x4195BE867A07700CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x5290BFED5ADB8128ULL,
			0x88E2A03232E3112FULL,
			0x18A81EB7A31CC125ULL,
			0x68C7710815289CF8ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x4707F1CB36E89378ULL,
			0x04EF0433AC6576DBULL,
			0xA007CCF386E2C97DULL,
			0x0F2EB619F0EDBAFCULL
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
			0xA0DCBD97D47D2F90ULL,
			0x2CF6A8F5B1BB71D2ULL,
			0x60CD43352A85CCB8ULL,
			0x40AD6E6C77AFA530ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x2DC0CE6C9603F1D0ULL,
			0xDE9945118C932148ULL,
			0x0FD3B47949214576ULL,
			0x49A9E3B50DF08DD5ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x37A2F78B629F44B0ULL,
			0x53CA5913339D95B0ULL,
			0xD4125EBB55F670C0ULL,
			0x71956F1D05C2338FULL
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
			0xAA0E5CB24BD25228ULL,
			0xD4B4C2433C75EABAULL,
			0xDB83FFD8C04A6050ULL,
			0x70AB8DA99058BDB4ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB14AAE58732049D8ULL,
			0x280A4E2802C08C14ULL,
			0xDFD522FBA076AAE1ULL,
			0x58A87E4446306095ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x433CB1C88356A518ULL,
			0xE0DD01F0F278DC87ULL,
			0xD3713A7D306B8CA0ULL,
			0x1AFAA8F677132746ULL
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
			0xCC47018B4FEEE2E8ULL,
			0x3DA3FA6D13AF25F8ULL,
			0x5F7039783A92FC52ULL,
			0x6AB65A9B2AADA6FEULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xBD55824574093EB8ULL,
			0x1418078A03CA2158ULL,
			0xF2834667B80E18C7ULL,
			0x74423C0FF0E9D297ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x9A16679072205DD9ULL,
			0xFDCE574E35857993ULL,
			0xD4DB1F54F50E095EULL,
			0x5A84912B7290C552ULL
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
			0xB3E25BF69D6A8190ULL,
			0xAC03841D151AAF6FULL,
			0xA10F9D303EA819A3ULL,
			0x7275C978E6A35F4AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xE057FC404918E3E0ULL,
			0xD2F68E9C7B5E41EBULL,
			0xBA64A340166172F8ULL,
			0x7157AE169618AFA9ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x259F00D809490EE5ULL,
			0x495C1BE57FE31B26ULL,
			0x4056B52CB6AE5B3FULL,
			0x42FDD3235869740DULL
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
			0x1C7A1E09C132DFA8ULL,
			0xD8A6DAC3EA1B9F89ULL,
			0x76390BDC34321035ULL,
			0x4BA84F09DBD259C1ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xCD134FD0B90AD3B8ULL,
			0x8F44B70EEDD60C40ULL,
			0x21AA9065AA0644FAULL,
			0x7A27F705AC9C3820ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x927E524B15A37702ULL,
			0x933483A1C1B521D7ULL,
			0x2AD6AE64ADB5F4C5ULL,
			0x4D1A83EAA4E0F611ULL
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
			0xE023D2B78F3E6F58ULL,
			0x66B927E3DAF01338ULL,
			0x58B88610A381F9E4ULL,
			0x5D2D0A050D57ED70ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xFDFF0F4EF28073F0ULL,
			0x1EEC25D226B0E0D1ULL,
			0xD58945F89A07FC42ULL,
			0x4422A73BB7C53365ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x5903471891BD24E9ULL,
			0x68AFE964FDD97ED9ULL,
			0xDF303354438F2093ULL,
			0x52A7415197683D7BULL
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
			0x8FF26AF3E0DA3F00ULL,
			0xF01C9EF7C69926A2ULL,
			0xF41558595AB1B0A7ULL,
			0x48A49F04238A5621ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x3613E00237920040ULL,
			0xB207752740063328ULL,
			0x9C36C09F2A56D945ULL,
			0x6ED8DE83B60F61ABULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x43977FB487BEB369ULL,
			0xF7E61520016DA50DULL,
			0xBFDFB0F63227F949ULL,
			0x6FF1DD8ACE1DDB90ULL
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
			0xFE071C27E4B2EF80ULL,
			0x0C0338FBF28857AEULL,
			0xAC117EF88EF0BDC6ULL,
			0x4D632B6E4C48625AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x497FCD135A137000ULL,
			0xE09ACFFB861605E9ULL,
			0x45A7BDC23D716A18ULL,
			0x6FBE37C048A031ABULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xA0E0C08ACC760D99ULL,
			0xA897CE6564771F4DULL,
			0xCC2087F990B099DFULL,
			0x78710D07B460E02BULL
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
			0x0BFDFB5C22099B50ULL,
			0x7D02E3A85E822E03ULL,
			0xDBD81241CFE68A86ULL,
			0x4C7A6AFD37A05F9AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x73557EA9EA97B4D0ULL,
			0xDE95E99860E58AEDULL,
			0x88E624A31867F4FDULL,
			0x659C2F4B59ED013CULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x9750DA0EAF39FD01ULL,
			0x127866694FEF2CDAULL,
			0x9769EEAED9ADC18FULL,
			0x6D6CDD362FD8E8CBULL
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
			0x7AE63A7F88FB0828ULL,
			0x0048E7FC1AF028C3ULL,
			0x55FF413952F4F0F0ULL,
			0x664C815A6D882BF6ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x71FEECF97EB75C78ULL,
			0x663767DB95B3135AULL,
			0x9C44C8E1F07FCB77ULL,
			0x777CD09264C13153ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x6B20C8A8E1408E66ULL,
			0x90C65C7258238C95ULL,
			0x86C34F4B84244441ULL,
			0x0000F111196BB6A3ULL
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
			0x26995AEE53BECC38ULL,
			0xEDB72E35D6B6EF30ULL,
			0x1BDC2E5902C2BACEULL,
			0x75749705C62188B6ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xE102AF265A459708ULL,
			0xC751BA797BBD30F9ULL,
			0x5956C037BD396873ULL,
			0x66C64FBD52BF08F2ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF8BFD0792FDD2BCDULL,
			0x05B0DC0470E1C3F5ULL,
			0x9136CAD4232DB1CDULL,
			0x00E668BCEEDB9E91ULL
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
			0xEF1743BCDB0C7F90ULL,
			0x1E22D7D2D34CBCB4ULL,
			0x7064D65DC8655095ULL,
			0x789C777166B7078FULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xBC40271D057BF7A0ULL,
			0x9DA9103DDB5D8BCDULL,
			0x7DC70AD7A4B09EEDULL,
			0x427D45AC520D573DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x410264F92D165AFEULL,
			0x7F1297411B7C2B97ULL,
			0x0CDC707FC1BD9FC8ULL,
			0x0887E37C469213DAULL
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
			0x5EC3FD8A16078288ULL,
			0x05563DA6A1128C36ULL,
			0xB72CBCE11CF4B003ULL,
			0x40CFF76EF045AD15ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC9C4DEE962C43C70ULL,
			0x19767E8F8E57E1F3ULL,
			0x5E0FB9D788D25E2AULL,
			0x6EF669562AF9786FULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x22FA24932C12028FULL,
			0xB3E96A78F0938869ULL,
			0x0DCF8C3459ADCB02ULL,
			0x66C7D4972C646FF2ULL
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
			0x3061C2BEEF7156C8ULL,
			0x3D515A2877F49863ULL,
			0x212D7307798112ACULL,
			0x5668D64187C72B9DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD07FD37160CF5DF0ULL,
			0x6C46FC4D6879DC87ULL,
			0x713706C1A82694B8ULL,
			0x486202A267A23E86ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xA3135CBAA0C0C09FULL,
			0x4DBC0EAA206E5C8AULL,
			0x715CD4E2271F55A6ULL,
			0x4BC310B6573944AAULL
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
			0x0D8D927B342BF110ULL,
			0xE8CF2BF18FFA15EFULL,
			0x1BF9D4927A851CFBULL,
			0x750B51CF14F2CE48ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x3F464BF416CF1E48ULL,
			0xB2B6ED8171FA8B27ULL,
			0x5899E7C84D850DFAULL,
			0x65C28510FAD63874ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE76377B3B953ECFBULL,
			0x72461D5823DE94C0ULL,
			0x458ADA3D5E7E7CE4ULL,
			0x5E04EF5F623B15C3ULL
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
			0x17E0B78465F1D7D8ULL,
			0x36DB098DD6CFD3F5ULL,
			0x6B90666BC5F328C2ULL,
			0x4B20AA6B2CF2E95DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x8BFDFDEC5D086B18ULL,
			0x48181C5E2F5DF020ULL,
			0x1BCD3B357A0F9AE0ULL,
			0x53F6C9028A40693CULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x9EF883F70846B0E6ULL,
			0x13EDFA989014DB47ULL,
			0x93D836E527950707ULL,
			0x635D8065B0000E2EULL
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
			0xD4DFB272BDECC940ULL,
			0x575133EF9E73F66DULL,
			0x555FFFCF72CF0B4CULL,
			0x57A03AE0AB7A8D40ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD7E81ADC70437C50ULL,
			0x307E391BB876C471ULL,
			0x480257D383264457ULL,
			0x7A7D7D37D18DB390ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x1D42B11DD9E19A4DULL,
			0xBF43B4D0C9F85377ULL,
			0xD08C9D02FE6BCECFULL,
			0x1621815A19281D90ULL
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
			0xD2208460B062F930ULL,
			0xE18D4B6AC07A707CULL,
			0x315E3F1D407DB80EULL,
			0x502822469BC8BD7EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA531635AE973D658ULL,
			0xD927D9BEA4A3E9CCULL,
			0x489F2742A8BF9A7DULL,
			0x669260EC3014AC3FULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xECEA63476C5A9338ULL,
			0xA5D90B2D19CDE102ULL,
			0x93A295F9E8F6FBBAULL,
			0x2F6F2A80848E9780ULL
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
			0xC7B93C6777EB7BE8ULL,
			0x5C04DF886694FD7DULL,
			0x02EB15E8C481D8B6ULL,
			0x67A5479C360BAA6FULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xBEEFD08615046F08ULL,
			0xBB083D72131B2536ULL,
			0x5EF11B0F1D3FEB86ULL,
			0x6554B3FA60B0527DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x2D05B96FD99C7499ULL,
			0x784F56FA028CF66EULL,
			0x3418FDF234B856DCULL,
			0x5604D5E612B5B1BDULL
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
			0x60CF7A1BABC9D630ULL,
			0x5FCC650DDBA9A81DULL,
			0xDF8926F720AB051AULL,
			0x678005AB128758C2ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x6A9B9213F0BD0C68ULL,
			0x2AC04F95297BDBA1ULL,
			0xAC8E831D8BFB86C0ULL,
			0x4D8CBE855B58C219ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x103D768B949A3F81ULL,
			0x5DD4A002714C796AULL,
			0x6838D07F07147120ULL,
			0x13348AEDFB04A809ULL
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
			0xBD8526537C6E7CF0ULL,
			0xEE5E9196E7F64A3BULL,
			0x41E5C9C903141B09ULL,
			0x4AE10B3FDAED0DFDULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xBDCC98BFB3E05280ULL,
			0xE842DE0947B0B734ULL,
			0x81B66EC2ECB9BDF6ULL,
			0x718791FDE3E1D865ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x8AD7CFEFB53D03C9ULL,
			0xBE909823590BA25FULL,
			0x09C4D7A7A17706FDULL,
			0x4787BCBAF1CB15D9ULL
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
			0x83C2B2DD276C7D90ULL,
			0xB5386C4A29973397ULL,
			0xB02EBB479AA9EE7FULL,
			0x4FD4489AA47D7C7CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB94C2902E1C40C78ULL,
			0x23944F974249A9C5ULL,
			0x38ADC36612DDC48DULL,
			0x5B35405C9E55D788ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x2E7711769318F80EULL,
			0xD3A755124CDC5042ULL,
			0x8EA5BB1DEE3DA522ULL,
			0x742153AA46E4E9BAULL
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
			0xD64BFB5207F31628ULL,
			0x4825E0F934B8FF4BULL,
			0x21BAF1A95A937FD2ULL,
			0x72A5E3609827C3ADULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x47A2371F54B9E198ULL,
			0xFCA0C959FA899153ULL,
			0x8DE1E86C112938EEULL,
			0x75FBA157E7B8B09EULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x14510A00EF22BB27ULL,
			0xDE08A85EC7A13C76ULL,
			0x29F867B7B84D7028ULL,
			0x7B2FEF3D681775C2ULL
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
			0xF41E1200FCFC3268ULL,
			0xC57F5F3C2255632FULL,
			0x6F5B9FC4F0238BCBULL,
			0x4B46CA51592373FCULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x8E66C9EDB12E43E8ULL,
			0xB6072C0BEBEC08FDULL,
			0x5FE8D43308AFFDA6ULL,
			0x70DA1062254BFC9EULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x1ADE216AB49F566EULL,
			0x99044E9A402390FFULL,
			0x6EDEE996C4C48B24ULL,
			0x04EC38778275247DULL
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
			0x17BAFF4980B5CAB0ULL,
			0x1D3F1F7A06C3E0D6ULL,
			0x955DAA1E1B3BF2BBULL,
			0x79B7C8CC43ED483BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x181832E986C4D9C0ULL,
			0xA5F47FC154D58406ULL,
			0xF709BB79E5D404FFULL,
			0x4E0B2478BD25FBACULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x7C02285C29768B49ULL,
			0x09BBF32BF621CB38ULL,
			0x9E25BA5D40C421FBULL,
			0x614D1036FBAFA2A4ULL
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
			0x3BABF368B62BA2C0ULL,
			0x286BE1A0BBB16655ULL,
			0x746770270B0A5DFFULL,
			0x586C2C512E6CBCF5ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF962E8B8E7B997C0ULL,
			0x70AFC2FCD7E2E656ULL,
			0xC9F2CF148206FDAEULL,
			0x79E84D905715FB0AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x1E1F7AD232B9BFF9ULL,
			0x8702EA47E4457A9FULL,
			0x3EA79040FEE8E111ULL,
			0x6FF0DAB91B4C6350ULL
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
			0xBD911D387F03CA58ULL,
			0x0A8B63768B7BC6BCULL,
			0x6C3F7EEAD18A2137ULL,
			0x60D3AF397CBE6A34ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF742E9FF84BA19A8ULL,
			0x51734A4F50EAD429ULL,
			0x40ED0341E64F2635ULL,
			0x4D193880442BC7F5ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x63655A7808FD999FULL,
			0xBCC8441AA582B98EULL,
			0x3AD49EDC4EB1E43AULL,
			0x157D748C3C49B029ULL
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
			0xA482D2BBC2D4F8D0ULL,
			0xF80B19BB885A3678ULL,
			0xE5E78B261E5EB39BULL,
			0x65FB81133E2B9A67ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF24E836DD5725DA0ULL,
			0xA032D8631C2B70F1ULL,
			0x16281A9209F00E6CULL,
			0x75DBCC428701E2C3ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD164F36112321DAAULL,
			0xE902384E52250677ULL,
			0xBFF3C92E3D9BB649ULL,
			0x525D322DB16AF9CAULL
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
			0x3854921B7529E830ULL,
			0xB444CF2D06F1A8F8ULL,
			0xBA1173C65C02E29FULL,
			0x60D1ED25F7091F43ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x239D593546C0F1E0ULL,
			0x7A7A3969154D47B6ULL,
			0x9434A11200709086ULL,
			0x6B4E700AEE46E30EULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD16AFB136A3887DDULL,
			0x1FEAD71426F09FC7ULL,
			0xE41C19E366CED9FFULL,
			0x6F480045896741F8ULL
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
			0x416B8EAA9369F810ULL,
			0x16F5AFCF27103FDFULL,
			0xD74F8DF86D10FF23ULL,
			0x58492D35677BCAA4ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xCD3FE59ED4D78FD0ULL,
			0x475856B0BD504E3EULL,
			0x2701AB359C936710ULL,
			0x5507CBB16F245D79ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB34F93747D96DED8ULL,
			0xFB2DB88928586604ULL,
			0x5EB3AC50E9B9BF61ULL,
			0x00F3CE90321E3FC8ULL
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
			0x427DFD3DA32A07E0ULL,
			0x21028D16189E2F08ULL,
			0xA13920DB72752D45ULL,
			0x5AB22F5E88015B0CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x3E9395A653D1B300ULL,
			0xBC4D1BFEBE2BCD7DULL,
			0xA5814C002201D051ULL,
			0x75EB25E3F3982684ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x199E06F45DFE02AFULL,
			0x8DE461A7654BF3C6ULL,
			0xE2E722823980C93FULL,
			0x370CF83532132DABULL
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
			0x253CFB01B7C89560ULL,
			0xE892772D4CC629F2ULL,
			0x7E8A1B67A1BE8E35ULL,
			0x76C4CA32307C9A9BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB1147ABF10552778ULL,
			0x1542BD997F893939ULL,
			0xE335EDA8A212F4F5ULL,
			0x4057547BEE602408ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x1EC6F7C490022345ULL,
			0x3B8C679C87E7C7BAULL,
			0x232D8CD2285A0294ULL,
			0x7057C45B078CB435ULL
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
			0x6565A183D81E7638ULL,
			0xAFCFCB5D59A5FEFDULL,
			0xB0187B123A783511ULL,
			0x530182AC27B91AB5ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x7A09E75557F88158ULL,
			0xC046AD1E18213EFBULL,
			0xAA46A11417161E27ULL,
			0x4CC74EFD3655FFE8ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x9D3FFEF60A500500ULL,
			0x8C5F4C40FC86B283ULL,
			0xBDBB94B15B4B43D3ULL,
			0x4F3743033088CF72ULL
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
			0x00A1FB2738363F80ULL,
			0x9F8D797AC1BCD60DULL,
			0x0C6DF46B785A1136ULL,
			0x574C01D6FDAD258AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x998CD7D3F50135A0ULL,
			0x5BF07401863B38BFULL,
			0x571B6D92E6833213ULL,
			0x5D75F4F0407499ADULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE3DB59D2683E5D2BULL,
			0x3E6BEE349E8390F8ULL,
			0x32945FCD25891179ULL,
			0x283B470BE3D0A014ULL
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
			0x516254563703F358ULL,
			0x7E02CEE95B5C78ACULL,
			0xD2325420141C709DULL,
			0x6089E6D345556891ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xE6F176517A937A78ULL,
			0xF5CE4889424CBE54ULL,
			0x368B77FD9FC7535CULL,
			0x6BD2EE7216D3480CULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC09B76A867A0EB6EULL,
			0x9ACDB475EAA43EC7ULL,
			0xDE6DA1E22959E77AULL,
			0x657CCD0D84FD7506ULL
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
			0x23CB84A07928C028ULL,
			0xD18B9EC34909F7CAULL,
			0x682D6187D63D03FDULL,
			0x4BFB4605C010C9EBULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x97DCFAF42CEA1CB8ULL,
			0x9F876F779F55F92DULL,
			0x4E3FC5CB45B0BDC8ULL,
			0x7C93C71E06016CB4ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF30DCCCA04826268ULL,
			0x92EE42FD81CE32B3ULL,
			0xE9F13F84EA8DCCF6ULL,
			0x34D9D0B342C32831ULL
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
			0x080D5B3051D69D38ULL,
			0x6C287F77CBAD6562ULL,
			0xF725CB29383E2D76ULL,
			0x7769EFE4CE22A6AEULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA01E0F46B6DF3DA0ULL,
			0x7C74C0A463F379D1ULL,
			0x1F78078A4CDD89C2ULL,
			0x455E380E81B010D3ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xAC8FCB3B17B0F803ULL,
			0x0436AE55B5507285ULL,
			0x3C89966D6A793A40ULL,
			0x474A43F4ADC5D421ULL
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
			0x03D701EF6A995778ULL,
			0x1F3F0D78FA4675A1ULL,
			0xA02EA8A84283C606ULL,
			0x42C5020295E1DA03ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xE5EACEE0E316E898ULL,
			0x21B50240C3B204F8ULL,
			0x8FF6F35D548D64EDULL,
			0x46600D73261F9EF7ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xA0652D58388EA692ULL,
			0xDB9339A573E945E0ULL,
			0x1F620634EBFA92A0ULL,
			0x4D7669109EDAB8B7ULL
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
			0x602A0346AA73BCB8ULL,
			0x5BE18B3972057E67ULL,
			0x1949946F1E5581D9ULL,
			0x5E09FCE2CF410A58ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x8A44552CA42CF9D8ULL,
			0x8F38EEF4D5F3C9BEULL,
			0x66D87638D77CB8D3ULL,
			0x436A288A8E068059ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE7501B6445303F57ULL,
			0x373A07381894A3C1ULL,
			0x1C394DF23A3F8437ULL,
			0x04EC86B1C2189567ULL
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
			0x372CB0A8F8912418ULL,
			0x422FA60D9F64ADADULL,
			0xC8532AA043B612E4ULL,
			0x630F8EDE25122F85ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4BC12F18DCCDF790ULL,
			0x5316A07A90D38E20ULL,
			0x18A5D6616C1CF840ULL,
			0x4BFD3E2BE2454BB0ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x5E1F1BAA85B9E198ULL,
			0x59298D3523AA66F8ULL,
			0x604A2D38A35AC0D7ULL,
			0x214FBBAA3AED244BULL
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
			0xE2415159834B38D0ULL,
			0xC2E2255635F8AF51ULL,
			0x3CC23B23F41FDCAEULL,
			0x694D1D636FBBC449ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x3C7A01F2E548C498ULL,
			0xC0840115527E878AULL,
			0xC534F532BAF148EAULL,
			0x4BFAE6A1775ED022ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x9FB13091804FFC6AULL,
			0xAE64AC975928DA56ULL,
			0x2DF5ABFA7AC2781BULL,
			0x16C02F1CD6898D97ULL
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
			0x64EB21AE66907AE0ULL,
			0x2F3C24E87F2E6741ULL,
			0x56778B8AA74FB5F6ULL,
			0x5B095FD3323082D8ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x50002567ED25AE88ULL,
			0x83DF076DB6F3A663ULL,
			0xFA3B293E7878A414ULL,
			0x6CF874810FBCDEC0ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xCF40398620A0DEF4ULL,
			0xB828F51EF03B9242ULL,
			0xAE93CB37043F5D8CULL,
			0x7A83493471F43BC9ULL
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
			0xC4FBB14CB5073F20ULL,
			0x60508D467ABEFF25ULL,
			0xB870CB813B11AA27ULL,
			0x68EBC801DFE8F5B9ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x9559E9BFEFE1E0F0ULL,
			0x3B0922E17D3C8497ULL,
			0xD1F1F0F4E754B3FBULL,
			0x557DCB2BB68866D9ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x0644367027B177DDULL,
			0xC6439E1746BA3F25ULL,
			0xF72F1F33AC89852DULL,
			0x5E49DFA312A446B0ULL
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
			0x222C75A80837CEF8ULL,
			0xCCE86D61015FEF8EULL,
			0xE6366C1A9CD71DF9ULL,
			0x47E549FDFB399610ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x3FBC73605FD1B128ULL,
			0x659F1592B09E6AC5ULL,
			0xA44432B8D754890EULL,
			0x6D8E4C734B85A4CBULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xAA3109938123E120ULL,
			0xBB785FCA417003EEULL,
			0xA05DB56D05205457ULL,
			0x4FB1CBB1EC7E8343ULL
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
			0xD139A9198A7CCF80ULL,
			0xD3FEE3F5A9482A3DULL,
			0x93FC2305A5A9F844ULL,
			0x5BAD25C8222153D0ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x49751B24DEBE26F0ULL,
			0x2E9848DB1A0D2552ULL,
			0x8D5B0DF2FECBB726ULL,
			0x787D7C71F182BD2BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xBC0B373B8C4E9E45ULL,
			0xABCF2F38AD252064ULL,
			0xD12DACF04924E3A8ULL,
			0x13B1F79CE1AEAF1DULL
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
			0x8E7AD2ED7F561538ULL,
			0x4E0D0324E3901DA8ULL,
			0x45F2385A499C87FFULL,
			0x7FF4CB91858F1D9CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x0F6A13CF9E31F710ULL,
			0x941AD268967291A6ULL,
			0x719D1025F279E29FULL,
			0x6B96777ACC31DB51ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x83C761C11A58D26EULL,
			0x4A930881113C77BAULL,
			0xFA69D3B4F188B65EULL,
			0x4609D10C3EF71826ULL
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
			0xF5E9C27D9B99C088ULL,
			0x2D43DFA934B3C156ULL,
			0xD80AC22B678225B6ULL,
			0x4DEF29C9DF934E64ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA38B997374E880E8ULL,
			0x2EA6C01DC14E300AULL,
			0x8C464FCD6A8FE9A8ULL,
			0x613D1AAB1C039916ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x6C95939FA627D73CULL,
			0x545982F7423A3911ULL,
			0xB338C6701B52741EULL,
			0x30C1D52E816C0979ULL
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
			0xEEA7D8FA0090C8D0ULL,
			0xB0D305CF3A65B7C2ULL,
			0xF2F34345356746BBULL,
			0x411C1EC86D7B667BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4AF3D3402A3CE508ULL,
			0xB9ABBAB7186834B9ULL,
			0x96BA8C6361C23CABULL,
			0x621E997D02684C97ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x96FB70A8155CADD3ULL,
			0x8F0C7EE150BD168CULL,
			0x85849A50B9AB7A05ULL,
			0x72B2CB897807E0E8ULL
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
			0x59E04C7D738B6770ULL,
			0xEEA2B85B45CDAF14ULL,
			0xC0147B2E1CB56F31ULL,
			0x74FDE9B31E1B9562ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x5E5EB7198501EC18ULL,
			0xC62F4544AAB54580ULL,
			0x9704EE6114B9DE61ULL,
			0x7BF6786BA6FB1D7CULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE9018B84DE59EEFFULL,
			0x5A5CA1AF0D846A8EULL,
			0xC64DEFDC0A091712ULL,
			0x5C101BAAEFBBC593ULL
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
			0xB7B4E239E11B04B0ULL,
			0x5F46B41E8F520BB0ULL,
			0x5392259DC8345A53ULL,
			0x46ABEEE47393A6E9ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xE556EE7A00EB5DD8ULL,
			0xFA908B5068C9CDA5ULL,
			0x270A38A8101E0EDAULL,
			0x6B607123F2C44248ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x7ED42A3A7D173DC4ULL,
			0xA5B27BB6D945A050ULL,
			0xCFA83E1A6AC97C8DULL,
			0x4AA71F4CC76F2D66ULL
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
			0x0CC5EF74EEDB0A98ULL,
			0x395085E8299ECA40ULL,
			0xB887A83B9B64B0E6ULL,
			0x54DD2233D5C4A188ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xFFDEFCA6C91613B0ULL,
			0x0B6E54264329436EULL,
			0xB259BAF0E5A99072ULL,
			0x7A5DD51C7BAC0FE9ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x344B37A3441A44ADULL,
			0xEBDADD2814C9B0A8ULL,
			0x8E38A8B529A8DA18ULL,
			0x6099C37E7E1CBDD2ULL
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
			0x13B8BD50684085B0ULL,
			0xF9EF14385B0B0D2FULL,
			0x63BDD4CBEF2220C5ULL,
			0x66A3F6C9203F9849ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x2889A17FE9AD62B8ULL,
			0x07C5B8C9264F3875ULL,
			0x8C40514D65067042ULL,
			0x527168550379F04DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x227B68B8071074D7ULL,
			0xE25F2D9626E2A17EULL,
			0x46736A970C7830B4ULL,
			0x15C4945F55988BC6ULL
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
			0x87AA73080542E178ULL,
			0xE9489FBB5BBEF462ULL,
			0xCF7D439BFEC22B27ULL,
			0x4CEAF127F74DC012ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x3BC5D74501790B78ULL,
			0x3222FA10D3A6CC69ULL,
			0x1470B3C040E9D673ULL,
			0x47106C19CBD1DFE9ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x400267599F9BB9FFULL,
			0xDEB7FFCA86807D06ULL,
			0x3BA97FA3FA478F85ULL,
			0x6E72469FABA7C128ULL
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
			0x1A4CC712A166E3B0ULL,
			0x0525FEB98B73F8AAULL,
			0xE6A6FCCBF359DC95ULL,
			0x553E9C37B0886D7EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x6996938E8305B8C8ULL,
			0x0E2A2115C8346902ULL,
			0x37A617159608EA2AULL,
			0x495BD9EFBE24B355ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD12C67553B2BE842ULL,
			0x2CE311996D0DF073ULL,
			0x4B9DAEE9DC132D89ULL,
			0x4DA634BE64A7B8ABULL
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
			0xC885245026E4A6E0ULL,
			0x19D741710B7F690CULL,
			0xF573B7B0FD5FCA34ULL,
			0x4D0929145C441DA0ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB33C5C5E1D61D448ULL,
			0x913C4FC2CE8F86C3ULL,
			0x1CC7C6F06FD35233ULL,
			0x5195E1E3D2C5DAEFULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x7964A7C23C0FDD28ULL,
			0xFFD91B00FE487018ULL,
			0xB0999F6A2000662CULL,
			0x026EF155CFFCB648ULL
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
			0xEEA330BF893404B8ULL,
			0x4EAA76A1776D446CULL,
			0x4A2B3804A85EFD87ULL,
			0x7F78436EFAB448B9ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x3684E7D700F33F50ULL,
			0x6976EACD03C883D9ULL,
			0x2BDBAC3A05CF9769ULL,
			0x62F23181A1679DDBULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x72E89080A20CF2E9ULL,
			0xC8872E8E0C3E263CULL,
			0xEDC8AD75823A7347ULL,
			0x741CE08589CB9038ULL
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
			0x0680FC209F99C430ULL,
			0x3B164D5C897BE549ULL,
			0x23B179FE2C4E9D56ULL,
			0x589BB47355876A1FULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x18F77EF1F619D6E0ULL,
			0x98D06592624CC2A3ULL,
			0x8FDA2541C91A07B0ULL,
			0x6FCA345D456E9740ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x742990264EC26C1AULL,
			0x3B325838AE2A1489ULL,
			0x6349D6D7BB94D97AULL,
			0x5E2AD645429B86A7ULL
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
			0xDDD264D6B338DC08ULL,
			0x3E81D1AA20A40AEEULL,
			0x4F8C3AB369AF3BFBULL,
			0x407993814B749A66ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x08B0DEEEBEECA658ULL,
			0xDE1205A17643CEACULL,
			0xA519711A414E4620ULL,
			0x4D1E6B9B538B41D2ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x4AF19F370A4DB039ULL,
			0x50E1097C258A53A5ULL,
			0x7AF53F995E6985DEULL,
			0x48F6E539BD418D0EULL
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
			0x64AEA93D1BBFF728ULL,
			0x80D4983B821CBEA4ULL,
			0xCE4BD25EDE2C7CBCULL,
			0x6736550F6335A8D2ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x58EFC6047502A2E8ULL,
			0xAAB539D9CF5EEA19ULL,
			0x18BEC939E2031930ULL,
			0x6A301F8B83C450FDULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB4D41E473DE2B10EULL,
			0x5F1F0CEA34D3C1B4ULL,
			0xBDCC36ED57BEC39DULL,
			0x422A71F009C74FCAULL
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
			0x3F94E656297A7AF0ULL,
			0xB470B1970CA32E2EULL,
			0xBCFC694222EBFF82ULL,
			0x4E0AB9C996DE1130ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF4A7900A4D93FAB0ULL,
			0xEEF60EF6F4B8D3C3ULL,
			0x8ACD32F155DDB784ULL,
			0x7F89B1EB31CA137AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xBAC270C11B1CB3C8ULL,
			0x6B1CEC12519155E1ULL,
			0x72547CABFFE46B35ULL,
			0x49828133FB7B9B46ULL
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
			0x5BDA35F5F405C570ULL,
			0xD409529C1B34873BULL,
			0xFC194D4A54644FE2ULL,
			0x67457E9287B3A894ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4DECF6B7D6ED2140ULL,
			0xFB9FA6D68B1F51ECULL,
			0x27CA3C3E530B2E0BULL,
			0x48537551809A4BEFULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF7A8F950942270D4ULL,
			0x48EA622A9F30B8CEULL,
			0xB17BFECBC124D295ULL,
			0x23282E8C6B04B239ULL
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
			0x1584BDCD2219C8C0ULL,
			0x3BC277A8298F18A0ULL,
			0x87775B610BF5418FULL,
			0x72EF59BCB6BF0D52ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xCAE6655F1B2B3BA0ULL,
			0x61472A9A56700519ULL,
			0x19013741CE3BF5AAULL,
			0x7A2CEA7CE18D0244ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC2531B43AEFBCD0AULL,
			0x8AB4F41599BFF456ULL,
			0x529D1FFD90CFBE3BULL,
			0x1E098C4866161380ULL
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
			0x5F2858A6EDD90938ULL,
			0xD35735794E3AC687ULL,
			0xCA8F62CC5899D382ULL,
			0x7BB8132F51D9EFE8ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x98E1DE9CA0E39A50ULL,
			0x504D881CF7110CFAULL,
			0x1EADFB75AB5CE915ULL,
			0x67375A1C1DBA3F53ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB2352246F757C4F6ULL,
			0x2EA45FE468CE98E2ULL,
			0x38706F99A0028433ULL,
			0x7300DF32728223B0ULL
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
			0x3B12BC47A7E254F8ULL,
			0xA660C646EE988DA0ULL,
			0xB550625FA6FD29FEULL,
			0x42CD094E6F44151CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xDBBBCDAD91BB1758ULL,
			0x847B241A3090CC9FULL,
			0xDD8D17FE90AD35A2ULL,
			0x448E6CECD739E853ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x223012E6B97D92AFULL,
			0x9EF2AE770F7C3F3FULL,
			0x8F85829CB69C081BULL,
			0x47E6B70B45D51883ULL
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
			0x8435E3202BA77BB0ULL,
			0x99B29A2F4053F1BAULL,
			0x9F3097BBD3F76347ULL,
			0x59AF861DE8B9C103ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC35150ECB1EB0D08ULL,
			0xD4B41CDF4D6BC290ULL,
			0x2D52A766BF85F8E5ULL,
			0x7C1FF1900448595FULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x92930B9008C957F4ULL,
			0x3E3E0A3FD6EDE0CCULL,
			0xFC7F0AF64D1BD8BBULL,
			0x6F30F64E2EFF3C16ULL
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
			0xDF4CD556CC5E6880ULL,
			0x0ADE3F83198D5B9FULL,
			0xA2462EF9F89173A3ULL,
			0x61FF39CFB78E94D0ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xAFBB512A48110150ULL,
			0x3FA121CD3EB46404ULL,
			0x64C7C73654E0C187ULL,
			0x514E2F6B041FA39DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x62596F6701A41F54ULL,
			0xCC2BA3DC7F4962B5ULL,
			0x5E073B79B7D94015ULL,
			0x49EA1DFF6F0E045EULL
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
			0xEC70C8345D1B6BD0ULL,
			0x224985069E384FE0ULL,
			0xDBB3FD3AE3EFD88DULL,
			0x52AB13C6A281DEADULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x89644C906BBD8AE0ULL,
			0xD18B89C384D8E653ULL,
			0x0A3B7260DE8503FAULL,
			0x5B488467CEBBF854ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD85E67C7A1FD89BBULL,
			0x2520F4C88C1E3924ULL,
			0xECA13645F992BB10ULL,
			0x1DC4111F89C5F552ULL
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
			0xCC921412AE81BBE8ULL,
			0xE485EFFA31A1DDE8ULL,
			0x56D3A15CFA0E4491ULL,
			0x45978AA0A313D620ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xE38AD22AFA547B00ULL,
			0x9F3FC7D72595E1EAULL,
			0x7C659074BD2E7B32ULL,
			0x600E9D933CAEF474ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xDFD2AE2F76A42E7AULL,
			0x23B9040989E038CDULL,
			0xA6E6DDBC516392E1ULL,
			0x7AF6B0DAFE34A42BULL
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
			0x1A3CA032A1DF0B58ULL,
			0xFDD699EABC041661ULL,
			0x73FE8D494B236DE9ULL,
			0x6F92EC8E923A521DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x61C538A7B41FEA20ULL,
			0xBB4E567B515BA6C5ULL,
			0xCEEE6B3FB7347DD1ULL,
			0x468F36D0EB33AD02ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x5F09D005762BFFCFULL,
			0xA89B10FD7FB7B4FDULL,
			0x8B3B7DE2621B6CEFULL,
			0x4D0096084C32A50FULL
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
			0x415876B55454B7C0ULL,
			0x14A89F554A8F3A70ULL,
			0xA2006EBC72B5826EULL,
			0x59C8F16CFA261638ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x340334C26F26D648ULL,
			0x38DB50B9778D3E9AULL,
			0x57C4195B04527423ULL,
			0x52BB96755BAC88B7ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x2817A400A0C12CE6ULL,
			0xAEDBEB1E6559AA53ULL,
			0xEC0CDD15E1E0D418ULL,
			0x1734156E293DBEC6ULL
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
			0xBEB82A8F66176AA8ULL,
			0x74BE49A4643672F3ULL,
			0xB0C430F8D9703AE5ULL,
			0x6EA412B728E9999FULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4B0353F95DD9A698ULL,
			0x0B6D31981234E73AULL,
			0xCDFABCBA5BAD28A6ULL,
			0x5B4D092C884CD0DFULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x8AA7F22B7253F805ULL,
			0x82A11A114CD8347DULL,
			0xC1BC325951338ED3ULL,
			0x07E29D671BA6F3D5ULL
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
			0x00C66D9C0DFE2D78ULL,
			0xD7F557CEB3A386EAULL,
			0x9AC47AAFC65687D4ULL,
			0x5E062DD1C6C41022ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x35564EE63106B070ULL,
			0xD111EDA386AB1D59ULL,
			0x3781590455F1DEC6ULL,
			0x71500FD3558A75B4ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE136237251A36994ULL,
			0x5FCAB6F21AC81085ULL,
			0x9F9E6E3B7991E2D3ULL,
			0x318AE6357B42B2C3ULL
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
			0x26C7FA88384DEEE8ULL,
			0x6CD67207AC8FE6FBULL,
			0xE54FF5F944B6EBB8ULL,
			0x6A37F8E1562FD22EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x6693C89A0245BE00ULL,
			0x0EBE727FA55F0CC7ULL,
			0x73888FBABC16CC1CULL,
			0x655BBED2A1944C3DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF92C3B4FBF8D3E7DULL,
			0x46AB51B89F105EC2ULL,
			0x78406D28FBA5EA80ULL,
			0x55DA975021AA9C41ULL
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
			0xB4C7E98D793BB1D0ULL,
			0xAC97C7B4F44BB22BULL,
			0xC33BC1D71915C191ULL,
			0x69568886ED165AB7ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xAD403C460B3D2950ULL,
			0xFD6D7A6270A19C48ULL,
			0x84FF254F89773A98ULL,
			0x5FF9AE4F2C3124B8ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x36A981E40BADE4B1ULL,
			0x7C21768E1A09DC9AULL,
			0x4978AD3AC0EDE668ULL,
			0x7B17F37219CE51D0ULL
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
			0xC83583ACE83DF418ULL,
			0x0711B0C1E9C63CA5ULL,
			0xD10F628BB5F6BB48ULL,
			0x5F0BA9AE26D5896AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC17F8674C95D9C50ULL,
			0xF90D2B5FC449C0D7ULL,
			0x18C1F46638F864EAULL,
			0x7CD23BAB1D0AE66DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x8F4D581C3D47D7FEULL,
			0xDCDA5ACAF7029F74ULL,
			0xEE3A53AB7861FFF8ULL,
			0x3ADAA34DD4346EFEULL
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
			0xC1498AA18E677E58ULL,
			0x7C4504CCED75AAF1ULL,
			0xD7E57AE4A2E97AD2ULL,
			0x719FB42A38D4D3F5ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xE22806DE62062128ULL,
			0x60A3D2FAB91B406CULL,
			0x2E7250E14C3E01C5ULL,
			0x7D03490A48BE3FBCULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xA5654C8845B6274AULL,
			0x95E296B915A1D2A9ULL,
			0x04D58DD1BA29AD60ULL,
			0x2BCCD1C913A024B8ULL
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
			0x174682A6A060C478ULL,
			0x3B1730971C41F252ULL,
			0x461142D5ECDBA61DULL,
			0x63D84EE22948B088ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4BA2054A2C972600ULL,
			0xBD29C6BCC7409063ULL,
			0x9FA3A5972C5995D8ULL,
			0x5247855DA2CABF18ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xFC636338CA64DCE8ULL,
			0xE203E0DCC336DB85ULL,
			0xA88EFA84264B2056ULL,
			0x412F8D5F7DA5148DULL
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
			0x6818321AD0F8A928ULL,
			0xFF7EC11725869F73ULL,
			0x7BC9C1312FB001B7ULL,
			0x57231A73C86405F0ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA1DAAB706EC54628ULL,
			0x320BCE271D010492ULL,
			0xD256C2101108A564ULL,
			0x76F621D24F74C767ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xCED65EEFE4BBF30BULL,
			0x2638E13E7AF5BA2BULL,
			0x1F3DBDD105AD007EULL,
			0x1EF59FC8560BFD55ULL
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
			0x4CF56133BBE4E9B0ULL,
			0x86C02C559D59E4D4ULL,
			0x3A433598B253A6E4ULL,
			0x58D51D82CA256050ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x9D53040495B75470ULL,
			0xABE66626B9ED3488ULL,
			0x578B13B59526C601ULL,
			0x6C5651674977D2DCULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD0F5E12F07B68B89ULL,
			0xFA13B8D3BD409812ULL,
			0xBEB6A3C2A6ED0C6EULL,
			0x2D5FC9250B9DD5A8ULL
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
			0xF5B05709D9AA5238ULL,
			0x7358C235EC86A236ULL,
			0x3ABAFC97652D4486ULL,
			0x645058459EE683BBULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x1E8558A3CBEF92D0ULL,
			0x42ADF8AD88DCCFFEULL,
			0x5661B29F6F748B9BULL,
			0x5744EEA3BFF52ECCULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE04CADAA30070913ULL,
			0x38F7C68FE0895237ULL,
			0x4396203E8BAFA09AULL,
			0x18CC93E105965D66ULL
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
			0x3B2B3242164C3880ULL,
			0x35C5360A63142ED2ULL,
			0x48F33FF951967442ULL,
			0x76D12B8579AC8574ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x7C047D1A1DC89970ULL,
			0x330983EF7D746969ULL,
			0x34B76548CD8E4A7BULL,
			0x49DA2DC7545CB7A6ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x85C3A77F3A3E0D21ULL,
			0x7BE84FC315A58306ULL,
			0xA91D7D405EA6073AULL,
			0x1EEAE2BF6A08445DULL
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
			0xC7D3041786D624D0ULL,
			0xF26450B2D744EF64ULL,
			0x67917C105872D9C9ULL,
			0x5DD5D6193332FE2CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xE1168E50572E64E8ULL,
			0x6B0A9D2BA286C9BCULL,
			0x39B90C69D24CB538ULL,
			0x76DA5D1BF2291358ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x7A43318634B0F723ULL,
			0xCE223EF102633BE9ULL,
			0x8AC49967A2B6B3DBULL,
			0x2D94A4CD19F66F8AULL
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
			0x2264E157DF245140ULL,
			0x56BF4C15FB826619ULL,
			0xAC58071E4E2F788EULL,
			0x51A676C66CDEB8D4ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x16C02DC57F3A52C0ULL,
			0x3B8FFE7DBFF8EBF2ULL,
			0xE87D86DCC46EC38EULL,
			0x66E648E8096C84AEULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x224A9D90E431ED64ULL,
			0x6D2026D632CA4F9BULL,
			0x2F73646043EC3815ULL,
			0x20AB415D97692A33ULL
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
			0x8CBA3EDE5E95EFF8ULL,
			0x54B0C66428131527ULL,
			0xB8965F43944209F8ULL,
			0x773781A0C59BC0BCULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x32EE7D08F0515118ULL,
			0xEE60B2512C5EE1CAULL,
			0x479A69EAA25D84CFULL,
			0x53A0F26968EA0156ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x51255C8FF4C56F11ULL,
			0x94C858D5F3CB1731ULL,
			0xA437861339C261E0ULL,
			0x01FE30AC2E35A1BEULL
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
			0x3DBF00A08988C948ULL,
			0x0C9345C7CC63FAADULL,
			0x6CF926535809CBECULL,
			0x7752B8D9555804C6ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xED05E1B66FDD9690ULL,
			0xE3502C97DC9E6EA9ULL,
			0x1001FF7901A19374ULL,
			0x78FF9981C8FA296DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x7E059681091E1842ULL,
			0xCD3574BF3EFE2F41ULL,
			0xF9AEC468C2A146BDULL,
			0x44FBB3D0C0F8EEC7ULL
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
			0x4766C73ECBA05268ULL,
			0x3001945E0ABDCEADULL,
			0xAC9F4E85E515E1A1ULL,
			0x44F9B453FD6AFB61ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x174772DBCF503448ULL,
			0xA9080CFEA8777B72ULL,
			0xD12242E62410A0A7ULL,
			0x40224A3CF1D6A8C9ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xBC5233386F3EDE16ULL,
			0x0078425F4C8DAC85ULL,
			0x56A042DF5E7B79C9ULL,
			0x1B6FF4AC8C84DCABULL
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
			0x44CE4543048DE380ULL,
			0xE5E584B55A1B1F24ULL,
			0x87B7AEC38B014E8FULL,
			0x7D6288A49F13D20DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC2B44B3DE8A12CD8ULL,
			0x664B318E7E6A7C43ULL,
			0xF65F32F07D1C71B4ULL,
			0x50A26BFD92F0F481ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x92BE583F4331003EULL,
			0x48ABFBFB6CD43810ULL,
			0x169101F281D7AF35ULL,
			0x647AEEA745B07743ULL
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
			0x3F8CDACA12965CE8ULL,
			0x848653E6FCA4888EULL,
			0x2976BA1BD6FDB5D0ULL,
			0x5118BDCCB3DEE231ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x7BE51AB460E32D68ULL,
			0x32BF90623676F82FULL,
			0xCECFD1D4B88A6012ULL,
			0x5A9A32063B265CBDULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x4D8F9A8316FF4C97ULL,
			0x25A7FEFAE5A1A98AULL,
			0x34D0D5E9C8DAB949ULL,
			0x717688825F6FDC38ULL
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
			0x0BBF3D8F5F02B730ULL,
			0xF24691C369982DC3ULL,
			0xB09C0421A9FD073CULL,
			0x63F73E3E609DEB98ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x1F631BB405BE47C8ULL,
			0x28BDF0B3780ED709ULL,
			0x824A670A88A0557BULL,
			0x5AB226F7530F0946ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x69418F0E88EF5106ULL,
			0x7F29AFF4941C74E4ULL,
			0x0089517F72E21E1EULL,
			0x5858539CF8E44315ULL
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
			0x4CCC89DD83104E50ULL,
			0x6790DC585539BE34ULL,
			0x4E5D455DCAA3B50EULL,
			0x79714B6E517AADB6ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x704C340867E1D0A0ULL,
			0x5CA40F11600C9A22ULL,
			0xEABC308343EAFA80ULL,
			0x6D2D200FA85BC82AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x4F663BC1D31D2F10ULL,
			0x969E30A16845351CULL,
			0xCEB6233D770D35BAULL,
			0x35EA7FD52A14E92FULL
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
			0xECFF44A0D1C31BF8ULL,
			0xFBBB0A0D00EDB7A8ULL,
			0x8A46C86FCA9218AEULL,
			0x501E127FB13945DDULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x3F1E5CD48649E600ULL,
			0xB203DEC7E90FC647ULL,
			0x64F153C41BF20528ULL,
			0x419B4155D0326B02ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x7213CDF7C64DC6F1ULL,
			0x6114479B818170A7ULL,
			0xCA680AA6C31CB6C4ULL,
			0x61CA83B52420167CULL
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
			0x6B9DFA7B6635AE60ULL,
			0x2CF98899E1EBD7BBULL,
			0x325ACB4CA186A3C5ULL,
			0x5DECFEAA1D376E8CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF7FD5A5739E18BD8ULL,
			0xB7E5F738DF0AD89BULL,
			0xDE5303572AEE3ADCULL,
			0x4CAD48ABB5E83CFDULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x639B1B0697E0777EULL,
			0xBA67FAA749AD1D98ULL,
			0xD48EE568CA588605ULL,
			0x69AFA4F5EC0D1C94ULL
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
			0xA10EF48A2C859020ULL,
			0xBC5F20CD84137D5AULL,
			0xDFA198BF43EB5185ULL,
			0x7F962B0C5F0235D2ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x742078FB61AD2FD0ULL,
			0xF57A0FC5EFC695AFULL,
			0xDF6B714502C1BDC2ULL,
			0x433E2E914045F016ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x0FDCDBE9E4DAD574ULL,
			0x2726E63F83774FB7ULL,
			0x972BB68204AF0334ULL,
			0x6E66856ECB1ED578ULL
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
			0x79E6CB973FA28578ULL,
			0xB6AC206589A2FA94ULL,
			0xD48BEA7467B54D89ULL,
			0x5EB5CD03FD8E5B5DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA0D24F11BA783468ULL,
			0x3F90BE8B27D7C610ULL,
			0xFB83DC1C79924DD3ULL,
			0x42D215DA50A9577FULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x8DE6618797FE7FCAULL,
			0x16A41AC5D72BFA2EULL,
			0xB7BCCEE7897A12D9ULL,
			0x1EAD7324DAAE3685ULL
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
			0x623B93073D9559E8ULL,
			0x02A9E9F5CE1EA946ULL,
			0x748CC71FA8EC3957ULL,
			0x6014F7A3EDB711CCULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x232DDD31A95642C8ULL,
			0x2FADCCD320EC5822ULL,
			0xC8E42E894F192374ULL,
			0x589E0422A356618BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x63A341EACA8CA4CDULL,
			0x6CD1A27BEB753F90ULL,
			0x72A12C74264FE5EEULL,
			0x42F74E1D32C83E4AULL
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
			0xC7D0460F25AD2770ULL,
			0xC8F012C00BBAF9AEULL,
			0x9BBEEF03C1D36235ULL,
			0x52E5C112990CC7A0ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xDF7485F017314658ULL,
			0xED2845CFCB9374E0ULL,
			0x893A40F003515762ULL,
			0x53D7CF5350DAC1B3ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x5B132F2F6CEE1B84ULL,
			0x0D434BB282D8CB78ULL,
			0xA035F93809C50FC6ULL,
			0x1FE7D068534D3707ULL
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
			0x59901B6E048D1E08ULL,
			0x0712ACE72F88E60FULL,
			0x7CFB56B6062E3E17ULL,
			0x70D0FB3927D0F4AAULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x9E5DBEF4BC10D860ULL,
			0x595F90569860C132ULL,
			0xEED4D7D6A89004E8ULL,
			0x7A73A7F8C864274AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x971FCBA1314EF437ULL,
			0x86683EE58C2D067CULL,
			0x5E17CAB01A243A94ULL,
			0x30758D7F10083C7FULL
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
			0x1DD15D2FD5C04060ULL,
			0x183E3728B00C1115ULL,
			0xC8A89F20E3C1E344ULL,
			0x4548898907CD86D1ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x640969BA25E3E9A8ULL,
			0x10681297C0AAFC63ULL,
			0x3CC1F0B900CE06B7ULL,
			0x6D4A63827E6CA42FULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x1C3E752C1AE4CE52ULL,
			0x01C754BBA6736727ULL,
			0x944F84035DD4600DULL,
			0x5A65C35685994A28ULL
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
			0xA170A8629CE10318ULL,
			0xDC1EA14B82A97885ULL,
			0xAA57F01DF212BFBAULL,
			0x501CBCC6F00C8E1DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD8EEAFB8C584B338ULL,
			0x0A3DA83AB772A32AULL,
			0xE65DCCA53DA8A930ULL,
			0x62271069DC70F2DDULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x43342CFAF6D3B590ULL,
			0x025D7FB6855B391AULL,
			0x41348BB0993246DBULL,
			0x02B25D34E88F6051ULL
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
			0x52F9DDF272B85640ULL,
			0x8DBF9286A1C8419DULL,
			0xEC1FE0911B605A04ULL,
			0x53908CE3A873612EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x01571479463528B8ULL,
			0xB3E197AE36B56531ULL,
			0x452853CCA361FF68ULL,
			0x7EC9B56B3CAE1C89ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x4F90E0E147ADE33EULL,
			0x7F5CA9236308EF60ULL,
			0xB4AB271F280E774FULL,
			0x08705CE238ADACCAULL
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
			0xF5E2802EF23427C8ULL,
			0x512D13F67308F2E6ULL,
			0xD57B6B7BA13B83C9ULL,
			0x67071B975BFE7744ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xDE392E74F6873408ULL,
			0x30268FD0E6F6B42CULL,
			0xBCE277E830784E75ULL,
			0x44B55714C0835AEAULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x39AC955646550948ULL,
			0x99EE8919FF2525B4ULL,
			0x25A2EE486B8A56F4ULL,
			0x7C02AA583716A28AULL
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
			0x40A44ACAF46CC8E8ULL,
			0x1114E54E87A04A41ULL,
			0xAD72713F2E77F784ULL,
			0x6256E7320276D442ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x52C15CCD1E37C138ULL,
			0x106603A9E2C571F0ULL,
			0xC8321920716FFAB1ULL,
			0x5CE3433B093A8D95ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF88539F9B6A78DEDULL,
			0xA58018CAC64FD86AULL,
			0x7849AD06B0AD3A33ULL,
			0x3ADC422527B82A89ULL
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
			0x413A650D187D7CE0ULL,
			0xDA03BD99D4610BD8ULL,
			0x680398747559D744ULL,
			0x47D019AB17475029ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x9EE30EFCB57A2690ULL,
			0xEA3B5EAD1479FC87ULL,
			0x6D98159E0B4993E8ULL,
			0x584F16935EE59A19ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x1149378798E9C38AULL,
			0xEB51869A6066C8CEULL,
			0x3DD05CFF2054A221ULL,
			0x1279064777B702DAULL
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
			0xA15C725F6AEF55D0ULL,
			0xB8181B4F80F99804ULL,
			0xD2968739DF9446C9ULL,
			0x56B4E38C129FE9A6ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF2405DA9A12C0700ULL,
			0x364914441E87E0F9ULL,
			0x1C5B06B33265EAF6ULL,
			0x5B2DE52B5E912814ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x06486389587E9996ULL,
			0x5F0AEF0DBFCC26D3ULL,
			0x5998711BF80683D9ULL,
			0x4440994EDFBFD580ULL
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
			0x9CF98EE995E65850ULL,
			0x2723DB4C0EBA9C82ULL,
			0x1882E65085A0E4BDULL,
			0x6AC32712DD96E36CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB6C33E0EE92B43D8ULL,
			0xEA0519BCEDCD0EFEULL,
			0xA718E17F007659F1ULL,
			0x62F22E2FB6D14C37ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x396BBBBE7037969DULL,
			0x563A8B4D9487EBAAULL,
			0x17523A29CF02BCB7ULL,
			0x3C408239CA0E89E5ULL
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
			0x691DF2232617AD08ULL,
			0x1DC885D7C33735E9ULL,
			0xAEB71E1840789C2CULL,
			0x691AEFAE8D53E331ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF62B44248B540138ULL,
			0xCFFB837E5F00346FULL,
			0x1F33CFD8F3262C7FULL,
			0x76C2C31DE85F6987ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x731EE45B15359710ULL,
			0x21C52217B03D45F5ULL,
			0xEEDF75E28A6BCB74ULL,
			0x75A3A326B5C0A9F7ULL
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
			0xB662106F712B2928ULL,
			0x4C64C1083419D392ULL,
			0xE35A366B1E4E69C2ULL,
			0x7151B8F803920C03ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xECFB65713B333730ULL,
			0xB52500BA3F62EDB6ULL,
			0x5DBE1BA8BF7C9C01ULL,
			0x76989ACE1BD3892AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x83B9BD8B128620B9ULL,
			0x79E516903A306C2DULL,
			0x07F3A7CB3B32BD6AULL,
			0x03A6DFFE7CB81426ULL
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
			0xB17290E721070288ULL,
			0x8A4BF9C17508A41AULL,
			0xF528300C5D8E825FULL,
			0x423C34AC24CCC38AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xDE5CB4A88A148EE8ULL,
			0x22CC4A76E6DDEC43ULL,
			0x0D27C6D1D560FE37ULL,
			0x767297CD7E70C1D9ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xCEA490797C120D98ULL,
			0xB97C7F7D8DF7019AULL,
			0x90A41380E2A2E6D3ULL,
			0x224E1A011B0F70F9ULL
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
			0x2C1B40A44C0DEF08ULL,
			0x0401AFF976BFF498ULL,
			0x373C08C86096FF67ULL,
			0x5CA96837E1EBF537ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x8398583F2B9385A8ULL,
			0x8133C2FB81076EDBULL,
			0xCEB35E224C2732B5ULL,
			0x78895CBF0FFB2006ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x840BE27BBD119758ULL,
			0x10E4FCF150C04625ULL,
			0x4C3CB576C9DE4CCCULL,
			0x78E237D20BBF82E5ULL
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
			0xE888EBF63A3AA1C8ULL,
			0xB16229BFF41DC710ULL,
			0xA4D1E6497A7CF039ULL,
			0x444F8D50DC788757ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD647BAEFF7696B28ULL,
			0x967947EBE460A78CULL,
			0xF17EEC911029F411ULL,
			0x41AEA39A86395C46ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xAA33CBC13A480B10ULL,
			0x5320E48D60F377D6ULL,
			0x4D9C343252A6B87AULL,
			0x057F8CE9F1BC3374ULL
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
			0x2352DE3E921EEB98ULL,
			0xFF5A5AD44EC0FAAEULL,
			0x621B5B0E63E7C1B1ULL,
			0x76F8D209D00F8563ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x6DCCC049DF3BF670ULL,
			0x7AE43BC1D42CDFC9ULL,
			0x77381F02E2E5FFD4ULL,
			0x61CAAB98AFD4AA26ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x828162B5A44CF05DULL,
			0x55D1A0437CED0100ULL,
			0x228511FD124AEB8CULL,
			0x636C605CE4A758D9ULL
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
			0x11E1BF46E2488328ULL,
			0xE5C4E465030F133BULL,
			0xE5F956557E9C5261ULL,
			0x5EBC09F6FFF3085BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC732A777CA7DC058ULL,
			0x8E81C680CC10FD2BULL,
			0xC9A55AFFBF1FA466ULL,
			0x5E40A90D16FB3B57ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x139D3906D3102F4BULL,
			0xADDA8DC69B450377ULL,
			0xFA1C364EF8926C4BULL,
			0x3D654FA9D6256297ULL
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
			0x7740DF5FD6E8F108ULL,
			0x6EAF5F22635A3C9CULL,
			0xF488CE03F3A1C981ULL,
			0x73D4FAB73CE8B95CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xCE1DA95A46549C20ULL,
			0x7C1B72303E6D22E1ULL,
			0xE81DFCD400EF9DABULL,
			0x43FA917332DAC84CULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x6192803ECA4F2CB7ULL,
			0xD6F2912E12913CF5ULL,
			0xEE5DF9E124509A1CULL,
			0x5BAB8E7323FBA7B9ULL
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
			0x86D81EB7334975A8ULL,
			0xBA08346E2FB97016ULL,
			0x02684E41F419047DULL,
			0x7A267814800DCA73ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x7047D37ABFA20478ULL,
			0x4564EFCADD4A99C5ULL,
			0x3A4D38B53E8CD466ULL,
			0x5C069E190E90A910ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xEEB54AC23CD0BF45ULL,
			0xA1D285E6705F0FAFULL,
			0x599C1B9CCCC98637ULL,
			0x50F34BD2D38805E7ULL
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
			0x72A32DC4E35E6EC0ULL,
			0x6B174BBD76B64EFBULL,
			0x1ED7D882B0B908EEULL,
			0x6887F133E453757BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x51228694A23B6E88ULL,
			0x9D8F4F74BF1BCDFAULL,
			0x3F58FAF61179791FULL,
			0x55A9720444388FA9ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xADC3BF9DDFE9CEDDULL,
			0x269C9827F12C4791ULL,
			0xF093C91F2A5C9673ULL,
			0x0C0DB5C22DE70E25ULL
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
			0x6C02C909CA6AB430ULL,
			0x606873475398212BULL,
			0x8B7CEAA8E9A971C0ULL,
			0x457C1F67510A221AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x353FE477CEB73B28ULL,
			0x2007C6367D981B8EULL,
			0xD4B51AF12CFBD171ULL,
			0x5A75FDFEC2C7487EULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x8C8C0E440976EE12ULL,
			0x1FBB5A523FD61F39ULL,
			0xD0D63DD8F5EB73C0ULL,
			0x563C1F7858704BFDULL
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
			0x7AA39F52B9383390ULL,
			0xBBC014A4B9B187BAULL,
			0x54DC02CBDDF4B549ULL,
			0x7B1F5B4A2FB6E40EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xBEC1D7C287DF1760ULL,
			0x9B0A0A028B9D5563ULL,
			0xCC9C478C5EC68385ULL,
			0x61C3ECC5C57A8E12ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x95DE5E182A563248ULL,
			0x1987236EA510A8D7ULL,
			0x2F2F5A636B3AF88AULL,
			0x47CF6D89B229AF4FULL
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
			0xF4624D0A19721358ULL,
			0xCBC91EC8B6C302BEULL,
			0x57F7A046A007B6F2ULL,
			0x63CDA8618738517DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x244758AE1478BB90ULL,
			0x38A7DB51C8DB4430ULL,
			0xF76C97A7FAC5F9CEULL,
			0x70CDBAA301318729ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x93E7F39D882A5798ULL,
			0x56B84EB53FCA24BFULL,
			0xCE8B1B1A2173AF41ULL,
			0x0C939AE913F1EC19ULL
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
			0x1E7BB8CDBC226A70ULL,
			0xCF0F53738100A99FULL,
			0x399A59B4B2AEF040ULL,
			0x4208E96C573DAECBULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x780E6F00F8AABF08ULL,
			0x5478B83405641E8CULL,
			0xA6C4318B1E12FB8BULL,
			0x46B351DF1D7A7CD8ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x351CF97015474BC7ULL,
			0xE16188BE6F4B0E94ULL,
			0xA095C9389351EC10ULL,
			0x5FBE0257A0B9DAFCULL
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
			0xFA0AAFD9451075D0ULL,
			0x39F8F26EFBC69D3FULL,
			0x6FB8EFFFB124F427ULL,
			0x543B0710E06D417FULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xEB9C38CF1615B928ULL,
			0x73092FC431340B5CULL,
			0xBCE2613A13A2224BULL,
			0x693F1048AEAAD6FBULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x03C9F67062AD4461ULL,
			0xF7299D61C7743B6AULL,
			0xA665AAB45A6E96C6ULL,
			0x5351E06D813B0988ULL
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
			0x005C057BFA69E088ULL,
			0xD4A2D09FF5C48AC3ULL,
			0x68AD5DA520874F01ULL,
			0x72A9E46663DF9BA7ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x6C9D3C0FDE3592F0ULL,
			0xA55220C51F4369B9ULL,
			0xB2355DF3A7F86AD2ULL,
			0x66AB9AFDAA9B4C99ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xCEAFA2AC4E2FAA93ULL,
			0x7379D54DCBB6C6BDULL,
			0xEC93FC6302AD2122ULL,
			0x7BE0533B5E2827F1ULL
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
			0x16863D9846E66870ULL,
			0x37FA0AB60B73AE7AULL,
			0x528F5FCB428BD165ULL,
			0x5050713043C1E44CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x11F0EC84950A9BE0ULL,
			0xC58788CD18B1451DULL,
			0x800C3944B8AE43CBULL,
			0x7303B8A605F390C3ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x79DA61E6C1D74496ULL,
			0x5A60D85C5BF09B8FULL,
			0x08761F68852F1831ULL,
			0x130F0DEFAB729789ULL
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
			0x2520879C758610B0ULL,
			0x427F1C40D23E452FULL,
			0xC4F0EFE90D2C7AE7ULL,
			0x595F4000597C1F6CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB4F18F2380A7C110ULL,
			0xAA51600020A778E8ULL,
			0x68B64F93BBE1F949ULL,
			0x6731C2CBCE987812ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x43E13B1B281EDCE7ULL,
			0xDF5BF0CB3F1B8E5AULL,
			0x7BAB90B54A87CCD0ULL,
			0x727A1A69D7F8858AULL
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
			0x28F68E590542C1B8ULL,
			0xDC7E42D8C70478DFULL,
			0x430D8B142ACEF562ULL,
			0x6FFDF21E532CB75DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xE0E396E61462E3D0ULL,
			0xB2AA23AF398F6689ULL,
			0x6ACCA16C93DE4ECFULL,
			0x705FB07CE25FA525ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x6B308AFF63676ECAULL,
			0xC69ED17A3CE89B62ULL,
			0xDF95CF592F9E694AULL,
			0x0D7E651024DCE952ULL
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
			0x7114700102F82100ULL,
			0xC720F0EC36139526ULL,
			0x7BAA0FD8886882D5ULL,
			0x599D649E89847EE2ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x03B0003B2D80A610ULL,
			0xDBC4113BF542E178ULL,
			0x8DE9FDD69A571D85ULL,
			0x75FD3E9765CF7479ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x265C98605CE75F04ULL,
			0x6649AA2B5567184BULL,
			0x98B6D66D91C1D533ULL,
			0x4A8F1A85FB78E6EDULL
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
			0xD6A8A5081D360B10ULL,
			0x462F8F7DC80964BBULL,
			0x9E3F673089BB3E80ULL,
			0x4A78CB5A57A59B95ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC8545ACE96A9F350ULL,
			0xC6CFC7372D8FEF86ULL,
			0x69C1B4E4D064B65DULL,
			0x50E88B3E23557641ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD9CEC5901500A4D6ULL,
			0x0AC7058E157E1E6CULL,
			0xEA48111FC3F7A9D4ULL,
			0x2CC593CE298424CBULL
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
			0xE90E8119C5F0B278ULL,
			0xA67778E99CDCB5EDULL,
			0x87CA21427E4CA759ULL,
			0x61C1342A95720CABULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB9F4715728B2FBE0ULL,
			0xE8F4EFC312F84CE4ULL,
			0x2748A0E3B98668C2ULL,
			0x6330C2E2768697EEULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x6B201B911A85F2C0ULL,
			0x3A635F654618FBDDULL,
			0x61C45C331E09BF85ULL,
			0x6CB55ABDF5E1DFFFULL
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
			0xA3615B8A4556D5C0ULL,
			0xA766CAF2D002935AULL,
			0xA737609C2FC6F71CULL,
			0x41DCEB71877B8C71ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC5E26FCD3EDA1AA0ULL,
			0x7070BF21A6F59D51ULL,
			0x84826967E1BFD914ULL,
			0x7A5B74EDF941C7D1ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x056055AAA6449F8AULL,
			0x2594787835806029ULL,
			0x6A93AAF4675BB82EULL,
			0x685171E19B083527ULL
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
			0xAF40876DA6A5C180ULL,
			0x1F037B889BBD1DCCULL,
			0x48ABDB84C4CCA1DAULL,
			0x70E87D7E3A5D494BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xDF09D6AE0FC2FA00ULL,
			0xCB314EF7A8EB4EB3ULL,
			0x3FBEA6653AD14545ULL,
			0x6B777329039F2697ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x5EE1DE36702B85AEULL,
			0x293EFC030C50FF36ULL,
			0x316E2A10A242606BULL,
			0x494DD96D772ACCBFULL
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
			0xB2F7592108E11B60ULL,
			0x20CE897764281171ULL,
			0xDB0545DE76A7B1EBULL,
			0x723E0CE600CA405EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x60DA4ABC62135EA8ULL,
			0xC22EB36FC4E2CFA6ULL,
			0x27923EFD007882FEULL,
			0x728995F54FC612F9ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF979CF0F111517ABULL,
			0xE672E992285F6CB8ULL,
			0xF5EA080C53F2AAD8ULL,
			0x051F9D68B686332DULL
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
			0x9EEBF2C68A2ACD58ULL,
			0x003F980B36B13A6AULL,
			0xD8097CC43FA62E81ULL,
			0x49DEA437BEE971D9ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x8109ACAE325E6CC0ULL,
			0xF89AA8221F1FC614ULL,
			0x35E28655B5FA2810ULL,
			0x6F31B961EFEC3BFBULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xA25DAAEB7575E0A9ULL,
			0xFF765B54417FD439ULL,
			0xDDE466694DC5E4E3ULL,
			0x5C9CC42D103F181BULL
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
			0x910386647F29B620ULL,
			0x3B3878BF1FE3FA9EULL,
			0xE9597C0DEEA01B4FULL,
			0x7F9EAA759C344C07ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA06F523C0DCD5E58ULL,
			0x2FD19C14C84B2D59ULL,
			0xCEC275378FB803F1ULL,
			0x63DC4AD17EF71CA4ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x8C9CE1928B430072ULL,
			0xAF61F4BF298B0CCEULL,
			0x2FC581D86DD015E3ULL,
			0x7597EEDBC5EF657DULL
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
			0xA2828E81F7A913C0ULL,
			0xEEB4347F7AB068D6ULL,
			0xFAF4FBD39A59048FULL,
			0x41D60ACCE1441F84ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF1F651E18184A2E8ULL,
			0x9F5435784776C32FULL,
			0x2ED56217DB503892ULL,
			0x5F58CCC9E39F5135ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF036E7E090783EEAULL,
			0x20F32F12B09A8C01ULL,
			0x9EA94BC068A407C8ULL,
			0x5F08C2638CD44F50ULL
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
			0x6DC01A2A914AF628ULL,
			0xFB3F56800FCCA232ULL,
			0x555D1E74B5DCE79FULL,
			0x58AA8140F3795C35ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xFD27F631F8786958ULL,
			0x3FA7451A28D5FA95ULL,
			0xF5601D880321FEA7ULL,
			0x7EB1C78A7C68BEC7ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x3C04EB316FF810AAULL,
			0xCA787D49F36023C1ULL,
			0x591F690541F28BE8ULL,
			0x3818ADAE725AD2DAULL
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
			0x62196601BF5AB180ULL,
			0x2C6DA3A1B8CB49CFULL,
			0xB6DE2262EED98BB6ULL,
			0x41F086EBC25671FBULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x892B2392F3F7A608ULL,
			0x4A121CB3A7C765F2ULL,
			0xBD2915E38DC1B994ULL,
			0x63C65C77CDF275F3ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x841AC675544BE0AEULL,
			0x427D954472AADE88ULL,
			0xE5DC31D8DDCB7EAEULL,
			0x072908B254C94B54ULL
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
			0x033EA0E91EAC51A8ULL,
			0xADF8CD633FC8624AULL,
			0x51A2AD0F3136CF35ULL,
			0x7FE33C7E73820C44ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x9C3717F302550F18ULL,
			0x622E24FF69DE4C3EULL,
			0xA66AC797844ED217ULL,
			0x727B5674BD11E91EULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xA1D7B4C74563DD6FULL,
			0xFDB93C459E87A345ULL,
			0xB6D169104B7A0867ULL,
			0x0945C087E5F7CC81ULL
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
			0xEEFBD62FBE913128ULL,
			0x4A81F52EBAD80264ULL,
			0x93930E63A2AE78C2ULL,
			0x60A46B94CCCBC9ACULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x1B957549248D84C0ULL,
			0x14B2E43F2F5059E9ULL,
			0x4648F33E586FDDE2ULL,
			0x4DBF84CAF12DF81DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x109BC8A82892F353ULL,
			0x0650A394288A286DULL,
			0x57683FF0B86B6F4AULL,
			0x22025DBE31E51CB0ULL
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
			0x32D43A33AA0EE728ULL,
			0x79E97C3DCFB13B2FULL,
			0xBB9B3D22776EC480ULL,
			0x4FDCA24F31E414FCULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4E14677CD8DC4CA8ULL,
			0x28D45210133C3462ULL,
			0xD432CB20F90CD934ULL,
			0x51C49ED2293C5D1CULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x0BD2437971F953C5ULL,
			0x19F6FFD99D8FEFBFULL,
			0xD43367D6A54BF4B2ULL,
			0x47A2B9D97E0C2294ULL
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
			0x4401FE3565FE0628ULL,
			0x3505DF0406E86806ULL,
			0xF9F7E54FDC76A73BULL,
			0x4A575671449F5D22ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xFFEB1841946D76E8ULL,
			0xE3387422AFDAF5FEULL,
			0xD5FCF7A55D02070DULL,
			0x4533BF7879429929ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x779C4FC14690E5D6ULL,
			0xB7A8F4AE31031834ULL,
			0x91DA96F87480EE3CULL,
			0x409BCF5008265410ULL
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
			0xABCF031E800118E0ULL,
			0xF69C4D8085BDC57BULL,
			0x3C3D1F6A97B353F5ULL,
			0x611D84310789E97FULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xEABFAD2B44C22338ULL,
			0xD280CA25D7202CE8ULL,
			0xB49A78BA8DEE8DE3ULL,
			0x5BD4996CED16C2D0ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x14210F25F25A765BULL,
			0xB10D0CEE35A490BCULL,
			0xD98EB17CBFBF55B1ULL,
			0x5CEE06C339A6FCDAULL
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
			0x0F256D1981082D08ULL,
			0x2B678A3C1DE61AE6ULL,
			0xDF5C578CC6E25F5BULL,
			0x503DD4AC9E30CC26ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xBB68469EC2968468ULL,
			0x0317ABBFB2ACB171ULL,
			0xC080C6E3C64B0319ULL,
			0x65543ABBBB72545AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE69FE062C8AE2322ULL,
			0xD701AE03EC7B7F58ULL,
			0xADB382D2BEC85D4CULL,
			0x436CAC750300F501ULL
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
			0x32B349A02366DA60ULL,
			0xACA86DB82F18EA72ULL,
			0x77EB47F374D15877ULL,
			0x5172B6FF9BC5FB82ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x54521A1464AC0FA0ULL,
			0xC9D5BCBCE040C876ULL,
			0x31E80ADF574FCFB4ULL,
			0x53A663D22D61B85FULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x5690CEA9042B107EULL,
			0x9AF0C974F2A72D86ULL,
			0x38517353AD0A856CULL,
			0x46BC2245CF14E904ULL
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
			0x336652792CE8F760ULL,
			0x2DD126735B2F88B7ULL,
			0xBFA56C9D04C9AD75ULL,
			0x6E45C5D8ACB2EDB0ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x5CD7DFEA9BD5EF00ULL,
			0x8A453F4E3D17CCB1ULL,
			0x6C948A5FDF8D1BC3ULL,
			0x627BC4C81576CDBDULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE1F2FE25ED4DCA10ULL,
			0xF1E16C588AA6F46CULL,
			0xCCBC1E4F4791B82CULL,
			0x6D9A7A2CD97D1BE6ULL
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
			0x67B04EC9E89FB938ULL,
			0xF9F4EB5455DB830BULL,
			0xEFD4117628D6B29BULL,
			0x4128F757F7C7D199ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x6442039930EE0848ULL,
			0x38225A59C6128194ULL,
			0x5CB1C375FD02AFF4ULL,
			0x50B3AE3E7D0839CFULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x5589700DF824408EULL,
			0xA9E51BDC1406D598ULL,
			0x6F0EFFBB96CBE146ULL,
			0x7111499A7B921CDAULL
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
			0x51B6A9D093AD0650ULL,
			0x05A0104FBBE12D76ULL,
			0x6C6732C3362F3B82ULL,
			0x684BB91313922298ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB6A00DA1EC02E570ULL,
			0x064BE34DF5DC298EULL,
			0x08241F7514D6DDC0ULL,
			0x7B0AFF1F7935EA5BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x7023A7F23703F8D2ULL,
			0x654DE38B1DBF63F3ULL,
			0xBDCE513365CAF97CULL,
			0x59605C0B5DEBA477ULL
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
			0x9F47C558C5994348ULL,
			0x5FAA92060E4E6639ULL,
			0xD09C84A9045101C0ULL,
			0x7C8C870844A1460DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC32ECD78D8E024D8ULL,
			0x91F3555219F76C95ULL,
			0x5F1F9FAB003AC877ULL,
			0x5EE9807D324A81B4ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x2F0341F4E5D56804ULL,
			0xFBE760732CEDBDB2ULL,
			0xAF21CB3F04DF4AFDULL,
			0x06653BEADEAD6E41ULL
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
			0xAD5E7FC248FEA818ULL,
			0x0181779CD6E39393ULL,
			0x074FB6A7EF92FA6AULL,
			0x7352AD0F92DEB9B8ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x433D430F09BE5200ULL,
			0x9CBA2561A64C6067ULL,
			0x327AF5C7930E24F8ULL,
			0x6E2F093E5E06CD20ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB1336A818DF2F8BDULL,
			0x14905D5C58B91975ULL,
			0x7EEFBACF27C42B61ULL,
			0x09A78675B0934F6FULL
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
			0x525C58CAE621DA60ULL,
			0xB9D902EA3C08DB19ULL,
			0x51DCF6CCCDF5C81FULL,
			0x79A1799BDB5D12A0ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x1E09D030543EB9A0ULL,
			0x873CEF3CBA7BCC12ULL,
			0xFACA531090D8CA65ULL,
			0x66D20F02BA1617D6ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC494B0ABA1C71F6CULL,
			0x003B401E9CBA030CULL,
			0xDDC5011F640E26BDULL,
			0x37EFF44E377F5A38ULL
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
			0x129101F60E8B9120ULL,
			0x685211264C75DFC1ULL,
			0x668E3375E89F7179ULL,
			0x4865A421648F0CECULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB2DBA3662288B170ULL,
			0x1F3068FB9ACB1819ULL,
			0xDF10A0EDFA3A6CFFULL,
			0x48E8EF60D0600490ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x7988C7A39E84A0C8ULL,
			0xB638F0E59F1C9B86ULL,
			0x6DD51BDC5B3FC41AULL,
			0x3851FA5F5734EB7DULL
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
			0x9873C8F7900F0400ULL,
			0xD403AE0485879363ULL,
			0xDF980C6243942222ULL,
			0x5A0EC77D5B8B3925ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x3A0C5D477F9412E0ULL,
			0xA43A50237D62E66FULL,
			0x570C2E1E86A09F60ULL,
			0x7344EC499C7D7911ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xDEBEEDADD2124FF8ULL,
			0x0590D0A2B6B6822AULL,
			0xE602C32F783FFC97ULL,
			0x3CED3283AF54857FULL
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
			0xDAA302ECB1A9C698ULL,
			0xADDA7F827BE9CD5AULL,
			0xDE72FF278FFD7170ULL,
			0x56E79D64A121E367ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x5454CA0D8086B708ULL,
			0xA3A198E54E524E48ULL,
			0xD6BE3735B845A548ULL,
			0x64920A8D8D7EA91DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x979F82D6D3FC767FULL,
			0x98E46F56FA2519D0ULL,
			0xF772864DE6A58152ULL,
			0x54B1C5D79C0DC2EEULL
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
			0xCE5A40253F1DBF08ULL,
			0x5A357B491BF2B02DULL,
			0xF0C26B14E50BD760ULL,
			0x4C6BA89934951B63ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xBEA89B810918B828ULL,
			0x477B0F78E955B2ACULL,
			0x328F2DE5BCFE4018ULL,
			0x5C1B0EC0316C5E4FULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x5B55B614992AFD58ULL,
			0x4A21257CF07C8E2CULL,
			0x87C01A33B7320096ULL,
			0x5C6A2E17EB4B84D6ULL
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
			0xF06E184AEB26C240ULL,
			0x2273413DA167CB80ULL,
			0xAD4F402B53A5EFDEULL,
			0x7B1783B853EC8013ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x6EB6020AC0E68690ULL,
			0x95CCEEDE6E9889FFULL,
			0xFF72EB1980D7E3F3ULL,
			0x500D99AE722457C9ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB51F6113CF1B8E4EULL,
			0xA93841F5E20B3200ULL,
			0x1EC821AA128EFA9EULL,
			0x53E88A7834BB4398ULL
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
			0xAC14FE7959B43918ULL,
			0x24155B60819AEDA9ULL,
			0x6B364869BEAE359EULL,
			0x71B510871C1F7F07ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x7F849B4EC70C6E20ULL,
			0x6A81589C50D534DDULL,
			0x8893C23A6968CD02ULL,
			0x62899410B2405373ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF723BC6B25D6458BULL,
			0x1048C5CFAB67E1E1ULL,
			0x1203BE6DFB0395C2ULL,
			0x439C4D86B99B5048ULL
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
			0xFB61EA68F89873B0ULL,
			0xC6FA496D1A410CC7ULL,
			0x219C9687E3D2DBD2ULL,
			0x53EDA5F044713CE5ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x58403C0519375630ULL,
			0xE4A042B2E9EE6F8DULL,
			0xC799F40062AF6DCFULL,
			0x561DDDAD292E74A7ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC1FE0AB68C586FADULL,
			0xAE7C53E13A84EB03ULL,
			0xDE5F361B32084504ULL,
			0x5CDEA7F4F57973B6ULL
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
			0xF8DA8484262110E0ULL,
			0xEB7084D0BA76CC2FULL,
			0xE2A96073A43C0022ULL,
			0x6B293456675356A9ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x667196C44FB96C30ULL,
			0xFC159385DF3BF024ULL,
			0xC3CA56B0BEC1723DULL,
			0x5C15785CD8D584CFULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x4FAFD044302F8D26ULL,
			0xEE2ADD0A6733FCD5ULL,
			0xA1A7C8F5EF091E04ULL,
			0x7F1CF5F26D8DA624ULL
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
			0x9637D1AA6C6E9450ULL,
			0x6AE7721C501B2F05ULL,
			0xD213195BBFE520ACULL,
			0x49E0308F08306455ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x11ABDDEEEC4B52D8ULL,
			0x0FCEE327C59B3E25ULL,
			0x263B2C1F715B6C92ULL,
			0x59C9B6F01FC4022CULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x5E1FEED8D911E976ULL,
			0xEDA19668636B34FDULL,
			0x4DE3592FC255E307ULL,
			0x77608273FFE2C045ULL
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
			0xB929C7A6714B4E90ULL,
			0xB34C877AEBA3E3A1ULL,
			0x03D9DE1C1E4800E3ULL,
			0x41DACF0037241D00ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x2ACCD98BAD73B698ULL,
			0x011FCCD08B559870ULL,
			0x8CD2DC5DC5934562ULL,
			0x6135C95460460400ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xFF713C349B838AD2ULL,
			0xED31D639383D8009ULL,
			0xB2B15AF28768348AULL,
			0x25A3F67F641AE941ULL
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
			0xC93257B555E44568ULL,
			0xC5D41C3914BBF822ULL,
			0xF0E22244ABBB96AFULL,
			0x4AD22026642901CCULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x069451E2FFB63AB0ULL,
			0x0AF02E84C0392A45ULL,
			0x30F502C4C02D2392ULL,
			0x7C2C2FE2C83858E0ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x1DA006321D0BA7F3ULL,
			0x5956F5DAD63F6D4FULL,
			0x7CA18B1E8FDD02CBULL,
			0x28F0321390132651ULL
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
			0x1223015F5EC04CB8ULL,
			0x118ED3297F4B4A35ULL,
			0x680E3DB8978934D5ULL,
			0x6B326D6436D2B903ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x478F554978E3E218ULL,
			0x558F6F84BF9D95BEULL,
			0x8BAE889AB35D70C0ULL,
			0x6602A8DB30E1E489ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC47675D13035C7A4ULL,
			0xFF9CC6D8F985A8B4ULL,
			0x1684D4B1A2F6E1CAULL,
			0x1F700C133CD95EA4ULL
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
			0x25C95F38E9F31EA0ULL,
			0xACBC225C9239CC48ULL,
			0x7A115FFEB47F06FAULL,
			0x52FF91D28F63CC8EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xEAF9726C37C6CE58ULL,
			0x73D612D07D733853ULL,
			0x6B3C168849921ACFULL,
			0x52EAD5EC702F9A5CULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xA5780A3070E513FDULL,
			0x7F17BAEC8DBC4A56ULL,
			0x8ADB4CB527713E4BULL,
			0x72956871BDE65D91ULL
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
			0x57C9C0F23F5C5E68ULL,
			0x6F83ADA901A22DF6ULL,
			0xF81A23A80186C9C0ULL,
			0x50AF021A490168F2ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x65934332DE44C568ULL,
			0x5A5235293AFB5308ULL,
			0xF02A55F3B85BA918ULL,
			0x6320CD2B0CD30704ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD77ED0DDC56AEA6DULL,
			0x342D953F8A3AEE39ULL,
			0xE6FC104A38BBC46EULL,
			0x6941FDBDAEF5571DULL
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
			0x9FD3D3633011C478ULL,
			0xAE9BF45B4A890363ULL,
			0x3E5750C40AA041B1ULL,
			0x525DB2029828E844ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x611708A2A215C2C8ULL,
			0xC233F3D55B3EA50BULL,
			0xC08FC210DEAEB73AULL,
			0x72DE5C2875B4405BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE14E49F2666667E0ULL,
			0x7C6B0C01B7A686FEULL,
			0xEC8D60DD5792868DULL,
			0x5C2CBFFAF1044677ULL
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
			0x1878C3E43D17D858ULL,
			0x0A0B85EAF6531532ULL,
			0xB3CD481E7CC320D9ULL,
			0x494A057A9E625F90ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x27D9590E111E24B8ULL,
			0x752282F0425DDE08ULL,
			0xE875D14D966F0B66ULL,
			0x7C76626922E6FCA0ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x4CFC72A1DAE1FF42ULL,
			0xCF77C5EFC5C1426FULL,
			0x1959F0296E75F7EBULL,
			0x48161EE13D5852DBULL
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
			0xF08397C556F07308ULL,
			0x449B594D594326E4ULL,
			0x204A2526DDFE209DULL,
			0x6DEA953259C38627ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x88472663A31DF370ULL,
			0x2DC4D2F64B842006ULL,
			0x4DB5A166AF2A6025ULL,
			0x780BC642D5707A55ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x0AE283DE8254C39DULL,
			0x5D0345A3737AF840ULL,
			0xB4D4B219578A6CC4ULL,
			0x3926670C66977C31ULL
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
			0xFABD67D5726D33D8ULL,
			0x2EA5926CED9F3F3EULL,
			0x06E0ADC3C8A3C845ULL,
			0x4E607597721B5508ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x9FC99D912E20DD28ULL,
			0x17E449871E25D6B2ULL,
			0x8051657741B7FA77ULL,
			0x6FF5A5B799886FD2ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xA686576B626A4E6CULL,
			0x7CDE8BDF7FCA5A64ULL,
			0x0C76BF1E3694D428ULL,
			0x2856DC4CA33E8CF4ULL
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
			0xAD07715B56DE63D8ULL,
			0x9FC47B49B8BD9D8FULL,
			0x07CC559EFC076E2AULL,
			0x4208C86594A9944AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4F8C572D40610360ULL,
			0xC2148C4AB4D8D485ULL,
			0xAF8C8E7DE54D81BBULL,
			0x59C8BEE0875E433BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xA0F3128369C08313ULL,
			0x4AB4216FA052C8F6ULL,
			0x4AEDF3E88131B682ULL,
			0x51F839AC87C57EDCULL
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
			0x325E4C3EF0877CB0ULL,
			0x9354DCDC8C358254ULL,
			0x1BF7356C6EE6CC81ULL,
			0x50A2975FBFC7185AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4D8345C670AA5498ULL,
			0x1ED6AA1203FEA1B9ULL,
			0x7137357C85AB5C9CULL,
			0x6409CB9C9B439135ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x48C7310E7C4F89F7ULL,
			0x708F117B993617DAULL,
			0xA1731E14BD248EF4ULL,
			0x3A6CF9805FAE1663ULL
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
			0x16E6C3C446B57C60ULL,
			0x15753B2E820798AEULL,
			0xC4F706F45EA2625FULL,
			0x6106045C966C3995ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x192BCFD89F6871D0ULL,
			0x52515307A19BC99BULL,
			0x96356FA02B13FC1CULL,
			0x6936700C056E4E33ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC36748A5D618D0FBULL,
			0xD420EF65FAD1E0FBULL,
			0xAE2E625093A8E894ULL,
			0x687300BF1C060EABULL
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
			0x388D2F4184A01138ULL,
			0x0D002C8B0A57557AULL,
			0x3B684CCF8BCA3517ULL,
			0x43A2E8AC28AC6785ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x67D2C8EA10D91D20ULL,
			0xCA8A0CE6430900D7ULL,
			0xDD357E87ED827874ULL,
			0x7C00DA316CC9110FULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xCF5966006AFBCB04ULL,
			0x814834B680415F73ULL,
			0x12337C392D5C4172ULL,
			0x0966D2789E710091ULL
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
			0xE544CB6F8F711EA0ULL,
			0x8A10D0FCFD990B0BULL,
			0x7CF5ECBCFBC0DBE1ULL,
			0x6BB769F74A8A979FULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xE90BCBF6A56961E8ULL,
			0x8E10C34FB0E00A8BULL,
			0x2155FE8E93F68298ULL,
			0x41EBF604952098DDULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x1CE7E2463FEE8630ULL,
			0x69650D714FBB6672ULL,
			0x7D0B5E0DA30501BBULL,
			0x0CE3A2C53B162129ULL
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
			0x3EB184B7C30D0F60ULL,
			0x03B20939549D88B1ULL,
			0x52268ABA12B532AFULL,
			0x60F76BD4ED3D3F68ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x666D14018F1E7EB8ULL,
			0x455A18327A8C755EULL,
			0xA3FC4A3F436F1A95ULL,
			0x70B21182D00751CEULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x5E7FBB294181BCEAULL,
			0x3CDB30711CDDA6A7ULL,
			0x84971D9BEE6447A6ULL,
			0x5BF933F3F5494726ULL
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
			0x04043A90651952B0ULL,
			0x439F4A5B9A82DC10ULL,
			0x5804714C52E2A34FULL,
			0x7EBEDC7C69C70277ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x2CAF7D38F3A44258ULL,
			0xCF407AF1BD093A81ULL,
			0x5C4F6C4A73F9D07CULL,
			0x5608B1D186E9695AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x0C4499B66762E824ULL,
			0x14C649A20439ED8DULL,
			0x800F294E8E7C42D6ULL,
			0x3F262718ACF1DEFCULL
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
			0xB78581954A3C3B90ULL,
			0xC42997E670927EF0ULL,
			0x40A0A21DF114AD30ULL,
			0x4B1D304C29458FFFULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4BB7835FEC5330F0ULL,
			0xDC7C3FDB14B930BBULL,
			0xEE1253C4F4D1148AULL,
			0x6B946FBF2DC8D9E7ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x8E6E9A6C35649061ULL,
			0xFA8DB5EFE8868850ULL,
			0xD16C7A974FDFEA73ULL,
			0x18F218BB47AE1FC2ULL
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
			0x55496DA13E1A18E8ULL,
			0x55B5B73C2EE0FABCULL,
			0x2FA4CD9E1237A7A4ULL,
			0x77A1FF6C70CC4B4DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x960989B5FDA56630ULL,
			0x2B29A26501DAD04FULL,
			0xA08DA0813B3E4DF3ULL,
			0x55AD8B0568C9A2F4ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xDC5456D7186BB313ULL,
			0x7E693C050F50A4D6ULL,
			0x51062A5DB101D5A4ULL,
			0x727B1E40F58518B7ULL
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
			0x101F9EC111CAF4E8ULL,
			0x3AB4A0798FD3C9B5ULL,
			0x4B887495235075A6ULL,
			0x7F2AE930B1817F02ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xAB6CD5B94C91D1B0ULL,
			0xDAB683C398F3239CULL,
			0xC54F0A77920832B5ULL,
			0x57C1205BD475DC3EULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x93E80DC0F403051EULL,
			0x465147C453915ED5ULL,
			0xB910C9DE9ACEF4C7ULL,
			0x100326F904D22A8DULL
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
			0xAD30C4CDBC520A00ULL,
			0xC75BFA7E7727E641ULL,
			0xE497E773237AE8FFULL,
			0x5505D918D5C2E641ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x2C3E5CEB9619C8D8ULL,
			0x3BA5432CD79BBED1ULL,
			0xAFE673A13D784359ULL,
			0x7403193786A3B42DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x832713994F6A46F0ULL,
			0x815D8BD17B88D9AEULL,
			0x4C7FD3C6D671B668ULL,
			0x068C55F7C0DC16B5ULL
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
			0x05F918A7846A5F68ULL,
			0x5C88907D5B13584AULL,
			0xFB0237615ACA7228ULL,
			0x4F15D617BC855288ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x9C814EA72E900DA8ULL,
			0x73699A203B2CDE77ULL,
			0x63BBD38279103EC7ULL,
			0x5F8D6B137C31A4F1ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x7A612E9CDFF1F76BULL,
			0x52D407C8984603C8ULL,
			0x9385FF58792344B7ULL,
			0x0CD552305CBFF36BULL
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
			0xA14C46BB570BE548ULL,
			0xEAC616503316388AULL,
			0x71B8760E3216576DULL,
			0x7205420A26AE5ED0ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF849E6384168BE30ULL,
			0x9537D761ADCC1CC1ULL,
			0xF0E2AD59AFE53BDEULL,
			0x7D0A048B63840100ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF5F0D85765FA4F78ULL,
			0xA473E45CCDE31405ULL,
			0xF2EBEBC6CB5271BBULL,
			0x3E9B93459CB64990ULL
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
			0x920C1AFF6BF0AA98ULL,
			0x0B142E310A81EA56ULL,
			0xA6336AA9E835C6D3ULL,
			0x7E0DD714C39E1511ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x1E11A60805FF25B8ULL,
			0x046F146800ABE583ULL,
			0xDBE43451076D5332ULL,
			0x6117373FCDF598E5ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x98B2E3F9E2A38EE3ULL,
			0x480D26B587B15218ULL,
			0xDF0E7CC655D9E6D8ULL,
			0x5BDD6D51E959CF30ULL
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
			0xCF24416193764AD0ULL,
			0x3700F074530B9456ULL,
			0xE308D13F58C65A80ULL,
			0x4C55293B9464B0E7ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x279F1E91CF393560ULL,
			0x74A8F884539C09C4ULL,
			0x50D4D4CA37D95DBFULL,
			0x7F9EE00DBBEF2BE1ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x7DA4E851D181DAE6ULL,
			0xCECC9468C4060FBDULL,
			0x71689D663CF542CAULL,
			0x164247B7FA0691EEULL
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
			0x7BAD8270C28FEF48ULL,
			0xA56389DF0130F021ULL,
			0x2A344B6D18FFCD5FULL,
			0x6150BD5BD67DF721ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xAE533BE152A36A00ULL,
			0x7F3C3A8482CB5080ULL,
			0x0CF15C1AA82D567BULL,
			0x41C6D207D03B93FFULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xAD0CC0FBACCE7768ULL,
			0x607A985CF108D43EULL,
			0x922ADDEC691A14ECULL,
			0x4695F489D976D4E9ULL
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
			0xCB98A4BA099CE0B0ULL,
			0x44524300C6101851ULL,
			0x3003AA4EE256C956ULL,
			0x4C8DDB668802842DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x125DAE4206C65670ULL,
			0x23D35273D38B96C3ULL,
			0xA3870916CCF66626ULL,
			0x461BA8C278428E1EULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x5FEFF875FC8F8F00ULL,
			0xA0CE96B900D65F6DULL,
			0xA291760F1DF55A86ULL,
			0x467E8773A4036297ULL
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
			0xF3D65A9E15CA82D8ULL,
			0x05D565FF6B8A7A4EULL,
			0xAFD4EFF83C22A0EFULL,
			0x53C6A537D01A64F1ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF608A8B40C9E1088ULL,
			0xFDABB30054BA0C1AULL,
			0x430A79C77F05DCCCULL,
			0x6EA131D8BA73C45DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x966695D2375670FBULL,
			0x804C3B15C5269035ULL,
			0xDFED4E015DA5085AULL,
			0x44AFB1336097D1A9ULL
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
			0xA16221F47A400490ULL,
			0x859337B7AB2F7F05ULL,
			0x19F636410AFD51DAULL,
			0x6A1178155B472F64ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x023EB516B77B46C8ULL,
			0x8F51D7F29A3B7F0DULL,
			0x1B8B1D650F3A9217ULL,
			0x6D8170BA740218CAULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x348790FC45699EF7ULL,
			0xED9279A4D0D12B77ULL,
			0xDE5252D5CAFBF563ULL,
			0x15C9E152043F6470ULL
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
			0x25801181869D6168ULL,
			0xF7CA58A65540FB82ULL,
			0x726A9562315FC1DBULL,
			0x5026FF34070F6CF4ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x3C49119E81950CB0ULL,
			0x7BA1D844DCD3BA0DULL,
			0xF63FD955D1553E91ULL,
			0x5595B0FA177371FFULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x4A941D6DA43E9F7AULL,
			0xCC7F0DAE97FEDCCEULL,
			0x16B26DEF10C28154ULL,
			0x1E477698D4DF97B3ULL
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
			0x3B18D8F7FDE25518ULL,
			0x5DD3952D0B188729ULL,
			0x586AD555F0C3CCCCULL,
			0x5E182783F5BA4EF0ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xEB9C47AC99478060ULL,
			0x35A33CB16028F40EULL,
			0x6CD77E2CD7FE8705ULL,
			0x5239DD23FEA79220ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x6B8A9A46B3A9019BULL,
			0x0BF29EFC9DFD1492ULL,
			0x5D56D30809B17F4CULL,
			0x19B44EA19C2CD9D1ULL
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
			0xFE318BAEC052BB38ULL,
			0x09CC59FF0CFC3B1FULL,
			0x7E3AD2092FA176C1ULL,
			0x7F30C5E0C53EF523ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x5FD286F7A8C4C158ULL,
			0xA069DC630104F397ULL,
			0x5A080DFDBD5F30E0ULL,
			0x69080053E09B2CBAULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF9BCF131E711D55CULL,
			0xA4BE5639C0B12502ULL,
			0x53725BA240C393CFULL,
			0x62C9946112C83A5EULL
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
			0xC5FAD7CF22444778ULL,
			0x388B745B05408EEFULL,
			0x2318F0255C6516FAULL,
			0x78E58B2B7D10A92DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x58CB44144B271390ULL,
			0x8F2B9B1E67BDAD29ULL,
			0x9B45D93BC5E9B30CULL,
			0x67ACEE81327F8F56ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x42B81AF4B5946821ULL,
			0x2F33AF232BD151F9ULL,
			0xFF5FD5CDF1012764ULL,
			0x4D49CB0160A21EBAULL
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
			0xE6DF85A0CA28A140ULL,
			0xB98DA97E94B3B3CFULL,
			0x46C315DF2C3ED350ULL,
			0x639869D4FD80F885ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xFF18B499E4D44530ULL,
			0xE4F2D6DD624138BEULL,
			0x9D67055F370ABDDCULL,
			0x54322050057692D9ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x47F32515024187B6ULL,
			0xF2488CF341BC3897ULL,
			0x38A3A106B321C097ULL,
			0x38E0AD6DDE1BCBA7ULL
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
			0x9779205571D4D1D8ULL,
			0xECD00889597CFA6DULL,
			0x42BD68D20F904396ULL,
			0x791FCFF374F5E371ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x8D04EF760BF7CE98ULL,
			0xD093B8B93E8E27BFULL,
			0xF594623928E35C65ULL,
			0x59441E67F1769BC0ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE674D494577D5AA6ULL,
			0x59813DB9583C23E4ULL,
			0x4FC39F4B0849EA73ULL,
			0x09C32D658C2B8370ULL
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
			0xF4581EFFF9A11690ULL,
			0x23527049E027AE10ULL,
			0xFEF22F063508A47EULL,
			0x6C17862D74BE42A9ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD2321A33E0547838ULL,
			0x7B00663F59B52E72ULL,
			0xAE63B894F5654933ULL,
			0x50553E241A810D20ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xA4BC03099C82EE9BULL,
			0xD7F527D506822E57ULL,
			0x6C415B8BEC81DC24ULL,
			0x16A46A9000AF67ACULL
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
			0x91754C4158C63240ULL,
			0x4F2950A95BF48131ULL,
			0x166B582190E221A9ULL,
			0x489FE4D01B916B84ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x959A21E8B5C6C920ULL,
			0xC3FF4A9D49FB7D9AULL,
			0x111184EAEA2CA7D4ULL,
			0x4A6820C9FDF29167ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x1F0BF1E60BD56761ULL,
			0x79730ED5B9FB577DULL,
			0xB4A84F3D972399EDULL,
			0x2E47F5568D709135ULL
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
			0x16A4DF83C5C6B960ULL,
			0xD7F450A2D622C1ECULL,
			0x53B07E3F10A37062ULL,
			0x5200EC6A20E248F9ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC7748DC917189248ULL,
			0xBF8EE4E65DB4F36FULL,
			0x9A45B798265800AFULL,
			0x7B101E85C1D58B13ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x29411350C9ED0A65ULL,
			0x9BA3B17843BA71BCULL,
			0xA16338454E87C0E9ULL,
			0x77D3250027281A75ULL
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
			0x34FB3AFC98191E90ULL,
			0x090D33D0ED58038DULL,
			0x773B56CEF6EA9B73ULL,
			0x66BD594CD9F42654ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x9AA8E1918CC2E7A8ULL,
			0x0D73982A18507D59ULL,
			0xC8523511870C7B28ULL,
			0x4DD9FFECF682C8D9ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE810FFFBB86BE50AULL,
			0xE912303F76E72A08ULL,
			0xD0B6F7FAE6DA7FF7ULL,
			0x1E7FEFD444ECD2D2ULL
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
			0xB37A0F60FB118EF0ULL,
			0x6A95684CFDE33844ULL,
			0x21F439F1009C0D12ULL,
			0x69AB2DEFD4D8C30DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x72BE7314BE38BBC0ULL,
			0xBDC90B215330CB72ULL,
			0xAA0C0F75EF3B9F73ULL,
			0x621C1AED3B562B58ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x6DD9936A4959669EULL,
			0x3AA029F392828737ULL,
			0x73E2A1A82E9D60BBULL,
			0x09CA12182BB43561ULL
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
			0x1D977FEE2A67AA48ULL,
			0x119F82A984B103BEULL,
			0xD08BDFB98FFD93EBULL,
			0x4D8DAD6D6978199AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x527A2314E8304518ULL,
			0x1534D8666BACFD20ULL,
			0x2FFCB23AE4805554ULL,
			0x76FD8A7FC3308109ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC7FB63CF6DA09E09ULL,
			0x20C6BC456F180F47ULL,
			0xF2FFD59C0FAE049CULL,
			0x535B92CDFB76D9FBULL
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
			0xB51FCF46BB9921D8ULL,
			0xC49B1E9DAFBE6403ULL,
			0xE556EC83CE952AB0ULL,
			0x53E1C1E26C394DAEULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x1973E34E767469A8ULL,
			0xB829DD3193F46FACULL,
			0xBE9280A5DD0F4A85ULL,
			0x58F03CC560B9CF2AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC8795F64B3AAB02AULL,
			0x521B6A33E6AD4E15ULL,
			0x890BA8F148E48921ULL,
			0x0F7928600E9B2B54ULL
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
			0x9DA4462F1C5D1FD0ULL,
			0x38D48B112D3ED31FULL,
			0x9023D00C345EB76CULL,
			0x46FA50E700DC02E3ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x6FFA6E45486A7190ULL,
			0xF6558E7FA815B791ULL,
			0x02C9F447FD8B1E4AULL,
			0x73073554DEF20538ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE7EC72D225318C94ULL,
			0x29963B37C74AAF6CULL,
			0xA3484BE5A26E4EE4ULL,
			0x49EFBB6C8901F9E9ULL
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
			0x336B85CB27BB13E0ULL,
			0x40139787E62681EDULL,
			0xE35201B86351765BULL,
			0x4750F092E28144DAULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4A164058C62DADD8ULL,
			0xD1C2A67F7CD9BD3AULL,
			0xA9D636DDE3B33692ULL,
			0x5DE82E6087616197ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF96BB713976BD66FULL,
			0xC8C60E79A89CC05AULL,
			0x30C1CDC1DBBF1F2DULL,
			0x4E7FCF66A9971273ULL
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
			0xBEC2F5132193C258ULL,
			0x6468364F278586D8ULL,
			0x53B5FFD10CD1FF16ULL,
			0x4EB890A89801F592ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x250280337A4B8F98ULL,
			0xD0C82645BB553175ULL,
			0x9901593ED703082FULL,
			0x5EC22636F013D063ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x0E090D995DDA6E10ULL,
			0x0D8A7ABC05863470ULL,
			0x103CBC6EB5012A77ULL,
			0x781049DFEF8DC316ULL
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
			0x8A1D44273E930B00ULL,
			0xBDE1846A5EE70639ULL,
			0x537E2580B3B386CCULL,
			0x5A7341BE42C98F75ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x79A5F7FB152F2B48ULL,
			0xA854415E3C96AF8AULL,
			0x991B14C164B179D4ULL,
			0x6CC5B4E282AF7321ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x7A39A8D4D2D14D2EULL,
			0x2186A5DAD044F947ULL,
			0xA483EA673791C78FULL,
			0x42F5E8287296B538ULL
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
			0x0A763476840AF5F0ULL,
			0x4230ECC0676FAF82ULL,
			0xD2D70EDA85351A24ULL,
			0x638FEE942023C91EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x5B0B96DFD86BD3B8ULL,
			0xC24F9F77A4C7E242ULL,
			0xECA80D7BFE9BC87BULL,
			0x63DE4C69E60041A3ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE00390F89CF47BF7ULL,
			0xA038C89213C70B33ULL,
			0xAA09FE4480A79C24ULL,
			0x7E853232DE011EEFULL
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
			0xA86F733C361F8B30ULL,
			0x12C167A046966C21ULL,
			0xF3EFE23DDC33CF87ULL,
			0x427C81BECC24EE1CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF7A9FAB5DA116D60ULL,
			0xB7A561E021E76179ULL,
			0x4FDB0C662DAF62BAULL,
			0x71033561C3335989ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x164EC3D72D7FFFF7ULL,
			0x6054CE793FA82B5FULL,
			0x6358F0EEFB146569ULL,
			0x775FA285FF4EC010ULL
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
			0x010F52FFF9B7CAB0ULL,
			0xB035B710A1F84C06ULL,
			0xD5353CF58C08B918ULL,
			0x4551734C19F57225ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD874FA2E0DA53E78ULL,
			0xD475FF592DADF4FEULL,
			0x0019C6ECB6C3DFD6ULL,
			0x4819E4D55D19D4F6ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x7E8EE81AF252BD5EULL,
			0xCDB36DCBA4BD8334ULL,
			0x0C2E01A9789079A4ULL,
			0x0246A1760041DA3FULL
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
			0x37F7C59D3D602A88ULL,
			0xA0BAABEE93ED77C3ULL,
			0xB1B174C16003612FULL,
			0x5DF0EA71242F0A5CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB5ADE474CE6AB7B8ULL,
			0xEF6C786A20AE58C0ULL,
			0x373CF09DDE9322F3ULL,
			0x5F1F0E30986E18BCULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC7D1CD3410A87A32ULL,
			0x2D900157B7ED8A6AULL,
			0x127D06F2ECCF2B46ULL,
			0x112715D74B3019E5ULL
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
			0xC6EA3D94D2E2B590ULL,
			0x5E5B06A5A70DF93CULL,
			0xA41EB5BA5FD3248EULL,
			0x5E46C25E7972B84DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x345A647B5EA007A8ULL,
			0x182AD61FCFD0C640ULL,
			0xD74CC5DB2165CEE8ULL,
			0x729CC9232C8FDA47ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xCA0F90FB3DC9E852ULL,
			0x57577FC77D9AE0BEULL,
			0x74172B6F20CE1676ULL,
			0x70189A9BB0BEA760ULL
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
			0xF0E97476DF3D5B08ULL,
			0xAC5285509C5EC921ULL,
			0x5C05054BA744A852ULL,
			0x5105E322320733BFULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xECA7A0EEEFB0B0B8ULL,
			0xBB1BC6FB8FB77FFEULL,
			0x744C215CCB26F3B3ULL,
			0x7EDF1EC0710C0436ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x0F8DE3387BF5392EULL,
			0x4847E9E4DD370AC7ULL,
			0x31AC325344814DBBULL,
			0x73D96EE139C251A7ULL
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
			0x139205680D4CD928ULL,
			0xA7BF26895C4CD105ULL,
			0xD3FCE898D8481086ULL,
			0x6234CE7E0E251065ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x2217ADBFD89DA760ULL,
			0x4EA22521348D4393ULL,
			0x9C8F8F690B766866ULL,
			0x55FFDDE07A23B1AEULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB42ED1D90A8D1DB2ULL,
			0xD3356548AF7C3B7AULL,
			0x5D3625C8CA791320ULL,
			0x77A276FBC7D717AAULL
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
			0xCCF996FCF6E59018ULL,
			0x7EBDCA0D976D5BF7ULL,
			0xBC2E61371E1CDF9DULL,
			0x5D986D8490CECE86ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x6322F28D527AE9C8ULL,
			0x3AE67DE22DA5604CULL,
			0xE69DCDE7D01A0F69ULL,
			0x5F5535893742CAD3ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x3F8608EA53CC2AE1ULL,
			0x7AF92F65D7693F7BULL,
			0x2EBCB9FEBB8C41CBULL,
			0x6E0B838481243F18ULL
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
			0xB38C92C4D3585AC8ULL,
			0xE6AA42150BCBF4BCULL,
			0xD1A085FCDE121A25ULL,
			0x7D886B2BB6DE82CDULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x349116E0F0467888ULL,
			0x29BA314D1C670AFAULL,
			0x961FDC30577DE43CULL,
			0x687EA29C37CE93CAULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x5931D7AB68A623B6ULL,
			0x5BA5031963A2C35EULL,
			0xF3833D54E7D4DAD5ULL,
			0x7634D21D9CAE5470ULL
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
			0x631B6EF539279D58ULL,
			0x39C78C7D7C6609DFULL,
			0xE9E21A246E790BCFULL,
			0x484DBC1A266BCB2AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA27AF66A03E90330ULL,
			0x100CC641A85B1197ULL,
			0x61D98A80B2620CC1ULL,
			0x56BF01717ACF0252ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB29C4829C7CA2011ULL,
			0xB23C2204848EF901ULL,
			0x01D12AD72FAC8EB2ULL,
			0x547F0CCCB1349253ULL
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
			0xC61462EC07817FE0ULL,
			0xF2AAA822FB8562FBULL,
			0x1EDB7197AC60CECFULL,
			0x79BAF212C69F7D39ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x83CD759D30B61558ULL,
			0x4B96A9238B92CB9BULL,
			0x13788599EEB1B2B4ULL,
			0x620D99DDD1EFCD0CULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x70312AB44F41C72DULL,
			0x30EF45DF51F63D0CULL,
			0xA46146D7F26C0EA4ULL,
			0x20912EFD598BF343ULL
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
			0x05BDDF19ABB3DC78ULL,
			0x1C805ED0341A4E60ULL,
			0x3C8402612F33E1F4ULL,
			0x695DD92FA63FB0EBULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB9D01315703BA010ULL,
			0xEE7652D5DFBD6665ULL,
			0xF79F442387EB7ACCULL,
			0x6ED81DB0C50BF128ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD36DD83F367DF810ULL,
			0x70B12D67988808C1ULL,
			0x7F315DB3A398001BULL,
			0x3EC05FCFB6B03C97ULL
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
			0x19AB36A31731A2E8ULL,
			0xD28AA2E319C4E6D7ULL,
			0xAE89A25125269215ULL,
			0x66B34310EC697678ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x3E9A688E779DD9A8ULL,
			0x836DB64B5284264EULL,
			0xD95C4ED15E7F748FULL,
			0x6F90823267260842ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x06C22BB93596B13CULL,
			0xE60A805DE71C2FA4ULL,
			0x3DD006810F8F58A4ULL,
			0x07BE1B313DCAFD19ULL
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
			0x9CE49B7614608490ULL,
			0x1FC79917BF259199ULL,
			0xC20CCB9E12A4257EULL,
			0x54830CEC58520514ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x71CA827A88A42E10ULL,
			0x524FEEE86D887052ULL,
			0xBE08967266202991ULL,
			0x5B6007F32803C72BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x094D7ABAD89E75E7ULL,
			0x6EC7F594F6D33F71ULL,
			0xEF4305E4D4EDB033ULL,
			0x3C50A43D1143E92FULL
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
			0x9A6BDD3A767454B0ULL,
			0x5EBF165695372371ULL,
			0xBCF263116BDEE926ULL,
			0x4943F2EFFBDC9B36ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xCCF64B9CA05C6510ULL,
			0x0FD29ACBF024A9FEULL,
			0x3EA8311AFF7B0FC1ULL,
			0x6CE6E6F997241B92ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x23A217B97F73131EULL,
			0x0455FF837A601361ULL,
			0x04D0B9E71F5AEBA4ULL,
			0x287221085CE814F5ULL
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
			0x63B52049A6D31E08ULL,
			0xD14B3F5D18573EAFULL,
			0x20782E92478573F9ULL,
			0x6E965B60E00EE286ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB5DE5E2CA54A5898ULL,
			0xC79835BB9380F7FEULL,
			0xAE7D4F15E2CF7D07ULL,
			0x75E2C6F5F646DEC1ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xFF31C9CFC584D7A8ULL,
			0x8F830F103F4A21FFULL,
			0x4B4AE7D38E4C590BULL,
			0x0EFB01DF16FBF4A0ULL
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
			0x5635C3379523C098ULL,
			0x42798DFCDDAFDDEFULL,
			0x64F8A16C4AEA9714ULL,
			0x47A6DD1E764C11EAULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x3F31477153E0E428ULL,
			0x011E5C48237687AFULL,
			0xBE096D6D3763F009ULL,
			0x48059D00ED97DDE1ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xAE340798ED43F6F4ULL,
			0x0E1710F7F6055F80ULL,
			0x8308BB42B3CF5307ULL,
			0x366A9216C2E08AFFULL
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
			0x74CB23099E8D8210ULL,
			0xF93EEFB7D4BE230AULL,
			0xD093BCE51597D4BFULL,
			0x6202CD699EF52BE5ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x0D62A156D1CD6B78ULL,
			0x46EAFC9D6F0FEB10ULL,
			0x295CC958456177A0ULL,
			0x74CBD74472CB21D9ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xCB726E93CCCE1B1AULL,
			0x09C36BF29DED5DC1ULL,
			0xA97095F62F9EFCC0ULL,
			0x585464A20084C1D0ULL
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
			0x049FCE9A4452DB90ULL,
			0x48DC866D4C3424A9ULL,
			0x58B8B02A4CC35C6AULL,
			0x4AB93EA9F0950F00ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x359D71AD3D315D50ULL,
			0x7D6A92352C3E5099ULL,
			0xA282992DB8D64EA9ULL,
			0x50B88F9E770B0E84ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x4C1B5E96B78F63B3ULL,
			0x32EFE44F27734E55ULL,
			0xA1FA45F0D51C2041ULL,
			0x604BF338A955EC92ULL
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
			0x16114C8952683450ULL,
			0xCBE92D28C3C227FAULL,
			0xEBC6FFBA92604AACULL,
			0x6A4B691105B7FF4FULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xEB0F4D6C34EDCB18ULL,
			0x6007A746E8376429ULL,
			0x96919A7A0A5F99A2ULL,
			0x451BE10B1835EF18ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x9DCF923276024725ULL,
			0x7361D99B40A6B01BULL,
			0x03261633184ACBCCULL,
			0x2727FBD2DB4ECC89ULL
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
			0x4DC55EE15C525AE8ULL,
			0xBCCF7C48BAB00456ULL,
			0x48F886E3C3E4A8C5ULL,
			0x5C74DD12069B8CE5ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xAADC1C937FCEC950ULL,
			0x9CD4E26E1C19A88FULL,
			0x1E064F242E9930CDULL,
			0x431DC09EE3ED9A40ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x9A9F8AB732D1A602ULL,
			0x306B5400900814B6ULL,
			0xF2110A58F9B0FB23ULL,
			0x3CF856D3CC1D7223ULL
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
			0xD0DC5B3F230B96D8ULL,
			0x165D42136EE14ED6ULL,
			0x33E8DB21E34A40A3ULL,
			0x675F92F225FEBA82ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xE8057856C6F4FEB0ULL,
			0xCC322C394D3940B5ULL,
			0xB05A56DC0C435707ULL,
			0x710365755837EAD4ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC2233F62667E53F2ULL,
			0xC9326B704B63BEDBULL,
			0x4649952DBEC35EE5ULL,
			0x7EF36F576AEEEA0EULL
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
			0x0E751D964F0808C8ULL,
			0xC4E316161B242A0FULL,
			0x338A7DD2CC82A8A4ULL,
			0x5EB255153BC7D6DEULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xEED141BE9BA9C3A8ULL,
			0x312470002A50082AULL,
			0xCB1C175825FF1085ULL,
			0x61D59121796539E3ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x3D556B79104F48BFULL,
			0x0CC022F1589B5792ULL,
			0x67F63325EA4080C2ULL,
			0x7C31B37F0AF4FF40ULL
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
			0xF65DBAB85A848C08ULL,
			0x47CFEDA8EB22404BULL,
			0xAC8D37298A93AC1EULL,
			0x41D643225D63C78FULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA88F02AF29D71520ULL,
			0x5305CD04C154269EULL,
			0xC0BF60845FCF83BAULL,
			0x6599D13060315A4EULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x908CB57959A03389ULL,
			0x67EEA85CB484B48CULL,
			0x3F8956DA0CC108FAULL,
			0x4F2497CD385F9E3EULL
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
			0xE03086007F8B26E0ULL,
			0x6E593B03F6B2CC83ULL,
			0xC4794E252A21DB4DULL,
			0x7A9B10A3A8F739C5ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xEEFF3ABF3A76BA18ULL,
			0x429EB498090C89A7ULL,
			0xBCC49D91B4343B58ULL,
			0x7B8D1EF6B4988D5DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x11F078278AC27542ULL,
			0xC828D11961F4764BULL,
			0x13CB6D795139F22DULL,
			0x169FF4E73FCDA18DULL
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
			0x33997AC8C309F400ULL,
			0xE6251310539D47B8ULL,
			0x03F4EC060D4F1870ULL,
			0x682DA47399454BAEULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC5598DB2ABD504F0ULL,
			0x50C991C9ECA12E76ULL,
			0x25F3F7AA35C9AB0BULL,
			0x43249EC7F6DC83E9ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x48FBCF9BD64C6C5BULL,
			0xE4CFBE5331F915D8ULL,
			0x4195A3E8789B3BBFULL,
			0x02BDAE75CC771DCDULL
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
			0x27520268BEA9A8A0ULL,
			0x20D6272395E656D7ULL,
			0xF64496DF3769826FULL,
			0x51068F5EB988FE9DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x0FC27DCA40BBF620ULL,
			0x8583D3156200CFF3ULL,
			0x6705E51527CA2F4AULL,
			0x58B04E9F0DC76AB4ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x3F02FC3F81EC02F7ULL,
			0xF44922A38C016774ULL,
			0xCA69B39DF7A33533ULL,
			0x45741E4EA08C2D5DULL
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
			0xF8B97833A0AA1D08ULL,
			0xAFDFD9D7AC1C7C07ULL,
			0x8A4EB4E7D2B59F92ULL,
			0x4437C6AE53BFF698ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x3D31A8C4DEDF7440ULL,
			0xA1410F683F8DD0F5ULL,
			0x6C3530F2E32AF1F9ULL,
			0x718D1A1D0B9BF923ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x2B54984CA30344A1ULL,
			0x061BBBF57C6772FAULL,
			0xF5DC951DC8A697A0ULL,
			0x7B3CBED19A74B665ULL
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
			0x4A67DC768B751700ULL,
			0xD77063977D038484ULL,
			0x1727080FB1CEF7F8ULL,
			0x5CAD790A7E98EE6FULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xDDFBE61BF3E3EE48ULL,
			0x0457E6D5F5659798ULL,
			0x31A040BC0F20BFBCULL,
			0x476F9B6D79ED1999ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE14C07A606412BB1ULL,
			0xF1EA481CDCA4EC7CULL,
			0x9AE625E12C0F0375ULL,
			0x2BA0F0DFF9E7F1F3ULL
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
			0x1E1731334AB91378ULL,
			0xD148277872419B66ULL,
			0xB91ADE6AAFBC3621ULL,
			0x407B2188EFA94805ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xE9828DD4C3186328ULL,
			0x0110EC114304EFEAULL,
			0xFBEA29DF44324F32ULL,
			0x6ED690B02E334AD4ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x4B7EA5DC44083C4EULL,
			0xFD64550AC6F1F417ULL,
			0x689999533C244509ULL,
			0x40C811B26CD28DDDULL
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
			0xF3D88556496C8098ULL,
			0x5C9B94DBE9F16925ULL,
			0x241976E9B53712C9ULL,
			0x6C670FD174851C19ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x5D214A71DA9B2D70ULL,
			0x814365B101C02448ULL,
			0x065255EA4069E6DDULL,
			0x7D7DD448831A6961ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x027658EFDBE50E1AULL,
			0x2A84074DA5589071ULL,
			0xE52E173D189A7140ULL,
			0x6878DEFBB93968EDULL
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
			0xEA7983BB33418E68ULL,
			0x8FFDCA032CF11CE9ULL,
			0x6AC0240B3510F510ULL,
			0x7F272C317A75ED66ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xFF45D97500303B28ULL,
			0x2DA2D0D7642256DFULL,
			0x7D75C81DE0DB96A7ULL,
			0x552094BD4EE02220ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x09155F57E09BDCDBULL,
			0x135105705236EF67ULL,
			0x2663360AE2A99E9EULL,
			0x61048233A1F8FD82ULL
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
			0x8293D21FCC443858ULL,
			0x101B0AC9E357AF23ULL,
			0x362D813194EDBBCBULL,
			0x65C56658BB373250ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x1AB8331F0C29DFE0ULL,
			0xC34864B9E436D81DULL,
			0xF7520182304FEAD2ULL,
			0x69BB2D7E275AC38FULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x33A1A942D6881C37ULL,
			0xF547073DF1BA5488ULL,
			0x0BCE4C563A17AC59ULL,
			0x1C74786C5AC84FA9ULL
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
			0xC93B819DCDF1D500ULL,
			0xEA94760742139566ULL,
			0x63D5C88D19BFC0E2ULL,
			0x710168DA4DB356D9ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x0FB4F02C73815188ULL,
			0xEC4DCDB9DDB758DEULL,
			0x86B946D5C6281810ULL,
			0x50D0F404D1E09075ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x85E31F8E33EBE825ULL,
			0x8D0AC133F5FD75ACULL,
			0x6109867568107A48ULL,
			0x65A20244B5706AD7ULL
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
			0xAD0B86841A6F3328ULL,
			0x2D4BC7DAAF66F68EULL,
			0x4AADFE81CBFE9530ULL,
			0x532142E0FAD3F937ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x493A37E85F613878ULL,
			0x6CBD0633C0132184ULL,
			0xF09A3C80A61F8650ULL,
			0x6D8A06B83E9068CBULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x5BA2E0BFEAD79E00ULL,
			0xF13A153E05BB454BULL,
			0xE74747AE53530291ULL,
			0x6E6D3941DF2B01FEULL
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
			0x07E628D92F5D8340ULL,
			0xD23BFC44B77D848AULL,
			0xC1F9500BCF05E11EULL,
			0x6CBAD3556E102283ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA0893D6B2C91C940ULL,
			0xF826813192566509ULL,
			0x59B478066C10149DULL,
			0x47B30222926EEDDCULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xBCB595E8C075E35FULL,
			0xBC357CFDA4A2A89BULL,
			0xB7E7A0E366D80271ULL,
			0x5ECAE010739AA26AULL
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
			0xEB5652B8A7F75088ULL,
			0x0D0E744394A79B21ULL,
			0xB01E24D4758326F2ULL,
			0x6A901A7FB8396B67ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x5AD06C1636A1CB58ULL,
			0xBB5C0F4E000A2E6BULL,
			0xDEA1B8F2BF86AC86ULL,
			0x4A9A2AEBC8506A17ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x2436A3FEA31D0223ULL,
			0x30D40BF87FBA8832ULL,
			0x69D7B67B0C69FB22ULL,
			0x4C04936222881CC5ULL
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
			0x912234D24BA89700ULL,
			0x80369BE116112256ULL,
			0x42E0246A8248C41CULL,
			0x6391B76049EAB9B9ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x5A9969BEABCE1FD0ULL,
			0xE84660DDA8AA7372ULL,
			0xAD77B904CCCFE46DULL,
			0x5E91B45DDC8DF34CULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD028AE8C8E5A0DD9ULL,
			0x0B065C54FA377302ULL,
			0xAC93D17C916D9AE2ULL,
			0x2ED53EDB731B41F6ULL
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
			0xD78FBA4D311EBE28ULL,
			0xEF6E8CE982A15910ULL,
			0xD0B4566DB2EF8FA2ULL,
			0x596C655FA86E7324ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA2FECD97B31B2C00ULL,
			0xDB354E6AB8C031CBULL,
			0x4D1E9CBF4E0F910FULL,
			0x70BA4B74626F6DECULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xFD40985A815E1AB3ULL,
			0xAF3A965C9758ADBCULL,
			0xF7C7C805288F30B1ULL,
			0x331720E269F6B750ULL
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
			0x005D8998871F1DF8ULL,
			0x443D574DA281057CULL,
			0x50B5F1BFA86BCB5BULL,
			0x549A35B71D9A5BABULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x5CCD97A53AB7E040ULL,
			0x6D411ADE994F1C1BULL,
			0xE28353FC24CA4A19ULL,
			0x7478AF34F144A7C9ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x05B38B66B8930819ULL,
			0x9149D3AB5325DD09ULL,
			0x28236CDA5A0B6862ULL,
			0x1892AE4F2011D8B6ULL
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
			0x1FF3E619DBD2A7E0ULL,
			0x20756166FFD55FB7ULL,
			0x06C872690B1F3615ULL,
			0x476A14E5B8247493ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x566E9B3587606980ULL,
			0x897C007239C2186BULL,
			0x8E793753471A1686ULL,
			0x429557B30114003DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x57D6896E6BE1796DULL,
			0x1FFBF336D44065A8ULL,
			0xB98784672713B945ULL,
			0x4752FD979549656DULL
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
			0xEA15105B2F2DCE08ULL,
			0x2D10F382ECA25808ULL,
			0x77AE18CBFB06C04AULL,
			0x5B8E823A0F94ED44ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x577EA91409C5FCE0ULL,
			0x2BEDAEC365195520ULL,
			0x853B8767871170E0ULL,
			0x60471E92257E7A20ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x737C2F0DADA07C76ULL,
			0x0F4D3EC81FBA131AULL,
			0x05C05EC064DA2384ULL,
			0x7F8A8C5D58A4FAEBULL
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
			0xF30A870F05C598D8ULL,
			0xFF8ED27418475720ULL,
			0x7FC84099AA04CD64ULL,
			0x6720303E85F5188DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x0078F4BE0A60C150ULL,
			0x57D3D0F671B690EAULL,
			0x75DFB06166EEFDECULL,
			0x688DF75BA9A97793ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x694788872D405EC8ULL,
			0x5C872188633705AFULL,
			0x3582709832FD930CULL,
			0x6A5FD2A01D0D9928ULL
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
			0x8462FF0E894790E8ULL,
			0xF836B9D14C08C6EAULL,
			0x5B62FAECC74F0341ULL,
			0x41E9F0DFEA819FD9ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x578C5C55B49F9BB8ULL,
			0xA33605E3403D0000ULL,
			0x88F924B573433DBEULL,
			0x41E79B03B272516EULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB0BE9BE2D2286788ULL,
			0xD5A9118681DEC571ULL,
			0x14AEE2EDC52731E3ULL,
			0x16CF2147A3639B85ULL
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
			0x4EC7EF5E5DD2DF48ULL,
			0x899557277F1B3CBEULL,
			0x9FC658482F5E09D2ULL,
			0x6B093D465FB030E2ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4A84C23C94CEE098ULL,
			0x87F2833BC929CF0FULL,
			0xB400E4E0AB15FC39ULL,
			0x5CE52D20E67702A3ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x112A16469F4F061CULL,
			0x85ED75CE572198C9ULL,
			0x6987021446CB7101ULL,
			0x0ED6340B87DBB22FULL
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
			0x12F770519DC82198ULL,
			0xD13947DC9A26E279ULL,
			0xD149DC073A270E1EULL,
			0x4CE7E5D6319411E4ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4670AF1ADAC71738ULL,
			0x404A959F6A487F28ULL,
			0x822F5FDAE16F1619ULL,
			0x716EBB5FEB4C4D9BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF78BF845A9D5D243ULL,
			0x0EB8B8F4C39C08C4ULL,
			0xCA91A585983F5CD6ULL,
			0x320BE2D6823EE9CAULL
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
			0x9A7C2FF7993DF998ULL,
			0xFA7C6E8133C80DFDULL,
			0x9D44C4CE9B2EFE83ULL,
			0x67C0B671ADB94804ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD39C83A084219D68ULL,
			0xA94FA766DE4961FBULL,
			0xB0F1B02664025DC4ULL,
			0x4E9A32393AD74C57ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x1C446C739934761CULL,
			0x1A24D6A61C413B37ULL,
			0x9A4311186D1C880CULL,
			0x2A045A79088D2428ULL
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
			0xC66322A8A8701FF8ULL,
			0xA5DD5D4481310E4DULL,
			0xC71C555EC702C8B6ULL,
			0x550B039AB1479B54ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x175A1CD29B3B6F40ULL,
			0x46C1457CE0F8986FULL,
			0xCE1DD075668BF6E6ULL,
			0x70C5AFBBADAB3CA8ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD523F61F77B2A5BAULL,
			0xB4E8C15B235F920BULL,
			0x4B8816C54ED2A6BBULL,
			0x2ACAB5ED3EB669C6ULL
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
			0xA60A427A1DB740A0ULL,
			0xDBFF1FB2205D5B58ULL,
			0xFB78472EF9E65CEFULL,
			0x6383F1B02BBED085ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x9673560DB3860F98ULL,
			0x851B6147F352A7F3ULL,
			0x630377302B8C993BULL,
			0x79874B30BBF7926FULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x14E621AE29F79BF2ULL,
			0xBC790C3061662916ULL,
			0x77CA9B3B7CF6EE6BULL,
			0x048924ED3E6DA871ULL
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
			0x8071DF592EB6B358ULL,
			0x898EF719F3762060ULL,
			0xA7F9D00121DA5184ULL,
			0x57ADD0C968040EC9ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x43B177AFBEC923C8ULL,
			0xF7594188E9C45903ULL,
			0x20C1B31DB94EC085ULL,
			0x661F1D5778305A48ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x92F3BAA19AC5D654ULL,
			0x7FF3CB94A2DA5EC1ULL,
			0x3227D4BF39370B5EULL,
			0x136C7837881C0103ULL
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
			0xFEF18429B3265970ULL,
			0x82C0019778949C66ULL,
			0x098418F7B5D34BAFULL,
			0x7E27626E8931FA65ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x6464D684FFDB6768ULL,
			0xC210D84280BF1D49ULL,
			0x72F657399975FBE0ULL,
			0x64DC5686DF4C5045ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x1D8038794DE5D68FULL,
			0x49C48A252C3591F8ULL,
			0x82813C71D0BBC714ULL,
			0x32E44DE767026AAEULL
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
			0xAA71B67533058D00ULL,
			0x3E6D86EF7ACC9CEEULL,
			0x1AD4AEE0E1EF933BULL,
			0x6062851F837858F2ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x9E4438FB87BC92F8ULL,
			0xC05A6DF2AA4FE2DFULL,
			0x77D22F56BD20B4BAULL,
			0x4FFE21A71ECBF2B9ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x2B5DD15691C79B54ULL,
			0x48B89BDF2A6F6CABULL,
			0x0DFDC2F8CDB878E1ULL,
			0x51CD5D7C997725FAULL
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
			0x13A03CD52FCA9F68ULL,
			0xFCD633BB55425ECAULL,
			0x3E05212F5A88E2B7ULL,
			0x588726B224CC12A6ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x451090C661CD87E8ULL,
			0x58FE120648958F91ULL,
			0x3513067864C28FDCULL,
			0x5D8AD7A3E5867149ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x1DC13D1086BC149FULL,
			0x3F59AF7D0312999EULL,
			0x2962642270885116ULL,
			0x0080AD117D7F62A4ULL
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
			0x5A5C9C96B948DB60ULL,
			0x6CBB921319AEDC6BULL,
			0x552F7BFD43FD607EULL,
			0x63CDD0AF12F1CA88ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA3F4CBC2431080D0ULL,
			0x915D9DEE817402F7ULL,
			0xF4C0503EF8FAF5CDULL,
			0x7F895BB7128616A1ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x18B811A600FCFD4DULL,
			0x251C826693AE6C15ULL,
			0xF0AB29D240701286ULL,
			0x478A6D2C767BB31AULL
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
			0x55F1C5168360F688ULL,
			0xB818B51B30E6CF4BULL,
			0xE07F88E2FD9AFC83ULL,
			0x46A3373543FC6BDCULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD9F018F841E73B10ULL,
			0x0A6F5CF806827E78ULL,
			0x1C25BEFA96DDB385ULL,
			0x7C5A1CF2A634EF3CULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x41985EAE8879DC79ULL,
			0x91E988B8B880ADE6ULL,
			0xF80983E7CF30AC1AULL,
			0x63E069B098B9BD4EULL
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
			0xDD69BDD6A5E7E3F8ULL,
			0x822AF588BACD26ACULL,
			0x2D9BBA4AE7641E93ULL,
			0x659E52947666BA11ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x94B399A21C458F00ULL,
			0x38D5A9CCE034E038ULL,
			0x32A3F37D59EF3338ULL,
			0x7D56FD39DD0F0C35ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x60CF39F68366824CULL,
			0x9690859C82CCD331ULL,
			0x7D43786BE974B9A0ULL,
			0x006FCB48FFA65EB6ULL
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
			0x8B8D609D6BFA61F8ULL,
			0xC9D6DBA21375045FULL,
			0x998C1D6D30498F9FULL,
			0x72594A382DC5E94AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC374B33AB8284120ULL,
			0x78ECBFECA7461913ULL,
			0x9F3415161A1A0CFBULL,
			0x4C4765044E3CE7E4ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC5421FA9251A36E8ULL,
			0x65B7A0493C396DF1ULL,
			0xAEAC5D58D042B82DULL,
			0x6C68C6C9B6BA0A89ULL
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
			0x4E9F4B499A1F3AE0ULL,
			0x0508EBE51EE9DCCDULL,
			0xB67CA17C247E689AULL,
			0x43F575838E213F40ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD9833CC8343AEC18ULL,
			0x11BD93E9F9B1033AULL,
			0x2B3837A31D548FCFULL,
			0x5357EDF7D07AA43AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x9F39E5624740386EULL,
			0x6066DF8C81C4C8D4ULL,
			0xDB15B235B7E4FED2ULL,
			0x6CBF6E98425DE8FEULL
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
			0xFF53B2FF14FEF860ULL,
			0x00062A51EB963A14ULL,
			0x83FA295C7C52BFB6ULL,
			0x69B5958A6FC6A203ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x8161C41804356F58ULL,
			0x0F999F9296118A74ULL,
			0xC27181493BAC05CAULL,
			0x55695E154D731028ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x87E8E5C0F9711E7CULL,
			0x75945450845F1913ULL,
			0xE02C68BC649F689CULL,
			0x65E98B7CFA9C2280ULL
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
			0x130EA4FF3CF628C0ULL,
			0x92ADCA75D34F08A5ULL,
			0x9D204F8E302C19A3ULL,
			0x618222488D8E6662ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF5F1CC9253A5FCE0ULL,
			0x4BDD6727C2CFC747ULL,
			0x2147383E27DDC0F6ULL,
			0x6FD9F594B05AA923ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x0624682B6E11041BULL,
			0x8D491FACF79DD489ULL,
			0x6F2A48C6106DD874ULL,
			0x13146FA6D2BE2070ULL
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
			0x8C20B86D5A8D9400ULL,
			0x147C2CC7106483CBULL,
			0x6A63E405F8E682F4ULL,
			0x5F180EDEFD9D1388ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA2199BDF5FDAD2F8ULL,
			0xEB84971137B9333EULL,
			0x699AD0D95B7E7ED1ULL,
			0x65F5EADE8A70DEDEULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xDFAFA30A9CBD6F2EULL,
			0x1C6130584D8CB930ULL,
			0x0B1FDB3744E608DBULL,
			0x583ACFDB1F25E80EULL
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
			0xDD36E7C75FDA5238ULL,
			0x37329FE74EA2DBE1ULL,
			0xA2EB371DCB9ADBC8ULL,
			0x6BB1B3C5DFF9BE55ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x04CB3E5F58D28B28ULL,
			0x8A29333C3A971742ULL,
			0x4CD43B4556381921ULL,
			0x4046CA3656B7956FULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xA725109A9C8B232AULL,
			0x0AA395B15A151534ULL,
			0xEEC493AE5685B8B9ULL,
			0x7A04BBADE774D807ULL
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
			0xA9A8B8518DF0A2B0ULL,
			0xD47BE7FF77734569ULL,
			0x4DA5581EA37AD023ULL,
			0x65C819695C9E92ABULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF0768FB53A9D8330ULL,
			0xDD9B127FF2111091ULL,
			0xC8F0D1EB15106834ULL,
			0x6E09B1D44547CE05ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x5A3E305A12FEBD2BULL,
			0x7E32A8F0326295BAULL,
			0xAB2723F3EA3C6878ULL,
			0x136D7AD5083CC584ULL
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
			0xB377FAC049A2BE80ULL,
			0x3DCBDF6A381ACE9CULL,
			0x9DEB3B9E9CAB93EFULL,
			0x56FD16107CD0DAB6ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD3B45565CECAB220ULL,
			0x9DE4D95C6E51DC42ULL,
			0xFBDEF4F5A65175F2ULL,
			0x6EB87FAEAD22030DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x51C831DF6C893E7DULL,
			0x8777645A82380D55ULL,
			0x0423928F7A853DF8ULL,
			0x289C647E65D1C8BBULL
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
			0x017BD8EB73C649E0ULL,
			0xE46299F7A8495D33ULL,
			0xFC6DF63DA23397BBULL,
			0x53782990FDE46AE1ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x295F9A57F05972E8ULL,
			0x14C13E4049EE37A7ULL,
			0xAD15B245374D4A75ULL,
			0x6004F7C1DAAE49F4ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xA5D78B0A2243E3DDULL,
			0x523B259CD2E796A0ULL,
			0xE7DC2CE7D5FED92AULL,
			0x45D038A8F92EC1D7ULL
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
			0xC31CBAE28D75EDA0ULL,
			0x7D44032A2D00E5B5ULL,
			0x21D54543DE43F072ULL,
			0x4FD8C68EC47B2EEBULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xBC6DD41191EC14C8ULL,
			0xC9B99FB3E8A13B63ULL,
			0x70DB1C35CECD71B7ULL,
			0x507B44BCAA8F5AA6ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x7018708BE7DCF1F9ULL,
			0xA9F6176F0F3E45FBULL,
			0x64A7F18E43DCF65AULL,
			0x2AB086A081043A82ULL
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
			0x0E1F7B887BAF34F0ULL,
			0x38C4DFF211BC7BB2ULL,
			0xC70BAFEE901402EDULL,
			0x5C774A231B6CCECAULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xFB4B8AC910324408ULL,
			0x813E1A5B8B106DE5ULL,
			0x7038E51BBBE9F43FULL,
			0x75DE7BB0733A6FA1ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD749E126C31D621BULL,
			0x5747E7FD59116939ULL,
			0xAF3486032D046CADULL,
			0x4B70AACEF559DA53ULL
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
			0x1D7586ED8D9A4D88ULL,
			0x3043BE4DBBE1FE70ULL,
			0xE69649FE89E06DEBULL,
			0x79AFF57464B3EA7CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x8107EB01C95CC0F0ULL,
			0xFD07C4E8B014ABF6ULL,
			0x86CCD4DF43662A57ULL,
			0x7B4EF6C4F504E371ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xBCF5151BC4BBD3B5ULL,
			0x938D8F3A8E42875AULL,
			0x12A8F4EE9F53E51FULL,
			0x75FFC50882833178ULL
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
			0x14DBE06609F63B48ULL,
			0x3488EC0ADC347AC4ULL,
			0x102520677B31020CULL,
			0x6761DC7C7E8632D8ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x22C49DBD32BFCDD8ULL,
			0x3430C7A9F4FD2673ULL,
			0x1B68DC70F090979CULL,
			0x5D685DB7FF9CFEA7ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x765E57699358265EULL,
			0xA78AAE790F33FC9EULL,
			0x7F91CCA1BBD63375ULL,
			0x1D9E9C00E8C961C9ULL
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
			0xE8D47DEA5FA54D50ULL,
			0xEA265AEC49BD77EFULL,
			0x24E332469D97DFE4ULL,
			0x7AB1503262A762C8ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x6876E2E277DAABA8ULL,
			0x82985A952DE3DE9AULL,
			0xC08643017800DD81ULL,
			0x420E54DD252A033DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF2A84A4B6B3A8101ULL,
			0xC0AEC8313D9FAFD1ULL,
			0x62D98C4DA59D724AULL,
			0x78A51DD49248A6FFULL
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
			0x760A7EBDD3663820ULL,
			0x38E8C2E7C91ACBFFULL,
			0x29228D9F2C6935AAULL,
			0x501F11E311538631ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF319B61DCE1F2FA0ULL,
			0xC6B09227AC36E528ULL,
			0xDE409AC188875B3FULL,
			0x62B2FA780D237EDBULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x32EFF1ED7C37B598ULL,
			0x8A1BA1C0E1908765ULL,
			0xC81272AE1F5D28BBULL,
			0x55C2326DFCE6B561ULL
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
			0x45BE4BA447543A90ULL,
			0x0D61BBF2D671E58AULL,
			0x6492D7F2858737EEULL,
			0x6C5694A280BA9C28ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xEA5D0847A52A95C0ULL,
			0x664BF55F259DD7BAULL,
			0x09781E67EABFB884ULL,
			0x6C2022EF06233C07ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x547A97A2556C1CA8ULL,
			0x93162763D362C2E2ULL,
			0x467A188224A8621BULL,
			0x17BD50EBFF902632ULL
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
			0xEBB8EBE9D277DE48ULL,
			0x70BC14D15702AEC6ULL,
			0x44F555B4D58EAFDDULL,
			0x4FCECCE464F36394ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x91BEB3407002A0F8ULL,
			0x219A65C25A37F183ULL,
			0xD96AC163CF56FB17ULL,
			0x7364F172BE9E1146ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x272FE36D092E9A8EULL,
			0x67F427783B5F6BD9ULL,
			0x4420326BD0A75182ULL,
			0x36ED6794CE0FB867ULL
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
			0x127757CC9050F7F0ULL,
			0x0EC28B98118DA3FCULL,
			0x31E302DA64857704ULL,
			0x66122723316859D8ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x36DD66C473E560C0ULL,
			0xA29CC205FA35D1F4ULL,
			0xD3D6B7A822655AFAULL,
			0x545D8E5A6F3BF35EULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x8D2C6648CDE67941ULL,
			0xBA060ACF23A7EA9DULL,
			0x200D0A268EFEC344ULL,
			0x787BD4BEEC37E819ULL
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
			0xC0993F85131FB180ULL,
			0x057965FEB2D667EFULL,
			0x9D6542366EED2C7CULL,
			0x4BC3FD30D73C9A9EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x718CC7B9BA049678ULL,
			0x53EE51B7DE2385A4ULL,
			0x2F631B6C99BAE7F0ULL,
			0x5B21F2AC07C6B990ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB9C9AB32BD90B7D4ULL,
			0xE7660FF8AD1F694BULL,
			0xDF60D0AE2FA30436ULL,
			0x69FB38B187B7E7FDULL
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
			0xE871698DB90DE2A0ULL,
			0x58940EC06F9BD1D2ULL,
			0x3BAB72E46DD39CABULL,
			0x4BF1B01C8F5AC281ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xE157CE8476A025B8ULL,
			0x4E00451018E22E4DULL,
			0x30084B36C283BCBDULL,
			0x55863670DFED1BECULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD54A6B1079D93396ULL,
			0x73825D3E5296A82FULL,
			0xBD20BE23AE6DB684ULL,
			0x7240362205A4EB0CULL
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
			0x69B9C5C533FB64B0ULL,
			0xB3CB15589FC067EAULL,
			0xECBC42985DDBF7BBULL,
			0x7D66A88FC54C590BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF573DE2C6C771E48ULL,
			0x4D49B2C56D45A3B6ULL,
			0xD189D95B62A8ED2EULL,
			0x46974A86CFF011BAULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xCEB70075F8F21727ULL,
			0xAE312521B2D8117DULL,
			0xF5883019406DB750ULL,
			0x604C90BF4F30F433ULL
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
			0x214469FAAD84FD28ULL,
			0x679F6DC85AA0201DULL,
			0x62B81427EC92E103ULL,
			0x74E092808CE6A49EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xEE1418909EEF5568ULL,
			0x33D37D01DB598634ULL,
			0x489DD5F148B3C014ULL,
			0x5B89B0D89ED88D13ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE16A067354A9F508ULL,
			0x038036763FB63420ULL,
			0x520241783B42D5CEULL,
			0x64D80D23F99386E1ULL
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
			0x74DA4A250AE0CBD0ULL,
			0xF8951F43B6D37DBAULL,
			0xF5A58A8DA9E9632FULL,
			0x7177CE9652304C79ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x0941EA7F41889B98ULL,
			0x349A7591748E2FC5ULL,
			0x5B7E8A7A0AACB6E8ULL,
			0x5228F43A609345F6ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x797AD90C939EE363ULL,
			0xFFB4FBC26DEE84C5ULL,
			0xA925092A1C5BF58BULL,
			0x26C574A37B06EF27ULL
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
			0xB7B8170E339D1788ULL,
			0xB2F6052DECED7C48ULL,
			0x3F6A3C4C0F00C46EULL,
			0x5D5E15EA02BDA7B9ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x1A72AC11737F6B40ULL,
			0x3763CDEC4A8304CBULL,
			0x0FF5562ED52B6495ULL,
			0x62BE8401085DA28DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xBCF3FEDB10834D33ULL,
			0xF07F38DE053D5054ULL,
			0x5DC4F25E6FDD8943ULL,
			0x746E5F5799465CFEULL
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
			0x910BCD4CC8A94948ULL,
			0xDD9F87FA58ED7E7BULL,
			0xCA000F06D42E0395ULL,
			0x74310AB354DEF787ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x5DF81EF67641DE58ULL,
			0x6987BF9122FB60B0ULL,
			0xC230D174C21E1B8EULL,
			0x7806D8DF25A99451ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x3E1633D4E9C946E4ULL,
			0x898E0C259C398E69ULL,
			0x2381F0F61268E7E2ULL,
			0x4F9708FB4665E03DULL
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
			0x729BA6C198B07558ULL,
			0xBBEC4CDB40A54DF4ULL,
			0x523F830B07E0D21AULL,
			0x49FEB00781B1E4BAULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xFA08A3EE546631D0ULL,
			0xF7173B437BD80AEAULL,
			0x40EBD9DCCD2ECEDCULL,
			0x5811632347515F76ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE80ECE3945923150ULL,
			0x3FD6BE28ABDAEF0FULL,
			0xB72E0514943DB0B2ULL,
			0x62A01189B513C16AULL
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
			0x1DCCF0ED8A62F3F0ULL,
			0x05082D4C1F4E43C6ULL,
			0x7AEDE6DBFF8FC6C5ULL,
			0x7D12C181A18E3AE5ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF6337BE628711068ULL,
			0x1EA1AD8C230569D2ULL,
			0x35C066C41DAD256EULL,
			0x6DC6EF4954A45E8EULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x4243DE32386168C7ULL,
			0x3CDB092D8DDD2EA4ULL,
			0xE95B3AC4A4CAA567ULL,
			0x26B0506C8FA61894ULL
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
			0x958F31DF13241A68ULL,
			0x2AADE448D7E878E6ULL,
			0x9A71DA29D72A6488ULL,
			0x75C186675490B012ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xBF58F007E6980CE0ULL,
			0xDCF6335A137497B6ULL,
			0x0EA180BFE35CB90EULL,
			0x6DB9C2F86945BDD4ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x0260689FDF13E659ULL,
			0xDE485C53B8D86CF4ULL,
			0xCA2226BE0F9D7A8EULL,
			0x3D5D4A0BE8955FB0ULL
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
			0x0D88F1F5FD1FA338ULL,
			0x487C96E8BF117696ULL,
			0x68B8FB72D3C2E09CULL,
			0x60E509B41B43BFBFULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4C1962F10C885C98ULL,
			0x56FD43236245FFCFULL,
			0x47E8DB561E6EF49BULL,
			0x6D6F5062D74CB660ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x3074B21A9130B401ULL,
			0x0DDD15233B795CB3ULL,
			0x66F948AE07756D02ULL,
			0x0CE2180507F77494ULL
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
			0xBBF792A231A26E70ULL,
			0x996305FE84C2DDC6ULL,
			0x4245A1865171553AULL,
			0x6EE8633D5F7AA4C2ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xCDA9F420791ADEA0ULL,
			0xD8C648EA297381F8ULL,
			0xF42CDAFB153EE8B8ULL,
			0x59B27BD50F1E25B4ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x7C6BB2A0C7DE62D4ULL,
			0xCD14114805B60638ULL,
			0xFC73D55B7567BBC4ULL,
			0x69F3E5CE1A89F4B8ULL
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
			0x870C593D6C323AA8ULL,
			0x90009821F86C884CULL,
			0x848A3D279E67D04BULL,
			0x488B44C12448A0A5ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x6F6823E1E9907488ULL,
			0x62CF2100A61415AEULL,
			0xEF0BDCDFB28E8172ULL,
			0x75A869FBDD7C98B6ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x5D4F7A57A09D9DD4ULL,
			0xEE9EA79AF1A4B1BFULL,
			0x62592A8E264E6251ULL,
			0x0AFB4FA51D6A9244ULL
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
			0xBAB608565D6A3338ULL,
			0x79FBD165F3A5A6E0ULL,
			0xCA5187EAB7945965ULL,
			0x58BB443D45C6E17CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x97CB3D03E5A69738ULL,
			0x73E2D0A400F3DFE9ULL,
			0xF68D6F9D9D06CCF4ULL,
			0x618970D357826F84ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x60905F1B6C792510ULL,
			0xA50058D7841E482CULL,
			0x251FF15DB3D4FAADULL,
			0x4FDF015BDCD4413AULL
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
			0x95E41C7309B91A00ULL,
			0xD986EDAE0997468FULL,
			0xE17708EE5AAED98CULL,
			0x74AD13D69E40D46AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x0C89B422CFB33100ULL,
			0x5C3F0AC29D017F27ULL,
			0x277ED65A273BC7F4ULL,
			0x5926356679BB9E17ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x10E2B5CF4E80A808ULL,
			0x1927A9DF4E7A5222ULL,
			0x93E6B387A32C72EAULL,
			0x58A5258F0B3D8E20ULL
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
			0xC024A20D19371160ULL,
			0x9CE64D94FB8DC29FULL,
			0xC45B5C6B17FA2F05ULL,
			0x471A77B50D635D4EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x861C61C692D8AC30ULL,
			0xF04C635D0176BB43ULL,
			0xFAFE70ECA1800AC8ULL,
			0x514AB0741E7B3E6AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x41108177AEB9B936ULL,
			0x4A0B9D47E97EEAC3ULL,
			0xDFAA28EF88C284A5ULL,
			0x609B0ED31BF048EFULL
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
			0xCFB7B31A1D019E98ULL,
			0xF258347B2518E65AULL,
			0x0A878E70B0891E08ULL,
			0x6DF14102E4504F93ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB7E76FF9498E9440ULL,
			0x56D087DEC4A4FD09ULL,
			0xD9C9752EA5CDB2ACULL,
			0x69595915759A2014ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x9208E66C6E411792ULL,
			0xFC0E57B966B13B68ULL,
			0xEF66B96D6B8DA06BULL,
			0x3B06349AC4BC4E08ULL
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
			0xD428DE6E852CD918ULL,
			0x1FF5BB292FD1B1E6ULL,
			0x80BBA477F6D65DE1ULL,
			0x4EDD41CBF428AA4DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xCFA3EE84297F1730ULL,
			0x1E0A802A7233EC2AULL,
			0x5FFDD29C149B5FC7ULL,
			0x76B6DBBD203B39E5ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB7C416694A461B96ULL,
			0xDA9E2C599D051BA7ULL,
			0x76D46A8403373525ULL,
			0x1A3F2F88219EDF24ULL
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
			0xE8F2460AAA3520E0ULL,
			0x187A511AFDB5DE75ULL,
			0x2BA60D1F6526BE0AULL,
			0x65F842544799F136ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xCE99B20B390A07F0ULL,
			0x43FB664310901435ULL,
			0x72018287B1AF80B3ULL,
			0x4A68FDC5EA2FAC28ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x02956A8E73C253D1ULL,
			0x6B4DB662BB1CB56DULL,
			0x1AF34DFE74D26F92ULL,
			0x4243AFD579B4FC6DULL
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
			0xEE75EA5554819EE0ULL,
			0xF26450A2B7551262ULL,
			0x8CF5E20237D34E5FULL,
			0x59DD986AD81463ADULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB8CA529B8D929A38ULL,
			0x39FBEA599D5E9D4EULL,
			0xD2AD9A68B6DA21D6ULL,
			0x45E54A65D5BB0E53ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x363E09249E2FB8CBULL,
			0x40B4CDF4FF32C4E3ULL,
			0x15604E869F208D5DULL,
			0x21C13FE59E000CCDULL
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
			0x6B75515632B1B378ULL,
			0xED29C40551A622EDULL,
			0xA4AB9C6310960F99ULL,
			0x610B556B6CEDE989ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA0D2B9685D99B340ULL,
			0xA5FF79AA694D4F3FULL,
			0xDFDF8F0A8B0C7946ULL,
			0x68869CD38623DCA9ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x1C6B2927290D5752ULL,
			0x7DCBFEEE2D06735AULL,
			0x9F35AF278EA06E72ULL,
			0x4038024CBE725EBFULL
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
			0x377B8CFEA1E88758ULL,
			0x17AFB4F6C227F8CAULL,
			0x00851A266A714502ULL,
			0x70E7BD9CA78D9785ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB132863EE50D7210ULL,
			0xCAEDC6D89C78F940ULL,
			0x1A6B2DAA6BB2994DULL,
			0x657C22F78A5A16BFULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x039C07C15A65CF9AULL,
			0x6650180B7724E55AULL,
			0xC65B6F84138F54C3ULL,
			0x745523A20E636FA1ULL
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
			0x3D3100853ED70560ULL,
			0x1A069F0BA916FEB9ULL,
			0x904771F658C3BD70ULL,
			0x5D1F9B402BEA7C6AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x1EAF1637FC7CA0F0ULL,
			0xC12AA772C3147558ULL,
			0x743500B718D9AF80ULL,
			0x5626366C6C893C04ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x065266E3519E449AULL,
			0x6EECD9C1011D67C0ULL,
			0x61B46AD9606F372FULL,
			0x0FA1922FE9D8799CULL
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
			0xB5F7DA2CBD869D60ULL,
			0xDFDDEB8AA32F5AB9ULL,
			0x52C1DC5929F9F1AEULL,
			0x7F246E98F240F497ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x3FFF9304F41592E0ULL,
			0x4EA171CF564D5CD2ULL,
			0x38B9E23717655A0FULL,
			0x72AF730408F7BACDULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB3EAFE068D9147EFULL,
			0x5072BC874832BC43ULL,
			0x30527E83EF5C4C95ULL,
			0x69CFD6D8374AB473ULL
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
			0x1990D982B5B8CC10ULL,
			0x653810C8463C8BF9ULL,
			0x92F6F3104D6AACD3ULL,
			0x496B0B082C0CD63DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x43B1DC5AF1D80D70ULL,
			0x9EE28A0860D15A6BULL,
			0x06A0CE98AB010E65ULL,
			0x47169FE361362ECBULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xCACF9BF4B4A97EADULL,
			0xDEC4A4AC6FFA8C96ULL,
			0xEB2EC699AD48F18FULL,
			0x4F6D286CE0261BB2ULL
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
			0x035D818A54FE3C38ULL,
			0x6D7116385D4C23B1ULL,
			0x08E0221588DF3FB1ULL,
			0x4895ADC0ACD0A00AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x8BCFF3E9B9754AB8ULL,
			0x72C901FFE37DFE3CULL,
			0x6DB6FD6D27B4A1ABULL,
			0x40AAFF513D5D6C1EULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD1AC1CD419D56CBFULL,
			0x5140A0FCE4B2C4CCULL,
			0xD1D18EB971FE6E45ULL,
			0x183BFB0AE72F1070ULL
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
			0xFF2AD9BBBB34E5B8ULL,
			0xD7CC53B0C680A671ULL,
			0x7165304B498A1280ULL,
			0x6EE986AA856E042BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x119F820BEE146870ULL,
			0xA5AAC1E240636361ULL,
			0xD4F935E9D369CC64ULL,
			0x4DADE85B8DB6B852ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xA7C55DFD12804A9AULL,
			0xB896BD75F1A1EA6CULL,
			0xEA3C26F13056AEA0ULL,
			0x6A66B82A71DB0A1AULL
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
			0xDD3C6DDE7EB103D0ULL,
			0xA9E5A01ED7D93463ULL,
			0xB9FE9D3439983034ULL,
			0x7ECA122DF4DEA17EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x43B2F0C37AA46E18ULL,
			0x0865CDF3A615DC29ULL,
			0x6C19113D948FB443ULL,
			0x4E2D7D87F4D988A2ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xA29411F9F184E820ULL,
			0x4C8AF848F82DC549ULL,
			0xD9EC013BFABD81BFULL,
			0x7C833F1CD2B8F943ULL
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
			0xF342394C01AC4300ULL,
			0x1EB55D8FB922485BULL,
			0x2872D6E0172BD033ULL,
			0x685CE663AC215F1EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xFB71D00A535DCD80ULL,
			0xB57A68A9A9E5BC3AULL,
			0x9B32C477423EE6A6ULL,
			0x450D18E436A512F6ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x54B782729A29F797ULL,
			0xA358C80FF20CAC99ULL,
			0xF109EAC4C72977D1ULL,
			0x6D03131BE5967AA7ULL
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
			0xDA28716FB0F54270ULL,
			0x27FF265A68BD8DDBULL,
			0x6DC3F61D9EEA330AULL,
			0x646D14452CF05993ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA198089CF3706C38ULL,
			0x135BE49821EABA42ULL,
			0xB45028CF8CA2FF1CULL,
			0x7149093884840C53ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x3472A2A67021A722ULL,
			0xC88C4A4C13BB65D1ULL,
			0x2D6A09063A2C3AEDULL,
			0x189D03B5DD775EEBULL
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
			0x8B3E668BB3464278ULL,
			0x1CF44A753D0E95DDULL,
			0xB81EDFB07356E086ULL,
			0x71156042709E0C99ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x7FB69ED66DC905E0ULL,
			0xC3CCE1F3E4527936ULL,
			0x33CCC0F466A1ED43ULL,
			0x4D50DC96CCC4233AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x7808778E7ADC7E3DULL,
			0x01357E560CFB39D9ULL,
			0x778A726EF19FFD42ULL,
			0x32BFDA765DA5A677ULL
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
			0xA5B98DCB0B5A6658ULL,
			0xA40DA2C534F63FC2ULL,
			0x4F22D6C378566C94ULL,
			0x494A3254DE914803ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x58873B8199D23A98ULL,
			0x5E3569DCC9E34202ULL,
			0xF45972684B1D2E71ULL,
			0x7D36C977153A882DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x1312DAE37C8ACF68ULL,
			0xBF27429CB84A75ADULL,
			0x2761098402781DE3ULL,
			0x13B6E3582636FD4FULL
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
			0x7AD64DA83F443800ULL,
			0xAB3CFC54D6491BA0ULL,
			0x8C05CA2FE5858F97ULL,
			0x6940E1AFC8EE0385ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB7C29DF8FC15CF60ULL,
			0x168DA81775C47985ULL,
			0x807AF4DB832BAB7AULL,
			0x6253D252447A4041ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x5A3EA65B3CA47A5AULL,
			0x6BD1B1C82C8262C0ULL,
			0xAD77C2A593880A87ULL,
			0x74404DAFB7E5B964ULL
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
			0x06C699691BF81200ULL,
			0x91074A11837AF51CULL,
			0x44E3B2756893439DULL,
			0x704711E92729D6A8ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x70C7F456876612B0ULL,
			0x313503077CF2D755ULL,
			0x73D86B1316B1039BULL,
			0x62689671CFD63D4CULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x3B1407C2315135CEULL,
			0x27F91F628A79184CULL,
			0x0CFB56B82F07DFCEULL,
			0x7031C8DDF1B19FE0ULL
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
			0x020F45327FE95C58ULL,
			0x0B2CB250CD4EBC62ULL,
			0x5471E49B981EBF28ULL,
			0x7239BDB6EDDF6388ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB7895819D4E7D6C0ULL,
			0xD9F13D77443B0A85ULL,
			0xC02C9571D11DF347ULL,
			0x6F381229B5DA5D51ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x09A0D549FC15EAD0ULL,
			0xE27CA84FA2711D78ULL,
			0x7A3FB9673AFDA0E5ULL,
			0x6FC9753E32B512D1ULL
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
			0x6AD53048DCBAB388ULL,
			0xC72E552055A2AA67ULL,
			0x33C890DC38EC5660ULL,
			0x6457AC15D85B0F1EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x49F70A1D942A73E0ULL,
			0xDA81958B21DA19AEULL,
			0xB6674E112E8862BCULL,
			0x6D41E13A5CBD682DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x6F24517DC9AADC94ULL,
			0xECBCB13373561FFDULL,
			0x06F77492AFB99F41ULL,
			0x287F7551514EC4F6ULL
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
			0xA162730FCE15F1B0ULL,
			0x0E62CEE9EAA92047ULL,
			0x1C4173B019B13B0DULL,
			0x4F5834DB1281EB17ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x568BDE36C6AB5400ULL,
			0xA074E96FD07A3821ULL,
			0xF324613BC4C216ABULL,
			0x411C37BDAFFC7B0EULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x2EF73BEE0D6824CBULL,
			0xF772AF8C31225285ULL,
			0xED0CEC03141297D8ULL,
			0x7ABC1C1DE1CAFFFCULL
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
			0xBBD669CCAE124568ULL,
			0x7FCBD03E063C1C58ULL,
			0xE3CA198948161F05ULL,
			0x542A7A6BC67C9429ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x482F5C875CF87E98ULL,
			0x6BA8F41D771F1810ULL,
			0x48A0BD2088C8802CULL,
			0x7233317C1A20A6FFULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x37B46996B4424C80ULL,
			0xE6D4EC3315F9C50AULL,
			0xEFFD481FC919C723ULL,
			0x6731C0D9F577EB24ULL
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
			0x0CE55B477551A6A0ULL,
			0x9493DBA1284CBF7CULL,
			0x6F3CA824A6FCEADCULL,
			0x6BDB5FBE0BF9B389ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA76E5B64FA8E6538ULL,
			0x3B2A5C8398A2C5BAULL,
			0xC2AE8FA631A4DFF5ULL,
			0x6DE38AB885501509ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x013F1ED2F3CD8D70ULL,
			0x70E34E05E6C9B4BBULL,
			0x2F4C667C3BA68B09ULL,
			0x08368D6372FF3C41ULL
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
			0xB5B7AE2909484E70ULL,
			0xE9C231FA28B83F7CULL,
			0xE0F481929CC1F972ULL,
			0x5896D4446C7AFA82ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x114880998B251BF8ULL,
			0x7AFAF0EB35EE4328ULL,
			0x778E89C93641AF70ULL,
			0x54702A4ED5687060ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x3E684A724194EA3BULL,
			0xADD9DCA0265684D6ULL,
			0x4EC3F3A191E387B1ULL,
			0x07B11E7D530BF381ULL
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
			0x8BAEA94C85B0BEC8ULL,
			0x0326B5E8FE43ADF8ULL,
			0x9BA991A9FAC1B667ULL,
			0x7FD3BA2939FC5C3FULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x6ED8503467445520ULL,
			0xE91123DF1E2B249DULL,
			0x3FDB69AB2B4551C7ULL,
			0x524D021E152D3789ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xA08D33950CC224CBULL,
			0x02028268C71F73EDULL,
			0x24E67F6ACCFC9496ULL,
			0x6B91F5E0B5E8E984ULL
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
			0x99301831DF9DD380ULL,
			0xAE1479249D938D27ULL,
			0x942C0CDD76854794ULL,
			0x5F93C54994AD16A0ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x719A5FED5BDDE7C0ULL,
			0xAD186C4FD4122618ULL,
			0x396D5543B8A22701ULL,
			0x70ED5EF0A29624D3ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD9787BCE096E7197ULL,
			0x6C33FF71CB19DD55ULL,
			0xD74343486A158BD2ULL,
			0x5B10114AD7FF0D0BULL
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
			0x98E8575FECBD94F0ULL,
			0xCFC0D12BCF94CB66ULL,
			0xDB855CE63A268AF2ULL,
			0x7455620F1AF31447ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x954BD74298018190ULL,
			0xE222FE8ED5E130DAULL,
			0x461F81FE4D42709BULL,
			0x5DC9C97DAF586C8EULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x449191383F09E53FULL,
			0x4806A066A8517DCCULL,
			0xDED32ADE852A6537ULL,
			0x5EF101D37B371242ULL
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
			0x58F6CC86C938DE28ULL,
			0x41D7C873F517F118ULL,
			0xD77E1A5ADDA7E1A0ULL,
			0x7AB464BABF2FC281ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x48D09B0FAC7D3538ULL,
			0xDD606E927FB05CDDULL,
			0x59A03281898DE84FULL,
			0x7BE31EE670BA945BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF81EABF3ABEE1852ULL,
			0x1B7F9F873DED0604ULL,
			0x219282DF2B5F15EEULL,
			0x6F981E5D2506619BULL
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
			0x9B87C969838CDD80ULL,
			0xB1DED53BB0D3D13FULL,
			0x4BB9D6DD6344255DULL,
			0x66BB1B3B391BEBCCULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x6598A5CC2E06A738ULL,
			0xB1267C96A51AE6F2ULL,
			0x45A48267C005A864ULL,
			0x554BC0E375FBD56CULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x7FF93D041CF72211ULL,
			0x49D2EF1951FDE258ULL,
			0xEF6AFE988D537981ULL,
			0x3F870F22CACA2440ULL
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
			0x4946E2329C30BB00ULL,
			0x55DA4A8F56E26473ULL,
			0x648A66C2D69BB4EBULL,
			0x674E946C9F0D71D8ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF294C8EE63CA5C18ULL,
			0x9C2C2AB042AE789AULL,
			0x3A9D242DA2E826CEULL,
			0x5A466976E3BD618BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE23EFC25DD0A3E0BULL,
			0xDCA2B797EA2FD4ACULL,
			0x3BBE6B54B54A43C7ULL,
			0x5E79728BE5452F3BULL
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
			0x151E2668E9C7C398ULL,
			0xF0BFE1DDCE16831AULL,
			0xDB7570F0D1AAF5A2ULL,
			0x6C6BAEC351CDE10EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xEA098E337AD9FE10ULL,
			0xE61F0DD5EA975C04ULL,
			0x0491833D198944A4ULL,
			0x55B18A4A9A8BC984ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB1C529FD057CF89AULL,
			0xE0AC4916B51E5657ULL,
			0x82036EF3D6AE47EAULL,
			0x142DE6D824D648AAULL
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
			0x91C32C427EFB9590ULL,
			0x2EABBE4CD2D203A9ULL,
			0x7EBF423F61EB38AFULL,
			0x521202B2A6D449F8ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x6464C520073FA818ULL,
			0x8D2DF8CD8FFAE4CBULL,
			0xE0A5CF8D1D664987ULL,
			0x7A58F43E3BDAACAEULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x340C29E293EFB31EULL,
			0x6E1D4F9F08E441EEULL,
			0x9CE8D4ED71C3D273ULL,
			0x1BD30DE9C531A577ULL
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
			0x52E3AEDF1D386318ULL,
			0xB0475E6DFA6CBBA5ULL,
			0x41850C7C5778DC9CULL,
			0x65B34A30E9ED5D54ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x5F48E25BD0E46910ULL,
			0x170B0521F88D37F9ULL,
			0x42A3BE663C6C13CAULL,
			0x559B823B99A77BD9ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xFA0279CEB5B5406CULL,
			0x2E5DDF0DD715F025ULL,
			0xD84E7268D21B2083ULL,
			0x1E5BE2A0C896A623ULL
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
			0x854DB561C222DC50ULL,
			0x8C1F3CFA8F6C4AB4ULL,
			0x817E92EADFE51F99ULL,
			0x4223D499E2FDE16BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x588432CAC332DA00ULL,
			0x2374815BE29D183AULL,
			0xB20A21DFB6350657ULL,
			0x72B1466684B110D8ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x194FE0DB0F49D5FBULL,
			0x6F1B5A6FAC018D33ULL,
			0xCA304A6798A1EDB6ULL,
			0x68076595B6413C16ULL
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
			0xE574DC807D4BDAB8ULL,
			0xC27FC473D112635AULL,
			0xF0BA9243041B5F05ULL,
			0x5E3104FD89F73BDFULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4568A3161F840D90ULL,
			0x199C664F4C61F82EULL,
			0x7DB0542F4957D375ULL,
			0x60558B08CD62D4B3ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x791D8DF6A23C97A9ULL,
			0x89E0867B9E072299ULL,
			0x50A8D840B665E984ULL,
			0x6C4EA358A4256E35ULL
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
			0x956A14E19B38E798ULL,
			0x994ED959D52C7037ULL,
			0xB4D020912EF1AAA6ULL,
			0x76F0240BA7BBFA62ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x7718D9687D9228C8ULL,
			0x77025D31D22CEA53ULL,
			0x99BECA810D7E68F9ULL,
			0x6709E92475D58960ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF2ACFBE796ACC7EAULL,
			0xC12284868AF64996ULL,
			0xE1C42B5DE3ACC563ULL,
			0x0CD8AF9F882BE0A5ULL
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
			0xB1D94AB5F8AC1630ULL,
			0xF5346F2362D15C0AULL,
			0x7B868518786ED5E9ULL,
			0x51E06EB1A084B47EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x8B773D7339DD5770ULL,
			0xB8C2596FE0668A32ULL,
			0x0A241FE7B57AB14BULL,
			0x6F53A5997CD33AB0ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x8AB4AEEA8A0B4219ULL,
			0xD86E16228CEC32DAULL,
			0x737543D837B4A396ULL,
			0x7774EF9B6AB96ABCULL
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
			0x3113474F7854F0D8ULL,
			0x7FC65C54A345FD51ULL,
			0x64CAE088956AE41DULL,
			0x5A5CBA04088BD273ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x768974FCAB950C80ULL,
			0x923BD84634761877ULL,
			0x1B12ED0C32DDFD9BULL,
			0x5B5AB3484D9416A8ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF0AE6C54418EE621ULL,
			0x784DDF078C894250ULL,
			0xB93792CBF9830302ULL,
			0x2E87D62EB8CA9517ULL
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
			0xE00D19DDC5BA80E8ULL,
			0xAB1E76FDD375B732ULL,
			0xC1DA12A98615211FULL,
			0x5B2CB9D4A1CFC68BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA082FF4591B6C1B0ULL,
			0xE3AE03F3BF45B84CULL,
			0xA8E38DB96D6A421AULL,
			0x4870CF38B1EE8006ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x0F0F1F394AA3EA28ULL,
			0x4B29938793B4A301ULL,
			0x51DDADCF07CB69C3ULL,
			0x044E99CC8034BC5BULL
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
			0xC786271A4D068DA0ULL,
			0x2FA3D41ABC5897F9ULL,
			0x262B61F7C25CDFC6ULL,
			0x656E36F6F036DDA1ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x5485BB8BC4A585B8ULL,
			0x8A4FC202767C899FULL,
			0x38B4DEA857891227ULL,
			0x58089E479FF5902EULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x8A643EC8B2164B38ULL,
			0x046EB5910AE6D6F2ULL,
			0xE571C3617822D1ABULL,
			0x30B063E5D6D34439ULL
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
			0xAD98B2DF8B47BE00ULL,
			0x5403AF68666A83B6ULL,
			0x7A89689D2D718AC9ULL,
			0x56295CEF971D9E37ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xCA594A0057C1C310ULL,
			0xF4E98896EA2E8569ULL,
			0xDFC9EDAF6B473EE2ULL,
			0x6713FE195440CB09ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x7EEEBFC35C8CFF54ULL,
			0x9CFB6129A69EBB97ULL,
			0x713D858864668D54ULL,
			0x5A16B8D231CCDA03ULL
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
			0xA09726DA22C23C40ULL,
			0x6B268DBC4A37796EULL,
			0xB25A293D89CD7116ULL,
			0x46AEF0E678D2105CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xFBCD736F68C34478ULL,
			0x92703FE3E09AB021ULL,
			0x9EB8A7306C2CC4AAULL,
			0x766D8DE111904C02ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x8B7379A8D805154FULL,
			0xEE455FEEB8AEB7B8ULL,
			0x732E5842893E0624ULL,
			0x492D9E01FC1AE9E6ULL
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
			0xD56812B14C6DB988ULL,
			0x7B0B02AA5AD76985ULL,
			0xC6AF49DBA990F17FULL,
			0x5DF4F9457C1E5B0BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF3F7B20EDF234600ULL,
			0x89C5C8E70A37F84EULL,
			0xA60E5A215F0310B3ULL,
			0x57F68D9041FAFA21ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC549EB8AA959AA6AULL,
			0xA9A0A128531261C3ULL,
			0x7421FE906A7A39BAULL,
			0x6DBD8387461D6863ULL
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
			0xD43ADBEB9948C2A8ULL,
			0xED691C59B2DE38CEULL,
			0x8281642821A38095ULL,
			0x7FF2AB37ADD76E29ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC76AB603C8192BF8ULL,
			0x6BE2BA1300460AC4ULL,
			0x19A13F192A2AFF02ULL,
			0x7928F05ED7E546ECULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE93D0632AD8FFC64ULL,
			0x5355CACFC848CC4CULL,
			0xEB101D5DF2D3B011ULL,
			0x1ADE47D513BC02E8ULL
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
			0xE01235683C559230ULL,
			0x1145C710B3826A39ULL,
			0xAAA030848BA036B4ULL,
			0x4506D3D4A918E266ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x2966D48AD6CAED78ULL,
			0x72D53E7BB23CBC8BULL,
			0x88B70328C87E16F7ULL,
			0x69FC0878A0797904ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x626C9D2339AA8219ULL,
			0x9DC59873892EE70AULL,
			0xFE1D41E38D8002D8ULL,
			0x763FD2E752BC9802ULL
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
			0x6CE2D07D26FE4B50ULL,
			0x9A68E8F19CB5D4D8ULL,
			0xD10F5D812CE1E408ULL,
			0x7B911C13EBAB816DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x2308172AFD981BC8ULL,
			0x989FD2A8488F8443ULL,
			0x93A4A8EC608EC9A9ULL,
			0x6D0B9330D736D5BCULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x0D1443B967E6679EULL,
			0x01A0416EF268A5D1ULL,
			0x3BB6F58427F35C5AULL,
			0x4CC6C1BCA47422C4ULL
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
			0xFDC5170FE30EB7E0ULL,
			0x6F7D92D2063ACF14ULL,
			0x1C5E5E78DB2A0823ULL,
			0x6D524CAE153742B9ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x70B3C3D3D7AC19B0ULL,
			0x9E877EF4733B30C2ULL,
			0x10F917AB7162D9DBULL,
			0x750635A7944EBBEBULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE443A47DF76E6187ULL,
			0x0E2559322E9C5EDBULL,
			0x7967303F3F73B45AULL,
			0x6614F9A525FD6FF8ULL
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
			0xC99CBAD517BFC2B8ULL,
			0x24397923F8009AFBULL,
			0xFCC822D766FAD77CULL,
			0x71990C70962726C0ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF9C597DCE550C7F0ULL,
			0x6BD0B7A47713F9CAULL,
			0x25AD1DAB00787DE2ULL,
			0x7834F81ACD1F97B6ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x732649541F8D9937ULL,
			0x4C37D2A1892E0346ULL,
			0x30C79D72D7ABE525ULL,
			0x7F1D638FFF65D60CULL
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
			0x151237869D862E80ULL,
			0x9D7F826D037ED2F1ULL,
			0x744171B9B772434FULL,
			0x4BC765F1765E8DD3ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xEABE15EDD63D1818ULL,
			0x666CBE23B24D2DFAULL,
			0xCFBAF27B3C7E13D0ULL,
			0x4965667111009374ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x7C1F5C9B7834C68AULL,
			0xDCA664B6FF28C3F2ULL,
			0x9AC8860990F730FAULL,
			0x5DBB404FA7C73F73ULL
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
			0x28CBF3A854832C38ULL,
			0x80FA8B0294961019ULL,
			0x5B917E6A3B7E4B44ULL,
			0x610F149A50D6749BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD44FE6B62DFBA248ULL,
			0xC402D0B4ED38A4F8ULL,
			0x1B6027A08EC45929ULL,
			0x4011CCE3C9B687CBULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xDF3A7F4AA3D5E001ULL,
			0x4DB82F18785FF23CULL,
			0x1B6657487437F9BCULL,
			0x2280949965A98D1CULL
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
			0x9F475B76CEBFC080ULL,
			0xB423715DAFE22D5FULL,
			0x8A6743167881A9FCULL,
			0x55D4A140BCC6D480ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x9BF11CD94D5A2D30ULL,
			0xDC2B713652632FFAULL,
			0xC7F82DCBA7333C3EULL,
			0x6483E3196FB984A3ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x7BE759C6D62FAAE5ULL,
			0xA83B3F2CF0C00253ULL,
			0x0D2938BA3FA59BAAULL,
			0x16EAEF2B6D1F2C6CULL
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
			0x0CB4529655F2D5F0ULL,
			0x3FAF98AB8AA395FFULL,
			0x26D19061C459CBB1ULL,
			0x78F7F25CA51621C2ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x30BDAA954723E628ULL,
			0xBF31BE2485229A8EULL,
			0x644159E3C4F02641ULL,
			0x5BA39A9F8859BC48ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD646597EE9BD66EBULL,
			0x332F7CE7C12C61F5ULL,
			0xD12444B229A6254EULL,
			0x737362D2E809CA67ULL
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
			0xC7C2AF4F0A8B0638ULL,
			0xEC3929823618C3CEULL,
			0x8FD6D166B11B2DCBULL,
			0x5ACD2CBCB1ACE49BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x299F932CA3B3F858ULL,
			0xD253D79F20992316ULL,
			0xBE51299180C47842ULL,
			0x4B510E4A872E5D59ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xCE6171E64B904356ULL,
			0xB1A1E21205623707ULL,
			0x16A1FB14EBF18E33ULL,
			0x05D9F64006D63606ULL
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
			0x7B80590BACB9A2B0ULL,
			0x59B17B9E8AFDD55CULL,
			0x7ACA13CAE0DA2615ULL,
			0x6C8586D4260C137FULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x11321ECC09A896A8ULL,
			0xC230F2A4C3ECD2ABULL,
			0xDB085F4C02EB4FEEULL,
			0x42DA25EF3BB37449ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xCE12338C12211AEFULL,
			0xBF3AB80FCECC88FBULL,
			0x199801FFDCAAD2C6ULL,
			0x53158B1983A882AFULL
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
			0xFD11171B794BEF90ULL,
			0xCE7EEAFD1B1149D0ULL,
			0x18BE84FCEE3927C3ULL,
			0x4306E4A87020897AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA23EE52F2A8B97E8ULL,
			0x431206F4BEB83266ULL,
			0x51D56DB048F6FB13ULL,
			0x74A76BC008BC8004ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE3A89FDF91CD2B5BULL,
			0x17E7B9362210F8EEULL,
			0x701B1B8F1DC6D168ULL,
			0x7C3517251299500EULL
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
			0xEBA6D4231F32B828ULL,
			0x904094103724FD16ULL,
			0xFB41E4A6A1DF9E1AULL,
			0x741989BD69A0ADEEULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x7E346D18B6852738ULL,
			0xC2C8431B8E56FA64ULL,
			0xAAA5B142AEA3E669ULL,
			0x49AD0B672E9C8475ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x3D8B0327AB08DC8FULL,
			0x42A64625BA84DB71ULL,
			0x3EF46684767CEDF1ULL,
			0x4342121700D063F7ULL
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
			0x68D1535F6FF2EF50ULL,
			0x6245EFD116C47E91ULL,
			0xF321D65C61991F5FULL,
			0x587F4B5DFD70209DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x56BBFB404B9DF1A0ULL,
			0xFD9E71E8DA1B2934ULL,
			0x03A3ADCEC3D2D950ULL,
			0x7A5D949F414C58BFULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x47E0AE40FB0B2802ULL,
			0xC5E4765DB9BC44C7ULL,
			0x828BF660F18E4EF3ULL,
			0x7694FCD2B4CEE1B5ULL
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
			0x14F25A1C94B09970ULL,
			0x35C30F022B82BAA6ULL,
			0x0D15F570F81D3E16ULL,
			0x6265719DC959A75DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xEEF32F228C0AA6B0ULL,
			0x75A6CC86296E2BF7ULL,
			0xEEDD85C178808A8FULL,
			0x459E5EB834CFD0FAULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF4D73DBB247EDB8FULL,
			0x6C9E837C64232678ULL,
			0x75E0BC6985588EDAULL,
			0x02D0F7A1677129C2ULL
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
			0xC3CDEB7A0DCD3B50ULL,
			0x2109A2E2E42D8FEAULL,
			0x589114519BFBD390ULL,
			0x42A1B8A90C626B12ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC61DAD99B176D2D8ULL,
			0x4701A974A7B327C8ULL,
			0xA216DF4B1FBDCC57ULL,
			0x5ADFFA136638EDCAULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xCBB40E2D611592B5ULL,
			0x366B610C144924ACULL,
			0x088F5D53A85066B1ULL,
			0x5FD4F2D8BE806D42ULL
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
			0xB2613D8FA7F0C980ULL,
			0x3C60B07C2D76BA66ULL,
			0xC171DD4BFDE3B7CEULL,
			0x7CFE42B74E43B20BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA3D417E7662F67B8ULL,
			0x532E4BF53ACD8893ULL,
			0x22F833C2BA12E011ULL,
			0x7080EDC1A0A5134DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x6F531E2C800ACCFCULL,
			0x972FF9F22807D210ULL,
			0xBEB49BB4DC041539ULL,
			0x4A06A32A6E4CCFA1ULL
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
			0x5A554514B0A29558ULL,
			0x8689684A44192382ULL,
			0xC10D7AB72B9A1877ULL,
			0x42B44556DEC11104ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x66DFC7AC11A50BC0ULL,
			0xD6570A8CAFC7588BULL,
			0x7A4E82863D83E550ULL,
			0x4D5714E9C01A66E9ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD8FFD9853DCF727BULL,
			0x53E308012560C1D6ULL,
			0x2BC8F4FEB75C32E2ULL,
			0x51CFDA5012FB8F1BULL
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
			0x9272BE7A09545C88ULL,
			0x7EA1554359F11317ULL,
			0x280C85D3B97C874FULL,
			0x7A58CA15DCE797BCULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x88A824C97362FF58ULL,
			0xB1BDB738C3489108ULL,
			0x047765F68127F120ULL,
			0x55350DA82C1FB3A1ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD39D8E29C236D024ULL,
			0x635816D6AA1DD7D3ULL,
			0x1D6A3DFFFF8459A9ULL,
			0x36C4AD84182C47AAULL
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
			0x201097FC9A0B7F88ULL,
			0x59306627010BB4B2ULL,
			0x71D33061C4603F2AULL,
			0x44B03CB5257C061CULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x8488E63BCDA34A10ULL,
			0x46E6B252F35B690DULL,
			0xD9D9C19C6066B516ULL,
			0x485FFBA013A8678DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x4AC973673A31CC0FULL,
			0x79EED33E56B4FD78ULL,
			0x8E2F7C7CC42A7A9DULL,
			0x281C0305A0015024ULL
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
			0xB8E22FE77FBA37A8ULL,
			0xEBE1BC5C471E4E51ULL,
			0xFC555F50CD4D0CA2ULL,
			0x717F188AB08CE383ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4E1EE85EFB9462C8ULL,
			0x9C9064ABB14DE4A7ULL,
			0xE607EC2C06132CFBULL,
			0x751B137F3EB1EB92ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC70AF6F4C7B52A5BULL,
			0x5F3BE2456BF30AD8ULL,
			0x620CBA6F9E6C2962ULL,
			0x4D561CDE0CCE9FA2ULL
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
			0x929FE856989FBB40ULL,
			0xB26D9B7B18E190FDULL,
			0x0000F65A7C510E84ULL,
			0x544BC38C19E0430AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4A2F363F0E038B20ULL,
			0xF6DC350CE55EE5D3ULL,
			0x89B8038F9EB505D7ULL,
			0x46740DB21217DCBCULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x396F2B223DB031DEULL,
			0x5ED0FD0A4B82CC9BULL,
			0x01A7B9EFBE914DF9ULL,
			0x5BABCE00C494496CULL
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
			0x044806D171FF7620ULL,
			0x87498F44D811F808ULL,
			0x952E5D92B2B4980DULL,
			0x6D9849A0F4E90418ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xFA137A1DD28E9000ULL,
			0x4118FE2689FAD375ULL,
			0xA848721BDFDC079BULL,
			0x704EB138ACE91049ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x669FA35FE9B72B55ULL,
			0xF96890802B533352ULL,
			0xA05508BBE1ACF826ULL,
			0x6C4392F79767329FULL
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
			0xC0317FB27ACF34E8ULL,
			0xB5FB4CEA1B16F5B7ULL,
			0x106084A2249C13BFULL,
			0x4A63A0FD0D1B2B25ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xDE8253720A50FF58ULL,
			0xFBEC43ACBBE94704ULL,
			0x93BE7FB7A98A0C6BULL,
			0x63DE6CB4D7A6292DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x89909358FF3175AAULL,
			0x4D5E79061034FA6BULL,
			0x2C387E2CBB5FD970ULL,
			0x6D5D35480106307DULL
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
			0x87D95542DD67DE90ULL,
			0x947150683944E17EULL,
			0x6784CD7F1876CC69ULL,
			0x57821A3537456EC3ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x0740B385B0F85330ULL,
			0x7A126B7D7CB97593ULL,
			0xCF0F87644835874EULL,
			0x6A16ACA7DEF5850AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xBE9E7F6248E6E740ULL,
			0x866D723DFB16A281ULL,
			0xD85714005C4A7A6FULL,
			0x281884B30E0096B9ULL
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
			0x55422C41A87E2150ULL,
			0x2EB23C6B91511D57ULL,
			0xEC445EDBF9A6D909ULL,
			0x5DF74C0B9D9AA598ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x2EBA42AA5920B060ULL,
			0xB47868A0878F5E83ULL,
			0xDBF6E3586E3592D9ULL,
			0x799A40F207B8D9BBULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD03DCDB3C0757CDFULL,
			0x52508DC9B98AC278ULL,
			0xDC1011A5E612FB00ULL,
			0x4A38ABD48D5F88D4ULL
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
			0xFF4340B506BD5EC0ULL,
			0x9A517CDD603662F8ULL,
			0x68BCF112C8FC0335ULL,
			0x798023F9AE015937ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x5CF61A81F52EA0A0ULL,
			0x29E55752766E6F08ULL,
			0x2B6F92FDC936FE34ULL,
			0x7565166E2DE41742ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xD5C78772F681E9DCULL,
			0x07A521DB97E6DF0DULL,
			0x6224DA5AA6D0EF33ULL,
			0x0FCA4E839AFC933BULL
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
			0x3CF198BA3E2B1498ULL,
			0x06E3A90256789126ULL,
			0x4DB20B5234716F6FULL,
			0x4566FF743AD65E03ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x799EF3F6BE2E3420ULL,
			0x39186B7D30B3D00DULL,
			0xB4C21F01A25D7C4AULL,
			0x7EBAD53DD8ED4D25ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x745AA1CDB104F8B6ULL,
			0xDDD794F1869FABC3ULL,
			0x77A17E5B14F220F0ULL,
			0x17360506A9A971D8ULL
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
			0x96AD5E2139680760ULL,
			0xB5928DD1C02D741CULL,
			0xA9D16C9A65BA73E2ULL,
			0x73361E25408D963EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x7F982BCE93F62828ULL,
			0x0138152676A3C7F1ULL,
			0x555B1B5C88BDCCDAULL,
			0x731E9CEC3FFD6DACULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC19DAE493CEBED7CULL,
			0x1487CA9C1664FD63ULL,
			0x3E2DEC90347F838DULL,
			0x306DBEA2374096CFULL
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
			0x06941D64D9023BC0ULL,
			0xEA2E11216069C6CFULL,
			0xDCAFC045BAA9E46BULL,
			0x58B01489BCB71AD1ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF471AB4CCFC35788ULL,
			0x54383DAB49DB400BULL,
			0x9236E682B6266C19ULL,
			0x650B3308A29A1813ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x2937D9A75D02C729ULL,
			0xA3D622ED46656740ULL,
			0xC74568A99D48085CULL,
			0x4C04D5DE95917440ULL
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
			0xDB35D15CEE4F5288ULL,
			0xFAABADA6177BEA4FULL,
			0x02F6C8B9CA53F33AULL,
			0x5A1310CCD0240A2AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x1D9A3288A5809938ULL,
			0x2921C24E4032ACABULL,
			0x0BDE6FAF872BAD3FULL,
			0x51CAC9CE1E7A95AEULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x1FDF5767257F1EA8ULL,
			0x9ED169F3F9F0EA41ULL,
			0x5DFEAEA7383C6FACULL,
			0x76CAABE3FB95199FULL
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
			0x2E7D5D18A5FDA710ULL,
			0x4B96E826AD6E9E26ULL,
			0x01FD165243AD73F3ULL,
			0x5E1F21E7155C6593ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x5D08B6E0EA943EE8ULL,
			0x578560653578BA10ULL,
			0x3285D76A088E42D8ULL,
			0x67EC588E9F339D2DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x72F477F4CA496A42ULL,
			0x6B5D7C468182AEB8ULL,
			0x6424D53A8423459AULL,
			0x3A4442156E97B980ULL
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
			0xE748BBDDF928B6E0ULL,
			0xD93BBC69CADD1048ULL,
			0x565CC9D1D15E009FULL,
			0x6234E48AC13345F7ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xA90BC3F0767DFF50ULL,
			0x71C9943D4EB7E750ULL,
			0xE69F8091FADE8F26ULL,
			0x7A8FEE269BB2F4D9ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xFE0903139E46A39AULL,
			0x9811CBB6BE10E6F7ULL,
			0x06A83B6B42161B27ULL,
			0x20C542DAFB034783ULL
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
			0xF8FD7E7BC5D56EB8ULL,
			0xD217F6ED3854AE58ULL,
			0xE9144E508B7CD72DULL,
			0x75DCBF3E96934D31ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x497915798C01C100ULL,
			0xE7C6431D11056731ULL,
			0x9A5B2BEB8EB04F5BULL,
			0x66CBEB3B032CC443ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x28CBDAF03090AD20ULL,
			0x96942DE9981AFBD3ULL,
			0xC28D5347ABCD5783ULL,
			0x78B141A6D9117115ULL
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
			0xA9F6336826517638ULL,
			0x95F19E30B9DCA8AAULL,
			0xA23492914982782BULL,
			0x7F96546E04209318ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xE4EB3BF28646BC68ULL,
			0x572A4D4B68B8F18AULL,
			0x358D377F9BF873C3ULL,
			0x4498EC30734C130FULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x6A59423EDEEE1F7DULL,
			0x090D14284D6D4A20ULL,
			0xCA1EBCA810C34557ULL,
			0x7DD481E9C14BDFE8ULL
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
			0x65408E5719410ED8ULL,
			0x6652CD515EE6530BULL,
			0x300659F19750E90DULL,
			0x55705C44687F7E62ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x743DEA2EDA345C30ULL,
			0x23B0A4D4B12034CCULL,
			0xD62D5B0AF3D88D94ULL,
			0x59775FDA9FADCC57ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC64E53EF316788AFULL,
			0x13B113C494D65832ULL,
			0x881BB273E20C9149ULL,
			0x5BF6CCC61DB16FCDULL
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
			0x0E79510EC8A2A9F0ULL,
			0xCE211E78754A7A6AULL,
			0x85D65D2AFA98354DULL,
			0x75B33316C16AB1ECULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xCA9F87E5BB23FA70ULL,
			0x243985C51777DDA1ULL,
			0xF248C171ECD248D8ULL,
			0x6410F80FD0637793ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF81CFF5ACC804AC3ULL,
			0xA6A27002F9FFE975ULL,
			0x2A1741B072530A07ULL,
			0x7246A6F075169F2FULL
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
			0xC5ECF13552DC7D70ULL,
			0xAC386AF887B1D31CULL,
			0x79A45CF4F75CE389ULL,
			0x6B95943B31AB2195ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC954D035CB00BCF8ULL,
			0xB5C2427A6D46F6BEULL,
			0x2BE9559F642EDF03ULL,
			0x48F88C972CCA364AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xDE421ED118978181ULL,
			0xC854BFA9E8011187ULL,
			0x1FA46A9D8F7D88BCULL,
			0x3ACA45244DF67D3EULL
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
			0xC423E75364AC00B0ULL,
			0xBCF3ADBCAAE7DE4DULL,
			0xC6DB5828F6A6A2ABULL,
			0x6E896ACF55CAEF88ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x9BCD420BFCCA64B8ULL,
			0xBBEC80EEB1189A5DULL,
			0xC74A1E26480CF5B4ULL,
			0x69925E569FC41ABCULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xDFBC9B8A6A806765ULL,
			0x007EA6C0C2DCCB97ULL,
			0x11A8EFAE4D0B1D59ULL,
			0x2528B23582A055FCULL
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
			0xD4260D6215810B70ULL,
			0x3D2B0149F7BE5E91ULL,
			0x0625C7A3DF3EC1BCULL,
			0x602F100D2133D899ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x2BBD4C65FC4AD0A8ULL,
			0x20E390DAA57310E7ULL,
			0xA96E1AEF316B64E4ULL,
			0x70F9CC69398E7C20ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF4FDC87D30E508E6ULL,
			0x06353B6ABCBD8B21ULL,
			0x7BA3CEA450794281ULL,
			0x2F0D1CCEF6284E32ULL
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
			0x8B8699355D5F4EA8ULL,
			0xE3C3EF45E73D3F63ULL,
			0xFDA0F6E7DAB52CEBULL,
			0x49241203B07E16BDULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xB15AE8FCB404A7E0ULL,
			0xA064FEEE167AF639ULL,
			0x0CE5AA774EAAE420ULL,
			0x634E71DD5102A93AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xA0C62B58F297DC16ULL,
			0xF8122BA4B0DBF1B4ULL,
			0x274691B5AE10B1E5ULL,
			0x12B58326B9A5922EULL
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
			0xFBCAF511E3151AC8ULL,
			0xDBC985F218E54740ULL,
			0x266702A429812589ULL,
			0x71CAD11B41FF04D8ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4EEE1EFDA311F018ULL,
			0x07176E79A003B7C8ULL,
			0x4FA8B0C63D8540F6ULL,
			0x52CA3BBCAB30A2BEULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xFCC2DC4734F8928BULL,
			0xCBFF9D6AD81FEF28ULL,
			0x52B9523B071B9E04ULL,
			0x4EF8CD968D9FDBD6ULL
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
			0x2D94117AE6A94FB0ULL,
			0xB9142D112F95ADF9ULL,
			0x8A50AB3A50D155C1ULL,
			0x76F09ABB58231C30ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xABF97CEB772B2878ULL,
			0x6E3E9E3CC81C5F7AULL,
			0x0A0D7EA736BCCBCAULL,
			0x5983FC829B7D52B1ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x51D6DF7A8AAD76D4ULL,
			0x0095A8C7261E687CULL,
			0x7A683FEE4FB7E882ULL,
			0x0C04A992E0DE136CULL
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
			0x7BFE44DACA6C8310ULL,
			0xBB15D4DBA48AC30BULL,
			0xF25C7E2944DE67D6ULL,
			0x40E2BFFE75007913ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x69F36BF8F3435CF0ULL,
			0xFFB1B97D8FA10BC0ULL,
			0x9A9E6C713F8DF8D0ULL,
			0x41AC2211D78732F0ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x3697A8CED86775FAULL,
			0x8D399B5C99F568AEULL,
			0xC2D31322FEBE0791ULL,
			0x7B4FE4443BA6E573ULL
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
			0x98B8E747A3AD9F08ULL,
			0xD7DB2A23B014DEB1ULL,
			0x54F675C56336E128ULL,
			0x4ABF57435EDEEA2BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x9264D823A5AD97B0ULL,
			0x917F92E9D975B6EAULL,
			0xE730E026E0A247C2ULL,
			0x739D90A66B429A63ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x78231E13B5673311ULL,
			0x87C69335B8C7D5BDULL,
			0x324E6C9FC689A77AULL,
			0x1896097574BF6234ULL
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
			0xB8C62AC6140CEA18ULL,
			0x079B50270E25C774ULL,
			0x87D6B1CACED93147ULL,
			0x615176C9AF415D09ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x2308074335B8E2C0ULL,
			0xF176117CA1A9D99CULL,
			0x9F4A8C4823113E51ULL,
			0x622F67FB3D525CE8ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x089FA1F114331172ULL,
			0x0D1EDC23B6A4C251ULL,
			0xB2D0EE1C91407A46ULL,
			0x5ECACB41BDB7591BULL
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
			0x99F129F5626662B8ULL,
			0x09C9E48D17343C8DULL,
			0x18DEAE556805FB8EULL,
			0x7A3F46C0FC06CA67ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x4198C5EBF619ACE0ULL,
			0x5999558066B54E83ULL,
			0xD1DC3717437F0317ULL,
			0x747DA0E0EA898D30ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x8B625413F7E6D9E5ULL,
			0xA3E506771D99A02FULL,
			0xEBD75A0144AF0ACBULL,
			0x2A7A9A04AF1B94E5ULL
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
			0x6CC80DB7ECE31AD0ULL,
			0x305FF4B579708D4EULL,
			0x23B51C2234D2CE35ULL,
			0x7595EBFA69103F2AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x81F85AE4069B0100ULL,
			0xD330B72BF49332F0ULL,
			0xB20E753A5115F26AULL,
			0x4D555478F1F65BA1ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x8224D383FF9B1A37ULL,
			0xEF3A921181F5B888ULL,
			0x02F52259D039D3E9ULL,
			0x18957C1C020AF053ULL
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
			0x06059CAE9826BB78ULL,
			0xEC522B6127302834ULL,
			0x34FB037957E54D50ULL,
			0x770F03C4BAB1FCACULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x799FDD69FFC5CEA8ULL,
			0x1BA3CA3428F63D5BULL,
			0x689B33254FB64A41ULL,
			0x4C9347EF7B2FD9C0ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE55CBA05C67B15DAULL,
			0xE64781E711ABBE73ULL,
			0x53D560569B2A391BULL,
			0x6EE76641A3393BC5ULL
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
			0xAA009330CCD60D10ULL,
			0x61015BA7EE0C2402ULL,
			0x0CFB9A1892F229CAULL,
			0x62439AF6D8D63946ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x9C30D1B849A6D870ULL,
			0x042C796566FFC397ULL,
			0xCA9B04EBCDED4BC8ULL,
			0x4A218272FDE9E2B9ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x513944982459EA5DULL,
			0xE60D2FB807B7BAF9ULL,
			0xF7639741D8B924A8ULL,
			0x0CDBD821AF83F6FEULL
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
			0xBC0CA218B071F140ULL,
			0xCD52F4C8FB477EB5ULL,
			0x3B2C46F68B9DD094ULL,
			0x6E1BC7C83CE2157DULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x90E0AC2C30624930ULL,
			0x3A114A2FCC50CF42ULL,
			0xF4C74B6C2C178994ULL,
			0x409D5C56C83E991DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x6CF59DC228264DDFULL,
			0x16528D7A581709D3ULL,
			0xC68C524450F6F719ULL,
			0x32C6ADE42BE272DEULL
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
			0xB9CB14E1A313BB98ULL,
			0xBF3130BB4B2D325DULL,
			0x5F641545CD4D5784ULL,
			0x4A412B920AEE823AULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x7797006C01E876B0ULL,
			0x3C67444974EA6F36ULL,
			0x40F291E980837ECCULL,
			0x6CAAF2165FF02A7AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x0DB87FEC0F03838AULL,
			0x57ACC4A6755DC29BULL,
			0xBD0464A53829688DULL,
			0x541771077D33D7CFULL
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
			0x6E828718FC538020ULL,
			0x5B8668E8F59CE969ULL,
			0x2D761987C425205CULL,
			0x649177AF1536B858ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x88CBD5FE2A2F4A10ULL,
			0x8DCCC2930A6EBDD0ULL,
			0x1B85A210055F3EA0ULL,
			0x77BA71DBFBA6CEF8ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x3C6591492CB11473ULL,
			0x93059F5B8F252EE7ULL,
			0x49DD6CD6A963B48DULL,
			0x67402EB4A3E9BC1DULL
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
			0x859039BA0C3B4138ULL,
			0x0868457A22E091C8ULL,
			0x8A45F547C2A45445ULL,
			0x5C2AA4D0ED4295B5ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x8674FE33673668D0ULL,
			0x294C0729F58E42ECULL,
			0xC023B3AEA0A49B0CULL,
			0x4CB2D6AA57E298A4ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x8C774D6F6BD73667ULL,
			0xBD7401F79EFAB888ULL,
			0x52FACA2B154FC145ULL,
			0x6C2A8951210D58C5ULL
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
			0x1597CBEA460F5B78ULL,
			0x03BE19A108F3F83FULL,
			0x5794F2AA534C1882ULL,
			0x63E487E8A4B4BE3FULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF04705AD9E788230ULL,
			0xC48D0DD7A125279FULL,
			0x0E266A97BC8E4A19ULL,
			0x7A0F1DE14DD4FA2BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE09013064B18C96AULL,
			0xA0ABFBF28027345AULL,
			0xA5CD341C6AC65380ULL,
			0x1C04800744BB7298ULL
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
			0x8FA8E07BC0B0A3C0ULL,
			0x287D0F247F69B4EAULL,
			0xD93A65C4FE639FB2ULL,
			0x41343925D9ACC0ABULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC32092AD816B23D0ULL,
			0x7069B6EF36B514CEULL,
			0xA13DED2BD0A27547ULL,
			0x53FDC21323C43AE0ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x201825EE20035559ULL,
			0x8CA58E61025A33BEULL,
			0x34B3E2666DE5D782ULL,
			0x3FBFAE16F46C9934ULL
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
			0x51220B35CEC8C108ULL,
			0x176804117B849B6CULL,
			0x1C35DF1262F43FE0ULL,
			0x40B22515F15632DDULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x2DD5F2CFD9BC1F28ULL,
			0xA51850BE034CBF99ULL,
			0x80F3ABAA22827753ULL,
			0x7D0C2B01351184B7ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC8131654CAA1964BULL,
			0x6473FC790274335CULL,
			0xD2DE3F82BACA93A9ULL,
			0x2301EFE4A73995D9ULL
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
			0x257E4643CB6A9910ULL,
			0x3465055A3584FE0BULL,
			0xC73AD1CBA51B1FD0ULL,
			0x52003E69AA08E6DEULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x124F73851F83BCE0ULL,
			0xB36F9A81DC076D03ULL,
			0xE86C08C1D7B352FAULL,
			0x608E4E15E1812573ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xC83BFE5060A94976ULL,
			0x628BB6A8F3B1C5EAULL,
			0x22BFD55B671D9F3DULL,
			0x3E526FF765A3A60BULL
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
			0xB28E20F64FD3DF58ULL,
			0xE09B8599BCE5954CULL,
			0xDA9C8EEE637F904DULL,
			0x70D2DB57BB287424ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x43A91A9E6934F698ULL,
			0x7314F0A228F55E41ULL,
			0xD5686852F9D81B32ULL,
			0x4562CC41145F54EAULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE3B9C483E3E1F1DBULL,
			0x9D65CE8E674670D9ULL,
			0x2F94B42EEEC245C3ULL,
			0x0D9BAFB0C3AA86ECULL
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
			0xF39A2A1F409DBF40ULL,
			0x905F4DB87795F2B3ULL,
			0x31A9F6269E744184ULL,
			0x7C7B42E4C58C8F9EULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x23231717C5EA3508ULL,
			0xD2E9D4166803E20AULL,
			0x56D06258716E4995ULL,
			0x6704C1613DA932C5ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x1D2B5D6CA4CA8924ULL,
			0x89FA881FA7544636ULL,
			0x8FE9C881B291B8AFULL,
			0x6AEE29566F35774CULL
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
			0x4C0ED109D82A0C38ULL,
			0xEE048759997A3B06ULL,
			0xBD42966A947BC4BDULL,
			0x70188E87F5E2346FULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF0D5297E56E8FB98ULL,
			0xC8514329864AFE55ULL,
			0x05640223999B3FF9ULL,
			0x577CF4B7E7F23AF2ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x4CF2E72AA22846E1ULL,
			0x557EA66575C897BEULL,
			0x1222705BEA1A61E3ULL,
			0x43A4176524A89BA7ULL
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
			0x8248C4D2B2E1C638ULL,
			0xF03BEF5D51B1235CULL,
			0x2E6D9F7930690DF1ULL,
			0x785BBB6E6A7382BFULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x1108D97FCBE428E8ULL,
			0x9593880E0F9AB5F3ULL,
			0x92C1B26A78107E19ULL,
			0x4C91C6DC4D6D31A5ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x964BC68BF541CE13ULL,
			0xA916184C5EC57384ULL,
			0xC1CEABE2637E1CEFULL,
			0x6896A05DA739EA18ULL
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
			0xEC52C218C11CF018ULL,
			0xABA101951E4AC4C9ULL,
			0x24BD4C191ECC5DC8ULL,
			0x40C36D4E9D68A7ECULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xF3BDE00384654818ULL,
			0x776A081DE737A8C5ULL,
			0x8C8042EF68059F3FULL,
			0x58516D5AB203173AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x2024EB86B7BA7385ULL,
			0x43ABD561FCF8F74AULL,
			0x585F18A6F6AA55F8ULL,
			0x09986E40B27F1F75ULL
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
			0xE54DA12A5E3B9490ULL,
			0xC41A8FA133759464ULL,
			0x8235727F1E59F40BULL,
			0x4831ED041A01C6CAULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xEAE98527976AAF90ULL,
			0x05EF2F8A68E0F458ULL,
			0xE2D58362D08F6829ULL,
			0x635C9E75F4C9AEA2ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x756E1A08F5832B57ULL,
			0x208E27B3E4B70309ULL,
			0x40BE22441B3C623EULL,
			0x1CC93A3287E431D7ULL
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
			0x544303F6C46B0050ULL,
			0xF3A22168A8B8F4DDULL,
			0xE1972DF0A292CCB1ULL,
			0x7FAA7AB4C4463869ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x3AE9064A91A6ADC8ULL,
			0x19976703431EE225ULL,
			0xDE8C744DB7698389ULL,
			0x7701B61B51D9ED41ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x68AF91941D5E9F0BULL,
			0x5BE9E05A0D34E219ULL,
			0x8321CA9CEC7C547FULL,
			0x4E006B64CA391BE9ULL
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
			0x9B508817BE71B860ULL,
			0x180C82DAAA172F3CULL,
			0x04EEC12B6398716CULL,
			0x48B51566A40C3EB2ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x2922CAF2459D8170ULL,
			0xE4994BFF12B0CC6EULL,
			0x01F910DC9A45C8E1ULL,
			0x707EDE9C4C02C996ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x4256B35639A79365ULL,
			0x58E10D1F148C4621ULL,
			0x6C45C16085345EABULL,
			0x6BF40E658161066FULL
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
			0x33C8B06093415F28ULL,
			0x5D325E5DC571712EULL,
			0x9B0CAAFD1844928EULL,
			0x71A93E47114F9AEDULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x44725D0B95AC13A0ULL,
			0x707DAC072FAA4E23ULL,
			0x8059269D791FFF49ULL,
			0x6143E899B2A68ED7ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB577DD577494E8B9ULL,
			0xB03A3FCDB698C107ULL,
			0xA41377F7337D1872ULL,
			0x7B336C81B37A1AFCULL
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
			0x554CDDF26958F640ULL,
			0x7B194C1252DBBEE8ULL,
			0x50D88318D4DACEC9ULL,
			0x6F49CB9EB4C45D67ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x68517DF9B4E9FE00ULL,
			0x627FE291DE294984ULL,
			0x402B78A1D02DA8FAULL,
			0x4793E94A5AFF77D1ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xF29CBF3FA852F34DULL,
			0x14B7FC61EBF4F250ULL,
			0xE99CF7418ABFA33BULL,
			0x7795D856CB9C5ED4ULL
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
			0x7C633D4F72D533B8ULL,
			0xB713ED48DBF6FBB3ULL,
			0xDCE87598D21A9C0AULL,
			0x605B386A9E19F985ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x274CE50CE721B3D0ULL,
			0x9B498548FE93DD31ULL,
			0xDEF803FF4721E1C0ULL,
			0x548564200A963126ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xDD1DE2926DA2C68AULL,
			0xB0EEF45BF1EBB1D0ULL,
			0xC6A4938E71EE9A76ULL,
			0x2EB8C00871F09596ULL
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
			0x125F94B95F092348ULL,
			0x6A266492DAE387A4ULL,
			0xEC5B50C8789B69DAULL,
			0x6F3E3D11F0A0FE8BULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x20D3124B8AAB5740ULL,
			0xF5165F691E32A2C1ULL,
			0x439C7E996D5BB3A6ULL,
			0x57C326DD00C33CC3ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB44527CD4C2E8C5BULL,
			0xE87913DD586E47D2ULL,
			0x667A2C619245192EULL,
			0x5A29AB44567275D5ULL
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
			0x91EE2075F5E74188ULL,
			0x470E40F880568059ULL,
			0x6D0914FCD3C424CEULL,
			0x6BCF70C0EE76AC62ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xAA3D4F30C7E70F40ULL,
			0x383CC7F29390187FULL,
			0x3FC456191255D22CULL,
			0x4EA9A15BCA685B2BULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xB0B6520E77046A0CULL,
			0x9D18B3DE00AC7079ULL,
			0xCE2E7031CC31A15AULL,
			0x1DF966784DFE71A0ULL
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
			0x4250302EB415B740ULL,
			0x5C3942CF4390DA97ULL,
			0x74F791858796411EULL,
			0x5890293F5E5E8014ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x6A58520555028A80ULL,
			0x0251B685E519B3BDULL,
			0xF46ED03CAF687F1AULL,
			0x4FA74816A8EC3C4DULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE0EF5C27EABB2888ULL,
			0x3A65705A5C2EA15AULL,
			0xE00D7463ED718378ULL,
			0x50A065F54B674B06ULL
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
			0xBE49250A29C16B28ULL,
			0x3925EDA0F6CAB830ULL,
			0xB81BD7F43BBD2757ULL,
			0x51A03F1729B67914ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xC6320F775F48EB58ULL,
			0x01AF266313438491ULL,
			0xDE2B63060AFD6340ULL,
			0x686E8D95477841DFULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xCA2DD69EF6B45B0CULL,
			0xEF521A5D91619196ULL,
			0xD95A20987679CC4EULL,
			0x0C8A038BE813DCB2ULL
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
			0x7FA2733D760FB528ULL,
			0xB6651BA887D090A3ULL,
			0xC6FE35DBEA3C0CE3ULL,
			0x7466D6D372D063D6ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xD13A0B06C5005310ULL,
			0x4A25B939E45CAB47ULL,
			0xA972DBC194A75DDCULL,
			0x44A77AEA3CA46C2AULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xE572FE7914681A83ULL,
			0xBC343E493EB1AD35ULL,
			0x69508DC35AD4B2F4ULL,
			0x262494EDE84584ECULL
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
			0xE34C915212164698ULL,
			0xD0F18D670C4E94E3ULL,
			0xAF389263370917D3ULL,
			0x49F4BA15F10D0A8FULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x47C495D689E60868ULL,
			0xEC03C17090722C6AULL,
			0x513754CA4693CD61ULL,
			0x641F09A79FCC6BD1ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xCD0BF728F75F7EE2ULL,
			0x05E2D3199627718FULL,
			0x80CCEAB9250EC6BBULL,
			0x6654DD6BF4880449ULL
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
			0x13DAD9735AEE26E0ULL,
			0x36249728FA10AB94ULL,
			0xCB36AC8FB1E74758ULL,
			0x73542D69F2F9F970ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x3A5A323049CB6320ULL,
			0x3AFD97C562272974ULL,
			0x06A78197E5526E01ULL,
			0x52BD3CF72ED5C998ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x5A4BE800DCEB52EDULL,
			0x30279B6980E9F012ULL,
			0xF9B26CC779019E3AULL,
			0x78B0BEEB026B9DC7ULL
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
			0x2E791658B4BC21D8ULL,
			0x2DE654766F3C694AULL,
			0xA9473D2A55FC015AULL,
			0x558F54E92F93AD82ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0xE1345A4C41894658ULL,
			0x9FA7A40C95A87366ULL,
			0xCBAC7DEF16993234ULL,
			0x6A6586CF32844016ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0x886E1CC421A90475ULL,
			0xEE97EAE89217477BULL,
			0x8F723E84D14A1E8CULL,
			0x2BCBB1A5513B8273ULL
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
			0x0E18072FCC00AF38ULL,
			0x11641BCFBCAF2BEEULL,
			0x6FEE02A817EA1503ULL,
			0x582845D1BF3813A2ULL
		}
	};
	base = (curve25519_key_t){
		.key64 = {
			0x7B1DAFEB96091228ULL,
			0x5FFEDD5977931EFBULL,
			0x620C6C4898DD6A23ULL,
			0x6C5F83395AF07DB8ULL
		}
	};
	nbase = (curve25519_key_t){
		.key64 = {
			0xBFDBB909DD5DC4BAULL,
			0xF2F99F8476995DF0ULL,
			0x00D3EDE3BCA3D0E4ULL,
			0x37C2DD3A2D057D76ULL
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