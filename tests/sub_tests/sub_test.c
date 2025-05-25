#include "../tests.h"

int32_t curve25519_key_sub_test(void) {
	printf("Key Subtraction Test\n");
	curve25519_key_signed_t r = {};
	curve25519_key_t k1 = {.key64 = {
		0x95CD673048A0ACF2ULL,
		0xAAAA9D0A431B36A9ULL,
		0x35319798A4225FB9ULL,
		0xA994BEFD930B4F63ULL,
		0x710FC7514C0C5A73ULL,
		0x84A6A4C4E0A44094ULL,
		0xF59C8F44734EEC66ULL,
		0x635840772827C99DULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xFDAAE4B7181AA5B4ULL,
		0x72C8F5426FAF35F6ULL,
		0xB5075D1B01BAAF6EULL,
		0x32C2505332C1A682ULL,
		0xD8C6D4EAF0803B55ULL,
		0x10D7B08ECF7DE21DULL,
		0x313B8A543A7804CBULL,
		0xCD3F1ED601FD04A5ULL
	}};
	curve25519_key_t k3 = {.key64 = {
		0x982282793086073EULL,
		0x37E1A7C7D36C00B2ULL,
		0x802A3A7DA267B04BULL,
		0x76D26EAA6049A8E0ULL,
		0x9848F2665B8C1F1EULL,
		0x73CEF43611265E76ULL,
		0xC46104F038D6E79BULL,
		0x961921A1262AC4F8ULL
	}};
	printf("Underflow\n");
	int sign = 1;
	printf("Test Case 1\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	int borrow = curve25519_key_sub(&k1, &k2, &r);
	int32_t res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 1 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x92B33559C3C35F66ULL,
		0x2C3D209E7AFB7DEEULL,
		0xA5D44EFDF27F79BAULL,
		0x6A215FF74F71430DULL,
		0x0D447BBBE8070D1FULL,
		0x7282B3281DF859C9ULL,
		0x12C890ECD8DAFF15ULL,
		0x6442C382E5FFAC93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FA52E25654D9259ULL,
		0xF01173DC1265027CULL,
		0xBE1D3279442F7308ULL,
		0x554CC8DA7D5F71D8ULL,
		0xD4E0D08DF5618F26ULL,
		0x70AC140DAC4C582AULL,
		0xD8E05B6EEAAC01B2ULL,
		0xE0D88F246FF63D1DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x330E07345E75CD0DULL,
		0x3C2BACC268967B72ULL,
		0xE7B71C84AE5006B1ULL,
		0x14D4971CD211D134ULL,
		0x3863AB2DF2A57DF9ULL,
		0x01D69F1A71AC019EULL,
		0x39E8357DEE2EFD63ULL,
		0x836A345E76096F75ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 2\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 2 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x51A5C912A7FFFE82ULL,
		0xBB58DEBC7D984E8FULL,
		0x1FE832721C303C1DULL,
		0x0E24D2D5CF200DE1ULL,
		0x8AB2E2BDD66ABE40ULL,
		0xBB7821DBA5566D50ULL,
		0xD7866EAF816D05A0ULL,
		0x85F316D8B4AA5CAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB02E3606140FCD20ULL,
		0xDCCC103189E8A0AEULL,
		0xFBFA38AD1776107DULL,
		0x7947A248D2845BB9ULL,
		0xAA8A6A9B8C96AB1FULL,
		0x2B7668EEAAD6389CULL,
		0x47824AE43D68B3C0ULL,
		0xC4457AB65FA6A495ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA177930C93F03162ULL,
		0xDE8CCE8AF3AFADE0ULL,
		0x23EDF9C504BA2B9FULL,
		0x94DD308CFC9BB227ULL,
		0xE028782249D41320ULL,
		0x9001B8ECFA8034B3ULL,
		0x900423CB440451E0ULL,
		0xC1AD9C225503B81AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 3\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 3 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE7D3BCD1D2AD4B8EULL,
		0xB0126329D890386AULL,
		0x2E5165791AB54706ULL,
		0x3EA569205CE935A8ULL,
		0xB13707DD40AAFCBDULL,
		0x57D19D784BDEDE9DULL,
		0xC52D77F3D2AECEA9ULL,
		0x33ED7C3BC5BB0B3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9A1D166541724E5ULL,
		0xDD4AF8AC099F48DEULL,
		0x4DFC0DCD7F82415CULL,
		0xB3CF6B15FA8468D3ULL,
		0xF2AD4ADE552F9501ULL,
		0xA78FD4F5FB8EA305ULL,
		0x3FC4B3BA802FB3B1ULL,
		0xC95D05A1E58FC484ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3E31EB6B7E9626A9ULL,
		0xD2C76A7DCEF0EF8CULL,
		0xE05557AB9B3305A9ULL,
		0x8AD5FE0A6264CCD4ULL,
		0xBE89BCFEEB7B67BBULL,
		0xB041C88250503B97ULL,
		0x8568C439527F1AF7ULL,
		0x6A907699E02B46B6ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 4\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 4 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBFC3661D6C2EE486ULL,
		0x5D08EA2D2A03F98DULL,
		0x7AFC91F459ABA016ULL,
		0x29F9B1022EE7CD14ULL,
		0x25A41DE33E8C3E5FULL,
		0x74EB5F3CB19E93FBULL,
		0x05CE98A2BFD5878EULL,
		0x5BBA8D87CEC859C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83E8C2361CAFEA87ULL,
		0xCCF9B8D5466F74B3ULL,
		0x5F1F3790B034C6CDULL,
		0x9E83787E63076856ULL,
		0xBBB05F76C42CE715ULL,
		0x993B980F6D80F98CULL,
		0xC89E8B3699CD1903ULL,
		0x2B949ABA9431BE9EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3BDAA3E74F7EF9FFULL,
		0x900F3157E39484DAULL,
		0x1BDD5A63A976D948ULL,
		0x8B763883CBE064BEULL,
		0x69F3BE6C7A5F5749ULL,
		0xDBAFC72D441D9A6EULL,
		0x3D300D6C26086E8AULL,
		0x3025F2CD3A969B25ULL
	}};
	sign = 0;
	printf("Test Case 5\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 5 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7BBD64A843F11FF6ULL,
		0xB64C199639480E60ULL,
		0x24884B5F82699CFAULL,
		0xDA42DBE52AF8C482ULL,
		0x32E877830569F05AULL,
		0x2C5C7A172F64D9FBULL,
		0xE861A8D26694F703ULL,
		0x28348C4F9F59B677ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4682DD59AA7549AFULL,
		0xB57FE6617F1A94A5ULL,
		0x0B68D6094E4F0B2FULL,
		0xAC54B8BB5020E62CULL,
		0x5DB4C754CF0B07EEULL,
		0x48F2CEE0814AA05DULL,
		0xD8CE2642D8E28433ULL,
		0xF1EBD298452056DFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x353A874E997BD647ULL,
		0x00CC3334BA2D79BBULL,
		0x191F7556341A91CBULL,
		0x2DEE2329DAD7DE56ULL,
		0xD533B02E365EE86CULL,
		0xE369AB36AE1A399DULL,
		0x0F93828F8DB272CFULL,
		0x3648B9B75A395F98ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 6\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 6 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB2E2F81A05AB5B9BULL,
		0xC3D488285D36330EULL,
		0xE83E8561BBEDA2B2ULL,
		0xD6E5FD34C27006E7ULL,
		0x6E552EA6AA4A3E3EULL,
		0xCDF42A7C0B9126C6ULL,
		0x3907AC3760E683B4ULL,
		0x1AFCA50328DA7A01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2561DE4CD2D64C36ULL,
		0xF2E6A23ED8F138B9ULL,
		0x333A37EE6A9D47D0ULL,
		0x56E98DC387C68CE9ULL,
		0x0ABF70714C2A96B4ULL,
		0x010FC5FEC2CDCE98ULL,
		0x886375C2188A8E08ULL,
		0xC3BC7DCF2B96FEB1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8D8119CD32D50F65ULL,
		0xD0EDE5E98444FA55ULL,
		0xB5044D7351505AE1ULL,
		0x7FFC6F713AA979FEULL,
		0x6395BE355E1FA78AULL,
		0xCCE4647D48C3582EULL,
		0xB0A43675485BF5ACULL,
		0x57402733FD437B4FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 7\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 7 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8A0C30E2D24C4A1CULL,
		0x5F4FB32BA86D255EULL,
		0x5A7767C31FCBEF1BULL,
		0x1ABA2D54FA2A4916ULL,
		0x50E791736F5440A7ULL,
		0x9308014D561B6429ULL,
		0x07253887E53B918AULL,
		0x080D09853125A61FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B0975504ED5D7B9ULL,
		0x96A6FEC5600334BCULL,
		0xCAEEA5BF229B25DBULL,
		0xF7E3207DAB31AD10ULL,
		0x4789B1AC5D6762C1ULL,
		0xEDD3AC41A8387E4EULL,
		0x8D1A00FAEC52B3CAULL,
		0x62C4A13581AE7377ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2F02BB9283767263ULL,
		0xC8A8B4664869F0A2ULL,
		0x8F88C203FD30C93FULL,
		0x22D70CD74EF89C05ULL,
		0x095DDFC711ECDDE5ULL,
		0xA534550BADE2E5DBULL,
		0x7A0B378CF8E8DDBFULL,
		0xA548684FAF7732A7ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 8\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 8 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC2FB823C5F0A3E9AULL,
		0xAD8BDDB21EE4C169ULL,
		0xC35A82A9FB85043CULL,
		0x6BF080EABBF0EF98ULL,
		0x2594580F24789C63ULL,
		0xB75A26827CCA5217ULL,
		0x2A5C73E1604E4EA4ULL,
		0x6AD71470C36BD551ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58523612754DB3C2ULL,
		0x937E7C6FCC21F405ULL,
		0x3013441E7462B42FULL,
		0x6CF9B8C724CA47CFULL,
		0xAA363EF34EC495D6ULL,
		0x647FF144D1DC4625ULL,
		0x65A1DFEA0464F29BULL,
		0xDC8C51439D035C12ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6AA94C29E9BC8AD8ULL,
		0x1A0D614252C2CD64ULL,
		0x93473E8B8722500DULL,
		0xFEF6C8239726A7C9ULL,
		0x7B5E191BD5B4068CULL,
		0x52DA353DAAEE0BF1ULL,
		0xC4BA93F75BE95C09ULL,
		0x8E4AC32D2668793EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 9\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 9 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0D63C2E4D769F227ULL,
		0x608B60734E85B785ULL,
		0x7DE8F81C34927984ULL,
		0x655C40ABC5EF0DC0ULL,
		0x0605629B53C6D82BULL,
		0x7F09439BC3934AF4ULL,
		0x740D683A18322E9BULL,
		0x6CDC09B3D4EF125EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75E952169B40EAB0ULL,
		0x9056C6FDD02A6545ULL,
		0x13E313FDB2460394ULL,
		0xBF83C74C0A8B3452ULL,
		0x7922F012E54F7F72ULL,
		0x9E93B32C1D4BBB0FULL,
		0x8BB141B3D3CC5A61ULL,
		0xDD4B41714A836C2FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x977A70CE3C290777ULL,
		0xD03499757E5B523FULL,
		0x6A05E41E824C75EFULL,
		0xA5D8795FBB63D96EULL,
		0x8CE272886E7758B8ULL,
		0xE075906FA6478FE4ULL,
		0xE85C26864465D439ULL,
		0x8F90C8428A6BA62EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 10\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 10 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x272CF3688D41F2B6ULL,
		0xC6A2995EA3820E97ULL,
		0xB890DEFB4D332AF4ULL,
		0xBF15A8F8605FD498ULL,
		0xDD17ACEF08FFDA90ULL,
		0x625F876AECC2FAFDULL,
		0xB063F096C568A640ULL,
		0xE88BD7ECE1D0415DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC899CE54275990ECULL,
		0x4F70F13DF6957B74ULL,
		0xD30A6337EC4B0F93ULL,
		0xE0B802886B480584ULL,
		0x8DA0A48B29536308ULL,
		0x99650D95C3F2E73CULL,
		0xEEFA1924437D6DF1ULL,
		0x074BD143EC9C9C94ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5E93251465E861CAULL,
		0x7731A820ACEC9322ULL,
		0xE5867BC360E81B61ULL,
		0xDE5DA66FF517CF13ULL,
		0x4F770863DFAC7787ULL,
		0xC8FA79D528D013C1ULL,
		0xC169D77281EB384EULL,
		0xE14006A8F533A4C8ULL
	}};
	sign = 0;
	printf("Test Case 11\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 11 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE96E27CFCFE24E19ULL,
		0x99A91486D750CD03ULL,
		0x9E0F8D795F7BE6E4ULL,
		0xD51E942AB386C867ULL,
		0x5E22A7DDA41AC58EULL,
		0xE8B20D3870C987A7ULL,
		0x7C529482BB8A4FE8ULL,
		0x05E289A7C100C49FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEBD539BF3CBF5E6ULL,
		0x1B243ACEE21FEF17ULL,
		0xF057808A9198407AULL,
		0xD7003EE1D27146A6ULL,
		0x78BDF8AB18CA2BC2ULL,
		0xB8ACB6FB4F54C973ULL,
		0xE743163BDFC65353ULL,
		0xEC8FCC8F8E7A6394ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0AB0D433DC165833ULL,
		0x7E84D9B7F530DDECULL,
		0xADB80CEECDE3A66AULL,
		0xFE1E5548E11581C0ULL,
		0xE564AF328B5099CBULL,
		0x3005563D2174BE33ULL,
		0x950F7E46DBC3FC95ULL,
		0x1952BD183286610AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 12\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 12 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x39420B177838A0C5ULL,
		0x401FA3D35B6A92C3ULL,
		0x4E1DF5A94FEC0FB8ULL,
		0x29D49F3E19BFB952ULL,
		0x01D533D747DA17E2ULL,
		0xE32D78E0C4CB79FDULL,
		0xCD9FBBA7D2D38BD2ULL,
		0x6A7D2332F9627777ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E3B48DF673B4796ULL,
		0x9B0BFA1885BD10ADULL,
		0xCF5E4E8DCA99F497ULL,
		0x1EEAF8C1C59768F2ULL,
		0xFD414BA0727E0362ULL,
		0x10A082716975C1BCULL,
		0xCB0D077537D1A48BULL,
		0x164C7F89AE7A16ADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCB06C23810FD592FULL,
		0xA513A9BAD5AD8215ULL,
		0x7EBFA71B85521B20ULL,
		0x0AE9A67C5428505FULL,
		0x0493E836D55C1480ULL,
		0xD28CF66F5B55B840ULL,
		0x0292B4329B01E747ULL,
		0x5430A3A94AE860CAULL
	}};
	sign = 0;
	printf("Test Case 13\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 13 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCD4F334FD098F488ULL,
		0x614CC321E66086EBULL,
		0x3D33FB60891F6FDCULL,
		0x792806E593504CFAULL,
		0x26B8B1563F6D5899ULL,
		0xAACCA22663906051ULL,
		0xFEDB4479F83F02D6ULL,
		0xF02DD5F1AA8EBA20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x242CC94B6F88854AULL,
		0x8306F964C81B31CCULL,
		0xB21BDBE392EA967CULL,
		0xE4B46AA59550840DULL,
		0x4947190C192C5F14ULL,
		0xEB350C4762C27C92ULL,
		0x9A0CF2BEDA47AF63ULL,
		0x04AE65F4F8BBE6AAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA9226A0461106F3EULL,
		0xDE45C9BD1E45551FULL,
		0x8B181F7CF634D95FULL,
		0x94739C3FFDFFC8ECULL,
		0xDD71984A2640F984ULL,
		0xBF9795DF00CDE3BEULL,
		0x64CE51BB1DF75372ULL,
		0xEB7F6FFCB1D2D376ULL
	}};
	sign = 0;
	printf("Test Case 14\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 14 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x24DFFC5416567FFBULL,
		0xAA75BD28A84FAEDAULL,
		0x3065CAEB1253B898ULL,
		0x6F836B7D55DEAE20ULL,
		0x6B8D9F3E8EAF1757ULL,
		0xAE75CF29994E4E36ULL,
		0xCE0473FED38CF592ULL,
		0xB713889CA0B84299ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xECD6AD10A4F42755ULL,
		0x97DBDEDB594F6CE6ULL,
		0x7BB7F848E11EE9B5ULL,
		0xBE5DE6FE91553A09ULL,
		0xD1C26CCA7E3C3A58ULL,
		0x93E494AEA9B0A83DULL,
		0x34ED3AD8548E6FB1ULL,
		0x9DC361D400430BDBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x38094F43716258A6ULL,
		0x1299DE4D4F0041F3ULL,
		0xB4ADD2A23134CEE3ULL,
		0xB125847EC4897416ULL,
		0x99CB32741072DCFEULL,
		0x1A913A7AEF9DA5F8ULL,
		0x991739267EFE85E1ULL,
		0x195026C8A07536BEULL
	}};
	sign = 0;
	printf("Test Case 15\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 15 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x38D42F77BF3847E5ULL,
		0x3E2BF500F5B40CE5ULL,
		0xAB3BC195AF04593AULL,
		0x5D163E4EDDD85846ULL,
		0xB1D99F37537162DFULL,
		0x4A3541A5A81245F9ULL,
		0x3008F2B3D3EA2B66ULL,
		0x494D2D7265C8319EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9B3EFE995D79011ULL,
		0xBCAB1E0720B744CEULL,
		0xDEA25B99F046C455ULL,
		0x21D9B50E24466F68ULL,
		0x3979B44596373DCBULL,
		0x52610D064BD8E8AAULL,
		0xC790C0B00CD853BEULL,
		0xDAB4123559AB4B6AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5F203F8E2960B7D4ULL,
		0x8180D6F9D4FCC816ULL,
		0xCC9965FBBEBD94E4ULL,
		0x3B3C8940B991E8DDULL,
		0x785FEAF1BD3A2514ULL,
		0xF7D4349F5C395D4FULL,
		0x68783203C711D7A7ULL,
		0x6E991B3D0C1CE633ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 16\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 16 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF76924A6FDAE2EA0ULL,
		0xE60751BE4E8C0C9CULL,
		0x1BE59EBB0FC07B6CULL,
		0x6C4E8B82BF7548A6ULL,
		0x385B2336A92A1887ULL,
		0x6082A67EF90D5911ULL,
		0x14453699A39D0FF0ULL,
		0x21C3EA34F08CB075ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCEC4F52DC7D114DULL,
		0x89BD9C5405DA7C67ULL,
		0x33441E4ABFD7A769ULL,
		0x2E94C3BA419C522CULL,
		0x11C73047DD2F4DB7ULL,
		0xAE8451DBE4DC08E6ULL,
		0x91AAC7AA02ED8DCFULL,
		0xB9BD86CB72325C22ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFA7CD55421311D53ULL,
		0x5C49B56A48B19034ULL,
		0xE8A180704FE8D403ULL,
		0x3DB9C7C87DD8F679ULL,
		0x2693F2EECBFACAD0ULL,
		0xB1FE54A31431502BULL,
		0x829A6EEFA0AF8220ULL,
		0x680663697E5A5452ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 17\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 17 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE35310472D5B170FULL,
		0x3D774329B7D045B2ULL,
		0xE53476AA08443AD7ULL,
		0x6279E5222E51504CULL,
		0xE9A7FE45BCF4AF6EULL,
		0x4DD6723B9D617CEDULL,
		0xD8136287A47634C1ULL,
		0x7F37B7BDECBF4B03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EA308BDF25A10D5ULL,
		0x660B43E3E980A7B4ULL,
		0xB1576B06366B9C89ULL,
		0x82D3B4D8FF4796C4ULL,
		0xBE63F0717E7E959FULL,
		0xDF17DD3DEB2D1999ULL,
		0xC30BE6F3B0FBFCF0ULL,
		0x5B3B95FC860CF8FDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x74B007893B01063AULL,
		0xD76BFF45CE4F9DFEULL,
		0x33DD0BA3D1D89E4DULL,
		0xDFA630492F09B988ULL,
		0x2B440DD43E7619CEULL,
		0x6EBE94FDB2346354ULL,
		0x15077B93F37A37D0ULL,
		0x23FC21C166B25206ULL
	}};
	sign = 0;
	printf("Test Case 18\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 18 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x841D0551B3BA68BFULL,
		0x0E3A23130D08D17BULL,
		0x7ED3F18A670D136AULL,
		0xE761BA4B4A1DF862ULL,
		0x4FF2C326D75CF761ULL,
		0x3403D33A0F19ADCDULL,
		0x31372A184AE9B421ULL,
		0x512B1C8E26A73922ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2CABEE1628DB237ULL,
		0x170CCADDA76EDBE8ULL,
		0x38B4E98CD37B9043ULL,
		0x6D4006C4F7D2CE76ULL,
		0xB8812093A3602CA7ULL,
		0x31BACBE09C4D0207ULL,
		0x9A15DD2EDF33620BULL,
		0x5E06B1A9B5776827ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD1524670512CB688ULL,
		0xF72D58356599F592ULL,
		0x461F07FD93918326ULL,
		0x7A21B386524B29ECULL,
		0x9771A29333FCCABAULL,
		0x0249075972CCABC5ULL,
		0x97214CE96BB65216ULL,
		0xF3246AE4712FD0FAULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 19\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 19 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDEADFACEC0761D0AULL,
		0x75249429121C4072ULL,
		0x6C99E0FAD1C93E5CULL,
		0xE1AFEDFF2C1A930EULL,
		0x06F6EB83802D44E2ULL,
		0x1951C1F1DBE5CE29ULL,
		0xF52D2D10EA7ECB5BULL,
		0x62D5CC3E2D90022EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67A92F7BC8312B2DULL,
		0x3B9667A57F27C0FDULL,
		0x1B1D1FDCE9BC9154ULL,
		0x2C1E60C7A54A4E8DULL,
		0x846D9CDBFBB83FF4ULL,
		0x68D3A59AA630CD41ULL,
		0xA47CA37D7660CDF0ULL,
		0x3F9F4E88B2368EC4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7704CB52F844F1DDULL,
		0x398E2C8392F47F75ULL,
		0x517CC11DE80CAD08ULL,
		0xB5918D3786D04481ULL,
		0x82894EA7847504EEULL,
		0xB07E1C5735B500E7ULL,
		0x50B08993741DFD6AULL,
		0x23367DB57B59736AULL
	}};
	sign = 0;
	printf("Test Case 20\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 20 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9032AB7125D0D125ULL,
		0x0170023B22B9AF05ULL,
		0x226E6E714318BC77ULL,
		0x23DDEEDFE1D7D5B6ULL,
		0x0DAEF3243D1B4B8EULL,
		0xC5D1831585103A3FULL,
		0xAB1AE49E7FC16085ULL,
		0x5CA62CF20B6A8D8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DF0A31E0927AC3CULL,
		0x333659B72482E41BULL,
		0x8D0849E98AE6B13DULL,
		0x4A2C7E42B5C4FEE2ULL,
		0xCEDBB0741F442108ULL,
		0x6E349BCA21676C15ULL,
		0xFEACE87F21D989CDULL,
		0x9F8B3B15F24D9699ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x824208531CA924E9ULL,
		0xCE39A883FE36CAEAULL,
		0x95662487B8320B39ULL,
		0xD9B1709D2C12D6D3ULL,
		0x3ED342B01DD72A85ULL,
		0x579CE74B63A8CE29ULL,
		0xAC6DFC1F5DE7D6B8ULL,
		0xBD1AF1DC191CF6F0ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 21\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 21 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x803FB7F086E51862ULL,
		0x511E2AA196809293ULL,
		0x0D1B310886A627B5ULL,
		0x4119BDBC71C1A541ULL,
		0x6FF4F5769C970B04ULL,
		0x54EF580B2909A205ULL,
		0x2D05485464A2FFDEULL,
		0xACD67CBA9EEA094EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB54C375019B0D46EULL,
		0x87FA565E97583572ULL,
		0x32C541508A1ACE67ULL,
		0x5C6A22CCE8FCFCBCULL,
		0x027F1D81D6D54211ULL,
		0x6279263DEE65417BULL,
		0xDB5CCD04FF45CE05ULL,
		0x8A6B94D939AC4CEEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCAF380A06D3443F4ULL,
		0xC923D442FF285D20ULL,
		0xDA55EFB7FC8B594DULL,
		0xE4AF9AEF88C4A884ULL,
		0x6D75D7F4C5C1C8F2ULL,
		0xF27631CD3AA4608AULL,
		0x51A87B4F655D31D8ULL,
		0x226AE7E1653DBC5FULL
	}};
	sign = 0;
	printf("Test Case 22\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 22 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8CA25C892D6910FFULL,
		0x11330EB7F67AFD72ULL,
		0x197F91129DFD31D4ULL,
		0x9636CAA2A1A9FDE5ULL,
		0xD82B786E576D2795ULL,
		0x790CC7C40561358AULL,
		0x216C63189B142C4FULL,
		0x04B7C8639E6498A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF54D4D771584935ULL,
		0x7AF543CCA3CF5904ULL,
		0x02B7F98758A0619BULL,
		0xA75B7750EBC1B8D9ULL,
		0xC8532AD8388F93DAULL,
		0x190DB6CDB0BDA158ULL,
		0xD41D92386754F9DBULL,
		0x2DFC6E4E9ABFB751ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8D4D87B1BC10C7CAULL,
		0x963DCAEB52ABA46DULL,
		0x16C7978B455CD038ULL,
		0xEEDB5351B5E8450CULL,
		0x0FD84D961EDD93BAULL,
		0x5FFF10F654A39432ULL,
		0x4D4ED0E033BF3274ULL,
		0xD6BB5A1503A4E150ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 23\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 23 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x204D2946D3A4ACF3ULL,
		0x80C033A5B049C7BCULL,
		0x6C9A33A0AB76C531ULL,
		0xEBBF92D6820192CCULL,
		0xBC617F104D21D839ULL,
		0xE7767B04FFE9C129ULL,
		0x938631C9CE5CA51BULL,
		0x8286EC7961514071ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4BBE8F7B517E37BULL,
		0x310DEC2F392CEB78ULL,
		0xFEA77DE744778358ULL,
		0x6E3323A7696E24DEULL,
		0xA2CC50360D71EE4BULL,
		0xED247C01ECAF86FEULL,
		0xC0EF2951FDAE13F5ULL,
		0xA1313AEEEDEB74F4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7B91404F1E8CC978ULL,
		0x4FB24776771CDC43ULL,
		0x6DF2B5B966FF41D9ULL,
		0x7D8C6F2F18936DEDULL,
		0x19952EDA3FAFE9EEULL,
		0xFA51FF03133A3A2BULL,
		0xD2970877D0AE9125ULL,
		0xE155B18A7365CB7CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 24\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 24 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x430A7FB1C75F9271ULL,
		0x71434569F78B0873ULL,
		0x4FAEC626F39664D4ULL,
		0x782748405ED981ADULL,
		0x6507DFA6EB1FFC24ULL,
		0x001443EE6F5E090BULL,
		0xE227CA756756E531ULL,
		0xF1C4E6A8EAF6F355ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CC0AECCF18EE403ULL,
		0xA444C362B900BD72ULL,
		0x7ACBE9781D75DD7FULL,
		0xE678C544941AA1D4ULL,
		0xD71A280BFEB2FC6AULL,
		0xC37FE40C43722979ULL,
		0xBC16598EC50B174EULL,
		0xF60AC51C026DB9C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2649D0E4D5D0AE6EULL,
		0xCCFE82073E8A4B01ULL,
		0xD4E2DCAED6208754ULL,
		0x91AE82FBCABEDFD8ULL,
		0x8DEDB79AEC6CFFB9ULL,
		0x3C945FE22BEBDF91ULL,
		0x261170E6A24BCDE2ULL,
		0xFBBA218CE8893993ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 25\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 25 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD473D113D24B4DD6ULL,
		0xABB51AAB627B33B3ULL,
		0xFD299D61256A86ECULL,
		0x4F018A7FB8492ED8ULL,
		0x1D418C72F8BA4105ULL,
		0x64DDA244A50824F6ULL,
		0x0BF4CAFDBA09CA20ULL,
		0x3F15CD2FE7ABFD68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF773FAFFBC864BA5ULL,
		0x9ADEAF0E75C65C9BULL,
		0x910AF18C9BA167C5ULL,
		0x81EFA7B069653041ULL,
		0xF85A570530C21DC8ULL,
		0xB49825DF873F85D2ULL,
		0xC0E500F6A1EFEA73ULL,
		0xECA2526E12D9FFE6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDCFFD61415C50231ULL,
		0x10D66B9CECB4D717ULL,
		0x6C1EABD489C91F27ULL,
		0xCD11E2CF4EE3FE97ULL,
		0x24E7356DC7F8233CULL,
		0xB0457C651DC89F23ULL,
		0x4B0FCA071819DFACULL,
		0x52737AC1D4D1FD81ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 26\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 26 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD82CF573160785E9ULL,
		0x097FFC3365B6F1C6ULL,
		0xEA516CED12254935ULL,
		0xFA96CE9D3CF1A369ULL,
		0xB889B4B655BCB715ULL,
		0xF215C1B043B56AE7ULL,
		0xDB9BA11C3F2B3A99ULL,
		0x5E2BD8C9B60251FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD2205A9C5A4C50BULL,
		0xD34EC1C68FE6190EULL,
		0xD300607314D80BC1ULL,
		0x7040C61200350030ULL,
		0x65B68FA5B5197331ULL,
		0xDABED2D7DEF30F7BULL,
		0xC652C0BB5A23B326ULL,
		0x2BA4ECCE9AAE7D46ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1B0AEFC95062C0DEULL,
		0x36313A6CD5D0D8B8ULL,
		0x17510C79FD4D3D73ULL,
		0x8A56088B3CBCA339ULL,
		0x52D32510A0A343E4ULL,
		0x1756EED864C25B6CULL,
		0x1548E060E5078773ULL,
		0x3286EBFB1B53D4B6ULL
	}};
	sign = 0;
	printf("Test Case 27\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 27 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1E881EB59B0BACA0ULL,
		0x560A262D33E0AC68ULL,
		0x36ABC9A63E7B5F28ULL,
		0x5507673C1922CBADULL,
		0x2DDBDC9502C3A7FDULL,
		0xFB7ADEB0A7896910ULL,
		0xF7524A218A097B5AULL,
		0xCA55D805603F42E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B14DEFDC2BF0736ULL,
		0xDB5DC5C5B6780C64ULL,
		0xA9DC2BB7F9A0FAF5ULL,
		0xE5EF9D0157A9081BULL,
		0x94BD6C27E392227AULL,
		0x0401D40BEC0E0760ULL,
		0x41951365BFAACD13ULL,
		0xD779676D13FC129AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x03733FB7D84CA56AULL,
		0x7AAC60677D68A004ULL,
		0x8CCF9DEE44DA6432ULL,
		0x6F17CA3AC179C391ULL,
		0x991E706D1F318582ULL,
		0xF7790AA4BB7B61AFULL,
		0xB5BD36BBCA5EAE47ULL,
		0xF2DC70984C43304BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 28\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 28 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5BEBEB7F70D30F2AULL,
		0x3BB4DB24780DD7E5ULL,
		0x1E5A8A9BB477CF26ULL,
		0x3EB57342BAF148AFULL,
		0xE4E478E812CD2142ULL,
		0xA1E51D190857BA4BULL,
		0x68C18E1723F3F0FFULL,
		0x4A9C9FA6ABB94CEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7681E8461A39C845ULL,
		0xF5CE28684F1DCC20ULL,
		0xBC49AD2B1156E12CULL,
		0xC6A85AEFF6E4CEAEULL,
		0x6A34B04FCB9B8A0AULL,
		0x3FB4BC8B7DE0B0C2ULL,
		0x718B8C723EEA1131ULL,
		0xFDD7B091912E32AAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE56A0339569946E5ULL,
		0x45E6B2BC28F00BC4ULL,
		0x6210DD70A320EDF9ULL,
		0x780D1852C40C7A00ULL,
		0x7AAFC89847319737ULL,
		0x6230608D8A770989ULL,
		0xF73601A4E509DFCEULL,
		0x4CC4EF151A8B1A43ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 29\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 29 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD2E7FA128DBB260BULL,
		0xB64E95BD54C8EA05ULL,
		0x99149498F3CAA991ULL,
		0xAADAB74D8079F7B3ULL,
		0xC72CDA63898703C8ULL,
		0xD872C2D2B070FC3EULL,
		0xD0446B0D10295B48ULL,
		0x25FD92861D694D0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71E758F04237DB16ULL,
		0xE97F9FE0F2399C3BULL,
		0x443B877E26498F3FULL,
		0x4B0C80E73FDD2911ULL,
		0x5AA6706F99EE7A04ULL,
		0x53C0534DBFFBE3C6ULL,
		0x52C81858B83E2C4DULL,
		0x809E4034CF830409ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6100A1224B834AF5ULL,
		0xCCCEF5DC628F4DCAULL,
		0x54D90D1ACD811A51ULL,
		0x5FCE3666409CCEA2ULL,
		0x6C8669F3EF9889C4ULL,
		0x84B26F84F0751878ULL,
		0x7D7C52B457EB2EFBULL,
		0xA55F52514DE64903ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 30\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 30 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEEC91D64DBB8A621ULL,
		0x57B6C2BE26C3D0F8ULL,
		0x7EAAAE2F657D4EB0ULL,
		0x994828106FE73CBFULL,
		0x5D70BEF0D00207B7ULL,
		0xC3C40C97FCA9A6BCULL,
		0x32E3ED72C2E0557DULL,
		0x1C17F7394CD868AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FAE2665BF19846DULL,
		0x49C1BD1AE7FC8018ULL,
		0xD7B15655B86A063EULL,
		0x5CF0D33DC1AC2CB8ULL,
		0xB6059B8EAF9CD18AULL,
		0x2F6496CBB6EF4B1AULL,
		0x8D72F12601A58DEEULL,
		0x65FC946BA5123FA3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8F1AF6FF1C9F21B4ULL,
		0x0DF505A33EC750E0ULL,
		0xA6F957D9AD134872ULL,
		0x3C5754D2AE3B1006ULL,
		0xA76B23622065362DULL,
		0x945F75CC45BA5BA1ULL,
		0xA570FC4CC13AC78FULL,
		0xB61B62CDA7C6290AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 31\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 31 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x85FF347070ACBA5BULL,
		0xD286A00926F824DFULL,
		0xEB706F99F6E68945ULL,
		0x66DAFE36BDD11B9DULL,
		0xD3A73368866EF35DULL,
		0x1B14DAF73E6721B8ULL,
		0xD12CD35BF04C35C1ULL,
		0x75977B6D22450CE5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12FFAB1B0657800AULL,
		0x34B53EE55CC1B44AULL,
		0x186027F4A7B77A86ULL,
		0x94822C414ADEC2A1ULL,
		0xA8841B541351024FULL,
		0xE2307D79F9319F0AULL,
		0xA797885E6F4FF27EULL,
		0xD2977CCC996A271FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x72FF89556A553A51ULL,
		0x9DD16123CA367095ULL,
		0xD31047A54F2F0EBFULL,
		0xD258D1F572F258FCULL,
		0x2B231814731DF10DULL,
		0x38E45D7D453582AEULL,
		0x29954AFD80FC4342ULL,
		0xA2FFFEA088DAE5C6ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 32\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 32 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCF5CB7A60B107CEEULL,
		0x5BBC75BA75413F23ULL,
		0x9ED030DB10028A22ULL,
		0x35FAD076BAB1C8DEULL,
		0xB0E1994255A5313AULL,
		0x29BA097372F22726ULL,
		0xF17C96FB7F25B6F9ULL,
		0xAD9B535AE0ADBAD5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x597A24EC8749B995ULL,
		0x27685A1A23C5FB22ULL,
		0x763D61F234533921ULL,
		0x17D86AB38AB67BCAULL,
		0xA905E40A5240A122ULL,
		0xA5EC67E6948EE3E2ULL,
		0xC7B0DD7077CC98C7ULL,
		0x80398552EBC0BA74ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x75E292B983C6C359ULL,
		0x34541BA0517B4401ULL,
		0x2892CEE8DBAF5101ULL,
		0x1E2265C32FFB4D14ULL,
		0x07DBB53803649018ULL,
		0x83CDA18CDE634344ULL,
		0x29CBB98B07591E31ULL,
		0x2D61CE07F4ED0061ULL
	}};
	sign = 0;
	printf("Test Case 33\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 33 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x33B3D390C9C3729FULL,
		0x9FABCF61B725B454ULL,
		0x182ACA4D4D178786ULL,
		0xA5F43DAEE7925B05ULL,
		0x3DDF4CFA4FFA6020ULL,
		0xECD6FC7F2FEB954EULL,
		0x3E6BB8D29B352E4EULL,
		0xB5D33C9070BFC6B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x123A7F9FEA142F0EULL,
		0x922E0FEF168B9932ULL,
		0x6961DD8D3C5CFA0FULL,
		0xB9A552A92D324357ULL,
		0xB286F4A71ACBC5AFULL,
		0x9964B19FBE7F2AC7ULL,
		0xBB4FFBC6A0667667ULL,
		0xD75B8F4C66937B70ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x217953F0DFAF4391ULL,
		0x0D7DBF72A09A1B22ULL,
		0xAEC8ECC010BA8D77ULL,
		0xEC4EEB05BA6017ADULL,
		0x8B585853352E9A70ULL,
		0x53724ADF716C6A86ULL,
		0x831BBD0BFACEB7E7ULL,
		0xDE77AD440A2C4B44ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 34\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 34 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEEBED05865888A1FULL,
		0xFCDF7465747DBAA7ULL,
		0x224D322D2CCAE837ULL,
		0xB4003A9D1E997DB4ULL,
		0xB9594392363B1C16ULL,
		0xE662871C0D881CF4ULL,
		0x4B4287072E52CA0FULL,
		0x09DF477A673273F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E4AD0F524E7EBA4ULL,
		0x134116F499821135ULL,
		0x778A47803E6756CCULL,
		0x9E5878CA18048156ULL,
		0x1988A46485008960ULL,
		0x124FA18A34E548D7ULL,
		0xE04EFC4FBF30C095ULL,
		0xFE7F8B9D2422FE9AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5073FF6340A09E7BULL,
		0xE99E5D70DAFBA972ULL,
		0xAAC2EAACEE63916BULL,
		0x15A7C1D30694FC5DULL,
		0x9FD09F2DB13A92B6ULL,
		0xD412E591D8A2D41DULL,
		0x6AF38AB76F22097AULL,
		0x0B5FBBDD430F7555ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 35\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 35 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF7CA406FB04857D9ULL,
		0x4E436DAC58226024ULL,
		0x6EA2DD32AD3CCC92ULL,
		0x8B38881FDF7660A8ULL,
		0xDD223975A2078908ULL,
		0x05812CD5CD6D73B2ULL,
		0xEB87B976F31950BDULL,
		0xE5C499572814DC60ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29A80E356B7A5F47ULL,
		0xFB613C14A4503DCAULL,
		0x34EB1DA0A1110103ULL,
		0x546AF845BAF2A2E6ULL,
		0x3B3E1AF199E67AD0ULL,
		0x8D9FB8898C99D785ULL,
		0xB356058D4E26408FULL,
		0x7F0F53A89573A351ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCE22323A44CDF892ULL,
		0x52E23197B3D2225AULL,
		0x39B7BF920C2BCB8EULL,
		0x36CD8FDA2483BDC2ULL,
		0xA1E41E8408210E38ULL,
		0x77E1744C40D39C2DULL,
		0x3831B3E9A4F3102DULL,
		0x66B545AE92A1390FULL
	}};
	sign = 0;
	printf("Test Case 36\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 36 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x02D299D409F59219ULL,
		0xAB581BB434777124ULL,
		0x90D11FAFF1BE2A00ULL,
		0xDCFA2223B66BD47BULL,
		0x6BA454A5B0ADDC24ULL,
		0x76D6A7A690594D19ULL,
		0xF01F30BB93E61BF8ULL,
		0xA68D19C418B70FB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03D26F01EE0BF417ULL,
		0x3EF13C8DB3D90C35ULL,
		0xE3A094F8D791DA17ULL,
		0x274FFB97DADBD59EULL,
		0x865AE7EAE65944F0ULL,
		0x9CF5D5E5F3A91AA0ULL,
		0x933559E3745FD150ULL,
		0xA856DBFFD26A6E56ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFF002AD21BE99E02ULL,
		0x6C66DF26809E64EEULL,
		0xAD308AB71A2C4FE9ULL,
		0xB5AA268BDB8FFEDCULL,
		0xE5496CBACA549734ULL,
		0xD9E0D1C09CB03278ULL,
		0x5CE9D6D81F864AA7ULL,
		0xFE363DC4464CA15BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 37\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 37 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC65C3D947B9B2B8FULL,
		0xF671011AAC19DE65ULL,
		0x5D48AA9999AED7D4ULL,
		0x48E000D7B1E1FD54ULL,
		0xBB3DCCA09D092173ULL,
		0xD5B6DF3DF745FAEFULL,
		0x784763F152CEAF0EULL,
		0xB92688AD88BD9350ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5E7D2F431A06A09ULL,
		0xA322DB3E82A7C59BULL,
		0x7C769F816830D11DULL,
		0x848145DF22AAF780ULL,
		0x8852C902E98C0537ULL,
		0x793BE6E7AE90D971ULL,
		0xBB5CD0F3979CE0CBULL,
		0x6CF466F05C423F60ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE0746AA049FAC186ULL,
		0x534E25DC297218C9ULL,
		0xE0D20B18317E06B7ULL,
		0xC45EBAF88F3705D3ULL,
		0x32EB039DB37D1C3BULL,
		0x5C7AF85648B5217EULL,
		0xBCEA92FDBB31CE43ULL,
		0x4C3221BD2C7B53EFULL
	}};
	sign = 0;
	printf("Test Case 38\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 38 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFF417CEECEE39C2BULL,
		0xAE0B8FB525927336ULL,
		0x63D12CD476BD3330ULL,
		0x7E0B94813B8624CAULL,
		0x746D2B319CC12CA5ULL,
		0xC70E182667592958ULL,
		0xF29739F08D604485ULL,
		0x90378BDDBABFA989ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE47E025142596874ULL,
		0xBAF023B4DFB0981DULL,
		0x74F9270986BC06E5ULL,
		0x2791F0BB59707F17ULL,
		0x09B5CF5A92EC7DC8ULL,
		0x93EF2B8254A46393ULL,
		0x792C3E6166D14165ULL,
		0x6A4D17EE3F9D75DEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1AC37A9D8C8A33B7ULL,
		0xF31B6C0045E1DB19ULL,
		0xEED805CAF0012C4AULL,
		0x5679A3C5E215A5B2ULL,
		0x6AB75BD709D4AEDDULL,
		0x331EECA412B4C5C5ULL,
		0x796AFB8F268F0320ULL,
		0x25EA73EF7B2233ABULL
	}};
	sign = 0;
	printf("Test Case 39\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 39 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6ED96D20CA670C2AULL,
		0x14B842594559E8D6ULL,
		0x2C869A34658C755FULL,
		0x8C9AE909AB110C71ULL,
		0x28B08F78826B4C5CULL,
		0x1D32866213DFBAE1ULL,
		0x91CEABC4BEBDC764ULL,
		0x9E74038C702B1329ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CB93AC511DA942CULL,
		0x075C16C1377A4D11ULL,
		0x63F44D0F98AD1F6CULL,
		0xDFE944E280215D95ULL,
		0xE6681180DE94D776ULL,
		0x7438BF0F25008775ULL,
		0x2C95DE4CDAA95E84ULL,
		0xB3E843B480CEF2CAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE220325BB88C77FEULL,
		0x0D5C2B980DDF9BC4ULL,
		0xC8924D24CCDF55F3ULL,
		0xACB1A4272AEFAEDBULL,
		0x42487DF7A3D674E5ULL,
		0xA8F9C752EEDF336BULL,
		0x6538CD77E41468DFULL,
		0xEA8BBFD7EF5C205FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 40\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 40 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x856FBB8269B76B09ULL,
		0x6F2173E5637ECBBEULL,
		0x2204695CC3D20754ULL,
		0xBE0E692503181B20ULL,
		0xC92F26C555976843ULL,
		0x82CD0A396100A839ULL,
		0x8DA7685853139CEAULL,
		0x3D21CFE6006381A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF1C034DC6B910D9ULL,
		0xEBC229750BA735FEULL,
		0xEBCAC3F35176E7EBULL,
		0x7885556944FC9026ULL,
		0xFEC5924903C9B0A2ULL,
		0x56C84D1DB14CBA0BULL,
		0x4822E863ED9EF2E2ULL,
		0xBECE184CC3691852ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9653B834A2FE5A30ULL,
		0x835F4A7057D795BFULL,
		0x3639A569725B1F68ULL,
		0x458913BBBE1B8AF9ULL,
		0xCA69947C51CDB7A1ULL,
		0x2C04BD1BAFB3EE2DULL,
		0x45847FF46574AA08ULL,
		0x7E53B7993CFA694EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 41\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 41 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2B0E49454B243F54ULL,
		0x1B882EE62E06E2CBULL,
		0x69CC0B038DE6363EULL,
		0xFA890F757017383CULL,
		0x43563A7F54BDE49EULL,
		0x789482578E5EA39BULL,
		0xD26F0B0F22A14C45ULL,
		0xDFC532F877A7488CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x818E13299A361183ULL,
		0x12EEB0FA673F1036ULL,
		0xAC0FB7516E4C5612ULL,
		0xBB0F2A7827B1059FULL,
		0x9EC00E0E7C932E3DULL,
		0x1DF08A99FC1A9810ULL,
		0xFA3E9D7591EB1654ULL,
		0x69DCA75F9378E1A9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA980361BB0EE2DD1ULL,
		0x08997DEBC6C7D294ULL,
		0xBDBC53B21F99E02CULL,
		0x3F79E4FD4866329CULL,
		0xA4962C70D82AB661ULL,
		0x5AA3F7BD92440B8AULL,
		0xD8306D9990B635F1ULL,
		0x75E88B98E42E66E2ULL
	}};
	sign = 0;
	printf("Test Case 42\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 42 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7EAFD84B379EFCBAULL,
		0x7264104B1394B756ULL,
		0xBAF2B1C431F410BCULL,
		0x326AACB2F29A1910ULL,
		0xAD57C75BFEAF911EULL,
		0x234B0D95E170BE03ULL,
		0xC270104367C67CDAULL,
		0xE132C9F3B87B5D73ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32EC93C00ABC64D2ULL,
		0xF7DDA3D1BF1E1622ULL,
		0xE679E56640162199ULL,
		0xFEAF8F148100DAD0ULL,
		0xD6585265D3545902ULL,
		0x3AD1385B83F22DC6ULL,
		0xC7A59551D67D6335ULL,
		0x7FCD73234352D956ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4BC3448B2CE297E8ULL,
		0x7A866C795476A134ULL,
		0xD478CC5DF1DDEF22ULL,
		0x33BB1D9E71993E3FULL,
		0xD6FF74F62B5B381BULL,
		0xE879D53A5D7E903CULL,
		0xFACA7AF1914919A4ULL,
		0x616556D07528841CULL
	}};
	sign = 0;
	printf("Test Case 43\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 43 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x881E6F1A4C978ED1ULL,
		0x3477651BF3B099B1ULL,
		0xCC635123E1581191ULL,
		0x66F649D0D09BB191ULL,
		0x8C24840BDD8431F8ULL,
		0x538DD72356707325ULL,
		0xEED041B5B019B67FULL,
		0x5D909036CCA9FDA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DD6F061625C5F52ULL,
		0x8146EF9C8235057FULL,
		0x8BC9EDFC4C944776ULL,
		0x6FCE0FB1A2FD55A3ULL,
		0x23C9D7B45EF2411FULL,
		0x7FEEF0A60D3D883EULL,
		0x43CFFF04CF53E49FULL,
		0x6CBD7611B909A5B6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEA477EB8EA3B2F7FULL,
		0xB330757F717B9431ULL,
		0x4099632794C3CA1AULL,
		0xF7283A1F2D9E5BEEULL,
		0x685AAC577E91F0D8ULL,
		0xD39EE67D4932EAE7ULL,
		0xAB0042B0E0C5D1DFULL,
		0xF0D31A2513A057EBULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 44\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 44 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA88E75F687DDA06EULL,
		0x355BDDAE04856C7BULL,
		0x045F57D44AF195DAULL,
		0xB4A919BF2D9CA845ULL,
		0x39FB8AC0B0F11B18ULL,
		0x7405893608143B0AULL,
		0xBBDA946DABC6F31BULL,
		0xDE786181247CBA80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB8CB6039B9788C2ULL,
		0x7A5587E6EFB514AAULL,
		0xD5F360AB689CDD36ULL,
		0x2AA796ED087AA5BEULL,
		0x4719853645B41CE0ULL,
		0x46572159780E0ECCULL,
		0xE51ADC1B09928D72ULL,
		0xBEE12C9F526EE08EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xED01BFF2EC4617ACULL,
		0xBB0655C714D057D0ULL,
		0x2E6BF728E254B8A3ULL,
		0x8A0182D225220286ULL,
		0xF2E2058A6B3CFE38ULL,
		0x2DAE67DC90062C3DULL,
		0xD6BFB852A23465A9ULL,
		0x1F9734E1D20DD9F1ULL
	}};
	sign = 0;
	printf("Test Case 45\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 45 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9C49571726057CF4ULL,
		0x4AA5A1A5461D64D6ULL,
		0x4E26F8D7A092A534ULL,
		0x81687A397AABFCF1ULL,
		0x8A3B2AA24CADA20BULL,
		0xF01103DCC4F6774BULL,
		0xC903AB6628E160FCULL,
		0x8CCB9CDB3A1B9709ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF92910B0E0B500C4ULL,
		0xEA6489A5573B5C28ULL,
		0x286893C89A5A8AA4ULL,
		0xAA0E407499075F55ULL,
		0x596F17DCBBAAFC97ULL,
		0xD132561FA0B442A8ULL,
		0xE7ADB926673BB6CDULL,
		0x95731F3C071899DEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA320466645507C30ULL,
		0x604117FFEEE208ADULL,
		0x25BE650F06381A8FULL,
		0xD75A39C4E1A49D9CULL,
		0x30CC12C59102A573ULL,
		0x1EDEADBD244234A3ULL,
		0xE155F23FC1A5AA2FULL,
		0xF7587D9F3302FD2AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 46\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 46 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBA8954200E80FBF3ULL,
		0xCF6C17D32C4F19A4ULL,
		0x7FC19E67412D4044ULL,
		0x6247E6562BE2200EULL,
		0x038BABF4BA5A11AEULL,
		0x2A3C08573779A9CDULL,
		0x0BA41D00E670AD9FULL,
		0x404DF0206D1615F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3C7539AFDDDD98BULL,
		0x9A0233014A9866A0ULL,
		0x2AEFA08F845DDBFAULL,
		0xAC7DB0BEC5C57750ULL,
		0xA71E1DEAF55E0EDDULL,
		0x31B63452DD32F8AAULL,
		0x9AFD3D7F11E39F91ULL,
		0x4552A6F6358BAB62ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x16C2008510A32268ULL,
		0x3569E4D1E1B6B304ULL,
		0x54D1FDD7BCCF644AULL,
		0xB5CA3597661CA8BEULL,
		0x5C6D8E09C4FC02D0ULL,
		0xF885D4045A46B122ULL,
		0x70A6DF81D48D0E0DULL,
		0xFAFB492A378A6A8EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 47\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 47 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7C8EA1A74CB67311ULL,
		0x527A02F4CFA534E7ULL,
		0xCB1BE656FEB9D597ULL,
		0x66E406D6F5AD4EB2ULL,
		0x33C531E6E1D76865ULL,
		0x09D6126FB5F134D6ULL,
		0xB7EFAFF08CEDF635ULL,
		0xE428A862C79A6BBCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD02628C2D9C9C2C1ULL,
		0x5466E9B30EE3F9B2ULL,
		0x589BB6F82C15C100ULL,
		0xC5A3D92F8B7C43A4ULL,
		0x51385CF85C1B4FE6ULL,
		0xE74D800B23E8544BULL,
		0xFE881AFADADC789CULL,
		0x5447FE7851B46A02ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAC6878E472ECB050ULL,
		0xFE131941C0C13B34ULL,
		0x72802F5ED2A41496ULL,
		0xA1402DA76A310B0EULL,
		0xE28CD4EE85BC187EULL,
		0x228892649208E08AULL,
		0xB96794F5B2117D98ULL,
		0x8FE0A9EA75E601B9ULL
	}};
	sign = 0;
	printf("Test Case 48\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 48 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF42376FA69BCB63EULL,
		0x232B2BABB2F5750FULL,
		0x7C19EA076616B75FULL,
		0x3EB0FF9D4BD77E13ULL,
		0x5826DC248C8C57B2ULL,
		0x8F22DDFCC43200E8ULL,
		0xDD61A464BD3FC9EDULL,
		0x327266CA567BE257ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E3BB1F968C6CA30ULL,
		0x5D2312375F01475EULL,
		0xEE85458759016924ULL,
		0x9427B01CAB458CADULL,
		0x856E98F0269B8820ULL,
		0x374A16A344FF5E63ULL,
		0x7FF1084193FD67CFULL,
		0x6DB15D06660005D9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x65E7C50100F5EC0EULL,
		0xC608197453F42DB1ULL,
		0x8D94A4800D154E3AULL,
		0xAA894F80A091F165ULL,
		0xD2B8433465F0CF91ULL,
		0x57D8C7597F32A284ULL,
		0x5D709C232942621EULL,
		0xC4C109C3F07BDC7EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 49\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 49 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB46935772CEADF8DULL,
		0x5F2CF9C90D39F430ULL,
		0x8D0B3A02501604DDULL,
		0x0A5BD8E154CB59F2ULL,
		0x6FD9D45C6CD753E7ULL,
		0x2970B54854200EF7ULL,
		0x3711482F32DE0B05ULL,
		0x575329580057C4D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1A8FFA371619A6CULL,
		0xFCEC7E38899219FBULL,
		0x03BB2E61B530ABB5ULL,
		0x12F2613B203B8189ULL,
		0x480B41D9984D1274ULL,
		0xF882E51C0B06B5CDULL,
		0x652F98F4BEE1C82EULL,
		0x8F243D3F2A67C968ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF2C035D3BB894521ULL,
		0x62407B9083A7DA34ULL,
		0x89500BA09AE55927ULL,
		0xF76977A6348FD869ULL,
		0x27CE9282D48A4172ULL,
		0x30EDD02C4919592AULL,
		0xD1E1AF3A73FC42D6ULL,
		0xC82EEC18D5EFFB69ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 50\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 50 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x16E7C908AA142233ULL,
		0x0D2983ACED47D8B4ULL,
		0xB79747580AF2B23DULL,
		0xE1BD55DE9A2F0CCDULL,
		0xE8C3D1DEE38F7556ULL,
		0x13825033452A4B2EULL,
		0xDC10430EBFF6280BULL,
		0x0B6BD79B155CC51DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x505061265CFE8679ULL,
		0x5BBA36551ED437FAULL,
		0xE7624B57426F9C6DULL,
		0xD66239284CABCF27ULL,
		0xDDC3207557B21962ULL,
		0xF035CF8ECAA5913BULL,
		0x7B85DFE3F263D456ULL,
		0xD422B2051DBD5B36ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC69767E24D159BBAULL,
		0xB16F4D57CE73A0B9ULL,
		0xD034FC00C88315CFULL,
		0x0B5B1CB64D833DA5ULL,
		0x0B00B1698BDD5BF4ULL,
		0x234C80A47A84B9F3ULL,
		0x608A632ACD9253B4ULL,
		0x37492595F79F69E7ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 51\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 51 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -51;
	} else {
		printf("Test Case 51 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1C92D4A49CB4A341ULL,
		0x12598133FA486F01ULL,
		0x1880D3B8438726C2ULL,
		0xFAA2EB0A9088882AULL,
		0xF16D1E5A0D9FE517ULL,
		0x7ACD94012984414EULL,
		0x3E30476156FC0D1CULL,
		0x088B391406C409F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E880DC48340E433ULL,
		0x2EEB3F457C3CD8B3ULL,
		0xE691F95A0DBDE9F8ULL,
		0x7F85AB500412B6F3ULL,
		0xE76A327EC47837BDULL,
		0x689F5A7BE178159DULL,
		0x689A235F0D2B3EA1ULL,
		0xE9DA9DCAF69A693DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCE0AC6E01973BF0EULL,
		0xE36E41EE7E0B964DULL,
		0x31EEDA5E35C93CC9ULL,
		0x7B1D3FBA8C75D136ULL,
		0x0A02EBDB4927AD5AULL,
		0x122E3985480C2BB1ULL,
		0xD596240249D0CE7BULL,
		0x1EB09B491029A0B4ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 52\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 52 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -52;
	} else {
		printf("Test Case 52 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0C478F644153C0D0ULL,
		0xE6B9FB81517D4E98ULL,
		0xFB8D1EC13650FEEFULL,
		0xE3E683B05CD53792ULL,
		0x7F748EA683C61C4AULL,
		0x3EF9644DC6A149C5ULL,
		0xB1070B7527E4529BULL,
		0xED663D63D1208C3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA11FFCC10FAFAEFULL,
		0x99F6C435375393F1ULL,
		0x624A78442AD773ACULL,
		0x0E4AE3CF8F6D5B07ULL,
		0x75F2537BBEA983B7ULL,
		0xD8C5B5840A028E1BULL,
		0x1B2DA58309655D33ULL,
		0x2051ED12E76AAA7BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x22358F983058C5E1ULL,
		0x4CC3374C1A29BAA6ULL,
		0x9942A67D0B798B43ULL,
		0xD59B9FE0CD67DC8BULL,
		0x09823B2AC51C9893ULL,
		0x6633AEC9BC9EBBAAULL,
		0x95D965F21E7EF567ULL,
		0xCD145050E9B5E1C3ULL
	}};
	sign = 0;
	printf("Test Case 53\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 53 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -53;
	} else {
		printf("Test Case 53 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDFCB45A29136FD48ULL,
		0x44050297C6789205ULL,
		0xA810387E0ABB1BCFULL,
		0xE9E5EEB8159CAF0FULL,
		0x72CE35A00EEE3AE6ULL,
		0x25BE04E801ACC4CFULL,
		0x7C02EA3079813ABCULL,
		0xC7164471B1D00228ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9349F2520BBEAB5ULL,
		0xC519C77896F434A7ULL,
		0x241511C341090EBFULL,
		0x566BD6F2B52F7644ULL,
		0xF47E1175BBFF9660ULL,
		0x2B3CC8012E483B38ULL,
		0xC8AB109B14EDFB74ULL,
		0xA79A9348D7D8CE0FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2696A67D707B1293ULL,
		0x7EEB3B1F2F845D5EULL,
		0x83FB26BAC9B20D0FULL,
		0x937A17C5606D38CBULL,
		0x7E50242A52EEA486ULL,
		0xFA813CE6D3648996ULL,
		0xB357D99564933F47ULL,
		0x1F7BB128D9F73418ULL
	}};
	sign = 0;
	printf("Test Case 54\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 54 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -54;
	} else {
		printf("Test Case 54 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x63480571B331357FULL,
		0x419D7CF8A26CCA62ULL,
		0x524DF0BFE60E67FFULL,
		0x498C7103F3495016ULL,
		0xD5B69DC349BE967CULL,
		0xC86961E6977F8C7CULL,
		0x35B3DEC635C09200ULL,
		0xE0BB8005159E1AB5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x721A74CAB6B5D428ULL,
		0xEF4AE9CFC99E1111ULL,
		0x0AD5AE459A24A8C6ULL,
		0x059E5BE67E637753ULL,
		0x4F6D1FDDB29DA627ULL,
		0x73D9CEEB04DBE7A2ULL,
		0xD454EE9FD336F870ULL,
		0xE44AC4FCB0591914ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF12D90A6FC7B6157ULL,
		0x52529328D8CEB950ULL,
		0x4778427A4BE9BF38ULL,
		0x43EE151D74E5D8C3ULL,
		0x86497DE59720F055ULL,
		0x548F92FB92A3A4DAULL,
		0x615EF02662899990ULL,
		0xFC70BB08654501A0ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 55\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 55 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -55;
	} else {
		printf("Test Case 55 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4AE9533A1D9EC099ULL,
		0xDC677E2B24CE523CULL,
		0x356A06452DA2EC57ULL,
		0x7B5F96195766E09EULL,
		0xC7CBAF852543FBCEULL,
		0x1C461B8347AC55ADULL,
		0x5B32C56E32038601ULL,
		0xDA73D445696F7A9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9519E88A1AAAFE6ULL,
		0x24573EAA6F01E4EEULL,
		0x73AEE8C5AE3D60F5ULL,
		0x27A97A0080CB4A83ULL,
		0xF7B59B9FFCD3A27DULL,
		0x6B6531D60D2D3ADEULL,
		0x3F1BA1546AD60840ULL,
		0x7BF82A0DDDC258BBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9197B4B17BF410B3ULL,
		0xB8103F80B5CC6D4DULL,
		0xC1BB1D7F7F658B62ULL,
		0x53B61C18D69B961AULL,
		0xD01613E528705951ULL,
		0xB0E0E9AD3A7F1ACEULL,
		0x1C172419C72D7DC0ULL,
		0x5E7BAA378BAD21DFULL
	}};
	sign = 0;
	printf("Test Case 56\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 56 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -56;
	} else {
		printf("Test Case 56 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x471B58770FAF7EECULL,
		0x9CEB8DFDC8DD8185ULL,
		0xB37BB77D7000832CULL,
		0xC461C6F377ADCE82ULL,
		0x2E57C4F03B0CBCF4ULL,
		0x228C42DB50250312ULL,
		0x1B21D4182187E595ULL,
		0x1214348A89939D05ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AAC8554B8FA985DULL,
		0x1563B6735D8F4165ULL,
		0xCECC7CF34B4ED33FULL,
		0x8337DC25AB6AAE27ULL,
		0x417BE28FB0D31F05ULL,
		0x18AD22D21008D5E4ULL,
		0x11BAC354BA1D6EE5ULL,
		0x8AA61B06CD1F5740ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEC6ED32256B4E68FULL,
		0x8787D78A6B4E401FULL,
		0xE4AF3A8A24B1AFEDULL,
		0x4129EACDCC43205AULL,
		0xECDBE2608A399DEFULL,
		0x09DF2009401C2D2DULL,
		0x096710C3676A76B0ULL,
		0x876E1983BC7445C5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 57\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 57 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -57;
	} else {
		printf("Test Case 57 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD2C049582E473EA8ULL,
		0xED2A323486EFEE7FULL,
		0xBC7F2EA66E41B26FULL,
		0xA6A406CB4E1C3CDEULL,
		0x8972643098417CA6ULL,
		0x1C70613FAD2D67A7ULL,
		0xFA8D6CFF3F5E922BULL,
		0x3741992F56C32EC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28DC369D7C7A5242ULL,
		0x4450C794E80CC5D0ULL,
		0x08C50FAB872F13A0ULL,
		0xEB2076B4474D9429ULL,
		0x32766957FD8B0B31ULL,
		0x9CA89843FBD1AABFULL,
		0xB6130405718A29C4ULL,
		0xFEBA86D8CEB863C5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA9E412BAB1CCEC66ULL,
		0xA8D96A9F9EE328AFULL,
		0xB3BA1EFAE7129ECFULL,
		0xBB83901706CEA8B5ULL,
		0x56FBFAD89AB67174ULL,
		0x7FC7C8FBB15BBCE8ULL,
		0x447A68F9CDD46866ULL,
		0x38871256880ACB00ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 58\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 58 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -58;
	} else {
		printf("Test Case 58 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFDF4BDD53C79823BULL,
		0xF9AAF923B958EFDFULL,
		0x482DD2B4012EB659ULL,
		0x5820A51B31FE00B5ULL,
		0x8A214C14283D54CCULL,
		0xA7C177A8B254D782ULL,
		0xAB44F0A281B31AF8ULL,
		0xBD21A4720A63A69DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7FD7835D739E3E8ULL,
		0x500E3EB7C2058085ULL,
		0xB19175C287E9C71FULL,
		0xA1F49040784D663BULL,
		0x171268B8DCE4E06DULL,
		0xA2E31FF716FDB819ULL,
		0xFCBFFDBD4D4212EFULL,
		0x24BDBD203CB9793AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x15F7459F653F9E53ULL,
		0xA99CBA6BF7536F5AULL,
		0x969C5CF17944EF3AULL,
		0xB62C14DAB9B09A79ULL,
		0x730EE35B4B58745EULL,
		0x04DE57B19B571F69ULL,
		0xAE84F2E534710809ULL,
		0x9863E751CDAA2D62ULL
	}};
	sign = 0;
	printf("Test Case 59\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 59 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -59;
	} else {
		printf("Test Case 59 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C499367EE330389ULL,
		0xED5E06B0E7A60517ULL,
		0x87C555F142D9CABAULL,
		0x9E4EB04198CECCD9ULL,
		0x0B62482510F73492ULL,
		0x4C5E47726D550415ULL,
		0xE4C5E1292B89DC24ULL,
		0x66A6A379C15E3D83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F3F8A497C3EE117ULL,
		0xD9A3BB69C4FDAA53ULL,
		0x49ACF83DDD2697AFULL,
		0x02505BD7398F33B1ULL,
		0x0646C8786CB30574ULL,
		0xEB5C8E147AC19E61ULL,
		0xABAF0AAC83AFA734ULL,
		0xF2F35BE4FB8BA1C9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFD0A091E71F42272ULL,
		0x13BA4B4722A85AC3ULL,
		0x3E185DB365B3330BULL,
		0x9BFE546A5F3F9928ULL,
		0x051B7FACA4442F1EULL,
		0x6101B95DF29365B4ULL,
		0x3916D67CA7DA34EFULL,
		0x73B34794C5D29BBAULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 60\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 60 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -60;
	} else {
		printf("Test Case 60 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x71FBA4DDF1D1A3F9ULL,
		0xC248FDCC09867AACULL,
		0x903AA359391BB59FULL,
		0x27E409F9FFC20C8BULL,
		0x6D813B6D0CFB6EF1ULL,
		0xA02DE19D94F2D46AULL,
		0x10BDA186C2355C6BULL,
		0x19ABA471A4ABB7DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DB6C45D34F36D06ULL,
		0x9D99BE9E7B46AB2EULL,
		0x58FC6C304A49220BULL,
		0x464BBBF78E38189BULL,
		0x9E36E8CDB4D3DD6EULL,
		0x659E1ACE5ED8532EULL,
		0xD28502B04D6910B3ULL,
		0x7737B98570C63C3BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0444E080BCDE36F3ULL,
		0x24AF3F2D8E3FCF7EULL,
		0x373E3728EED29394ULL,
		0xE1984E027189F3F0ULL,
		0xCF4A529F58279182ULL,
		0x3A8FC6CF361A813BULL,
		0x3E389ED674CC4BB8ULL,
		0xA273EAEC33E57B9FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 61\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 61 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -61;
	} else {
		printf("Test Case 61 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x617EEE5368A471BDULL,
		0xF22D43B87F55CF1BULL,
		0xB8EA763AC536230EULL,
		0xCF4C442A8AFEC0BDULL,
		0x65A963A58FC56BCBULL,
		0xE015F9C8687766CFULL,
		0x70A6AAF124EA59A0ULL,
		0x22354F5A03AD4583ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE710330F59F38B6FULL,
		0x2065EFBC2D6854D1ULL,
		0x70B9954A91C55F81ULL,
		0x456B904655404A10ULL,
		0x11A61A4D95857E16ULL,
		0x2FB6DB386EEAB258ULL,
		0x7B6738BB93AFF80BULL,
		0xBEF238362895ED27ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7A6EBB440EB0E64EULL,
		0xD1C753FC51ED7A49ULL,
		0x4830E0F03370C38DULL,
		0x89E0B3E435BE76ADULL,
		0x54034957FA3FEDB5ULL,
		0xB05F1E8FF98CB477ULL,
		0xF53F7235913A6195ULL,
		0x63431723DB17585BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 62\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 62 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -62;
	} else {
		printf("Test Case 62 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA3E28D010ACB3F0CULL,
		0xBFB740940DCF380EULL,
		0x29480815DB447064ULL,
		0xB27FA88B7BF58250ULL,
		0xE65186CE92A595C6ULL,
		0x181D774C1DC9D842ULL,
		0xED58AE180692B4C6ULL,
		0xEED702CE8D1968F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D1D8121AEBABBC2ULL,
		0x726DDE34C893657EULL,
		0xB1895C5716A428A8ULL,
		0x16D349C29BAD0022ULL,
		0x4C5093F098DCC118ULL,
		0xE8E9560F5BF821BDULL,
		0x13B40FB4F1485229ULL,
		0x1E5EB289ABC116D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x56C50BDF5C10834AULL,
		0x4D49625F453BD290ULL,
		0x77BEABBEC4A047BCULL,
		0x9BAC5EC8E048822DULL,
		0x9A00F2DDF9C8D4AEULL,
		0x2F34213CC1D1B685ULL,
		0xD9A49E63154A629CULL,
		0xD0785044E158521FULL
	}};
	sign = 0;
	printf("Test Case 63\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 63 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -63;
	} else {
		printf("Test Case 63 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x133B50356ADA4FE7ULL,
		0x0A3EB428C6C033E5ULL,
		0x72BC5493A484C697ULL,
		0x351E64B38853473BULL,
		0x1B0D6C524BEC377BULL,
		0xF34D158160A63865ULL,
		0xF3B6930C396F6B05ULL,
		0x38F2B20DD112506AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8210A8811F4E7AE0ULL,
		0xDD74CE44953DC13CULL,
		0x2221479FBFE4D2EEULL,
		0x95A0E35F51123865ULL,
		0x0033F9B615E4A5E6ULL,
		0x626DEA9644DFDF4DULL,
		0x56EC0D1B1250AFC8ULL,
		0xBD2591F8B0DC0601ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x912AA7B44B8BD507ULL,
		0x2CC9E5E4318272A8ULL,
		0x509B0CF3E49FF3A8ULL,
		0x9F7D815437410ED6ULL,
		0x1AD9729C36079194ULL,
		0x90DF2AEB1BC65918ULL,
		0x9CCA85F1271EBB3DULL,
		0x7BCD201520364A69ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 64\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 64 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -64;
	} else {
		printf("Test Case 64 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1E9685C1926E97D1ULL,
		0x15BAE2D6F76D6144ULL,
		0xEA42CE84BE5B781CULL,
		0xC7270AF948451104ULL,
		0x6AFA2C403D702DD4ULL,
		0x85F0AC88433E96CBULL,
		0x8FB7304BF4C5A9FAULL,
		0x25C6863E75519324ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8560EC138A8C534ULL,
		0xF50AA7DF383A0277ULL,
		0x3A22E1FF46AFD867ULL,
		0x8E51816FF5312B74ULL,
		0x16746B9573C44934ULL,
		0x864744E9271EAE57ULL,
		0xA888E627CD8306F0ULL,
		0xEA6D5E40B84F16CEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6640770059C5D29DULL,
		0x20B03AF7BF335ECCULL,
		0xB01FEC8577AB9FB4ULL,
		0x38D589895313E590ULL,
		0x5485C0AAC9ABE4A0ULL,
		0xFFA9679F1C1FE874ULL,
		0xE72E4A242742A309ULL,
		0x3B5927FDBD027C55ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 65\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 65 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -65;
	} else {
		printf("Test Case 65 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x08C68F295CF99542ULL,
		0xEAB2ED100F3A7B6FULL,
		0x37DBE0BC3C016088ULL,
		0x7BC129D5D0CD0E88ULL,
		0x5300F941BDE4FB8CULL,
		0xF05AD59458EA7589ULL,
		0xC961540AE3F68747ULL,
		0x5395669838F2D554ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE33ECD187B62596AULL,
		0xDD71BDF47E0853F5ULL,
		0xE894779304CF10BBULL,
		0x2242BDE933F6C8EAULL,
		0x7F859100E72C252FULL,
		0xBDAC92FED6416D88ULL,
		0xB4C1BACC957DCADEULL,
		0x65A1D6A9C9A1D9FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2587C210E1973BD8ULL,
		0x0D412F1B91322779ULL,
		0x4F47692937324FCDULL,
		0x597E6BEC9CD6459DULL,
		0xD37B6840D6B8D65DULL,
		0x32AE429582A90800ULL,
		0x149F993E4E78BC69ULL,
		0xEDF38FEE6F50FB56ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 66\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 66 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -66;
	} else {
		printf("Test Case 66 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC1AC7DFC3601DF2EULL,
		0x3B06D2F2DF14C94AULL,
		0x0244B73F4791798BULL,
		0x94868668996A9E2DULL,
		0x1D9CF3FE64448B0EULL,
		0xB08C8938C94A945FULL,
		0x7930D20C14B16778ULL,
		0x5547FE89462776BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46CDDE604611B7DEULL,
		0x994401156AC4669DULL,
		0x9C1751C5D2A9862DULL,
		0xD2CEED14A915047AULL,
		0xF99232AA528ED0F7ULL,
		0xF02B5C1C2CE089BFULL,
		0xF94552640F412BFCULL,
		0xCD80976FF26098EFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7ADE9F9BEFF02750ULL,
		0xA1C2D1DD745062ADULL,
		0x662D657974E7F35DULL,
		0xC1B79953F05599B2ULL,
		0x240AC15411B5BA16ULL,
		0xC0612D1C9C6A0A9FULL,
		0x7FEB7FA805703B7BULL,
		0x87C7671953C6DDCDULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 67\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 67 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -67;
	} else {
		printf("Test Case 67 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB2084E2C22C1E31BULL,
		0x77F846317B9DFA23ULL,
		0xEE7C0F2FB2FCA4BAULL,
		0x9CBC0886B57A25E3ULL,
		0xFF082EA13FC1817CULL,
		0x9E4890C149CB6FD7ULL,
		0xE963CDF977C17B51ULL,
		0x36D5033BD333A5E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB520A6A983425C00ULL,
		0x942626DE9231BA2EULL,
		0xB2D9C3F3510D84FAULL,
		0xC33B3E5FE27A2077ULL,
		0x260F862D234C3E8AULL,
		0x5913E886E0F2350AULL,
		0x3AEA34CFF934A0DAULL,
		0xBAAA6503BF780CDCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFCE7A7829F7F871BULL,
		0xE3D21F52E96C3FF4ULL,
		0x3BA24B3C61EF1FBFULL,
		0xD980CA26D300056CULL,
		0xD8F8A8741C7542F1ULL,
		0x4534A83A68D93ACDULL,
		0xAE7999297E8CDA77ULL,
		0x7C2A9E3813BB990BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 68\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 68 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -68;
	} else {
		printf("Test Case 68 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA0B450A1A7FA3E5DULL,
		0xCFA86B850EEC8DC5ULL,
		0x4445DAA874F088EAULL,
		0xDE3551C4A3142D75ULL,
		0x051E11EB55975970ULL,
		0xDBB0460713E0D7B0ULL,
		0x5361526643E379E0ULL,
		0x1CD5E57D0D95791DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3444EE464E1EC560ULL,
		0x13D370C2E94EDF4CULL,
		0xA238342CB2882F80ULL,
		0x83DF1EA71638E799ULL,
		0x7BA8C4DCC988E11AULL,
		0x6F162FEB6CF480ABULL,
		0x4D8F9C6B655EFD46ULL,
		0x01ADC7D8F43B87D4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6C6F625B59DB78FDULL,
		0xBBD4FAC2259DAE79ULL,
		0xA20DA67BC268596AULL,
		0x5A56331D8CDB45DBULL,
		0x89754D0E8C0E7856ULL,
		0x6C9A161BA6EC5704ULL,
		0x05D1B5FADE847C9AULL,
		0x1B281DA41959F149ULL
	}};
	sign = 0;
	printf("Test Case 69\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 69 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -69;
	} else {
		printf("Test Case 69 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAA2440CD0B3EC640ULL,
		0xCD5751D7E3C46F3AULL,
		0xD0865F164643F7A7ULL,
		0x8433C44A34A8C419ULL,
		0x10D7821EA6B9D6C4ULL,
		0x77983AC2461E6044ULL,
		0x8FF1943DA2031AC5ULL,
		0x07EF9D42C5F072CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32B43AE532BD73F9ULL,
		0x1FDC1AD2CE8D2662ULL,
		0xFDD039C421F6F74CULL,
		0xFF432C02121AE9F8ULL,
		0x1C34C0BF4DB43A66ULL,
		0xAEDAB2E297E65726ULL,
		0xE5B1ABC3B9009421ULL,
		0x5C49B50345FCE7AAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x777005E7D8815247ULL,
		0xAD7B3705153748D8ULL,
		0xD2B62552244D005BULL,
		0x84F09848228DDA20ULL,
		0xF4A2C15F59059C5DULL,
		0xC8BD87DFAE38091DULL,
		0xAA3FE879E90286A3ULL,
		0xABA5E83F7FF38B21ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 70\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 70 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -70;
	} else {
		printf("Test Case 70 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB2FA397F6B57B2DCULL,
		0xFFA5440A6867B39AULL,
		0x7036D11E05E4B84CULL,
		0x9BA6EE981E264E3FULL,
		0xACC22E1FEAC4984FULL,
		0x1889330C265CD962ULL,
		0xB57E977FD7BFFF7FULL,
		0x3914302D867AFF43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4DDF459A1E85B12ULL,
		0x0DC218DB6F40F93AULL,
		0xEDCC5C4DD1C367F0ULL,
		0xEE97298AFE7A119FULL,
		0xF69B5DD0418FEE34ULL,
		0xB8F88A30D40FCFA4ULL,
		0x6570368EEB872B24ULL,
		0xF3373869F570CA03ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E1C4525C96F57CAULL,
		0xF1E32B2EF926BA60ULL,
		0x826A74D03421505CULL,
		0xAD0FC50D1FAC3C9FULL,
		0xB626D04FA934AA1AULL,
		0x5F90A8DB524D09BDULL,
		0x500E60F0EC38D45AULL,
		0x45DCF7C3910A3540ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 71\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 71 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -71;
	} else {
		printf("Test Case 71 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5650E435007CDB45ULL,
		0xE670AF141522E90FULL,
		0x03A95A4E9A04AC53ULL,
		0xE690B0F6317C3DFFULL,
		0x9F9B62D286DB6C39ULL,
		0xF3980D12AFF5A5E3ULL,
		0xBF8F876ABA297888ULL,
		0xC2E56D301A88B588ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC19402B6AFBC167AULL,
		0x80E4EE5ABD6CBD8AULL,
		0x63A6584A08D8BA73ULL,
		0xCCAAE87B09D46045ULL,
		0xC26AA3D4FBECE5F1ULL,
		0xCC6413ED225B4354ULL,
		0x727E2FFDE37A884CULL,
		0xD6606B201EAFB807ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x94BCE17E50C0C4CBULL,
		0x658BC0B957B62B84ULL,
		0xA0030204912BF1E0ULL,
		0x19E5C87B27A7DDB9ULL,
		0xDD30BEFD8AEE8648ULL,
		0x2733F9258D9A628EULL,
		0x4D11576CD6AEF03CULL,
		0xEC85020FFBD8FD81ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 72\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 72 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -72;
	} else {
		printf("Test Case 72 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0CCA08F4E4B0478DULL,
		0xDE8BB85BDCB1E79AULL,
		0xA5340DCBA90EA2B0ULL,
		0xEF62A71E6C3A89DCULL,
		0xBD95821A367E335FULL,
		0x500C37C308396CF8ULL,
		0xF7408ABAFCBE530AULL,
		0xD9CE840B769C926FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x081D192B5E870992ULL,
		0x55A5A62B7A7D55E0ULL,
		0x8F7BF7D4F872DE76ULL,
		0x0AB8AF81C80C97C2ULL,
		0x8CBE792313B2EC5AULL,
		0x3646635278E1390BULL,
		0x98AE7C1D3F38B7B7ULL,
		0x48F408314F1D2CC1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04ACEFC986293DFBULL,
		0x88E61230623491BAULL,
		0x15B815F6B09BC43AULL,
		0xE4A9F79CA42DF21AULL,
		0x30D708F722CB4705ULL,
		0x19C5D4708F5833EDULL,
		0x5E920E9DBD859B53ULL,
		0x90DA7BDA277F65AEULL
	}};
	sign = 0;
	printf("Test Case 73\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 73 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -73;
	} else {
		printf("Test Case 73 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x880050D2C87BA556ULL,
		0xF03DA9D65A502FCAULL,
		0xB4401FD809D5F201ULL,
		0xD1A18588871C9109ULL,
		0x013688EF69B9A375ULL,
		0x91CEADC271C63A96ULL,
		0x52B0931DA36D415AULL,
		0x44D866327D9ACEAAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B92C1A52FF681ACULL,
		0xD21E75AAC669BC84ULL,
		0x7EDC31B05D45F6DDULL,
		0x09150342889A6CD2ULL,
		0xCE6081B6A9172152ULL,
		0xF748EA3E0BDF0FAEULL,
		0x18D1FFDAF81C66D5ULL,
		0xC09770C24E8C8760ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C6D8F2D988523AAULL,
		0x1E1F342B93E67346ULL,
		0x3563EE27AC8FFB24ULL,
		0xC88C8245FE822437ULL,
		0x32D60738C0A28223ULL,
		0x9A85C38465E72AE7ULL,
		0x39DE9342AB50DA84ULL,
		0x8440F5702F0E474AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 74\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 74 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -74;
	} else {
		printf("Test Case 74 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF56AD516E84CA649ULL,
		0xE6A0A4E43980E621ULL,
		0x505E54764DEB4EE5ULL,
		0x39A0632D0F1AA040ULL,
		0x2B92D4135B89A5D1ULL,
		0xED5A0B8DE675DA7AULL,
		0x5738672318F7CF52ULL,
		0x6D54B6C2E0395D63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E001FA53A3F39EEULL,
		0x92E1937EBC30C99BULL,
		0x9E63B25961D52692ULL,
		0x1E694BECD8C51548ULL,
		0x5AFD3DF57654D562ULL,
		0xD55813463771FCCDULL,
		0xB96A560591C17FC6ULL,
		0xA0EF41239D29E9EDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x976AB571AE0D6C5BULL,
		0x53BF11657D501C86ULL,
		0xB1FAA21CEC162853ULL,
		0x1B37174036558AF7ULL,
		0xD095961DE534D06FULL,
		0x1801F847AF03DDACULL,
		0x9DCE111D87364F8CULL,
		0xCC65759F430F7375ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 75\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 75 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -75;
	} else {
		printf("Test Case 75 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8A1462D9A357FFCEULL,
		0xB52D169CB8FB66C1ULL,
		0x953F1229C79A3AFDULL,
		0x8EBCDDD4C18B7C31ULL,
		0xA532203F7EFB1BBEULL,
		0x15C6881728434D57ULL,
		0x0DFBB7138745C2B4ULL,
		0x78F7A86618BFA534ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04A7CE08EDC5401EULL,
		0xE8A23F10116B22B1ULL,
		0x922F85294E3375CAULL,
		0x1CE4A5897A2C1CC1ULL,
		0x20E9D029612F4F52ULL,
		0x79CC46F1F710EFE1ULL,
		0x4D872F0744A3C33FULL,
		0x2FDB8C16D2D2EC14ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x856C94D0B592BFB0ULL,
		0xCC8AD78CA7904410ULL,
		0x030F8D007966C532ULL,
		0x71D8384B475F5F70ULL,
		0x844850161DCBCC6CULL,
		0x9BFA412531325D76ULL,
		0xC074880C42A1FF74ULL,
		0x491C1C4F45ECB91FULL
	}};
	sign = 0;
	printf("Test Case 76\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 76 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -76;
	} else {
		printf("Test Case 76 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0F25139018949D12ULL,
		0x9610F8FDB2EC5A5DULL,
		0x0763DC64E3582532ULL,
		0xA0B63BC20946A6A7ULL,
		0x68721715DC30645AULL,
		0x22EF4F601E496CE8ULL,
		0x05CF363A2BF6A3CBULL,
		0x0FB4C77471B7BB17ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x029300BF68243E75ULL,
		0x61D2EE1DA5223987ULL,
		0x889D540A30B023B1ULL,
		0x0426ABAA905BA34BULL,
		0x0DA771618C67CAD6ULL,
		0xC11BFFFA7B3B16CDULL,
		0xB58F6A0F3F6F7447ULL,
		0x6BA2D32780A0BB8AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C9212D0B0705E9DULL,
		0x343E0AE00DCA20D6ULL,
		0x7EC6885AB2A80181ULL,
		0x9C8F901778EB035BULL,
		0x5ACAA5B44FC89984ULL,
		0x61D34F65A30E561BULL,
		0x503FCC2AEC872F83ULL,
		0xA411F44CF116FF8CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 77\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 77 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -77;
	} else {
		printf("Test Case 77 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2D3303F98032513FULL,
		0x908FF896E869D34BULL,
		0x619D0F99EB79181BULL,
		0xC362F24DACBDBEBBULL,
		0x38BEBD7CDDEDB80DULL,
		0x9667217D77C0F275ULL,
		0x20D71D7C70F618DBULL,
		0x062FB1803CACEE77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13592FC6899CF113ULL,
		0xAE9B0747C0F6C8F8ULL,
		0x82DA21F002963054ULL,
		0xB73014A4F331CF67ULL,
		0x35A0EE6B22F3FDCCULL,
		0x18E94027F1699559ULL,
		0xC9873B8497C0C136ULL,
		0x1262F7CE7891E67EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x19D9D432F695602CULL,
		0xE1F4F14F27730A53ULL,
		0xDEC2EDA9E8E2E7C6ULL,
		0x0C32DDA8B98BEF53ULL,
		0x031DCF11BAF9BA41ULL,
		0x7D7DE15586575D1CULL,
		0x574FE1F7D93557A5ULL,
		0xF3CCB9B1C41B07F8ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 78\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 78 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -78;
	} else {
		printf("Test Case 78 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDF5B198BECEEC48CULL,
		0x6906FE60858F1D9DULL,
		0x621640D6EFF30F0EULL,
		0x23D469C4D7220757ULL,
		0x6EC6480B8228C4D9ULL,
		0x3B08DB1B80304339ULL,
		0xEFBC0BFBDA9F6313ULL,
		0x46ABFAEA13201BB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7AAC8E7E699E5794ULL,
		0xCAEBE32952A10E12ULL,
		0x9A562CF837F95064ULL,
		0xF2DDC02C6417E80FULL,
		0xC1748DCDBEA85737ULL,
		0xD8FEE29F210CC060ULL,
		0x54D4F854B13E570DULL,
		0x384C10C4EFA97276ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x64AE8B0D83506CF8ULL,
		0x9E1B1B3732EE0F8BULL,
		0xC7C013DEB7F9BEA9ULL,
		0x30F6A998730A1F47ULL,
		0xAD51BA3DC3806DA1ULL,
		0x6209F87C5F2382D8ULL,
		0x9AE713A729610C05ULL,
		0x0E5FEA252376A93CULL
	}};
	sign = 0;
	printf("Test Case 79\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 79 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -79;
	} else {
		printf("Test Case 79 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x87FA0AE48B32A4EDULL,
		0x236DCAC09B03DEB8ULL,
		0xF288067D42FCAE9BULL,
		0x6946DCC7CA76354CULL,
		0x25C99AC1D9852E53ULL,
		0x4F6CBB34611B1B68ULL,
		0x930EED609104FD94ULL,
		0xA25DCA3430761D38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF73447B407773E6ULL,
		0x4E13515214958472ULL,
		0x724032925662ED96ULL,
		0x4CF414702DC86D79ULL,
		0x5C1F4AA4CE358388ULL,
		0xB4C34A75BAE902DEULL,
		0x8DAD022938E8CEA2ULL,
		0x160AD42F0DF84D39ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB886C6694ABB3107ULL,
		0xD55A796E866E5A45ULL,
		0x8047D3EAEC99C104ULL,
		0x1C52C8579CADC7D3ULL,
		0xC9AA501D0B4FAACBULL,
		0x9AA970BEA6321889ULL,
		0x0561EB37581C2EF1ULL,
		0x8C52F605227DCFFFULL
	}};
	sign = 0;
	printf("Test Case 80\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 80 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -80;
	} else {
		printf("Test Case 80 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEAE4D7C9625CB470ULL,
		0x98E4F8347A2EB47BULL,
		0x725B5D0297AA9EB6ULL,
		0x28DFC3A7BC3C83EDULL,
		0xFD5C89D5BD7EFF7EULL,
		0x9CBA92C853C6EC85ULL,
		0x6FFAF8D5DFFFD55CULL,
		0x7918270D2AFD412AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C790F3514212DF6ULL,
		0x3C2269F14180B43DULL,
		0x3271254AE675CADCULL,
		0xDFF17EED7F13EC1CULL,
		0x12D815E236EC5A52ULL,
		0x68861DFBD50685E0ULL,
		0x7619EA6B5C301F07ULL,
		0x1B842133092F238CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCE6BC8944E3B867AULL,
		0x5CC28E4338AE003EULL,
		0x3FEA37B7B134D3DAULL,
		0x48EE44BA3D2897D1ULL,
		0xEA8473F38692A52BULL,
		0x343474CC7EC066A5ULL,
		0xF9E10E6A83CFB655ULL,
		0x5D9405DA21CE1D9DULL
	}};
	sign = 0;
	printf("Test Case 81\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 81 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -81;
	} else {
		printf("Test Case 81 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAC42D0D60DAC3A69ULL,
		0x2C1F83EC55233A74ULL,
		0xB832B9EDDE829717ULL,
		0xBD66A2BD4B27DF42ULL,
		0xE72A637466918A9EULL,
		0xD8D45376E7EE2994ULL,
		0x0B4752373F7E8FD0ULL,
		0xCFFADC8755DB4EE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DD65BAF5DD2BE6CULL,
		0x3837C23FC70157ABULL,
		0x04C920B3D4FD0DF9ULL,
		0xF661774160E4BDBCULL,
		0x73179C249D2539A5ULL,
		0x91F5EEBBDCB86674ULL,
		0xEC14F644EBA7DFCDULL,
		0x493D18CF6F7208F8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7E6C7526AFD97BFDULL,
		0xF3E7C1AC8E21E2C9ULL,
		0xB369993A0985891DULL,
		0xC7052B7BEA432186ULL,
		0x7412C74FC96C50F8ULL,
		0x46DE64BB0B35C320ULL,
		0x1F325BF253D6B003ULL,
		0x86BDC3B7E66945EFULL
	}};
	sign = 0;
	printf("Test Case 82\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 82 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -82;
	} else {
		printf("Test Case 82 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC0B401A7148DADCFULL,
		0xC41790DE37175903ULL,
		0xE705F21AB04A2C5DULL,
		0xA79D38ABF79BBD8AULL,
		0x9827013B7D065155ULL,
		0x7E86C5150F58B3BEULL,
		0xE0E8E8EE43F66862ULL,
		0x1CA4BAA4DE937084ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61CA8F03899220B4ULL,
		0x93C845C62221EC40ULL,
		0xBE83D21C94791668ULL,
		0x00FD14B9D08A78E0ULL,
		0x0EFE00D3E900FFA3ULL,
		0x27DA6C89D10456D8ULL,
		0x4040F9A2512F16A1ULL,
		0x5D5542528094DFB6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5EE972A38AFB8D1BULL,
		0x304F4B1814F56CC3ULL,
		0x28821FFE1BD115F5ULL,
		0xA6A023F2271144AAULL,
		0x89290067940551B2ULL,
		0x56AC588B3E545CE6ULL,
		0xA0A7EF4BF2C751C1ULL,
		0xBF4F78525DFE90CEULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 83\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 83 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -83;
	} else {
		printf("Test Case 83 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF5BFFE7F4DBC4A4BULL,
		0x5596405092D06ED1ULL,
		0xD1F77CCBAD72F94EULL,
		0x9D70BA7E76325B67ULL,
		0x60D7477EE9B4778CULL,
		0xA33F7B3799A9EDC3ULL,
		0x9C6054F93BA1F2F8ULL,
		0xE8B64F7758EC57B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD7E3BAAC5255E32ULL,
		0xC2E1DF81D07A3A12ULL,
		0x3215F880C5909B3CULL,
		0x633806179258D62EULL,
		0xF66DF8C4BC157FD7ULL,
		0xC6DAD795D1567045ULL,
		0x98BDF514011A4754ULL,
		0x6DDB95ACD09418B7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1841C2D48896EC19ULL,
		0x92B460CEC25634BFULL,
		0x9FE1844AE7E25E11ULL,
		0x3A38B466E3D98539ULL,
		0x6A694EBA2D9EF7B5ULL,
		0xDC64A3A1C8537D7DULL,
		0x03A25FE53A87ABA3ULL,
		0x7ADAB9CA88583EFAULL
	}};
	sign = 0;
	printf("Test Case 84\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 84 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -84;
	} else {
		printf("Test Case 84 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD22B9554AE114982ULL,
		0x08E6E6ECFD376BC5ULL,
		0x51FD7A3245CD13BDULL,
		0xD335B8E3A874EE5CULL,
		0xB839591B67B53917ULL,
		0x390FAAB49A4ADFF2ULL,
		0x28486CB93FD9FBE7ULL,
		0x7B30135D0DBA746EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E14238057120201ULL,
		0x7FB61B5DEA645905ULL,
		0xE5FE5027EE46B6A4ULL,
		0xF9EEACF92B6AD4E9ULL,
		0xDB276D323CD7EDBAULL,
		0x424103F4CA40CAF0ULL,
		0x41A28CDF2DDB9A95ULL,
		0x1A9DAD3899B93144ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x441771D456FF4781ULL,
		0x8930CB8F12D312C0ULL,
		0x6BFF2A0A57865D18ULL,
		0xD9470BEA7D0A1972ULL,
		0xDD11EBE92ADD4B5CULL,
		0xF6CEA6BFD00A1501ULL,
		0xE6A5DFDA11FE6151ULL,
		0x6092662474014329ULL
	}};
	sign = 0;
	printf("Test Case 85\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 85 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -85;
	} else {
		printf("Test Case 85 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDCDAD4979FCD013DULL,
		0x0E3914FDC057FB5EULL,
		0x9B995DD3CF7656DBULL,
		0x025603158F9BE13BULL,
		0x781C8494BD417D7AULL,
		0x36845E72FD929096ULL,
		0x4BA7E1971BB3E3A8ULL,
		0x3A494EB85E5DA0A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D6EB7EF518A9234ULL,
		0x1815C601CDCE9AEAULL,
		0xB57C835793DF8675ULL,
		0xD1A6053C9A8F039DULL,
		0x9B0BA58E1A8C72C2ULL,
		0x26EDD50CFC702083ULL,
		0x3B8A385BDA49286BULL,
		0xD15A88B9FF44BFD4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCF6C1CA84E426F09ULL,
		0xF6234EFBF2896074ULL,
		0xE61CDA7C3B96D065ULL,
		0x30AFFDD8F50CDD9DULL,
		0xDD10DF06A2B50AB7ULL,
		0x0F96896601227012ULL,
		0x101DA93B416ABB3DULL,
		0x68EEC5FE5F18E0D3ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 86\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 86 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -86;
	} else {
		printf("Test Case 86 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x53D86A7C0FE45DB1ULL,
		0xFA2F6029BF78A6E2ULL,
		0xC6DE731034CE7800ULL,
		0x3606C48FFCD9D83EULL,
		0xA2D0BAAF56B21894ULL,
		0x8426A42D098E717EULL,
		0xCC565FC0EFFBE65EULL,
		0x3A366A4D9A4A28F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70261B077DFC1B42ULL,
		0xF1A5EF99E1D2A6F0ULL,
		0x4C879B68F1797DA1ULL,
		0x7706D6C003F0C8F7ULL,
		0xF696AC3C1D038C7AULL,
		0x5172CA0071AC344FULL,
		0x4C1F4A7FAAA111D2ULL,
		0x16701A25944531DAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE3B24F7491E8426FULL,
		0x0889708FDDA5FFF1ULL,
		0x7A56D7A74354FA5FULL,
		0xBEFFEDCFF8E90F47ULL,
		0xAC3A0E7339AE8C19ULL,
		0x32B3DA2C97E23D2EULL,
		0x80371541455AD48CULL,
		0x23C650280604F719ULL
	}};
	sign = 0;
	printf("Test Case 87\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 87 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -87;
	} else {
		printf("Test Case 87 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x11B2ADFA16A8EC11ULL,
		0x1EDE6F4C63F49D7BULL,
		0x45B1AFA8EE348556ULL,
		0xD018A0369240ACDCULL,
		0x3D8AE89B148FEAE0ULL,
		0x6F34542E03940694ULL,
		0x48A56E158F29607BULL,
		0xD07D40E41BCA0BC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2EC3D91F48BC34FULL,
		0x460C061644873D9DULL,
		0x9BA939260F45A266ULL,
		0x5A316687B9AF1EBFULL,
		0x674C06E6DCD0EAFDULL,
		0x798BB90777517470ULL,
		0x7E4DDB47AA05B50AULL,
		0x70E666819C4B14A5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5EC67068221D28C2ULL,
		0xD8D269361F6D5FDDULL,
		0xAA087682DEEEE2EFULL,
		0x75E739AED8918E1CULL,
		0xD63EE1B437BEFFE3ULL,
		0xF5A89B268C429223ULL,
		0xCA5792CDE523AB70ULL,
		0x5F96DA627F7EF723ULL
	}};
	sign = 0;
	printf("Test Case 88\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 88 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -88;
	} else {
		printf("Test Case 88 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x956513D18B5ED151ULL,
		0xB0A85C39A2276D89ULL,
		0xFCCD918DAE24F69EULL,
		0x8772B4D7FB763D1EULL,
		0x6795296C2E0629B2ULL,
		0x199AC314822CBEF8ULL,
		0x0F2DFA495CD81F45ULL,
		0x7830FD843B5EC48DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0DECDC5B0D98DBBULL,
		0x76166A4670B96296ULL,
		0xEA3354BE395A06D7ULL,
		0x4B44586BCAD75DA4ULL,
		0x2213C5201A52CCC0ULL,
		0xF02A5FCD21A41822ULL,
		0xCE6C2F19AC78F516ULL,
		0xBE31F5CA17840D3BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB486460BDA854396ULL,
		0x3A91F1F3316E0AF2ULL,
		0x129A3CCF74CAEFC7ULL,
		0x3C2E5C6C309EDF7AULL,
		0x4581644C13B35CF2ULL,
		0x297063476088A6D6ULL,
		0x40C1CB2FB05F2A2EULL,
		0xB9FF07BA23DAB751ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 89\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 89 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -89;
	} else {
		printf("Test Case 89 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x751CD4C3B746EBB4ULL,
		0xD0475A6C0E57BB8EULL,
		0xB27A862E3A681048ULL,
		0xFFCA4BF8974A7960ULL,
		0xD2024D0AF2CC2D78ULL,
		0x24BC224B4B571A33ULL,
		0x802C2B003FBEE84AULL,
		0xD5786CCC4C963CD9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x026AD3BBEBAA65D7ULL,
		0xCBC8D4B1399B8393ULL,
		0xCDDD9EE46F3F8EF7ULL,
		0xE54666D886B518E1ULL,
		0x6026F4B85F338127ULL,
		0x8651253F27F8CE6FULL,
		0xC8AE2A9CCEE365C4ULL,
		0x9C5C910040CDA731ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x72B20107CB9C85DDULL,
		0x047E85BAD4BC37FBULL,
		0xE49CE749CB288151ULL,
		0x1A83E5201095607EULL,
		0x71DB58529398AC51ULL,
		0x9E6AFD0C235E4BC4ULL,
		0xB77E006370DB8285ULL,
		0x391BDBCC0BC895A7ULL
	}};
	sign = 0;
	printf("Test Case 90\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 90 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -90;
	} else {
		printf("Test Case 90 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6474AF7B7D5D41D2ULL,
		0xD7FDA51BFB5E2EC5ULL,
		0xCCE89B56579B7DA0ULL,
		0x1F5A1F2F189B268DULL,
		0xE8715D2D786FFB16ULL,
		0x23DE9CB420FA13D2ULL,
		0x827CE5594B8EFB88ULL,
		0x50E9D107378A2001ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC79E378EB1CFBA4BULL,
		0x52710A0E9C96393BULL,
		0xE3F446219B89AE45ULL,
		0xF006715EE458134FULL,
		0x16C535864F45084EULL,
		0xB151D707D05E9A7DULL,
		0x777248D908BFC63DULL,
		0x5674DC4CD0923C83ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9CD677ECCB8D8787ULL,
		0x858C9B0D5EC7F589ULL,
		0xE8F45534BC11CF5BULL,
		0x2F53ADD03443133DULL,
		0xD1AC27A7292AF2C7ULL,
		0x728CC5AC509B7955ULL,
		0x0B0A9C8042CF354AULL,
		0xFA74F4BA66F7E37EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 91\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 91 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -91;
	} else {
		printf("Test Case 91 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7BB1BA1FE91BE4D4ULL,
		0xC1D9EA5B59541237ULL,
		0x0A56BE4CA000A14FULL,
		0x99490999911DD97AULL,
		0x3824CA6073B6BFCEULL,
		0x58DC4A043432AC58ULL,
		0xEA8675170C51E079ULL,
		0x7E2C09C3FA8E4C41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B30715EFF41F851ULL,
		0x27CC93C6106C477FULL,
		0xFC32F4303B60E857ULL,
		0x8B5455C9BD43814AULL,
		0x6C114FCC9E4BE5B5ULL,
		0xDE03CA5D5C47313AULL,
		0x8A1CED036B789759ULL,
		0xC046022B40959334ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x208148C0E9D9EC83ULL,
		0x9A0D569548E7CAB8ULL,
		0x0E23CA1C649FB8F8ULL,
		0x0DF4B3CFD3DA582FULL,
		0xCC137A93D56ADA19ULL,
		0x7AD87FA6D7EB7B1DULL,
		0x60698813A0D9491FULL,
		0xBDE60798B9F8B90DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 92\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 92 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -92;
	} else {
		printf("Test Case 92 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x755707491C388A66ULL,
		0x9E93BC9613272677ULL,
		0x5351DD3FE400E56DULL,
		0x0B603E05E71E11E3ULL,
		0x4FB72E6936CA8FC8ULL,
		0x22EB3AEC898F0642ULL,
		0xCCC09788DA0359C1ULL,
		0xB8B9858781FD7FAAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4732EFD3B15C0789ULL,
		0x68C2AC15BC5BF190ULL,
		0x24861C16507E89CFULL,
		0x89753892FA4A8B2FULL,
		0xDB12CC002335CA14ULL,
		0xB100ACA17BCF273EULL,
		0x55ABC65AC657BD41ULL,
		0x2D9BB1BE960756FDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2E2417756ADC82DDULL,
		0x35D1108056CB34E7ULL,
		0x2ECBC12993825B9EULL,
		0x81EB0572ECD386B4ULL,
		0x74A462691394C5B3ULL,
		0x71EA8E4B0DBFDF03ULL,
		0x7714D12E13AB9C7FULL,
		0x8B1DD3C8EBF628ADULL
	}};
	sign = 0;
	printf("Test Case 93\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 93 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -93;
	} else {
		printf("Test Case 93 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6C17180FFDE11621ULL,
		0x994FE9DDF2431CE0ULL,
		0x34929E624C728E1CULL,
		0x069A94DEE56B53F2ULL,
		0xBE37EF200618C6FFULL,
		0x64D20CE5F6ABE652ULL,
		0x3788245EE06CFA3EULL,
		0x44B39621EB9C0670ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93A86EEBB05025E7ULL,
		0xA9FEC54D19DAA859ULL,
		0xE6194208D1812B1EULL,
		0xCA5E1378DC7EA30DULL,
		0xB9049B30EC0614BAULL,
		0xC00CF30738D81CD3ULL,
		0x8A2E14109A339723ULL,
		0xAAB9276D099FCF30ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD86EA9244D90F03AULL,
		0xEF512490D8687486ULL,
		0x4E795C597AF162FDULL,
		0x3C3C816608ECB0E4ULL,
		0x053353EF1A12B244ULL,
		0xA4C519DEBDD3C97FULL,
		0xAD5A104E4639631AULL,
		0x99FA6EB4E1FC373FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 94\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 94 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -94;
	} else {
		printf("Test Case 94 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC0005240240C7D29ULL,
		0x62297782B9519B8EULL,
		0x7B8A76980E9CE5D8ULL,
		0xCD41F4309AB5F5EDULL,
		0x61D40CF1DF8D4C02ULL,
		0x559FEFB698277078ULL,
		0xB2CC1118996F1D04ULL,
		0x3E66C365D6DD8AD8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5940A2D413B24DFEULL,
		0xB398B3C6C21B591FULL,
		0x3D84B1345FBAC4F7ULL,
		0x1C2FF1F5543C4167ULL,
		0x0147E2E620EE6F8EULL,
		0xF85B6B2DEA3955B6ULL,
		0x696D13FBF200C0C3ULL,
		0xC73BBF7B550C5DCBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x66BFAF6C105A2F2BULL,
		0xAE90C3BBF736426FULL,
		0x3E05C563AEE220E0ULL,
		0xB112023B4679B486ULL,
		0x608C2A0BBE9EDC74ULL,
		0x5D448488ADEE1AC2ULL,
		0x495EFD1CA76E5C40ULL,
		0x772B03EA81D12D0DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 95\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 95 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -95;
	} else {
		printf("Test Case 95 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6B8977A94ABC59ABULL,
		0xFC9E6E0261332C68ULL,
		0x557141F91B355D5DULL,
		0x56A8D238F3C631BAULL,
		0x6E408D485540A66EULL,
		0xE62D023A516958D9ULL,
		0x40501F7E7B0A7CB1ULL,
		0xF6E51591E2E7463BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB149E4FB3E3C9F28ULL,
		0x90D127020D1EF233ULL,
		0xF5CF2C302F77A8B8ULL,
		0xAB1F5E6D1EA4205DULL,
		0x67A59FC5500FC9BCULL,
		0xF346EF9E58587EC8ULL,
		0x7D93801214642359ULL,
		0xDC67E62FF1EC39B0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBA3F92AE0C7FBA83ULL,
		0x6BCD470054143A34ULL,
		0x5FA215C8EBBDB4A5ULL,
		0xAB8973CBD522115CULL,
		0x069AED830530DCB1ULL,
		0xF2E6129BF910DA11ULL,
		0xC2BC9F6C66A65957ULL,
		0x1A7D2F61F0FB0C8AULL
	}};
	sign = 0;
	printf("Test Case 96\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 96 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -96;
	} else {
		printf("Test Case 96 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1EF416C0366E609DULL,
		0x2FAE4A498F78BAECULL,
		0xFBC73004D1CCBAE8ULL,
		0x4D80A895F601DB25ULL,
		0xED0DC3306E310838ULL,
		0xEC4B275E7DC8E1A6ULL,
		0x7E553222705C9F2BULL,
		0x3BF468484321DBC2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE71B439B3D855839ULL,
		0x66A013FEE73F560EULL,
		0xA64FDEE5F44ECD04ULL,
		0x7FAE10E8C67B669EULL,
		0x00460FDFC8E1678BULL,
		0xE8B99736E5CCDD88ULL,
		0x8D9BC1590ADD14E2ULL,
		0x77187F00772134EFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x37D8D324F8E90864ULL,
		0xC90E364AA83964DDULL,
		0x5577511EDD7DEDE3ULL,
		0xCDD297AD2F867487ULL,
		0xECC7B350A54FA0ACULL,
		0x0391902797FC041EULL,
		0xF0B970C9657F8A49ULL,
		0xC4DBE947CC00A6D2ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 97\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 97 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -97;
	} else {
		printf("Test Case 97 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x322DD6AB3C04C63EULL,
		0x2BBA5053E02CD565ULL,
		0x6B96BBE2614F2A5FULL,
		0x5EC90C0596F824A7ULL,
		0xA1CA69D110C76855ULL,
		0xA3C68E1F122B9A3DULL,
		0xF25B1A9E0C866CEBULL,
		0x852EFA3B34856000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4BAB73203D9B217ULL,
		0x40CA20F3C15D7A73ULL,
		0x6EEA192BEA5B2416ULL,
		0x3466161EAE9769EFULL,
		0xA2D28B7EA67B121FULL,
		0xBD30264086965256ULL,
		0x4D173B5B2E1E26BAULL,
		0xA81941641B218D72ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4D731F79382B1427ULL,
		0xEAF02F601ECF5AF1ULL,
		0xFCACA2B676F40648ULL,
		0x2A62F5E6E860BAB7ULL,
		0xFEF7DE526A4C5636ULL,
		0xE69667DE8B9547E6ULL,
		0xA543DF42DE684630ULL,
		0xDD15B8D71963D28EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 98\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 98 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -98;
	} else {
		printf("Test Case 98 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6BBCB39555291D65ULL,
		0x3A1ECF11FB4A8E43ULL,
		0x91A7980E179E482BULL,
		0x4BFC77F7A3E9085AULL,
		0x91F195907C654C41ULL,
		0x25641212E6BE5434ULL,
		0x63C1786A4AF30D6CULL,
		0x71EF410F4E9D553FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F26505ED1B52AD6ULL,
		0x041C9094ABF6F978ULL,
		0x2064C99C8A8498D5ULL,
		0xAB7B9981C4A2EDD6ULL,
		0xA80F4C0E3405966DULL,
		0xC4411FD4EDA101C3ULL,
		0x35E54A80FFD39264ULL,
		0x0128B5B9E8EAEB3FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C9663368373F28FULL,
		0x36023E7D4F5394CBULL,
		0x7142CE718D19AF56ULL,
		0xA080DE75DF461A84ULL,
		0xE9E24982485FB5D3ULL,
		0x6122F23DF91D5270ULL,
		0x2DDC2DE94B1F7B07ULL,
		0x70C68B5565B26A00ULL
	}};
	sign = 0;
	printf("Test Case 99\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 99 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -99;
	} else {
		printf("Test Case 99 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5F3DF4FC6BC3F22EULL,
		0xBDF2DF93D33D4757ULL,
		0xCA8303DB513519D0ULL,
		0x72BCECC980F8C9EAULL,
		0x2B69ADCCA133D2FFULL,
		0x7FB2D9DAB188D25DULL,
		0x3AA7E9222E21F62DULL,
		0x6B6E3A29CA77215DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE7C0D329D8CA963ULL,
		0xA6B1DF954D7723FBULL,
		0x761FADF0CEBA087BULL,
		0xCD69EEDA36B4EE09ULL,
		0x1516D1C2D3705A2AULL,
		0xEF85D5E08F66CF2CULL,
		0x5E86CEE68107C3D0ULL,
		0x5C303227EDD6D7F1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x70C1E7C9CE3748CBULL,
		0x1740FFFE85C6235BULL,
		0x546355EA827B1155ULL,
		0xA552FDEF4A43DBE1ULL,
		0x1652DC09CDC378D4ULL,
		0x902D03FA22220331ULL,
		0xDC211A3BAD1A325CULL,
		0x0F3E0801DCA0496BULL
	}};
	sign = 0;
	printf("Test Case 100\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 100 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -100;
	} else {
		printf("Test Case 100 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0F65C282F55A97FAULL,
		0x29FBAAC736369869ULL,
		0x52D16C61ACCF1C1BULL,
		0xD7A30E15AF2EF1C4ULL,
		0x12603E20B96C35FEULL,
		0x2852E9A8B2B21BF0ULL,
		0xC5DD2BAC662A7B91ULL,
		0x346F4676A4FB8ECFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD71D0687A8FDDAA9ULL,
		0x07D4559D35E18389ULL,
		0x630CC5A0F331657DULL,
		0x05AD9B08A3412D59ULL,
		0x3550A8B155636E09ULL,
		0x2148462E43747353ULL,
		0x9A4D2970254E2DD1ULL,
		0x0E74A2BEFBC02341ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3848BBFB4C5CBD51ULL,
		0x2227552A005514DFULL,
		0xEFC4A6C0B99DB69EULL,
		0xD1F5730D0BEDC46AULL,
		0xDD0F956F6408C7F5ULL,
		0x070AA37A6F3DA89CULL,
		0x2B90023C40DC4DC0ULL,
		0x25FAA3B7A93B6B8EULL
	}};
	sign = 0;
	printf("Test Case 101\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 101 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -101;
	} else {
		printf("Test Case 101 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x83C0B31B04212B7EULL,
		0x349601A51CC33523ULL,
		0x1EBD74BE16DB623FULL,
		0x1D3D5746C32FEEEFULL,
		0xCFBD9C825D81A72AULL,
		0xD5E7F50AA36FEE11ULL,
		0xA180EBCAAFFC299BULL,
		0x023AD6A7273B565FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C28FECF5271843BULL,
		0x50466CE4EAA9727BULL,
		0x307FBCB03B0BDE22ULL,
		0x0D3927148C5F6591ULL,
		0x3E27CE9C5C5B765AULL,
		0xD8EA6800E5EB8FDEULL,
		0x33E08850EF3E8412ULL,
		0xD6E229DA379D9213ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4797B44BB1AFA743ULL,
		0xE44F94C03219C2A8ULL,
		0xEE3DB80DDBCF841CULL,
		0x1004303236D0895DULL,
		0x9195CDE6012630D0ULL,
		0xFCFD8D09BD845E33ULL,
		0x6DA06379C0BDA588ULL,
		0x2B58ACCCEF9DC44CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 102\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 102 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -102;
	} else {
		printf("Test Case 102 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBB83714561342615ULL,
		0x0E5259E25E5531F3ULL,
		0x429432601A47F804ULL,
		0x81E541D8BD91D582ULL,
		0x91781C191410DC5EULL,
		0x1BB8D96C2288804FULL,
		0x07EAA3398DB978A6ULL,
		0x5158C6FEAFCEDB01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A1BA13F8F33892EULL,
		0x12EE2CDCD53C8FF4ULL,
		0xFDFFF5BE37CA99C9ULL,
		0x4B081A5E2B0B0FE5ULL,
		0xCCFD6C1654F90E51ULL,
		0xAE7ED9612CBB7F31ULL,
		0x464E3908A33A1A1BULL,
		0xC3B8DDD3F7C18092ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6167D005D2009CE7ULL,
		0xFB642D058918A1FFULL,
		0x44943CA1E27D5E3AULL,
		0x36DD277A9286C59CULL,
		0xC47AB002BF17CE0DULL,
		0x6D3A000AF5CD011DULL,
		0xC19C6A30EA7F5E8AULL,
		0x8D9FE92AB80D5A6EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 103\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 103 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -103;
	} else {
		printf("Test Case 103 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4B521119DD8BB32EULL,
		0xA81FD3646BA6854AULL,
		0x1B58CAB8664806E4ULL,
		0x7835D936FA83B167ULL,
		0x63A90D0E2C9C92BDULL,
		0x1E687327A205C8A5ULL,
		0x8FFCEFE22BA0A28FULL,
		0x3F0D3C7C28EF30D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC18DA464580A4B93ULL,
		0xD512D2FB528DC075ULL,
		0x7E2D222A727935ECULL,
		0xED7FB2FC32C61C39ULL,
		0xECE448893EC9F347ULL,
		0x9D21ACB3B4E4ED81ULL,
		0x9B89B9997385FDF3ULL,
		0x5FFD5B0858902CFDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x89C46CB58581679BULL,
		0xD30D00691918C4D4ULL,
		0x9D2BA88DF3CED0F7ULL,
		0x8AB6263AC7BD952DULL,
		0x76C4C484EDD29F75ULL,
		0x8146C673ED20DB23ULL,
		0xF4733648B81AA49BULL,
		0xDF0FE173D05F03D5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 104\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 104 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -104;
	} else {
		printf("Test Case 104 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7C3662E475170B71ULL,
		0xC50F06EF67E8802DULL,
		0xCEE84844E14C82DFULL,
		0xD96A2198D29507D9ULL,
		0x76E27891D36CB1A8ULL,
		0x567D3C83BD7F3113ULL,
		0xBDBF72CDA84BFD63ULL,
		0x8119ED6B2D58E8FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47D33CF9DE39FD5FULL,
		0xF32C286010F1FD7CULL,
		0x4B0DACC990717ADAULL,
		0x4F3C799360514915ULL,
		0xE1885151BA3DB0DEULL,
		0x9F13BFE7825846B8ULL,
		0x6E0B2AA075F41A88ULL,
		0xCA36491B9FDB5326ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x346325EA96DD0E12ULL,
		0xD1E2DE8F56F682B1ULL,
		0x83DA9B7B50DB0804ULL,
		0x8A2DA8057243BEC4ULL,
		0x955A2740192F00CAULL,
		0xB7697C9C3B26EA5AULL,
		0x4FB4482D3257E2DAULL,
		0xB6E3A44F8D7D95D8ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 105\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 105 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -105;
	} else {
		printf("Test Case 105 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD448AE24C2356FC9ULL,
		0x1316FD2B312A862AULL,
		0xDCC858BCAA28D4F4ULL,
		0xF347A624CDC74A44ULL,
		0xB9BE44C077833121ULL,
		0x196FC63FC8D5B4A6ULL,
		0x882D2ED25198B296ULL,
		0x46133170CF0A6F3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x630E57C5ACD08122ULL,
		0xE2167067CE12E921ULL,
		0x843D94475327AE84ULL,
		0xFFC41A50147364C1ULL,
		0x047F5466E4709554ULL,
		0x4EE5DB4C0AC1BA7DULL,
		0xC381E07218934303ULL,
		0x9330A602E665C074ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x713A565F1564EEA7ULL,
		0x31008CC363179D09ULL,
		0x588AC4755701266FULL,
		0xF3838BD4B953E583ULL,
		0xB53EF05993129BCCULL,
		0xCA89EAF3BE13FA29ULL,
		0xC4AB4E6039056F92ULL,
		0xB2E28B6DE8A4AEC9ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 106\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 106 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -106;
	} else {
		printf("Test Case 106 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE507534FA93F2FB1ULL,
		0x529DD40FEC61CE5AULL,
		0xA838C81AB0CC3B64ULL,
		0x01CD51BAF6D3C89BULL,
		0xCAB21323C14C0DA4ULL,
		0xA8B2C4EBD2B2BEE4ULL,
		0x8F5D92044A6F9078ULL,
		0x31B41C9C56A49003ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1ED437360DA9D5AAULL,
		0x014710B577F715B2ULL,
		0x5C74729D9FBFFF20ULL,
		0x18B04F910E91B385ULL,
		0x80F529A80F469C1AULL,
		0x32D08FDA2A167D7DULL,
		0xCAC2615190CC96E3ULL,
		0x69E13F9FED50A6A1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC6331C199B955A07ULL,
		0x5156C35A746AB8A8ULL,
		0x4BC4557D110C3C44ULL,
		0xE91D0229E8421516ULL,
		0x49BCE97BB2057189ULL,
		0x75E23511A89C4167ULL,
		0xC49B30B2B9A2F995ULL,
		0xC7D2DCFC6953E961ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 107\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 107 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -107;
	} else {
		printf("Test Case 107 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x522A43504F275FD2ULL,
		0x652AFBB4881B49A7ULL,
		0xC7CBDC35BA82111DULL,
		0x78B517A1613CF57AULL,
		0x553AC7DA6BF7D5BBULL,
		0x61BB5987B1486814ULL,
		0x2AE53CB7B04BC1C0ULL,
		0xDE444DC935102AEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4070556D415FB1C8ULL,
		0x4B80E93D88E0A0D5ULL,
		0xDF2D3D5258B30AFAULL,
		0x5371A5FDB39552C8ULL,
		0xAE215DF88AEE67DCULL,
		0x9ACEB0523794A9BFULL,
		0x532506EADA8C0F07ULL,
		0x68BC7A628ACFA842ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x11B9EDE30DC7AE0AULL,
		0x19AA1276FF3AA8D2ULL,
		0xE89E9EE361CF0623ULL,
		0x254371A3ADA7A2B1ULL,
		0xA71969E1E1096DDFULL,
		0xC6ECA93579B3BE54ULL,
		0xD7C035CCD5BFB2B8ULL,
		0x7587D366AA4082AAULL
	}};
	sign = 0;
	printf("Test Case 108\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 108 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -108;
	} else {
		printf("Test Case 108 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0FB28D01DBE63F63ULL,
		0x9B2E08BD9687EFA3ULL,
		0x2DB13FFE9590D85FULL,
		0x944D32B07AC5CEA5ULL,
		0x673A2A462837F6CEULL,
		0xCB8FEDAD43D920DCULL,
		0x73DBEAD11266507CULL,
		0xBFF677EB2B13E35DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x877953CB7D05D929ULL,
		0xFAA440AE15098C5CULL,
		0xCA7DADDE941C78D3ULL,
		0x149A58AA58EC8102ULL,
		0x99900858779CF10DULL,
		0x6E1D405945FBACDFULL,
		0x7217C0DF1D63A308ULL,
		0xEA64C79A7BAFDDD1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x883939365EE0663AULL,
		0xA089C80F817E6346ULL,
		0x6333922001745F8BULL,
		0x7FB2DA0621D94DA2ULL,
		0xCDAA21EDB09B05C1ULL,
		0x5D72AD53FDDD73FCULL,
		0x01C429F1F502AD74ULL,
		0xD591B050AF64058CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 109\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 109 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -109;
	} else {
		printf("Test Case 109 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2A40DB97507D9167ULL,
		0xF20F8447F56662DAULL,
		0x80931EAD3523C0E4ULL,
		0xE81E17274B4B2720ULL,
		0x24E6011E8486ACB5ULL,
		0x866B9BB73B3A30B3ULL,
		0x4119D6E31F5FEB42ULL,
		0xA72CDC010AE3A3F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B3A37FCDE2E02B2ULL,
		0x89B2F86471BF3FB5ULL,
		0x04992308E844C09EULL,
		0xE55C3EAA11E53C22ULL,
		0xAB528E4C65CB0C6BULL,
		0x44D4062F871F53BAULL,
		0x7C03F067768251EAULL,
		0x15E625F9E12F456BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAF06A39A724F8EB5ULL,
		0x685C8BE383A72324ULL,
		0x7BF9FBA44CDF0046ULL,
		0x02C1D87D3965EAFEULL,
		0x799372D21EBBA04AULL,
		0x41979587B41ADCF8ULL,
		0xC515E67BA8DD9958ULL,
		0x9146B60729B45E85ULL
	}};
	sign = 0;
	printf("Test Case 110\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 110 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -110;
	} else {
		printf("Test Case 110 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x86DA4312538ED245ULL,
		0x7B9B8270556186E5ULL,
		0xB70346461510D9AEULL,
		0x6485CE582FD3A1F8ULL,
		0xC34EF0A14F676A6CULL,
		0x7937615EBB6CB5C0ULL,
		0x233830307E994180ULL,
		0x58E37596CB4C76C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x619AED76A2602A3CULL,
		0xA47141EA67553B75ULL,
		0x63245FC14120CE63ULL,
		0x9EC5E2DB3BDC2E6DULL,
		0x0A7217BE4680A33CULL,
		0xDBC042F3BBC070C3ULL,
		0x74D40935B94817B9ULL,
		0x86AAB671EA37AA52ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x253F559BB12EA809ULL,
		0xD72A4085EE0C4B70ULL,
		0x53DEE684D3F00B4AULL,
		0xC5BFEB7CF3F7738BULL,
		0xB8DCD8E308E6C72FULL,
		0x9D771E6AFFAC44FDULL,
		0xAE6426FAC55129C6ULL,
		0xD238BF24E114CC73ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 111\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 111 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -111;
	} else {
		printf("Test Case 111 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x032097EA62EA05C1ULL,
		0x4F69A220A2B3D148ULL,
		0x27AF43B1CC07B33FULL,
		0x2E8079FFD227A8E2ULL,
		0xE26EB0328D571786ULL,
		0x459393142C6B623FULL,
		0x449E7FEAD5E75692ULL,
		0xB0EA30B6120DED4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46A19B96D29BE10AULL,
		0xF01AA1A153298DB7ULL,
		0x516225439029B532ULL,
		0x6A67CCAB76B30229ULL,
		0xD7990BFE166D4453ULL,
		0x66B6401C72132F3AULL,
		0xB891B2A04EFC04D0ULL,
		0x76BAAF7D41D2C08AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBC7EFC53904E24B7ULL,
		0x5F4F007F4F8A4390ULL,
		0xD64D1E6E3BDDFE0CULL,
		0xC418AD545B74A6B8ULL,
		0x0AD5A43476E9D332ULL,
		0xDEDD52F7BA583305ULL,
		0x8C0CCD4A86EB51C1ULL,
		0x3A2F8138D03B2CC0ULL
	}};
	sign = 0;
	printf("Test Case 112\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 112 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -112;
	} else {
		printf("Test Case 112 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAAAA45F0557D7EB2ULL,
		0x7E0BAF6722EE017FULL,
		0xDB1D7E70DB411FF4ULL,
		0x31A6073B9CCF427AULL,
		0x5583A1F332CA2F5EULL,
		0xE0A832C8F5C7FFB4ULL,
		0x31436E7D67DFD6C0ULL,
		0xE7E9AAAF99340F45ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C3002811EE6CA65ULL,
		0xBD438BC603E87300ULL,
		0x9E9AB51E13A653CCULL,
		0xD198449E0CFF5D61ULL,
		0x43A0E0C919BF5A31ULL,
		0x1167E0431F96A9A5ULL,
		0x5FFF61F0658C35C4ULL,
		0x29D5176B3792B29EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8E7A436F3696B44DULL,
		0xC0C823A11F058E7FULL,
		0x3C82C952C79ACC27ULL,
		0x600DC29D8FCFE519ULL,
		0x11E2C12A190AD52CULL,
		0xCF405285D631560FULL,
		0xD1440C8D0253A0FCULL,
		0xBE14934461A15CA6ULL
	}};
	sign = 0;
	printf("Test Case 113\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 113 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -113;
	} else {
		printf("Test Case 113 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCCEC61481957D387ULL,
		0x152707C1A931939BULL,
		0x2F2D6549FA6888D3ULL,
		0x05B6986E29C456A7ULL,
		0x9A0916D6A9193BE3ULL,
		0x7594B18596F254F7ULL,
		0x6A92038751412A52ULL,
		0xC63181FA381BE3A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF580011BF45BF22ULL,
		0x621D55F1C0250235ULL,
		0x8595908ACB58FFA1ULL,
		0xA8D4C203734862CFULL,
		0xA391DAF46FAF5529ULL,
		0x8EB981430E767641ULL,
		0x4C9C17E1B2F1733CULL,
		0x54541285CEF33EE5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1D9461365A121465ULL,
		0xB309B1CFE90C9166ULL,
		0xA997D4BF2F0F8931ULL,
		0x5CE1D66AB67BF3D7ULL,
		0xF6773BE23969E6B9ULL,
		0xE6DB3042887BDEB5ULL,
		0x1DF5EBA59E4FB715ULL,
		0x71DD6F746928A4C4ULL
	}};
	sign = 0;
	printf("Test Case 114\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 114 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -114;
	} else {
		printf("Test Case 114 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5E7CAFAFEC7B13BDULL,
		0xEDC9AFECE998CD58ULL,
		0x781D47920CD73E85ULL,
		0xEFD7AF9B5167E511ULL,
		0x94A9E6CA2422CD1DULL,
		0x019D81C0615CD786ULL,
		0x9CE4673BBF21C4C5ULL,
		0x59914A7DAF3E7575ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC90086FB6D6BEB31ULL,
		0xECE3536F2D15E586ULL,
		0xB6460C50806E1331ULL,
		0x73E9C17AFE07165CULL,
		0x0C5BDBBAA1195DB3ULL,
		0x1F309A1B66D6AC45ULL,
		0x6692F776704B3557ULL,
		0xD6DB4D817EB61558ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x957C28B47F0F288CULL,
		0x00E65C7DBC82E7D1ULL,
		0xC1D73B418C692B54ULL,
		0x7BEDEE205360CEB4ULL,
		0x884E0B0F83096F6AULL,
		0xE26CE7A4FA862B41ULL,
		0x36516FC54ED68F6DULL,
		0x82B5FCFC3088601DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 115\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 115 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -115;
	} else {
		printf("Test Case 115 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF9FD91345F93E9D3ULL,
		0x3FECAE932E0E729CULL,
		0xD27F452E888D54AFULL,
		0xA2DFA3DABEDE465DULL,
		0x3C190BB49C4AD996ULL,
		0x0D9A29CC470F1E07ULL,
		0x6BD0ADB2088376DAULL,
		0x238A2B047CDEB02BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDC1DEF046BC9276ULL,
		0xD0ADB1CE7356D9DBULL,
		0xE0104B08B235C4A2ULL,
		0x6BA676AE91F48F89ULL,
		0xCB903AFEE895659DULL,
		0x070034FDBE34ED27ULL,
		0x6E86D64C4AD5E792ULL,
		0xBBB57511504DA49EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1C3BB24418D7575DULL,
		0x6F3EFCC4BAB798C1ULL,
		0xF26EFA25D657900CULL,
		0x37392D2C2CE9B6D3ULL,
		0x7088D0B5B3B573F9ULL,
		0x0699F4CE88DA30DFULL,
		0xFD49D765BDAD8F48ULL,
		0x67D4B5F32C910B8CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 116\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 116 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -116;
	} else {
		printf("Test Case 116 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5015E5D6D71D61F3ULL,
		0x65BFC1DC68EC22DAULL,
		0x8C54425FE20D9AF6ULL,
		0x5DB8E9926B02C545ULL,
		0x556E9B5DD3DCA950ULL,
		0x5EF52443CAFB585BULL,
		0x6BF9D9D0C7593067ULL,
		0xF43AD8C401196FC1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF119677134A2FBD4ULL,
		0x4C9F6B51C8D132A9ULL,
		0x8BD765E3599FDB5FULL,
		0x66BC4C1283B13AFFULL,
		0xF7A812631E1B98F0ULL,
		0x066A53E6F66E5091ULL,
		0x675FB57AB760CF0DULL,
		0x4BF94ACD406AE3F1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5EFC7E65A27A661FULL,
		0x1920568AA01AF030ULL,
		0x007CDC7C886DBF97ULL,
		0xF6FC9D7FE7518A46ULL,
		0x5DC688FAB5C1105FULL,
		0x588AD05CD48D07C9ULL,
		0x049A24560FF8615AULL,
		0xA8418DF6C0AE8BD0ULL
	}};
	sign = 0;
	printf("Test Case 117\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 117 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -117;
	} else {
		printf("Test Case 117 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x019AD15474666539ULL,
		0x1D8EBBCC0BBCFF06ULL,
		0x1AFA24A64F9CA102ULL,
		0x2B8F0B89A9E40FE5ULL,
		0x4B64DDEC83BA6A0DULL,
		0x33FF0E9464895E94ULL,
		0x46A223EE509D9093ULL,
		0xD05EC7E6A6F66ED6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42F2DDE80F1FE64DULL,
		0x860474C35EB6A401ULL,
		0xFA99A456EDB2298FULL,
		0xAD99DDA81500CA7BULL,
		0x5FEA90248EC5C54FULL,
		0x70D0800949B27F2AULL,
		0x223D04B9A4F6A8D2ULL,
		0xB86341270FA08451ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBEA7F36C65467EECULL,
		0x978A4708AD065B04ULL,
		0x2060804F61EA7772ULL,
		0x7DF52DE194E34569ULL,
		0xEB7A4DC7F4F4A4BDULL,
		0xC32E8E8B1AD6DF69ULL,
		0x24651F34ABA6E7C0ULL,
		0x17FB86BF9755EA85ULL
	}};
	sign = 0;
	printf("Test Case 118\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 118 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -118;
	} else {
		printf("Test Case 118 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB6C240A478B26C27ULL,
		0x9B18AECEF3E8A728ULL,
		0x4E25B9921C9464CCULL,
		0xC1B9F1AFED2126DDULL,
		0x0202DC3757B618B8ULL,
		0xA7B77ABFB30C2DB7ULL,
		0x78BF7EC8FE379DD1ULL,
		0x88565558B14BA81BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B20FB856EF33D61ULL,
		0x73B9DF85455DB925ULL,
		0x58C55BEFBAAB95A0ULL,
		0xF1F98996DA35CA99ULL,
		0x721851DC062473D0ULL,
		0x12F127AF414BA8FBULL,
		0x7890D47A261A849BULL,
		0x38878B0754FD6077ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4BA1451F09BF2EC6ULL,
		0x275ECF49AE8AEE03ULL,
		0xF5605DA261E8CF2CULL,
		0xCFC0681912EB5C43ULL,
		0x8FEA8A5B5191A4E7ULL,
		0x94C6531071C084BBULL,
		0x002EAA4ED81D1936ULL,
		0x4FCECA515C4E47A4ULL
	}};
	sign = 0;
	printf("Test Case 119\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 119 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -119;
	} else {
		printf("Test Case 119 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6E987A8BBF11741FULL,
		0x7B10E8CAC05180D2ULL,
		0xAC22EF57AEC77459ULL,
		0xDD09C1D45322FFA4ULL,
		0xCBEB3C89564F36A7ULL,
		0xDDDDA1135E4ECB81ULL,
		0xA5306982842B88FAULL,
		0xAB764CF59F7F8221ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4129DFF9989DD067ULL,
		0xCC96F824C607AB81ULL,
		0x81941F586467B5BEULL,
		0xA93339FBDAA287C9ULL,
		0x70230CF8E30B4E6FULL,
		0x89F9BEA4FC34532BULL,
		0x95F0D1CD2A286306ULL,
		0xAEB7DAC19844CBB4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2D6E9A922673A3B8ULL,
		0xAE79F0A5FA49D551ULL,
		0x2A8ECFFF4A5FBE9AULL,
		0x33D687D8788077DBULL,
		0x5BC82F907343E838ULL,
		0x53E3E26E621A7856ULL,
		0x0F3F97B55A0325F4ULL,
		0xFCBE7234073AB66DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 120\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 120 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -120;
	} else {
		printf("Test Case 120 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE46C5D59D1718BF3ULL,
		0x796EFE5898B8DC4DULL,
		0x6726B7D3830864C0ULL,
		0x8BC8881A1983F119ULL,
		0x341F0196ED1B8B3FULL,
		0xF44E1E775B05B5FCULL,
		0xC83C01DCFF45D0B4ULL,
		0x6C8178D0CDD6A7C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAEA67BCF78A5C376ULL,
		0xF1078A7F8CC8B504ULL,
		0x49961302E1951B23ULL,
		0xA6F02C6EC21420FEULL,
		0xF83F93F743780FC7ULL,
		0x9BC7A5480BCB363DULL,
		0x44C25A2D6E8E35AFULL,
		0x211F431DE6930D54ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x35C5E18A58CBC87DULL,
		0x886773D90BF02749ULL,
		0x1D90A4D0A173499CULL,
		0xE4D85BAB576FD01BULL,
		0x3BDF6D9FA9A37B77ULL,
		0x5886792F4F3A7FBEULL,
		0x8379A7AF90B79B05ULL,
		0x4B6235B2E7439A70ULL
	}};
	sign = 0;
	printf("Test Case 121\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 121 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -121;
	} else {
		printf("Test Case 121 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x880E4A3BF69910C2ULL,
		0x45E13CE26AC83C18ULL,
		0x7C566AE8B61D9169ULL,
		0xBBFC27A06E1109B7ULL,
		0xE903395A2A3C0399ULL,
		0x9EA53C5BC37C872CULL,
		0xC28D4D88CA499B26ULL,
		0xF0220960B72EBADDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADC22A301A017559ULL,
		0x7CDF1556916F48F9ULL,
		0xF29E1697F9638AC1ULL,
		0x088FDC6D2DBE4EE1ULL,
		0x4DD7B2D7D53EEC24ULL,
		0xCFE79BE81B7FD41EULL,
		0x24FDF836F7F971BAULL,
		0x2400CDB46494C5A6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDA4C200BDC979B69ULL,
		0xC902278BD958F31EULL,
		0x89B85450BCBA06A7ULL,
		0xB36C4B334052BAD5ULL,
		0x9B2B868254FD1775ULL,
		0xCEBDA073A7FCB30EULL,
		0x9D8F5551D250296BULL,
		0xCC213BAC5299F537ULL
	}};
	sign = 0;
	printf("Test Case 122\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 122 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -122;
	} else {
		printf("Test Case 122 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF7F1B3DDF61344CAULL,
		0xD182AC8AF1E8BCF7ULL,
		0xE5C57E7419985C0DULL,
		0xA63D7E3D0A5F82B1ULL,
		0xCDD9101AAD944849ULL,
		0x1B72F4726525D6DBULL,
		0x49859B9456D0018BULL,
		0xADE78CA5D26905EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07507C905D4725F8ULL,
		0x8CD7F2D7816F87CCULL,
		0xCD4BB5365C1E8130ULL,
		0x972DE5A9A24CF762ULL,
		0x9FCF7515D56A60EDULL,
		0xBE361DC647389FDEULL,
		0xD36E864CB7D6B3E8ULL,
		0xBFF9651820E3E91AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF0A1374D98CC1ED2ULL,
		0x44AAB9B37079352BULL,
		0x1879C93DBD79DADDULL,
		0x0F0F989368128B4FULL,
		0x2E099B04D829E75CULL,
		0x5D3CD6AC1DED36FDULL,
		0x761715479EF94DA2ULL,
		0xEDEE278DB1851CD3ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 123\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 123 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -123;
	} else {
		printf("Test Case 123 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4CD9A919B5AEDE0CULL,
		0x596F8A5638E96BD9ULL,
		0x333F1C6AAFBED9E5ULL,
		0x28764B52F3CA6850ULL,
		0x617C8B86850A15D0ULL,
		0x11622DF695F197F4ULL,
		0x0C02B58034DC304CULL,
		0x7A57993EEF7CB39AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DA261C4CECF4360ULL,
		0x73884311D693F7F1ULL,
		0xC39EF4C4189DC826ULL,
		0x4F5DE09648DA1121ULL,
		0x008584141B261B0BULL,
		0x669A1128348D8910ULL,
		0xDDCA43AC8F95CA3DULL,
		0xABF5EC4972C5C11BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEF374754E6DF9AACULL,
		0xE5E74744625573E7ULL,
		0x6FA027A6972111BEULL,
		0xD9186ABCAAF0572EULL,
		0x60F7077269E3FAC4ULL,
		0xAAC81CCE61640EE4ULL,
		0x2E3871D3A546660EULL,
		0xCE61ACF57CB6F27EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 124\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 124 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -124;
	} else {
		printf("Test Case 124 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2F20548386B2AF8EULL,
		0xD9AA05E0200752A7ULL,
		0x1994334C97E9FE04ULL,
		0x58B45FA095986CAEULL,
		0xDF0EFD8151786E1FULL,
		0x6EFADAAE25FCECC4ULL,
		0xB9C8E7AC56A10A8CULL,
		0x7503B21FBE0B75A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D56EC47DDE90527ULL,
		0x30E35E443C1EF981ULL,
		0xA84D9D2CE86A7440ULL,
		0xFD467EDB35288832ULL,
		0x4CB9CED5552A6664ULL,
		0xCE826F6F5600CF35ULL,
		0x6290669C7C4DDFA8ULL,
		0x69F1CB187DFBFB70ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA1C9683BA8C9AA67ULL,
		0xA8C6A79BE3E85925ULL,
		0x7146961FAF7F89C4ULL,
		0x5B6DE0C5606FE47BULL,
		0x92552EABFC4E07BAULL,
		0xA0786B3ECFFC1D8FULL,
		0x5738810FDA532AE3ULL,
		0x0B11E707400F7A32ULL
	}};
	sign = 0;
	printf("Test Case 125\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 125 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -125;
	} else {
		printf("Test Case 125 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x53AD22099BF69981ULL,
		0x9692BBC9878A522CULL,
		0x70F3B70910FCE38FULL,
		0xBA8E0B6E314D0B82ULL,
		0xAA4AFA21649665C2ULL,
		0x57A106A7BADC164CULL,
		0xB525898B5D11D273ULL,
		0xEEC2B3DA0DE1F584ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B94DDC4A9782B77ULL,
		0x0DC05BC69F874DB1ULL,
		0x57D52ED0A701BC87ULL,
		0xBA6AD6ABF5F8D3F8ULL,
		0x45596D2F84753DC4ULL,
		0x944C5BB2DEE431BBULL,
		0xE6D67E00286D1E21ULL,
		0x565996A21107336AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB8184444F27E6E0AULL,
		0x88D26002E803047AULL,
		0x191E883869FB2708ULL,
		0x002334C23B54378AULL,
		0x64F18CF1E02127FEULL,
		0xC354AAF4DBF7E491ULL,
		0xCE4F0B8B34A4B451ULL,
		0x98691D37FCDAC219ULL
	}};
	sign = 0;
	printf("Test Case 126\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 126 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -126;
	} else {
		printf("Test Case 126 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x484207F6460D1615ULL,
		0x838253D575952931ULL,
		0xF1BEA9B0BD821C8DULL,
		0x42A650646DE851A3ULL,
		0x5A1A6F5F0E7F064AULL,
		0x5D35591105973A8DULL,
		0x07E1CE5028A5A0A3ULL,
		0x307E272231D3846AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x885FAF309D5EEDBDULL,
		0x45E460EE60B9E7B0ULL,
		0x8CBEA2F5151F6DD7ULL,
		0x3D6715DD01FF2EB8ULL,
		0x32C85B391313A2FAULL,
		0x34772C90345EE614ULL,
		0x1D9C30D5018F5F5DULL,
		0x9CDD0EFD27C5BC07ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBFE258C5A8AE2858ULL,
		0x3D9DF2E714DB4180ULL,
		0x650006BBA862AEB6ULL,
		0x053F3A876BE922EBULL,
		0x27521425FB6B6350ULL,
		0x28BE2C80D1385479ULL,
		0xEA459D7B27164146ULL,
		0x93A118250A0DC862ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 127\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 127 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -127;
	} else {
		printf("Test Case 127 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE9AA5AB019CCAC3AULL,
		0x64DF1D7315FF09F4ULL,
		0x58717A29A0431817ULL,
		0xAFB6349CE8E66AEAULL,
		0x4025A1DD662A10A8ULL,
		0xBA6EEB30B7B8017FULL,
		0x54EC6F3E22427099ULL,
		0x4FD74994A886DD6AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68F0BE456BF9A252ULL,
		0x880BED009D469B53ULL,
		0x0E08ADF79E951C43ULL,
		0x0DCB1BDCE6DE99D1ULL,
		0x862F742CB92C83A1ULL,
		0xA96DD33904536FA8ULL,
		0xCA4B63988B335DE7ULL,
		0x8A34F7B540E3BA0AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x80B99C6AADD309E8ULL,
		0xDCD3307278B86EA1ULL,
		0x4A68CC3201ADFBD3ULL,
		0xA1EB18C00207D119ULL,
		0xB9F62DB0ACFD8D07ULL,
		0x110117F7B36491D6ULL,
		0x8AA10BA5970F12B2ULL,
		0xC5A251DF67A3235FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 128\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 128 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -128;
	} else {
		printf("Test Case 128 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB2E74C0F4D73C40BULL,
		0x92B85220C6066418ULL,
		0xB28A2DD42F9D0976ULL,
		0x8C91D13FAB07489DULL,
		0x276E8D78C60E8B29ULL,
		0xC8B6285AA795F8D5ULL,
		0x885F38F9B3610026ULL,
		0xA2C4CAF07B62CE22ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB67C6CEB5CC591BULL,
		0xE613C58B19BEDE65ULL,
		0x543E9FD409B64960ULL,
		0x4DBF843CDEC5B609ULL,
		0x34BC6ADF4CA1C182ULL,
		0xC6061BE02F9EF4B6ULL,
		0x6FB669C8294A41E2ULL,
		0x8AE5CD6802AE7796ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB77F854097A76AF0ULL,
		0xACA48C95AC4785B2ULL,
		0x5E4B8E0025E6C015ULL,
		0x3ED24D02CC419294ULL,
		0xF2B22299796CC9A7ULL,
		0x02B00C7A77F7041EULL,
		0x18A8CF318A16BE44ULL,
		0x17DEFD8878B4568CULL
	}};
	sign = 0;
	printf("Test Case 129\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 129 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -129;
	} else {
		printf("Test Case 129 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5220F82FC8394E57ULL,
		0x5D6212914CFC6FC6ULL,
		0x12DBF99F78F4088BULL,
		0x5CE1A39F339E1FFAULL,
		0x67C2C8E13BF03FB5ULL,
		0xB090ACE4CE8CFE55ULL,
		0xD5BFD924403BBD11ULL,
		0x8441AAB59839E4E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE14B58F1D641A437ULL,
		0xDF8553BDC3FD7CE8ULL,
		0x4A256118B132854BULL,
		0x851246E9FA2EADDCULL,
		0xB21B0F73198729F5ULL,
		0xC7EA179797703EF7ULL,
		0xE793B0BEDE244490ULL,
		0xA4DF9F78A9A6C075ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x70D59F3DF1F7AA20ULL,
		0x7DDCBED388FEF2DDULL,
		0xC8B69886C7C1833FULL,
		0xD7CF5CB5396F721DULL,
		0xB5A7B96E226915BFULL,
		0xE8A6954D371CBF5DULL,
		0xEE2C286562177880ULL,
		0xDF620B3CEE93246AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 130\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 130 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -130;
	} else {
		printf("Test Case 130 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD8796E6C9D17AB5AULL,
		0x4554A5E7C63927DAULL,
		0xA9737B724D5BCAFDULL,
		0x6B7441D082E2D3C9ULL,
		0x57FB97CC785999EBULL,
		0xBFC45F564BD6497BULL,
		0x782F712C36814130ULL,
		0x07E89BB5ADFB1DFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BAE0B5C6DFAAEEFULL,
		0xAC299646B8BF0DF9ULL,
		0x367A393EE9342805ULL,
		0xA14DBDB2CF1AB593ULL,
		0xC9FB39F2F72BB5FDULL,
		0x3DB22ED2E5381737ULL,
		0x9E8127771FE670A3ULL,
		0x7BC6A1B640CBE2B3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBCCB63102F1CFC6BULL,
		0x992B0FA10D7A19E1ULL,
		0x72F942336427A2F7ULL,
		0xCA26841DB3C81E36ULL,
		0x8E005DD9812DE3EDULL,
		0x82123083669E3243ULL,
		0xD9AE49B5169AD08DULL,
		0x8C21F9FF6D2F3B49ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 131\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 131 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -131;
	} else {
		printf("Test Case 131 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7766718D40627910ULL,
		0xAF8A215C9AAC3245ULL,
		0x966A64F7BE4D0C95ULL,
		0x26FF02A5D1F23526ULL,
		0xADFB43A0C2C94BDEULL,
		0x8C5F2B21B7C6D1ADULL,
		0x5AD0A6F0945D0017ULL,
		0x8924D1DB03638C61ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF50D55FE6DC460DULL,
		0xCB4ADD1D9887484CULL,
		0x54F9215C1838B5CEULL,
		0x14B623813C61D904ULL,
		0xECC59B229A404F26ULL,
		0xFABD1293D0604863ULL,
		0xC90F693B5B915349ULL,
		0xF2263A95834BC0F7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB8159C2D59863303ULL,
		0xE43F443F0224E9F8ULL,
		0x4171439BA61456C6ULL,
		0x1248DF2495905C22ULL,
		0xC135A87E2888FCB8ULL,
		0x91A2188DE7668949ULL,
		0x91C13DB538CBACCDULL,
		0x96FE97458017CB69ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 132\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 132 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -132;
	} else {
		printf("Test Case 132 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8D6B822959A12BD6ULL,
		0x1D3B2FA9B98508CEULL,
		0x0E2ACAEBB3EBAA0DULL,
		0x3963870E45E55E21ULL,
		0x00BB9596379423C9ULL,
		0xF0A48A144656179CULL,
		0xB96CC0D4C9747829ULL,
		0x687E4141720CC4C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16A1AF36DA1F87BCULL,
		0x85744B10CA76CEFAULL,
		0x299DAE95C2605C78ULL,
		0x45AC45BEADE95F8DULL,
		0x994180B31CD4B13AULL,
		0x379F8EBF12B292EDULL,
		0x90A5487515C21D58ULL,
		0x461C044DB1399754ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x76C9D2F27F81A41AULL,
		0x97C6E498EF0E39D4ULL,
		0xE48D1C55F18B4D94ULL,
		0xF3B7414F97FBFE93ULL,
		0x677A14E31ABF728EULL,
		0xB904FB5533A384AEULL,
		0x28C7785FB3B25AD1ULL,
		0x22623CF3C0D32D6FULL
	}};
	sign = 0;
	printf("Test Case 133\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 133 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -133;
	} else {
		printf("Test Case 133 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFF189CF396192610ULL,
		0x3659C4326797B4A3ULL,
		0x3CA1F47BFAC9AA63ULL,
		0x40B7B4215F9F1D49ULL,
		0x5A7E13A8384A66C5ULL,
		0x9EBA38F210F38CC7ULL,
		0x66EF05F6D9B2A91FULL,
		0x937212C7942B0C9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3862B019F0F9A38EULL,
		0x0B1CEFBC45CFD581ULL,
		0x502D9678A8F19BD8ULL,
		0x2F34F15E90795377ULL,
		0xCD4F2E3C1075C97EULL,
		0x34A83FD2CCE0A0AFULL,
		0xE22FD055837D829CULL,
		0xF4DAA2FDC8B999EFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC6B5ECD9A51F8282ULL,
		0x2B3CD47621C7DF22ULL,
		0xEC745E0351D80E8BULL,
		0x1182C2C2CF25C9D1ULL,
		0x8D2EE56C27D49D47ULL,
		0x6A11F91F4412EC17ULL,
		0x84BF35A156352683ULL,
		0x9E976FC9CB7172AEULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 134\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 134 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -134;
	} else {
		printf("Test Case 134 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0B8A85FCE25859B9ULL,
		0x5DAC397E53FC6997ULL,
		0x27C4119D69BEEF5CULL,
		0xD4F2E281D2BE6B62ULL,
		0x3C11792FF24040BAULL,
		0xD70B0C4BA3F6F9EEULL,
		0xEEDBDA54B4AADF17ULL,
		0x566CBF49E653B8ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x044EAF1721F70054ULL,
		0x9D09D0E11E968039ULL,
		0x0D5C2669C6ECB413ULL,
		0xB3A49C049E48812FULL,
		0xFFEA697E3CEFDADEULL,
		0x401EEE59D7FC1084ULL,
		0xC3934CD6FB31B401ULL,
		0x14616F9FB6CE69EBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x073BD6E5C0615965ULL,
		0xC0A2689D3565E95EULL,
		0x1A67EB33A2D23B48ULL,
		0x214E467D3475EA33ULL,
		0x3C270FB1B55065DCULL,
		0x96EC1DF1CBFAE969ULL,
		0x2B488D7DB9792B16ULL,
		0x420B4FAA2F854EC2ULL
	}};
	sign = 0;
	printf("Test Case 135\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 135 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -135;
	} else {
		printf("Test Case 135 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE72E65B72336184EULL,
		0x4B0218409F636952ULL,
		0xD07C9C3579F6064DULL,
		0xBCF1EE71B3A85D87ULL,
		0xCCCACDF2AF9BFF54ULL,
		0x0E0D2A7ADE9B672AULL,
		0xB92DF334C1295E16ULL,
		0x09F28998BE43E519ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D36D787C5018787ULL,
		0x79685301AE52FC05ULL,
		0xB5330E8D278A4499ULL,
		0xC61B7D98C8C88C43ULL,
		0x2A0B2708A862E640ULL,
		0x37BEC69444B86202ULL,
		0xBAFEF2A4DEAE2D05ULL,
		0x4E09CB052144F51CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD9F78E2F5E3490C7ULL,
		0xD199C53EF1106D4DULL,
		0x1B498DA8526BC1B3ULL,
		0xF6D670D8EADFD144ULL,
		0xA2BFA6EA07391913ULL,
		0xD64E63E699E30528ULL,
		0xFE2F008FE27B3110ULL,
		0xBBE8BE939CFEEFFCULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 136\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 136 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -136;
	} else {
		printf("Test Case 136 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5B7431A7E27D8AE1ULL,
		0x2DD708F946E28A9BULL,
		0x8C72F62C8E81FC45ULL,
		0xA08179E4CE0151D7ULL,
		0xE77B5CC6E9BA458AULL,
		0x88C2A21A28DE5FE7ULL,
		0xA7F6107719E6087EULL,
		0xF29AA5A9AEBDFEFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4062210B258EC131ULL,
		0xA686F834ABDA238DULL,
		0xF93A05974F25B32FULL,
		0x0782401FE68285C9ULL,
		0x10988C63312FA049ULL,
		0x984B33958435FF55ULL,
		0x6ACB5AEC178B2EB4ULL,
		0x8DF41768E4CEEFAFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1B12109CBCEEC9B0ULL,
		0x875010C49B08670EULL,
		0x9338F0953F5C4915ULL,
		0x98FF39C4E77ECC0DULL,
		0xD6E2D063B88AA541ULL,
		0xF0776E84A4A86092ULL,
		0x3D2AB58B025AD9C9ULL,
		0x64A68E40C9EF0F50ULL
	}};
	sign = 0;
	printf("Test Case 137\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 137 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -137;
	} else {
		printf("Test Case 137 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC0FB3FBDA95590A5ULL,
		0x73268167DC8DFB4DULL,
		0x3CD7123C3C2BA600ULL,
		0xDA7C21CBE84E910FULL,
		0xED7F7A44AF534C95ULL,
		0xFA74751EFBBCD3F5ULL,
		0x79024A523A3DD26FULL,
		0x2B8F8AFFB5A552D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81CEFAD04CD90F9BULL,
		0x4180CC4532D907B4ULL,
		0x019F3D72B3CAD088ULL,
		0xA8784BBCE2ED3557ULL,
		0xFD91E48B8A33A0FEULL,
		0x4A9D5EBE8B424A18ULL,
		0xE225E494F05D9E28ULL,
		0x95A501549B104D9CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3F2C44ED5C7C810AULL,
		0x31A5B522A9B4F399ULL,
		0x3B37D4C98860D578ULL,
		0x3203D60F05615BB8ULL,
		0xEFED95B9251FAB97ULL,
		0xAFD71660707A89DCULL,
		0x96DC65BD49E03447ULL,
		0x95EA89AB1A95053BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 138\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 138 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -138;
	} else {
		printf("Test Case 138 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x340B373A64AFCD53ULL,
		0x8F42029445E5E202ULL,
		0x95161FE8DEF45DCFULL,
		0x93C4DFD2306EA451ULL,
		0x3BD5DBBB2DAFED62ULL,
		0xF17364FE91D3DA27ULL,
		0x873FE27EF553F06CULL,
		0xD93C3F2B37FD8EDAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1124D1EAA0A1659ULL,
		0xB68250A76FD592E0ULL,
		0xBD32B8DEC83B4A23ULL,
		0x760DA790551CF10AULL,
		0xD1B088F954454FC3ULL,
		0x2FCBCABCDBEE172CULL,
		0xF902ED44C9AB56D7ULL,
		0x82EF8E36DB01F4A1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x92F8EA1BBAA5B6FAULL,
		0xD8BFB1ECD6104F21ULL,
		0xD7E3670A16B913ABULL,
		0x1DB73841DB51B346ULL,
		0x6A2552C1D96A9D9FULL,
		0xC1A79A41B5E5C2FAULL,
		0x8E3CF53A2BA89995ULL,
		0x564CB0F45CFB9A38ULL
	}};
	sign = 0;
	printf("Test Case 139\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 139 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -139;
	} else {
		printf("Test Case 139 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5875EE71B05A093EULL,
		0xE559DB7B60C71BEDULL,
		0x4EFBC0A8E6B6EA00ULL,
		0xCDD707947F47F32DULL,
		0x9B33834E1618ADD6ULL,
		0x48AB69C00D56A5A7ULL,
		0x746F24802EC03D59ULL,
		0x898FFE001346135AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D3296FDB69534C2ULL,
		0xC9CBA1C8DF213C57ULL,
		0x0B84AC335443394AULL,
		0x8BCE7F26FE15EDF5ULL,
		0x12C119D09DA3D4DBULL,
		0x3FC2E244B495E40BULL,
		0xC9423740CA3BD944ULL,
		0x50F7977ADF6CAC32ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2B435773F9C4D47CULL,
		0x1B8E39B281A5DF96ULL,
		0x437714759273B0B6ULL,
		0x4208886D81320538ULL,
		0x8872697D7874D8FBULL,
		0x08E8877B58C0C19CULL,
		0xAB2CED3F64846415ULL,
		0x3898668533D96727ULL
	}};
	sign = 0;
	printf("Test Case 140\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 140 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -140;
	} else {
		printf("Test Case 140 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1DAF2FA31E2F5A64ULL,
		0x4392D351F47AFE4BULL,
		0x765E51654A951DAAULL,
		0x53FC3EAB4F55AC18ULL,
		0xA10C7C0373284D65ULL,
		0xBA11851CD34FC80AULL,
		0x4B91E92EE40FA9B3ULL,
		0xFD6ABAD2CD7C0867ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA83F384E47E9E0E2ULL,
		0x38A4766EE1632947ULL,
		0x4A04A6E30A6B0E6CULL,
		0x233F2D69D52A7C17ULL,
		0x2A1CAF9EC76876A4ULL,
		0xE4D998C69E102C6EULL,
		0xF09AA1BAD74BFEE8ULL,
		0x6F41543F6D396B02ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x756FF754D6457982ULL,
		0x0AEE5CE31317D503ULL,
		0x2C59AA82402A0F3EULL,
		0x30BD11417A2B3001ULL,
		0x76EFCC64ABBFD6C1ULL,
		0xD537EC56353F9B9CULL,
		0x5AF747740CC3AACAULL,
		0x8E29669360429D64ULL
	}};
	sign = 0;
	printf("Test Case 141\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 141 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -141;
	} else {
		printf("Test Case 141 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x267BE9C7B6D14083ULL,
		0x2DFA6114ECB8CCDCULL,
		0x5955FD33C6D47AFAULL,
		0xF8CBDF743A870B5AULL,
		0x3C0E7CA7AEF78B80ULL,
		0x02AFCBA35728E776ULL,
		0xA9714087424FFE7CULL,
		0xC7E7FBAA3B91AD7EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7393CB87C86C4DAULL,
		0x77710000A27FF6B8ULL,
		0x70CF877553A5782FULL,
		0x2A37F7B355E4F0CAULL,
		0x0E9C2653242631C8ULL,
		0x84DAD30C67DCF9CDULL,
		0x3452389C99B83C19ULL,
		0xE7ADF77BF07864AEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7F42AD0F3A4A7BA9ULL,
		0xB68961144A38D623ULL,
		0xE88675BE732F02CAULL,
		0xCE93E7C0E4A21A8FULL,
		0x2D7256548AD159B8ULL,
		0x7DD4F896EF4BEDA9ULL,
		0x751F07EAA897C262ULL,
		0xE03A042E4B1948D0ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 142\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 142 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -142;
	} else {
		printf("Test Case 142 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA1232F5263200B58ULL,
		0x365BAE87EBC2C006ULL,
		0xB25351A6A7B57AEAULL,
		0x5D29BD2899ECD44AULL,
		0x6F85FCCD007A38C7ULL,
		0x1B506D615BAD2B0AULL,
		0x9A8D1B77D027430BULL,
		0x5280AFC6B60D4DC0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8D8CFC7FFADC30AULL,
		0xCA26FDCB4E69A271ULL,
		0x055FD417C308651AULL,
		0xC56C97A0019A1C5AULL,
		0x8928657F1516EE61ULL,
		0xBDCD541F1ACEE2B3ULL,
		0x93AAF7EDC805B182ULL,
		0x14A2666652C28197ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB84A5F8A6372484EULL,
		0x6C34B0BC9D591D94ULL,
		0xACF37D8EE4AD15CFULL,
		0x97BD25889852B7F0ULL,
		0xE65D974DEB634A65ULL,
		0x5D83194240DE4856ULL,
		0x06E2238A08219188ULL,
		0x3DDE4960634ACC29ULL
	}};
	sign = 0;
	printf("Test Case 143\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 143 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -143;
	} else {
		printf("Test Case 143 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2A37F6E3A31933C2ULL,
		0x3C117A3AE02446FEULL,
		0x125AFBFE15C4BD93ULL,
		0x7DE8BEFEAB51A0B8ULL,
		0xE9AC63AC3792E2C7ULL,
		0x0976FD554537654EULL,
		0x9E6121541E7B6D69ULL,
		0x23CA9C2D083D4C7FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA5D6F14CE2C5564ULL,
		0xA8A2A74C9920134BULL,
		0xCF3C6E505E278107ULL,
		0xDC0C4FCCD1705506ULL,
		0xB0BF7B1232D89787ULL,
		0x41EBAFA3AEDC9B89ULL,
		0x763DB38E0AAC4EC8ULL,
		0xAA62ADA0443DA6E7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2FDA87CED4ECDE5EULL,
		0x936ED2EE470433B2ULL,
		0x431E8DADB79D3C8BULL,
		0xA1DC6F31D9E14BB1ULL,
		0x38ECE89A04BA4B3FULL,
		0xC78B4DB1965AC9C5ULL,
		0x28236DC613CF1EA0ULL,
		0x7967EE8CC3FFA598ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 144\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 144 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -144;
	} else {
		printf("Test Case 144 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x89977B730A9E61F0ULL,
		0x91BEAD32608F4D41ULL,
		0x6D35C99FECA882F6ULL,
		0x6D6FC246BD65F2B2ULL,
		0x7EC601FE0C42796DULL,
		0x79B640F80D51FEEEULL,
		0xB427E6DD7CBEB861ULL,
		0x4069CE44D8221970ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA91EC8D8B93B0CE4ULL,
		0xFFA33C9D687DEC75ULL,
		0x39C407927E97A895ULL,
		0xBFE521792E6E9418ULL,
		0x7EE512E8FEF9B37BULL,
		0x2A41D2F052665815ULL,
		0x9EB7891B88CCCE74ULL,
		0xD1F1FE97631E086BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE078B29A5163550CULL,
		0x921B7094F81160CBULL,
		0x3371C20D6E10DA60ULL,
		0xAD8AA0CD8EF75E9AULL,
		0xFFE0EF150D48C5F1ULL,
		0x4F746E07BAEBA6D8ULL,
		0x15705DC1F3F1E9EDULL,
		0x6E77CFAD75041105ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 145\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 145 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -145;
	} else {
		printf("Test Case 145 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x78DA010F57CDDC3EULL,
		0x63C9A2A0BEBDDF00ULL,
		0x9AC556409D6D3CF8ULL,
		0x15E8F524614EBC06ULL,
		0xF0CB42B08D234ED0ULL,
		0x1742B00D07D8CDC5ULL,
		0x0B1FDA8887944F78ULL,
		0x99B7D85756E514C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48321E034BE7A23BULL,
		0xC1624C35D8E7BECEULL,
		0x4117A87C670063B5ULL,
		0x5C3E6DC11F604BF9ULL,
		0xE66538200C162972ULL,
		0x194DA944FD17E231ULL,
		0xD5E8D5225EDDF1BFULL,
		0xE059D417F2F45064ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x30A7E30C0BE63A03ULL,
		0xA267566AE5D62032ULL,
		0x59ADADC4366CD942ULL,
		0xB9AA876341EE700DULL,
		0x0A660A90810D255DULL,
		0xFDF506C80AC0EB94ULL,
		0x3537056628B65DB8ULL,
		0xB95E043F63F0C463ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 146\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 146 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -146;
	} else {
		printf("Test Case 146 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x851A7968F74994CCULL,
		0x7673A8FCA3FF2E30ULL,
		0xA6DBACC95C610E50ULL,
		0xE2D2358607CE9AD5ULL,
		0x751D31B3D8785B44ULL,
		0x5D9F886145DA2158ULL,
		0xFDE13EF1921E2315ULL,
		0xCF8BB5269F206D0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A5B97983BC9E6CDULL,
		0xB8658EBDDEF6ADB5ULL,
		0x8C31C173B292FF06ULL,
		0xB80B9B007086FC63ULL,
		0x027015AD6014CE74ULL,
		0x7C97259BDCBE95A6ULL,
		0x68A10D2A0A23D6E3ULL,
		0x4B43D905EE349600ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6ABEE1D0BB7FADFFULL,
		0xBE0E1A3EC508807BULL,
		0x1AA9EB55A9CE0F49ULL,
		0x2AC69A8597479E72ULL,
		0x72AD1C0678638CD0ULL,
		0xE10862C5691B8BB2ULL,
		0x954031C787FA4C31ULL,
		0x8447DC20B0EBD70EULL
	}};
	sign = 0;
	printf("Test Case 147\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 147 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -147;
	} else {
		printf("Test Case 147 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCF2DF6A32C0E606FULL,
		0x651EA0DB9D9FD668ULL,
		0xA86375B79D9465D7ULL,
		0xE35919ACB91B9D6DULL,
		0x6F44EB0B12B8AB4FULL,
		0xCA7BB4642538872BULL,
		0x6ED03EF45B6E7FD7ULL,
		0x6A53144FC93FBF4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4ECB4606CB0754D0ULL,
		0xC103445087C06BF6ULL,
		0x6275ADAC5FBF5895ULL,
		0x76B6648E9D1F5784ULL,
		0x35DCE0B266EC3201ULL,
		0xE43000C44DBB0633ULL,
		0xF86D610C9B5FE270ULL,
		0xB522110F7493FDB4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8062B09C61070B9FULL,
		0xA41B5C8B15DF6A72ULL,
		0x45EDC80B3DD50D41ULL,
		0x6CA2B51E1BFC45E9ULL,
		0x39680A58ABCC794EULL,
		0xE64BB39FD77D80F8ULL,
		0x7662DDE7C00E9D66ULL,
		0xB531034054ABC196ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 148\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 148 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -148;
	} else {
		printf("Test Case 148 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4A8BDB22FF59AEC8ULL,
		0x8389091306A39180ULL,
		0x27CE52DD6B357E70ULL,
		0x5B5349079E4627DBULL,
		0xDFE639EA1EB87679ULL,
		0xB36310749D52EB62ULL,
		0x906D55302CC3BD8FULL,
		0xF055589635C365D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCD9B290F5A5FD68ULL,
		0x4789ECC23E614226ULL,
		0xE7B25E4CBE697971ULL,
		0xF94D3A71EBDF21F1ULL,
		0xDCE5C9F127829E6EULL,
		0xACC4A0BFD0F06C2BULL,
		0x5816FB8133A1EFF9ULL,
		0x2C46453C61F966D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7DB2289209B3B160ULL,
		0x3BFF1C50C8424F59ULL,
		0x401BF490ACCC04FFULL,
		0x62060E95B26705E9ULL,
		0x03006FF8F735D80AULL,
		0x069E6FB4CC627F37ULL,
		0x385659AEF921CD96ULL,
		0xC40F1359D3C9FEFAULL
	}};
	sign = 0;
	printf("Test Case 149\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 149 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -149;
	} else {
		printf("Test Case 149 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEF5635E7629040F4ULL,
		0x524232431A726F22ULL,
		0x83B733396D0DE1D1ULL,
		0x11C9A5BF9F63FE5FULL,
		0x989164091DF3B6F4ULL,
		0x2DFBBB222B458AC5ULL,
		0xAE5EB331C83D9047ULL,
		0x5D5B839B99C6A723ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F14E9ACBFEFA296ULL,
		0x6FD24300FB7EF360ULL,
		0x29B4BE7E2727C866ULL,
		0x2EB6158262084E4FULL,
		0x69059F73C2D9FD26ULL,
		0x0D706A303D684D7BULL,
		0xBE4485590DFC9A19ULL,
		0x6EEB53F818DDD4F5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x90414C3AA2A09E5EULL,
		0xE26FEF421EF37BC2ULL,
		0x5A0274BB45E6196AULL,
		0xE313903D3D5BB010ULL,
		0x2F8BC4955B19B9CDULL,
		0x208B50F1EDDD3D4AULL,
		0xF01A2DD8BA40F62EULL,
		0xEE702FA380E8D22DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 150\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 150 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -150;
	} else {
		printf("Test Case 150 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x81F78478520559D4ULL,
		0xDD833540DC0A0EA3ULL,
		0x718BC1B6FFB2F1D2ULL,
		0xA9A67B507D202D8FULL,
		0x1BDBA7E6EE8BF545ULL,
		0x262A5CCDE05B3184ULL,
		0x035D589DFC89F34EULL,
		0x92D83AC5BCF12B1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2185A0AFE74D1C35ULL,
		0x10DC6792A6F095BCULL,
		0xB48A994558E11E4DULL,
		0x5D50656C8A1B6EEFULL,
		0x8F2429BD73B115D5ULL,
		0x3D6993A28CE4D26DULL,
		0x2BEB70D87561D60EULL,
		0xBE33E5FBD2A24371ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6071E3C86AB83D9FULL,
		0xCCA6CDAE351978E7ULL,
		0xBD012871A6D1D385ULL,
		0x4C5615E3F304BE9FULL,
		0x8CB77E297ADADF70ULL,
		0xE8C0C92B53765F16ULL,
		0xD771E7C587281D3FULL,
		0xD4A454C9EA4EE7ACULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 151\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 151 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -151;
	} else {
		printf("Test Case 151 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDFF50E63F7C7EE75ULL,
		0x880DBDFDFD1C9E58ULL,
		0x811D4E62CB343C23ULL,
		0x66782C50BBCB48B0ULL,
		0xE984303E002B2611ULL,
		0x86BBB04521A99F20ULL,
		0x805D04FF19403CEAULL,
		0x2A195E9706285911ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E81924F006667B4ULL,
		0x109C2D7FA180AEC4ULL,
		0xE1993DA097A1DB87ULL,
		0x10C9785DDCFDA561ULL,
		0x9DD59BB2F69247D2ULL,
		0x125CB0687315B152ULL,
		0x0DC5E69479086594ULL,
		0x77A890B931A1AC27ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x41737C14F76186C1ULL,
		0x7771907E5B9BEF94ULL,
		0x9F8410C23392609CULL,
		0x55AEB3F2DECDA34EULL,
		0x4BAE948B0998DE3FULL,
		0x745EFFDCAE93EDCEULL,
		0x72971E6AA037D756ULL,
		0xB270CDDDD486ACEAULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 152\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 152 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -152;
	} else {
		printf("Test Case 152 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFC59BD008FB87D97ULL,
		0x9B483426E8DF21F3ULL,
		0x02A382F501D724FCULL,
		0x897E433B4A2A97F2ULL,
		0x1C300D70AEBA45A7ULL,
		0x13406D5C66837C52ULL,
		0xCFB5B39A51191CA3ULL,
		0x027A5F01F2AB265BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB526DCFE43908D2ULL,
		0xC2108B27090FA4E2ULL,
		0x26D32D94270C8CA5ULL,
		0x2ED2506A6990B50FULL,
		0xDBDFA26B5BFDC19DULL,
		0x0F391AC08773D4F5ULL,
		0xCAB51E13761E7611ULL,
		0x79288ED38928B290ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01074F30AB7F74C5ULL,
		0xD937A8FFDFCF7D11ULL,
		0xDBD05560DACA9856ULL,
		0x5AABF2D0E099E2E2ULL,
		0x40506B0552BC840AULL,
		0x0407529BDF0FA75CULL,
		0x05009586DAFAA692ULL,
		0x8951D02E698273CBULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 153\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 153 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -153;
	} else {
		printf("Test Case 153 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8BDF90D768FC506EULL,
		0x4728192692B9C2D2ULL,
		0x48C3D70B58E766A7ULL,
		0x40A6425953280D6AULL,
		0x3F6C4DBFC138970FULL,
		0x4EB69F16532DE9CCULL,
		0xE8135AC385C5CC6AULL,
		0xCA736C590F3083EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95CC0901D9C131F6ULL,
		0x88650936A9429EDEULL,
		0x208D39C414BA8116ULL,
		0x83E0C5CFDB1E65B4ULL,
		0x4491FD2FF5EE9998ULL,
		0x997B713851BBA8A1ULL,
		0xDA2338DD45DD8C37ULL,
		0x73DDB18169689444ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF61387D58F3B1E78ULL,
		0xBEC30FEFE97723F3ULL,
		0x28369D47442CE590ULL,
		0xBCC57C897809A7B6ULL,
		0xFADA508FCB49FD76ULL,
		0xB53B2DDE0172412AULL,
		0x0DF021E63FE84032ULL,
		0x5695BAD7A5C7EFABULL
	}};
	sign = 0;
	printf("Test Case 154\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 154 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -154;
	} else {
		printf("Test Case 154 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6D7D4555B02D6D0BULL,
		0x2F604A60EF974321ULL,
		0xE72943924D515C6AULL,
		0xC2E514F028C5F29BULL,
		0xE0B1E57AC7376420ULL,
		0xC9B49CE3AA36B411ULL,
		0x485C7F172BCC9DF9ULL,
		0x1D1D66CA1D383537ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xECF3E4B4BE47ECA6ULL,
		0x25726F551E602C03ULL,
		0x178ADB5B7F9716C4ULL,
		0x36295160765AF860ULL,
		0xC96C1E97AF0504D9ULL,
		0xA8F076E17C017BD6ULL,
		0x0208F0DB10257AB3ULL,
		0xEF9E35E331CDDC00ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x808960A0F1E58065ULL,
		0x09EDDB0BD137171DULL,
		0xCF9E6836CDBA45A6ULL,
		0x8CBBC38FB26AFA3BULL,
		0x1745C6E318325F47ULL,
		0x20C426022E35383BULL,
		0x46538E3C1BA72346ULL,
		0x2D7F30E6EB6A5937ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 155\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 155 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -155;
	} else {
		printf("Test Case 155 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x29B1103D4EA9C311ULL,
		0x1652CEF79F479CB2ULL,
		0x0D662540A4B2210CULL,
		0x75B20BFD0EC45C86ULL,
		0x0303701CC8319F67ULL,
		0xE2146D857B625876ULL,
		0x504C028ABFE8BE6DULL,
		0xB7078A882BA30E8EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDD7AFCD770CF69CULL,
		0xA5698AA08207A4C4ULL,
		0xB5BB317212C376C7ULL,
		0x6D1F0B5E4777E056ULL,
		0xC01C75E9870C65A6ULL,
		0x45357549D053ADEAULL,
		0xF892D89B1E7B505AULL,
		0x030F46323172AA95ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4BD9606FD79CCC75ULL,
		0x70E944571D3FF7EDULL,
		0x57AAF3CE91EEAA44ULL,
		0x0893009EC74C7C2FULL,
		0x42E6FA33412539C1ULL,
		0x9CDEF83BAB0EAA8BULL,
		0x57B929EFA16D6E13ULL,
		0xB3F84455FA3063F8ULL
	}};
	sign = 0;
	printf("Test Case 156\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 156 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -156;
	} else {
		printf("Test Case 156 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF455EE89C4F3A0F1ULL,
		0xACCC4FD9DE905403ULL,
		0xAD8924A8DBFAA429ULL,
		0x81E7D923F87E65F3ULL,
		0xFAD8C95440C87684ULL,
		0x0D66A7B34792AE63ULL,
		0xCFAFFDB1DAB61466ULL,
		0x20169E7C36148293ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x106CAFB7EDC164D7ULL,
		0xF18FF042111BB7DCULL,
		0xF6F6E08CCC7AF6FAULL,
		0x9006264E0376D3CAULL,
		0x983F9786BBC75EAFULL,
		0x95CD3E93A3FE53D1ULL,
		0x371369340158ABEDULL,
		0x6DB3051CD8129A66ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE3E93ED1D7323C1AULL,
		0xBB3C5F97CD749C27ULL,
		0xB692441C0F7FAD2EULL,
		0xF1E1B2D5F5079228ULL,
		0x629931CD850117D4ULL,
		0x7799691FA3945A92ULL,
		0x989C947DD95D6878ULL,
		0xB263995F5E01E82DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 157\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 157 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -157;
	} else {
		printf("Test Case 157 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF2F32B7F2871C545ULL,
		0xCB161D2D5B0819D2ULL,
		0xFAD02DAA2FAF5424ULL,
		0xF2472F16B5D77704ULL,
		0xD6BCD645598FAAC9ULL,
		0x4CD0210C9DEEF40EULL,
		0xE15A8521FFE655A7ULL,
		0x926A1ECADA7A09CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB86FAF442F4917CDULL,
		0x4C691F459F6FAD43ULL,
		0x6D2DE3EECC3A5A9FULL,
		0xAE0125F80BC3A14DULL,
		0x7D8B4DABB98EF46AULL,
		0x2DAEA8CE0A942105ULL,
		0xA623700EEF279C25ULL,
		0x481506B7476B05D9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3A837C3AF928AD78ULL,
		0x7EACFDE7BB986C8FULL,
		0x8DA249BB6374F985ULL,
		0x4446091EAA13D5B7ULL,
		0x59318899A000B65FULL,
		0x1F21783E935AD309ULL,
		0x3B37151310BEB982ULL,
		0x4A551813930F03F5ULL
	}};
	sign = 0;
	printf("Test Case 158\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 158 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -158;
	} else {
		printf("Test Case 158 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x29E809200CB61F22ULL,
		0xC9597484DEB9A29AULL,
		0x3B2C39FB0F2FC055ULL,
		0x47E753B77975786AULL,
		0x8D4ED5734A55F2F3ULL,
		0xEF4BA2D764FB489EULL,
		0x68968156A7B40B30ULL,
		0x867A94F9C84F75FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CFEBB4A695CDB89ULL,
		0xD3A473D2D194B822ULL,
		0x353B95DDA59EE5CAULL,
		0xE31453CB8D485D73ULL,
		0xDB82CB47EA4F585DULL,
		0x5A4DBA9892769D87ULL,
		0x22C93B69080466CBULL,
		0x0A198C230C716112ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCCE94DD5A3594399ULL,
		0xF5B500B20D24EA77ULL,
		0x05F0A41D6990DA8AULL,
		0x64D2FFEBEC2D1AF7ULL,
		0xB1CC0A2B60069A95ULL,
		0x94FDE83ED284AB16ULL,
		0x45CD45ED9FAFA465ULL,
		0x7C6108D6BBDE14ECULL
	}};
	sign = 0;
	printf("Test Case 159\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 159 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -159;
	} else {
		printf("Test Case 159 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x96C990BB964517A5ULL,
		0xB35FF003F69915A8ULL,
		0x0CE9EDC6EBC5DB0EULL,
		0xE5D2A8E4E010515AULL,
		0x1984FB4736C1595DULL,
		0xAD65C0351587AA96ULL,
		0xA63759CBF08AA59FULL,
		0xCB62184306C2D85FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA43B271552D830A5ULL,
		0x2428DE91872652CCULL,
		0x89A60A6EE00CA4A8ULL,
		0x7DE1FB09FFE98473ULL,
		0x93A961ADAF4535D1ULL,
		0x02F9E6CDCDCCD961ULL,
		0xDCC393855C5D0EEEULL,
		0x04490341521C2F4DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF28E69A6436CE700ULL,
		0x8F3711726F72C2DBULL,
		0x8343E3580BB93666ULL,
		0x67F0ADDAE026CCE6ULL,
		0x85DB9999877C238CULL,
		0xAA6BD96747BAD134ULL,
		0xC973C646942D96B1ULL,
		0xC7191501B4A6A911ULL
	}};
	sign = 0;
	printf("Test Case 160\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 160 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -160;
	} else {
		printf("Test Case 160 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCC444E84E9AD7AFCULL,
		0x9CA903C9B731B0B6ULL,
		0x80AB97B8EFBDCB7EULL,
		0x2A91D14CD5D91380ULL,
		0xE2525C418B660467ULL,
		0x88632C4414D6FBBDULL,
		0xF4A8690BF5B654C7ULL,
		0x897DC156C36D4257ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63B74AFEFE8A9B09ULL,
		0x6D7F9DF75C5C6467ULL,
		0x48E5788A1B158684ULL,
		0xDF7C4EB9286E555EULL,
		0x4310C2A0EBBC8E93ULL,
		0xC51A7B124F92861EULL,
		0x4DB0CFA702574D33ULL,
		0x6ED762814EF94078ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x688D0385EB22DFF3ULL,
		0x2F2965D25AD54C4FULL,
		0x37C61F2ED4A844FAULL,
		0x4B158293AD6ABE22ULL,
		0x9F4199A09FA975D3ULL,
		0xC348B131C544759FULL,
		0xA6F79964F35F0793ULL,
		0x1AA65ED5747401DFULL
	}};
	sign = 0;
	printf("Test Case 161\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 161 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -161;
	} else {
		printf("Test Case 161 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC42BAC8E25FAD010ULL,
		0x1994C0861EC58460ULL,
		0x82A6B33D69F1D855ULL,
		0x737F8A88FB13192AULL,
		0x2BC05B8EE9CDFA98ULL,
		0x02B465BBF3E3B865ULL,
		0x39BB45E3D52892D8ULL,
		0x54FF3AB4FE6C525DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0181A7AB3F01A5CDULL,
		0x604BC62F3E8CDBE6ULL,
		0x5FBA692D5A043B10ULL,
		0xBD042E4CF01B42F7ULL,
		0xD331C2C39A7942B1ULL,
		0xB8C6FA2802B624DDULL,
		0x0ED032CA321DCBA1ULL,
		0x9376691E5A4C9B34ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC2AA04E2E6F92A43ULL,
		0xB948FA56E038A87AULL,
		0x22EC4A100FED9D44ULL,
		0xB67B5C3C0AF7D633ULL,
		0x588E98CB4F54B7E6ULL,
		0x49ED6B93F12D9387ULL,
		0x2AEB1319A30AC736ULL,
		0xC188D196A41FB729ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 162\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 162 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -162;
	} else {
		printf("Test Case 162 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4F2696C63CEF0C93ULL,
		0xFE9664BBCCE8DF56ULL,
		0xA59A4452B8315BB4ULL,
		0x2A1DEB7C0C3F5298ULL,
		0x7284E4DFC1608DD2ULL,
		0xDD731B36CC4FC134ULL,
		0x22FA6D4304A0ACFEULL,
		0x71F09420DD940242ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA359DB42AE3B0FE9ULL,
		0x832B7A2D925A74C0ULL,
		0xCD846B123648B29EULL,
		0xB2E8419C758C8F5BULL,
		0x80B39E2F97899194ULL,
		0x1BC6EA2F021E2F1AULL,
		0xF4CCCABC061DF60FULL,
		0xFD144236A58AC780ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xABCCBB838EB3FCAAULL,
		0x7B6AEA8E3A8E6A95ULL,
		0xD815D94081E8A916ULL,
		0x7735A9DF96B2C33CULL,
		0xF1D146B029D6FC3DULL,
		0xC1AC3107CA319219ULL,
		0x2E2DA286FE82B6EFULL,
		0x74DC51EA38093AC1ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 163\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 163 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -163;
	} else {
		printf("Test Case 163 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x692D138A8E53F863ULL,
		0x03AEAEA842629C92ULL,
		0x6FEBC9398A234F52ULL,
		0x8D3F4509FD26A34DULL,
		0x49E2C942FFC423ACULL,
		0x59DC6E30C39C4211ULL,
		0x6D03D27A8BFC225DULL,
		0xD0A387C1576C6BE4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D8B72450524F351ULL,
		0x698A6C2B017EA7C8ULL,
		0xB2FB2911952D8647ULL,
		0x364B1D411E009726ULL,
		0x410F84406CD12DABULL,
		0x23797AA7D2FDC9B3ULL,
		0x15F6E0A6A8AB0B49ULL,
		0x7EAAD88DBF8ECEACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2BA1A145892F0512ULL,
		0x9A24427D40E3F4CAULL,
		0xBCF0A027F4F5C90AULL,
		0x56F427C8DF260C26ULL,
		0x08D3450292F2F601ULL,
		0x3662F388F09E785EULL,
		0x570CF1D3E3511714ULL,
		0x51F8AF3397DD9D38ULL
	}};
	sign = 0;
	printf("Test Case 164\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 164 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -164;
	} else {
		printf("Test Case 164 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x90CBBEAC6B410AAFULL,
		0xFC9E67E6406027DBULL,
		0xA8F52A2C80736BEEULL,
		0xDFD8BF1B6A414771ULL,
		0x37D88588012334F7ULL,
		0xE51D17472E5DEC20ULL,
		0x8447067B8130397DULL,
		0xAB1BF53E7E72D011ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F75ED1A533E1F2DULL,
		0x0395D9EB30E0FFC1ULL,
		0x3A7DE36D9CA6D707ULL,
		0xA005935C7F7FAB66ULL,
		0xF5D60158F2358EA0ULL,
		0x8BE41FB73ABADA31ULL,
		0xD8FAE966A1E7A757ULL,
		0xC90C7D4EC01CB576ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0155D1921802EB82ULL,
		0xF9088DFB0F7F281AULL,
		0x6E7746BEE3CC94E7ULL,
		0x3FD32BBEEAC19C0BULL,
		0x4202842F0EEDA657ULL,
		0x5938F78FF3A311EEULL,
		0xAB4C1D14DF489226ULL,
		0xE20F77EFBE561A9AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 165\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 165 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -165;
	} else {
		printf("Test Case 165 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x27DFC44F46E16FF9ULL,
		0x2C31177912B8C223ULL,
		0x689C540A86DDD2B1ULL,
		0x4DFBF81BA6AD639EULL,
		0x43D6103156A53B4CULL,
		0xD194F24E89A10724ULL,
		0x4AB7612158115141ULL,
		0xE47F8ACDAED2B1B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DC61B72825F4B3AULL,
		0x39661323B77CCF41ULL,
		0x64909170746E0E11ULL,
		0x2DF4A5FD570B18E0ULL,
		0x0EFBB941198A358BULL,
		0xEC23EBC693AF14AFULL,
		0xD08D99DA3AC5E6DBULL,
		0xA1104018D98EBD43ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBA19A8DCC48224BFULL,
		0xF2CB04555B3BF2E1ULL,
		0x040BC29A126FC49FULL,
		0x2007521E4FA24ABEULL,
		0x34DA56F03D1B05C1ULL,
		0xE5710687F5F1F275ULL,
		0x7A29C7471D4B6A65ULL,
		0x436F4AB4D543F474ULL
	}};
	sign = 0;
	printf("Test Case 166\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 166 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -166;
	} else {
		printf("Test Case 166 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x70A83320609277B1ULL,
		0x155BE37A993251BBULL,
		0x5B2A5E65FF239377ULL,
		0xFA7C5D5187B26739ULL,
		0x50CF2C697FCD97D7ULL,
		0x10A75778C06E1154ULL,
		0x65017478CF9405C2ULL,
		0x6D813B22775B4610ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE73A67DBD91E596ULL,
		0xE7E1C57B827233C9ULL,
		0xCAC425A804F9E932ULL,
		0x62CD5EE15C5FD9F8ULL,
		0xA046EDEA6E487F78ULL,
		0x2D6160DED3002F4CULL,
		0xF16F84822E56D93BULL,
		0x1CC55CC9BD365A93ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA2348CA2A300921BULL,
		0x2D7A1DFF16C01DF1ULL,
		0x906638BDFA29AA44ULL,
		0x97AEFE702B528D40ULL,
		0xB0883E7F1185185FULL,
		0xE345F699ED6DE207ULL,
		0x7391EFF6A13D2C86ULL,
		0x50BBDE58BA24EB7CULL
	}};
	sign = 0;
	printf("Test Case 167\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 167 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -167;
	} else {
		printf("Test Case 167 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x14A71A60CF0350AFULL,
		0xC7335F2F7C54A34EULL,
		0x3C4E3AC8864AEADFULL,
		0xCD226FCD9F30577EULL,
		0xE60635D0EC56AB25ULL,
		0x6D8F03072EBBBCA2ULL,
		0x1A84F92806BC7A78ULL,
		0x47E82016112925F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x859C93FFB26FFC7AULL,
		0x472D0A7E8508DFBAULL,
		0xB5289BD6938B12E6ULL,
		0x323CE1E5B92053C9ULL,
		0xA3301C124F5F8FE4ULL,
		0x888F958970E90743ULL,
		0x7046C0F2256E0B6AULL,
		0x933A7C619ED70A29ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8F0A86611C935435ULL,
		0x800654B0F74BC393ULL,
		0x87259EF1F2BFD7F9ULL,
		0x9AE58DE7E61003B4ULL,
		0x42D619BE9CF71B41ULL,
		0xE4FF6D7DBDD2B55FULL,
		0xAA3E3835E14E6F0DULL,
		0xB4ADA3B472521BCBULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 168\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 168 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -168;
	} else {
		printf("Test Case 168 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1F314A1CCF8D467BULL,
		0x9F21985ACCBE29C2ULL,
		0xDBE97928E3C52BECULL,
		0xF37E01F80AED9B80ULL,
		0xE8B3C1408541A8E9ULL,
		0xB4A6AD433ED168EDULL,
		0xE7AAFF6AEB487C6EULL,
		0xC7E97B092D83B569ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB12DCD9B9AD666A1ULL,
		0x47C1623401A5FD02ULL,
		0xC6E648FF43709EB4ULL,
		0xFF65AA8C3531879EULL,
		0x4C037DB23E6C2C47ULL,
		0xF8479B1A42CB09D8ULL,
		0x0B26E7D9FC5A7983ULL,
		0xAAC68728E575E32BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6E037C8134B6DFDAULL,
		0x57603626CB182CBFULL,
		0x15033029A0548D38ULL,
		0xF418576BD5BC13E2ULL,
		0x9CB0438E46D57CA1ULL,
		0xBC5F1228FC065F15ULL,
		0xDC841790EEEE02EAULL,
		0x1D22F3E0480DD23EULL
	}};
	sign = 0;
	printf("Test Case 169\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 169 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -169;
	} else {
		printf("Test Case 169 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5024B2B170786A14ULL,
		0x8DA589D6C1A7B999ULL,
		0x30D5DA7F281F2488ULL,
		0x52C43688E81647CCULL,
		0x168B5D65747CFE32ULL,
		0x79FDB6C68ABEAEE2ULL,
		0x99610D9E122B4CD9ULL,
		0xD7A54BD5A1D4B0BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6A48957FFB0A953ULL,
		0x3B8295519DB92622ULL,
		0x3AAB565F3413657AULL,
		0xF249A8649FEBEC88ULL,
		0x1AC0A18806521826ULL,
		0x0F619DD123A3EBE4ULL,
		0x34B17D690C4701B7ULL,
		0xD0C228CBF16B3634ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5980295970C7C0C1ULL,
		0x5222F48523EE9376ULL,
		0xF62A841FF40BBF0EULL,
		0x607A8E24482A5B43ULL,
		0xFBCABBDD6E2AE60BULL,
		0x6A9C18F5671AC2FDULL,
		0x64AF903505E44B22ULL,
		0x06E32309B0697A8AULL
	}};
	sign = 0;
	printf("Test Case 170\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 170 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -170;
	} else {
		printf("Test Case 170 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEDD88B94315D1E3FULL,
		0x81A397ACF2DCEC1FULL,
		0xDBED24850F0EBCB8ULL,
		0x57ED90FD98856837ULL,
		0xA4FE4DD89AE9390AULL,
		0x2E03A7F6A10A6931ULL,
		0x4F790E8413CD6A58ULL,
		0x07968985DB229674ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B0090F9D511D078ULL,
		0xBFCDE31CEDFA3AE8ULL,
		0x60D4C94A6506FA34ULL,
		0x6273D914BBCF33DDULL,
		0xE3BC336C49662719ULL,
		0xD490E72F0AD68253ULL,
		0xAD082B8A85191F31ULL,
		0xA8B6A4919EEE0EC3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB2D7FA9A5C4B4DC7ULL,
		0xC1D5B49004E2B137ULL,
		0x7B185B3AAA07C283ULL,
		0xF579B7E8DCB6345AULL,
		0xC1421A6C518311F0ULL,
		0x5972C0C79633E6DDULL,
		0xA270E2F98EB44B26ULL,
		0x5EDFE4F43C3487B0ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 171\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 171 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -171;
	} else {
		printf("Test Case 171 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x03C05EA4AFFF4D13ULL,
		0xB0F2FAB4A97D789DULL,
		0x4AEC2C9E60E9A48EULL,
		0xD2728A9C4C261976ULL,
		0x531B0F65E454F6A7ULL,
		0xDEC84B66EC2C2110ULL,
		0x4963C141F8B4C8A8ULL,
		0xDAEA3CF7B7BF3186ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD831D02AD091028CULL,
		0xE1E274D7EE82D022ULL,
		0xBE59C2D3FF0ED023ULL,
		0x1579E234982C43FEULL,
		0x5645BA1802FD203AULL,
		0xFD05C5176F192014ULL,
		0xA0DEB8D925E61DE6ULL,
		0xDE51801DBC267848ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2B8E8E79DF6E4A87ULL,
		0xCF1085DCBAFAA87AULL,
		0x8C9269CA61DAD46AULL,
		0xBCF8A867B3F9D577ULL,
		0xFCD5554DE157D66DULL,
		0xE1C2864F7D1300FBULL,
		0xA8850868D2CEAAC1ULL,
		0xFC98BCD9FB98B93DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 172\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 172 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -172;
	} else {
		printf("Test Case 172 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x99137825809FB232ULL,
		0xF8065B73ABD9A5A3ULL,
		0x800AC9FA14A987CBULL,
		0x7AC48BCF79208F1BULL,
		0x0CB4DBCC47E6B09AULL,
		0x85455FFFD0BBC705ULL,
		0x2CFE87D7FBF385E7ULL,
		0xDAFEB5DBFA0CB4A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34BB791CAE675C4CULL,
		0xF2C9CAD0DBD8B852ULL,
		0x2DD28D3A684B944CULL,
		0x0C55E6B6C2A918E8ULL,
		0xC6F6A3DCC8A05707ULL,
		0x4E91674921FE392BULL,
		0xE8D8B7EA3E0314DCULL,
		0x365407BCD2A95A46ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6457FF08D23855E6ULL,
		0x053C90A2D000ED51ULL,
		0x52383CBFAC5DF37FULL,
		0x6E6EA518B6777633ULL,
		0x45BE37EF7F465993ULL,
		0x36B3F8B6AEBD8DD9ULL,
		0x4425CFEDBDF0710BULL,
		0xA4AAAE1F27635A5DULL
	}};
	sign = 0;
	printf("Test Case 173\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 173 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -173;
	} else {
		printf("Test Case 173 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x46F6E15A082DA54BULL,
		0x69633BD1A4EE6879ULL,
		0x77EEEA3CD38FDADAULL,
		0x7E8B2CE5BCCED644ULL,
		0xC53B6D75E108A628ULL,
		0xA5013FC4E6877D15ULL,
		0xA4BD4AEF324186A0ULL,
		0xE09AEE819F26FFA3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC23BE62A96E5E704ULL,
		0xBB660E348F154F5BULL,
		0x31C51EB8D16EDDDFULL,
		0x4FDB084CD2836A47ULL,
		0x1CDBA3973D7C7624ULL,
		0xB55997F05F4C2746ULL,
		0x2617E23C2E72B8E7ULL,
		0x94907BD1CDDEA977ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x84BAFB2F7147BE47ULL,
		0xADFD2D9D15D9191DULL,
		0x4629CB840220FCFAULL,
		0x2EB02498EA4B6BFDULL,
		0xA85FC9DEA38C3004ULL,
		0xEFA7A7D4873B55CFULL,
		0x7EA568B303CECDB8ULL,
		0x4C0A72AFD148562CULL
	}};
	sign = 0;
	printf("Test Case 174\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 174 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -174;
	} else {
		printf("Test Case 174 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1C6023CB0F0BE196ULL,
		0xD65ABA2947F45941ULL,
		0x35BCBE4F2563A044ULL,
		0x4059DD9E964DDD85ULL,
		0x59C23460E15CFFA3ULL,
		0x2B2A0927C16D57F0ULL,
		0x7B397D3B8AB9B7DAULL,
		0xA4BCB665A25CE3B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4E764BE074A4733ULL,
		0xD9233FF0D9BCCFBBULL,
		0x9EB24E469DBBA2BAULL,
		0x15E19D0969580EEBULL,
		0x9370538A8B93CC5FULL,
		0xCC79776F342E8AE1ULL,
		0x6FF19B36B7A5C372ULL,
		0x6F8719BF892BE34DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4778BF0D07C19A63ULL,
		0xFD377A386E378985ULL,
		0x970A700887A7FD89ULL,
		0x2A7840952CF5CE99ULL,
		0xC651E0D655C93344ULL,
		0x5EB091B88D3ECD0EULL,
		0x0B47E204D313F467ULL,
		0x35359CA61931006BULL
	}};
	sign = 0;
	printf("Test Case 175\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 175 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -175;
	} else {
		printf("Test Case 175 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x28F2018B23A4E11FULL,
		0x0021F16BE6D2CC66ULL,
		0x2B4A7D733DF41CEAULL,
		0xC3D5EDD3D5ADF3FCULL,
		0xB284D1AC6D19DAAAULL,
		0xB6D57EEE8CF5AD18ULL,
		0xDD7FC66B592793BAULL,
		0x5C271D5A3E9D30F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28BACC342D85412FULL,
		0x8379E92805E7417FULL,
		0xFCAE43FF199310D1ULL,
		0x7D798FEDA6CCF25AULL,
		0xD3A47571CDC24947ULL,
		0x07D7238CFF0EC063ULL,
		0x4139DE660CB54B7BULL,
		0xBBC18E76186F0125ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00373556F61F9FF0ULL,
		0x7CA80843E0EB8AE7ULL,
		0x2E9C397424610C18ULL,
		0x465C5DE62EE101A1ULL,
		0xDEE05C3A9F579163ULL,
		0xAEFE5B618DE6ECB4ULL,
		0x9C45E8054C72483FULL,
		0xA0658EE4262E2FD0ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 176\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 176 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -176;
	} else {
		printf("Test Case 176 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE8B3885E149409AAULL,
		0xEECC564BC6A35261ULL,
		0x61F99DC577666CF0ULL,
		0x0FBE558673E053E9ULL,
		0x16320C5284426FDEULL,
		0x5A9EEC978C8F21A3ULL,
		0x1BC2114533310F3AULL,
		0x12A20A5EFE35D145ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53C11AFAB46F08B5ULL,
		0x7B0BA313459400ADULL,
		0xF74378AD441E3CBFULL,
		0x070E9F685FD7910EULL,
		0xB8B1F1A40F228701ULL,
		0xFA7E078275BA49CDULL,
		0xB91886E2250D5849ULL,
		0x772361E855DA8257ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x94F26D63602500F5ULL,
		0x73C0B338810F51B4ULL,
		0x6AB6251833483031ULL,
		0x08AFB61E1408C2DAULL,
		0x5D801AAE751FE8DDULL,
		0x6020E51516D4D7D5ULL,
		0x62A98A630E23B6F0ULL,
		0x9B7EA876A85B4EEDULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 177\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 177 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -177;
	} else {
		printf("Test Case 177 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x45D52F1E147BC034ULL,
		0x4069A7B3143E7F52ULL,
		0xA427B076EFCAAB4BULL,
		0xC663C3A76432E0BDULL,
		0xD868D4952C98A07CULL,
		0x2574695238BB93BAULL,
		0x5667FE2B540CBCA7ULL,
		0xD24D75FF63EAC71CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x145322329C5EBA29ULL,
		0xC8DC860DBF56305CULL,
		0x9C0DB84E4F92DA45ULL,
		0xBDCAF0FDAE70829DULL,
		0x7F12C23A975C52F1ULL,
		0x0C9932485EFAAEBDULL,
		0x28DFA52E790124BAULL,
		0x4DFA3866A154D92DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x31820CEB781D060BULL,
		0x778D21A554E84EF6ULL,
		0x0819F828A037D105ULL,
		0x0898D2A9B5C25E20ULL,
		0x5956125A953C4D8BULL,
		0x18DB3709D9C0E4FDULL,
		0x2D8858FCDB0B97EDULL,
		0x84533D98C295EDEFULL
	}};
	sign = 0;
	printf("Test Case 178\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 178 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -178;
	} else {
		printf("Test Case 178 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBA5F700CEB5F842CULL,
		0x823CFC3C0BB71645ULL,
		0x9E44B74A30044F95ULL,
		0x832F1C9802BC7769ULL,
		0x7CF30D4EF069E065ULL,
		0xDAA12EB65EB18A20ULL,
		0xD9D249A15F841426ULL,
		0x1604B257B0504B9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C2753AE3B3F6712ULL,
		0x2BB1443227550DBBULL,
		0xD64A6A7672D5E5A4ULL,
		0x83C0A96F77977D82ULL,
		0x9CBF1DA870771302ULL,
		0xB0A8D878A4F062E0ULL,
		0xD0AB3ACFD28F3289ULL,
		0x14D62763D25ADF4DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7E381C5EB0201D1AULL,
		0x568BB809E462088AULL,
		0xC7FA4CD3BD2E69F1ULL,
		0xFF6E73288B24F9E6ULL,
		0xE033EFA67FF2CD62ULL,
		0x29F8563DB9C1273FULL,
		0x09270ED18CF4E19DULL,
		0x012E8AF3DDF56C4EULL
	}};
	sign = 0;
	printf("Test Case 179\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 179 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -179;
	} else {
		printf("Test Case 179 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFEA3E562F2150FA6ULL,
		0x994C279A2F119340ULL,
		0x7C270DD8D1135FE6ULL,
		0x510919A302DAABBCULL,
		0x53B0F4368D08CC90ULL,
		0x00E671E679DC44F0ULL,
		0x4CC78D7F54C7C783ULL,
		0x0E501D049B3DED88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x756DD00832E3FBDAULL,
		0x56AD9E7644CA18E7ULL,
		0xB3410C8FF4AD2319ULL,
		0x650DA9C24F8B7074ULL,
		0x69D7B83AB0D15819ULL,
		0x1D913E1ED6EB4237ULL,
		0x1861AF0AD4357075ULL,
		0x9C8E66EA640FFC2AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8936155ABF3113CCULL,
		0x429E8923EA477A59ULL,
		0xC8E60148DC663CCDULL,
		0xEBFB6FE0B34F3B47ULL,
		0xE9D93BFBDC377476ULL,
		0xE35533C7A2F102B8ULL,
		0x3465DE748092570DULL,
		0x71C1B61A372DF15EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 180\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 180 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -180;
	} else {
		printf("Test Case 180 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2304D6DC7650C8C8ULL,
		0x32008EE90073E161ULL,
		0xE2C5F2583EFA46C0ULL,
		0x227CA19820864C9BULL,
		0x9E4C3DD00A578560ULL,
		0x28578E65BF0EF9E7ULL,
		0xF99AA2B1D726C21EULL,
		0x4E4FAC943CF5E823ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85D7B9FE3333C0CEULL,
		0xE13533A46300B5D6ULL,
		0x3BF25D5CC8621D3FULL,
		0x074FC5ABDD24E94FULL,
		0x5268583AB1EF9EC4ULL,
		0x11239F33B5DC41C6ULL,
		0x688EB89CDC22A266ULL,
		0x3DC1484DF0C45192ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9D2D1CDE431D07FAULL,
		0x50CB5B449D732B8AULL,
		0xA6D394FB76982980ULL,
		0x1B2CDBEC4361634CULL,
		0x4BE3E5955867E69CULL,
		0x1733EF320932B821ULL,
		0x910BEA14FB041FB8ULL,
		0x108E64464C319691ULL
	}};
	sign = 0;
	printf("Test Case 181\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 181 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -181;
	} else {
		printf("Test Case 181 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF52E2960D3975C79ULL,
		0xE6B05C39DA8D7F41ULL,
		0x80D81EFB48D8CC0DULL,
		0xA5161B8E92561FA5ULL,
		0x529AE28879DAA2D8ULL,
		0x092B6FAD189685E1ULL,
		0x08086ABAD77087BAULL,
		0x307E70BFDA634354ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC41B951FC2CCA548ULL,
		0x0AE947CED4B71721ULL,
		0xB85E3AC88722DE9CULL,
		0xADCE45AB6A71BF19ULL,
		0x4096D44B4A10CF98ULL,
		0xBE94E275299A1CA2ULL,
		0xCD2212B80F2FCE6AULL,
		0x1AF6969C2AAE1FF4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3112944110CAB731ULL,
		0xDBC7146B05D66820ULL,
		0xC879E432C1B5ED71ULL,
		0xF747D5E327E4608BULL,
		0x12040E3D2FC9D33FULL,
		0x4A968D37EEFC693FULL,
		0x3AE65802C840B94FULL,
		0x1587DA23AFB5235FULL
	}};
	sign = 0;
	printf("Test Case 182\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 182 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -182;
	} else {
		printf("Test Case 182 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB44404F400581C16ULL,
		0x80ABD75A1B7E657BULL,
		0xD83086C210761F53ULL,
		0xF25DE8BBB40EA373ULL,
		0x179244B460E9905AULL,
		0xBC80A041636E535BULL,
		0xDFF2F6284A2400CAULL,
		0xA5D11CBC3E111EA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B465B062954FA88ULL,
		0x8A7AAABD9F0A4A70ULL,
		0x4740CB9DFD00D5B2ULL,
		0x45F9E9EC563F7EDAULL,
		0x38F004673EA95263ULL,
		0x4D4C41B52F4B43CBULL,
		0xE76001EEEB4C061FULL,
		0x161B30DC9E06844CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x28FDA9EDD703218EULL,
		0xF6312C9C7C741B0BULL,
		0x90EFBB24137549A0ULL,
		0xAC63FECF5DCF2499ULL,
		0xDEA2404D22403DF7ULL,
		0x6F345E8C34230F8FULL,
		0xF892F4395ED7FAABULL,
		0x8FB5EBDFA00A9A59ULL
	}};
	sign = 0;
	printf("Test Case 183\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 183 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -183;
	} else {
		printf("Test Case 183 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4F8AD79EA0373176ULL,
		0xB42BB103641367AFULL,
		0x276DDE882EB0A780ULL,
		0xF2FC06500592257CULL,
		0xF3A5CC7EBE1995B5ULL,
		0xCA5841609B0EF5D6ULL,
		0xDF36E163948ADF98ULL,
		0x19C4B078ABB50FC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2FA401EEFE711CAULL,
		0xB72704571EC0E02FULL,
		0x098EE51B14AFAF69ULL,
		0xDF6A8DFD18E4E6DEULL,
		0x4D3BFEE7F2C82070ULL,
		0x28ACEE3A4515CDA7ULL,
		0x7E186DA332CDCD47ULL,
		0x706030634375BA3CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8C90977FB0501FACULL,
		0xFD04ACAC4552877FULL,
		0x1DDEF96D1A00F816ULL,
		0x13917852ECAD3E9EULL,
		0xA669CD96CB517545ULL,
		0xA1AB532655F9282FULL,
		0x611E73C061BD1251ULL,
		0xA9648015683F558BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 184\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 184 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -184;
	} else {
		printf("Test Case 184 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC42156DC26F157BBULL,
		0x46D1A509BB0D2AADULL,
		0x599A6F6E90324557ULL,
		0x647EACB9F55C2210ULL,
		0x7ABA8890FDC04410ULL,
		0x8F8006AD74D2A02CULL,
		0x09167460DAABEF89ULL,
		0xCAE1C13576F93B77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADAF968B4891A603ULL,
		0x08DEF2438B42D0C6ULL,
		0xFA07A952351E2437ULL,
		0x0C7C91C57115F1C4ULL,
		0x8FA1494F7457B33AULL,
		0x7DC26FFDF9FF7F6CULL,
		0xDB30C3C90A7FD2EEULL,
		0x819DE60BDD7AAB59ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1671C050DE5FB1B8ULL,
		0x3DF2B2C62FCA59E7ULL,
		0x5F92C61C5B142120ULL,
		0x58021AF48446304BULL,
		0xEB193F41896890D6ULL,
		0x11BD96AF7AD320BFULL,
		0x2DE5B097D02C1C9BULL,
		0x4943DB29997E901DULL
	}};
	sign = 0;
	printf("Test Case 185\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 185 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -185;
	} else {
		printf("Test Case 185 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA2A78D1ECBE4BD21ULL,
		0x9F3F05786E8F6286ULL,
		0x7B671129F9AFE493ULL,
		0x8F6121F8A643572AULL,
		0xCEEACD5E19FE561BULL,
		0x2E793B54446021E5ULL,
		0x28434F4519244BCEULL,
		0x7AE5BABDA2A9C4D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A341739F55BC0CFULL,
		0xE6F65EB66F878368ULL,
		0x6E3929CA2BD6AE8CULL,
		0x5910224764E61780ULL,
		0x6171195C69EBCD33ULL,
		0x607BF09BCC80B21EULL,
		0x9C2165FEACB63E7FULL,
		0x8101FF9382285479ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x487375E4D688FC52ULL,
		0xB848A6C1FF07DF1EULL,
		0x0D2DE75FCDD93606ULL,
		0x3650FFB1415D3FAAULL,
		0x6D79B401B01288E8ULL,
		0xCDFD4AB877DF6FC7ULL,
		0x8C21E9466C6E0D4EULL,
		0xF9E3BB2A20817059ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 186\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 186 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -186;
	} else {
		printf("Test Case 186 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2FFE9CCEE18D717FULL,
		0x7E5AD9B37874C2CAULL,
		0xDCED5108EBD58FF3ULL,
		0xF35F5D801FE964D3ULL,
		0x1969C196AE47D234ULL,
		0x0AEAADBF40451CFAULL,
		0x393DCEEEEC8113D6ULL,
		0x7A18D10A8F3556A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8EF6575E290E6BE9ULL,
		0x21FA3EB310AC6043ULL,
		0x7FA1D7ADB3397AF9ULL,
		0xABB5A58E0D1872D0ULL,
		0x317FF54F0AD41082ULL,
		0x6F67D296E3DEC80DULL,
		0x6112B2D6B51065C6ULL,
		0x680D7A025D544FD9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA1084570B87F0596ULL,
		0x5C609B0067C86286ULL,
		0x5D4B795B389C14FAULL,
		0x47A9B7F212D0F203ULL,
		0xE7E9CC47A373C1B2ULL,
		0x9B82DB285C6654ECULL,
		0xD82B1C183770AE0FULL,
		0x120B570831E106CDULL
	}};
	sign = 0;
	printf("Test Case 187\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 187 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -187;
	} else {
		printf("Test Case 187 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA2858EF4BE242E9EULL,
		0x371C429971A04872ULL,
		0x494E58E7DC1A421CULL,
		0x373C7321E0F34129ULL,
		0xDE7B5791DCB70762ULL,
		0x8B7C8872A674E686ULL,
		0x6145E8F2FABD525DULL,
		0x6053E44659AE62C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB9E1886D92C7874ULL,
		0x76CC3D7F38810A6EULL,
		0x699FC2656BDA845DULL,
		0xAACC8D085CCEBEC0ULL,
		0xE54820B8C587133EULL,
		0x136EB83A93FCB832ULL,
		0xE9A7A99C1DAADDC3ULL,
		0xA8434F3DEDA119AAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA6E7766DE4F7B62AULL,
		0xC050051A391F3E03ULL,
		0xDFAE9682703FBDBEULL,
		0x8C6FE61984248268ULL,
		0xF93336D9172FF423ULL,
		0x780DD03812782E53ULL,
		0x779E3F56DD12749AULL,
		0xB81095086C0D491AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 188\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 188 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -188;
	} else {
		printf("Test Case 188 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4174FB8BAF83D8FEULL,
		0xEC0D0CAB6C0894DDULL,
		0xDB438EDB708E652BULL,
		0x77D3A721643FC370ULL,
		0x89F9CD7BEF3F9EDBULL,
		0x6DDD549AE5C5B9FFULL,
		0xE0534B6BECB5FB8BULL,
		0x9C8B7B88F3CE4398ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x422EDDBF0291C209ULL,
		0xB7B7FBD8117C7529ULL,
		0x3D919685E896B0D0ULL,
		0x553DF2CDBB9F56CFULL,
		0x249DDBC480775C28ULL,
		0x1AC34B459A369049ULL,
		0x763A57EF57C2E0B4ULL,
		0xE3BAB3D0B0C686B6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFF461DCCACF216F5ULL,
		0x345510D35A8C1FB3ULL,
		0x9DB1F85587F7B45BULL,
		0x2295B453A8A06CA1ULL,
		0x655BF1B76EC842B3ULL,
		0x531A09554B8F29B6ULL,
		0x6A18F37C94F31AD7ULL,
		0xB8D0C7B84307BCE2ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 189\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 189 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -189;
	} else {
		printf("Test Case 189 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCF73F7259EBAB4E8ULL,
		0xF0195CF0CA2E767BULL,
		0x3B7DD442DA317B1AULL,
		0x8A3E8CD135DA0DFDULL,
		0x1C6639EF56EB6FA1ULL,
		0x653339FF1948E873ULL,
		0x0718D6F12154152EULL,
		0xF6156BBB9A07BB5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9577742BAB4E8BF6ULL,
		0x8F25F069ED067122ULL,
		0x7B80049044622939ULL,
		0x2BD5D696A872F475ULL,
		0x46E9F3DF7E513B23ULL,
		0x2A35E8D1A980CC00ULL,
		0x61D0F87A2102D836ULL,
		0xBCF9AC6CBEB2F433ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x39FC82F9F36C28F2ULL,
		0x60F36C86DD280559ULL,
		0xBFFDCFB295CF51E1ULL,
		0x5E68B63A8D671987ULL,
		0xD57C460FD89A347EULL,
		0x3AFD512D6FC81C72ULL,
		0xA547DE7700513CF8ULL,
		0x391BBF4EDB54C729ULL
	}};
	sign = 0;
	printf("Test Case 190\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 190 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -190;
	} else {
		printf("Test Case 190 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x880EE485FCD6645FULL,
		0x598ED6ABD4AEFFC6ULL,
		0x4E37AA31D58DE460ULL,
		0xC71C0202B09A30EBULL,
		0xCB206F235E4E5088ULL,
		0xFDC227B83543AB33ULL,
		0xA3F7B354448E0499ULL,
		0xD7DC453B4B940B4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA263945353C9F876ULL,
		0x281306241635F8C0ULL,
		0x310CD3238700B27BULL,
		0x285C7E4545B467F3ULL,
		0x2DA4C243A976DD7DULL,
		0xC18356A09DB64369ULL,
		0x91584EC0CC26536CULL,
		0x3D22A8A161DD1D49ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE5AB5032A90C6BE9ULL,
		0x317BD087BE790705ULL,
		0x1D2AD70E4E8D31E5ULL,
		0x9EBF83BD6AE5C8F8ULL,
		0x9D7BACDFB4D7730BULL,
		0x3C3ED117978D67CAULL,
		0x129F64937867B12DULL,
		0x9AB99C99E9B6EE04ULL
	}};
	sign = 0;
	printf("Test Case 191\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 191 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -191;
	} else {
		printf("Test Case 191 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x59F6A9DD48719AAAULL,
		0xBDFC7E88926A2776ULL,
		0xD42E5EDFC2B905D1ULL,
		0x60FA3D2E538ADE23ULL,
		0x35A6FB471BB2E860ULL,
		0xD14195F634148541ULL,
		0xEFD608442404EEC8ULL,
		0x27C6E9D1753776CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24B54847181DE752ULL,
		0x1EC56AA68736BC79ULL,
		0x653902780B24B7D5ULL,
		0x651D1846354E3F51ULL,
		0x5837BF900ED8351CULL,
		0x8FC7E1DAA92AFB0EULL,
		0x808A0DE22ADBCB2CULL,
		0x966ECE095783A896ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x354161963053B358ULL,
		0x9F3713E20B336AFDULL,
		0x6EF55C67B7944DFCULL,
		0xFBDD24E81E3C9ED2ULL,
		0xDD6F3BB70CDAB343ULL,
		0x4179B41B8AE98A32ULL,
		0x6F4BFA61F929239CULL,
		0x91581BC81DB3CE37ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 192\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 192 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -192;
	} else {
		printf("Test Case 192 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8B1205D8D9B975F2ULL,
		0x632E45BC041EF193ULL,
		0x7206344CD3381697ULL,
		0x582942EC9CD26ADBULL,
		0x3BA6E8B041A46EE9ULL,
		0x10EF59B82918AB50ULL,
		0xA91F94CC2C061342ULL,
		0xBA12E0A358DEDEE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE59970776076E9B2ULL,
		0x433236095D63B691ULL,
		0xAF90675FEA85C47FULL,
		0x6FAF3D6E83F57ADCULL,
		0xEC976F8F5C6AA783ULL,
		0xE1E52628E33E73C7ULL,
		0x607638DFEA982F0FULL,
		0x0D462F5492EFAEADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA578956179428C40ULL,
		0x1FFC0FB2A6BB3B01ULL,
		0xC275CCECE8B25218ULL,
		0xE87A057E18DCEFFEULL,
		0x4F0F7920E539C765ULL,
		0x2F0A338F45DA3788ULL,
		0x48A95BEC416DE432ULL,
		0xACCCB14EC5EF3033ULL
	}};
	sign = 0;
	printf("Test Case 193\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 193 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -193;
	} else {
		printf("Test Case 193 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0AC5E58D012255A5ULL,
		0x0D268ADEE48C3A8FULL,
		0xA25197B987A3FAB4ULL,
		0x2ABA2A9C87DED3C6ULL,
		0xC5F59A172497604FULL,
		0xCA8AEE7ADC3777C0ULL,
		0xB2006D6B9D638C41ULL,
		0x7BB9D232F50A7534ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x477FB8A20FFE10BEULL,
		0x4110E06077F2D86FULL,
		0x55FD889CBB004BB3ULL,
		0xF89A76EB4D437610ULL,
		0x6B494518335304D0ULL,
		0xE7A5BC640381D735ULL,
		0x2D0C22A72ED61E1FULL,
		0xD09A92DD6EC41892ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC3462CEAF12444E7ULL,
		0xCC15AA7E6C99621FULL,
		0x4C540F1CCCA3AF00ULL,
		0x321FB3B13A9B5DB6ULL,
		0x5AAC54FEF1445B7EULL,
		0xE2E53216D8B5A08BULL,
		0x84F44AC46E8D6E21ULL,
		0xAB1F3F5586465CA2ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 194\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 194 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -194;
	} else {
		printf("Test Case 194 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD78D6485820FB65BULL,
		0xB2F34F08F422B5D5ULL,
		0xBEBEA9E2CF3ED9EFULL,
		0xEF92602A9C4D4D7CULL,
		0x38A399015A34E75BULL,
		0x72AC0A20DF04D757ULL,
		0x2A9F91B620D398DEULL,
		0x8B284743367A339CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E035D4754D3AD8CULL,
		0xD824E174EEB492C7ULL,
		0x1302E605EE14BB3DULL,
		0x4AC8C0A6F75DBA08ULL,
		0xF210AE6C8FFEE43BULL,
		0xD4D089525DEA6DACULL,
		0x546397B518DD7F0EULL,
		0x68A4A16EF3A331E0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x398A073E2D3C08CFULL,
		0xDACE6D94056E230EULL,
		0xABBBC3DCE12A1EB1ULL,
		0xA4C99F83A4EF9374ULL,
		0x4692EA94CA360320ULL,
		0x9DDB80CE811A69AAULL,
		0xD63BFA0107F619CFULL,
		0x2283A5D442D701BBULL
	}};
	sign = 0;
	printf("Test Case 195\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 195 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -195;
	} else {
		printf("Test Case 195 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5014420DEC0ECF7BULL,
		0x71E7697D282F2314ULL,
		0x84749B76BD8CCFDFULL,
		0xA33F945568623C60ULL,
		0xF532F0E3EA2A1304ULL,
		0xCDA5F29F20A41F80ULL,
		0xA5A8B2B287C8F4AAULL,
		0x0D0311283864B037ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB127B28656EEA37DULL,
		0x51A28611665CDA88ULL,
		0xF51DDAB06B018CA0ULL,
		0xC8CB7B69D4772515ULL,
		0x90FF281E8C7FCB91ULL,
		0x1B0D53C49A5B6545ULL,
		0xE02E49ABF14E7D63ULL,
		0xE50437524E656497ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9EEC8F8795202BFEULL,
		0x2044E36BC1D2488BULL,
		0x8F56C0C6528B433FULL,
		0xDA7418EB93EB174AULL,
		0x6433C8C55DAA4772ULL,
		0xB2989EDA8648BA3BULL,
		0xC57A6906967A7747ULL,
		0x27FED9D5E9FF4B9FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 196\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 196 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -196;
	} else {
		printf("Test Case 196 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x16AB02800B90CF00ULL,
		0xC30BD9589326F016ULL,
		0x939E6AE3D9572D52ULL,
		0x00281FB89EC3D59AULL,
		0x4DFF3165C12F6512ULL,
		0x70358E13F6013F59ULL,
		0x4515DCB499F965DAULL,
		0xF4065F263DAF4C81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC397A5570A37A706ULL,
		0x63B0289C83B6300EULL,
		0x8A1E8D35AC9BCB2FULL,
		0xCCD7DF7023F90F81ULL,
		0x07B8744D727AA320ULL,
		0xEC442274F52EF0EFULL,
		0x1D292210AF838595ULL,
		0xDACAE5DB959DEBC4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x53135D29015927FAULL,
		0x5F5BB0BC0F70C007ULL,
		0x097FDDAE2CBB6223ULL,
		0x335040487ACAC619ULL,
		0x4646BD184EB4C1F1ULL,
		0x83F16B9F00D24E6AULL,
		0x27ECBAA3EA75E044ULL,
		0x193B794AA81160BDULL
	}};
	sign = 0;
	printf("Test Case 197\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 197 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -197;
	} else {
		printf("Test Case 197 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x02BB94B52FAFE4BFULL,
		0x4612B337FE643F1FULL,
		0x80330B68EF3B43AEULL,
		0xCBE544A0B7B8C321ULL,
		0x188AF3E75B71BC1FULL,
		0x30B8EAC86211EA76ULL,
		0xB94A79C418663D77ULL,
		0xF4EFEB3C67B950AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x606076AD29263A6DULL,
		0x5271699B6C03DC1CULL,
		0x0C9D6140DF9A02C9ULL,
		0x09CC977EEB5A9C1FULL,
		0xDCF7EE656F268459ULL,
		0xFFD598F6BFD40761ULL,
		0x0270C3D6F0F29FBCULL,
		0xCE916726C143ADB2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA25B1E080689AA52ULL,
		0xF3A1499C92606302ULL,
		0x7395AA280FA140E4ULL,
		0xC218AD21CC5E2702ULL,
		0x3B930581EC4B37C6ULL,
		0x30E351D1A23DE314ULL,
		0xB6D9B5ED27739DBAULL,
		0x265E8415A675A2F8ULL
	}};
	sign = 0;
	printf("Test Case 198\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 198 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -198;
	} else {
		printf("Test Case 198 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x12A14F68B1273405ULL,
		0x63AADDDDA6951CA3ULL,
		0x80FF7F69F7EF01E0ULL,
		0xB3CA2E8B9A53766CULL,
		0x45425E3678053C1FULL,
		0xB23D4996AAD2610DULL,
		0x6DE7B2103ACFB3E6ULL,
		0x4EC1D06176706DD8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35A48BABDE4DD9C7ULL,
		0xDB760AD9BBDF4B3AULL,
		0xF8B9B69F8302FC82ULL,
		0xA8E69C4C35F46B93ULL,
		0xD9D328F5713A96DCULL,
		0xF777CEAEEF0C82A4ULL,
		0xDADF7390E1BF4F55ULL,
		0x69C5AD93374E31F9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDCFCC3BCD2D95A3EULL,
		0x8834D303EAB5D168ULL,
		0x8845C8CA74EC055DULL,
		0x0AE3923F645F0AD8ULL,
		0x6B6F354106CAA543ULL,
		0xBAC57AE7BBC5DE68ULL,
		0x93083E7F59106490ULL,
		0xE4FC22CE3F223BDEULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 199\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 199 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -199;
	} else {
		printf("Test Case 199 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5C41FBCCE8C550D1ULL,
		0x993E33033EA0A1DDULL,
		0x31A9FDFC85E7A38AULL,
		0x8251919B4CA8965DULL,
		0x70897E025614DDAFULL,
		0x97AAA5D68A30631EULL,
		0xDD28D9C148F0646CULL,
		0x4484E385B4180021ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D4A5A7B69BAEEABULL,
		0x95D4ADE592B546B7ULL,
		0xF75347890FE1B7DDULL,
		0x38B4BB00D6E0F377ULL,
		0x8FCB1BC1C673958FULL,
		0x522C8A399CBF0ADBULL,
		0x6DA63327F102E608ULL,
		0xD86C107A04A67472ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDEF7A1517F0A6226ULL,
		0x0369851DABEB5B25ULL,
		0x3A56B6737605EBADULL,
		0x499CD69A75C7A2E5ULL,
		0xE0BE62408FA14820ULL,
		0x457E1B9CED715842ULL,
		0x6F82A69957ED7E64ULL,
		0x6C18D30BAF718BAFULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 200\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 200 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -200;
	} else {
		printf("Test Case 200 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF69771F1E557D512ULL,
		0x645FE7E0BC690BE2ULL,
		0x62F2A0DA2794AF09ULL,
		0x6906C0CB3AAAAC48ULL,
		0x030EC8EA60D07C00ULL,
		0xA36F5286CCDDA278ULL,
		0x1A2F3857AF7FDC2AULL,
		0x7B0F2494F5672F5FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7026880E30D0BA43ULL,
		0x556B908FE2DC83E1ULL,
		0x0057941E0738A695ULL,
		0xF3A9FB07857BD8DFULL,
		0xC60EB1682349E7A6ULL,
		0xF215A17BA36B5A6DULL,
		0x5D190B7561635FCEULL,
		0x9D63F1861BAF407FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8670E9E3B4871ACFULL,
		0x0EF45750D98C8801ULL,
		0x629B0CBC205C0874ULL,
		0x755CC5C3B52ED369ULL,
		0x3D0017823D869459ULL,
		0xB159B10B2972480AULL,
		0xBD162CE24E1C7C5BULL,
		0xDDAB330ED9B7EEDFULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 201\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 201 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -201;
	} else {
		printf("Test Case 201 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4C168020F82A34EBULL,
		0x4ABE7B948164AC51ULL,
		0x938CEAF5FFD0A474ULL,
		0xA09E3CC04B2DA75AULL,
		0xEEA6BEED440CECF9ULL,
		0x07A68BE6DED67E93ULL,
		0x5A195C3614192B9EULL,
		0xF5F5A3976E6F6D40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x866C474B9696F306ULL,
		0x6323FC57FFC1FDC1ULL,
		0x008A27399BDDE09EULL,
		0xC3426C5899ACC749ULL,
		0x0ED714E366578FF8ULL,
		0xDB231DA4BFB2C208ULL,
		0xA2AA926D23648FDBULL,
		0x26F5C8E365004FC2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC5AA38D5619341E5ULL,
		0xE79A7F3C81A2AE8FULL,
		0x9302C3BC63F2C3D5ULL,
		0xDD5BD067B180E011ULL,
		0xDFCFAA09DDB55D00ULL,
		0x2C836E421F23BC8BULL,
		0xB76EC9C8F0B49BC2ULL,
		0xCEFFDAB4096F1D7DULL
	}};
	sign = 0;
	printf("Test Case 202\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 202 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -202;
	} else {
		printf("Test Case 202 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x57C042A1E13FD3C9ULL,
		0xD3C88973C2F43262ULL,
		0xB7B7C418C700EEE7ULL,
		0x3075C74CF6C24534ULL,
		0x81D653083CCD51FCULL,
		0xE020EBA95AF8BAD7ULL,
		0xDB2621C699CDFA47ULL,
		0x7C0D3A2625640682ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF800E2F2DDD8D390ULL,
		0x710A20DB17A4F9C5ULL,
		0x2B11DFD789F523DBULL,
		0xF97359E56BBF8C21ULL,
		0x90CAEDB9C19A2A1AULL,
		0x4AF4ABEE998A2B42ULL,
		0xA1C9B1B405329AF3ULL,
		0x60FC359FC9DF1C34ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5FBF5FAF03670039ULL,
		0x62BE6898AB4F389CULL,
		0x8CA5E4413D0BCB0CULL,
		0x37026D678B02B913ULL,
		0xF10B654E7B3327E1ULL,
		0x952C3FBAC16E8F94ULL,
		0x395C7012949B5F54ULL,
		0x1B1104865B84EA4EULL
	}};
	sign = 0;
	printf("Test Case 203\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 203 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -203;
	} else {
		printf("Test Case 203 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x04CF957B9BF3470CULL,
		0x7DBAC2620160FF04ULL,
		0xB69A458364D031A2ULL,
		0x57D6E55ACDD27B74ULL,
		0x340329DB670E3C1AULL,
		0xA74CE17073C58042ULL,
		0x15B9CA87926DC39AULL,
		0xB35D34F966C4741BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC68E347BFB7F1BFULL,
		0x4F752772E6F459CDULL,
		0x7FDCA43EA957162AULL,
		0xB369A963FE563CB6ULL,
		0x613E05BCF2A6D584ULL,
		0x68CD21DCD4996FCCULL,
		0x73ED87322425BBB1ULL,
		0x392586A64CBA6784ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1866B233DC3B554DULL,
		0x2E459AEF1A6CA536ULL,
		0x36BDA144BB791B78ULL,
		0xA46D3BF6CF7C3EBEULL,
		0xD2C5241E74676695ULL,
		0x3E7FBF939F2C1075ULL,
		0xA1CC43556E4807E9ULL,
		0x7A37AE531A0A0C96ULL
	}};
	sign = 0;
	printf("Test Case 204\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 204 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -204;
	} else {
		printf("Test Case 204 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE25E5FF67D649CF3ULL,
		0x6D3969EB61877B7BULL,
		0xD0635757C67C3AADULL,
		0xB0747FE34E70CCC2ULL,
		0x2E8B212432074E3FULL,
		0x57E26B4314229F1EULL,
		0x67C0518875A42627ULL,
		0xA815F7CE684F06C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA7DB60991DCECFAULL,
		0xDC7FD647609552B9ULL,
		0x5F5B965E0BFA42FAULL,
		0x266BD8CE7D563E0BULL,
		0xB4D85B8886FCD0E3ULL,
		0xF958138C9F881A0AULL,
		0xBCA6CDC1265B0724ULL,
		0xB0C1353CE519980EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x37E0A9ECEB87AFF9ULL,
		0x90B993A400F228C2ULL,
		0x7107C0F9BA81F7B2ULL,
		0x8A08A714D11A8EB7ULL,
		0x79B2C59BAB0A7D5CULL,
		0x5E8A57B6749A8513ULL,
		0xAB1983C74F491F02ULL,
		0xF754C29183356EB4ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 205\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 205 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -205;
	} else {
		printf("Test Case 205 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1B95824AE0C043E9ULL,
		0x74786B2E1522028FULL,
		0xD5480B4861BCDB8DULL,
		0xEEB29C533FE52546ULL,
		0x19765BBA3ED0452BULL,
		0x03927CD3DC64C062ULL,
		0xABB247EC79A018BCULL,
		0x058988F0E1743324ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x121D0F68CBA4BC58ULL,
		0xAA518A8A354D84D0ULL,
		0x1923BA51D0962D3EULL,
		0x2CB262FC4314E9AAULL,
		0xDEBCCFF48F0C3994ULL,
		0xD20517E828BF5FD1ULL,
		0x98C67D63C455C784ULL,
		0xA747D3F72C70FEA9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x097872E2151B8791ULL,
		0xCA26E0A3DFD47DBFULL,
		0xBC2450F69126AE4EULL,
		0xC2003956FCD03B9CULL,
		0x3AB98BC5AFC40B97ULL,
		0x318D64EBB3A56090ULL,
		0x12EBCA88B54A5137ULL,
		0x5E41B4F9B503347BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 206\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 206 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -206;
	} else {
		printf("Test Case 206 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAB003CDEB6CB9F6DULL,
		0xDF830E920606690CULL,
		0x28DE2C407AB22712ULL,
		0x97D883DEE2969298ULL,
		0x298BCBE8C7A078F6ULL,
		0x4DFEDF94E69EC886ULL,
		0x8D26BAD4DFD6241CULL,
		0xCE28F5D8023BC5BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x199405CFF1C0E1D8ULL,
		0x386384D058CA43F0ULL,
		0x35D463ECB1DDB44DULL,
		0xD9FCFEF40D298D2DULL,
		0x182B16C113A7EF73ULL,
		0xBD4301BA3001E53BULL,
		0xC41EDA6D1CA61AC2ULL,
		0xCAD3E22367F36DE7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x916C370EC50ABD95ULL,
		0xA71F89C1AD3C251CULL,
		0xF309C853C8D472C5ULL,
		0xBDDB84EAD56D056AULL,
		0x1160B527B3F88982ULL,
		0x90BBDDDAB69CE34BULL,
		0xC907E067C3300959ULL,
		0x035513B49A4857D3ULL
	}};
	sign = 0;
	printf("Test Case 207\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 207 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -207;
	} else {
		printf("Test Case 207 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x51A7F2952B66DCAEULL,
		0x1678AE4CE53B3E49ULL,
		0x74C031F1AC3D5E93ULL,
		0xB91DF90DE5EA0DD9ULL,
		0xBE5FD25380B33976ULL,
		0x1208D0EBA233B436ULL,
		0x54E2F0DF0C505F87ULL,
		0x41435BAA58C7B7BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41BBC50E7245F76FULL,
		0x0F9A1C5C49AE0EA1ULL,
		0x8D2448E0BDE292F3ULL,
		0x190A3693AB05673EULL,
		0x33C014B6D117E3C5ULL,
		0x28CDF9DDB8741746ULL,
		0x87D9C17DD1EA70EEULL,
		0x673AB64EBEBA3485ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0FEC2D86B920E53FULL,
		0x06DE91F09B8D2FA8ULL,
		0xE79BE910EE5ACBA0ULL,
		0xA013C27A3AE4A69AULL,
		0x8A9FBD9CAF9B55B1ULL,
		0xE93AD70DE9BF9CF0ULL,
		0xCD092F613A65EE98ULL,
		0xDA08A55B9A0D8334ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 208\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 208 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -208;
	} else {
		printf("Test Case 208 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x48DBE4D0F026DEE9ULL,
		0x2E718C0E2F8ACE2FULL,
		0x3DA6E23CD14BE68EULL,
		0x8BFBFF6D71F7334EULL,
		0xAB382074CE920C03ULL,
		0xF3C33FE1D440DA4DULL,
		0xCE7E2E3A8C31BB38ULL,
		0xF7AD0B506A034DD9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A4BB3785EA3766DULL,
		0x18E913D2F10BFA1AULL,
		0x985B31EB8CCDADEDULL,
		0x00F98AD399445528ULL,
		0xA2BD439436D1DD1DULL,
		0x773C2C96293FCA5EULL,
		0x8F2E75C107A9C5AEULL,
		0x8B7A9C0E367C806CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E9031589183687CULL,
		0x1588783B3E7ED415ULL,
		0xA54BB051447E38A1ULL,
		0x8B027499D8B2DE25ULL,
		0x087ADCE097C02EE6ULL,
		0x7C87134BAB010FEFULL,
		0x3F4FB8798487F58AULL,
		0x6C326F423386CD6DULL
	}};
	sign = 0;
	printf("Test Case 209\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 209 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -209;
	} else {
		printf("Test Case 209 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x894969213D5B95E3ULL,
		0xA40B239D3AF09B7BULL,
		0x20F088DE5F9984C6ULL,
		0xCAD2A74130DFB20EULL,
		0x343A1EBAD4E214BFULL,
		0x72B937DA375222ABULL,
		0x1BE157D782D8F705ULL,
		0x4A74BB9C7CA78CE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC3799A9E67FB91AULL,
		0x7CE1A6D624DDA93FULL,
		0x29DD3C346084750DULL,
		0x0616476E27A57DD2ULL,
		0x27E674C6DC644176ULL,
		0x69BEB307B7BFA37BULL,
		0x49727BA8A4B36533ULL,
		0x494A8BE63133BC79ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8D11CF7756DBDCC9ULL,
		0x27297CC71612F23BULL,
		0xF7134CA9FF150FB9ULL,
		0xC4BC5FD3093A343BULL,
		0x0C53A9F3F87DD349ULL,
		0x08FA84D27F927F30ULL,
		0xD26EDC2EDE2591D2ULL,
		0x012A2FB64B73D06EULL
	}};
	sign = 0;
	printf("Test Case 210\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 210 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -210;
	} else {
		printf("Test Case 210 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x75E6BCDC32325BEFULL,
		0x2B3F6E22CDE04581ULL,
		0xD148008818E47088ULL,
		0xA344E69E505732F9ULL,
		0x1E987CA46DA58A10ULL,
		0xE803C3E2CD2095CEULL,
		0xCFF1B5191F5FE68EULL,
		0xC99DE9F4CE55F082ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x864834CEEF4716A1ULL,
		0xC521DD2CEA4982CEULL,
		0x3E3CCF96A2D8B001ULL,
		0xE80D503AF913892AULL,
		0x96E0A6F0F9F6F723ULL,
		0x44B4DBA43198308CULL,
		0x06A88E80C3E6ADDBULL,
		0x2791EBFF8A01B436ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEF9E880D42EB454EULL,
		0x661D90F5E396C2B2ULL,
		0x930B30F1760BC086ULL,
		0xBB3796635743A9CFULL,
		0x87B7D5B373AE92ECULL,
		0xA34EE83E9B886541ULL,
		0xC94926985B7938B3ULL,
		0xA20BFDF544543C4CULL
	}};
	sign = 0;
	printf("Test Case 211\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 211 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -211;
	} else {
		printf("Test Case 211 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3DBE581F1BEF6507ULL,
		0xD0DBA812229F864AULL,
		0x1877A9CFCB1240F7ULL,
		0xCA600A7F863866A2ULL,
		0x265CEF6B396029D0ULL,
		0x12A6C25AF57FA774ULL,
		0xA69BE5C21D744B3BULL,
		0x06CA2B7B9E849D1AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB52A20709C41C87ULL,
		0x87CB195AA14DA6E3ULL,
		0xD40700AAB84A62EBULL,
		0xA10277040495A6C7ULL,
		0x85BF153A2ABB1903ULL,
		0x1E25CA345EEE28EEULL,
		0xEF38778D470A6DB0ULL,
		0xD42EDFE7F3B25FE5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x626BB618122B4880ULL,
		0x49108EB78151DF66ULL,
		0x4470A92512C7DE0CULL,
		0x295D937B81A2BFDAULL,
		0xA09DDA310EA510CDULL,
		0xF480F82696917E85ULL,
		0xB7636E34D669DD8AULL,
		0x329B4B93AAD23D34ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 212\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 212 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -212;
	} else {
		printf("Test Case 212 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x94B7D188FB641CF9ULL,
		0x14CDB405C5F92A50ULL,
		0x2E4D5C4DF6BC46D4ULL,
		0x7A9254031C0EE331ULL,
		0x8777BBAF19746FDBULL,
		0x38B40626F8C1F7EEULL,
		0x45F4268DE8B5472BULL,
		0x94805042233D96F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9948083FC7A39C9ULL,
		0x8A5DC1C18F4A7E02ULL,
		0x3B0ED21801996816ULL,
		0x8F980381B5C891F5ULL,
		0x25BE41264CB32200ULL,
		0x819C5EB583711360ULL,
		0xB77294D028CC8A5DULL,
		0xBA3AA1FF23D6F8F2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBB235104FEE9E330ULL,
		0x8A6FF24436AEAC4DULL,
		0xF33E8A35F522DEBDULL,
		0xEAFA50816646513BULL,
		0x61B97A88CCC14DDAULL,
		0xB717A7717550E48EULL,
		0x8E8191BDBFE8BCCDULL,
		0xDA45AE42FF669E00ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 213\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 213 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -213;
	} else {
		printf("Test Case 213 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5BCA1007F6591A73ULL,
		0x6190318B1BF68DC9ULL,
		0xBAA071CC6FBC9BC0ULL,
		0xF690811857EACCE7ULL,
		0x4F4B07459F870BBAULL,
		0x70333747540B30ACULL,
		0x62A480D9CF3E9FB7ULL,
		0xBEDA167A327F8FC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD832775ED9B15EC2ULL,
		0x707A69EF6BFC0077ULL,
		0x6D301730F2ED983EULL,
		0x031D40DFA141FEFFULL,
		0x97712B39F2A224ACULL,
		0x8A1639EAB0CAEF3CULL,
		0xF6FECB056BDAA3F5ULL,
		0x06C6394F93EF7895ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x839798A91CA7BBB1ULL,
		0xF115C79BAFFA8D51ULL,
		0x4D705A9B7CCF0381ULL,
		0xF3734038B6A8CDE8ULL,
		0xB7D9DC0BACE4E70EULL,
		0xE61CFD5CA340416FULL,
		0x6BA5B5D46363FBC1ULL,
		0xB813DD2A9E901733ULL
	}};
	sign = 0;
	printf("Test Case 214\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 214 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -214;
	} else {
		printf("Test Case 214 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4954BF32F27BAE1EULL,
		0x36EF62D966730ABCULL,
		0xCC4F77729CB7A1F3ULL,
		0x944B426C8BB6307CULL,
		0x2667E0986A47926DULL,
		0x1B4C1A1C861EB17EULL,
		0x85F7AE0A6970FAC7ULL,
		0x2EEB31158421D902ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x650F4987EAF0F45FULL,
		0x181165ED28B66F1CULL,
		0x9684E31EEC645EC5ULL,
		0x3604C54DC5DBD401ULL,
		0x0B7F0CB4ABF1BB0BULL,
		0x07503DB1680262E3ULL,
		0xFD2550851F0A2668ULL,
		0xFF4C11A4E3CC5A29ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE44575AB078AB9BFULL,
		0x1EDDFCEC3DBC9B9FULL,
		0x35CA9453B053432EULL,
		0x5E467D1EC5DA5C7BULL,
		0x1AE8D3E3BE55D762ULL,
		0x13FBDC6B1E1C4E9BULL,
		0x88D25D854A66D45FULL,
		0x2F9F1F70A0557ED8ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 215\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 215 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -215;
	} else {
		printf("Test Case 215 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xADF13418FE16D4E0ULL,
		0xC98603B13AC00105ULL,
		0x69A682E955084D9FULL,
		0x3620DFDA5C4595A7ULL,
		0xBEB120FF9BD4B0B9ULL,
		0xEF36BDBB8DA3E0F1ULL,
		0xE3B4F8FE8E18ACA5ULL,
		0x62F29F7A0317201DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F4D232524E3DF88ULL,
		0xFE4C675CBEE6894FULL,
		0x090DE0C7DB887843ULL,
		0x6C419E6BA9835CD1ULL,
		0x7D68F90F98FF7106ULL,
		0x8E0C3BF8B8866843ULL,
		0x259FC54AD6BE3165ULL,
		0xFA7A68DFAC61D7DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7EA410F3D932F558ULL,
		0xCB399C547BD977B6ULL,
		0x6098A221797FD55BULL,
		0xC9DF416EB2C238D6ULL,
		0x414827F002D53FB2ULL,
		0x612A81C2D51D78AEULL,
		0xBE1533B3B75A7B40ULL,
		0x6878369A56B54842ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 216\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 216 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -216;
	} else {
		printf("Test Case 216 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2E4F96D1A7A60CF3ULL,
		0x4E298C327CAEA5C3ULL,
		0x90514FAC72986C8CULL,
		0xB0E4580FBC5C37A3ULL,
		0xEAC38B5B4D54E1A6ULL,
		0x869CEA5ABE741AD3ULL,
		0x07591471DBE2E361ULL,
		0x5B27B6997474279DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42E4A2BB63D7725EULL,
		0x78EFEFC775B1E9F4ULL,
		0x07C51217613AA711ULL,
		0x887E8A92191F30C5ULL,
		0x2E766F16C1092DA3ULL,
		0xE1940A3DE494E074ULL,
		0x41E7BE06C9A6011DULL,
		0xFDA96267D2285721ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEB6AF41643CE9A95ULL,
		0xD5399C6B06FCBBCEULL,
		0x888C3D95115DC57AULL,
		0x2865CD7DA33D06DEULL,
		0xBC4D1C448C4BB403ULL,
		0xA508E01CD9DF3A5FULL,
		0xC571566B123CE243ULL,
		0x5D7E5431A24BD07BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 217\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 217 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -217;
	} else {
		printf("Test Case 217 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF4872B9A20755BF3ULL,
		0xCCB1C25175AE8ED5ULL,
		0xC15AD0C25C7EEB00ULL,
		0x9BE97B831FE848D1ULL,
		0xFB15FC2A568599D7ULL,
		0xF94C9EEAA1DE5579ULL,
		0x3ACCCB0D08479D7FULL,
		0xB6D0848273BCBA85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x325E14836B8B49E7ULL,
		0xB5F16F88703A1D8FULL,
		0xF8C4121168E8F54DULL,
		0x509F181F8758F0CEULL,
		0xDCC4E9C3F74683FBULL,
		0x6CB1ACD13380655CULL,
		0xB62EED0AE93EC0BAULL,
		0x2CFF7437235FA2BFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC2291716B4EA120CULL,
		0x16C052C905747146ULL,
		0xC896BEB0F395F5B3ULL,
		0x4B4A6363988F5802ULL,
		0x1E5112665F3F15DCULL,
		0x8C9AF2196E5DF01DULL,
		0x849DDE021F08DCC5ULL,
		0x89D1104B505D17C5ULL
	}};
	sign = 0;
	printf("Test Case 218\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 218 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -218;
	} else {
		printf("Test Case 218 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1FC8A7AB7BBD376DULL,
		0x7B03D6D454A9E833ULL,
		0x2A048E9BEC7B713FULL,
		0x66510A6E171DFF99ULL,
		0xD7C557AE373C2D1DULL,
		0x3563DDCDD6378813ULL,
		0x711290FA2AFA2711ULL,
		0xC1AB2435C7145447ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04EBD1FB602BC249ULL,
		0x3C6C191DA2D459DAULL,
		0x17FB617C975CF906ULL,
		0xBEADDA8EBD9AAE89ULL,
		0x597620BFB05BA0ADULL,
		0x7440F4DC697A0804ULL,
		0x2DB14B6A9FE6B160ULL,
		0xF7462A814FF95B58ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1ADCD5B01B917524ULL,
		0x3E97BDB6B1D58E59ULL,
		0x12092D1F551E7839ULL,
		0xA7A32FDF59835110ULL,
		0x7E4F36EE86E08C6FULL,
		0xC122E8F16CBD800FULL,
		0x4361458F8B1375B0ULL,
		0xCA64F9B4771AF8EFULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 219\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 219 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -219;
	} else {
		printf("Test Case 219 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x24BCDFABB0152A92ULL,
		0x24A5D85B664D467EULL,
		0x8D479F91D50E9CC1ULL,
		0x4F799E6C9A397127ULL,
		0xE4EE36F3CEE901F4ULL,
		0x01D8C19D43DA3988ULL,
		0x74C94FC84AF05820ULL,
		0xE06A57B6C592121FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA350ECD9EB7763EULL,
		0x8336992572708B45ULL,
		0x7850FF7C390EFD16ULL,
		0x837BA2FD3914A0D6ULL,
		0x6FDF1E176B238A47ULL,
		0xD00676DEE73F448FULL,
		0x14946B537B16FCE2ULL,
		0x62D1FE217ACCC88AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2A87D0DE115DB454ULL,
		0xA16F3F35F3DCBB38ULL,
		0x14F6A0159BFF9FAAULL,
		0xCBFDFB6F6124D051ULL,
		0x750F18DC63C577ACULL,
		0x31D24ABE5C9AF4F9ULL,
		0x6034E474CFD95B3DULL,
		0x7D9859954AC54995ULL
	}};
	sign = 0;
	printf("Test Case 220\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 220 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -220;
	} else {
		printf("Test Case 220 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x24DFF11BF2073B07ULL,
		0x2A2EDF4AC295FD37ULL,
		0xE0D10F800911EE74ULL,
		0xDD2F1DDEB15DBF0EULL,
		0x6435A1C285672688ULL,
		0x1DD3ED6434C502F2ULL,
		0xE2E64E14E0998E68ULL,
		0x94164104E34FCD77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7E7FCABDF895A09ULL,
		0xFBDCAED0A0434981ULL,
		0x35668959FB1CC857ULL,
		0x31ADAA93FBDC58B5ULL,
		0x68F9A18277CA022CULL,
		0x2090A36CC5351592ULL,
		0xAF9E920D7D5B98EBULL,
		0xE149E2C0C721081BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3CF7F470127DE0FEULL,
		0x2E52307A2252B3B5ULL,
		0xAB6A86260DF5261CULL,
		0xAB81734AB5816659ULL,
		0xFB3C00400D9D245CULL,
		0xFD4349F76F8FED5FULL,
		0x3347BC07633DF57CULL,
		0xB2CC5E441C2EC55CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 221\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 221 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -221;
	} else {
		printf("Test Case 221 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x682B8B3CA0ECD9E9ULL,
		0xB3B565197C8AD053ULL,
		0x57DD3EC69E5A28F5ULL,
		0xB72559617F73ABB3ULL,
		0xB3E4319A4C765C1EULL,
		0xB40273B4A1C656F0ULL,
		0xC8697C6B586E66F0ULL,
		0x332478119CD45B9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55A12C848613F11BULL,
		0x7C13D7B46A0D3EACULL,
		0x36EBA08060D43402ULL,
		0xAF79F0A5D092136CULL,
		0x46024FCAF0E2BE79ULL,
		0xE3204A252204E1DDULL,
		0x95DE0EB9FEA28ECDULL,
		0x21A76230AAD83848ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x128A5EB81AD8E8CEULL,
		0x37A18D65127D91A7ULL,
		0x20F19E463D85F4F3ULL,
		0x07AB68BBAEE19847ULL,
		0x6DE1E1CF5B939DA5ULL,
		0xD0E2298F7FC17513ULL,
		0x328B6DB159CBD822ULL,
		0x117D15E0F1FC2354ULL
	}};
	sign = 0;
	printf("Test Case 222\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 222 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -222;
	} else {
		printf("Test Case 222 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCFBAF36B0E633EADULL,
		0x1D9D055123F0E9CEULL,
		0xAD510B4F368A49C6ULL,
		0xC7D5AC5F36141680ULL,
		0x8F9D3A8897199943ULL,
		0x511D575D19BB291CULL,
		0x0109B173B991491DULL,
		0xF74D7E08C9ED1F94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2790039247E4DE87ULL,
		0x23633AEA520B698BULL,
		0x599D9491E98B0FC6ULL,
		0x1CAB0F27F7E9C1EBULL,
		0xD62781A140E07411ULL,
		0xFEE9FB43EBB5D307ULL,
		0x0E11CEFA253185E4ULL,
		0xEB0C10E9C0E1ADD4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA82AEFD8C67E6026ULL,
		0xFA39CA66D1E58043ULL,
		0x53B376BD4CFF39FFULL,
		0xAB2A9D373E2A5495ULL,
		0xB975B8E756392532ULL,
		0x52335C192E055614ULL,
		0xF2F7E279945FC338ULL,
		0x0C416D1F090B71BFULL
	}};
	sign = 0;
	printf("Test Case 223\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 223 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -223;
	} else {
		printf("Test Case 223 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE0983D94231348CEULL,
		0xDA45653DAF3E3B50ULL,
		0x705DCFAEF4A3ADCEULL,
		0xB46040E48E0EE7EEULL,
		0xDC7ABA5F26B7E565ULL,
		0xBBC5FC1723E9B8FBULL,
		0x2956F8873E3F23C0ULL,
		0x8708DD0EFBDAFDF5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA63F11597F67BAAULL,
		0xF6AF1E19A38238A2ULL,
		0xBEF6E10A0F1471A0ULL,
		0x0643E759DAB8932DULL,
		0xE876915DCB7B95FBULL,
		0xE607BD0E7D71844CULL,
		0x209ABE56D18068D7ULL,
		0x565343E6E05B6122ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE6344C7E8B1CCD24ULL,
		0xE39647240BBC02ADULL,
		0xB166EEA4E58F3C2DULL,
		0xAE1C598AB35654C0ULL,
		0xF40429015B3C4F6AULL,
		0xD5BE3F08A67834AEULL,
		0x08BC3A306CBEBAE8ULL,
		0x30B599281B7F9CD3ULL
	}};
	sign = 0;
	printf("Test Case 224\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 224 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -224;
	} else {
		printf("Test Case 224 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6145FBB428199AFBULL,
		0x198EA1C68DBD0F87ULL,
		0xC75F320FF8BA8851ULL,
		0xC7A235108BA6BB77ULL,
		0x621E3158C253C6DFULL,
		0x78C1ECD6F9ACD436ULL,
		0xB07AD1B4DD596984ULL,
		0x4C11E5C6532F79F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85C4D538E54F377AULL,
		0xCC8AAC1FFA6F75FCULL,
		0x66AF80B586BC2236ULL,
		0x65F7D685B7656112ULL,
		0x4B0EC4A64C844832ULL,
		0x6F3446C44A910D47ULL,
		0x80BBE527CE104EBFULL,
		0x22756C395B2B017EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDB81267B42CA6381ULL,
		0x4D03F5A6934D998AULL,
		0x60AFB15A71FE661AULL,
		0x61AA5E8AD4415A65ULL,
		0x170F6CB275CF7EADULL,
		0x098DA612AF1BC6EFULL,
		0x2FBEEC8D0F491AC5ULL,
		0x299C798CF8047876ULL
	}};
	sign = 0;
	printf("Test Case 225\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 225 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -225;
	} else {
		printf("Test Case 225 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1FB329857CD4D6CAULL,
		0xB6286C45982559C7ULL,
		0x0440F97E5FEF4DEEULL,
		0xA5A25BA2CAFCBA43ULL,
		0x5130EC24923CE878ULL,
		0x729D163417DC2AB0ULL,
		0x40854F6C337017AAULL,
		0x08CD367AAE330F8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB33BA903A1DFAA46ULL,
		0xE38D93FF77331CE3ULL,
		0x5A281FBB8351DEEEULL,
		0x384C6684D037AC56ULL,
		0x0BE2468E5E692614ULL,
		0x4D871B278580AAF0ULL,
		0xE45D71DE90F5CE18ULL,
		0xED937E600F289DAFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6C778081DAF52C84ULL,
		0xD29AD84620F23CE3ULL,
		0xAA18D9C2DC9D6EFFULL,
		0x6D55F51DFAC50DECULL,
		0x454EA59633D3C264ULL,
		0x2515FB0C925B7FC0ULL,
		0x5C27DD8DA27A4992ULL,
		0x1B39B81A9F0A71DAULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 226\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 226 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -226;
	} else {
		printf("Test Case 226 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5F74051AE99CC67DULL,
		0xBD9DE96D9D721021ULL,
		0x2DAAAA74E160DDD0ULL,
		0xB713150B1B09B335ULL,
		0xFA5FF16358B23249ULL,
		0x43CFA1C1A9B5DD63ULL,
		0xF9EF89C8CD8CC4D7ULL,
		0x50A6084E4EFBEA97ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF413FA16208514FULL,
		0x5C134C10B097B7A9ULL,
		0xB4F27D3D0577373DULL,
		0x2B0EF4F223C00A3DULL,
		0xFAD372FAAD6B9099ULL,
		0xFC7D85192FC00EEEULL,
		0xDD030F4C0DE0F8E2ULL,
		0xCDE48C68F2D6725EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB032C5798794752EULL,
		0x618A9D5CECDA5877ULL,
		0x78B82D37DBE9A693ULL,
		0x8C042018F749A8F7ULL,
		0xFF8C7E68AB46A1B0ULL,
		0x47521CA879F5CE74ULL,
		0x1CEC7A7CBFABCBF4ULL,
		0x82C17BE55C257839ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 227\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 227 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -227;
	} else {
		printf("Test Case 227 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x03E1E8240AF9DE78ULL,
		0x863C380CD5E2B0B0ULL,
		0x80FFC3DBB3E07C09ULL,
		0xB8859C98B407F4E8ULL,
		0x66A637D4A67A0389ULL,
		0x793F1ED47F00B522ULL,
		0x4D4A79C4461E8C84ULL,
		0xE1951212D5D4E8A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB13F0C6544AA14CULL,
		0xACA99AAFA572EA14ULL,
		0x5EF9583F4F93D55CULL,
		0x1F2972000DF73953ULL,
		0x4D44A2B4B284817CULL,
		0x086209953AD84D86ULL,
		0xB72703B32965F677ULL,
		0xB6BB4BB103223C1DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x28CDF75DB6AF3D2CULL,
		0xD9929D5D306FC69BULL,
		0x22066B9C644CA6ACULL,
		0x995C2A98A610BB95ULL,
		0x1961951FF3F5820DULL,
		0x70DD153F4428679CULL,
		0x962376111CB8960DULL,
		0x2AD9C661D2B2AC87ULL
	}};
	sign = 0;
	printf("Test Case 228\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 228 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -228;
	} else {
		printf("Test Case 228 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA218E679EEFEF169ULL,
		0x5542C324420D38E5ULL,
		0x16248F04733C8E0EULL,
		0xEEB501933FCA9A30ULL,
		0x04DFA459F9CDCC1FULL,
		0xD59389459030E901ULL,
		0x94BE419760AB2ECCULL,
		0x074CB122CCB6D3B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD172869F19144404ULL,
		0x0FFF52F0CF5112CAULL,
		0xD543376A0F8142FDULL,
		0xDCDB9F4BC9683819ULL,
		0x457B8920A6D4351CULL,
		0x7F456FC00BB5C465ULL,
		0xA7D759092ABB95B3ULL,
		0xF08B990CC4BFA24BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD0A65FDAD5EAAD65ULL,
		0x4543703372BC261AULL,
		0x40E1579A63BB4B11ULL,
		0x11D9624776626216ULL,
		0xBF641B3952F99703ULL,
		0x564E1985847B249BULL,
		0xECE6E88E35EF9919ULL,
		0x16C1181607F7316CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 229\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 229 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -229;
	} else {
		printf("Test Case 229 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5C0900B18EC32765ULL,
		0xFBA5A90341130A23ULL,
		0xD4F1979A4A0C79E7ULL,
		0x18F940AD90661D9AULL,
		0x3954F71A2FFAADF3ULL,
		0x57872AABA8376E5AULL,
		0xF500322164149CD9ULL,
		0xA6D7C8F4AAB09D25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6B6EE37EEEC4651ULL,
		0x2E3526A2E263D075ULL,
		0xBC99F859C840168BULL,
		0x4FFA47EF4535A0D1ULL,
		0x73BF477415142FFBULL,
		0x6FE3FB3DC968BE26ULL,
		0xEBF2575D81499B01ULL,
		0xE61C7F9746E6A900ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x955212799FD6E114ULL,
		0xCD7082605EAF39ADULL,
		0x18579F4081CC635CULL,
		0xC8FEF8BE4B307CC9ULL,
		0xC595AFA61AE67DF7ULL,
		0xE7A32F6DDECEB033ULL,
		0x090DDAC3E2CB01D7ULL,
		0xC0BB495D63C9F425ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 230\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 230 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -230;
	} else {
		printf("Test Case 230 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA3E27C3A48A755B0ULL,
		0x37380C5F2438195FULL,
		0x765E8F3F9135B0FAULL,
		0xA7A78820B545E7A1ULL,
		0x04B0E3B43C9A1872ULL,
		0xF3A6D63029BFD7DEULL,
		0x4A23911B45DB466BULL,
		0x8565C1E889FEF01DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D89CB1E4A1D97EDULL,
		0x52248A4E78C625EFULL,
		0x558F6FB76E19A22BULL,
		0xBA9C2F0692FC02BEULL,
		0xCD6AA6453BD58E3CULL,
		0xCB92AA72C6CCA8C3ULL,
		0x13EA1B3E581F973CULL,
		0x218AB367E7C8B859ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9658B11BFE89BDC3ULL,
		0xE5138210AB71F370ULL,
		0x20CF1F88231C0ECEULL,
		0xED0B591A2249E4E3ULL,
		0x37463D6F00C48A35ULL,
		0x28142BBD62F32F1AULL,
		0x363975DCEDBBAF2FULL,
		0x63DB0E80A23637C4ULL
	}};
	sign = 0;
	printf("Test Case 231\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 231 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -231;
	} else {
		printf("Test Case 231 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C7444383B603348ULL,
		0x2A8AA063E59B0E09ULL,
		0xC230625C33A63D19ULL,
		0x5E4E617A48031E4EULL,
		0x28D92C0BFC8246DBULL,
		0x8A9F231C97385FE1ULL,
		0x076A6F0A4EC02C8EULL,
		0x857CB3D4575DAB47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x839889CE33B00254ULL,
		0x6B5F55830185B6F1ULL,
		0xAB941F1B6C8F3105ULL,
		0x88F2A1AFC8A754CEULL,
		0xCFD53B183FFA4759ULL,
		0xF81A4F5F3CF7E400ULL,
		0x60BF109B8AC0932DULL,
		0xC2578E4CD5240A71ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x08DBBA6A07B030F4ULL,
		0xBF2B4AE0E4155718ULL,
		0x169C4340C7170C13ULL,
		0xD55BBFCA7F5BC980ULL,
		0x5903F0F3BC87FF81ULL,
		0x9284D3BD5A407BE0ULL,
		0xA6AB5E6EC3FF9960ULL,
		0xC32525878239A0D5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 232\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 232 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -232;
	} else {
		printf("Test Case 232 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1DB79F7847BF635CULL,
		0xD59181EAFCB92AE8ULL,
		0x8F8203AD77759C50ULL,
		0x543F9E8C0B2ABFBFULL,
		0xA071543EC915DE4FULL,
		0xA4AC6922670260E3ULL,
		0x89D654F1B42AC8E4ULL,
		0x56EA113780361166ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x176F29479D52B36AULL,
		0x6CE7259670F9B009ULL,
		0x40F6CD95E9E71C4FULL,
		0x4F4C4F0402D2D8F6ULL,
		0xFD548910C1FF638CULL,
		0x40CFBEC8A08FA5D1ULL,
		0x9BCDEC010E09C285ULL,
		0x364E7A6108CEB2DAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x06487630AA6CAFF2ULL,
		0x68AA5C548BBF7ADFULL,
		0x4E8B36178D8E8001ULL,
		0x04F34F880857E6C9ULL,
		0xA31CCB2E07167AC3ULL,
		0x63DCAA59C672BB11ULL,
		0xEE0868F0A621065FULL,
		0x209B96D677675E8BULL
	}};
	sign = 0;
	printf("Test Case 233\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 233 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -233;
	} else {
		printf("Test Case 233 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4573773472902044ULL,
		0xA574D30C1B8DF016ULL,
		0x221C0824DF74EB6DULL,
		0xA12D1588280F6805ULL,
		0x9A026639A9311560ULL,
		0xAA32E7E11FCB4B4AULL,
		0xAF916B5D59E48E50ULL,
		0xB42133FC7DCC5AF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3DDD10715A948E3ULL,
		0x0811686FEF0BC894ULL,
		0xE0E0AEBC84E6AF38ULL,
		0x43540A824B7472BFULL,
		0x3C4B59E375F40CF5ULL,
		0x78100403AFCBCA64ULL,
		0x893D0E9DBE400CECULL,
		0x27CA8DD925E327E9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5195A62D5CE6D761ULL,
		0x9D636A9C2C822781ULL,
		0x413B59685A8E3C35ULL,
		0x5DD90B05DC9AF545ULL,
		0x5DB70C56333D086BULL,
		0x3222E3DD6FFF80E6ULL,
		0x26545CBF9BA48164ULL,
		0x8C56A62357E9330EULL
	}};
	sign = 0;
	printf("Test Case 234\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 234 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -234;
	} else {
		printf("Test Case 234 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x219ECD1D58B2620BULL,
		0x0EE69891E2DC6E12ULL,
		0x51E21ECB88FEA47CULL,
		0x72C20C33D43D79EAULL,
		0xFF6317C9A605A0D9ULL,
		0x6A909DAF94A965A8ULL,
		0x9E8A88AD3D17E7DEULL,
		0xCFBEA21E6A59E5BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x299B9D2C22B9B48AULL,
		0x4E664BA08E75B04BULL,
		0x4A0D3D107D52B516ULL,
		0x62C751666FCDD7DFULL,
		0xA8B2B58E2EFFB757ULL,
		0xD4F2B7B065573224ULL,
		0x937016C9116D243EULL,
		0x2D90301251CA2D9CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF8032FF135F8AD81ULL,
		0xC0804CF15466BDC6ULL,
		0x07D4E1BB0BABEF65ULL,
		0x0FFABACD646FA20BULL,
		0x56B0623B7705E982ULL,
		0x959DE5FF2F523384ULL,
		0x0B1A71E42BAAC39FULL,
		0xA22E720C188FB823ULL
	}};
	sign = 0;
	printf("Test Case 235\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 235 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -235;
	} else {
		printf("Test Case 235 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5D84454F586944D2ULL,
		0x3C973FAA90EE7F83ULL,
		0x1C789860D708FE36ULL,
		0x5FCF42EEDE165F8CULL,
		0x7C59B1652CB5C7CAULL,
		0xF2FD297F24E503FAULL,
		0x555A36FAC3B35AD4ULL,
		0x99B446866426BE48ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x657B9CBF3F73F545ULL,
		0xBF005D14544E063EULL,
		0xEFD7EEF85FEBA9ACULL,
		0xC0E0C1D5E6478A4CULL,
		0xDE84A38C7F75489BULL,
		0x8426C6650A1D470DULL,
		0x85220FC91E2189ACULL,
		0x00A222A0517AA067ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF808A89018F54F8DULL,
		0x7D96E2963CA07944ULL,
		0x2CA0A968771D5489ULL,
		0x9EEE8118F7CED53FULL,
		0x9DD50DD8AD407F2EULL,
		0x6ED6631A1AC7BCECULL,
		0xD0382731A591D128ULL,
		0x991223E612AC1DE0ULL
	}};
	sign = 0;
	printf("Test Case 236\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 236 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -236;
	} else {
		printf("Test Case 236 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8DF4BB1CE752C5E0ULL,
		0x58A93890BC790FCEULL,
		0xEAF34E53329AEB66ULL,
		0x2B3D6252F019FEEAULL,
		0xDA0A17E9E5A57C03ULL,
		0x6CA4F99E683F51B0ULL,
		0x6853275672CFDA4AULL,
		0x8C4776BA1950F6D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A255016DDAFBF97ULL,
		0xF1A3CF048D3D92B9ULL,
		0x37427F21FE96B575ULL,
		0x95FA0F17B55807CCULL,
		0xB809E099CB4A1D1AULL,
		0xECD487BC83C7FDB5ULL,
		0xB0D6EBFCDC9463E1ULL,
		0xBE92897C49E4EBA7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x33CF6B0609A30649ULL,
		0x6705698C2F3B7D15ULL,
		0xB3B0CF31340435F0ULL,
		0x9543533B3AC1F71EULL,
		0x220037501A5B5EE8ULL,
		0x7FD071E1E47753FBULL,
		0xB77C3B59963B7668ULL,
		0xCDB4ED3DCF6C0B30ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 237\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 237 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -237;
	} else {
		printf("Test Case 237 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC853CA2D24526DBFULL,
		0xE123A0E360C1C25AULL,
		0x3E3FE61B05824BB2ULL,
		0x377CCEFDA666775DULL,
		0x80AAB30438ED1A23ULL,
		0xB20D8EA4E2FA1FC9ULL,
		0x6DBA0BEB583F9497ULL,
		0xC67792C1884B374FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19844ECFD0F3D3C3ULL,
		0x4735CCBED1CCE081ULL,
		0xDEA031901AEF884AULL,
		0x1E644F948E784824ULL,
		0x8430BC427C20E133ULL,
		0x0243DF4E0E2F3A69ULL,
		0x76B103D4653CE78FULL,
		0xF1E860A0DA0DC4B3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAECF7B5D535E99FCULL,
		0x99EDD4248EF4E1D9ULL,
		0x5F9FB48AEA92C368ULL,
		0x19187F6917EE2F38ULL,
		0xFC79F6C1BCCC38F0ULL,
		0xAFC9AF56D4CAE55FULL,
		0xF7090816F302AD08ULL,
		0xD48F3220AE3D729BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 238\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 238 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -238;
	} else {
		printf("Test Case 238 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD2EBF46673902E49ULL,
		0x2AD84D0ED06A50D5ULL,
		0x829F0EFF5969E3BEULL,
		0x2D4DF03E306AE040ULL,
		0x59EDD2D1AB735BFDULL,
		0xC96AD1E46AF2BCFAULL,
		0x5B303479EA58BD28ULL,
		0x05AFB8DEB227A7D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F406FF6EAA2CB73ULL,
		0xE3ED0202A85A0CA4ULL,
		0x6FA14EEC7D3E8D4EULL,
		0xE4254EC1912A140EULL,
		0x1F85283948CE8560ULL,
		0xB23AB12E0BD96C19ULL,
		0x45754254A8D5B725ULL,
		0xE067658D8A13D842ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x33AB846F88ED62D6ULL,
		0x46EB4B0C28104431ULL,
		0x12FDC012DC2B566FULL,
		0x4928A17C9F40CC32ULL,
		0x3A68AA9862A4D69CULL,
		0x173020B65F1950E1ULL,
		0x15BAF22541830603ULL,
		0x254853512813CF91ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 239\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 239 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -239;
	} else {
		printf("Test Case 239 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3F87FA3CDAA5B63DULL,
		0xD20A9F92B656B7B8ULL,
		0x84EAB23CF8305BE4ULL,
		0xD52D7D4184D47C6AULL,
		0x72B09A3051D5CEC8ULL,
		0x95E044E876C9A29EULL,
		0x5A4828ED40F393ECULL,
		0x424FC277F14E5F19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x873292EE9402A692ULL,
		0xFE7B84F1EE6505B4ULL,
		0x12631543493AC808ULL,
		0x7A6F3A4CE44842FEULL,
		0xF0D233571B38C388ULL,
		0xB0DAB5628A1B8F59ULL,
		0xEAA9248A2E095A98ULL,
		0xBF28D5B1E9D35386ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB855674E46A30FABULL,
		0xD38F1AA0C7F1B203ULL,
		0x72879CF9AEF593DBULL,
		0x5ABE42F4A08C396CULL,
		0x81DE66D9369D0B40ULL,
		0xE5058F85ECAE1344ULL,
		0x6F9F046312EA3953ULL,
		0x8326ECC6077B0B92ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 240\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 240 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -240;
	} else {
		printf("Test Case 240 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x18CC971BF95597C7ULL,
		0xFA8588405CD10115ULL,
		0xDFA437F4F4FFCC1EULL,
		0x74F96EA8D529F52EULL,
		0x1CF0E29500E0650CULL,
		0xCE8E57586BD0F7DAULL,
		0x73A24D30FA175A49ULL,
		0x7ED68BF5734FCD3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38275075BF61EA7AULL,
		0x5DC9F0C3C1DCF779ULL,
		0xC14320F198BAE74FULL,
		0x38801229A534043BULL,
		0x412D4F293BD73B49ULL,
		0x35A4E91DDEF22FB1ULL,
		0x7C9BC8A469EE02BBULL,
		0x3894C0D6DF39F6ECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE0A546A639F3AD4DULL,
		0x9CBB977C9AF4099BULL,
		0x1E6117035C44E4CFULL,
		0x3C795C7F2FF5F0F3ULL,
		0xDBC3936BC50929C3ULL,
		0x98E96E3A8CDEC828ULL,
		0xF706848C9029578EULL,
		0x4641CB1E9415D651ULL
	}};
	sign = 0;
	printf("Test Case 241\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 241 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -241;
	} else {
		printf("Test Case 241 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6623598753DEDDD3ULL,
		0x8E18B933DC457B62ULL,
		0xEF152EC4800D7F64ULL,
		0x2C37FC2E4FA3CCF4ULL,
		0x0C9FBB2552AEF4F4ULL,
		0xC7724C3F0263302DULL,
		0xCCB0475168E08307ULL,
		0xBF26E1C1EDC53D16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D421D297FCED1FEULL,
		0x256D8E4D423D0DE5ULL,
		0xF364C3CD60673B9EULL,
		0x154AA55BF24117B5ULL,
		0xFA49ECCE2290D240ULL,
		0x7DA4B9343E15A35FULL,
		0x24CAED743A9DF094ULL,
		0x9BE03CA2E9B79885ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x38E13C5DD4100BD5ULL,
		0x68AB2AE69A086D7DULL,
		0xFBB06AF71FA643C6ULL,
		0x16ED56D25D62B53EULL,
		0x1255CE57301E22B4ULL,
		0x49CD930AC44D8CCDULL,
		0xA7E559DD2E429273ULL,
		0x2346A51F040DA491ULL
	}};
	sign = 0;
	printf("Test Case 242\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 242 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -242;
	} else {
		printf("Test Case 242 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC44DD6393368F33DULL,
		0x688A6E719C7A5CB8ULL,
		0x1AAB521314807EBCULL,
		0x3C78DEBE305199DDULL,
		0x4C86F75DFFCB7298ULL,
		0xE83F18BC85305F24ULL,
		0x92194CFA79B1DE69ULL,
		0xC3EAFA47F4A6E035ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA554839B6DF583C1ULL,
		0xA764F7FAC0B79010ULL,
		0xB577B04FD7D6C0C1ULL,
		0x8D3A5B7C2B80E683ULL,
		0x2F8B407F04CF3797ULL,
		0x63B1E84D844B000CULL,
		0x5118508D1BE3DF3CULL,
		0xA38A696403A1A8E2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1EF9529DC5736F7CULL,
		0xC1257676DBC2CCA8ULL,
		0x6533A1C33CA9BDFAULL,
		0xAF3E834204D0B359ULL,
		0x1CFBB6DEFAFC3B00ULL,
		0x848D306F00E55F18ULL,
		0x4100FC6D5DCDFF2DULL,
		0x206090E3F1053753ULL
	}};
	sign = 0;
	printf("Test Case 243\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 243 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -243;
	} else {
		printf("Test Case 243 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0A7BAE068880AA27ULL,
		0x0F4E2ADCFE96353DULL,
		0xAF651908C250C26EULL,
		0x2F9656F7348715F6ULL,
		0xFF8774856A6A6BD5ULL,
		0x308DBF9B0CF7A827ULL,
		0x3D85A5448AE344EBULL,
		0xFFCE2C3473C69CB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCEBC6D57517F54E6ULL,
		0x9A981DEC79015179ULL,
		0x7D3187F51536B63EULL,
		0x585F5722B559350FULL,
		0x18A16CDC4935F4DAULL,
		0x841F406F79DBF4ECULL,
		0xD59F337C6069159DULL,
		0x413E3E96F6039FA1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3BBF40AF37015541ULL,
		0x74B60CF08594E3C3ULL,
		0x32339113AD1A0C2FULL,
		0xD736FFD47F2DE0E7ULL,
		0xE6E607A9213476FAULL,
		0xAC6E7F2B931BB33BULL,
		0x67E671C82A7A2F4DULL,
		0xBE8FED9D7DC2FD14ULL
	}};
	sign = 0;
	printf("Test Case 244\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 244 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -244;
	} else {
		printf("Test Case 244 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x628FE847741490A8ULL,
		0x972804ED78689A1CULL,
		0x6201744FE27C9CE0ULL,
		0x178E067814C1D32EULL,
		0x00DB5C8ABE86410EULL,
		0x61AB5E2F37EC801DULL,
		0x054D15B74DC0D7D3ULL,
		0xDF0A8C6538163770ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE732E2F6E0F187CDULL,
		0xC71C8B3BF612EFFFULL,
		0x413A688BDFDF1AEEULL,
		0x633138CF289B0BF9ULL,
		0x895AFAC6189DB162ULL,
		0x5ED7B9B54DD30FB9ULL,
		0x15F7AF1C9F716474ULL,
		0xE2672B01D2354137ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7B5D0550932308DBULL,
		0xD00B79B18255AA1CULL,
		0x20C70BC4029D81F1ULL,
		0xB45CCDA8EC26C735ULL,
		0x778061C4A5E88FABULL,
		0x02D3A479EA197063ULL,
		0xEF55669AAE4F735FULL,
		0xFCA3616365E0F638ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 245\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 245 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -245;
	} else {
		printf("Test Case 245 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBCDAE11854AD98F5ULL,
		0x784EDF23539E0DFAULL,
		0x358F914158E9BE3EULL,
		0x5B2C1A68EE814D93ULL,
		0x41BCDDFD7124D8E3ULL,
		0x93B55CD7F9D285F3ULL,
		0xE65DE9A330F17CB2ULL,
		0xFF7717A74F3213F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B03FF648574CE02ULL,
		0x631AFBD98D197976ULL,
		0x1193A5EDA4707435ULL,
		0x6D61776294184711ULL,
		0xBF89A5A1D6962F12ULL,
		0xF99A6AA606B93736ULL,
		0xF8911156B4214080ULL,
		0x497D2FA016BAAFFDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x71D6E1B3CF38CAF3ULL,
		0x1533E349C6849484ULL,
		0x23FBEB53B4794A09ULL,
		0xEDCAA3065A690682ULL,
		0x8233385B9A8EA9D0ULL,
		0x9A1AF231F3194EBCULL,
		0xEDCCD84C7CD03C31ULL,
		0xB5F9E807387763F2ULL
	}};
	sign = 0;
	printf("Test Case 246\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 246 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -246;
	} else {
		printf("Test Case 246 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA1CB7E724CC1F641ULL,
		0x7301CA2D0566610EULL,
		0x54084A40A77ED442ULL,
		0x4F4FFB1A1B23FE80ULL,
		0xDEE6F8A0B55809F7ULL,
		0x91FC32C633789857ULL,
		0x9050A48DEC25F5DAULL,
		0x265380EEB5BBA27FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB22F7D25F3281692ULL,
		0xA95948B54FA45845ULL,
		0xA7637608F6CC0663ULL,
		0x79472195FC35517EULL,
		0x089A143B20A7338CULL,
		0xD8C5DD36921C84DDULL,
		0xE6605BE67507D7A0ULL,
		0x2D5EC0AB404721BEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEF9C014C5999DFAFULL,
		0xC9A88177B5C208C8ULL,
		0xACA4D437B0B2CDDEULL,
		0xD608D9841EEEAD01ULL,
		0xD64CE46594B0D66AULL,
		0xB936558FA15C137AULL,
		0xA9F048A7771E1E39ULL,
		0xF8F4C043757480C0ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 247\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 247 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -247;
	} else {
		printf("Test Case 247 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE845B70E13D8F957ULL,
		0xA1879BE6557D76A6ULL,
		0x03E9824C44826788ULL,
		0xA0250FCF2EE6A274ULL,
		0x94CE5D86A298FC40ULL,
		0x192994E9106B330AULL,
		0xC57902137C3AA453ULL,
		0xEF30DAA232892BDFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC9DA2301666FBB7ULL,
		0x1FFF9B7D24553E26ULL,
		0x76E9E0D5DCA1F81BULL,
		0x98FAD220DB4B94B5ULL,
		0xD9071CF189526C8BULL,
		0x23EC4AFD5FF3FDA5ULL,
		0xF73C50C8BB49BAA5ULL,
		0xC6FBED570D997663ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3BA814DDFD71FDA0ULL,
		0x8188006931283880ULL,
		0x8CFFA17667E06F6DULL,
		0x072A3DAE539B0DBEULL,
		0xBBC7409519468FB5ULL,
		0xF53D49EBB0773564ULL,
		0xCE3CB14AC0F0E9ADULL,
		0x2834ED4B24EFB57BULL
	}};
	sign = 0;
	printf("Test Case 248\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 248 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -248;
	} else {
		printf("Test Case 248 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7D4BDE36287D4175ULL,
		0xDD84EEC2DFAA305EULL,
		0x5D34BB9627D1112FULL,
		0x924D7DE04C55B597ULL,
		0xF0E6F528D547F1EFULL,
		0x254443C09E914CCFULL,
		0x0F9DA3E0CDD10E08ULL,
		0xDBB3EDB056D6F341ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x849793B116D0B6D0ULL,
		0x904453E7443BB93AULL,
		0xE0E47952C963DCF2ULL,
		0x6C234AC907F2F42AULL,
		0xC3085945B2320BB6ULL,
		0xD0100C4723D4B290ULL,
		0x544DA24D2FDBA65AULL,
		0x84164C0A0B6F2466ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF8B44A8511AC8AA5ULL,
		0x4D409ADB9B6E7723ULL,
		0x7C5042435E6D343DULL,
		0x262A33174462C16CULL,
		0x2DDE9BE32315E639ULL,
		0x553437797ABC9A3FULL,
		0xBB5001939DF567ADULL,
		0x579DA1A64B67CEDAULL
	}};
	sign = 0;
	printf("Test Case 249\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 249 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -249;
	} else {
		printf("Test Case 249 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4A155D5BE657D69EULL,
		0x66BB258D63A1FDE5ULL,
		0xBC623C391DFBA362ULL,
		0x877D629C89FB5865ULL,
		0x0ECACD45FA1D567AULL,
		0x72862DEB618FFDA8ULL,
		0xE9CD1407C2CDAA5FULL,
		0x3B5E295E8E2D2630ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x563121B1590864DFULL,
		0x762242AF6C5A9523ULL,
		0x7884B22D98EBEDA0ULL,
		0x6716B25BC43F6F88ULL,
		0xE55EA2E502B41DBAULL,
		0xC1AFC8010DE8CF2DULL,
		0xB5DBA890385EC083ULL,
		0x128D4752C680E850ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF3E43BAA8D4F71BFULL,
		0xF098E2DDF74768C1ULL,
		0x43DD8A0B850FB5C1ULL,
		0x2066B040C5BBE8DDULL,
		0x296C2A60F76938C0ULL,
		0xB0D665EA53A72E7AULL,
		0x33F16B778A6EE9DBULL,
		0x28D0E20BC7AC3DE0ULL
	}};
	sign = 0;
	printf("Test Case 250\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 250 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -250;
	} else {
		printf("Test Case 250 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA0AA3D06377C6563ULL,
		0x3F10C71CAA44E0FDULL,
		0xA8F813E6661B3D74ULL,
		0xAD25DCDEA3284955ULL,
		0xAFCF239C3A251317ULL,
		0x5E061FDADF800339ULL,
		0x64C46F772156E89AULL,
		0x44F2D8EE09F38D06ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C4DB06A54B6E5DAULL,
		0x8187D1690796824BULL,
		0x6F5C16009917B09CULL,
		0x731E1AC09998EB51ULL,
		0xE48635AF32482A75ULL,
		0x9412918C2FFC86D7ULL,
		0xA6FCED247025A0DCULL,
		0x298F2CB83876F3B9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x845C8C9BE2C57F89ULL,
		0xBD88F5B3A2AE5EB2ULL,
		0x399BFDE5CD038CD7ULL,
		0x3A07C21E098F5E04ULL,
		0xCB48EDED07DCE8A2ULL,
		0xC9F38E4EAF837C61ULL,
		0xBDC78252B13147BDULL,
		0x1B63AC35D17C994CULL
	}};
	sign = 0;
	printf("Test Case 251\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 251 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -251;
	} else {
		printf("Test Case 251 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD542BD7086EEEE7DULL,
		0xB407E9765C06CB72ULL,
		0xDBC218453BA74C3BULL,
		0x287283F08F02D2A7ULL,
		0x9982BDE94EC0E249ULL,
		0x6C7CBD7766988398ULL,
		0x0CE7080A623BED68ULL,
		0x23E379C2C506BC28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84A436764B21EF66ULL,
		0x41D5FB4B14049028ULL,
		0xD230C50DDBF519E8ULL,
		0x9CB829FBA156C2E1ULL,
		0x26D05C3AD850F840ULL,
		0x19D66F0E99F8D370ULL,
		0x538FBD125618D754ULL,
		0xF8AAEF5488945A6AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x509E86FA3BCCFF17ULL,
		0x7231EE2B48023B4AULL,
		0x099153375FB23253ULL,
		0x8BBA59F4EDAC0FC6ULL,
		0x72B261AE766FEA08ULL,
		0x52A64E68CC9FB028ULL,
		0xB9574AF80C231614ULL,
		0x2B388A6E3C7261BDULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 252\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 252 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -252;
	} else {
		printf("Test Case 252 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4BA149C0A968E63CULL,
		0x4304D6CD19FF8370ULL,
		0x190563FD53BC095CULL,
		0x7F7D97AB8197DAFEULL,
		0x8418ED4C5C14E145ULL,
		0xBEDEBF177C85D83FULL,
		0x81A20E926C8BDA00ULL,
		0x1C8351DE7976211EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87E9C7FC7DEBB133ULL,
		0x065779DB177CB184ULL,
		0xC2C7DA02CF6DD6EEULL,
		0x6274466B7979E629ULL,
		0xB7C410F35D2E9ADEULL,
		0x51C1BFDA06DB727AULL,
		0x4F7666872D752D02ULL,
		0xA25076D1BCBDC995ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC3B781C42B7D3509ULL,
		0x3CAD5CF20282D1EBULL,
		0x563D89FA844E326EULL,
		0x1D095140081DF4D4ULL,
		0xCC54DC58FEE64667ULL,
		0x6D1CFF3D75AA65C4ULL,
		0x322BA80B3F16ACFEULL,
		0x7A32DB0CBCB85789ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 253\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 253 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -253;
	} else {
		printf("Test Case 253 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x97CA238A4DEE63B8ULL,
		0xA49F7E5F1B3FB6C5ULL,
		0x19139BEBD3AA08A8ULL,
		0xFFB4AAB4F46B0655ULL,
		0xB40B4001A80E1730ULL,
		0x65EAA42CB41CE90DULL,
		0x2E2F0C0A4A067F71ULL,
		0xA22220C117E97996ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE97B4214BE6B913EULL,
		0xE8AF6392508A98CCULL,
		0x971E04105F384FF9ULL,
		0xB47753282C4FB438ULL,
		0x4A96295E3DDB35A7ULL,
		0x4B650CB897E0EC30ULL,
		0x378DEF24692C3A11ULL,
		0x11EFCCC1C696CE1AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAE4EE1758F82D27AULL,
		0xBBF01ACCCAB51DF8ULL,
		0x81F597DB7471B8AEULL,
		0x4B3D578CC81B521CULL,
		0x697516A36A32E189ULL,
		0x1A8597741C3BFCDDULL,
		0xF6A11CE5E0DA4560ULL,
		0x903253FF5152AB7BULL
	}};
	sign = 0;
	printf("Test Case 254\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 254 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -254;
	} else {
		printf("Test Case 254 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2E28864E9B4DDF88ULL,
		0xFC9B8726F7742334ULL,
		0xA3A0A4070FB288B3ULL,
		0x2EF84E2B2A134828ULL,
		0x524C81EF266AAC7DULL,
		0x7B3F635B8BCD6573ULL,
		0xE4EABE14C16374A7ULL,
		0x4D2631701639025FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31CFBF9B7BE20D22ULL,
		0x56EDF36FEB92420DULL,
		0x12D427C29EC6BC99ULL,
		0x7A3FFB46529D47EBULL,
		0x815B1790612CDB94ULL,
		0x0E8A2128C8B43CD3ULL,
		0xB2CF30439A1B74E0ULL,
		0xFC6E5260294E60E0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFC58C6B31F6BD266ULL,
		0xA5AD93B70BE1E126ULL,
		0x90CC7C4470EBCC1AULL,
		0xB4B852E4D776003DULL,
		0xD0F16A5EC53DD0E8ULL,
		0x6CB54232C319289FULL,
		0x321B8DD12747FFC7ULL,
		0x50B7DF0FECEAA17FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 255\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 255 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -255;
	} else {
		printf("Test Case 255 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x512F0198539E3619ULL,
		0x506F95DA63C91D38ULL,
		0xB29372F7680150A2ULL,
		0x0DAD34DAF27211C0ULL,
		0xD1A485E708D018F0ULL,
		0xE7EBE61F62EF6B7EULL,
		0xAB9037D351421F08ULL,
		0xF1C77217423ABE12ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08D640A9EBC23BCEULL,
		0x5382712D29996AE7ULL,
		0x4FA1B6E31A80C2CAULL,
		0x45E105E7367A1E2FULL,
		0xAA8DE22352A6E8FEULL,
		0xAF5E2698D72C1891ULL,
		0xB475CE3EC0E3979EULL,
		0x1E9B5374585C1908ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4858C0EE67DBFA4BULL,
		0xFCED24AD3A2FB251ULL,
		0x62F1BC144D808DD7ULL,
		0xC7CC2EF3BBF7F391ULL,
		0x2716A3C3B6292FF1ULL,
		0x388DBF868BC352EDULL,
		0xF71A6994905E876AULL,
		0xD32C1EA2E9DEA509ULL
	}};
	sign = 0;
	printf("Test Case 256\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 256 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -256;
	} else {
		printf("Test Case 256 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x42334603FB2A2F1BULL,
		0xC782AF83C97EFFE6ULL,
		0xCFE43270F99F81C8ULL,
		0x64730FAD4243D48EULL,
		0xA2ABED139AAF034EULL,
		0x65E9BFAC7A1D03C0ULL,
		0x4EAD2A46D4AE1D31ULL,
		0x718B695204CC825CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB637DD83BDDD0416ULL,
		0xD427567D219A3E33ULL,
		0xDF5572CBE1A19D9FULL,
		0xAC06BBDE367BAEE1ULL,
		0xC39F001B1B38AAD5ULL,
		0x04A02C3ACDFEB57BULL,
		0xB6501E2D8322B278ULL,
		0x5B6DA339EAA69324ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8BFB68803D4D2B05ULL,
		0xF35B5906A7E4C1B2ULL,
		0xF08EBFA517FDE428ULL,
		0xB86C53CF0BC825ACULL,
		0xDF0CECF87F765878ULL,
		0x61499371AC1E4E44ULL,
		0x985D0C19518B6AB9ULL,
		0x161DC6181A25EF37ULL
	}};
	sign = 0;
	printf("Test Case 257\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 257 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -257;
	} else {
		printf("Test Case 257 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x732293C17A7296ADULL,
		0xF0858FA54F71C254ULL,
		0xED817D18CEF6298DULL,
		0x866556B6CBBE2A38ULL,
		0xD2C5B15F3A1CFD31ULL,
		0x88B170D22A54B224ULL,
		0x2BB2CB2D2406471BULL,
		0x01BFF0B6460BD67DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48A06BBCD03C9727ULL,
		0x4E0B608726BA8FA0ULL,
		0x1B55E7D66613F898ULL,
		0xE0267E00CA959212ULL,
		0x46974B7897EAE2F8ULL,
		0xE03130B428661041ULL,
		0xE796F0A9953335D8ULL,
		0x64A889D214DDF56CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2A822804AA35FF86ULL,
		0xA27A2F1E28B732B4ULL,
		0xD22B954268E230F5ULL,
		0xA63ED8B601289826ULL,
		0x8C2E65E6A2321A38ULL,
		0xA880401E01EEA1E3ULL,
		0x441BDA838ED31142ULL,
		0x9D1766E4312DE110ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 258\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 258 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -258;
	} else {
		printf("Test Case 258 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x62A7DAD4AA07C389ULL,
		0xC35E4318995F81B0ULL,
		0x1012D15550837782ULL,
		0x603C65B49EA2FD72ULL,
		0x1A9D5977A336E594ULL,
		0xAA8C51D286FD8E83ULL,
		0xE05A6ECBDD306501ULL,
		0xE6E3FC5D1677BD76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB509113437B1A971ULL,
		0x6E8679B2D9D7838EULL,
		0xC1BE2B600CAFC93EULL,
		0x6000D70BC28EAA51ULL,
		0x6011642686EA633CULL,
		0x16B57E11E86C6006ULL,
		0xFD107E262534AB75ULL,
		0x145237C6E77080D5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAD9EC9A072561A18ULL,
		0x54D7C965BF87FE21ULL,
		0x4E54A5F543D3AE44ULL,
		0x003B8EA8DC145320ULL,
		0xBA8BF5511C4C8258ULL,
		0x93D6D3C09E912E7CULL,
		0xE349F0A5B7FBB98CULL,
		0xD291C4962F073CA0ULL
	}};
	sign = 0;
	printf("Test Case 259\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 259 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -259;
	} else {
		printf("Test Case 259 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9C2A3C5A38F6B6DDULL,
		0x2E996E2ACBF392BCULL,
		0x676F0D6BD5E36734ULL,
		0xA05906868149B4BCULL,
		0x4ECABF4FE421F68CULL,
		0xF844245C58BF87F1ULL,
		0x071DDBE948D98C25ULL,
		0x84E88518312CDD16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x830EBCD0017BFB79ULL,
		0xE83C049670C189FEULL,
		0xA5D1641D14B9132FULL,
		0x5D975883C24E9496ULL,
		0xE2EAFFDAC9383720ULL,
		0xDE1BEC3CC3CF40B8ULL,
		0x3F7A18ED5926A2EEULL,
		0x0485AD2F0F952726ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x191B7F8A377ABB64ULL,
		0x465D69945B3208BEULL,
		0xC19DA94EC12A5404ULL,
		0x42C1AE02BEFB2025ULL,
		0x6BDFBF751AE9BF6CULL,
		0x1A28381F94F04738ULL,
		0xC7A3C2FBEFB2E937ULL,
		0x8062D7E92197B5EFULL
	}};
	sign = 0;
	printf("Test Case 260\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 260 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -260;
	} else {
		printf("Test Case 260 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x40B501D9366D1FB6ULL,
		0x478CAC9988371699ULL,
		0xD7751BA58D5C7076ULL,
		0xA0FCE3A37EC5668DULL,
		0xF716FE853D48B085ULL,
		0xEADCEEADB453D777ULL,
		0x2FF067E71019370DULL,
		0x875A61B44B61017EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F12201872684F95ULL,
		0x842649DE4AB68FB7ULL,
		0xB97BDD77477E561CULL,
		0x5C1DDF963DCB10D3ULL,
		0x194CF92BA72C01D4ULL,
		0x014BCE9562340089ULL,
		0xFA5B4DADC15CD99BULL,
		0xABFF99AA7FDBB3DAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF1A2E1C0C404D021ULL,
		0xC36662BB3D8086E1ULL,
		0x1DF93E2E45DE1A59ULL,
		0x44DF040D40FA55BAULL,
		0xDDCA0559961CAEB1ULL,
		0xE9912018521FD6EEULL,
		0x35951A394EBC5D72ULL,
		0xDB5AC809CB854DA3ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 261\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 261 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -261;
	} else {
		printf("Test Case 261 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x365DF1543AB0DB17ULL,
		0x3C00F311C8A3A9D0ULL,
		0x4FD82484BFA598A7ULL,
		0x13F9DBD36D86D325ULL,
		0x624FB8D22B26AF41ULL,
		0x23427EEEAC80DD92ULL,
		0x93115F793C472C87ULL,
		0x2F8C692FAE894F9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D70A1979423CC7AULL,
		0x9D856C759130DDD5ULL,
		0xE2250F8DF92E2BBFULL,
		0x4DF176613AD9E8B2ULL,
		0x3E80AE91A02A6443ULL,
		0x774ACA06D5C44D21ULL,
		0xFDC7CF4860DF5386ULL,
		0xD5615329F9E874EEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x98ED4FBCA68D0E9DULL,
		0x9E7B869C3772CBFAULL,
		0x6DB314F6C6776CE7ULL,
		0xC608657232ACEA72ULL,
		0x23CF0A408AFC4AFDULL,
		0xABF7B4E7D6BC9071ULL,
		0x95499030DB67D900ULL,
		0x5A2B1605B4A0DAACULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 262\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 262 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -262;
	} else {
		printf("Test Case 262 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBB3F6C6B9BA18BB6ULL,
		0xED57FB781121FBABULL,
		0x656B52613B729106ULL,
		0xE1D7C08575BB797FULL,
		0x330521DBBF7E444BULL,
		0x00355262F06DFBBAULL,
		0x11CA767B76509EBFULL,
		0xD4715B87AA586179ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6ACF956398A41C1BULL,
		0x19AE42A8F32CD2A3ULL,
		0x91A2080B20DF12CAULL,
		0x8E7CAE924E00C90DULL,
		0xCFE7B145706690E9ULL,
		0x951B5EF89B2452C3ULL,
		0x733640747A742A4FULL,
		0x807FFEEC87CFA1D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x506FD70802FD6F9BULL,
		0xD3A9B8CF1DF52908ULL,
		0xD3C94A561A937E3CULL,
		0x535B11F327BAB071ULL,
		0x631D70964F17B362ULL,
		0x6B19F36A5549A8F6ULL,
		0x9E943606FBDC746FULL,
		0x53F15C9B2288BFA2ULL
	}};
	sign = 0;
	printf("Test Case 263\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 263 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -263;
	} else {
		printf("Test Case 263 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x94D2E1F7DA05C6DEULL,
		0xACD2CAD50902CEFEULL,
		0x735BBC4A903267D6ULL,
		0xD2507DB0CC2860B3ULL,
		0x1CFFC7A502938957ULL,
		0x8DF0C19A96ECDBBEULL,
		0xB53B1C10322FBBB6ULL,
		0x6730EB09AE475B22ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x940E30A606F42C6BULL,
		0x5E96533BE8D1E31EULL,
		0x90102997B9DBAC96ULL,
		0x4B865CC8AF040DB8ULL,
		0x3B414795F1002F49ULL,
		0x151F1684BCCDF8C7ULL,
		0xB362CB26CE08B00CULL,
		0x1454141D6E71F7D4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00C4B151D3119A73ULL,
		0x4E3C77992030EBE0ULL,
		0xE34B92B2D656BB40ULL,
		0x86CA20E81D2452FAULL,
		0xE1BE800F11935A0EULL,
		0x78D1AB15DA1EE2F6ULL,
		0x01D850E964270BAAULL,
		0x52DCD6EC3FD5634EULL
	}};
	sign = 0;
	printf("Test Case 264\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 264 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -264;
	} else {
		printf("Test Case 264 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x34D4240C09A0C585ULL,
		0x5294BB1129F4DFE1ULL,
		0x62D91C11A89B5D44ULL,
		0x591E73DCB3DAFAFAULL,
		0x63FC9F0EC43DEA76ULL,
		0x868C1BC175ACBD44ULL,
		0x93B59F48F01381D3ULL,
		0x7707E0B4D936897FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC85B9C27B12C831DULL,
		0x636B6EF024BB0026ULL,
		0xF121F8D6EE1A51CAULL,
		0x66566715C9689A87ULL,
		0x9DB79BD9DBCDD5B9ULL,
		0x10F35AF9883501D0ULL,
		0xCA7A25D8CA13580AULL,
		0x4A71D52ECE4CB396ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6C7887E458744268ULL,
		0xEF294C210539DFBAULL,
		0x71B7233ABA810B79ULL,
		0xF2C80CC6EA726072ULL,
		0xC6450334E87014BCULL,
		0x7598C0C7ED77BB73ULL,
		0xC93B7970260029C9ULL,
		0x2C960B860AE9D5E8ULL
	}};
	sign = 0;
	printf("Test Case 265\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 265 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -265;
	} else {
		printf("Test Case 265 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB9D0AA7EAD9C7DF9ULL,
		0xE6A2433D125F5569ULL,
		0xB5894B07D3E66600ULL,
		0x13B8B29E7DB8D63CULL,
		0x3855BECAC4A41199ULL,
		0x15041EDCAECE9921ULL,
		0xC856FCC039044FE1ULL,
		0x5F7CCB6AEF55839BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5709A8C20EB82B3AULL,
		0x1F9198F7567A224DULL,
		0x386B828CDCC0A12EULL,
		0x20B40D615ABB9099ULL,
		0x64A51C96B7F4E077ULL,
		0xC4395568524D09CDULL,
		0xD307CD14D5AAD80DULL,
		0x66316FD13D72ECDDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x62C701BC9EE452BFULL,
		0xC710AA45BBE5331CULL,
		0x7D1DC87AF725C4D2ULL,
		0xF304A53D22FD45A3ULL,
		0xD3B0A2340CAF3121ULL,
		0x50CAC9745C818F53ULL,
		0xF54F2FAB635977D3ULL,
		0xF94B5B99B1E296BDULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 266\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 266 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -266;
	} else {
		printf("Test Case 266 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE389CD3DB8797B62ULL,
		0x5F39138FEE1975ACULL,
		0x61A733D08CA236D9ULL,
		0x038453764E164DA2ULL,
		0x482BC2491A28E93DULL,
		0xEEA7DC54DECF5829ULL,
		0xAAE2BF3882387585ULL,
		0x7A27B60A6BF3CD06ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD339DD66FEDF939FULL,
		0xD005093BABEA16DBULL,
		0xC639A1E6C4AF41E3ULL,
		0x75238DF377C01443ULL,
		0x0E60AD5CB70151B3ULL,
		0x959A08E647439FA7ULL,
		0x83016B3C714F33D5ULL,
		0x1FEEC5CB9EFAD533ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x104FEFD6B999E7C3ULL,
		0x8F340A54422F5ED1ULL,
		0x9B6D91E9C7F2F4F5ULL,
		0x8E60C582D656395EULL,
		0x39CB14EC63279789ULL,
		0x590DD36E978BB882ULL,
		0x27E153FC10E941B0ULL,
		0x5A38F03ECCF8F7D3ULL
	}};
	sign = 0;
	printf("Test Case 267\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 267 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -267;
	} else {
		printf("Test Case 267 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA6EBFA2089439428ULL,
		0xAD5BB22231379BCBULL,
		0x716BC03D27354A07ULL,
		0x5302754E3A931918ULL,
		0xA90D475A67488EF2ULL,
		0xB891660848C42C67ULL,
		0x7401E9E872CB88B1ULL,
		0x2D7DC561573337E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA89E82128373203CULL,
		0xA9E6E1DB3755BCEFULL,
		0xE1CC56A80859A62EULL,
		0xBD10A7589FD14A13ULL,
		0xC0C1E2E4993100E4ULL,
		0xF7CBD6531881EFB9ULL,
		0x1CD2514AAF64F02BULL,
		0x008A3C156EBAB88EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFE4D780E05D073ECULL,
		0x0374D046F9E1DEDBULL,
		0x8F9F69951EDBA3D9ULL,
		0x95F1CDF59AC1CF04ULL,
		0xE84B6475CE178E0DULL,
		0xC0C58FB530423CADULL,
		0x572F989DC3669885ULL,
		0x2CF3894BE8787F54ULL
	}};
	sign = 0;
	printf("Test Case 268\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 268 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -268;
	} else {
		printf("Test Case 268 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xACFE8B405B124CFCULL,
		0xFE5CE0B0D4B0C002ULL,
		0xBB97BA76686FBEADULL,
		0x0F78EB8DA4A92D9BULL,
		0xD6C04CCFFBB0A9D4ULL,
		0xEACFF5A478ABEDE6ULL,
		0x590DABA6C09BCB01ULL,
		0x5C19769CD8821759ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8E7148F5974BF8FULL,
		0xBDE4C44C9703F1DDULL,
		0xE1948D7833D9EBEDULL,
		0x798077E331739629ULL,
		0x28C64E10BA97631AULL,
		0x74C07046167A28A6ULL,
		0xE0BE8E6258613D13ULL,
		0x876656663AD25FADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD41776B1019D8D6DULL,
		0x40781C643DACCE24ULL,
		0xDA032CFE3495D2C0ULL,
		0x95F873AA73359771ULL,
		0xADF9FEBF411946B9ULL,
		0x760F855E6231C540ULL,
		0x784F1D44683A8DEEULL,
		0xD4B320369DAFB7ABULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 269\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 269 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -269;
	} else {
		printf("Test Case 269 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA2EDDD3CA35DBAF9ULL,
		0xDD8DCE399BB306CEULL,
		0x4D5A977F74C9DDD9ULL,
		0x9E77D30C210BF820ULL,
		0x84BFC39C498DAD48ULL,
		0xC949CEC5E86DF317ULL,
		0x3C2BD8538539B727ULL,
		0x8C566C29A24F8744ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0490BCBA216191AULL,
		0xC7CA707001FF3E88ULL,
		0x8BC5B996A6121BF1ULL,
		0x88B2D39E2661F350ULL,
		0x34E4D998A1096C9FULL,
		0xCE830BBEAEA19648ULL,
		0xE33BD7F944436C46ULL,
		0x13FA5597F63B8310ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB2A4D1710147A1DFULL,
		0x15C35DC999B3C845ULL,
		0xC194DDE8CEB7C1E8ULL,
		0x15C4FF6DFAAA04CFULL,
		0x4FDAEA03A88440A9ULL,
		0xFAC6C30739CC5CCFULL,
		0x58F0005A40F64AE0ULL,
		0x785C1691AC140433ULL
	}};
	sign = 0;
	printf("Test Case 270\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 270 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -270;
	} else {
		printf("Test Case 270 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCC424E2B892CD90EULL,
		0x8A020DF37A0478F6ULL,
		0x36A1CA4D4F13842CULL,
		0xF3E8A0DA2C131D6FULL,
		0xAEF47690D4E3B263ULL,
		0x9419B296795EF87EULL,
		0x8CC31FAEE54A4A0CULL,
		0xF50C4954C9DB573DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEA215E20C307E42ULL,
		0xAE5446E31A49FEE5ULL,
		0xE1263559B04823ADULL,
		0xD73046D99AAB8A8BULL,
		0x66B8AA01D0C4E16FULL,
		0x18434323130FD497ULL,
		0xF1FCD57F77736889ULL,
		0x47D3052DD5A507FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEDA038497CFC5ACCULL,
		0xDBADC7105FBA7A10ULL,
		0x557B94F39ECB607EULL,
		0x1CB85A00916792E3ULL,
		0x483BCC8F041ED0F4ULL,
		0x7BD66F73664F23E7ULL,
		0x9AC64A2F6DD6E183ULL,
		0xAD394426F4364F3EULL
	}};
	sign = 0;
	printf("Test Case 271\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 271 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -271;
	} else {
		printf("Test Case 271 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7ADC056227F24524ULL,
		0x24DAE958D9C19F67ULL,
		0x9B477E5EF7D42C4CULL,
		0xCF8436A9FB785609ULL,
		0x28C8327082D06F54ULL,
		0x9DEA7CA34AA4EA06ULL,
		0xA6A584618222FA88ULL,
		0xA9D4E81183242F94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x633004B9FCE0B440ULL,
		0x12033C86C2BCAFDCULL,
		0x533931021663A13EULL,
		0x132805A642F2BFACULL,
		0xC55F3F85D7C85280ULL,
		0x19784D053AA11078ULL,
		0x7CCB86C78998B52FULL,
		0x58CB4E916BC80781ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x17AC00A82B1190E4ULL,
		0x12D7ACD21704EF8BULL,
		0x480E4D5CE1708B0EULL,
		0xBC5C3103B885965DULL,
		0x6368F2EAAB081CD4ULL,
		0x84722F9E1003D98DULL,
		0x29D9FD99F88A4559ULL,
		0x51099980175C2813ULL
	}};
	sign = 0;
	printf("Test Case 272\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 272 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -272;
	} else {
		printf("Test Case 272 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x978ECB0BF9680ED6ULL,
		0x210FC107CA8158B5ULL,
		0x11134108C46D4C88ULL,
		0xB769A9E0F36081FFULL,
		0x8F7C226BD0290C6EULL,
		0xC44BB74DAF9DF58BULL,
		0x8443991641A51BD2ULL,
		0x3494B16D31B8DCD8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE2A4B41A2A02C08ULL,
		0x5C38E47275AF3662ULL,
		0xE60B377F15DCEA29ULL,
		0xE419DD41B2E0580EULL,
		0x92C5C0035DAC4DBCULL,
		0x76599AE4E1AE360CULL,
		0xDFA28D80C012F63BULL,
		0x7F9BD19A99B2766EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE9647FCA56C7E2CEULL,
		0xC4D6DC9554D22252ULL,
		0x2B080989AE90625EULL,
		0xD34FCC9F408029F0ULL,
		0xFCB66268727CBEB1ULL,
		0x4DF21C68CDEFBF7EULL,
		0xA4A10B9581922597ULL,
		0xB4F8DFD298066669ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 273\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 273 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -273;
	} else {
		printf("Test Case 273 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x89E4BE0F63684DAAULL,
		0xC6AA650D4D4F50DBULL,
		0x7D5B336059EBA68EULL,
		0x15E999A3351A4E14ULL,
		0x03739F568D959CA8ULL,
		0x6EF2F0A680BB1180ULL,
		0x2CCC83FF54BC25CFULL,
		0xD2673CB6CB09C8ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D6BC79446E5B3DBULL,
		0x17F999B93357AD1FULL,
		0xC3DD51C9A6354ADBULL,
		0x49CCBCC18DD3AC8DULL,
		0x450EDB30A9A578F6ULL,
		0xB0DA3AB3221343F5ULL,
		0x347B54C1336B7D40ULL,
		0x254A5BB9C50AF4D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6C78F67B1C8299CFULL,
		0xAEB0CB5419F7A3BCULL,
		0xB97DE196B3B65BB3ULL,
		0xCC1CDCE1A746A186ULL,
		0xBE64C425E3F023B1ULL,
		0xBE18B5F35EA7CD8AULL,
		0xF8512F3E2150A88EULL,
		0xAD1CE0FD05FED3D3ULL
	}};
	sign = 0;
	printf("Test Case 274\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 274 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -274;
	} else {
		printf("Test Case 274 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x551616B53976E455ULL,
		0xF3828F0CA5952D3FULL,
		0x64607638DED48854ULL,
		0xBBFE591A36D43665ULL,
		0x07B62CAED5370349ULL,
		0xB09C0BB4F520B84AULL,
		0x829D2768C24B3ABAULL,
		0x336E616E1BF7D1E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49AFC220237A221FULL,
		0xF011B135105D8FC0ULL,
		0x38EBFCAE681129D8ULL,
		0x3D9D4274121C18BDULL,
		0xE580696C89D8A0A3ULL,
		0x0F1E74C3F17602F3ULL,
		0x61038397325EBD18ULL,
		0xD1D777D145F3446EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0B66549515FCC236ULL,
		0x0370DDD795379D7FULL,
		0x2B74798A76C35E7CULL,
		0x7E6116A624B81DA8ULL,
		0x2235C3424B5E62A6ULL,
		0xA17D96F103AAB556ULL,
		0x2199A3D18FEC7DA2ULL,
		0x6196E99CD6048D77ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 275\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 275 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -275;
	} else {
		printf("Test Case 275 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x74460E310E1451B5ULL,
		0x0D2A23C70CFA5CAFULL,
		0x15BE60901CC1C043ULL,
		0x15DBEA2B67569C34ULL,
		0x50E687EC6CD34BE7ULL,
		0x3110212FDD937D19ULL,
		0xDF4D7319E392D8CAULL,
		0xC3A29767D1F1B0CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFA3380D7FED0899ULL,
		0x64E7F3B5B6223BE3ULL,
		0x0F48E509A1A29F13ULL,
		0x0F2F2F6277EEA49FULL,
		0xA0264D1F135D1F56ULL,
		0xE799B19D0B298DA2ULL,
		0xA86D3F54862C7555ULL,
		0x880A31B0349196CAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA4A2D6238E27491CULL,
		0xA842301156D820CBULL,
		0x06757B867B1F212FULL,
		0x06ACBAC8EF67F795ULL,
		0xB0C03ACD59762C91ULL,
		0x49766F92D269EF76ULL,
		0x36E033C55D666374ULL,
		0x3B9865B79D601A01ULL
	}};
	sign = 0;
	printf("Test Case 276\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 276 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -276;
	} else {
		printf("Test Case 276 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5615BFBF215C479DULL,
		0xA3C835E7DCE0AC3DULL,
		0x777391819185E3A0ULL,
		0x312BBE6CD7439125ULL,
		0x2AC26D9906BFF5B1ULL,
		0xA01F273D8DF650ACULL,
		0x9E2A2E49CE2C51EDULL,
		0x57293EB2C7AF6F0DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32FF2BACE508C9DFULL,
		0x97E3157FB19A0ED1ULL,
		0x4050E2015F959F00ULL,
		0x68C6E95628B199F9ULL,
		0xF94D948348FE322FULL,
		0x5E4BA58BBD189F42ULL,
		0xE2713B4309ADE66AULL,
		0x047D65DD08C8D600ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x231694123C537DBEULL,
		0x0BE520682B469D6CULL,
		0x3722AF8031F044A0ULL,
		0xC864D516AE91F72CULL,
		0x3174D915BDC1C381ULL,
		0x41D381B1D0DDB169ULL,
		0xBBB8F306C47E6B83ULL,
		0x52ABD8D5BEE6990CULL
	}};
	sign = 0;
	printf("Test Case 277\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 277 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -277;
	} else {
		printf("Test Case 277 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA687D5B86A4CAC6EULL,
		0x45905FAF76E94158ULL,
		0x060BBA6E6C88F658ULL,
		0x5C8976821406FC7FULL,
		0xA1A6272E22CAA230ULL,
		0x7450E24C97C6118DULL,
		0x355427919E139A46ULL,
		0x736C0E4801C636D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE2A0DBBDBAA0343ULL,
		0x740E6C559EC5EEC8ULL,
		0x5DDEB6ED5098FDCDULL,
		0x1E7D1ACC89ABE848ULL,
		0x66FA2F01C246E669ULL,
		0x9BCA3E8376782F73ULL,
		0x5DFE039E33B75425ULL,
		0xB3AE8EB0AB340105ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC85DC7FC8EA2A92BULL,
		0xD181F359D823528FULL,
		0xA82D03811BEFF88AULL,
		0x3E0C5BB58A5B1436ULL,
		0x3AABF82C6083BBC7ULL,
		0xD886A3C9214DE21AULL,
		0xD75623F36A5C4620ULL,
		0xBFBD7F97569235CEULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 278\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 278 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -278;
	} else {
		printf("Test Case 278 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x611579A614A8BAD8ULL,
		0x710290D295CBF12BULL,
		0xA450F1FA7FD86864ULL,
		0x224819E8E4B8DE05ULL,
		0xF2DE89678C8A1875ULL,
		0xD86E24E7EBF1EF6AULL,
		0x3DB11E4E28104A77ULL,
		0xE05C532E173F73FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CEA090EBDA10E41ULL,
		0x6317FED2AB26EE22ULL,
		0xC9415ED4913B9E63ULL,
		0x0178223A318E5264ULL,
		0xEEE7FC8F72D37246ULL,
		0x9A4D7F610A8EEAE0ULL,
		0x6685CFD66F3524C1ULL,
		0x5859C0457DFBDBFDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x142B70975707AC97ULL,
		0x0DEA91FFEAA50309ULL,
		0xDB0F9325EE9CCA01ULL,
		0x20CFF7AEB32A8BA0ULL,
		0x03F68CD819B6A62FULL,
		0x3E20A586E163048AULL,
		0xD72B4E77B8DB25B6ULL,
		0x880292E899439801ULL
	}};
	sign = 0;
	printf("Test Case 279\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 279 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -279;
	} else {
		printf("Test Case 279 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7CF1B928BFBADCD2ULL,
		0xCDB37DE9096C94BDULL,
		0xB01F355091FBC12BULL,
		0x8DB005C8A1273F7EULL,
		0xD64700533241A725ULL,
		0x657B72A9FCA23A4FULL,
		0xBD37738064157FE8ULL,
		0x088AA9CF71F598ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1289BE17E1B3A0D9ULL,
		0xC30E75B3C8A35914ULL,
		0x25D2D3E39496CED2ULL,
		0x6837FF7807DE270CULL,
		0x93B440E3A0381753ULL,
		0x86675742299C55E4ULL,
		0xE467D72D75EC3E4DULL,
		0x9C6FA96383BB4A64ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6A67FB10DE073BF9ULL,
		0x0AA5083540C93BA9ULL,
		0x8A4C616CFD64F259ULL,
		0x2578065099491872ULL,
		0x4292BF6F92098FD2ULL,
		0xDF141B67D305E46BULL,
		0xD8CF9C52EE29419AULL,
		0x6C1B006BEE3A4E87ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 280\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 280 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -280;
	} else {
		printf("Test Case 280 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE790B6A2B7012E0FULL,
		0x45B0E274C1E00AE6ULL,
		0x700098183AF1031EULL,
		0x032281F3522D756DULL,
		0xFC9CA43E90CB2BB8ULL,
		0xA0A7474B8E9F49DDULL,
		0xE3FDD647179A4F31ULL,
		0x6EB00D5188B065DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55C65EE463B07E81ULL,
		0xBF56079055494735ULL,
		0xE7B8384FB4547FABULL,
		0xF5A9B9B142B9DF76ULL,
		0xEB4837BBA142A90EULL,
		0xDC7B91CAA927672DULL,
		0xD0C43455D826D9ADULL,
		0x7213106E5FAAD440ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x91CA57BE5350AF8EULL,
		0x865ADAE46C96C3B1ULL,
		0x88485FC8869C8372ULL,
		0x0D78C8420F7395F6ULL,
		0x11546C82EF8882A9ULL,
		0xC42BB580E577E2B0ULL,
		0x1339A1F13F737583ULL,
		0xFC9CFCE32905919CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 281\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 281 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -281;
	} else {
		printf("Test Case 281 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5F133F940D14DC76ULL,
		0x02CB480923006FE8ULL,
		0x885F01068F0DFAB1ULL,
		0x904B8D97FE775BBFULL,
		0x1C2814F2298B8CD3ULL,
		0x17E6DA65BADE47B8ULL,
		0xA6647998B3F1D5E3ULL,
		0xD36368965E20BF63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0CA2A648A43473D9ULL,
		0x2882CEC50364A43AULL,
		0x8893EAF22743C58FULL,
		0x359EBB38ACEBB33AULL,
		0x25A56B8AF0B8C9FEULL,
		0x4580BAE05F511F79ULL,
		0x9829649324ED4073ULL,
		0x8ADD57E8BF58EB5FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5270994B68E0689DULL,
		0xDA4879441F9BCBAEULL,
		0xFFCB161467CA3521ULL,
		0x5AACD25F518BA884ULL,
		0xF682A96738D2C2D5ULL,
		0xD2661F855B8D283EULL,
		0x0E3B15058F04956FULL,
		0x488610AD9EC7D404ULL
	}};
	sign = 0;
	printf("Test Case 282\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 282 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -282;
	} else {
		printf("Test Case 282 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD7C8DA9D466DECEDULL,
		0x53DCD6F992F855BBULL,
		0x9376C2037F452200ULL,
		0xD2FB5CFC47B0C3EEULL,
		0x709CA343B2D0A515ULL,
		0x50956A1F73B923ECULL,
		0x0FCDA0DC105C6097ULL,
		0x6462E19029F1D4AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55BFDA07776BFEF8ULL,
		0x268F9EE5D9CC6C05ULL,
		0xB5025EB77B9BE04DULL,
		0x23BAF2E56ADC9DA9ULL,
		0x0E2C31E4D1F3166AULL,
		0x98605E0EDB9652BFULL,
		0xFD61D1E0DD7E9F66ULL,
		0x99BEC4939618C5DFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x82090095CF01EDF5ULL,
		0x2D4D3813B92BE9B6ULL,
		0xDE74634C03A941B3ULL,
		0xAF406A16DCD42644ULL,
		0x6270715EE0DD8EABULL,
		0xB8350C109822D12DULL,
		0x126BCEFB32DDC130ULL,
		0xCAA41CFC93D90ECEULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 283\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 283 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -283;
	} else {
		printf("Test Case 283 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x208337DB55CB43AFULL,
		0xF5298BF05B33D7F8ULL,
		0x71E97D4A53EC2981ULL,
		0x3482766C51890623ULL,
		0xF0280E05BD47A3A7ULL,
		0xE8753B0DC2445B96ULL,
		0xBAF4BB4846BE78F9ULL,
		0xE1E560A922AA9A5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE35069FC03C1A4A6ULL,
		0x879D324BC27C213DULL,
		0x5359892E39657790ULL,
		0x04A51830D798736CULL,
		0x60892769E43501E9ULL,
		0x7FAF6199135D2748ULL,
		0x05F277287603F68BULL,
		0xCFC300931367353AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3D32CDDF52099F09ULL,
		0x6D8C59A498B7B6BAULL,
		0x1E8FF41C1A86B1F1ULL,
		0x2FDD5E3B79F092B7ULL,
		0x8F9EE69BD912A1BEULL,
		0x68C5D974AEE7344EULL,
		0xB502441FD0BA826EULL,
		0x122260160F436523ULL
	}};
	sign = 0;
	printf("Test Case 284\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 284 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -284;
	} else {
		printf("Test Case 284 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0680C45F67753413ULL,
		0x314D4BC10487033FULL,
		0xD65A285A23C5E66EULL,
		0x5D818E76568E9161ULL,
		0xA639145ED2477C27ULL,
		0xCB200C8D8F43FC52ULL,
		0xA3D17DCA06C5819CULL,
		0x742F7B4F252C794AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF004DFDB464BAC9AULL,
		0x127AD142731DE317ULL,
		0x27F825E76A787F94ULL,
		0x956925A03DF63913ULL,
		0x911893AD3B26B7B5ULL,
		0x47735ABD1B4F8647ULL,
		0x12B9FBE49C4E6386ULL,
		0x29DC63F520637373ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x167BE48421298779ULL,
		0x1ED27A7E91692027ULL,
		0xAE620272B94D66DAULL,
		0xC81868D61898584EULL,
		0x152080B19720C471ULL,
		0x83ACB1D073F4760BULL,
		0x911781E56A771E16ULL,
		0x4A53175A04C905D7ULL
	}};
	sign = 0;
	printf("Test Case 285\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 285 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -285;
	} else {
		printf("Test Case 285 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDC7286B4A5CF765BULL,
		0x953A017AD9183F54ULL,
		0x44FCFEF4026057F9ULL,
		0xEFFF9F614D51CC60ULL,
		0x36D931B2E2672F68ULL,
		0x57BC21CB5005AEC8ULL,
		0xF3470D8EC15DF964ULL,
		0xE7AE5B6F84EC68E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8EFE2F53AB2094C5ULL,
		0x855456C43F4F03C3ULL,
		0x9CE6E5017F000921ULL,
		0x89EF770403A08AF4ULL,
		0x19905E67CB2353E4ULL,
		0xFC18CEF856BE9975ULL,
		0xC0B34F121D0EEAB5ULL,
		0x89F8C3660103587AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4D745760FAAEE196ULL,
		0x0FE5AAB699C93B91ULL,
		0xA81619F283604ED8ULL,
		0x6610285D49B1416BULL,
		0x1D48D34B1743DB84ULL,
		0x5BA352D2F9471553ULL,
		0x3293BE7CA44F0EAEULL,
		0x5DB5980983E91066ULL
	}};
	sign = 0;
	printf("Test Case 286\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 286 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -286;
	} else {
		printf("Test Case 286 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x490335DAE3137267ULL,
		0xA7DA87E7258AD865ULL,
		0x93E2FA07D4C54311ULL,
		0x9D3540E160E69221ULL,
		0x25EE31FE8CAB8956ULL,
		0x5E8A9F1DFCC76F55ULL,
		0xD0D99C1EFBE0D3C4ULL,
		0x898F56FB97A7F64FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6020E393998EF7E3ULL,
		0xA4DEB5AE238032B7ULL,
		0x5CC84F995F40AFDFULL,
		0x2B8D37CDB9F9EF00ULL,
		0x77FB31AECC523B4FULL,
		0x0DA5D6F558F38B16ULL,
		0x8DCCE467962356BBULL,
		0x3AE595FF93A6B8ADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE8E2524749847A84ULL,
		0x02FBD239020AA5ADULL,
		0x371AAA6E75849332ULL,
		0x71A80913A6ECA321ULL,
		0xADF3004FC0594E07ULL,
		0x50E4C828A3D3E43EULL,
		0x430CB7B765BD7D09ULL,
		0x4EA9C0FC04013DA2ULL
	}};
	sign = 0;
	printf("Test Case 287\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 287 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -287;
	} else {
		printf("Test Case 287 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDCE21CE6FA9FA9C9ULL,
		0x969E2D3DC0C96652ULL,
		0x7D7BCAF30608AD69ULL,
		0x53CE774C23806FBFULL,
		0xCEEC379888657A6BULL,
		0x87A8EA50055D3DFCULL,
		0xD16247B2C3B74802ULL,
		0xD61A8B042D3D57F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB994201A37FAB98ULL,
		0xD85AAFA00D62C6BFULL,
		0x9139F831DDC1B26CULL,
		0xEEA86E88C31B8D23ULL,
		0xE1F2AA0B50088195ULL,
		0xBEE43AB45AB6C574ULL,
		0x9A65D2480F525C46ULL,
		0x685500916184BFB1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0148DAE5571FFE31ULL,
		0xBE437D9DB3669F93ULL,
		0xEC41D2C12846FAFCULL,
		0x652608C36064E29BULL,
		0xECF98D8D385CF8D5ULL,
		0xC8C4AF9BAAA67887ULL,
		0x36FC756AB464EBBBULL,
		0x6DC58A72CBB89845ULL
	}};
	sign = 0;
	printf("Test Case 288\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 288 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -288;
	} else {
		printf("Test Case 288 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBB19F76BF14A80EDULL,
		0x799C56197A51DFEDULL,
		0xDA9974BDF973FC8BULL,
		0x4D2EF46FA9E6C38AULL,
		0x0BC43C4F9FB40EACULL,
		0xC77E9762CF74F163ULL,
		0x823B054D5259B841ULL,
		0x4AA9FE6B943F59C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59392634F0DC027CULL,
		0x7D97684D74443C3BULL,
		0xC11174167BB7D1D9ULL,
		0xACFF503540B2FF88ULL,
		0x7FE6227F01183509ULL,
		0xC383E30D0E6D4E4FULL,
		0x6EB99128BA8B06E4ULL,
		0x89033607A234E993ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x61E0D137006E7E71ULL,
		0xFC04EDCC060DA3B2ULL,
		0x198800A77DBC2AB1ULL,
		0xA02FA43A6933C402ULL,
		0x8BDE19D09E9BD9A2ULL,
		0x03FAB455C107A313ULL,
		0x1381742497CEB15DULL,
		0xC1A6C863F20A7032ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 289\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 289 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -289;
	} else {
		printf("Test Case 289 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3B4848E0FDB66711ULL,
		0x6966161CDBD803E8ULL,
		0xE95D537F54C69B64ULL,
		0x26F4834207DE02E9ULL,
		0x25FA7D8CE2836927ULL,
		0x75267FC3C3E2147CULL,
		0x1673C0517AE63B86ULL,
		0xA4E1415A32E02276ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F291AAAF9B51A56ULL,
		0x17ED8064C0B5A3DCULL,
		0x3C8233EAA4F65CE7ULL,
		0x2A1E43414C51C242ULL,
		0x5ED3CBFEF9ECDF13ULL,
		0x7E1C84F7653599C7ULL,
		0x9CB381137A2D4262ULL,
		0x57AA07BD4334A259ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBC1F2E3604014CBBULL,
		0x517895B81B22600BULL,
		0xACDB1F94AFD03E7DULL,
		0xFCD64000BB8C40A7ULL,
		0xC726B18DE8968A13ULL,
		0xF709FACC5EAC7AB4ULL,
		0x79C03F3E00B8F923ULL,
		0x4D37399CEFAB801CULL
	}};
	sign = 0;
	printf("Test Case 290\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 290 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -290;
	} else {
		printf("Test Case 290 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x64CCEDD893F8CBE3ULL,
		0x6F8007222ACB8375ULL,
		0xDBDC09938C018B3AULL,
		0xAD6CFC475C232831ULL,
		0x83BBCF857DFC6E58ULL,
		0xE6737A805C67A20CULL,
		0x35F3FAF0E2EC3E34ULL,
		0x757EB32CBCAF655EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BA2F41DADBDE630ULL,
		0x60982DA508E6E617ULL,
		0xAEBF1BA63908F2EDULL,
		0xF9B8CD1ECC57721DULL,
		0x050EE717567784C4ULL,
		0x0C0983AFF4EE5D8EULL,
		0xB9D87F0746C9881DULL,
		0x7455EFA21AE3D5B1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5929F9BAE63AE5B3ULL,
		0x0EE7D97D21E49D5EULL,
		0x2D1CEDED52F8984DULL,
		0xB3B42F288FCBB614ULL,
		0x7EACE86E2784E993ULL,
		0xDA69F6D06779447EULL,
		0x7C1B7BE99C22B617ULL,
		0x0128C38AA1CB8FACULL
	}};
	sign = 0;
	printf("Test Case 291\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 291 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -291;
	} else {
		printf("Test Case 291 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1E4F0509BB7D6BF1ULL,
		0x629DCEBAF796464CULL,
		0xDA58270062B2EBFCULL,
		0xD4E261D715D81B52ULL,
		0x56E02A1202947BC9ULL,
		0x8524875287EC3CC9ULL,
		0x396676EBB5DB811CULL,
		0xB74094BB74BF87FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B63F6936994002FULL,
		0x9E036081E08C3E8CULL,
		0x0D491E98011C103BULL,
		0x3BF03B8DE03DF607ULL,
		0x4B9C07F64773501FULL,
		0xD00591292EB9FDBBULL,
		0x79410E568CDA495EULL,
		0x61B1A3E02084D82DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC2EB0E7651E96BC2ULL,
		0xC49A6E39170A07BFULL,
		0xCD0F08686196DBC0ULL,
		0x98F22649359A254BULL,
		0x0B44221BBB212BAAULL,
		0xB51EF62959323F0EULL,
		0xC0256895290137BDULL,
		0x558EF0DB543AAFCDULL
	}};
	sign = 0;
	printf("Test Case 292\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 292 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -292;
	} else {
		printf("Test Case 292 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF12EB2E4425CCF78ULL,
		0x8A565F92B2FD6183ULL,
		0x1A0D184A0F47FD0EULL,
		0x1856BC960FC0316EULL,
		0xF55DDC9054DA2424ULL,
		0xA91CA6201028EAE4ULL,
		0xCA04A0C9E33594B4ULL,
		0x626A725888513947ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14E38D27A9D24890ULL,
		0x87407AA7C6027097ULL,
		0x991E5F7E6F9C8C90ULL,
		0xF05E711901AEADD6ULL,
		0x82938EA6C5128970ULL,
		0x08D2962194684168ULL,
		0xE11871E87E7AE7B2ULL,
		0x1783F4EEFC6FB67BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDC4B25BC988A86E8ULL,
		0x0315E4EAECFAF0ECULL,
		0x80EEB8CB9FAB707EULL,
		0x27F84B7D0E118397ULL,
		0x72CA4DE98FC79AB3ULL,
		0xA04A0FFE7BC0A97CULL,
		0xE8EC2EE164BAAD02ULL,
		0x4AE67D698BE182CBULL
	}};
	sign = 0;
	printf("Test Case 293\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 293 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -293;
	} else {
		printf("Test Case 293 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7C78E74195C78BA8ULL,
		0xC75C9F5FE5E0F2CAULL,
		0x4BED5840F82731C5ULL,
		0x046ADBB5B7FD2D7EULL,
		0x4C6940FA6F839CE6ULL,
		0xEAFA4C8FBF66973EULL,
		0x3ADF79590524C0E3ULL,
		0x2EE1938029406613ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F2946C1F9713EC5ULL,
		0xD6E6E389BB40AFF7ULL,
		0x26438F66F902BA4BULL,
		0xFA5A1C9B300F2761ULL,
		0x2309CBBDFFC90138ULL,
		0xB9F5AB328AAF488CULL,
		0x4B2BF5258CD4DD42ULL,
		0xC434471E2EA5A5AFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6D4FA07F9C564CE3ULL,
		0xF075BBD62AA042D3ULL,
		0x25A9C8D9FF247779ULL,
		0x0A10BF1A87EE061DULL,
		0x295F753C6FBA9BADULL,
		0x3104A15D34B74EB2ULL,
		0xEFB38433784FE3A1ULL,
		0x6AAD4C61FA9AC063ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 294\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 294 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -294;
	} else {
		printf("Test Case 294 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x33CF009CCF6CF963ULL,
		0xC5359F84A3D3196AULL,
		0x32168D31DE12C010ULL,
		0x747630957816D4D6ULL,
		0x28578ED4D8A2CA83ULL,
		0xC714A5F929D01349ULL,
		0xF9E739927D35560CULL,
		0x57A1481F9CEA2452ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18F6310CE45EDE24ULL,
		0x05731D62CF2E9C4FULL,
		0x2BD600EB73B30734ULL,
		0x89C3CE8CC887FC30ULL,
		0xF55D18CC6A500F08ULL,
		0xBA30C28C54722E4BULL,
		0x8C94EA2E903C249DULL,
		0xF17365B6A2F42FB7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1AD8CF8FEB0E1B3FULL,
		0xBFC28221D4A47D1BULL,
		0x06408C466A5FB8DCULL,
		0xEAB26208AF8ED8A6ULL,
		0x32FA76086E52BB7AULL,
		0x0CE3E36CD55DE4FDULL,
		0x6D524F63ECF9316FULL,
		0x662DE268F9F5F49BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 295\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 295 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -295;
	} else {
		printf("Test Case 295 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0DDA421AF888C308ULL,
		0x38F040B7B93235C7ULL,
		0xF305F80A53767F94ULL,
		0x50FF1B681D36046EULL,
		0x7EC7BCBF31573945ULL,
		0xAC58C8F1F09423FCULL,
		0x696F6C9263ABDD33ULL,
		0x430A3E39C91824EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3E3B9B99AC80FA5ULL,
		0x550698AA56CD47F1ULL,
		0xE1F70324C6A027F5ULL,
		0x6215283E6BEBBD41ULL,
		0x0962551D3FF0107AULL,
		0x375F102B25A16C36ULL,
		0x6359C3F1F18E808DULL,
		0x4312458CF486F239ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x19F688615DC0B363ULL,
		0xE3E9A80D6264EDD5ULL,
		0x110EF4E58CD6579EULL,
		0xEEE9F329B14A472DULL,
		0x756567A1F16728CAULL,
		0x74F9B8C6CAF2B7C6ULL,
		0x0615A8A0721D5CA6ULL,
		0xFFF7F8ACD49132B2ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 296\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 296 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -296;
	} else {
		printf("Test Case 296 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE414E480CE1A4E49ULL,
		0x32E85CBDF68C652EULL,
		0x338DA557D7452FA9ULL,
		0x57A25AFC38EC020DULL,
		0x95737F402F7A56D7ULL,
		0x87E27776126D7328ULL,
		0xBD65B80D813055D8ULL,
		0x7152AA1CA078C875ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE861576ED89629A4ULL,
		0x8718FA89B4C4A7BFULL,
		0x03DE67708AB7833BULL,
		0x04D6D467AF1EA3C1ULL,
		0xEBA039C9808A6A8BULL,
		0x453F5E46B4004F6AULL,
		0x52E053697AD533D4ULL,
		0xEC58356B3A594D26ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFBB38D11F58424A5ULL,
		0xABCF623441C7BD6EULL,
		0x2FAF3DE74C8DAC6DULL,
		0x52CB869489CD5E4CULL,
		0xA9D34576AEEFEC4CULL,
		0x42A3192F5E6D23BDULL,
		0x6A8564A4065B2204ULL,
		0x84FA74B1661F7B4FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 297\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 297 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -297;
	} else {
		printf("Test Case 297 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1BEFF9DAFE38A8E9ULL,
		0x61790E3F5E7068E0ULL,
		0x0173B143E2FFF819ULL,
		0x73A6E3AFA47F1AFDULL,
		0xDAA9DCEC5BDBEA44ULL,
		0x6F85F6A2478023CDULL,
		0xFCCFEFC2187B2E0CULL,
		0x59EE338D45C7E2C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDEEAB622609163FULL,
		0xA83DB8195E29DB30ULL,
		0x794534637B5E689CULL,
		0x1C9293E0326FB86CULL,
		0x09EACC39344C13F2ULL,
		0xA0AC70C2D93AF140ULL,
		0x22EDDF167F9639A0ULL,
		0xCD9E8755EDBE3757ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1E014E78D82F92AAULL,
		0xB93B562600468DAFULL,
		0x882E7CE067A18F7CULL,
		0x57144FCF720F6290ULL,
		0xD0BF10B3278FD652ULL,
		0xCED985DF6E45328DULL,
		0xD9E210AB98E4F46BULL,
		0x8C4FAC375809AB72ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 298\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 298 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -298;
	} else {
		printf("Test Case 298 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC1A099D4CA2A63E1ULL,
		0xB9539F2CA0A4D91CULL,
		0x7F926A8E9D5367C5ULL,
		0x30A2A1C80CB7084BULL,
		0x42754A5836496756ULL,
		0x209278879F3D7610ULL,
		0x55563FAF40582C0EULL,
		0x13B39C182764702BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F58E7F1E3A44318ULL,
		0x85CCBCD3EAB5F08DULL,
		0xE95D0FEA6DB3024CULL,
		0x713B94A87875B607ULL,
		0xCE2A53B88592D6CFULL,
		0x7340F7253EB2D2E6ULL,
		0x6FD8FEA220237776ULL,
		0x55136B7F1A547A42ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8247B1E2E68620C9ULL,
		0x3386E258B5EEE88FULL,
		0x96355AA42FA06579ULL,
		0xBF670D1F94415243ULL,
		0x744AF69FB0B69086ULL,
		0xAD518162608AA329ULL,
		0xE57D410D2034B497ULL,
		0xBEA030990D0FF5E8ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 299\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 299 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -299;
	} else {
		printf("Test Case 299 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC6DDCC6C939D31B2ULL,
		0xD6571708BFA2EADCULL,
		0xCD61A490F210DAA0ULL,
		0x7D448B60F5771AE9ULL,
		0x01E388AECB8E1FADULL,
		0x2BFEB2BF350ECD24ULL,
		0x1B1F7DEC4BD10929ULL,
		0x85DC5D29BC85787AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE49C147EA306BAEULL,
		0x294753AD798E492DULL,
		0x74EA4017EBCFF4E0ULL,
		0xFB9C9B9C5DB2B50FULL,
		0xAFA8FAA3846671ECULL,
		0xB9BF73B968406D66ULL,
		0xC283DE6312F4A4AAULL,
		0x22342F9EA0AFAA00ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE8940B24A96CC604ULL,
		0xAD0FC35B4614A1AEULL,
		0x587764790640E5C0ULL,
		0x81A7EFC497C465DAULL,
		0x523A8E0B4727ADC0ULL,
		0x723F3F05CCCE5FBDULL,
		0x589B9F8938DC647EULL,
		0x63A82D8B1BD5CE79ULL
	}};
	sign = 0;
	printf("Test Case 300\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 300 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -300;
	} else {
		printf("Test Case 300 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x188A1FB1BD440675ULL,
		0x1D80AD66662418ACULL,
		0xACBA7370BF8C9F2CULL,
		0x69FCD5D520C47014ULL,
		0xA76203A2BCCCCE35ULL,
		0xA913B390AACA1677ULL,
		0x4FEC7700059D9EFCULL,
		0xB5C8EF814909DA86ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43D00723AC47099EULL,
		0xF81E5BEE79722EF9ULL,
		0xB13CC2B0B6929D67ULL,
		0xBB4365C3F1407FE2ULL,
		0x383CA563EFFC1DBCULL,
		0x70C96EFE7AB1E326ULL,
		0x896AD181B733E6F3ULL,
		0x56E9F3A7DE9F0D4FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD4BA188E10FCFCD7ULL,
		0x25625177ECB1E9B2ULL,
		0xFB7DB0C008FA01C4ULL,
		0xAEB970112F83F031ULL,
		0x6F255E3ECCD0B078ULL,
		0x384A449230183351ULL,
		0xC681A57E4E69B809ULL,
		0x5EDEFBD96A6ACD36ULL
	}};
	sign = 0;
	printf("Test Case 301\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 301 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -301;
	} else {
		printf("Test Case 301 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x96C8144C2BD2E7ABULL,
		0x68BDD6311AEC0B9AULL,
		0x600CE59D7C41C294ULL,
		0xBEDD0382E7982C89ULL,
		0x519D53A227BC21EAULL,
		0xA5CE217C2BA412A1ULL,
		0x9FF3898C25772890ULL,
		0xFE74D5E7243F525CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD9F75CD88FFFEEAULL,
		0xFFDA126D86A1C991ULL,
		0x3A8EC8A60788703CULL,
		0x8DD9343E6BDCA268ULL,
		0x628EDCFA8F2CFA2EULL,
		0xF9563989C448BB3AULL,
		0x63532D238EC2BE7CULL,
		0x7DEE73B1AC1C4E0AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD9289E7EA2D2E8C1ULL,
		0x68E3C3C3944A4208ULL,
		0x257E1CF774B95257ULL,
		0x3103CF447BBB8A21ULL,
		0xEF0E76A7988F27BCULL,
		0xAC77E7F2675B5766ULL,
		0x3CA05C6896B46A13ULL,
		0x8086623578230452ULL
	}};
	sign = 0;
	printf("Test Case 302\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 302 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -302;
	} else {
		printf("Test Case 302 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x02453720256EAAADULL,
		0xF508E2B48BD5E13CULL,
		0x86A6E96435AE283CULL,
		0x9BDD0C7C35CF1E3DULL,
		0xA6290C040CDD3242ULL,
		0x7AC986B7919812BAULL,
		0x902BAAF626E6A4A2ULL,
		0x2C6CA5A5189D7CF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x543CAE38B1574CE8ULL,
		0x82784BB45A551AFAULL,
		0xCC860D4A1F94AB75ULL,
		0xAA43127FC34B04D6ULL,
		0xDC1511B4EE2DED5CULL,
		0x52E7BF5D9FB40697ULL,
		0xAC391AEB458A84D4ULL,
		0x9C948929E11C689AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAE0888E774175DC5ULL,
		0x729097003180C641ULL,
		0xBA20DC1A16197CC7ULL,
		0xF199F9FC72841966ULL,
		0xCA13FA4F1EAF44E5ULL,
		0x27E1C759F1E40C22ULL,
		0xE3F2900AE15C1FCEULL,
		0x8FD81C7B3781145CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 303\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 303 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -303;
	} else {
		printf("Test Case 303 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x76C0B2F94D7E7DA5ULL,
		0xE59AA80D887A42C9ULL,
		0x24BF872E5F39ADFEULL,
		0x7164A35311ACBCA0ULL,
		0xA7B8249EA79B6F37ULL,
		0x6899D26A423C296BULL,
		0x84A943E1AD888A1DULL,
		0xED667CE394DB92C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4F64DD95370BCB7ULL,
		0x5623F8869C985627ULL,
		0xBAC403971160C381ULL,
		0xCDECCE7FF628BA87ULL,
		0xA1E2FA7663FC9590ULL,
		0xD5D99689E655C2A5ULL,
		0x4501BE23E38A0995ULL,
		0xA15A9BB3E8B9D705ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD1CA651FFA0DC0EEULL,
		0x8F76AF86EBE1ECA1ULL,
		0x69FB83974DD8EA7DULL,
		0xA377D4D31B840218ULL,
		0x05D52A28439ED9A6ULL,
		0x92C03BE05BE666C6ULL,
		0x3FA785BDC9FE8087ULL,
		0x4C0BE12FAC21BBC4ULL
	}};
	sign = 0;
	printf("Test Case 304\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 304 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -304;
	} else {
		printf("Test Case 304 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x65D1D12CB639BA7BULL,
		0x1ECB37999AE83729ULL,
		0x6EDDB335EA922280ULL,
		0xE6542DC420B1A2B0ULL,
		0x2C45DDB9FEB78D87ULL,
		0x3ED60144C10AC7BDULL,
		0x49E430681910966EULL,
		0x2D0EC4C5FF9653AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB69A4B5E3B66EEFCULL,
		0x0F314F81DDFE0D93ULL,
		0x5BBE78CF2CCAB80EULL,
		0x1F56736FD317511CULL,
		0xB7F08166BB229BF8ULL,
		0x881B61F7B845A9C7ULL,
		0xA23A9FAD80940309ULL,
		0xA435710EA645B473ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAF3785CE7AD2CB7FULL,
		0x0F99E817BCEA2995ULL,
		0x131F3A66BDC76A72ULL,
		0xC6FDBA544D9A5194ULL,
		0x74555C534394F18FULL,
		0xB6BA9F4D08C51DF5ULL,
		0xA7A990BA987C9364ULL,
		0x88D953B759509F3AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 305\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 305 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -305;
	} else {
		printf("Test Case 305 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x629F9697D2BE093DULL,
		0xAD82693BC89F2CD4ULL,
		0x1DC46303B1F83D97ULL,
		0x075BB8D11161625FULL,
		0xFE3E4604201871ADULL,
		0x9A09473D117C7989ULL,
		0xF7FD19F42264750AULL,
		0xCCBC77EFB7CDBC95ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFDF9A0FB0B424D3ULL,
		0xFE412238237F362AULL,
		0x0D688876687E8087ULL,
		0x93DE20A01FE095C7ULL,
		0xB118E027B301047FULL,
		0x1055C820362E19BBULL,
		0x2E3783DDFE6483BFULL,
		0x77FBBF09C3BC901FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x62BFFC882209E46AULL,
		0xAF414703A51FF6A9ULL,
		0x105BDA8D4979BD0FULL,
		0x737D9830F180CC98ULL,
		0x4D2565DC6D176D2DULL,
		0x89B37F1CDB4E5FCEULL,
		0xC9C5961623FFF14BULL,
		0x54C0B8E5F4112C76ULL
	}};
	sign = 0;
	printf("Test Case 306\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 306 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -306;
	} else {
		printf("Test Case 306 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4ACB468EC9013B50ULL,
		0x58D1ABEF00F2340BULL,
		0xB2BC81EDFECBE6FCULL,
		0xF4703E9CD6451552ULL,
		0xE9E49BD8231A1D26ULL,
		0x04CC2C6DE10CF6F5ULL,
		0xC8E97836D8A74D3CULL,
		0x587F9FF548E7365AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA86E1B39AD0EE54EULL,
		0x03E9CA24DB6D6A48ULL,
		0x219CCC0FE9F2BA76ULL,
		0xA1AB56C004C2F19AULL,
		0xD47E01E942C4674DULL,
		0xDED117BF5A06BAA7ULL,
		0x457F117C76F98D82ULL,
		0xBCB23F580F6021CFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA25D2B551BF25602ULL,
		0x54E7E1CA2584C9C2ULL,
		0x911FB5DE14D92C86ULL,
		0x52C4E7DCD18223B8ULL,
		0x156699EEE055B5D9ULL,
		0x25FB14AE87063C4EULL,
		0x836A66BA61ADBFB9ULL,
		0x9BCD609D3987148BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 307\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 307 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -307;
	} else {
		printf("Test Case 307 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE25054C52936473DULL,
		0x5A1E6D649559F657ULL,
		0xCABD61714C71D970ULL,
		0xE5CD86B75C84DF36ULL,
		0x61035DC9C2B61C08ULL,
		0xF01C4301C49F954BULL,
		0xD783FB8441D3016FULL,
		0xF5FFF17BA595C9BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D0D737BCAE4269DULL,
		0x34BC0E42ACCE0536ULL,
		0x995F3ECB45475602ULL,
		0x1952D277273856B5ULL,
		0x86B72EC0C13E3926ULL,
		0x4397F50D6CEEDB7FULL,
		0x71446F3ECFC15ABDULL,
		0xA49818B5A8106BA1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4542E1495E5220A0ULL,
		0x25625F21E88BF121ULL,
		0x315E22A6072A836EULL,
		0xCC7AB440354C8881ULL,
		0xDA4C2F090177E2E2ULL,
		0xAC844DF457B0B9CBULL,
		0x663F8C457211A6B2ULL,
		0x5167D8C5FD855E19ULL
	}};
	sign = 0;
	printf("Test Case 308\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 308 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -308;
	} else {
		printf("Test Case 308 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2462BEACE0BA4F48ULL,
		0x9821B48414BA10A7ULL,
		0xD53E26BC2C148C52ULL,
		0xA3034B6AD31005DFULL,
		0xA2163B498F9B7472ULL,
		0x07A57906728D8020ULL,
		0x4CC32E77319AAF60ULL,
		0xBEA4EA13910142E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4801C3157A944A05ULL,
		0x86BC5A59ECC33361ULL,
		0x8F145ABAA42B8F34ULL,
		0xD438ADD3E1E74D5DULL,
		0x42949B783C9FCFDBULL,
		0xCA8A9418C53DE28BULL,
		0xE7DC4071EAB99818ULL,
		0x84DBD76EAC7C8072ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDC60FB9766260543ULL,
		0x11655A2A27F6DD45ULL,
		0x4629CC0187E8FD1EULL,
		0xCECA9D96F128B882ULL,
		0x5F819FD152FBA496ULL,
		0x3D1AE4EDAD4F9D95ULL,
		0x64E6EE0546E11747ULL,
		0x39C912A4E484C272ULL
	}};
	sign = 0;
	printf("Test Case 309\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 309 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -309;
	} else {
		printf("Test Case 309 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF74ACD6774CFF274ULL,
		0x43F1FD6728CA34BEULL,
		0xFF17946E0AF61BE9ULL,
		0xD3F7EC574AE4982CULL,
		0xA9920CA6633D2EA7ULL,
		0xC06E6213F26AD2E0ULL,
		0x17889A3DDB1A38DEULL,
		0x79A274F4615669F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE233D77FCA820BA0ULL,
		0x41A67D0040DE8068ULL,
		0x1ED2F807CFD9CE73ULL,
		0x8E23DE4B0C6493F4ULL,
		0x54C59EFF3DB9BE70ULL,
		0xE3AD39F2C4783836ULL,
		0x9F649ED97D65A32EULL,
		0x6E3B1D57C0312558ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1516F5E7AA4DE6D4ULL,
		0x024B8066E7EBB456ULL,
		0xE0449C663B1C4D76ULL,
		0x45D40E0C3E800438ULL,
		0x54CC6DA725837037ULL,
		0xDCC128212DF29AAAULL,
		0x7823FB645DB495AFULL,
		0x0B67579CA1254499ULL
	}};
	sign = 0;
	printf("Test Case 310\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 310 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -310;
	} else {
		printf("Test Case 310 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9501DB43AF757C02ULL,
		0xA136E46914B0F121ULL,
		0xF056690FD398F6A2ULL,
		0x48BE14F3AD7A9F8DULL,
		0xCEF96326B785C5CAULL,
		0xE2BCFB69E6694F86ULL,
		0x28E5BA1997507C5CULL,
		0xEEF8A49F3379E540ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3835192FCF72F4DAULL,
		0x169D8064F4926199ULL,
		0x857F564CABAF2344ULL,
		0x9FAE51CD5F341C3DULL,
		0x8590E47047519EEEULL,
		0x69F359A6BF9D7067ULL,
		0x869D22FDDD2820D4ULL,
		0x2295F13E849473E6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5CCCC213E0028728ULL,
		0x8A996404201E8F88ULL,
		0x6AD712C327E9D35EULL,
		0xA90FC3264E468350ULL,
		0x49687EB6703426DBULL,
		0x78C9A1C326CBDF1FULL,
		0xA248971BBA285B88ULL,
		0xCC62B360AEE57159ULL
	}};
	sign = 0;
	printf("Test Case 311\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 311 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -311;
	} else {
		printf("Test Case 311 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C9EC49B2D5064D2ULL,
		0x3AB28C67E4449C7DULL,
		0x835B03087590FE10ULL,
		0x0F4C3E9F752F4B98ULL,
		0x5357B54AD69026A7ULL,
		0x7848810C647697D8ULL,
		0x03799E277C33956EULL,
		0x876D87C6B01D9E30ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41FF97AA1E2FBE44ULL,
		0x2D1A01CCBC796A92ULL,
		0xD76B33F958213A9DULL,
		0x46F42BC1CDD822BAULL,
		0xDF481CFC28D6107FULL,
		0x8F867CAD03A30BA1ULL,
		0x3FA4A41F5CDAE288ULL,
		0x86DC0AE9105B974FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4A9F2CF10F20A68EULL,
		0x0D988A9B27CB31EBULL,
		0xABEFCF0F1D6FC373ULL,
		0xC85812DDA75728DDULL,
		0x740F984EADBA1627ULL,
		0xE8C2045F60D38C36ULL,
		0xC3D4FA081F58B2E5ULL,
		0x00917CDD9FC206E0ULL
	}};
	sign = 0;
	printf("Test Case 312\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 312 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -312;
	} else {
		printf("Test Case 312 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x89162FA5442B92AFULL,
		0xB29AF206324DD1A2ULL,
		0xC950E270939EFA0BULL,
		0x26419C2A767E38C3ULL,
		0x679684122BF06C46ULL,
		0x919E28DAD78FE3AEULL,
		0x93E9C59C6ED92F6AULL,
		0x6F01A57F2E39D336ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EEC4ECDF53985E3ULL,
		0x3514F35D5A9FF06AULL,
		0x45367AF14D5F1F32ULL,
		0x7F5E074CAAA75396ULL,
		0x8498F6AA11745E81ULL,
		0x2944FFF22E271886ULL,
		0x595BD1CE9E9629B3ULL,
		0x3F6FE2B891032869ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7A29E0D74EF20CCCULL,
		0x7D85FEA8D7ADE138ULL,
		0x841A677F463FDAD9ULL,
		0xA6E394DDCBD6E52DULL,
		0xE2FD8D681A7C0DC4ULL,
		0x685928E8A968CB27ULL,
		0x3A8DF3CDD04305B7ULL,
		0x2F91C2C69D36AACDULL
	}};
	sign = 0;
	printf("Test Case 313\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 313 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -313;
	} else {
		printf("Test Case 313 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEC65B2BAE07CA743ULL,
		0x4AE7AC2565AB09CCULL,
		0x06A02DE75137BE8AULL,
		0x7FC2BC12BA6DA306ULL,
		0x0BD1BEE422CAECC6ULL,
		0xD980B432D4F385DBULL,
		0x80A2ED54E9A831FCULL,
		0x9288C3A20505E69FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4FBF41236422D22ULL,
		0x541D108911709FDBULL,
		0x9327DCBAFA67F728ULL,
		0x73E63F2FEAF753EEULL,
		0x58AA521782A0E3A9ULL,
		0x4054B309000C39B7ULL,
		0x576435027CF225B6ULL,
		0x2B3A85ABA4E12F41ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3769BEA8AA3A7A21ULL,
		0xF6CA9B9C543A69F1ULL,
		0x7378512C56CFC761ULL,
		0x0BDC7CE2CF764F17ULL,
		0xB3276CCCA02A091DULL,
		0x992C0129D4E74C23ULL,
		0x293EB8526CB60C46ULL,
		0x674E3DF66024B75EULL
	}};
	sign = 0;
	printf("Test Case 314\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 314 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -314;
	} else {
		printf("Test Case 314 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1664114C32907B5FULL,
		0x6859AE8A2CC498DAULL,
		0xE3BC28A6647C75C1ULL,
		0x986C83B970EF79EFULL,
		0xF9F54B48A6E87920ULL,
		0x654BC4775F780B53ULL,
		0x5F3A25EE162B4446ULL,
		0x3972FC1BCAD04C8EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB17154CF42687201ULL,
		0x7C429B997DFDF4FEULL,
		0xBB12BCD9ACDF8DAAULL,
		0xDEFF7B2D5E8B33EDULL,
		0x58C3C7AEE44A64C0ULL,
		0x597FA99A41B83937ULL,
		0x5F43D58258276709ULL,
		0x4165DD160E633884ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x64F2BC7CF028095EULL,
		0xEC1712F0AEC6A3DBULL,
		0x28A96BCCB79CE816ULL,
		0xB96D088C12644602ULL,
		0xA1318399C29E145FULL,
		0x0BCC1ADD1DBFD21CULL,
		0xFFF6506BBE03DD3DULL,
		0xF80D1F05BC6D1409ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 315\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 315 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -315;
	} else {
		printf("Test Case 315 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB4B10061B005ED8EULL,
		0xB060B0594F4EE93CULL,
		0x741C42DA5B909DF5ULL,
		0x2E0837DF734F1AC2ULL,
		0xB695FB913F0646D0ULL,
		0x208738426F845EFCULL,
		0x81E74A3F0A4E4045ULL,
		0xCCF32A54D9B43426ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55E38B92E645FE1DULL,
		0xCA38F712A399E49FULL,
		0xA6F22A762BD0623BULL,
		0xED8306D32465C52CULL,
		0x6B3A4DBAC53AE03FULL,
		0xAABD60D0C020A212ULL,
		0x9069BF2B9B94E6DBULL,
		0x4AC72ACE5F1C2F10ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5ECD74CEC9BFEF71ULL,
		0xE627B946ABB5049DULL,
		0xCD2A18642FC03BB9ULL,
		0x4085310C4EE95595ULL,
		0x4B5BADD679CB6690ULL,
		0x75C9D771AF63BCEAULL,
		0xF17D8B136EB95969ULL,
		0x822BFF867A980515ULL
	}};
	sign = 0;
	printf("Test Case 316\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 316 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -316;
	} else {
		printf("Test Case 316 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x89DA3895F6B3AF11ULL,
		0x74DE9272FB3CD4F0ULL,
		0x4331BE8A33CB5B0DULL,
		0x3096ED2C92F12247ULL,
		0x03B4A3CDD24023A2ULL,
		0xD2D2396582EA3FD4ULL,
		0x5D6A34F804418533ULL,
		0xF4E0D41A12CAB98DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE87129054E4ACED4ULL,
		0x6A34EA5E9306FD2DULL,
		0xB5195C689B777461ULL,
		0xC565CB4CB419BB05ULL,
		0xD82243FADA62F8C1ULL,
		0xE84A1B858D8358C2ULL,
		0x5C1F8BF34DA9B9D5ULL,
		0x24D1A2946CAF7549ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA1690F90A868E03DULL,
		0x0AA9A8146835D7C2ULL,
		0x8E1862219853E6ACULL,
		0x6B3121DFDED76741ULL,
		0x2B925FD2F7DD2AE0ULL,
		0xEA881DDFF566E711ULL,
		0x014AA904B697CB5DULL,
		0xD00F3185A61B4444ULL
	}};
	sign = 0;
	printf("Test Case 317\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 317 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -317;
	} else {
		printf("Test Case 317 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE963E5D1F327EB85ULL,
		0x161A59BCFD48F500ULL,
		0xF6DDDB48B5ED4AE1ULL,
		0x4394C5918F7141D3ULL,
		0x72168A5141D6C7C7ULL,
		0x334813D2E94DDDF2ULL,
		0x69A7B320D3011387ULL,
		0x371AD172899FB738ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x269920ABB022A5F6ULL,
		0xEDF88D39FB6AF00EULL,
		0x629D4D60B224599EULL,
		0x5D374FC93D5EA464ULL,
		0x7ED7E96ABE76E4ACULL,
		0xB97BBB6807174772ULL,
		0xA4D6E385D05A0DB6ULL,
		0xB05B8F79FBB58C4DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC2CAC5264305458FULL,
		0x2821CC8301DE04F2ULL,
		0x94408DE803C8F142ULL,
		0xE65D75C852129D6FULL,
		0xF33EA0E6835FE31AULL,
		0x79CC586AE236967FULL,
		0xC4D0CF9B02A705D0ULL,
		0x86BF41F88DEA2AEAULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 318\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 318 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -318;
	} else {
		printf("Test Case 318 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9D634DC22EC58071ULL,
		0x04947F7A3CFE053DULL,
		0x871854276E82FECBULL,
		0x5A81C6C11BF479C5ULL,
		0x2A1BB739BA9231E3ULL,
		0x8AC106C543F3050AULL,
		0xFD2B9A243A115DF8ULL,
		0x607FB8DE48071EC2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B79BB7353492006ULL,
		0xF91EFD9A9C74C047ULL,
		0x6B7FA189C8570E24ULL,
		0xE4B287D780844CF3ULL,
		0x3021917E62DA3A37ULL,
		0x6519DBA207A977B6ULL,
		0x1F3A06A3AD0DD538ULL,
		0x9D92B2CBCE37476EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01E9924EDB7C606BULL,
		0x0B7581DFA08944F6ULL,
		0x1B98B29DA62BF0A6ULL,
		0x75CF3EE99B702CD2ULL,
		0xF9FA25BB57B7F7ABULL,
		0x25A72B233C498D53ULL,
		0xDDF193808D0388C0ULL,
		0xC2ED061279CFD754ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 319\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 319 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -319;
	} else {
		printf("Test Case 319 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x944DCC6D78028E95ULL,
		0x4BB587C8134F2B3AULL,
		0x60F379B5AF7FB4A0ULL,
		0x748723BE13B72179ULL,
		0x9A94B08BDD3B2AC7ULL,
		0x79F70D0CD4717BCDULL,
		0xFDBFD5BE3D92A07BULL,
		0x8E704AD25147BAECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84AD450892DD5891ULL,
		0xBAB6DFA7563D2AFAULL,
		0x786138CEBCF18EACULL,
		0x06D7E99A0E372789ULL,
		0xBA61588542497293ULL,
		0x5E6B13025240B5E1ULL,
		0x81A0E6050B852E99ULL,
		0x7ECB546A9363798BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0FA08764E5253604ULL,
		0x90FEA820BD120040ULL,
		0xE89240E6F28E25F3ULL,
		0x6DAF3A24057FF9EFULL,
		0xE03358069AF1B834ULL,
		0x1B8BFA0A8230C5EBULL,
		0x7C1EEFB9320D71E2ULL,
		0x0FA4F667BDE44161ULL
	}};
	sign = 0;
	printf("Test Case 320\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 320 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -320;
	} else {
		printf("Test Case 320 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1F84CF936E41576AULL,
		0xE9FDED8263D09F23ULL,
		0x6D6746A60D333519ULL,
		0x359184428A178819ULL,
		0xE9772985050AF4F2ULL,
		0x89BC4E44D68F1E27ULL,
		0xAC063E92422F54FFULL,
		0x6039C5BE3FD15BE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2F66CFAEAB392AFULL,
		0x85F65B440936D38BULL,
		0x337A3167ABBAE88DULL,
		0xA7AAD5192BFB6163ULL,
		0x8EB88390D0D83EE7ULL,
		0x0E25D467C84DE14BULL,
		0xA8D5CAE886F5AEB8ULL,
		0xA21AE926BE18E527ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5C8E6298838DC4BBULL,
		0x6407923E5A99CB97ULL,
		0x39ED153E61784C8CULL,
		0x8DE6AF295E1C26B6ULL,
		0x5ABEA5F43432B60AULL,
		0x7B9679DD0E413CDCULL,
		0x033073A9BB39A647ULL,
		0xBE1EDC9781B876C1ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 321\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 321 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -321;
	} else {
		printf("Test Case 321 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3F97D1C08A41879EULL,
		0xA8A6C5F4B831F364ULL,
		0x566DDFFFE21DBB59ULL,
		0xB766A1FC6922A039ULL,
		0x02E12878F4C8AE5EULL,
		0x358DB7560A7AD1D2ULL,
		0x8DE8B978142E624CULL,
		0x23416567B6C12339ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9BD28B8CFA30319ULL,
		0x03FDD0462EB1EB90ULL,
		0xA14CCEBC8526F9B5ULL,
		0x5FAC548CFECE2EBFULL,
		0xFFE5E091A9E09E6BULL,
		0xB65897404C3F6796ULL,
		0x4BD0B2C5CE411870ULL,
		0xE6AE20FCBE813FF3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x75DAA907BA9E8485ULL,
		0xA4A8F5AE898007D3ULL,
		0xB52111435CF6C1A4ULL,
		0x57BA4D6F6A547179ULL,
		0x02FB47E74AE80FF3ULL,
		0x7F352015BE3B6A3BULL,
		0x421806B245ED49DBULL,
		0x3C93446AF83FE346ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 322\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 322 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -322;
	} else {
		printf("Test Case 322 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x028D51019D2AD543ULL,
		0xA1D99BB1EC038B5AULL,
		0x88F59699D7283F72ULL,
		0xA7D35C4E25A2109EULL,
		0x9CD16D188332E009ULL,
		0x5389AFE11F77423BULL,
		0x953F5D7C16A0122EULL,
		0x8588BD0099719570ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73E3EE51342A95E1ULL,
		0xBA60ED45EF59C782ULL,
		0x049254B1450E68E9ULL,
		0xF4A1E2CF0DE8D9E3ULL,
		0x3748A41520B78416ULL,
		0x8E1C0AC0B9633384ULL,
		0x9117E5296A16EC54ULL,
		0xDEC94E30ECE23E1AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8EA962B069003F62ULL,
		0xE778AE6BFCA9C3D7ULL,
		0x846341E89219D688ULL,
		0xB331797F17B936BBULL,
		0x6588C903627B5BF2ULL,
		0xC56DA52066140EB7ULL,
		0x04277852AC8925D9ULL,
		0xA6BF6ECFAC8F5756ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 323\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 323 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -323;
	} else {
		printf("Test Case 323 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD7CF80AD55BB852DULL,
		0xFF884FBAA7BA73DFULL,
		0x99863BD12AF34F4CULL,
		0x05D9BCB73A13BE43ULL,
		0x0FE5B49AAAAE3923ULL,
		0xFDC7987143A0A897ULL,
		0x0ED4828EC2463CC0ULL,
		0xA7503B4D1E69DFB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x474535AE25B4DAE3ULL,
		0x041F0C1AE05561E2ULL,
		0x19412FF2ABD21865ULL,
		0xACCCA81A000ACEB9ULL,
		0x3549BD6E773BAFB4ULL,
		0xD782BB2C12A0E585ULL,
		0x278A74A5A3C4684BULL,
		0xDBBBC503180621D5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x908A4AFF3006AA4AULL,
		0xFB69439FC76511FDULL,
		0x80450BDE7F2136E7ULL,
		0x590D149D3A08EF8AULL,
		0xDA9BF72C3372896EULL,
		0x2644DD4530FFC311ULL,
		0xE74A0DE91E81D475ULL,
		0xCB94764A0663BDDAULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 324\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 324 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -324;
	} else {
		printf("Test Case 324 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFB7CA1827E69595BULL,
		0x66780F05BB4A1214ULL,
		0x72773063E6B10C7CULL,
		0x02D871B4875D6B30ULL,
		0xF806EA655DE45602ULL,
		0xEB9DB5C3A92D0287ULL,
		0x2CA28FB173646C15ULL,
		0x40A04D2673108F05ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BA9C14564D1AE2CULL,
		0x7969125944880D32ULL,
		0xFF9B63F157B8C713ULL,
		0x72C5C8FAE939E403ULL,
		0xF9180B578AEFDE30ULL,
		0xD33285F43B46AB4AULL,
		0xD90F348E1B7942C4ULL,
		0x117F0400EE9A69B9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAFD2E03D1997AB2FULL,
		0xED0EFCAC76C204E2ULL,
		0x72DBCC728EF84568ULL,
		0x9012A8B99E23872CULL,
		0xFEEEDF0DD2F477D1ULL,
		0x186B2FCF6DE6573CULL,
		0x53935B2357EB2951ULL,
		0x2F2149258476254BULL
	}};
	sign = 0;
	printf("Test Case 325\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 325 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -325;
	} else {
		printf("Test Case 325 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAAAD1A317DA57B25ULL,
		0x67FB2E3B51D68487ULL,
		0x647B77C32BFC6CF3ULL,
		0xD5FA9CC350A65D9DULL,
		0x816F597B02B62B3CULL,
		0x19CB4EA6AC13E576ULL,
		0x0BA6AE2E89319A92ULL,
		0xC300767D8D6E1EDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92AB1FB2234CDFEAULL,
		0xC0D7B9C6A85100F8ULL,
		0xCCA1819A5AD25871ULL,
		0x99FDBDF7E3169AD8ULL,
		0xB6450B988E12550BULL,
		0x7606E7CAD393C930ULL,
		0x7402C1AD924E1DE3ULL,
		0x2C21B3355A63BD40ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1801FA7F5A589B3BULL,
		0xA7237474A985838FULL,
		0x97D9F628D12A1481ULL,
		0x3BFCDECB6D8FC2C4ULL,
		0xCB2A4DE274A3D631ULL,
		0xA3C466DBD8801C45ULL,
		0x97A3EC80F6E37CAEULL,
		0x96DEC348330A619BULL
	}};
	sign = 0;
	printf("Test Case 326\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 326 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -326;
	} else {
		printf("Test Case 326 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB5FFF3150E5A87A3ULL,
		0x27840CB87EBE8FA6ULL,
		0xCCE64C0558B38566ULL,
		0x7C38C68F558A1792ULL,
		0x8AC08DFECB3974BCULL,
		0x4DF51EA382B7AEF7ULL,
		0x899C587D69F32483ULL,
		0xAF002B2E292B0C01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FC3388D350630B1ULL,
		0x7EDE9FA77B12C7F2ULL,
		0xEE10453A71097147ULL,
		0x3D9664AE56DC9F16ULL,
		0xACD9C4046950DE06ULL,
		0xD374BA91FC1D7C62ULL,
		0x82D7646B748C4045ULL,
		0x0169FA79A22FCB11ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x363CBA87D95456F2ULL,
		0xA8A56D1103ABC7B4ULL,
		0xDED606CAE7AA141EULL,
		0x3EA261E0FEAD787BULL,
		0xDDE6C9FA61E896B6ULL,
		0x7A806411869A3294ULL,
		0x06C4F411F566E43DULL,
		0xAD9630B486FB40F0ULL
	}};
	sign = 0;
	printf("Test Case 327\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 327 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -327;
	} else {
		printf("Test Case 327 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA50097185F3A77BFULL,
		0x2726925A3613EBE3ULL,
		0x0802D6AAAA039EF5ULL,
		0x84366BACE1B4AD41ULL,
		0x0D4E0DA441AFB362ULL,
		0xF87EDB00084DD488ULL,
		0x20BE4A3971944FCAULL,
		0x80A3066FA5941947ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x442C0F9314A22661ULL,
		0x295B417705A7E1D6ULL,
		0x7775651F558D1C1DULL,
		0x744DC4F301007665ULL,
		0xB8605E4D66578983ULL,
		0xA6F4336F5F949BE8ULL,
		0xCEF45AF7A19DB273ULL,
		0x0400591C8BA42E13ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x60D487854A98515EULL,
		0xFDCB50E3306C0A0DULL,
		0x908D718B547682D7ULL,
		0x0FE8A6B9E0B436DBULL,
		0x54EDAF56DB5829DFULL,
		0x518AA790A8B9389FULL,
		0x51C9EF41CFF69D57ULL,
		0x7CA2AD5319EFEB33ULL
	}};
	sign = 0;
	printf("Test Case 328\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 328 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -328;
	} else {
		printf("Test Case 328 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA97085DC826798C7ULL,
		0x17B97E7FC52BB091ULL,
		0xDBCCCD404F528C8EULL,
		0x484899FBA2224B32ULL,
		0x5822E1D2F6BF322CULL,
		0x2556B3ABB3680A6BULL,
		0x17E82F09F3FB9C34ULL,
		0x323538E0CEC3B3E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD080D1A6D4470F40ULL,
		0x725F75CC3CEFD081ULL,
		0x4DCCB34573634E53ULL,
		0xF6B866668153E171ULL,
		0x450D6BF21FE217BFULL,
		0xBE744DCB419CAF4DULL,
		0xFFFAEF3DB4F93D30ULL,
		0x3E1DADAEC42E9B93ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD8EFB435AE208987ULL,
		0xA55A08B3883BE00FULL,
		0x8E0019FADBEF3E3AULL,
		0x5190339520CE69C1ULL,
		0x131575E0D6DD1A6CULL,
		0x66E265E071CB5B1EULL,
		0x17ED3FCC3F025F03ULL,
		0xF4178B320A95184CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 329\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 329 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -329;
	} else {
		printf("Test Case 329 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x841B4CBA6180C621ULL,
		0x43DD5D7CF1F76BDEULL,
		0x9CAF130EB23A4E35ULL,
		0x62998F11FB85F64EULL,
		0x739C4985F553E8DEULL,
		0x5568E32DC886761EULL,
		0x53628E946D414DFCULL,
		0x47F82D1EFD301363ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x729F218400DDA7C5ULL,
		0x07D7E93CB93F0876ULL,
		0x01B767D9958B6C8FULL,
		0xC1A69516B81D0EFDULL,
		0x0B56B30BB4C2F4E9ULL,
		0x23A21D5E14211FC5ULL,
		0x6607405B848D8DBDULL,
		0x97C1246B34CDD6EDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x117C2B3660A31E5CULL,
		0x3C05744038B86368ULL,
		0x9AF7AB351CAEE1A6ULL,
		0xA0F2F9FB4368E751ULL,
		0x6845967A4090F3F4ULL,
		0x31C6C5CFB4655659ULL,
		0xED5B4E38E8B3C03FULL,
		0xB03708B3C8623C75ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 330\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 330 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -330;
	} else {
		printf("Test Case 330 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAA83D9D52C45096CULL,
		0x0B188ADBEEC7D012ULL,
		0x701E3FCEFEBC55B8ULL,
		0x3D3DC1A2EB8E7828ULL,
		0x01F77F7AE97B0064ULL,
		0x49D8BAF8CAC45A1DULL,
		0x0E92827AE0E75A77ULL,
		0x53129B9FFF4CF597ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4F53FE81C894D8EULL,
		0xAF49D4E6A3C96BCEULL,
		0x9136C213E31DF8D7ULL,
		0xDC5DB98EB2B26E17ULL,
		0xBEBAB73724B060C8ULL,
		0x7C5FA595E687B087ULL,
		0x7D4CDFEC38F36D3CULL,
		0xE38F203708017A82ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC58E99ED0FBBBBDEULL,
		0x5BCEB5F54AFE6443ULL,
		0xDEE77DBB1B9E5CE0ULL,
		0x60E0081438DC0A10ULL,
		0x433CC843C4CA9F9BULL,
		0xCD791562E43CA995ULL,
		0x9145A28EA7F3ED3AULL,
		0x6F837B68F74B7B14ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 331\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 331 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -331;
	} else {
		printf("Test Case 331 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x351BE95450672ABDULL,
		0xB3C92C701FC4D1D9ULL,
		0x7497580500113488ULL,
		0x6918323316051324ULL,
		0xEE1E84846198688FULL,
		0x8A4C74B7C417EBE8ULL,
		0x1AB4938DD783C9FFULL,
		0x61F8E02099BCE964ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB087E8711293FECDULL,
		0x229DE9C99E6F3DC5ULL,
		0xF5A5B39E55A7729DULL,
		0x1B24CBE90915A81BULL,
		0x20C0D95208089867ULL,
		0x7EBE4C4A133A0ED2ULL,
		0xEC545ED26A0253EBULL,
		0x0179441B806296F6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x849400E33DD32BF0ULL,
		0x912B42A681559413ULL,
		0x7EF1A466AA69C1EBULL,
		0x4DF3664A0CEF6B08ULL,
		0xCD5DAB32598FD028ULL,
		0x0B8E286DB0DDDD16ULL,
		0x2E6034BB6D817614ULL,
		0x607F9C05195A526DULL
	}};
	sign = 0;
	printf("Test Case 332\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 332 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -332;
	} else {
		printf("Test Case 332 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC5448168742664FFULL,
		0x790E10346C5CB50DULL,
		0xBB4A6F7FA5994122ULL,
		0x40FEBB145BB229A4ULL,
		0x1FFB7344F9A18F3AULL,
		0xB5A5D13A869F6F42ULL,
		0xE20058A6DC46C9FDULL,
		0xC22892FA180915EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17DD4CEA1FDE2721ULL,
		0xA183EEB3517B7DE4ULL,
		0x1460AC7A51A00897ULL,
		0xF795C95399EE86F9ULL,
		0x7331AA2B90674CA3ULL,
		0x4FB9052ABB51E0F5ULL,
		0x09C3AC82F03CF4F1ULL,
		0x819B25CF457AD895ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAD67347E54483DDEULL,
		0xD78A21811AE13729ULL,
		0xA6E9C30553F9388AULL,
		0x4968F1C0C1C3A2ABULL,
		0xACC9C919693A4296ULL,
		0x65ECCC0FCB4D8E4CULL,
		0xD83CAC23EC09D50CULL,
		0x408D6D2AD28E3D59ULL
	}};
	sign = 0;
	printf("Test Case 333\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 333 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -333;
	} else {
		printf("Test Case 333 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF5909ABF4CC46A0AULL,
		0x43F73C50CEC1BD83ULL,
		0xD394B1CCAE8A3531ULL,
		0x17544216F9825F52ULL,
		0xEDBB484489A18743ULL,
		0x812D8EB55CA00F6EULL,
		0x0DD33252D98148CAULL,
		0x53CF4D3131D33F58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD9EE950B51C9D3EULL,
		0xECC8D0649439DAAEULL,
		0xB6C0336C7C92D574ULL,
		0xB1194D8E9FB09DADULL,
		0xF943BBF7F9EF971FULL,
		0x737BDC2316073CD1ULL,
		0x93235430CDCCCD51ULL,
		0x365BB034CD24F5E6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x47F1B16E97A7CCCCULL,
		0x572E6BEC3A87E2D5ULL,
		0x1CD47E6031F75FBCULL,
		0x663AF48859D1C1A5ULL,
		0xF4778C4C8FB1F023ULL,
		0x0DB1B2924698D29CULL,
		0x7AAFDE220BB47B79ULL,
		0x1D739CFC64AE4971ULL
	}};
	sign = 0;
	printf("Test Case 334\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 334 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -334;
	} else {
		printf("Test Case 334 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA6CB7FA88311DC93ULL,
		0x3F4F6CE5805F4D79ULL,
		0xE418A9CF87AB26B5ULL,
		0x195F3D026628D599ULL,
		0xA176DD9D51AE4D8EULL,
		0xD22C6F020802C603ULL,
		0xF7F333E9968C0BB4ULL,
		0xC9C7C0D94B30B5FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51E040ED1AFDA34FULL,
		0xDE543514F93EB321ULL,
		0xED947C92AB829B9FULL,
		0x3C804696B8484E5DULL,
		0x7A50FA36BB0AB01AULL,
		0xFE9DBB5A5F41BB88ULL,
		0x818148C1BC40FBE6ULL,
		0x26B6117F3C0FC165ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x54EB3EBB68143944ULL,
		0x60FB37D087209A58ULL,
		0xF6842D3CDC288B15ULL,
		0xDCDEF66BADE0873BULL,
		0x2725E36696A39D73ULL,
		0xD38EB3A7A8C10A7BULL,
		0x7671EB27DA4B0FCDULL,
		0xA311AF5A0F20F498ULL
	}};
	sign = 0;
	printf("Test Case 335\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 335 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -335;
	} else {
		printf("Test Case 335 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC046E69756405E66ULL,
		0x87F4BC043A86843AULL,
		0x29A195A097F1FB19ULL,
		0x2BF45416A00154C1ULL,
		0x83560EE296CCA8BAULL,
		0xEB0858DE02511382ULL,
		0x3416F7569BB7A5A6ULL,
		0x5F27731D2D75C515ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC32E383D8EF0979ULL,
		0x0EC01A974876C5DBULL,
		0x826CB5D58AECD4D7ULL,
		0xD698F57D6C2BB7DCULL,
		0xBEE5B8ABE33E8169ULL,
		0xCFBAC9787477147DULL,
		0xCE996A9A87402230ULL,
		0xFE2710A4AF76759AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD41403137D5154EDULL,
		0x7934A16CF20FBE5EULL,
		0xA734DFCB0D052642ULL,
		0x555B5E9933D59CE4ULL,
		0xC4705636B38E2750ULL,
		0x1B4D8F658DD9FF04ULL,
		0x657D8CBC14778376ULL,
		0x610062787DFF4F7AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 336\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 336 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -336;
	} else {
		printf("Test Case 336 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2426B667BEDE12B8ULL,
		0xBA9E74B88A5BEC16ULL,
		0xD1145D6E61CE84D8ULL,
		0xAB3ACE5017D7457DULL,
		0x14A618D72CCDAC26ULL,
		0xB757F589C0C627C4ULL,
		0x149C3BE0850C875BULL,
		0x2E63E7929285BA4FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8AE27F3E1149319AULL,
		0xA64F592C66B4D299ULL,
		0xF3C68A0F613B1E9BULL,
		0x86AC6F1FDD20E83BULL,
		0xCB3C7CEC9FBEEB78ULL,
		0x8784CF12E900D0BFULL,
		0x448C61C89E3F32B5ULL,
		0xE04BADF37DA84986ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x99443729AD94E11EULL,
		0x144F1B8C23A7197CULL,
		0xDD4DD35F0093663DULL,
		0x248E5F303AB65D41ULL,
		0x49699BEA8D0EC0AEULL,
		0x2FD32676D7C55704ULL,
		0xD00FDA17E6CD54A6ULL,
		0x4E18399F14DD70C8ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 337\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 337 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -337;
	} else {
		printf("Test Case 337 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEA6066655B58BACAULL,
		0x728D94DCF54C562BULL,
		0xB4092AB172BC14F9ULL,
		0x3FBEB96923280D95ULL,
		0xA9F8C62EA5373162ULL,
		0xD473AEBF6BF28643ULL,
		0x909968937D85FC77ULL,
		0xA5082BA5200408F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37F9C23B2052CD4EULL,
		0x66BF8C3F401795B1ULL,
		0x812D10EB85494537ULL,
		0x918F9A10A4B6D320ULL,
		0xB9B69BAD026BA092ULL,
		0x06AD9CF1092823A9ULL,
		0x20F9C2F025C61ADFULL,
		0xD762F9B2717FB3B4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB266A42A3B05ED7CULL,
		0x0BCE089DB534C07AULL,
		0x32DC19C5ED72CFC2ULL,
		0xAE2F1F587E713A75ULL,
		0xF0422A81A2CB90CFULL,
		0xCDC611CE62CA6299ULL,
		0x6F9FA5A357BFE198ULL,
		0xCDA531F2AE845544ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 338\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 338 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -338;
	} else {
		printf("Test Case 338 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5AD09C52D2FB7397ULL,
		0x94457CA4F39D109DULL,
		0xDDE8E3BBB24B40ABULL,
		0x814BD09729C99C04ULL,
		0xC6CC8938FD773C0FULL,
		0xA2709B8869023F0EULL,
		0x66F461E1B68D3E1FULL,
		0xFB078FD4754C4860ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31B90CD1F3E500E6ULL,
		0xC244ADCE5B8C9826ULL,
		0x129E3C7A87D1C069ULL,
		0xF50F417A3FA6A141ULL,
		0xB81B37707886D241ULL,
		0xBC3E87259C431FC8ULL,
		0xB616FD87241EEC04ULL,
		0xA93FD4B71DD531B7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x29178F80DF1672B1ULL,
		0xD200CED698107877ULL,
		0xCB4AA7412A798041ULL,
		0x8C3C8F1CEA22FAC3ULL,
		0x0EB151C884F069CDULL,
		0xE6321462CCBF1F46ULL,
		0xB0DD645A926E521AULL,
		0x51C7BB1D577716A8ULL
	}};
	sign = 0;
	printf("Test Case 339\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 339 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -339;
	} else {
		printf("Test Case 339 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4B6B46CE89D5082AULL,
		0x0042CD2E62D264F4ULL,
		0x62CE25ABBF013912ULL,
		0x0ABDFBAB0B19042FULL,
		0xC6AE221B6F77C43EULL,
		0x47FAFFD9AE7F26F8ULL,
		0x987F67DAFE9DC422ULL,
		0x0997B33D08F9FAC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D33DFC2CF23FE1EULL,
		0x674D42263454CC92ULL,
		0x8BE7BB0D9A919C86ULL,
		0xC536EE23E2BFA626ULL,
		0x08125644CC676797ULL,
		0xEAEDED3B2A09E0E1ULL,
		0x9F3393AA10DEFCD9ULL,
		0xCC9F0F18DAA3A2B4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E37670BBAB10A0CULL,
		0x98F58B082E7D9862ULL,
		0xD6E66A9E246F9C8BULL,
		0x45870D8728595E08ULL,
		0xBE9BCBD6A3105CA6ULL,
		0x5D0D129E84754617ULL,
		0xF94BD430EDBEC748ULL,
		0x3CF8A4242E565813ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 340\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 340 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -340;
	} else {
		printf("Test Case 340 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD4B730CC9CEC4363ULL,
		0xBB6EDB58B671EC20ULL,
		0x278B775F4083E567ULL,
		0xCBC83D496B6B8187ULL,
		0x4D0F1A94DBA5EE5FULL,
		0xC077E6BD42901059ULL,
		0x7C21BF17D1537719ULL,
		0xDF570F314A3761EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B664A0806BBF6DAULL,
		0x02D0D1EB1A94A880ULL,
		0x6716871DCE930DA1ULL,
		0x03480F7D5B574798ULL,
		0x8DAB74C4C81D5DF2ULL,
		0xBAAE10E523E89968ULL,
		0x0D45BD05AED5E393ULL,
		0xF8B94434DFA40C0FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6950E6C496304C89ULL,
		0xB89E096D9BDD43A0ULL,
		0xC074F04171F0D7C6ULL,
		0xC8802DCC101439EEULL,
		0xBF63A5D01388906DULL,
		0x05C9D5D81EA776F0ULL,
		0x6EDC0212227D9386ULL,
		0xE69DCAFC6A9355DBULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 341\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 341 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -341;
	} else {
		printf("Test Case 341 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC3490B63970518DBULL,
		0x8E058EA81D268BBEULL,
		0xF526CCE85CA3FECCULL,
		0x4F2F6A5D934FCADFULL,
		0x0A8B70BDB6D80ACBULL,
		0x2F236A94FBB3B81BULL,
		0x6589B4C158A29FB0ULL,
		0xBB2E8CD14FA4310BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCDD54ABEB4A21DFULL,
		0xE75FB57B87F58E3FULL,
		0x9418D9135883B1E7ULL,
		0x228AC8FF7659C94AULL,
		0xC812893825EFE29AULL,
		0xB8B40FFFF836CAFAULL,
		0x544FFC94AC015F7BULL,
		0xC2086588C9A4356CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC66BB6B7ABBAF6FCULL,
		0xA6A5D92C9530FD7EULL,
		0x610DF3D504204CE4ULL,
		0x2CA4A15E1CF60195ULL,
		0x4278E78590E82831ULL,
		0x766F5A95037CED20ULL,
		0x1139B82CACA14034ULL,
		0xF926274885FFFB9FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 342\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 342 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -342;
	} else {
		printf("Test Case 342 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC89C176B5F775B21ULL,
		0x9F25386AFA0CC7B6ULL,
		0x2E64E80E62BAA1A2ULL,
		0xC25C04AF2E60F51BULL,
		0xAE9879C0114E9EB8ULL,
		0x225BEAB74AA92922ULL,
		0xB87FA251F164ABD8ULL,
		0x83058E22C3915BF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F26D4D9D38B94D7ULL,
		0x3132EDF6F3FF7407ULL,
		0xC7B62F88D24F8EC4ULL,
		0x55945F84A92EBDCCULL,
		0x0F8CCECAB0E61A06ULL,
		0xE21466026B4C9CC1ULL,
		0xB939C3BB0DFBB831ULL,
		0x894CFCBDE3A11A3BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x597542918BEBC64AULL,
		0x6DF24A74060D53AFULL,
		0x66AEB885906B12DEULL,
		0x6CC7A52A8532374EULL,
		0x9F0BAAF5606884B2ULL,
		0x404784B4DF5C8C61ULL,
		0xFF45DE96E368F3A6ULL,
		0xF9B89164DFF041B4ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 343\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 343 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -343;
	} else {
		printf("Test Case 343 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x212BA7367966E89AULL,
		0x1904F30F5DBFDB8CULL,
		0x721F6CD3B96BB82CULL,
		0x1FBF5EF998C855F9ULL,
		0x9F39ABD9EC02527CULL,
		0xED439098D868A4E2ULL,
		0xC1EF942D32A05E35ULL,
		0x1E9FC7D6391B76ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x704C78576C82CA40ULL,
		0xE8B23445E4A40FE7ULL,
		0x796969DD0CB9201EULL,
		0x67854349B5E4F08EULL,
		0x5E856DB41274C151ULL,
		0xF02DF9FAADDE3E18ULL,
		0x2E80F8FFCAE13A97ULL,
		0xEFE464066F184F7BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB0DF2EDF0CE41E5AULL,
		0x3052BEC9791BCBA4ULL,
		0xF8B602F6ACB2980DULL,
		0xB83A1BAFE2E3656AULL,
		0x40B43E25D98D912AULL,
		0xFD15969E2A8A66CAULL,
		0x936E9B2D67BF239DULL,
		0x2EBB63CFCA032731ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 344\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 344 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -344;
	} else {
		printf("Test Case 344 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x227D81320609D17EULL,
		0x7999C644F13ADA27ULL,
		0xD9F38362C66AE6ACULL,
		0xEE11CD57418F42F9ULL,
		0x6AD0DCAF98068A33ULL,
		0x53407F3B3D83AD7AULL,
		0x31ED4942DFDE4B81ULL,
		0x174645E184190F4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x873B55CEE52C1C7AULL,
		0x0122225D0CC31E3CULL,
		0x4CE3DF56917349B7ULL,
		0x402BF0AE62CD94BDULL,
		0x11DED08A6F00DFF0ULL,
		0xD6AC7C4C3A5AF4C6ULL,
		0xE37C463F563132A6ULL,
		0x10441063A2189BC2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9B422B6320DDB504ULL,
		0x7877A3E7E477BBEAULL,
		0x8D0FA40C34F79CF5ULL,
		0xADE5DCA8DEC1AE3CULL,
		0x58F20C252905AA43ULL,
		0x7C9402EF0328B8B4ULL,
		0x4E71030389AD18DAULL,
		0x0702357DE2007387ULL
	}};
	sign = 0;
	printf("Test Case 345\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 345 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -345;
	} else {
		printf("Test Case 345 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5DFBC1AABDB5E966ULL,
		0xA62158831FC753A2ULL,
		0xF63CB0F29C4B8D64ULL,
		0xBEBB7910433631F5ULL,
		0x218F15FF9ADA4133ULL,
		0xC0DE73DDEDAA864AULL,
		0xDC3266E786C92B66ULL,
		0xA71555233E574DDFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF434D53337F18215ULL,
		0x745CB82D7C460DA1ULL,
		0x156263ACFC5D4D36ULL,
		0xFC19612267D57D63ULL,
		0x4F84BBADA39D161DULL,
		0xCA907C7B421D4A98ULL,
		0x79994012191CF3F5ULL,
		0x4C2B94F14E505700ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x69C6EC7785C46751ULL,
		0x31C4A055A3814600ULL,
		0xE0DA4D459FEE402EULL,
		0xC2A217EDDB60B492ULL,
		0xD20A5A51F73D2B15ULL,
		0xF64DF762AB8D3BB1ULL,
		0x629926D56DAC3770ULL,
		0x5AE9C031F006F6DFULL
	}};
	sign = 0;
	printf("Test Case 346\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 346 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -346;
	} else {
		printf("Test Case 346 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x293CC8DFF86200E4ULL,
		0x8A5ADF0B396361E1ULL,
		0x8DBE123FB20C6A48ULL,
		0xBF4A9AE001E47D2BULL,
		0x728917F0DBDCB0F6ULL,
		0x91FD59E6BA2481ABULL,
		0x2933472FD928B215ULL,
		0x7D133DF0F2BBD211ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF86D8ADF04EE3B3ULL,
		0x2600F665D05D590FULL,
		0x60AFDA3AC66D7689ULL,
		0xEA61E4375D73B4F0ULL,
		0xCA5A96DB03A783A6ULL,
		0x10DC30AE55ECDD5AULL,
		0x7183E692499862ADULL,
		0x01884C21D0FA9414ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x29B5F03208131D31ULL,
		0x6459E8A5690608D1ULL,
		0x2D0E3804EB9EF3BFULL,
		0xD4E8B6A8A470C83BULL,
		0xA82E8115D8352D4FULL,
		0x812129386437A450ULL,
		0xB7AF609D8F904F68ULL,
		0x7B8AF1CF21C13DFCULL
	}};
	sign = 0;
	printf("Test Case 347\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 347 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -347;
	} else {
		printf("Test Case 347 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD0A55DAA2A1B95ACULL,
		0xA3F240D2C327146FULL,
		0x506712BE87F87DB7ULL,
		0x1CDAEAB341DDA44DULL,
		0xC592CD7FFFBE4C38ULL,
		0xF3D3F901AE53C88FULL,
		0x1E3C3D8F8B2F4F39ULL,
		0x45879B83A8FF00D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD56ED2113B1C4C51ULL,
		0xD9F4DA24C52A256FULL,
		0x98FE000EBADE4F7FULL,
		0xBDB103214AF6DE56ULL,
		0xB650B688945C61EBULL,
		0xB238A39EACA39131ULL,
		0xA4B2B9DF01315E5BULL,
		0xAAFF9EB8DD327F3DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFB368B98EEFF495BULL,
		0xC9FD66ADFDFCEEFFULL,
		0xB76912AFCD1A2E37ULL,
		0x5F29E791F6E6C5F6ULL,
		0x0F4216F76B61EA4CULL,
		0x419B556301B0375EULL,
		0x798983B089FDF0DEULL,
		0x9A87FCCACBCC819AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 348\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 348 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -348;
	} else {
		printf("Test Case 348 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4E8A7E50F3DB44A8ULL,
		0x03D341221AC7698FULL,
		0x7F261AEC84559276ULL,
		0xCD8BE3655973E691ULL,
		0xA67405CD25099CB2ULL,
		0xC3724B6FA9D7A201ULL,
		0x003AF7B59331FB3BULL,
		0xF340EA28468A5CE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8302AB6892B5437ULL,
		0xF9A318F8ADBA6F71ULL,
		0x03F397E0878C2C64ULL,
		0x55E238FA265E0320ULL,
		0x78481058968EAB87ULL,
		0x0266692E4C5395B2ULL,
		0xCCFDF81F7B00F9DAULL,
		0x0F3BD8CC22E5DA52ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x565A539A6AAFF071ULL,
		0x0A3028296D0CFA1DULL,
		0x7B32830BFCC96611ULL,
		0x77A9AA6B3315E371ULL,
		0x2E2BF5748E7AF12BULL,
		0xC10BE2415D840C4FULL,
		0x333CFF9618310161ULL,
		0xE405115C23A48290ULL
	}};
	sign = 0;
	printf("Test Case 349\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 349 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -349;
	} else {
		printf("Test Case 349 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6138755E83DA3F20ULL,
		0x879645E6D0798530ULL,
		0x0AE182399B7D0800ULL,
		0xC04DB1B3E59CDCF2ULL,
		0x40C4A7DD8F1AED3EULL,
		0x0A576BB15BEF90D1ULL,
		0x511762EBB075A616ULL,
		0x7B53352B7448EE77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE20E58DE504E4BCULL,
		0xF0928CDA86BEEE02ULL,
		0xCCC84A6FA189A6D6ULL,
		0x3E3424479C28EDCFULL,
		0x29F855E6931131ABULL,
		0x3AD34D6505B4EB02ULL,
		0x5ED9E586098F2F6CULL,
		0x879C16FE656374B2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x93178FD09ED55A64ULL,
		0x9703B90C49BA972DULL,
		0x3E1937C9F9F36129ULL,
		0x82198D6C4973EF22ULL,
		0x16CC51F6FC09BB93ULL,
		0xCF841E4C563AA5CFULL,
		0xF23D7D65A6E676A9ULL,
		0xF3B71E2D0EE579C4ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 350\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 350 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -350;
	} else {
		printf("Test Case 350 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6FCF00F77AF9B028ULL,
		0xD9DC24BC33D76081ULL,
		0x0112E13AFB4DF700ULL,
		0x4C18C882B62C1BC9ULL,
		0xB3FF076EC55BDC47ULL,
		0xA674642813D5756BULL,
		0x930A2AFB8D551794ULL,
		0x6CB72AAB4633032EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8856ECA28796733AULL,
		0x8D2C9C24C10350F0ULL,
		0x3E8FBB7F3D9781B1ULL,
		0x3F450CD51F2920D9ULL,
		0x64EBE5B2A69C6161ULL,
		0x215A16555B25BB3AULL,
		0x166A17B032F77438ULL,
		0x930AE99906A6ADF7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE7781454F3633CEEULL,
		0x4CAF889772D40F90ULL,
		0xC28325BBBDB6754FULL,
		0x0CD3BBAD9702FAEFULL,
		0x4F1321BC1EBF7AE6ULL,
		0x851A4DD2B8AFBA31ULL,
		0x7CA0134B5A5DA35CULL,
		0xD9AC41123F8C5537ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 351\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 351 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -351;
	} else {
		printf("Test Case 351 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFBE8F2E82D770E2AULL,
		0x33E8C7B5CEDBC57EULL,
		0x8C40D09FFA7FB8C0ULL,
		0x0955A111B8A60DD2ULL,
		0x36028A5D1B7456BBULL,
		0xD3C5C4B67AF798DCULL,
		0xB86BEEF7D71C45B6ULL,
		0x872A1CC71DF5FFF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F5176150D733239ULL,
		0xDA6C63C1E11E428CULL,
		0x790F99A2D1B8FCB1ULL,
		0xC9C7D3B32638C387ULL,
		0x93A6C39CDEF26D0FULL,
		0x6E374C82CA9718E8ULL,
		0x33F0D3133E87E2CFULL,
		0xDC2B35CB359C09B8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCC977CD32003DBF1ULL,
		0x597C63F3EDBD82F2ULL,
		0x133136FD28C6BC0EULL,
		0x3F8DCD5E926D4A4BULL,
		0xA25BC6C03C81E9ABULL,
		0x658E7833B0607FF3ULL,
		0x847B1BE4989462E7ULL,
		0xAAFEE6FBE859F63CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 352\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 352 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -352;
	} else {
		printf("Test Case 352 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCADC8CE7370267A7ULL,
		0x319D0C9A0A51E14FULL,
		0x9CE003AA60A1C2CDULL,
		0xB309CB20E8394997ULL,
		0xE72B02EB5FE55837ULL,
		0x2D83351ABFC11665ULL,
		0x75C594749E2704A5ULL,
		0x7172939CB5B3A412ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2D6406F51BE42A9ULL,
		0x49CD435A8D4DC0A3ULL,
		0xF85350BD415107F7ULL,
		0xED6A2667FC193C54ULL,
		0x7C51B3689C67B0F8ULL,
		0x073FA8E0EBD08E2FULL,
		0xDDE268B8CB339EDAULL,
		0xBD316BCB25024EB7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD8064C77E54424FEULL,
		0xE7CFC93F7D0420ABULL,
		0xA48CB2ED1F50BAD5ULL,
		0xC59FA4B8EC200D42ULL,
		0x6AD94F82C37DA73EULL,
		0x26438C39D3F08836ULL,
		0x97E32BBBD2F365CBULL,
		0xB44127D190B1555AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 353\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 353 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -353;
	} else {
		printf("Test Case 353 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEB46E995822CE76DULL,
		0xE702A35D9B30811CULL,
		0xF5813FB940F43D8AULL,
		0xBA50E5ED4F69FBEAULL,
		0xD0F6548EE9495558ULL,
		0x7748EC42A7F5B4B8ULL,
		0x9AE7E30C862B7BEDULL,
		0x09CF4DC79B9D3866ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x174F045B07153662ULL,
		0x20D1F4B277F6161BULL,
		0xB6270258D0828B48ULL,
		0x7E9EF84EA2AFEAEDULL,
		0xF70509E5039CC816ULL,
		0x84B690A9D8DA5054ULL,
		0xA2DF0A0718ABD564ULL,
		0x63FAC6CDECBFDEE2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD3F7E53A7B17B10BULL,
		0xC630AEAB233A6B01ULL,
		0x3F5A3D607071B242ULL,
		0x3BB1ED9EACBA10FDULL,
		0xD9F14AA9E5AC8D42ULL,
		0xF2925B98CF1B6463ULL,
		0xF808D9056D7FA688ULL,
		0xA5D486F9AEDD5983ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 354\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 354 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -354;
	} else {
		printf("Test Case 354 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBF114590F3D93C47ULL,
		0x66B076B051158C4FULL,
		0x5C4A3253CB1A257EULL,
		0x44E3361D1CDD2642ULL,
		0x3C537902730740B7ULL,
		0xBBD30AD8F9990CDDULL,
		0xD638FD6F70F7897FULL,
		0x27F7E93DFC76C201ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58EDA818ADDE5BB4ULL,
		0xE9FF8EDB697B8200ULL,
		0xAC8F446F7BAC4645ULL,
		0x78158C40D17CEFB3ULL,
		0x850CF4EA3B1DC764ULL,
		0x0BE8222AD5202D0BULL,
		0x772350F578BDCCDAULL,
		0x5D8C86556499C415ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x66239D7845FAE093ULL,
		0x7CB0E7D4E79A0A4FULL,
		0xAFBAEDE44F6DDF38ULL,
		0xCCCDA9DC4B60368EULL,
		0xB746841837E97952ULL,
		0xAFEAE8AE2478DFD1ULL,
		0x5F15AC79F839BCA5ULL,
		0xCA6B62E897DCFDECULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 355\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 355 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -355;
	} else {
		printf("Test Case 355 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x02C852A06AE73284ULL,
		0xCE03FCA1265B0D8BULL,
		0xF905B2944D42B0CCULL,
		0x4F1995F6E1CB0D09ULL,
		0xD9C21A0DEBAF658EULL,
		0xC899DE26659191A8ULL,
		0x0A3841504BB80A69ULL,
		0x0B12773DD3FAB19BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2ABA55E609552690ULL,
		0xBE0E1F6B7DC8C145ULL,
		0xF2F9F8E5EFF07313ULL,
		0xECDF807A5F6CB3CDULL,
		0x570F9C87F25FD8F4ULL,
		0x5C24CE2183F6F451ULL,
		0x98425641D8F2E39CULL,
		0x929C2959DDADA859ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD80DFCBA61920BF4ULL,
		0x0FF5DD35A8924C45ULL,
		0x060BB9AE5D523DB9ULL,
		0x623A157C825E593CULL,
		0x82B27D85F94F8C99ULL,
		0x6C751004E19A9D57ULL,
		0x71F5EB0E72C526CDULL,
		0x78764DE3F64D0941ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 356\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 356 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -356;
	} else {
		printf("Test Case 356 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9F1708FD00F05116ULL,
		0x6FEA92063E76B449ULL,
		0x018FA2341E060C6EULL,
		0x2EEA93A742E77EE0ULL,
		0xEFDC63943F35809DULL,
		0x24C101D53D4E3003ULL,
		0x9085653420F29F65ULL,
		0x41FEC97AEA651444ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DF881A7FA107B14ULL,
		0x2E8212BF496AC05AULL,
		0x84E04CB36240018CULL,
		0xF2C917D108031D74ULL,
		0xAB1EA39D1D021C35ULL,
		0x56AEB4CFB5C783AAULL,
		0x4D9AE5359C1C06CCULL,
		0xC8CDFC58B436766FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x311E875506DFD602ULL,
		0x41687F46F50BF3EFULL,
		0x7CAF5580BBC60AE2ULL,
		0x3C217BD63AE4616BULL,
		0x44BDBFF722336467ULL,
		0xCE124D058786AC59ULL,
		0x42EA7FFE84D69898ULL,
		0x7930CD22362E9DD5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 357\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 357 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -357;
	} else {
		printf("Test Case 357 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4A6205E1FA3E7A1DULL,
		0x3C542AF1FDC873EAULL,
		0x7E2F2FB9CAFE4CA2ULL,
		0x1B4FCA4D91EDD549ULL,
		0xC6D04FC7D4CE2BE4ULL,
		0xB741A0969ABFB24FULL,
		0x0AA8FC01835F0AE8ULL,
		0x05A0FE7D073F32CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC22C7DDD4FA6B46AULL,
		0xEEAA2660D0A2E434ULL,
		0x77157E87842D40D5ULL,
		0x467F9F2B278F8AE7ULL,
		0xCA6156ACD4A3DD71ULL,
		0x7370658DA8C7E0F6ULL,
		0x84C7CA9B5286C107ULL,
		0x68C50C324BF3647CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x88358804AA97C5B3ULL,
		0x4DAA04912D258FB5ULL,
		0x0719B13246D10BCCULL,
		0xD4D02B226A5E4A62ULL,
		0xFC6EF91B002A4E72ULL,
		0x43D13B08F1F7D158ULL,
		0x85E1316630D849E1ULL,
		0x9CDBF24ABB4BCE52ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 358\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 358 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -358;
	} else {
		printf("Test Case 358 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0FF42CC8DDDBA8C3ULL,
		0xAB154F75B1C00F0DULL,
		0x4A9A9B3A9F9F3792ULL,
		0x221125A210E95D29ULL,
		0x8CA67DF74715E638ULL,
		0xC80CA56D203F2297ULL,
		0xB36D015B7AF1F1E0ULL,
		0xBE3E2A58C2D4038EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB0EFC6A65D4A3DBULL,
		0xB41076C167F40FEFULL,
		0xF9B2DF93A1B00F21ULL,
		0x1AD1795A1D963AF4ULL,
		0xF74BDDE19573122CULL,
		0x77302EB419466C09ULL,
		0xE53307B31ABFC531ULL,
		0x32D172B18E58F835ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x64E5305E780704E8ULL,
		0xF704D8B449CBFF1DULL,
		0x50E7BBA6FDEF2870ULL,
		0x073FAC47F3532234ULL,
		0x955AA015B1A2D40CULL,
		0x50DC76B906F8B68DULL,
		0xCE39F9A860322CAFULL,
		0x8B6CB7A7347B0B58ULL
	}};
	sign = 0;
	printf("Test Case 359\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 359 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -359;
	} else {
		printf("Test Case 359 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6478E98BD437F66CULL,
		0x0DBF69D0D7B2C797ULL,
		0x5013ED929F2FFD28ULL,
		0xD07B653C546AF699ULL,
		0x6C5FA57F86713F2EULL,
		0xFADEE1C7F37750FFULL,
		0x973DD354A853D286ULL,
		0xEAD2EAFDC613BC21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B8E2243603E4BBAULL,
		0x3D81078C6B8A7A6AULL,
		0xFCD8B161133B1F43ULL,
		0x6ECCCDCB0A4F18A7ULL,
		0xC47C2F7358A47CE2ULL,
		0xDD4F7054DCD9E95BULL,
		0xC595908477AB9110ULL,
		0xF8DB349A16B0DCB8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC8EAC74873F9AAB2ULL,
		0xD03E62446C284D2CULL,
		0x533B3C318BF4DDE4ULL,
		0x61AE97714A1BDDF1ULL,
		0xA7E3760C2DCCC24CULL,
		0x1D8F7173169D67A3ULL,
		0xD1A842D030A84176ULL,
		0xF1F7B663AF62DF68ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 360\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 360 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -360;
	} else {
		printf("Test Case 360 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA67310390F72B57DULL,
		0xAEFE521B91347DA5ULL,
		0x18127832015BA87EULL,
		0xB85A3C5246CDC539ULL,
		0xF8C1FA49EA222F4FULL,
		0xBC58AD8F1C531783ULL,
		0xBC5CD621C2739A05ULL,
		0x5A7043BFEBD5A7A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF356ACA6126510B4ULL,
		0x4AC7A8E425FFF81FULL,
		0x71E2E198C0440109ULL,
		0x78FBCFA8EDA91EA7ULL,
		0xC3B32C11D23052DBULL,
		0x9953CE699A9224E3ULL,
		0x96E7BF6382145FF9ULL,
		0x6702730191CDC07AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB31C6392FD0DA4C9ULL,
		0x6436A9376B348585ULL,
		0xA62F96994117A775ULL,
		0x3F5E6CA95924A691ULL,
		0x350ECE3817F1DC74ULL,
		0x2304DF2581C0F2A0ULL,
		0x257516BE405F3A0CULL,
		0xF36DD0BE5A07E727ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 361\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 361 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -361;
	} else {
		printf("Test Case 361 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x71888B87DF0110F7ULL,
		0x6B599844EF59DFFAULL,
		0xB13C6B2BAE321A92ULL,
		0x2D77B15510C7EB0AULL,
		0xA3136E0AA87BCA88ULL,
		0x08D40DF7D552A351ULL,
		0x46C5948168A7D93CULL,
		0xB874F568AF8F65CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD5FD391D07FBF58ULL,
		0xCABF8AA3A290DA3CULL,
		0x6119FF998A157DE4ULL,
		0xBCC922296A4A6D63ULL,
		0x481A342EE592669BULL,
		0x1E3810E421984373ULL,
		0x756820DA06D803B8ULL,
		0x655AE3B0E6BF0387ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7428B7F60E81519FULL,
		0xA09A0DA14CC905BDULL,
		0x50226B92241C9CADULL,
		0x70AE8F2BA67D7DA7ULL,
		0x5AF939DBC2E963ECULL,
		0xEA9BFD13B3BA5FDEULL,
		0xD15D73A761CFD583ULL,
		0x531A11B7C8D06242ULL
	}};
	sign = 0;
	printf("Test Case 362\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 362 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -362;
	} else {
		printf("Test Case 362 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB85FBE114C91A8D8ULL,
		0x6BA00F77164E5DB1ULL,
		0xC30D3EDD6D807F00ULL,
		0xCBECA7B850643341ULL,
		0x7F96B85ECFE9B1FBULL,
		0x233E2E8406FF7C45ULL,
		0x862D2CEE18DE54B9ULL,
		0x9E4C81FC2DEB64C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F60AD4542950C8CULL,
		0x37922AD371E142A6ULL,
		0xFA4B5CC9C420C36AULL,
		0x17F1F1E4BD9123CEULL,
		0x7E4CCEF9781A3996ULL,
		0xAE32E3E1C07BFBFEULL,
		0x1991563D5C8A8C84ULL,
		0x560BF092B650FD8DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA8FF10CC09FC9C4CULL,
		0x340DE4A3A46D1B0BULL,
		0xC8C1E213A95FBB96ULL,
		0xB3FAB5D392D30F72ULL,
		0x0149E96557CF7865ULL,
		0x750B4AA246838047ULL,
		0x6C9BD6B0BC53C834ULL,
		0x48409169779A6737ULL
	}};
	sign = 0;
	printf("Test Case 363\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 363 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -363;
	} else {
		printf("Test Case 363 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x431170581DEA8140ULL,
		0x2CA88798E857089FULL,
		0x1EDB8F59254D0921ULL,
		0xEF3D23C6D90A3AEAULL,
		0xAED1369A36C237ADULL,
		0xB689DA6CF9E818DFULL,
		0x8FF73BB3736E9D9EULL,
		0x9064B377AC4451CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39C7BE91E4B8F5ADULL,
		0x0347B613D4D7DDE8ULL,
		0x11D68EF14273C003ULL,
		0xD832A0C05DDEE1C1ULL,
		0x9926ECB0B6E407FFULL,
		0x363235426D135D12ULL,
		0x0B57FF6155EC52FDULL,
		0xFF01B59AA60E71B6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0949B1C639318B93ULL,
		0x2960D185137F2AB7ULL,
		0x0D050067E2D9491EULL,
		0x170A83067B2B5929ULL,
		0x15AA49E97FDE2FAEULL,
		0x8057A52A8CD4BBCDULL,
		0x849F3C521D824AA1ULL,
		0x9162FDDD0635E015ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 364\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 364 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -364;
	} else {
		printf("Test Case 364 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x44DC85D3969F69F4ULL,
		0x847D8BB8785E317FULL,
		0x5BC59DEEA6E8C174ULL,
		0xA94A3A57AA57036AULL,
		0xCB76AAC754C28775ULL,
		0x909EE1E5E2FD5C5BULL,
		0xEB9AA6A41BDBAABCULL,
		0xB372106F9AB86818ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81188DAFFAD81E77ULL,
		0x12646BA15767E7C0ULL,
		0xDDB5BBED120D722BULL,
		0x0966C44C4E8D5DFFULL,
		0xC46F71C69465AD95ULL,
		0x246F84619AF0F17DULL,
		0x05A3AF4349880663ULL,
		0x237442CFE099C684ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC3C3F8239BC74B7DULL,
		0x7219201720F649BEULL,
		0x7E0FE20194DB4F49ULL,
		0x9FE3760B5BC9A56AULL,
		0x07073900C05CD9E0ULL,
		0x6C2F5D84480C6ADEULL,
		0xE5F6F760D253A459ULL,
		0x8FFDCD9FBA1EA194ULL
	}};
	sign = 0;
	printf("Test Case 365\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 365 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -365;
	} else {
		printf("Test Case 365 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF2646F41993D6133ULL,
		0xA8F524D81210D9D3ULL,
		0x5D4FA3E5D5E01437ULL,
		0xDB2F8543789508CEULL,
		0x66A8C87692E43D4AULL,
		0x584022FD33B9C62EULL,
		0x913A099C57E22C55ULL,
		0x7AE006D3D1DD3C24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2DBE0115860AB99ULL,
		0x32AA85A185841F38ULL,
		0x87585DED0A559894ULL,
		0xDF6E73D6A9CEB2E6ULL,
		0xD079C3D7932FC154ULL,
		0x0E059657ED19BE24ULL,
		0xD053719ADC100946ULL,
		0xAA8D3BA4AB93708FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4F888F3040DCB59AULL,
		0x764A9F368C8CBA9BULL,
		0xD5F745F8CB8A7BA3ULL,
		0xFBC1116CCEC655E7ULL,
		0x962F049EFFB47BF5ULL,
		0x4A3A8CA546A00809ULL,
		0xC0E698017BD2230FULL,
		0xD052CB2F2649CB94ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 366\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 366 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -366;
	} else {
		printf("Test Case 366 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0B602BF7AA4936CBULL,
		0x6CCAEA137A5D9369ULL,
		0xD6927F093B1CEE53ULL,
		0x8C929CE9A8D4A61DULL,
		0xC4294B9026879351ULL,
		0xA7CD1FE4E8A6A04EULL,
		0xB875CFE3D7584A47ULL,
		0xE52B93846550D0C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42E6F3866D8ACCB1ULL,
		0x9557BDCD31F8E1A0ULL,
		0x699F793B8ACB79C8ULL,
		0x8B11556288771D73ULL,
		0x328283D986FFF525ULL,
		0xFFD59F47D12F88C0ULL,
		0xCC4D61CDB9F7F858ULL,
		0x91DF790F6556A3A3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC87938713CBE6A1AULL,
		0xD7732C464864B1C8ULL,
		0x6CF305CDB051748AULL,
		0x01814787205D88AAULL,
		0x91A6C7B69F879E2CULL,
		0xA7F7809D1777178EULL,
		0xEC286E161D6051EEULL,
		0x534C1A74FFFA2D21ULL
	}};
	sign = 0;
	printf("Test Case 367\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 367 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -367;
	} else {
		printf("Test Case 367 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4C233C0777454A5CULL,
		0x20B5FE68A998B7EFULL,
		0x6B9D3DBAB1982A9BULL,
		0x1550B202B435F3CFULL,
		0xDC2A1ACC37157B7DULL,
		0xBBFDB1F37EF7DB38ULL,
		0xAB44223E745C8DD7ULL,
		0x3D490C64B4D6546FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF6154937CF7AC72ULL,
		0x613FAD13A17CA817ULL,
		0xE040F51F55C33B98ULL,
		0x944B77BBC67C9740ULL,
		0xE5E5C58E74DEE2FFULL,
		0xCE6032BD22B4A822ULL,
		0x065D5530AA7A017EULL,
		0xE993162FFFF780BCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7CC1E773FA4D9DEAULL,
		0xBF765155081C0FD7ULL,
		0x8B5C489B5BD4EF02ULL,
		0x81053A46EDB95C8EULL,
		0xF644553DC236987DULL,
		0xED9D7F365C433315ULL,
		0xA4E6CD0DC9E28C58ULL,
		0x53B5F634B4DED3B3ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 368\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 368 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -368;
	} else {
		printf("Test Case 368 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAC4A1D9DC714588BULL,
		0xD0338171FBF0363CULL,
		0x3A91E213BF43E3F2ULL,
		0x5F41BD95D2CD1529ULL,
		0xB43728E513525415ULL,
		0xAE87FC3A90BBE73DULL,
		0xA2EF9A42E557D20BULL,
		0xB822423F802C5781ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC64D3BE471D03E85ULL,
		0x5CAE1EC39CE03BC5ULL,
		0xF943FB4286B8D821ULL,
		0x031E04DACB81223CULL,
		0x6DCA725F6562DC71ULL,
		0x124D6BE05371E455ULL,
		0xF99D758012EF650DULL,
		0xA5DACD8FC376EF88ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE5FCE1B955441A06ULL,
		0x738562AE5F0FFA76ULL,
		0x414DE6D1388B0BD1ULL,
		0x5C23B8BB074BF2ECULL,
		0x466CB685ADEF77A4ULL,
		0x9C3A905A3D4A02E8ULL,
		0xA95224C2D2686CFEULL,
		0x124774AFBCB567F8ULL
	}};
	sign = 0;
	printf("Test Case 369\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 369 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -369;
	} else {
		printf("Test Case 369 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7AECDF4C7ECEBD38ULL,
		0x4B424376B0516644ULL,
		0x69D6E33C86AB2D0BULL,
		0x33C64EAF85C0518AULL,
		0xC1DD5BD89B40B64BULL,
		0x64FD6C7912A6B10BULL,
		0xB83B48C862519F7EULL,
		0x526A6196B47BA1D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3497C9A10149C1B5ULL,
		0xC7659DD9405D7A94ULL,
		0x2FB75E927A149D27ULL,
		0x71B4A98EB09D07D2ULL,
		0x8C16F2E08F129017ULL,
		0x47076938F4F4A2BFULL,
		0x4D0DAC3BB557D763ULL,
		0x97B482E45D07F326ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x465515AB7D84FB83ULL,
		0x83DCA59D6FF3EBB0ULL,
		0x3A1F84AA0C968FE3ULL,
		0xC211A520D52349B8ULL,
		0x35C668F80C2E2633ULL,
		0x1DF603401DB20E4CULL,
		0x6B2D9C8CACF9C81BULL,
		0xBAB5DEB25773AEAAULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 370\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 370 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -370;
	} else {
		printf("Test Case 370 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA4EAB032CD65099BULL,
		0xDDBE433F77E6DE9EULL,
		0x31081CC8B05C76ACULL,
		0x3C601A89F894A75CULL,
		0x7E414C488AB3A14EULL,
		0xB502AA5F14DDE7B6ULL,
		0x07C3B1B308BBCBDCULL,
		0xDC08493C03E2E55BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AA1A716B375561AULL,
		0xC1720A30596C401BULL,
		0x3C68AAFA3A295324ULL,
		0xBC0F1B664C5BF03FULL,
		0xFF153203355A917CULL,
		0xF6F1C6CBF6B16283ULL,
		0x38F3B46E2615EF03ULL,
		0x27CCAF871D3C4047ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4A49091C19EFB381ULL,
		0x1C4C390F1E7A9E83ULL,
		0xF49F71CE76332388ULL,
		0x8050FF23AC38B71CULL,
		0x7F2C1A4555590FD1ULL,
		0xBE10E3931E2C8532ULL,
		0xCECFFD44E2A5DCD8ULL,
		0xB43B99B4E6A6A513ULL
	}};
	sign = 0;
	printf("Test Case 371\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 371 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -371;
	} else {
		printf("Test Case 371 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE9EC9AA26FC508E5ULL,
		0x8883CA9502FC2181ULL,
		0xFD68557641D31F20ULL,
		0x9A6FEFCC155E2F91ULL,
		0x0E878E38D92C66E7ULL,
		0xC6E5D982560F1A88ULL,
		0xA45E5A5C2EDDA59AULL,
		0x9791855D642B4DE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x925B1A44DCDAE05CULL,
		0xB90C2FF97191BDE9ULL,
		0x48471D8445148A65ULL,
		0x3A0B7B04D537044DULL,
		0x7C4A88C485B2583CULL,
		0x71F74C67A7FEB91EULL,
		0x52598F21B0291C5CULL,
		0x5229CF218BD34D27ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5791805D92EA2889ULL,
		0xCF779A9B916A6398ULL,
		0xB52137F1FCBE94BAULL,
		0x606474C740272B44ULL,
		0x923D0574537A0EABULL,
		0x54EE8D1AAE106169ULL,
		0x5204CB3A7EB4893EULL,
		0x4567B63BD85800C1ULL
	}};
	sign = 0;
	printf("Test Case 372\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 372 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -372;
	} else {
		printf("Test Case 372 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9133571653B16563ULL,
		0xA76A78FE619292A2ULL,
		0x4050186AD4FFD9F3ULL,
		0x48C4758790489C60ULL,
		0xB2A6A1A63748725AULL,
		0x060D1EB2354B038DULL,
		0x8DCD9788C964692CULL,
		0x012AF6DD06A996C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50CEEEC1B1BFEC56ULL,
		0x1475E38767719CF0ULL,
		0x6D0EDD0287377C46ULL,
		0xD4AB582E7D335AF2ULL,
		0xBE90DD9ACC48A6F9ULL,
		0x0FF972925ACE4E76ULL,
		0x4E62CCB31200899AULL,
		0x66FBF5EF06DA8BF3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40646854A1F1790DULL,
		0x92F49576FA20F5B2ULL,
		0xD3413B684DC85DADULL,
		0x74191D591315416DULL,
		0xF415C40B6AFFCB60ULL,
		0xF613AC1FDA7CB516ULL,
		0x3F6ACAD5B763DF91ULL,
		0x9A2F00EDFFCF0AD1ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 373\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 373 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -373;
	} else {
		printf("Test Case 373 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8404D250BD4C8A19ULL,
		0x5C3DD9AB1F391C43ULL,
		0xB4F35061584229DEULL,
		0x4E5B5E73B315F650ULL,
		0x7AFE6C6F6411C0BBULL,
		0x172B271D0BC751B7ULL,
		0x3C6036D99AFAE17CULL,
		0x96070341E9499AD5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB427FD544A758600ULL,
		0x0324658F92FB29B7ULL,
		0x8C8323045A53974BULL,
		0x1308394A49BF7025ULL,
		0xE9D7908641FC18E1ULL,
		0x7FFB840C33EE3502ULL,
		0x06AB86AF6E133D84ULL,
		0x80770BD0FDA65FBBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCFDCD4FC72D70419ULL,
		0x5919741B8C3DF28BULL,
		0x28702D5CFDEE9293ULL,
		0x3B5325296956862BULL,
		0x9126DBE92215A7DAULL,
		0x972FA310D7D91CB4ULL,
		0x35B4B02A2CE7A3F7ULL,
		0x158FF770EBA33B1AULL
	}};
	sign = 0;
	printf("Test Case 374\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 374 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -374;
	} else {
		printf("Test Case 374 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0B0C619A84DE5171ULL,
		0x09F850246EB1B586ULL,
		0x84BA7D1853600838ULL,
		0xF2DB43132D11D02AULL,
		0x95F7C75ECF0B360BULL,
		0x865EA3159490B61AULL,
		0xBDD569A9D734D3D5ULL,
		0x662FE55C74568702ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB66EF38F96E3D597ULL,
		0x71CB9BF3A9E2A69EULL,
		0xE4455F24577374F4ULL,
		0x5A9FEEBD049F7B63ULL,
		0x28AF5992A6A91A92ULL,
		0xBEF608BFD1A24588ULL,
		0x37F89683370B7013ULL,
		0x156678D26C557C8CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x549D6E0AEDFA7BDAULL,
		0x982CB430C4CF0EE7ULL,
		0xA0751DF3FBEC9343ULL,
		0x983B5456287254C6ULL,
		0x6D486DCC28621B79ULL,
		0xC7689A55C2EE7092ULL,
		0x85DCD326A02963C1ULL,
		0x50C96C8A08010A76ULL
	}};
	sign = 0;
	printf("Test Case 375\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 375 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -375;
	} else {
		printf("Test Case 375 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3EEB2769110DFA09ULL,
		0xEA976E5C5AB3CFDAULL,
		0xB3BCA6ED985AC674ULL,
		0x038406326D78D78CULL,
		0xC7B75321412ABC16ULL,
		0x0BAB50FBBAF67525ULL,
		0xA49CBC64389A07A6ULL,
		0x3EE851B818BEAACBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x811FAA6EBA7592B1ULL,
		0x7FA7B4669FD7A775ULL,
		0xC08A7AFA39E035ADULL,
		0x099BBD0863F3AD13ULL,
		0xE3A0639CFA703A36ULL,
		0x4CAFE9EE9A55BFBAULL,
		0xE1644AFE6C1262AAULL,
		0xB354DEE2E88E8DDBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBDCB7CFA56986758ULL,
		0x6AEFB9F5BADC2864ULL,
		0xF3322BF35E7A90C7ULL,
		0xF9E8492A09852A78ULL,
		0xE416EF8446BA81DFULL,
		0xBEFB670D20A0B56AULL,
		0xC3387165CC87A4FBULL,
		0x8B9372D530301CEFULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 376\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 376 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -376;
	} else {
		printf("Test Case 376 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9DEC4467816F3290ULL,
		0x7BE1F5FD56449827ULL,
		0xE14875F180E697CBULL,
		0xE3B544B67DE376E6ULL,
		0x9CED946CAF2017E5ULL,
		0xA32EF875F93075A0ULL,
		0x0AF817644B6BE3D5ULL,
		0x64354D67336E7321ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE42E62C0229E199DULL,
		0x95262BA96F710522ULL,
		0xDF483C01464C418EULL,
		0xDA94AFAC219AB2E0ULL,
		0x98CD2AFFF506BE8EULL,
		0xAFF5F5B8D77F171FULL,
		0xDAEB70B87D876C58ULL,
		0x6B4CF3E478F07C0FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB9BDE1A75ED118F3ULL,
		0xE6BBCA53E6D39304ULL,
		0x020039F03A9A563CULL,
		0x0920950A5C48C406ULL,
		0x0420696CBA195957ULL,
		0xF33902BD21B15E81ULL,
		0x300CA6ABCDE4777CULL,
		0xF8E85982BA7DF711ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 377\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 377 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -377;
	} else {
		printf("Test Case 377 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x60EB91536ED302AEULL,
		0xD5811F845C1BCE6AULL,
		0xC78072052E3873A7ULL,
		0x4CAB89FD02894BE1ULL,
		0xF42450D366B26375ULL,
		0x3CAE5AD31A418EA0ULL,
		0xEB8C43227D7F049BULL,
		0xC3D17B9C52303852ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA17B3D846B90E7EULL,
		0xCFB8291A5E316223ULL,
		0xC8C179708B73B2ACULL,
		0xFFBEC4FF85AE115DULL,
		0x81F27219B3DC93F8ULL,
		0xAA1D1403F6681BC8ULL,
		0x2D8F2111320E22CCULL,
		0x27334ED4D403995CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x76D3DD7B2819F430ULL,
		0x05C8F669FDEA6C46ULL,
		0xFEBEF894A2C4C0FBULL,
		0x4CECC4FD7CDB3A83ULL,
		0x7231DEB9B2D5CF7CULL,
		0x929146CF23D972D8ULL,
		0xBDFD22114B70E1CEULL,
		0x9C9E2CC77E2C9EF6ULL
	}};
	sign = 0;
	printf("Test Case 378\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 378 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -378;
	} else {
		printf("Test Case 378 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC115AD8DEFECE2BDULL,
		0xE49B9D9D6C681485ULL,
		0xCA0E9C7CF0E8B1DCULL,
		0x83713D798B1FD94CULL,
		0x9E6B2C70CC2985FFULL,
		0xCA21332242F39C57ULL,
		0xE67113861466DF76ULL,
		0x41F9F2EAEE1998B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE281FCF6F6E0E6B0ULL,
		0x2308FF50242EC464ULL,
		0x5BE3533D939D837EULL,
		0xBFCDC2438D7E17BDULL,
		0x665E960669C2D2D1ULL,
		0xF6C24960AFDA6DC8ULL,
		0x0DE3C9427980763BULL,
		0xA18B7CAE4F3E1BB1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDE93B096F90BFC0DULL,
		0xC1929E4D48395020ULL,
		0x6E2B493F5D4B2E5EULL,
		0xC3A37B35FDA1C18FULL,
		0x380C966A6266B32DULL,
		0xD35EE9C193192E8FULL,
		0xD88D4A439AE6693AULL,
		0xA06E763C9EDB7D05ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 379\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 379 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -379;
	} else {
		printf("Test Case 379 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0F21A91674B97980ULL,
		0x14186D4696D24369ULL,
		0xF43A37D208BFD6D7ULL,
		0x47400DF066A7EAF8ULL,
		0x4A98A9EB3D6D1113ULL,
		0xD643B0E585A2849DULL,
		0xB1B3DE70A7642C66ULL,
		0xFCC2E21CC044563FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2311CB5E37576CBCULL,
		0x2DB8174352616294ULL,
		0x54575AFC7D8F0243ULL,
		0x8CCF259BAA460160ULL,
		0xC9602F24D8422E2DULL,
		0xA7FF6D18711CE106ULL,
		0x9703E6AF0CC1C015ULL,
		0xCF231D840681329DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEC0FDDB83D620CC4ULL,
		0xE66056034470E0D4ULL,
		0x9FE2DCD58B30D493ULL,
		0xBA70E854BC61E998ULL,
		0x81387AC6652AE2E5ULL,
		0x2E4443CD1485A396ULL,
		0x1AAFF7C19AA26C51ULL,
		0x2D9FC498B9C323A2ULL
	}};
	sign = 0;
	printf("Test Case 380\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 380 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -380;
	} else {
		printf("Test Case 380 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4D0AECFE6C35B0DFULL,
		0x5FFD3B7029B8DB1CULL,
		0x5AC4CE9A33E02C10ULL,
		0x5D80FB0C168D464CULL,
		0x8C121C3B751A266CULL,
		0x6C93756CF4C27CC2ULL,
		0xCD01B24282C47EC5ULL,
		0xE7B0D53C9B87F45FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA943A4887AA535DAULL,
		0xB4A1E4BA67F7DAF4ULL,
		0x0DE94067D5A09F87ULL,
		0x16A351BC8A3D9ACDULL,
		0xF5AF35632A7C4D15ULL,
		0xBC95763801879FC1ULL,
		0xB1AB9AC7450EE061ULL,
		0x824867B87371429DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA3C74875F1907B05ULL,
		0xAB5B56B5C1C10027ULL,
		0x4CDB8E325E3F8C88ULL,
		0x46DDA94F8C4FAB7FULL,
		0x9662E6D84A9DD957ULL,
		0xAFFDFF34F33ADD00ULL,
		0x1B56177B3DB59E63ULL,
		0x65686D842816B1C2ULL
	}};
	sign = 0;
	printf("Test Case 381\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 381 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -381;
	} else {
		printf("Test Case 381 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDF7DDF08545880B9ULL,
		0xF9DE99C192140707ULL,
		0x11BF18B41ED5C2C3ULL,
		0x35C1B6E6195D6309ULL,
		0x88D2B990E9377D6FULL,
		0x65B9C96992870831ULL,
		0x52DAC7D5FCE67693ULL,
		0x036B463C5DAF0453ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DABA1EC4A8448B7ULL,
		0x3233D693A6929A7CULL,
		0x8D4B3D51E838B3DCULL,
		0xA2B7A8C52945B7B1ULL,
		0x48917F54634A61FAULL,
		0xFA27057633470267ULL,
		0x872F5F3D87AA8DA1ULL,
		0x1353DF5165A9549FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x61D23D1C09D43802ULL,
		0xC7AAC32DEB816C8BULL,
		0x8473DB62369D0EE7ULL,
		0x930A0E20F017AB57ULL,
		0x40413A3C85ED1B74ULL,
		0x6B92C3F35F4005CAULL,
		0xCBAB6898753BE8F1ULL,
		0xF01766EAF805AFB3ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 382\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 382 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -382;
	} else {
		printf("Test Case 382 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB65D05A8FA47F7E2ULL,
		0x27659622DCE5E1A0ULL,
		0x960152234202BDBEULL,
		0x627C5A7C12CC7B0FULL,
		0x4E5097FFDC7D5861ULL,
		0x18BC8E208E367828ULL,
		0x24F21EE828E421D0ULL,
		0xDB14A5919C1AC39FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2653DB870AEC96FULL,
		0x0900F79CBFEA1B21ULL,
		0xE7E0972C46B94630ULL,
		0x0489D7F0C92B3581ULL,
		0xE9B140D863A19527ULL,
		0x7C7E2A570D01E300ULL,
		0x27864C6A7F98D935ULL,
		0x638BD28482631D23ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x13F7C7F089992E73ULL,
		0x1E649E861CFBC67FULL,
		0xAE20BAF6FB49778EULL,
		0x5DF2828B49A1458DULL,
		0x649F572778DBC33AULL,
		0x9C3E63C981349527ULL,
		0xFD6BD27DA94B489AULL,
		0x7788D30D19B7A67BULL
	}};
	sign = 0;
	printf("Test Case 383\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 383 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -383;
	} else {
		printf("Test Case 383 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD572638A781F8CD0ULL,
		0x8B1C08CA712F059DULL,
		0xE566E2342F0BD9D5ULL,
		0x8FD790A432FE4895ULL,
		0x95B7FA58DAD2D762ULL,
		0xB2BF52C12E5F5A2BULL,
		0x7AB854185D56E291ULL,
		0x9CEA44DCEC57EF4FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7EC32FFE67877F49ULL,
		0xDD36B6D9AA40A269ULL,
		0x9FB5F02C442C3FC6ULL,
		0x729434DA911203E6ULL,
		0x85CD1087AB15699BULL,
		0x2E094EE843844EC0ULL,
		0x1D442F4A9A75A1B9ULL,
		0x7C54B94579A2D2B4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x56AF338C10980D87ULL,
		0xADE551F0C6EE6334ULL,
		0x45B0F207EADF9A0EULL,
		0x1D435BC9A1EC44AFULL,
		0x0FEAE9D12FBD6DC7ULL,
		0x84B603D8EADB0B6BULL,
		0x5D7424CDC2E140D8ULL,
		0x20958B9772B51C9BULL
	}};
	sign = 0;
	printf("Test Case 384\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 384 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -384;
	} else {
		printf("Test Case 384 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1BEFB984D4F2A8C3ULL,
		0x93627BDF4B688071ULL,
		0x1CDDB93C9A2B49A3ULL,
		0x1F864FC7169F6909ULL,
		0xCB769777079D2265ULL,
		0x38F98BEE217A08B4ULL,
		0xE14F67B2FC07AD0EULL,
		0x0BFCE785EB4A4EA3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6570E202E922F89ULL,
		0xD91848F1DD80E23AULL,
		0xBE1BC99C4D656DDFULL,
		0x6C67DB5060286E73ULL,
		0x1770E08A6E079866ULL,
		0x7486F7B868203767ULL,
		0x38474DE3F8910E28ULL,
		0xB5341D82B1A0F350ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3598AB64A660793AULL,
		0xBA4A32ED6DE79E36ULL,
		0x5EC1EFA04CC5DBC3ULL,
		0xB31E7476B676FA95ULL,
		0xB405B6EC999589FEULL,
		0xC4729435B959D14DULL,
		0xA90819CF03769EE5ULL,
		0x56C8CA0339A95B53ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 385\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 385 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -385;
	} else {
		printf("Test Case 385 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x53D793C5E931FDADULL,
		0x826BC1D55C947478ULL,
		0x7A08581730605644ULL,
		0x95AA1F83C9AD9596ULL,
		0x11F365C6ADBDFB7DULL,
		0x9FFC4BE2C7B94669ULL,
		0x0FF01AE247A3D945ULL,
		0xE1CB8D3800A13D88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2F7FDBB230D8AC7ULL,
		0x58FC4D34DD3CC50BULL,
		0xA36EABA0B1EC1172ULL,
		0xDA4060712D552728ULL,
		0xF1D67C647399C0EEULL,
		0x3950BD7D737E4FA4ULL,
		0xEE645D2FCE293164ULL,
		0x61994F14D284A496ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x90DF960AC62472E6ULL,
		0x296F74A07F57AF6CULL,
		0xD699AC767E7444D2ULL,
		0xBB69BF129C586E6DULL,
		0x201CE9623A243A8EULL,
		0x66AB8E65543AF6C4ULL,
		0x218BBDB2797AA7E1ULL,
		0x80323E232E1C98F1ULL
	}};
	sign = 0;
	printf("Test Case 386\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 386 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -386;
	} else {
		printf("Test Case 386 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDD12E91CC07DE67AULL,
		0x1D0A92D194214CC1ULL,
		0x2722A9224F7B5DAEULL,
		0x99043C74436E7F81ULL,
		0xE96DC2C605C53051ULL,
		0xA03FF415B1FECC86ULL,
		0x4F410397B6DB0A14ULL,
		0x90601E68B33A5B07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A1D9B647F791B85ULL,
		0x74B6627A452ED34CULL,
		0x863188610855F228ULL,
		0x96BE7A9AA9EAED35ULL,
		0x7A3B033489B90AE4ULL,
		0xAF744B802012802AULL,
		0x8EA1B6C4D7A93521ULL,
		0x40437B52B18971D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x42F54DB84104CAF5ULL,
		0xA85430574EF27975ULL,
		0xA0F120C147256B85ULL,
		0x0245C1D99983924BULL,
		0x6F32BF917C0C256DULL,
		0xF0CBA89591EC4C5CULL,
		0xC09F4CD2DF31D4F2ULL,
		0x501CA31601B0E92FULL
	}};
	sign = 0;
	printf("Test Case 387\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 387 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -387;
	} else {
		printf("Test Case 387 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF2888AF2D1FB3474ULL,
		0xFEF9EE511D11A6A6ULL,
		0x70545E81A3DE0545ULL,
		0xC692CBE138F756EFULL,
		0x1B96148D3E69340AULL,
		0xBF02AC5308A98794ULL,
		0xC31C0B9CE2D27151ULL,
		0x6A8AF4B85C88DF8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1DA07E1E85274D8ULL,
		0xA2F6ED5FD683ABC7ULL,
		0xA6ED1EFF87C381FAULL,
		0x382E498D34ADF592ULL,
		0xC81BDA4493DD4857ULL,
		0x7B28F96FE134C354ULL,
		0x576E04775EC30FCDULL,
		0xC355198639434C96ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x20AE8310E9A8BF9CULL,
		0x5C0300F1468DFADFULL,
		0xC9673F821C1A834BULL,
		0x8E6482540449615CULL,
		0x537A3A48AA8BEBB3ULL,
		0x43D9B2E32774C43FULL,
		0x6BAE0725840F6184ULL,
		0xA735DB32234592F9ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 388\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 388 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -388;
	} else {
		printf("Test Case 388 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x732651B6324DD78CULL,
		0xC5C04C9115A53EB7ULL,
		0x10764FB87FBF8478ULL,
		0x4FCCDC51025B5527ULL,
		0x51625C4BF14EA817ULL,
		0x1BA59C90A43E8CA9ULL,
		0x250CEA70E6F88B60ULL,
		0x73D6D193DE5F5CE5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E91B1B4AA661188ULL,
		0x22E409F6D22B333FULL,
		0xB31E9BE250757336ULL,
		0x9A4B36845F922C1DULL,
		0x2359522E54D6F721ULL,
		0x3D32CD114B0FACC1ULL,
		0x59363A556CFA21E4ULL,
		0x81C0E041041C9437ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2494A00187E7C604ULL,
		0xA2DC429A437A0B78ULL,
		0x5D57B3D62F4A1142ULL,
		0xB581A5CCA2C92909ULL,
		0x2E090A1D9C77B0F5ULL,
		0xDE72CF7F592EDFE8ULL,
		0xCBD6B01B79FE697BULL,
		0xF215F152DA42C8ADULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 389\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 389 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -389;
	} else {
		printf("Test Case 389 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5BF5EE89E2725061ULL,
		0xCE8A06C96CC316B5ULL,
		0xCC13F86E65DC337EULL,
		0x314FAC44AEFFB675ULL,
		0x307B89AAB9936875ULL,
		0xCC21ACEDFCDE08A1ULL,
		0xCDC3766F7767CF47ULL,
		0xF6B36EEDC1C15EF2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0808FEE886253AD9ULL,
		0x39FEFAA6E25F85EBULL,
		0xEC963F02510EFCEEULL,
		0xC3A70B4F0D8B6D7FULL,
		0x66CA3A3021E47B41ULL,
		0xCC3226BA4762340CULL,
		0x08B70D35BCA0BD7DULL,
		0x74597766B4BAFFB0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x53ECEFA15C4D1588ULL,
		0x948B0C228A6390CAULL,
		0xDF7DB96C14CD3690ULL,
		0x6DA8A0F5A17448F5ULL,
		0xC9B14F7A97AEED33ULL,
		0xFFEF8633B57BD494ULL,
		0xC50C6939BAC711C9ULL,
		0x8259F7870D065F42ULL
	}};
	sign = 0;
	printf("Test Case 390\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 390 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -390;
	} else {
		printf("Test Case 390 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD952E586CF141658ULL,
		0xC760645853B1DABCULL,
		0xBEA2AFAA6F5E67F1ULL,
		0x23449C53E81D6631ULL,
		0xFDE5BD04229F24A9ULL,
		0xFA0ED8DF2D57ED36ULL,
		0xD6D9078E18201094ULL,
		0xA12EC44CCCEBD627ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29FB5672B0D5F7E6ULL,
		0xB8E19A3A6FAB545FULL,
		0x5C836E7388642E41ULL,
		0x1404FFD3C671F42AULL,
		0x5DCFD794D1EFB47FULL,
		0x9BDF4EB626172C6EULL,
		0x85EE38E2772A655BULL,
		0x257F6807FCC5A647ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAF578F141E3E1E72ULL,
		0x0E7ECA1DE406865DULL,
		0x621F4136E6FA39B0ULL,
		0x0F3F9C8021AB7207ULL,
		0xA015E56F50AF702AULL,
		0x5E2F8A290740C0C8ULL,
		0x50EACEABA0F5AB39ULL,
		0x7BAF5C44D0262FE0ULL
	}};
	sign = 0;
	printf("Test Case 391\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 391 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -391;
	} else {
		printf("Test Case 391 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBC6B72406D084DF9ULL,
		0x2CCD4615EC39244AULL,
		0x8A7B68B5DD6B4AAFULL,
		0x97FBF7361C115609ULL,
		0xB477C4CAC82DB26BULL,
		0x9DC48958593E27ADULL,
		0x976DC618C71D1476ULL,
		0xBAAE45A34D20E6C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86582104580AA4CEULL,
		0x29F13C7E404F41B2ULL,
		0x80CAB5D15E303986ULL,
		0x907CD014841F01EBULL,
		0xF26AD84C82B3E1F1ULL,
		0x1A2500DD4F7F304EULL,
		0xC4158E5D2F45FD73ULL,
		0xC87D1B06BAC6BAA3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3613513C14FDA92BULL,
		0x02DC0997ABE9E298ULL,
		0x09B0B2E47F3B1129ULL,
		0x077F272197F2541EULL,
		0xC20CEC7E4579D07AULL,
		0x839F887B09BEF75EULL,
		0xD35837BB97D71703ULL,
		0xF2312A9C925A2C20ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 392\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 392 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -392;
	} else {
		printf("Test Case 392 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8FA6A20E7A79C9DCULL,
		0xF7CFC15E214AEF50ULL,
		0x3D777616846F2002ULL,
		0x439B8DC6AD32E8C8ULL,
		0x387194C33A3D3C85ULL,
		0x3C4408470FD00DE2ULL,
		0xA5F8FFD26CB7A88BULL,
		0x15FA1ABFD7B04ED0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8189040DC249F12DULL,
		0x13403DFA8FDE58EFULL,
		0x7E3ED088829EF306ULL,
		0xDF2C7E944262B421ULL,
		0x39F80F698DBDAD7CULL,
		0x8424EE604138C204ULL,
		0x73044B7088C42E80ULL,
		0xD5812DC91D7CC25FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E1D9E00B82FD8AFULL,
		0xE48F8363916C9661ULL,
		0xBF38A58E01D02CFCULL,
		0x646F0F326AD034A6ULL,
		0xFE798559AC7F8F08ULL,
		0xB81F19E6CE974BDDULL,
		0x32F4B461E3F37A0AULL,
		0x4078ECF6BA338C71ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 393\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 393 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -393;
	} else {
		printf("Test Case 393 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD3F4974752457A00ULL,
		0xFC0EA900955A1107ULL,
		0x6226D0E5D9DA613CULL,
		0x546DAFED28BCE178ULL,
		0x3B3F2129D30F5D90ULL,
		0xFE4C9DB335B8736BULL,
		0xF65E0CCE32168393ULL,
		0x0BFAD9B681AF38D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x349F7032405490F7ULL,
		0xA164CF3B615FCAC3ULL,
		0x154AA62BB30067F1ULL,
		0x907806873668845FULL,
		0x44C7D261472A61F6ULL,
		0xF81F6181D6410B64ULL,
		0xB45918BA7EF49469ULL,
		0x5539C452602B46B5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9F55271511F0E909ULL,
		0x5AA9D9C533FA4644ULL,
		0x4CDC2ABA26D9F94BULL,
		0xC3F5A965F2545D19ULL,
		0xF6774EC88BE4FB99ULL,
		0x062D3C315F776806ULL,
		0x4204F413B321EF2AULL,
		0xB6C115642183F222ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 394\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 394 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -394;
	} else {
		printf("Test Case 394 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD43CC2009721DAAEULL,
		0x6F453606E4B104A7ULL,
		0xB152F4DDC9AF1A61ULL,
		0x598EEE4D76DFE19CULL,
		0x0A19CFEDC0B79725ULL,
		0x78C51A40DEB64BA0ULL,
		0x7E20B8F382CAD76DULL,
		0xC1B143658E4BDE04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74B9B1F1D98F8D91ULL,
		0xDA18C5B2D1756C7BULL,
		0xC7EE283CB0F98F61ULL,
		0xDD660134FC58ED5DULL,
		0xE2EF5C87FF005DABULL,
		0x382A066AD5E02AFFULL,
		0x3DF89B15CDB23406ULL,
		0xDED2F8DF6106D065ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5F83100EBD924D1DULL,
		0x952C7054133B982CULL,
		0xE964CCA118B58AFFULL,
		0x7C28ED187A86F43EULL,
		0x272A7365C1B73979ULL,
		0x409B13D608D620A0ULL,
		0x40281DDDB518A367ULL,
		0xE2DE4A862D450D9FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 395\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 395 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -395;
	} else {
		printf("Test Case 395 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3330AE4AD253C86CULL,
		0xCF92A051FFD257E9ULL,
		0xFB0A53629BC57AE2ULL,
		0x05F7B03FDD7919C1ULL,
		0x809D0588A42EC75DULL,
		0xEBACFBF8939FD22EULL,
		0x5E7A408D023EAD46ULL,
		0xD430CB3E496ADCF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xABB5BF8D39784CAAULL,
		0x89C13E189D92AB89ULL,
		0x68A2199B8F4FEFD2ULL,
		0x8BFE728246789A3CULL,
		0xCD2954450A1D19C9ULL,
		0x988A5D71F18EBCE3ULL,
		0x1DC92F440D5127C1ULL,
		0x1971789B93785436ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x877AEEBD98DB7BC2ULL,
		0x45D16239623FAC5FULL,
		0x926839C70C758B10ULL,
		0x79F93DBD97007F85ULL,
		0xB373B1439A11AD93ULL,
		0x53229E86A211154AULL,
		0x40B11148F4ED8585ULL,
		0xBABF52A2B5F288C2ULL
	}};
	sign = 0;
	printf("Test Case 396\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 396 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -396;
	} else {
		printf("Test Case 396 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x474CE3557C449B65ULL,
		0xC759546595E1DA39ULL,
		0x21DD79319D378E10ULL,
		0x279E33C944FA0891ULL,
		0x86F81D1435D1A431ULL,
		0xC34376545201BFBCULL,
		0xC8E218772149FB2EULL,
		0x30C816A16D7748AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6BE01485FF931346ULL,
		0x4B3B1DCA4B48EDE1ULL,
		0x18596E0B05F98526ULL,
		0x9C7E33D7BAFBD785ULL,
		0x958D836671E25A32ULL,
		0xC97F68CC4FC3ABE3ULL,
		0xF80D383849A98801ULL,
		0xE4CA508F47C0F9F2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDB6CCECF7CB1881FULL,
		0x7C1E369B4A98EC57ULL,
		0x09840B26973E08EAULL,
		0x8B1FFFF189FE310CULL,
		0xF16A99ADC3EF49FEULL,
		0xF9C40D88023E13D8ULL,
		0xD0D4E03ED7A0732CULL,
		0x4BFDC61225B64EB7ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 397\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 397 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -397;
	} else {
		printf("Test Case 397 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x76DB3C3FD60B8B74ULL,
		0x6A9E3E4B4EB249A6ULL,
		0x18A3DDE390280278ULL,
		0x315C9B7F3C96B664ULL,
		0x79FA90A8B6D2BDC4ULL,
		0x3C4B05FBEE71115CULL,
		0x3B6EFEDF9773FB51ULL,
		0x03AD2B541A030750ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9EB080BE4D419F8CULL,
		0x1F6D3632C8A700B3ULL,
		0xF96119A1E5A4FA93ULL,
		0xFA7DF4FD1872758CULL,
		0x29CA1171C1D3611BULL,
		0x2CA00A9238F3C9F2ULL,
		0xBF3797BEF4B96C44ULL,
		0xEE686E8F2726B5C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD82ABB8188C9EBE8ULL,
		0x4B310818860B48F2ULL,
		0x1F42C441AA8307E5ULL,
		0x36DEA682242440D7ULL,
		0x50307F36F4FF5CA8ULL,
		0x0FAAFB69B57D476AULL,
		0x7C376720A2BA8F0DULL,
		0x1544BCC4F2DC518DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 398\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 398 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -398;
	} else {
		printf("Test Case 398 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x173983CF6AD3F486ULL,
		0x1CCAC605E0209350ULL,
		0xE97607E817BC7E5EULL,
		0x3A101F61F3B23E5BULL,
		0xF6B6977619D24FD7ULL,
		0xE2ABB827783EC2AFULL,
		0x0BF9FFEA32780CD4ULL,
		0x0AB76982FA37DE8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB632C33C2A23384ULL,
		0xEE468A685D2F8D2AULL,
		0xF82F370BA4F219C0ULL,
		0xD984874F5F5327C6ULL,
		0x324323C6C1B58968ULL,
		0xCFFB68F5C7E87A0BULL,
		0x9B9BEAA9F7062519ULL,
		0x12663ACFC0F711FFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6BD6579BA831C102ULL,
		0x2E843B9D82F10625ULL,
		0xF146D0DC72CA649DULL,
		0x608B9812945F1694ULL,
		0xC47373AF581CC66EULL,
		0x12B04F31B05648A4ULL,
		0x705E15403B71E7BBULL,
		0xF8512EB33940CC8BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 399\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 399 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -399;
	} else {
		printf("Test Case 399 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE678C2C3884ECD4FULL,
		0xD8A3F2B39CBA2961ULL,
		0x50C7BA8B9A3F58DCULL,
		0x4446E41FF1106BBDULL,
		0x6596D40167C03305ULL,
		0x9A7C9C47B302DF1AULL,
		0x991209C5768ECA42ULL,
		0x28F318F3E1C16C49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB1071C12FF2CF8EULL,
		0x1C81EEEBB16FA41DULL,
		0xECE1B81793169136ULL,
		0xEC4668EC9124A71CULL,
		0xC4E7C9F992E099E0ULL,
		0x42C8AC9B43602BEAULL,
		0x30A1CFF43F188ED0ULL,
		0x51C8F1BAB4F2A03DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEB685102585BFDC1ULL,
		0xBC2203C7EB4A8543ULL,
		0x63E602740728C7A6ULL,
		0x58007B335FEBC4A0ULL,
		0xA0AF0A07D4DF9924ULL,
		0x57B3EFAC6FA2B32FULL,
		0x687039D137763B72ULL,
		0xD72A27392CCECC0CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 400\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 400 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -400;
	} else {
		printf("Test Case 400 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0A2F464FD7AC447FULL,
		0x1049F37DAC97B3C5ULL,
		0xAEB9061734056A75ULL,
		0xBE843BAEA3C211F9ULL,
		0x5CED5BBC21EC915AULL,
		0x0A785BDCBF285CF2ULL,
		0xBD9D1B4BFC63C2E8ULL,
		0xC5E4683160A70455ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF4A8F66CDB7E39FULL,
		0x18D4ECA59CC0C223ULL,
		0xB33BCC3C9D3915BFULL,
		0xF4439D30E844B071ULL,
		0xE19D03EA8E2F7169ULL,
		0x7424F429CC520D07ULL,
		0x1C12FC6C434AC2F3ULL,
		0xF17E4A49A143ED25ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3AE4B6E909F460E0ULL,
		0xF77506D80FD6F1A1ULL,
		0xFB7D39DA96CC54B5ULL,
		0xCA409E7DBB7D6187ULL,
		0x7B5057D193BD1FF0ULL,
		0x965367B2F2D64FEAULL,
		0xA18A1EDFB918FFF4ULL,
		0xD4661DE7BF631730ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 401\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 401 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -401;
	} else {
		printf("Test Case 401 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFC699900575FDEB8ULL,
		0x9E63E897D8CF2FE0ULL,
		0xAE9665973DDC82F0ULL,
		0x9298783834B6F8CEULL,
		0x951CA6FE9A9BC1DEULL,
		0x0198C18B2DE5E621ULL,
		0x79CA4C8C09694DCAULL,
		0x6D98A189C2FF984CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCEBAF47D84C6EADCULL,
		0x6EFE6E1BFD45DF65ULL,
		0xDFA3E85917C95A3CULL,
		0xBD9066048CC93CFEULL,
		0xA1674BC9FFB65CDFULL,
		0x8C580CC95643463AULL,
		0x96794C1518231CDEULL,
		0x4C542FDD3C851BEBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2DAEA482D298F3DCULL,
		0x2F657A7BDB89507BULL,
		0xCEF27D3E261328B4ULL,
		0xD5081233A7EDBBCFULL,
		0xF3B55B349AE564FEULL,
		0x7540B4C1D7A29FE6ULL,
		0xE3510076F14630EBULL,
		0x214471AC867A7C60ULL
	}};
	sign = 0;
	printf("Test Case 402\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 402 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -402;
	} else {
		printf("Test Case 402 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0780122059DA60CDULL,
		0xE8F5DDC341C005BCULL,
		0xA4AF921339401BF5ULL,
		0xA8C9344FBD0DB656ULL,
		0xCFC9FD4D40FDEDC5ULL,
		0xD7BEAC10F1DF12D8ULL,
		0x78483AC633AE4B41ULL,
		0x21FC791DB90DC6AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F022409E82E73F3ULL,
		0x06875AD7DAA5FCDDULL,
		0xBEAA5C9B0A325653ULL,
		0x50EBDD50BF969E65ULL,
		0xA1FA6602D0D6B55CULL,
		0xD73F25637BED3D78ULL,
		0x75CEB617B31A4312ULL,
		0x0EAD6923E61E0AA7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB87DEE1671ABECDAULL,
		0xE26E82EB671A08DEULL,
		0xE60535782F0DC5A2ULL,
		0x57DD56FEFD7717F0ULL,
		0x2DCF974A70273869ULL,
		0x007F86AD75F1D560ULL,
		0x027984AE8094082FULL,
		0x134F0FF9D2EFBC03ULL
	}};
	sign = 0;
	printf("Test Case 403\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 403 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -403;
	} else {
		printf("Test Case 403 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4A5E3A430BFE7627ULL,
		0xB3EE7BE0BEE0A1FCULL,
		0x5D074618238641C7ULL,
		0xB2E871C8FF44739DULL,
		0x713A02B1820EB43FULL,
		0x7555EBCB49C2D26BULL,
		0xA457D147699BC348ULL,
		0xE5F7D93ED0D2E0D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x751CDA6C0E7D5EE6ULL,
		0x4A04E1F7E025B990ULL,
		0x09E4629D42633469ULL,
		0x43D8B0A66CBCECF1ULL,
		0x63BED921D33A6686ULL,
		0xB38757256C1EB927ULL,
		0xBEEA91D19B987753ULL,
		0xEBE64E8D546AB4FDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD5415FD6FD811741ULL,
		0x69E999E8DEBAE86BULL,
		0x5322E37AE1230D5EULL,
		0x6F0FC122928786ACULL,
		0x0D7B298FAED44DB9ULL,
		0xC1CE94A5DDA41944ULL,
		0xE56D3F75CE034BF4ULL,
		0xFA118AB17C682BD3ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 404\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 404 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -404;
	} else {
		printf("Test Case 404 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x947CF3305E14126DULL,
		0x5445E06D3BAE8084ULL,
		0x11358C72B02AFA0EULL,
		0x58EAA87BD005C089ULL,
		0x2AD5DC834FF13A55ULL,
		0x459B18103A1E3DEAULL,
		0xFE00E395D83D65A0ULL,
		0x09F36741F4B83E60ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78D38E4319B6ACB8ULL,
		0xDD6683ABE1719284ULL,
		0x9E749BB9238189F8ULL,
		0xA4060672398DEFF7ULL,
		0x93D7AD664C74E8B9ULL,
		0x9E0E4EB3C21B3CE3ULL,
		0xC191017A1E755591ULL,
		0xA61EB8EFD7326B1AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1BA964ED445D65B5ULL,
		0x76DF5CC15A3CEE00ULL,
		0x72C0F0B98CA97015ULL,
		0xB4E4A2099677D091ULL,
		0x96FE2F1D037C519BULL,
		0xA78CC95C78030106ULL,
		0x3C6FE21BB9C8100EULL,
		0x63D4AE521D85D346ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 405\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 405 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -405;
	} else {
		printf("Test Case 405 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9881F209FEBF20DFULL,
		0x71A059D719CBCB6BULL,
		0x590AC32D387AB562ULL,
		0x80D560C99745029FULL,
		0xA6C97E7856112C79ULL,
		0x9D2003555F8837D3ULL,
		0xEC96571758E1A238ULL,
		0x196FD4632A3B7D3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E8ACA49C35163A5ULL,
		0x2A89B2B636F6689BULL,
		0xD94ECF1F51BDAF38ULL,
		0x258F3C4620DB9995ULL,
		0x2BAF838C1786F5EFULL,
		0x72285EDE24FA87D4ULL,
		0x3BC52EA44BBA845BULL,
		0x91EE8A4ED0C56E02ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x29F727C03B6DBD3AULL,
		0x4716A720E2D562D0ULL,
		0x7FBBF40DE6BD062AULL,
		0x5B46248376696909ULL,
		0x7B19FAEC3E8A368AULL,
		0x2AF7A4773A8DAFFFULL,
		0xB0D128730D271DDDULL,
		0x87814A1459760F38ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 406\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 406 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -406;
	} else {
		printf("Test Case 406 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0F16B78D1E4898A5ULL,
		0x06413B929CFA5303ULL,
		0x63AE04C369F4B9DFULL,
		0xC091FAB2A373AE9DULL,
		0x196DC97CDD247BAEULL,
		0xD7748F8D55F9E51EULL,
		0x746ED812CFE76D2BULL,
		0x372C8FE65F8F481AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x678630E0A27A4837ULL,
		0x2E7460FF92415221ULL,
		0x8B65E73F14174E4AULL,
		0x998BBF10AC638EB1ULL,
		0x58BAEF6DE9A2A873ULL,
		0x1832C6E6C10366B4ULL,
		0x57A0968506379020ULL,
		0x6D05597855EC0F96ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA79086AC7BCE506EULL,
		0xD7CCDA930AB900E1ULL,
		0xD8481D8455DD6B94ULL,
		0x27063BA1F7101FEBULL,
		0xC0B2DA0EF381D33BULL,
		0xBF41C8A694F67E69ULL,
		0x1CCE418DC9AFDD0BULL,
		0xCA27366E09A33884ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 407\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 407 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -407;
	} else {
		printf("Test Case 407 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x92405F62C83E7891ULL,
		0x73326894BB7BD167ULL,
		0x0140BDE516C75E9EULL,
		0xDF561BB81128642FULL,
		0xEA761A58E7D925A7ULL,
		0x6E8DE6B56F09355FULL,
		0xBB68CD0191EB092BULL,
		0x38B5AEDB671B75A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF02C3D3F9C95121ULL,
		0xFA30B33C523E2B77ULL,
		0xD3C6E233B1C2FC56ULL,
		0xC2A88C30F5E70DF1ULL,
		0xBD1D4B3DE6DB0CC4ULL,
		0xFE0E018E76A74CF5ULL,
		0x85A3F64276E8EE27ULL,
		0xD0704ABC6734CFDEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB33D9B8ECE752770ULL,
		0x7901B558693DA5EFULL,
		0x2D79DBB165046247ULL,
		0x1CAD8F871B41563DULL,
		0x2D58CF1B00FE18E3ULL,
		0x707FE526F861E86AULL,
		0x35C4D6BF1B021B03ULL,
		0x6845641EFFE6A5C6ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 408\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 408 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -408;
	} else {
		printf("Test Case 408 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFAFB3551B57E033FULL,
		0xD5252573985D2166ULL,
		0x7F3F92E930C04DB1ULL,
		0xE6951561FB1CA90AULL,
		0x6344E7FADD8B3D65ULL,
		0xD08F2FFF6933C7F5ULL,
		0x8ACFC9734C9E57DBULL,
		0xA8E74C97055C8CE2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x553D7A3E520FA747ULL,
		0x53A53F09579A1835ULL,
		0xF977B545E8D6959AULL,
		0xA31B25096BAC9A84ULL,
		0x5D5376D3610B6829ULL,
		0x10C8ABCF18140C9EULL,
		0x155614772443ADCFULL,
		0x09A8145D33162FB3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA5BDBB13636E5BF8ULL,
		0x817FE66A40C30931ULL,
		0x85C7DDA347E9B817ULL,
		0x4379F0588F700E85ULL,
		0x05F171277C7FD53CULL,
		0xBFC68430511FBB57ULL,
		0x7579B4FC285AAA0CULL,
		0x9F3F3839D2465D2FULL
	}};
	sign = 0;
	printf("Test Case 409\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 409 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -409;
	} else {
		printf("Test Case 409 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x78058975503F3B71ULL,
		0x8659FF72BCA0A885ULL,
		0xDF8AB060088DEF79ULL,
		0xF9398B3E71D50FD8ULL,
		0xB809D0FDBD32E535ULL,
		0x680F4EDA86B28DC3ULL,
		0x52D8A39F1683DDDAULL,
		0xAA013AA4AA8C1A64ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x317CC2D7A82D13B6ULL,
		0xD5524B3F746426BBULL,
		0x4063ACBE14BB7266ULL,
		0xEE212D99547524AAULL,
		0xAADD50C61C6D8854ULL,
		0x336476B77D51B010ULL,
		0xF03D8842AD052568ULL,
		0xD72EE3365D43503FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4688C69DA81227BBULL,
		0xB107B433483C81CAULL,
		0x9F2703A1F3D27D12ULL,
		0x0B185DA51D5FEB2EULL,
		0x0D2C8037A0C55CE1ULL,
		0x34AAD8230960DDB3ULL,
		0x629B1B5C697EB872ULL,
		0xD2D2576E4D48CA24ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 410\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 410 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -410;
	} else {
		printf("Test Case 410 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4CE31FCBE5A83D08ULL,
		0x90C242C4722A79CAULL,
		0x6D951A7AD1D9D4CBULL,
		0xE64764FCF9A2209AULL,
		0x1AA780D094AE5888ULL,
		0x4CB26AD1031A0C9DULL,
		0xC9C76351D463636BULL,
		0x9E63D92B39E1C903ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3552D25AD4BC3750ULL,
		0xD17F8A9C97C22AA0ULL,
		0xE3BBA5F88E7CBC28ULL,
		0x6F5DE7161C712D0EULL,
		0x094C40B56100D98FULL,
		0xCF98BF36289F006AULL,
		0x9F104B6B21CFBDD5ULL,
		0x1893EABE6FD5C0FCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x17904D7110EC05B8ULL,
		0xBF42B827DA684F2AULL,
		0x89D97482435D18A2ULL,
		0x76E97DE6DD30F38BULL,
		0x115B401B33AD7EF9ULL,
		0x7D19AB9ADA7B0C33ULL,
		0x2AB717E6B293A595ULL,
		0x85CFEE6CCA0C0807ULL
	}};
	sign = 0;
	printf("Test Case 411\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 411 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -411;
	} else {
		printf("Test Case 411 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x39629A667DB285CEULL,
		0xC7D1F6D0DFC90D4EULL,
		0x938FD6B300461146ULL,
		0xF049AAB1D01B9BBFULL,
		0x2489FD6B3CC5C0E5ULL,
		0x451BEB3E9AF50ED6ULL,
		0x0C06ABAC57669D0AULL,
		0x73E6213EE62C1578ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x347AE8184612D4A2ULL,
		0xAB1564DC2D8F9948ULL,
		0x69FE652C3B358796ULL,
		0xB2DF342AA59ECE4CULL,
		0xED22D8574E03770BULL,
		0xF961A0E63BFEA2EEULL,
		0x294BA3E0962AEE4FULL,
		0xF69317FEB95918C6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04E7B24E379FB12CULL,
		0x1CBC91F4B2397406ULL,
		0x29917186C51089B0ULL,
		0x3D6A76872A7CCD73ULL,
		0x37672513EEC249DAULL,
		0x4BBA4A585EF66BE7ULL,
		0xE2BB07CBC13BAEBAULL,
		0x7D5309402CD2FCB1ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 412\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 412 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -412;
	} else {
		printf("Test Case 412 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFB43198A3E934004ULL,
		0x986018F817FCC082ULL,
		0x0BE144B4D57DE735ULL,
		0xBADA760327711D0CULL,
		0xAEA97541F5A38D4CULL,
		0xD25D07723DE55071ULL,
		0x0899D5DEFC770F4FULL,
		0x6FF51CF55D556215ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x720A455E6D384A21ULL,
		0x7CF3E221980F4AB3ULL,
		0x92C741FC3EBD763BULL,
		0x4CFC68013E7F8239ULL,
		0x630C9722B4223A37ULL,
		0xD6F512F13D1EB63BULL,
		0x759232D06614FC0EULL,
		0x20C8E6761F677829ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8938D42BD15AF5E3ULL,
		0x1B6C36D67FED75CFULL,
		0x791A02B896C070FAULL,
		0x6DDE0E01E8F19AD2ULL,
		0x4B9CDE1F41815315ULL,
		0xFB67F48100C69A36ULL,
		0x9307A30E96621340ULL,
		0x4F2C367F3DEDE9EBULL
	}};
	sign = 0;
	printf("Test Case 413\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 413 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -413;
	} else {
		printf("Test Case 413 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF3EFAA82DF0DCC5CULL,
		0xF2CEEA5C98B37661ULL,
		0xECCD5AACF20FA537ULL,
		0xD3F4A241BDCED534ULL,
		0xF5F3CC0E14EE79F2ULL,
		0x72D6B5F1187502C8ULL,
		0x1B848157687026EDULL,
		0x8F9B0E4E0AD5156BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D225FFDD88E3C24ULL,
		0xF7F81C9BE6E978BCULL,
		0xDC5B423BE9B57F68ULL,
		0x18ECDEF0E7D7F249ULL,
		0xD8B38CC3F6036613ULL,
		0x6185711C38FD2935ULL,
		0x0776192BB8492D65ULL,
		0xDA26065DBD75E33AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC6CD4A85067F9038ULL,
		0xFAD6CDC0B1C9FDA5ULL,
		0x10721871085A25CEULL,
		0xBB07C350D5F6E2EBULL,
		0x1D403F4A1EEB13DFULL,
		0x115144D4DF77D993ULL,
		0x140E682BB026F988ULL,
		0xB57507F04D5F3231ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 414\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 414 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -414;
	} else {
		printf("Test Case 414 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB905913F872CB440ULL,
		0x6537F7BC783C68ACULL,
		0x8C37855119542084ULL,
		0x009887B5CD10656AULL,
		0x18BB2848C435E6EFULL,
		0xAAC86DD6B45EC803ULL,
		0xF7AEAB2D6FF249CCULL,
		0xD0DB0E525191234EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68E2B25D043E475EULL,
		0x0AFA326DADF18F10ULL,
		0x74EDB04C0F2DA908ULL,
		0x89B545A9B5B4FDB5ULL,
		0x7CB0C480ABE9272FULL,
		0xAED1CD2BFC8552BBULL,
		0xBD4FE49774EC3608ULL,
		0xF079D3F9F1F7A4A0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5022DEE282EE6CE2ULL,
		0x5A3DC54ECA4AD99CULL,
		0x1749D5050A26777CULL,
		0x76E3420C175B67B5ULL,
		0x9C0A63C8184CBFBFULL,
		0xFBF6A0AAB7D97547ULL,
		0x3A5EC695FB0613C3ULL,
		0xE0613A585F997EAEULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 415\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 415 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -415;
	} else {
		printf("Test Case 415 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4DE14F14BD596ACCULL,
		0xCAE40FD00C9AEBB2ULL,
		0xE4ACC6427A4E5865ULL,
		0xA612616B18570351ULL,
		0xEEDC19739C75AD35ULL,
		0x2F9943A2191E63EAULL,
		0xB3AFF126F2EF5A0BULL,
		0x9506EBCE8F4C96ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5619C29AF0208F0BULL,
		0x7F2B0DE00FA84E14ULL,
		0x170C4D071A1D559CULL,
		0xF99AE1623136E673ULL,
		0x9014E9BD4AE67A3DULL,
		0x6A051B1D9613AA09ULL,
		0xABC50118976EB5F2ULL,
		0x80783A104BCAB486ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF7C78C79CD38DBC1ULL,
		0x4BB901EFFCF29D9DULL,
		0xCDA0793B603102C9ULL,
		0xAC778008E7201CDEULL,
		0x5EC72FB6518F32F7ULL,
		0xC5942884830AB9E1ULL,
		0x07EAF00E5B80A418ULL,
		0x148EB1BE4381E226ULL
	}};
	sign = 0;
	printf("Test Case 416\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 416 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -416;
	} else {
		printf("Test Case 416 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8143C536462EEF9EULL,
		0x31782045B52928B6ULL,
		0x37ACCF5242B1C3DFULL,
		0xC3333B7AC4DED5B7ULL,
		0xB15D127A20E2A8B1ULL,
		0x97941A694F700F25ULL,
		0x6C28C3E4FCCCBB58ULL,
		0x2859309724D52472ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6190D06FB8829CC4ULL,
		0x26753F997560F343ULL,
		0x889535672D60ADBCULL,
		0xEFE1CDC1C14398E6ULL,
		0x58E857A40BDE19F3ULL,
		0x014F611A7CA6940CULL,
		0xB07BA2FBC44CE729ULL,
		0x3B2D26C5B34A5BEAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1FB2F4C68DAC52DAULL,
		0x0B02E0AC3FC83573ULL,
		0xAF1799EB15511623ULL,
		0xD3516DB9039B3CD0ULL,
		0x5874BAD615048EBDULL,
		0x9644B94ED2C97B19ULL,
		0xBBAD20E9387FD42FULL,
		0xED2C09D1718AC887ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 417\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 417 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -417;
	} else {
		printf("Test Case 417 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5F7B383591018704ULL,
		0x01A1CC3EC027F309ULL,
		0xC6BF09272FE01DFEULL,
		0xDCF106F665868224ULL,
		0x58129A917635A49AULL,
		0xD1A2B9FE3BF4EA84ULL,
		0x9B73544243C27670ULL,
		0x28FCA7D5D9830057ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x914037CE3EFC6896ULL,
		0x8DCB85DCB6E3DE50ULL,
		0x3EF60C76AF46A745ULL,
		0x716FEFFDB056C364ULL,
		0x66EC75F931B1059EULL,
		0x1DEB0359C9810FA7ULL,
		0x8875D9D3E387C18DULL,
		0xA71FD4F735085DC5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCE3B006752051E6EULL,
		0x73D64662094414B8ULL,
		0x87C8FCB0809976B8ULL,
		0x6B8116F8B52FBEC0ULL,
		0xF126249844849EFCULL,
		0xB3B7B6A47273DADCULL,
		0x12FD7A6E603AB4E3ULL,
		0x81DCD2DEA47AA292ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 418\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 418 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -418;
	} else {
		printf("Test Case 418 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCBF81C87BFDE0DA4ULL,
		0x6C7EA4C3F7AB0085ULL,
		0x163B76F2596093AFULL,
		0x8EAF8F3E077AD7EDULL,
		0x48D1C435F9610E23ULL,
		0x5EF0E00409E18CD7ULL,
		0x1B76CED733A72F47ULL,
		0xB6F687C01CE7F7EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26AA13BEE78A4CE8ULL,
		0xDDCB79BD186BDD50ULL,
		0xFA33DB1BAB58E144ULL,
		0x09F2831D99508603ULL,
		0x274C36DC5B11836CULL,
		0xDAD4618EC2689422ULL,
		0xC812184926966873ULL,
		0xF3B05CD91C66D449ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA54E08C8D853C0BCULL,
		0x8EB32B06DF3F2335ULL,
		0x1C079BD6AE07B26AULL,
		0x84BD0C206E2A51E9ULL,
		0x21858D599E4F8AB7ULL,
		0x841C7E754778F8B5ULL,
		0x5364B68E0D10C6D3ULL,
		0xC3462AE7008123A0ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 419\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 419 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -419;
	} else {
		printf("Test Case 419 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFF05DCF2A5C0C600ULL,
		0xC0D479AC261E52B1ULL,
		0x4ACC366D7E4A909FULL,
		0xE82BE2CC6E61848FULL,
		0xFD877AA8458F4E06ULL,
		0xCA4A87BD7B13E56CULL,
		0xACB187ADA7633694ULL,
		0x421BA8574DB9226FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD78CB4D3F8B8AFFDULL,
		0x4227AF5C40B89551ULL,
		0x49EBD747A1E77E70ULL,
		0xE2E6B0B45B7F154CULL,
		0x98FFDE05AACAE87CULL,
		0x0702414EA49A2E39ULL,
		0x3855F11E77C30107ULL,
		0x719CF85C9B1D7D2FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2779281EAD081603ULL,
		0x7EACCA4FE565BD60ULL,
		0x00E05F25DC63122FULL,
		0x0545321812E26F43ULL,
		0x64879CA29AC4658AULL,
		0xC348466ED679B733ULL,
		0x745B968F2FA0358DULL,
		0xD07EAFFAB29BA540ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 420\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 420 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -420;
	} else {
		printf("Test Case 420 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBF634661A13FA1E8ULL,
		0xC1B54ECA883B484BULL,
		0xB2B321D152299B43ULL,
		0x0067DD15ECD8E080ULL,
		0x3CAE1BECDFB75FBDULL,
		0x37E330616D436435ULL,
		0xE079A331F5DF3CF8ULL,
		0x10AB71E57F235D4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C54ECE2424B95E0ULL,
		0xA02B250E5EDE6911ULL,
		0x996A456D5420BF6DULL,
		0x1344EE6838DB249CULL,
		0x56137C94E4D94187ULL,
		0xF90E7351B531CC31ULL,
		0x5B44F962BDBB817EULL,
		0xC1B10FAD7F95E766ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x330E597F5EF40C08ULL,
		0x218A29BC295CDF3AULL,
		0x1948DC63FE08DBD6ULL,
		0xED22EEADB3FDBBE4ULL,
		0xE69A9F57FADE1E35ULL,
		0x3ED4BD0FB8119803ULL,
		0x8534A9CF3823BB79ULL,
		0x4EFA6237FF8D75E8ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 421\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 421 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -421;
	} else {
		printf("Test Case 421 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF475D9298CF70CE2ULL,
		0x8A3CBC2AD2F057BAULL,
		0xACF476318BDDEB58ULL,
		0x1B535D1CBA7A6996ULL,
		0xD3D1A38F63206B5CULL,
		0xD5DB5A7F66DBDC0AULL,
		0x8AF3A804E9FDE01CULL,
		0xA47C99FBB5479118ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A405A5CF4C1075FULL,
		0xC228E00090EC9020ULL,
		0x514019F6698CF6D3ULL,
		0x2082F5D7BC1E78E3ULL,
		0x04B84F61C55E76BFULL,
		0xEC41A8D9E13A9BFCULL,
		0x1B8E520400A9FCECULL,
		0xAB55591A27E05A1FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9A357ECC98360583ULL,
		0xC813DC2A4203C79AULL,
		0x5BB45C3B2250F484ULL,
		0xFAD06744FE5BF0B3ULL,
		0xCF19542D9DC1F49CULL,
		0xE999B1A585A1400EULL,
		0x6F655600E953E32FULL,
		0xF92740E18D6736F9ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 422\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 422 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -422;
	} else {
		printf("Test Case 422 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3A0DBB2D2D6E8B3BULL,
		0xB1B55658F37AF64BULL,
		0x965E208A94A7F9D4ULL,
		0xEC9545274A6B93C6ULL,
		0x705E1D1B7ECEDAE4ULL,
		0xE457F1D7E5AB059AULL,
		0x01913459A4980750ULL,
		0x65BC71B3A7EDF4FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D17E018E8A813C4ULL,
		0xADAF20326A3D9B4DULL,
		0xF919449E3E89D11BULL,
		0xB118CD4A0B0962D1ULL,
		0x96338B7F09E98D48ULL,
		0xF64F25499B7D2714ULL,
		0x9C7C0EE946C934A3ULL,
		0x07C9966EDD1EF63AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2CF5DB1444C67777ULL,
		0x04063626893D5AFEULL,
		0x9D44DBEC561E28B9ULL,
		0x3B7C77DD3F6230F4ULL,
		0xDA2A919C74E54D9CULL,
		0xEE08CC8E4A2DDE85ULL,
		0x651525705DCED2ACULL,
		0x5DF2DB44CACEFEC0ULL
	}};
	sign = 0;
	printf("Test Case 423\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 423 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -423;
	} else {
		printf("Test Case 423 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x09DC208F9FB4D218ULL,
		0x5D24B22D92071AB4ULL,
		0x5FADC9311298E8B2ULL,
		0x36B4E7FA7A27A3F3ULL,
		0x3B71B34C562D131CULL,
		0x0D13C657385BC942ULL,
		0xFB13FE478645AD00ULL,
		0x13612F0E5B6DDB24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70F94F8E647F8326ULL,
		0x3026D4EF9AD16EC2ULL,
		0x2DF5EA6BA8750BC9ULL,
		0xE4B2435CE52DB566ULL,
		0xC4422C19A0150C95ULL,
		0xC1B1CB7F1874FC56ULL,
		0xE9B3E16EF6CF3767ULL,
		0x248F4A7AAC33959BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x98E2D1013B354EF2ULL,
		0x2CFDDD3DF735ABF1ULL,
		0x31B7DEC56A23DCE9ULL,
		0x5202A49D94F9EE8DULL,
		0x772F8732B6180686ULL,
		0x4B61FAD81FE6CCEBULL,
		0x11601CD88F767598ULL,
		0xEED1E493AF3A4589ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 424\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 424 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -424;
	} else {
		printf("Test Case 424 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7B735DC1D6EF4EA5ULL,
		0x27ED2E33164A4B65ULL,
		0xCF73B05FCC6A4BE3ULL,
		0x0F4ED44E777CBAF0ULL,
		0x09182671AD9293E5ULL,
		0xC181F43813FF98E4ULL,
		0x1D82F9F2D59F64FDULL,
		0x6E8C7BD2A805B723ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F5F7265BC844AA2ULL,
		0x1266630E7151DEA1ULL,
		0xF39FD861BCB3FA8CULL,
		0x48FE8A5C11843FB1ULL,
		0xAF192DA650FACC90ULL,
		0x797E18E4CA75233CULL,
		0x4EA62DFDF6E6BE2BULL,
		0x2C2B279E2B7F3EA9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2C13EB5C1A6B0403ULL,
		0x1586CB24A4F86CC4ULL,
		0xDBD3D7FE0FB65157ULL,
		0xC65049F265F87B3EULL,
		0x59FEF8CB5C97C754ULL,
		0x4803DB53498A75A7ULL,
		0xCEDCCBF4DEB8A6D2ULL,
		0x426154347C867879ULL
	}};
	sign = 0;
	printf("Test Case 425\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 425 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -425;
	} else {
		printf("Test Case 425 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBB35D01094E8EEC1ULL,
		0x757F976707E3F08BULL,
		0xFF9157D3C6E43266ULL,
		0xCC52CF646FB782AAULL,
		0xE742455FAB17E4CAULL,
		0xC839446FAFAEB354ULL,
		0xD952EC6B022673E2ULL,
		0x336BD866762F4520ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B1FC14A9E55A5BBULL,
		0xFC2873512A943D59ULL,
		0xD56A1D706E68D2D3ULL,
		0x71263D217ACC90B7ULL,
		0x0B0397EE2879B493ULL,
		0x1A93DDACB66EE5D2ULL,
		0xBA86ACEC7FDB223DULL,
		0x908CA8A83FECE5DFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x20160EC5F6934906ULL,
		0x79572415DD4FB332ULL,
		0x2A273A63587B5F92ULL,
		0x5B2C9242F4EAF1F3ULL,
		0xDC3EAD71829E3037ULL,
		0xADA566C2F93FCD82ULL,
		0x1ECC3F7E824B51A5ULL,
		0xA2DF2FBE36425F41ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 426\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 426 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -426;
	} else {
		printf("Test Case 426 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB1E59D78D34B6A5FULL,
		0x92001F9702D00DB0ULL,
		0xA5383DA505F6793DULL,
		0x35F83AF79B682A33ULL,
		0x3ADAD292D3731C63ULL,
		0xF215E276916D7121ULL,
		0x9EC6C82F47F1B98AULL,
		0xC6932E27165BE8ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA892A8B9EC6803ABULL,
		0xE88FBAEEAE16BD78ULL,
		0x22B251E8F823ACA2ULL,
		0x338235C8848064CAULL,
		0x0E4B474643EE01ADULL,
		0x2D36FE22D148D21DULL,
		0xFC5A43F1CE883BFCULL,
		0x54FE1FE8749A651AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0952F4BEE6E366B4ULL,
		0xA97064A854B95038ULL,
		0x8285EBBC0DD2CC9AULL,
		0x0276052F16E7C569ULL,
		0x2C8F8B4C8F851AB6ULL,
		0xC4DEE453C0249F04ULL,
		0xA26C843D79697D8EULL,
		0x71950E3EA1C18391ULL
	}};
	sign = 0;
	printf("Test Case 427\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 427 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -427;
	} else {
		printf("Test Case 427 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x43B428F975A769E2ULL,
		0x07B03C917D9AD185ULL,
		0x7870CC1D0D403108ULL,
		0x2B1F967EFEB73BC7ULL,
		0x6F1E3DDF3A61AD58ULL,
		0x214989C572F3FFF6ULL,
		0xF522D8AD4F87A433ULL,
		0xFBEA30457C66E099ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC198E7835EF4A63ULL,
		0xD084049A3C7DFE4DULL,
		0xDB5152D429BF9FC2ULL,
		0x7D3E11E94752BBB2ULL,
		0x904B796D7B35BFE6ULL,
		0xF6AC8F2D00B4127AULL,
		0x9198CE81DF690E63ULL,
		0xDFBAE455379CDA22ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x779A9A813FB81F7FULL,
		0x372C37F7411CD337ULL,
		0x9D1F7948E3809145ULL,
		0xADE18495B7648014ULL,
		0xDED2C471BF2BED71ULL,
		0x2A9CFA98723FED7BULL,
		0x638A0A2B701E95CFULL,
		0x1C2F4BF044CA0677ULL
	}};
	sign = 0;
	printf("Test Case 428\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 428 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -428;
	} else {
		printf("Test Case 428 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x57216A2B83DC04BCULL,
		0x535F251F1A51D4A5ULL,
		0x51C8DBCA3F606A60ULL,
		0xD207A8921BCD9A38ULL,
		0x5F89842E403B6948ULL,
		0x4853736671304D3AULL,
		0xDA9DBF20D62537AAULL,
		0x9CB2E2392FC5976AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC1681DADDDC2B75ULL,
		0xFB6673D2C2CC836CULL,
		0xB2B08D687DCAA5B6ULL,
		0xAFBB9E221E905196ULL,
		0xBDB4177EF78C07B3ULL,
		0x6E7E79831A394555ULL,
		0xA11D825616E47822ULL,
		0x5707EDD0B9483C89ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7B0AE850A5FFD947ULL,
		0x57F8B14C57855138ULL,
		0x9F184E61C195C4A9ULL,
		0x224C0A6FFD3D48A1ULL,
		0xA1D56CAF48AF6195ULL,
		0xD9D4F9E356F707E4ULL,
		0x39803CCABF40BF87ULL,
		0x45AAF468767D5AE1ULL
	}};
	sign = 0;
	printf("Test Case 429\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 429 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -429;
	} else {
		printf("Test Case 429 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCB37C1322AADCC41ULL,
		0x52A37F6C3FA9AE99ULL,
		0x8CB2E9EB69708D68ULL,
		0x5F75A80E3C2E0F3FULL,
		0x41E01786F9A96F46ULL,
		0xEB5650D6F47467A8ULL,
		0x64CBFFB5F2E6039AULL,
		0x5E04234683559E29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2868B5BA6A06B405ULL,
		0xE1CE39CABD7849F8ULL,
		0x0D12B17F2317DB9EULL,
		0xE4B344CD0D980A80ULL,
		0xC65A6368C2616075ULL,
		0x6D1C038C4F694621ULL,
		0x6EE1850EA9D7B15FULL,
		0x185DCAB062A8F3E9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA2CF0B77C0A7183CULL,
		0x70D545A1823164A1ULL,
		0x7FA0386C4658B1C9ULL,
		0x7AC263412E9604BFULL,
		0x7B85B41E37480ED0ULL,
		0x7E3A4D4AA50B2186ULL,
		0xF5EA7AA7490E523BULL,
		0x45A6589620ACAA3FULL
	}};
	sign = 0;
	printf("Test Case 430\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 430 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -430;
	} else {
		printf("Test Case 430 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6D79898B602E1FFAULL,
		0x7CCDE8DD6BB442D0ULL,
		0x83798F62E57145E6ULL,
		0x8B49FFE13A9045E0ULL,
		0x61F31160C262F6B1ULL,
		0xA9139F80086E9A24ULL,
		0x52048B58401D4749ULL,
		0x2946E3110F9C1439ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86218960CED061E1ULL,
		0x1981E132682F4E06ULL,
		0x76CD1B102E8AB53AULL,
		0x72877AD634DDC309ULL,
		0x8592D4F5500EEA38ULL,
		0x81605461EC167500ULL,
		0xC793145F235D9D81ULL,
		0xA73F08089AA9929AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE758002A915DBE19ULL,
		0x634C07AB0384F4C9ULL,
		0x0CAC7452B6E690ACULL,
		0x18C2850B05B282D7ULL,
		0xDC603C6B72540C79ULL,
		0x27B34B1E1C582523ULL,
		0x8A7176F91CBFA9C8ULL,
		0x8207DB0874F2819EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 431\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 431 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -431;
	} else {
		printf("Test Case 431 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8293AAAFA7E014B0ULL,
		0x2003C3736203D895ULL,
		0x82F2A05797DDF8CAULL,
		0x2293C2D8FD25918FULL,
		0x48A2120638904CA1ULL,
		0xB78B74888F36C3C6ULL,
		0x8167030A08FC4B18ULL,
		0x297C941546918118ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49D690A96D78F7A8ULL,
		0x26DD48C81911940CULL,
		0x2ADD762A7D291997ULL,
		0x8ACB26009EB46120ULL,
		0xAC64FF4D142E8371ULL,
		0x4592902ABC66A281ULL,
		0xF950101CFCCE7BE6ULL,
		0xC5A436C5C41B2170ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x38BD1A063A671D08ULL,
		0xF9267AAB48F24489ULL,
		0x58152A2D1AB4DF32ULL,
		0x97C89CD85E71306FULL,
		0x9C3D12B92461C92FULL,
		0x71F8E45DD2D02144ULL,
		0x8816F2ED0C2DCF32ULL,
		0x63D85D4F82765FA7ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 432\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 432 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -432;
	} else {
		printf("Test Case 432 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6DDEB559DD0450FBULL,
		0xA5913B55446A7309ULL,
		0x8690AACDD2DF098CULL,
		0x85B791A4BA56D4B2ULL,
		0xAE0866320C82A1EEULL,
		0xB045D01BADBEC0F0ULL,
		0xA824A40760341E58ULL,
		0xBC603135DB66269AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B68325E7C113247ULL,
		0x53C53705EA4A49D0ULL,
		0x8A0F8CD5AF9BEC2DULL,
		0x71ADFB0617CF2FF6ULL,
		0xC344FCB6B3F075A6ULL,
		0x9B6F9A6EF8E61AF3ULL,
		0x1B7130FA490B7C7EULL,
		0x514F0D5BA5EC0CA7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD27682FB60F31EB4ULL,
		0x51CC044F5A202938ULL,
		0xFC811DF823431D5FULL,
		0x1409969EA287A4BBULL,
		0xEAC3697B58922C48ULL,
		0x14D635ACB4D8A5FCULL,
		0x8CB3730D1728A1DAULL,
		0x6B1123DA357A19F3ULL
	}};
	sign = 0;
	printf("Test Case 433\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 433 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -433;
	} else {
		printf("Test Case 433 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD05EEA792EAAAEFDULL,
		0x2C0F4305DF69D2A3ULL,
		0x3A2B5E1970417EC7ULL,
		0xA1966C658724667BULL,
		0xC7C13B5527350CD8ULL,
		0x750AC986F43DC378ULL,
		0x7B2B410A4D092BD4ULL,
		0x302FAE78B4240BD9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE53DE7E41FB4BF05ULL,
		0x9D79CD8E0A092370ULL,
		0xD9C7821B682C5EB8ULL,
		0x89EEF6E95C8F90E7ULL,
		0xCD8D944A51BB16D0ULL,
		0xCC14D20234609BCBULL,
		0x54C8206892DACFC8ULL,
		0x6F8CD19C12D075E9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEB2102950EF5EFF8ULL,
		0x8E957577D560AF32ULL,
		0x6063DBFE0815200EULL,
		0x17A7757C2A94D593ULL,
		0xFA33A70AD579F608ULL,
		0xA8F5F784BFDD27ACULL,
		0x266320A1BA2E5C0BULL,
		0xC0A2DCDCA15395F0ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 434\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 434 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -434;
	} else {
		printf("Test Case 434 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCBDC54B42107CC9DULL,
		0x1EEC63D8A9F0F94BULL,
		0x91D363B2B5226B6EULL,
		0xB59BCC9498DC0CE1ULL,
		0x2B9BDCC1E22BEE5DULL,
		0xC4D63EE519BDB910ULL,
		0x07873B85B1A54BDAULL,
		0xA447588E282625ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37ACA321DFC16523ULL,
		0x572D4C28111DB945ULL,
		0x3348FB6B0D6DB9D1ULL,
		0x30A75490F3E9E4BFULL,
		0xA764F829AF066FA3ULL,
		0xD9E6080A8F764D10ULL,
		0xF36F09F31A903134ULL,
		0x779EC856C36B3192ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x942FB1924146677AULL,
		0xC7BF17B098D34006ULL,
		0x5E8A6847A7B4B19CULL,
		0x84F47803A4F22822ULL,
		0x8436E49833257EBAULL,
		0xEAF036DA8A476BFFULL,
		0x1418319297151AA5ULL,
		0x2CA8903764BAF41AULL
	}};
	sign = 0;
	printf("Test Case 435\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 435 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -435;
	} else {
		printf("Test Case 435 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDA27BA334DA95703ULL,
		0x82011CCFA7EF7BD5ULL,
		0xE1A2478F56847F20ULL,
		0x3827ABBA24BEC32CULL,
		0xDED0F8B0F8CCFB57ULL,
		0x59340F5F2FAFA77FULL,
		0xBCEFE53EE949642AULL,
		0xAF9D738EDC245AFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0FB8A128252D769ULL,
		0xB87F722DE6CF1B22ULL,
		0xFB2BDF5541D4CBB6ULL,
		0x1EAC38222F08AE92ULL,
		0x770E59CD4B92D03FULL,
		0x519254C15B42DDDAULL,
		0xC297415445E37C9CULL,
		0xE0ABF08A3378F3C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE92C3020CB567F9AULL,
		0xC981AAA1C12060B2ULL,
		0xE676683A14AFB369ULL,
		0x197B7397F5B61499ULL,
		0x67C29EE3AD3A2B18ULL,
		0x07A1BA9DD46CC9A5ULL,
		0xFA58A3EAA365E78EULL,
		0xCEF18304A8AB6739ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 436\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 436 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -436;
	} else {
		printf("Test Case 436 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB309B89D85BFCFBBULL,
		0x7A04B21965ABAE30ULL,
		0xEC40B6F1643D31D1ULL,
		0xDC1CECB16E77A705ULL,
		0x64CE35D515AB8AE2ULL,
		0xE564DAA1FD5A4061ULL,
		0xFAD2C6D49056FDD9ULL,
		0x5A4FA91247143B08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52F60BC1EB941357ULL,
		0x51206506FF3C2DEAULL,
		0xE1006204128D0747ULL,
		0x7072760CACCEC2EFULL,
		0x1046438B4C0B377AULL,
		0x7F205C653BBD5045ULL,
		0x53E222915606DBB0ULL,
		0x9EA9E75422AFEB5CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6013ACDB9A2BBC64ULL,
		0x28E44D12666F8046ULL,
		0x0B4054ED51B02A8AULL,
		0x6BAA76A4C1A8E416ULL,
		0x5487F249C9A05368ULL,
		0x66447E3CC19CF01CULL,
		0xA6F0A4433A502229ULL,
		0xBBA5C1BE24644FACULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 437\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 437 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -437;
	} else {
		printf("Test Case 437 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0C5169A3833CD236ULL,
		0x8B8D9311D36102A8ULL,
		0xADAEADE7A4753FA4ULL,
		0xC4D7B5F67BB37951ULL,
		0x93AC75C5B255A588ULL,
		0xB88D98F5D56442BBULL,
		0x929B951A2C1D5B35ULL,
		0x4E2E612CB8B5FC38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1292F40D9B794732ULL,
		0x74BA85090271167BULL,
		0xEB7E290B78A1527EULL,
		0x416E0A3EFCC6DE20ULL,
		0x766E1D32D48DF8C0ULL,
		0x09B3D14966FB6815ULL,
		0xCD2E44AECDD3A260ULL,
		0xAD48C401F133F542ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF9BE7595E7C38B04ULL,
		0x16D30E08D0EFEC2CULL,
		0xC23084DC2BD3ED26ULL,
		0x8369ABB77EEC9B30ULL,
		0x1D3E5892DDC7ACC8ULL,
		0xAED9C7AC6E68DAA6ULL,
		0xC56D506B5E49B8D5ULL,
		0xA0E59D2AC78206F5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 438\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 438 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -438;
	} else {
		printf("Test Case 438 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3E6E068EE9D6C28DULL,
		0xF995D72D172192A8ULL,
		0xF8DE9BC9915F1957ULL,
		0x31D2A6D4DE42C413ULL,
		0x930DF459D2901F41ULL,
		0x76A1CF0F6DB5964CULL,
		0xD6263D636C303F44ULL,
		0xFF225D5768C18B49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BD6231BF9165506ULL,
		0xDE7928E77A20E04EULL,
		0x61C1F53AACCD8E00ULL,
		0xA565F9761F039B5CULL,
		0xCFB7E0B438A68010ULL,
		0x39145699941F12E2ULL,
		0x0C35A31C9DA1F075ULL,
		0xFEDE674BC986AE4EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2297E372F0C06D87ULL,
		0x1B1CAE459D00B25AULL,
		0x971CA68EE4918B57ULL,
		0x8C6CAD5EBF3F28B7ULL,
		0xC35613A599E99F30ULL,
		0x3D8D7875D9968369ULL,
		0xC9F09A46CE8E4ECFULL,
		0x0043F60B9F3ADCFBULL
	}};
	sign = 0;
	printf("Test Case 439\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 439 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -439;
	} else {
		printf("Test Case 439 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x31ADF62B31BA2EBEULL,
		0x8B7FCE212EA753E6ULL,
		0xF6A64FFAEA861B51ULL,
		0x18736BC0FFCE9DCDULL,
		0xB35165F543196B32ULL,
		0x3C8C3E56FD485B15ULL,
		0x4F122DAFA7DF2E4BULL,
		0xBAFF70B0EC784C80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88F8B61F8F23555AULL,
		0x95984AC86E566662ULL,
		0x93FE82AFEEA6D4D3ULL,
		0x6841A8BAF045B063ULL,
		0x3E7A36200DB9B69BULL,
		0x5569584EC2F20D5DULL,
		0xFD094E02BF94929CULL,
		0x2C552E5932C35B22ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA8B5400BA296D964ULL,
		0xF5E78358C050ED83ULL,
		0x62A7CD4AFBDF467DULL,
		0xB031C3060F88ED6AULL,
		0x74D72FD5355FB496ULL,
		0xE722E6083A564DB8ULL,
		0x5208DFACE84A9BAEULL,
		0x8EAA4257B9B4F15DULL
	}};
	sign = 0;
	printf("Test Case 440\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 440 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -440;
	} else {
		printf("Test Case 440 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2AFFECF92504055CULL,
		0x8381E9C518460DD2ULL,
		0xB169A1BFF62EBFBEULL,
		0x1F13D50BFCBB0E34ULL,
		0x96063A84942B5058ULL,
		0xCED130E05758E696ULL,
		0xFF3AE87192351531ULL,
		0xAC95D19C586FD836ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B92817EB2BB593DULL,
		0x2B011F3F1DA53641ULL,
		0x4E3B84B1D0548538ULL,
		0x8B0EEFF350EDF646ULL,
		0x1C6F0F01CB5331C3ULL,
		0x91B82668771ECBD8ULL,
		0x83EE8D0572F58781ULL,
		0x8276BA5D59339639ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1F6D6B7A7248AC1FULL,
		0x5880CA85FAA0D791ULL,
		0x632E1D0E25DA3A86ULL,
		0x9404E518ABCD17EEULL,
		0x79972B82C8D81E94ULL,
		0x3D190A77E03A1ABEULL,
		0x7B4C5B6C1F3F8DB0ULL,
		0x2A1F173EFF3C41FDULL
	}};
	sign = 0;
	printf("Test Case 441\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 441 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -441;
	} else {
		printf("Test Case 441 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC0DA3FA61B54F1A0ULL,
		0xDBCFA877714F4BA0ULL,
		0xE6C96D3E7E90C3FDULL,
		0xAB2D371957E587E8ULL,
		0xE80AF8C489CC7352ULL,
		0xE73C20FB1224A996ULL,
		0x88AB382F2DA5EEFDULL,
		0x802DCAC11D9235DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84046EAF1A4F5AE9ULL,
		0xA09A5C822292E961ULL,
		0x731AE123081ECB03ULL,
		0x5FE7BA1805AA3241ULL,
		0x94825F1DC77152AAULL,
		0x04929AB420D15125ULL,
		0xBCB2EF615626A66EULL,
		0x9ABF7C482E1F349AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3CD5D0F7010596B7ULL,
		0x3B354BF54EBC623FULL,
		0x73AE8C1B7671F8FAULL,
		0x4B457D01523B55A7ULL,
		0x538899A6C25B20A8ULL,
		0xE2A98646F1535871ULL,
		0xCBF848CDD77F488FULL,
		0xE56E4E78EF73013FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 442\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 442 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -442;
	} else {
		printf("Test Case 442 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB3B2488C7DD67BFAULL,
		0xAC645925C8DF166AULL,
		0x84B03282A4852CF7ULL,
		0xE516D8DD25BC04A6ULL,
		0x39FFC11085EA406DULL,
		0xE3B40B41F661F58FULL,
		0xC1125467CC0E4035ULL,
		0x458668A3B9C599ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FB0F843FA35D9F4ULL,
		0xE8BE6B91E22E6B50ULL,
		0x86AD544ED46B58DBULL,
		0xBFAF72A3B14A308BULL,
		0x2507CFF23512835AULL,
		0x4EBE137C905E489EULL,
		0x8DAB535F0A57A61AULL,
		0x58F54FCC81C255F7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1401504883A0A206ULL,
		0xC3A5ED93E6B0AB1AULL,
		0xFE02DE33D019D41BULL,
		0x256766397471D41AULL,
		0x14F7F11E50D7BD13ULL,
		0x94F5F7C56603ACF1ULL,
		0x33670108C1B69A1BULL,
		0xEC9118D7380343B6ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 443\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 443 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -443;
	} else {
		printf("Test Case 443 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x774F5B74CAC78698ULL,
		0x76B01692B073B14FULL,
		0x56064D8DF019C81BULL,
		0x15944EBA255C51BEULL,
		0x9BB802DA026436F5ULL,
		0x1CE4ED92C1A27297ULL,
		0x8C1B53F31D7253F2ULL,
		0x10FE25FCB130CF11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13C6148764EE2595ULL,
		0x1D170ECB6B814685ULL,
		0x38FB264CEF1070F0ULL,
		0x655193F9DE8DBD2AULL,
		0x8C58F54E514EA485ULL,
		0x3EBF32D3CB86AEDDULL,
		0x714211A213411883ULL,
		0xE534857D21FD92E3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x638946ED65D96103ULL,
		0x599907C744F26ACAULL,
		0x1D0B27410109572BULL,
		0xB042BAC046CE9494ULL,
		0x0F5F0D8BB115926FULL,
		0xDE25BABEF61BC3BAULL,
		0x1AD942510A313B6EULL,
		0x2BC9A07F8F333C2EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 444\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 444 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -444;
	} else {
		printf("Test Case 444 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7C8DD5A74BA1F8D8ULL,
		0x4772B4BC56F87602ULL,
		0xAF95747DC0C05C0DULL,
		0x20548E32CB9F22ADULL,
		0x453E632BF6222034ULL,
		0xEAF296E804135F13ULL,
		0x2F892EF20AE78CF4ULL,
		0x5C377E02732F1957ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DA87106B481A3FBULL,
		0x68F1FAB6E73F8274ULL,
		0xDF599C52341D6475ULL,
		0x3CC985A3552DEF54ULL,
		0x804155D7C2241CDAULL,
		0x5BC94F2D49E55E25ULL,
		0xA0812857A6BFBC90ULL,
		0x6A0F96494583051BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDEE564A0972054DDULL,
		0xDE80BA056FB8F38DULL,
		0xD03BD82B8CA2F797ULL,
		0xE38B088F76713358ULL,
		0xC4FD0D5433FE0359ULL,
		0x8F2947BABA2E00EDULL,
		0x8F08069A6427D064ULL,
		0xF227E7B92DAC143BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 445\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 445 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -445;
	} else {
		printf("Test Case 445 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xACD3518DAA38EFEDULL,
		0xCE5F0AC20F12FE7AULL,
		0xFC6CEE798C193686ULL,
		0xC960D15E678EB81FULL,
		0x30407EBEDCB611C4ULL,
		0x4D97F6A5B4B6FF40ULL,
		0x7A70EFAFBC605AADULL,
		0x512E9E05533255A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98AAF0D1B1E49C53ULL,
		0x3D7F483C9F7D3D0BULL,
		0x7BB6FE1F962A12D1ULL,
		0x4D932FC8933AB57AULL,
		0x017EBFB73F17859DULL,
		0x0E31440E6CAEEDF4ULL,
		0x71CC918B4184043EULL,
		0xA2B3EFA91728475EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x142860BBF854539AULL,
		0x90DFC2856F95C16FULL,
		0x80B5F059F5EF23B5ULL,
		0x7BCDA195D45402A5ULL,
		0x2EC1BF079D9E8C27ULL,
		0x3F66B2974808114CULL,
		0x08A45E247ADC566FULL,
		0xAE7AAE5C3C0A0E49ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 446\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 446 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -446;
	} else {
		printf("Test Case 446 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC008FA134FF1F7E3ULL,
		0x26EC1FF79018ADDCULL,
		0x7918C93565F04BD7ULL,
		0x8A2B8B1804AB6C09ULL,
		0x900BC4DBE926DF70ULL,
		0xD6858AB3409EABC5ULL,
		0x610598511E8F6931ULL,
		0x97F498C41A1C2759ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25F8D418DC58C53EULL,
		0x6618B7715B302B3DULL,
		0xDFCDD0B1B2E8F1DBULL,
		0x57865B7BEB06423AULL,
		0x1653FD8A28F5BB61ULL,
		0x6139D79B2637EB65ULL,
		0x38DCF95FA2723A90ULL,
		0x7F6890666A735D17ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9A1025FA739932A5ULL,
		0xC0D3688634E8829FULL,
		0x994AF883B30759FBULL,
		0x32A52F9C19A529CEULL,
		0x79B7C751C031240FULL,
		0x754BB3181A66C060ULL,
		0x28289EF17C1D2EA1ULL,
		0x188C085DAFA8CA42ULL
	}};
	sign = 0;
	printf("Test Case 447\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 447 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -447;
	} else {
		printf("Test Case 447 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF11612B745F5364BULL,
		0x8352AF5F5A7B274FULL,
		0xE80C7D73B5D0AC7BULL,
		0xDB5BD9FF29EDED8DULL,
		0x8B23FA70AB1CA114ULL,
		0x17B1A022C7834EA5ULL,
		0xE18FF181A10E8EBCULL,
		0x8183333980D0067DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD76B3EAF4B4FF714ULL,
		0xD0271F46E18A2A3FULL,
		0x5901F9CD2FEF56F4ULL,
		0x3F058686C6FCCE89ULL,
		0xD620A2CEA271D20CULL,
		0xDD8E48ECB56CD91BULL,
		0x65B205FEFDF5672DULL,
		0x8851B7A9D7DBE573ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x19AAD407FAA53F37ULL,
		0xB32B901878F0FD10ULL,
		0x8F0A83A685E15586ULL,
		0x9C56537862F11F04ULL,
		0xB50357A208AACF08ULL,
		0x3A23573612167589ULL,
		0x7BDDEB82A319278EULL,
		0xF9317B8FA8F4210AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 448\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 448 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -448;
	} else {
		printf("Test Case 448 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA08771323D28EC1BULL,
		0x9EB569F3A09021E8ULL,
		0x6C5B6B7C170CFEF8ULL,
		0x79CF1E4B031CE0ECULL,
		0xB38D4BDFB4454154ULL,
		0xFFC814DEEE10C711ULL,
		0xFF7B5A25B0BA1FA0ULL,
		0xCE2CD8A3D411F478ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AAD4D254BEDACC1ULL,
		0xE24DB73A48D73C1DULL,
		0x3B00E21F3111E200ULL,
		0x87D30966EB66C554ULL,
		0xE9A729587A979D3FULL,
		0xB847EF7FD8195B6FULL,
		0x1CFB6918C6A16C5FULL,
		0x3BBECB4AF8F9AE0DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x85DA240CF13B3F5AULL,
		0xBC67B2B957B8E5CBULL,
		0x315A895CE5FB1CF7ULL,
		0xF1FC14E417B61B98ULL,
		0xC9E6228739ADA414ULL,
		0x4780255F15F76BA1ULL,
		0xE27FF10CEA18B341ULL,
		0x926E0D58DB18466BULL
	}};
	sign = 0;
	printf("Test Case 449\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 449 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -449;
	} else {
		printf("Test Case 449 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x68C23FFEB90B0C96ULL,
		0xAE260722F663FEAAULL,
		0x376854F4C058F4E2ULL,
		0x6613782D01184183ULL,
		0x81EB0EC77E7018CDULL,
		0x24E3ED3A3065246DULL,
		0x345FC061774FE52EULL,
		0xC3BD1C61FFC1E3CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B189044C33C5D8FULL,
		0xA8748AF009A1F9DDULL,
		0x7CEAED0ACE848399ULL,
		0x32FA2A2B72E31A16ULL,
		0x5E1DBFC880DB945DULL,
		0x2D4D7F6AA3200B2BULL,
		0x9372E3738B942AB3ULL,
		0x2132B0A9BEAF0BD8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCDA9AFB9F5CEAF07ULL,
		0x05B17C32ECC204CCULL,
		0xBA7D67E9F1D47149ULL,
		0x33194E018E35276CULL,
		0x23CD4EFEFD948470ULL,
		0xF7966DCF8D451942ULL,
		0xA0ECDCEDEBBBBA7AULL,
		0xA28A6BB84112D7F6ULL
	}};
	sign = 0;
	printf("Test Case 450\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 450 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -450;
	} else {
		printf("Test Case 450 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9FCB0C7A1CA99B6BULL,
		0x0314CFA0E649C74AULL,
		0xE9624D94F7DE2588ULL,
		0xC5F096BCA0A178A4ULL,
		0xC7DC6F5C785B7892ULL,
		0x123078829A287B09ULL,
		0x80DAB4D10195FA4CULL,
		0x7880042AF89A15AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA80BD95CCDA0A658ULL,
		0x30B86617BD1997FCULL,
		0x0140BAD6E3E8A570ULL,
		0x736977EC6A763E64ULL,
		0x3B6101DD1B6B273FULL,
		0x0BEC2A37BAD98567ULL,
		0x0544AD7A3F373CFCULL,
		0xCC25B1E8B3634E01ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF7BF331D4F08F513ULL,
		0xD25C698929302F4DULL,
		0xE82192BE13F58017ULL,
		0x52871ED0362B3A40ULL,
		0x8C7B6D7F5CF05153ULL,
		0x06444E4ADF4EF5A2ULL,
		0x7B960756C25EBD50ULL,
		0xAC5A52424536C7ADULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 451\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 451 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -451;
	} else {
		printf("Test Case 451 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x625D5B2F5F3C6E53ULL,
		0x2C10771ADC17564AULL,
		0xDD9B76DCB2DC5D3DULL,
		0x803B138EC4E33A81ULL,
		0x08ADE5E44E05E67AULL,
		0xEF67C4062F749CDDULL,
		0x2ED3C018A99C5F27ULL,
		0x729618FC008613EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9D62620C0854BA6ULL,
		0x9AAF8F64F67C2481ULL,
		0x8868183B74DA76AEULL,
		0xD91AEA9AB8A20686ULL,
		0xD4BA2A77AF7BCA82ULL,
		0x07BCCE9FAB995EF2ULL,
		0x3F867B5C6FAFFDE2ULL,
		0x39ED7D25EF7D911FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8887350E9EB722ADULL,
		0x9160E7B5E59B31C8ULL,
		0x55335EA13E01E68EULL,
		0xA72028F40C4133FBULL,
		0x33F3BB6C9E8A1BF7ULL,
		0xE7AAF56683DB3DEAULL,
		0xEF4D44BC39EC6145ULL,
		0x38A89BD6110882CAULL
	}};
	sign = 0;
	printf("Test Case 452\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 452 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -452;
	} else {
		printf("Test Case 452 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEEE993A96D043074ULL,
		0x522D62CD62D87886ULL,
		0x60F9848B57AC78B0ULL,
		0x3DB762C0383F68E5ULL,
		0x1F0D84DAA9327194ULL,
		0x983B6FB08C501308ULL,
		0x8275951E5B2E23BFULL,
		0x31578BC2D4B21C68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1FA2C87FDDACB0EFULL,
		0xE52EF883AB6DD05FULL,
		0x4314900183435AA2ULL,
		0xD83233D47C247A6AULL,
		0xB9437D1F5F757B3DULL,
		0x82EC13280508B3C5ULL,
		0x1B17023B91414458ULL,
		0x9B4456FA2B4575E3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCF46CB298F577F85ULL,
		0x6CFE6A49B76AA827ULL,
		0x1DE4F489D4691E0DULL,
		0x65852EEBBC1AEE7BULL,
		0x65CA07BB49BCF656ULL,
		0x154F5C8887475F42ULL,
		0x675E92E2C9ECDF67ULL,
		0x961334C8A96CA685ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 453\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 453 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -453;
	} else {
		printf("Test Case 453 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1ECF7C173E9FB083ULL,
		0xFC93F5A2479EC2C3ULL,
		0xBB59C0A74694CC48ULL,
		0xA44F022E35D755F0ULL,
		0x6C40FCD30979BBB0ULL,
		0x46B4DCABAFD7466DULL,
		0x6CF3ED30F7B44650ULL,
		0x7E167330BE24C864ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC891EA743AB931BULL,
		0x5410CDBF9DCA90BAULL,
		0x2DBEC33C91F82B7BULL,
		0xCD2010822086FFE6ULL,
		0xC6AFEB2F2276F845ULL,
		0x99536811A5C4C14AULL,
		0xCC9FAF1D2B84A384ULL,
		0xAB715030B178CBCDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x32465D6FFAF41D68ULL,
		0xA88327E2A9D43208ULL,
		0x8D9AFD6AB49CA0CDULL,
		0xD72EF1AC1550560AULL,
		0xA59111A3E702C36AULL,
		0xAD61749A0A128522ULL,
		0xA0543E13CC2FA2CBULL,
		0xD2A523000CABFC96ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 454\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 454 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -454;
	} else {
		printf("Test Case 454 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x740011C330509C99ULL,
		0xF086339B441BBFC2ULL,
		0xD43B0CF46F31D7EBULL,
		0x398BB5DCA220D256ULL,
		0x3BE5CF2900B253A4ULL,
		0x64F7386F5BE90F63ULL,
		0x63216260F683E2C5ULL,
		0xA44DC0D189EAA12CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF69684D1D42246FULL,
		0x56A0102646D0AD0AULL,
		0x253F5ED3FCD6873AULL,
		0xC02F83FFB1F89928ULL,
		0xCDBC3F13D352FDDBULL,
		0x1ECB4E1EC9462656ULL,
		0x05DE4BC4706B9A57ULL,
		0x71DEB7D0114AEFA9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8496A976130E782AULL,
		0x99E62374FD4B12B7ULL,
		0xAEFBAE20725B50B1ULL,
		0x795C31DCF028392EULL,
		0x6E2990152D5F55C8ULL,
		0x462BEA5092A2E90CULL,
		0x5D43169C8618486EULL,
		0x326F0901789FB183ULL
	}};
	sign = 0;
	printf("Test Case 455\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 455 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -455;
	} else {
		printf("Test Case 455 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x178F952778F905F3ULL,
		0x6398C696D4B00208ULL,
		0xD7383AAA70C7F02DULL,
		0x791190D2165EC104ULL,
		0x4E4FD6BD050D52AEULL,
		0xDB80401E17B72CC7ULL,
		0x1D93C17FF172BFD8ULL,
		0x36E2FC5C4A1FF5FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85286F1BD31D7B9AULL,
		0xA88C35F6E830A368ULL,
		0x0CED0216878774DFULL,
		0x0D5E4AD76C0C94F1ULL,
		0x829B5839730B0AA7ULL,
		0xF7A876DFC16D1535ULL,
		0x1027B80F957C525EULL,
		0x0B1D27693DEA5194ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9267260BA5DB8A59ULL,
		0xBB0C909FEC7F5E9FULL,
		0xCA4B3893E9407B4DULL,
		0x6BB345FAAA522C13ULL,
		0xCBB47E8392024807ULL,
		0xE3D7C93E564A1791ULL,
		0x0D6C09705BF66D79ULL,
		0x2BC5D4F30C35A467ULL
	}};
	sign = 0;
	printf("Test Case 456\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 456 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -456;
	} else {
		printf("Test Case 456 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7AE97B920E0F3F1BULL,
		0x37E30297A077849FULL,
		0x2B141D5079CED2D6ULL,
		0xA1D162BC59890BC1ULL,
		0x5FACD1FB0DAF1D08ULL,
		0x85DD6D7E3EB20693ULL,
		0x82E7A4F6398A03ABULL,
		0xB2CDB1729E6DCB2FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AE280F6AF085E2FULL,
		0xA9B51578C9B86FD0ULL,
		0x19C5035AA1C929FFULL,
		0x1A0EC23C7D48B857ULL,
		0xAD396E91036D93FCULL,
		0xC7892110C77E2CE8ULL,
		0x90C81ED21052CCCCULL,
		0xB709EC6281AB64C0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4006FA9B5F06E0ECULL,
		0x8E2DED1ED6BF14CFULL,
		0x114F19F5D805A8D6ULL,
		0x87C2A07FDC40536AULL,
		0xB273636A0A41890CULL,
		0xBE544C6D7733D9AAULL,
		0xF21F8624293736DEULL,
		0xFBC3C5101CC2666EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 457\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 457 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -457;
	} else {
		printf("Test Case 457 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCD6150D193AB9351ULL,
		0x8539DBED5894CB13ULL,
		0x378EE7F305C95610ULL,
		0xCF5D40D0C3A71EB7ULL,
		0x56BB607E2C6AA18BULL,
		0x90801A674F17E19EULL,
		0x6CD536F806F23DA5ULL,
		0x1C6768051B6DACF5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B229EF095E5051DULL,
		0xF98D75D38BE7491EULL,
		0x1677516F36B1D18DULL,
		0x431C14B6195CC477ULL,
		0xFE96B58C7415BE07ULL,
		0xE87319DD086089BDULL,
		0xF585224C0F803010ULL,
		0xF77E4B8FFF8023A3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x323EB1E0FDC68E34ULL,
		0x8BAC6619CCAD81F5ULL,
		0x21179683CF178482ULL,
		0x8C412C1AAA4A5A40ULL,
		0x5824AAF1B854E384ULL,
		0xA80D008A46B757E0ULL,
		0x775014ABF7720D94ULL,
		0x24E91C751BED8951ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 458\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 458 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -458;
	} else {
		printf("Test Case 458 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x49303E762A5ECDCBULL,
		0xF22EFB4E6590BD30ULL,
		0x8301AAC1B2C7C92CULL,
		0xAB393018FAC38379ULL,
		0x7945D75A787B1701ULL,
		0xCB6F9CA7519E3E89ULL,
		0xCA4CC244FB1CF809ULL,
		0x9F6AA2BBB7301624ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C16AD29D8A8C5EFULL,
		0x7AE5DC8F9E713D73ULL,
		0xE9E1AAB009D6CA80ULL,
		0x7471B67EDAAE89C3ULL,
		0xC44F1A5E8C5D00AFULL,
		0x9E292808DCD65B5AULL,
		0xE6C813E973E12454ULL,
		0x1E45AB18E597AD9BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBD19914C51B607DCULL,
		0x77491EBEC71F7FBCULL,
		0x99200011A8F0FEACULL,
		0x36C7799A2014F9B5ULL,
		0xB4F6BCFBEC1E1652ULL,
		0x2D46749E74C7E32EULL,
		0xE384AE5B873BD3B5ULL,
		0x8124F7A2D1986888ULL
	}};
	sign = 0;
	printf("Test Case 459\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 459 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -459;
	} else {
		printf("Test Case 459 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAAA1E353EDCA2D9FULL,
		0x1536D00C1F4A2ADBULL,
		0x869C9B2ECC25097BULL,
		0x2175E2BC2B558D46ULL,
		0xBCEC0F6169A422CAULL,
		0xD5CE4C57721C92A0ULL,
		0x25D5F62055997EDFULL,
		0x4ABB049444874E70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x707360792A6488F0ULL,
		0x9F99197147B41BA8ULL,
		0x7AF438346A154AA0ULL,
		0xBB8ABAB961762132ULL,
		0x09279BC32E8CE5A5ULL,
		0xD2CD78C47BC81AC9ULL,
		0x5603BC18E30B4D92ULL,
		0x22E096B921271F8FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3A2E82DAC365A4AFULL,
		0x759DB69AD7960F33ULL,
		0x0BA862FA620FBEDAULL,
		0x65EB2802C9DF6C14ULL,
		0xB3C4739E3B173D24ULL,
		0x0300D392F65477D7ULL,
		0xCFD23A07728E314DULL,
		0x27DA6DDB23602EE0ULL
	}};
	sign = 0;
	printf("Test Case 460\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 460 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -460;
	} else {
		printf("Test Case 460 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0D97ACC3939DD01DULL,
		0xEE84B55375A9BA7EULL,
		0xADCD3429A2B0201EULL,
		0xD5E00CDEF135091AULL,
		0xE22AFB8964A877D6ULL,
		0x432C29BB2ED2200AULL,
		0x316C49F0F0F725C8ULL,
		0x1D337A0BB78248CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41E8D5E7D3BF7462ULL,
		0x64C5C0ACEDF56CC3ULL,
		0x270C53430AC4AC72ULL,
		0xF61672507BF03C2EULL,
		0x86E3E530EDED7682ULL,
		0xE13E8A14642EAE12ULL,
		0x0E6F0A36C369461CULL,
		0xAF7D3007DE07BC21ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCBAED6DBBFDE5BBBULL,
		0x89BEF4A687B44DBAULL,
		0x86C0E0E697EB73ACULL,
		0xDFC99A8E7544CCECULL,
		0x5B47165876BB0153ULL,
		0x61ED9FA6CAA371F8ULL,
		0x22FD3FBA2D8DDFABULL,
		0x6DB64A03D97A8CAEULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 461\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 461 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -461;
	} else {
		printf("Test Case 461 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x44A0D719EDF6E910ULL,
		0xBC734F5ACF0A8F35ULL,
		0x57811F389089DA1AULL,
		0x9643D0C579FF9F75ULL,
		0x29D1ED2B84FD089BULL,
		0x9A607523CE5CA1E1ULL,
		0x6371FB8B828A655DULL,
		0xEE06022A5DC457D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39102A7CAC607B80ULL,
		0xCAE233A5C6FD392AULL,
		0x51BB2B3DE6D7DF3CULL,
		0x92E6C9FD7030D807ULL,
		0x7738BC1A2EBC170DULL,
		0xC8888F3677530BBFULL,
		0xF5B987870962C1BCULL,
		0xC3C2EC08DAEA3377ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0B90AC9D41966D90ULL,
		0xF1911BB5080D560BULL,
		0x05C5F3FAA9B1FADDULL,
		0x035D06C809CEC76EULL,
		0xB29931115640F18EULL,
		0xD1D7E5ED57099621ULL,
		0x6DB874047927A3A0ULL,
		0x2A43162182DA2461ULL
	}};
	sign = 0;
	printf("Test Case 462\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 462 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -462;
	} else {
		printf("Test Case 462 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0EA1957E14CABCDFULL,
		0x6176E530DFF30C4DULL,
		0x86B30CA4B3E05F8EULL,
		0x163E7E553F42FA4DULL,
		0x05CBF3E5806FC0E6ULL,
		0xF67868BD43A28AD7ULL,
		0x173082ACAA80AF9DULL,
		0x48A963FA8DC4A537ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9547AD0DCD528A95ULL,
		0x4AA357F29362486AULL,
		0xE1A49539872797D7ULL,
		0xA823A849B7A6975AULL,
		0x0128B3078B343CFAULL,
		0xA8533FA65C762308ULL,
		0x944FD1DA8423FCADULL,
		0x926FB104A6A0F7F5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7959E8704778324AULL,
		0x16D38D3E4C90C3E2ULL,
		0xA50E776B2CB8C7B7ULL,
		0x6E1AD60B879C62F2ULL,
		0x04A340DDF53B83EBULL,
		0x4E252916E72C67CFULL,
		0x82E0B0D2265CB2F0ULL,
		0xB639B2F5E723AD41ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 463\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 463 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -463;
	} else {
		printf("Test Case 463 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9529ECD67C9E63D3ULL,
		0xF207BDCA306DCCF2ULL,
		0xA6AC9564B15AC1C7ULL,
		0x56BCB4E18740E2A9ULL,
		0x857AAAAA1C93BAD4ULL,
		0xE7C64832219E5458ULL,
		0x13CC30CBB46C443BULL,
		0x3BFB2F66C7FEFAA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE3483E73EA24FA5ULL,
		0x7DF0A486D94B746AULL,
		0xA4B7EC364C0E5681ULL,
		0xA867484AAEEE7E7DULL,
		0xAE86066F68CB3F2BULL,
		0xE532894438D089A1ULL,
		0x70CB3382D2F1A7EBULL,
		0x6EC3D58C9451E0A1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC6F568EF3DFC142EULL,
		0x7417194357225887ULL,
		0x01F4A92E654C6B46ULL,
		0xAE556C96D852642CULL,
		0xD6F4A43AB3C87BA8ULL,
		0x0293BEEDE8CDCAB6ULL,
		0xA300FD48E17A9C50ULL,
		0xCD3759DA33AD1A05ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 464\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 464 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -464;
	} else {
		printf("Test Case 464 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x35650DA7C5053997ULL,
		0x416C9A909A3937EBULL,
		0xED653EA037410FD2ULL,
		0x228D7D28DA5B0D3DULL,
		0xEC42A660FB40EAAAULL,
		0xE15FE0D0D8CEBC1BULL,
		0x9C95B6CA7031016EULL,
		0xD511C6653A5DC635ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3623B4F9E00AA4D3ULL,
		0x9D4E38BE73484F6DULL,
		0xB02ABF5A70FB417EULL,
		0x0A4AD587CFDB9D0CULL,
		0xE1317F53D73671E8ULL,
		0xEE873A70FEC06C68ULL,
		0xE0AE3EB26DC28500ULL,
		0xF58D8B4F3590AF4BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFF4158ADE4FA94C4ULL,
		0xA41E61D226F0E87DULL,
		0x3D3A7F45C645CE53ULL,
		0x1842A7A10A7F7031ULL,
		0x0B11270D240A78C2ULL,
		0xF2D8A65FDA0E4FB3ULL,
		0xBBE77818026E7C6DULL,
		0xDF843B1604CD16E9ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 465\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 465 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -465;
	} else {
		printf("Test Case 465 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x049E7047F00C5493ULL,
		0x7808637AC0099D23ULL,
		0x260F5D44CBB88764ULL,
		0x187DE7E7085C7284ULL,
		0x0E49D0F45EBB6F12ULL,
		0xAE7BC82776DE1169ULL,
		0xE4B8C2C3142A23B4ULL,
		0x578904E31400FCF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83622B5DBF669E46ULL,
		0x01B70774AE8261AEULL,
		0xE1EEFCC5F2697086ULL,
		0xBF7E2CBF022672F6ULL,
		0x0833981560786CFAULL,
		0x0BF4B28CCDC2D652ULL,
		0x1B3ADA87F3E1D3BDULL,
		0xAC62B7E91072EC0BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x813C44EA30A5B64DULL,
		0x76515C0611873B74ULL,
		0x4420607ED94F16DEULL,
		0x58FFBB280635FF8DULL,
		0x061638DEFE430217ULL,
		0xA287159AA91B3B17ULL,
		0xC97DE83B20484FF7ULL,
		0xAB264CFA038E10ECULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 466\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 466 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -466;
	} else {
		printf("Test Case 466 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x05BE0260DB472BB9ULL,
		0x2103DD140099335DULL,
		0xD7A8ED175CA0A8BBULL,
		0x92ED462EFD13E9C8ULL,
		0xC051ABBA41425356ULL,
		0x158BE08EC261BD9AULL,
		0x0842BA7BFC25E9AEULL,
		0xB0B14CC7F2FABA0DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5817BD009A0D6C4ULL,
		0x85F58253EBD02BCBULL,
		0x240F8D3DBF692C07ULL,
		0x794A8A17A4015D0AULL,
		0x313CFBC27DEBF9AFULL,
		0xE8C69A88BB94CC90ULL,
		0xEAB81DF1912A21B1ULL,
		0x0FEA00C0C1075493ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x103C8690D1A654F5ULL,
		0x9B0E5AC014C90791ULL,
		0xB3995FD99D377CB3ULL,
		0x19A2BC1759128CBEULL,
		0x8F14AFF7C35659A7ULL,
		0x2CC5460606CCF10AULL,
		0x1D8A9C8A6AFBC7FCULL,
		0xA0C74C0731F36579ULL
	}};
	sign = 0;
	printf("Test Case 467\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 467 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -467;
	} else {
		printf("Test Case 467 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE0E8C6DB7CB69B06ULL,
		0x5F36F9392B2870ACULL,
		0xFEA0AAA7B79BE18FULL,
		0xD41131B7D9750DCCULL,
		0xD024BE376CBC1E56ULL,
		0x5244C245A843B8F8ULL,
		0x2F311C39850DC889ULL,
		0x64D0D0609E964C02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BF10635D5E1B89AULL,
		0x6557488537A9174BULL,
		0x8A8CF8814E8AA3C3ULL,
		0xEE7AC77630318CC4ULL,
		0x7F78934F80D7842BULL,
		0x32DEEC40F5F92E3DULL,
		0xB71B2761B035D3F1ULL,
		0xBFF98AA5C18D6AE5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x84F7C0A5A6D4E26CULL,
		0xF9DFB0B3F37F5961ULL,
		0x7413B22669113DCBULL,
		0xE5966A41A9438108ULL,
		0x50AC2AE7EBE49A2AULL,
		0x1F65D604B24A8ABBULL,
		0x7815F4D7D4D7F498ULL,
		0xA4D745BADD08E11CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 468\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 468 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -468;
	} else {
		printf("Test Case 468 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE5E62DCD205AC5FCULL,
		0x1EDAE6B0BB59BA9AULL,
		0xC52AB33B25E879ADULL,
		0x2589875E4EFB1678ULL,
		0xE5F176823A5134DDULL,
		0xB24523471A069FAAULL,
		0xA6545F3AAE7F7253ULL,
		0x742D29D7A62651A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC9607DDF6E9BD8AULL,
		0x92492B709868D46DULL,
		0x6C40622704F74012ULL,
		0xE7F3A89D9653DC1DULL,
		0xBC0D6232DBE993B7ULL,
		0xC084CDBD36F8C732ULL,
		0x344B0DEF87E83B15ULL,
		0xE4714911322D0658ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE95025EF29710872ULL,
		0x8C91BB4022F0E62CULL,
		0x58EA511420F1399AULL,
		0x3D95DEC0B8A73A5BULL,
		0x29E4144F5E67A125ULL,
		0xF1C05589E30DD878ULL,
		0x7209514B2697373DULL,
		0x8FBBE0C673F94B48ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 469\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 469 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -469;
	} else {
		printf("Test Case 469 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8BBA42F01AF212DDULL,
		0xB9ACC39AAF666B5EULL,
		0xA173B93A06F7373AULL,
		0xA475B89E8A391CA0ULL,
		0x9CB29B80AECEE35CULL,
		0x757D3940889CCFA1ULL,
		0x25BEE8E085342C84ULL,
		0x2DE670244DFDD627ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52798CFDCCF894D3ULL,
		0xD1F5690AB70042E2ULL,
		0xFE840F1C1657C72FULL,
		0x25AB2D36884344AAULL,
		0x255708AED130BE89ULL,
		0x96D4EED685F749F2ULL,
		0x9A816771311339F3ULL,
		0x40DFCB0A28C6C74FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3940B5F24DF97E0AULL,
		0xE7B75A8FF866287CULL,
		0xA2EFAA1DF09F700AULL,
		0x7ECA8B6801F5D7F5ULL,
		0x775B92D1DD9E24D3ULL,
		0xDEA84A6A02A585AFULL,
		0x8B3D816F5420F290ULL,
		0xED06A51A25370ED7ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 470\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 470 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -470;
	} else {
		printf("Test Case 470 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA472079CF7BF6509ULL,
		0xD7A7B211D43DB9CCULL,
		0x3F6D1447E44D5905ULL,
		0xA6D1D8DEE0E44169ULL,
		0x7F2A5D1BB498A262ULL,
		0x9203B9E1EAEE6BDAULL,
		0xD504191BE23D18E7ULL,
		0xF4D50DDBDED49F46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67ABC69CD4C6CCD5ULL,
		0xDFA42FA1CF33FC92ULL,
		0x1F9C8C43BD82861EULL,
		0x0958E1E97BC28983ULL,
		0x30EB873582B84792ULL,
		0xCD1D7CFEEE0BF3FEULL,
		0x8273FE2CB1FB582FULL,
		0xA2579288AC727831ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3CC6410022F89834ULL,
		0xF80382700509BD3AULL,
		0x1FD0880426CAD2E6ULL,
		0x9D78F6F56521B7E6ULL,
		0x4E3ED5E631E05AD0ULL,
		0xC4E63CE2FCE277DCULL,
		0x52901AEF3041C0B7ULL,
		0x527D7B5332622715ULL
	}};
	sign = 0;
	printf("Test Case 471\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 471 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -471;
	} else {
		printf("Test Case 471 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9C28ABB045B503B7ULL,
		0xB951A2076EC885E0ULL,
		0x9C9B0B94D0DCD4D0ULL,
		0x3BDE7C12A36EF97EULL,
		0x518290C1ADAE557EULL,
		0xE8A8E85DE1F2A306ULL,
		0x97F59FFCF9349423ULL,
		0xEEA45E11E163D9B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7BBA3F1DC800866FULL,
		0xBA92F018295653D7ULL,
		0xD120394B07507BBFULL,
		0xCCC4379DD6B1009EULL,
		0xEA615C25A507CA94ULL,
		0xDB24355660B00666ULL,
		0x0F8DC0D031DC0420ULL,
		0xCA9A5B5DAB7E784CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x206E6C927DB47D48ULL,
		0xFEBEB1EF45723209ULL,
		0xCB7AD249C98C5910ULL,
		0x6F1A4474CCBDF8DFULL,
		0x6721349C08A68AE9ULL,
		0x0D84B30781429C9FULL,
		0x8867DF2CC7589003ULL,
		0x240A02B435E5616DULL
	}};
	sign = 0;
	printf("Test Case 472\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 472 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -472;
	} else {
		printf("Test Case 472 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x82B28B88323FFD54ULL,
		0xF673F4B5D30D4742ULL,
		0xB7C41FE8869AF4EDULL,
		0x4CBFFD9C9132FA91ULL,
		0x96990DB6516F98FBULL,
		0xE59C249608F86B86ULL,
		0x092AFD8DE5A880BAULL,
		0x9B5943B36B99E98AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x807EF97AEBE3C08EULL,
		0x8FA8708A2C0BDEC0ULL,
		0xE6DADEBA637F0D6BULL,
		0xAE1917A496900F2AULL,
		0x54FC60C5D9010496ULL,
		0xCE02E2B3D6C8C498ULL,
		0x70C1D3A40B64B78FULL,
		0xACB059D182DF7E95ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0233920D465C3CC6ULL,
		0x66CB842BA7016882ULL,
		0xD0E9412E231BE782ULL,
		0x9EA6E5F7FAA2EB66ULL,
		0x419CACF0786E9464ULL,
		0x179941E2322FA6EEULL,
		0x986929E9DA43C92BULL,
		0xEEA8E9E1E8BA6AF4ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 473\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 473 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -473;
	} else {
		printf("Test Case 473 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7B07DD32535F1B1CULL,
		0x1E3FA96C7EAB368FULL,
		0xB70B349A8B877107ULL,
		0x1D17F4BA887C4367ULL,
		0x58004D18747C09A0ULL,
		0x72BB725AA9500BEAULL,
		0xDC16584759679A23ULL,
		0xD99B7C8EEA8F8E70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x036C600A11BF7FECULL,
		0xA95B3129B90C25F5ULL,
		0xBA8F77736B62BC15ULL,
		0xA60FB6D3A5EF3A0AULL,
		0x6BD3A672C2F92068ULL,
		0x3F017FE7466A94BFULL,
		0x39132D538C8641F8ULL,
		0xA25651313235FD1CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x779B7D28419F9B30ULL,
		0x74E47842C59F109AULL,
		0xFC7BBD272024B4F1ULL,
		0x77083DE6E28D095CULL,
		0xEC2CA6A5B182E937ULL,
		0x33B9F27362E5772AULL,
		0xA3032AF3CCE1582BULL,
		0x37452B5DB8599154ULL
	}};
	sign = 0;
	printf("Test Case 474\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 474 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -474;
	} else {
		printf("Test Case 474 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD2A7F6ED55E60B64ULL,
		0xE7B115492B5CBFE3ULL,
		0xBF2E8FCFAE45CEF7ULL,
		0x844E3D74B42BB24DULL,
		0x2A0F1AD12DE65001ULL,
		0xCB30C5D3D548297EULL,
		0x5638AE5B4035B3AAULL,
		0x555A203A0268CA5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9CCF1E0647F82A20ULL,
		0x22357661F2B55388ULL,
		0x57CDBC9267F182CEULL,
		0xA23D68584E80A0BBULL,
		0xEAB7B33933C5A88DULL,
		0x9CF7A3E1FE4810CCULL,
		0xA64B946F98CAB827ULL,
		0x64B4343F9D26C64CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x35D8D8E70DEDE144ULL,
		0xC57B9EE738A76C5BULL,
		0x6760D33D46544C29ULL,
		0xE210D51C65AB1192ULL,
		0x3F576797FA20A773ULL,
		0x2E3921F1D70018B1ULL,
		0xAFED19EBA76AFB83ULL,
		0xF0A5EBFA65420410ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 475\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 475 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -475;
	} else {
		printf("Test Case 475 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE229A2F76C8902EDULL,
		0x154C2FA66B073079ULL,
		0x3701A2F55389E980ULL,
		0xA8633DF41048749DULL,
		0xE493229CB407C3B6ULL,
		0x9DEF46F2295ACCB0ULL,
		0x208F52B6999E6353ULL,
		0x36CEEE33B12D0D83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40504BB50CA75A5BULL,
		0x1E9DE885AF983404ULL,
		0xF951DF7B1839707CULL,
		0x4CF2E5E2241446CAULL,
		0x2DDD9BA152A20A97ULL,
		0x47113764DC80F54CULL,
		0x1D5EC3C8E58F87B5ULL,
		0x335D758EF5E85E46ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA1D957425FE1A892ULL,
		0xF6AE4720BB6EFC75ULL,
		0x3DAFC37A3B507903ULL,
		0x5B705811EC342DD2ULL,
		0xB6B586FB6165B91FULL,
		0x56DE0F8D4CD9D764ULL,
		0x03308EEDB40EDB9EULL,
		0x037178A4BB44AF3DULL
	}};
	sign = 0;
	printf("Test Case 476\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 476 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -476;
	} else {
		printf("Test Case 476 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7296552971D94A2CULL,
		0x53A81444D8B4BCEAULL,
		0xAFF359B971089609ULL,
		0x70308AD8F676BFF3ULL,
		0x63C690CDDE9A51EFULL,
		0x82F66D77A15AD865ULL,
		0x333EBED5297346C9ULL,
		0x312D969F7066659FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD5F185DC0A9F568ULL,
		0xDAD3B721DABF6D2AULL,
		0x6F832324EF9707C7ULL,
		0xCDE4A0CB9B1AA3F2ULL,
		0x01B37E72C9E21964ULL,
		0xF44058D02AB80011ULL,
		0xD52A8152361ECBDAULL,
		0x127F6D5373782533ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC5373CCBB12F54C4ULL,
		0x78D45D22FDF54FBFULL,
		0x4070369481718E41ULL,
		0xA24BEA0D5B5C1C01ULL,
		0x6213125B14B8388AULL,
		0x8EB614A776A2D854ULL,
		0x5E143D82F3547AEEULL,
		0x1EAE294BFCEE406BULL
	}};
	sign = 0;
	printf("Test Case 477\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 477 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -477;
	} else {
		printf("Test Case 477 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9FC606BC6321DC4CULL,
		0xBDCDB1C51A3F146AULL,
		0x2334385734A5B550ULL,
		0xF327CDDE03A26C21ULL,
		0x07DF7435039C762FULL,
		0xFBF301098CD7C6B6ULL,
		0x9A74491D24F3AD3BULL,
		0x2538CAC1D4B7522DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA39C557C345D35FULL,
		0x49AF8948E6533BD8ULL,
		0x14D044CEA71913F0ULL,
		0x4FFF8E87D14F94F0ULL,
		0x46F6AA39F8C3E498ULL,
		0xCBE0D26A7B403751ULL,
		0x45A1BCE0F8070DECULL,
		0x7DB6439E3E187ACFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF58C41649FDC08EDULL,
		0x741E287C33EBD891ULL,
		0x0E63F3888D8CA160ULL,
		0xA3283F563252D731ULL,
		0xC0E8C9FB0AD89197ULL,
		0x30122E9F11978F64ULL,
		0x54D28C3C2CEC9F4FULL,
		0xA7828723969ED75EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 478\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 478 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -478;
	} else {
		printf("Test Case 478 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEF29FC50B9446BBEULL,
		0x1DC96C9220CF8BFCULL,
		0x5AA25A07A3C85C2CULL,
		0xBCC6320AB00B2D60ULL,
		0xB459260D73B001F1ULL,
		0x66F207B607B8944AULL,
		0xF77384104827620CULL,
		0xFEE752A8EE803FD3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAACB68DED46CE26EULL,
		0x52C3F42F2108A253ULL,
		0xA527228B5B61BF66ULL,
		0x917F9FECBC321C80ULL,
		0x2FC45010618DC484ULL,
		0x1B6AC9DAC8B84310ULL,
		0x3E7DCA3D223B3190ULL,
		0xFADE4F947BBD9AEDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x445E9371E4D78950ULL,
		0xCB057862FFC6E9A9ULL,
		0xB57B377C48669CC5ULL,
		0x2B46921DF3D910DFULL,
		0x8494D5FD12223D6DULL,
		0x4B873DDB3F00513AULL,
		0xB8F5B9D325EC307CULL,
		0x0409031472C2A4E6ULL
	}};
	sign = 0;
	printf("Test Case 479\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 479 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -479;
	} else {
		printf("Test Case 479 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC0B756DC4CA88222ULL,
		0xE8AB9FEAA0AE0E12ULL,
		0x68FAD9814D7F7E36ULL,
		0xB1385ACFDED55538ULL,
		0xFB82CEE0448D8F7FULL,
		0xD67E57971509A543ULL,
		0x190540D3C706A91DULL,
		0x16BDAFCB5949B1AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D687ABCB13A6DDAULL,
		0x6BC5C85EB04D328FULL,
		0x8B5BCD3629D6083DULL,
		0x130C1B09F2BCCFD5ULL,
		0x9391A37C1FB034E8ULL,
		0xCBD5D19995168C96ULL,
		0x485F6D2302A5CA0FULL,
		0xE4022D5033501284ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x434EDC1F9B6E1448ULL,
		0x7CE5D78BF060DB83ULL,
		0xDD9F0C4B23A975F9ULL,
		0x9E2C3FC5EC188562ULL,
		0x67F12B6424DD5A97ULL,
		0x0AA885FD7FF318ADULL,
		0xD0A5D3B0C460DF0EULL,
		0x32BB827B25F99F25ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 480\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 480 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -480;
	} else {
		printf("Test Case 480 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC648A9EFDBBF0BBCULL,
		0x527F5CF52BCDD180ULL,
		0xC12F3C87ACABE599ULL,
		0x464FB8C9F1143545ULL,
		0x2A48816F25FAD262ULL,
		0x81A9BE3651E35F23ULL,
		0xB4C9A15CFA94A82BULL,
		0x6735C5C170A45E78ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x625A3AB7D4F5C06EULL,
		0x3F5A520079EC2079ULL,
		0xC9846C9BB29AFD1BULL,
		0x7FB891B886DFB522ULL,
		0x653B8BCD8902FDFFULL,
		0xE84155F9A6D406B1ULL,
		0x7AA093D97C0E27EEULL,
		0x8F9A4D738F77D2A6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x63EE6F3806C94B4EULL,
		0x13250AF4B1E1B107ULL,
		0xF7AACFEBFA10E87EULL,
		0xC69727116A348022ULL,
		0xC50CF5A19CF7D462ULL,
		0x9968683CAB0F5871ULL,
		0x3A290D837E86803CULL,
		0xD79B784DE12C8BD2ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 481\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 481 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -481;
	} else {
		printf("Test Case 481 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x116C74C0E897072EULL,
		0x048A397274B20146ULL,
		0x7CB33D9499A40F44ULL,
		0xEB61F96FCA71399BULL,
		0x525238264A384229ULL,
		0x17D6467F75B2CFC8ULL,
		0x29039083B84E2E3CULL,
		0x28D3AC25CAC0429AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x023F1BD073A28C9FULL,
		0xC2CABA1E7EDDF864ULL,
		0x6A1E9F658D831998ULL,
		0xCFCC90B64ECC2432ULL,
		0xADAEF8AFF56ABDF9ULL,
		0x392F50A0BB492C54ULL,
		0x1F5CAF63CF0FA1E7ULL,
		0x5DE985CF20109579ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F2D58F074F47A8FULL,
		0x41BF7F53F5D408E2ULL,
		0x12949E2F0C20F5ABULL,
		0x1B9568B97BA51569ULL,
		0xA4A33F7654CD8430ULL,
		0xDEA6F5DEBA69A373ULL,
		0x09A6E11FE93E8C54ULL,
		0xCAEA2656AAAFAD21ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 482\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 482 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -482;
	} else {
		printf("Test Case 482 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB7EE036EB74F4100ULL,
		0x27F7CEBDFE39E4B1ULL,
		0x908D8A4B8E426E0CULL,
		0xD044EBA8377A0302ULL,
		0xE3E6773C6C334996ULL,
		0xE91AA62ADEB6C618ULL,
		0xE22DA40344B335F9ULL,
		0x237E4E914C8228EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F940F50CA1CE9DCULL,
		0x6D94709FD9AAB0C6ULL,
		0x0514035B78D2DF7BULL,
		0x25E6DDF357AAFBEFULL,
		0xE11C74572EE40725ULL,
		0x248E6B8CF27E7729ULL,
		0x92C1D77086A0722BULL,
		0xD1C05EA93758DFBAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA859F41DED325724ULL,
		0xBA635E1E248F33EBULL,
		0x8B7986F0156F8E90ULL,
		0xAA5E0DB4DFCF0713ULL,
		0x02CA02E53D4F4271ULL,
		0xC48C3A9DEC384EEFULL,
		0x4F6BCC92BE12C3CEULL,
		0x51BDEFE815294935ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 483\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 483 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -483;
	} else {
		printf("Test Case 483 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA04E337ABA24AAA3ULL,
		0x8EA1E2FA9164A934ULL,
		0xB622FC2CACBE31A7ULL,
		0x3CF173BBC05FB550ULL,
		0x72844D0C8D433672ULL,
		0xCB9FE8C5CD09FD92ULL,
		0x61F0929CCE82950DULL,
		0xD186C91FB5288A9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADFC7642E1F13799ULL,
		0xF1D6ADFF5ED1D8C5ULL,
		0xDD70B9CCC95E0AA8ULL,
		0x67DC8621A7E55269ULL,
		0x26D7C195660433FDULL,
		0xA22F00EFED984557ULL,
		0x5D430477B3B8C3C7ULL,
		0xE30A71FE187F2746ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF251BD37D833730AULL,
		0x9CCB34FB3292D06EULL,
		0xD8B2425FE36026FEULL,
		0xD514ED9A187A62E6ULL,
		0x4BAC8B77273F0274ULL,
		0x2970E7D5DF71B83BULL,
		0x04AD8E251AC9D146ULL,
		0xEE7C57219CA96358ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 484\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 484 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -484;
	} else {
		printf("Test Case 484 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8536A9F6A9853E81ULL,
		0x76C62795F37B03A4ULL,
		0x459B3D37297F36BAULL,
		0xB2204AEADA4DA6EFULL,
		0xC1EE015E9A760501ULL,
		0x6ADB3F46BBC80B4DULL,
		0xA7F161E1672C6B05ULL,
		0x54DBA179CF1CDE24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D81CEB06FA314D8ULL,
		0x215604D753B56097ULL,
		0x439EFB6BF4C7694BULL,
		0x04EBAA5237951A3AULL,
		0x59485057C3121444ULL,
		0x97B414D3D9C9C3DFULL,
		0x6888C7D16C265172ULL,
		0xB1EED7D0BAABF3B1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x27B4DB4639E229A9ULL,
		0x557022BE9FC5A30DULL,
		0x01FC41CB34B7CD6FULL,
		0xAD34A098A2B88CB5ULL,
		0x68A5B106D763F0BDULL,
		0xD3272A72E1FE476EULL,
		0x3F689A0FFB061992ULL,
		0xA2ECC9A91470EA73ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 485\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 485 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -485;
	} else {
		printf("Test Case 485 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x03158442E1BBD164ULL,
		0x446FF7FAE16E562DULL,
		0x4D8E411A0D138B01ULL,
		0x81D557D98569C643ULL,
		0x0685EF9BDE0D9260ULL,
		0x15FC4BC96E0062C3ULL,
		0xFAF92F98656E4C24ULL,
		0x980680B07F4553E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7507290629EA06B8ULL,
		0xB9ED374E16D3D70FULL,
		0x669FACB9339FEAFCULL,
		0xA5863595FC1FBEDBULL,
		0xEC608E959FCB5D2EULL,
		0x1ACE38C780A4C525ULL,
		0xC996D98B4580FB3DULL,
		0xDD7D985E004267A5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8E0E5B3CB7D1CAACULL,
		0x8A82C0ACCA9A7F1DULL,
		0xE6EE9460D973A004ULL,
		0xDC4F2243894A0767ULL,
		0x1A2561063E423531ULL,
		0xFB2E1301ED5B9D9DULL,
		0x3162560D1FED50E6ULL,
		0xBA88E8527F02EC3EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 486\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 486 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -486;
	} else {
		printf("Test Case 486 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7D08FE1F3E0E9030ULL,
		0x84AEB1C4B8DA124BULL,
		0x2DFE97C35455BC7BULL,
		0x1D80596A48B7CC8FULL,
		0x6CADE095187DFF26ULL,
		0x77F4DD9CF740C204ULL,
		0xCCF9C09FD1147763ULL,
		0x413A370E1CD0FD68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1197E44FA631F3AULL,
		0x7655827579A1FE76ULL,
		0xF4D9FA221FDE9C1FULL,
		0x4F0BBA3F95A9795CULL,
		0x6F0519CFDCB1451AULL,
		0x7A74A9FCA32B696AULL,
		0xCA3132053E245EABULL,
		0x7990BFFA5682C766ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDBEF7FDA43AB70F6ULL,
		0x0E592F4F3F3813D4ULL,
		0x39249DA13477205CULL,
		0xCE749F2AB30E5332ULL,
		0xFDA8C6C53BCCBA0BULL,
		0xFD8033A054155899ULL,
		0x02C88E9A92F018B7ULL,
		0xC7A97713C64E3602ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 487\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 487 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -487;
	} else {
		printf("Test Case 487 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x05394F471418375FULL,
		0x44D5995F6F0DD37BULL,
		0x905ADA48EFE3135DULL,
		0x88BAEE5B4957C902ULL,
		0xF7B0CD8DFB9D7023ULL,
		0x5AEF4F59366A1C32ULL,
		0xB54EEACB1AB1D48BULL,
		0x68EC4789AF2913FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4ABE5E914587BA55ULL,
		0xAAEB270B3C36374BULL,
		0x3068C17B30EC862BULL,
		0x833F895FD12676C8ULL,
		0xEE2E8B4B7D844EADULL,
		0x9909F1523672A4E8ULL,
		0xEC45004110F77160ULL,
		0x6FC93A4E7EFD0A71ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBA7AF0B5CE907D0AULL,
		0x99EA725432D79C2FULL,
		0x5FF218CDBEF68D31ULL,
		0x057B64FB7831523AULL,
		0x098242427E192176ULL,
		0xC1E55E06FFF7774AULL,
		0xC909EA8A09BA632AULL,
		0xF9230D3B302C0989ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 488\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 488 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -488;
	} else {
		printf("Test Case 488 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0326B549D35599D8ULL,
		0xCC2DC757555B51FBULL,
		0x4501B1AE3694F92CULL,
		0x47699B110FCB8B52ULL,
		0x3D99956E94B3CD4CULL,
		0x47AF55FBE22CE0F2ULL,
		0x0E5D95D3FD4D5B96ULL,
		0x69A72836EAEFE077ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB215A865F10B930EULL,
		0xC5A7EED46C8C42C3ULL,
		0x0F15A7C894F87A1BULL,
		0x033F47804D27C4ADULL,
		0x24C129F2B8DCDC83ULL,
		0xF44D3E5DA9273EC3ULL,
		0xCF1C52A491A0C6ABULL,
		0x36E54062F0C4FF7DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x51110CE3E24A06CAULL,
		0x0685D882E8CF0F37ULL,
		0x35EC09E5A19C7F11ULL,
		0x442A5390C2A3C6A5ULL,
		0x18D86B7BDBD6F0C9ULL,
		0x5362179E3905A22FULL,
		0x3F41432F6BAC94EAULL,
		0x32C1E7D3FA2AE0F9ULL
	}};
	sign = 0;
	printf("Test Case 489\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 489 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -489;
	} else {
		printf("Test Case 489 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBA5D19B257859CEDULL,
		0xECA89A24A1CBBCF5ULL,
		0xA7F46D1FD2890F29ULL,
		0xC14EFCA4F4AF7D45ULL,
		0x2C7AB045945D820BULL,
		0x8A57A714CFD32475ULL,
		0x6722D3420492BA49ULL,
		0xB5879C475245DD6AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x064139B747396F4FULL,
		0x8FF098650EA62F52ULL,
		0xCDCEDD77C98A0350ULL,
		0xB3222E6C211B16C0ULL,
		0x0955BCA072352BBBULL,
		0x9FFAA356C55D532DULL,
		0x5D52145BB647B665ULL,
		0x26DF8A8F9A9DE5FFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB41BDFFB104C2D9EULL,
		0x5CB801BF93258DA3ULL,
		0xDA258FA808FF0BD9ULL,
		0x0E2CCE38D3946684ULL,
		0x2324F3A522285650ULL,
		0xEA5D03BE0A75D148ULL,
		0x09D0BEE64E4B03E3ULL,
		0x8EA811B7B7A7F76BULL
	}};
	sign = 0;
	printf("Test Case 490\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 490 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -490;
	} else {
		printf("Test Case 490 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD0A9812062748C2FULL,
		0x7E9D47FB8B878155ULL,
		0x5271AE889F9B105DULL,
		0x52FF70A98BC70AF5ULL,
		0xD77A9CEE663BB924ULL,
		0xD732AE8603DE42A5ULL,
		0xFEB1B1AA5AAC5117ULL,
		0x0ABBCCA7F994C940ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD92ACA37B9B2CE51ULL,
		0xE6598A89A8CFF0EDULL,
		0x42682B30F847D9F5ULL,
		0x410E32F6851745B4ULL,
		0x29FA60D3A739ED4EULL,
		0x676AAA5835721338ULL,
		0xD52636810980E249ULL,
		0x285E538043CEB302ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF77EB6E8A8C1BDDEULL,
		0x9843BD71E2B79067ULL,
		0x10098357A7533667ULL,
		0x11F13DB306AFC541ULL,
		0xAD803C1ABF01CBD6ULL,
		0x6FC8042DCE6C2F6DULL,
		0x298B7B29512B6ECEULL,
		0xE25D7927B5C6163EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 491\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 491 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -491;
	} else {
		printf("Test Case 491 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x40A1A87956724A82ULL,
		0xD0F0F060F8C43553ULL,
		0xB66FC4F80CF4EDC7ULL,
		0x58618E57569504D7ULL,
		0x9AC87C22530153C6ULL,
		0xE458FE28E9DF181AULL,
		0x071CDCB8CBD35BC1ULL,
		0x1CEFD9D897FFBD7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FA2178BF794BC23ULL,
		0x6F91DBF8F3DFD125ULL,
		0x6D2CC056DA77D201ULL,
		0x267566FEF7401F82ULL,
		0xF350A69E3B43A01DULL,
		0xC2D83CDE749431BCULL,
		0x9B3C73D40291BDCBULL,
		0x9E288D4A7E11E548ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x30FF90ED5EDD8E5FULL,
		0x615F146804E4642EULL,
		0x494304A1327D1BC6ULL,
		0x31EC27585F54E555ULL,
		0xA777D58417BDB3A9ULL,
		0x2180C14A754AE65DULL,
		0x6BE068E4C9419DF6ULL,
		0x7EC74C8E19EDD832ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 492\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 492 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -492;
	} else {
		printf("Test Case 492 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7EF18D8FBC8B326AULL,
		0xF1B932BE0C228913ULL,
		0xF6556724E5565A1DULL,
		0x0B71F33BA6B68C94ULL,
		0xFBEA3CBF979431E1ULL,
		0x94455A902AAFAC17ULL,
		0xEDB5E5BFB77D9466ULL,
		0xE32BBA9080914AACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9839B80AAAE86B4ULL,
		0x7B57172DFD448318ULL,
		0xCE6E58D5FA930706ULL,
		0xB353181991BB9964ULL,
		0x05CAFDF1C41E38DCULL,
		0xEA969AC49F7CB151ULL,
		0x262F222E4C2614ECULL,
		0x1F3AC5DBBAA18DA8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD56DF20F11DCABB6ULL,
		0x76621B900EDE05FAULL,
		0x27E70E4EEAC35317ULL,
		0x581EDB2214FAF330ULL,
		0xF61F3ECDD375F904ULL,
		0xA9AEBFCB8B32FAC6ULL,
		0xC786C3916B577F79ULL,
		0xC3F0F4B4C5EFBD04ULL
	}};
	sign = 0;
	printf("Test Case 493\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 493 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -493;
	} else {
		printf("Test Case 493 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEEBB3440A383326FULL,
		0xF4A135F44B9098D3ULL,
		0x17B9CC6B0EE13A0DULL,
		0x3B541A50C790EFEAULL,
		0x5F33E2BCE9538C62ULL,
		0xDC82EB35A4D633A5ULL,
		0x4746528DA46EF3A7ULL,
		0xD0EF881A64E359C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0ECC3B3C38130D87ULL,
		0xF0A763F1535E79CCULL,
		0x8E4F7DEE712F1B4BULL,
		0xE6BBD3FA54366857ULL,
		0xAD067061EE126039ULL,
		0x07EAEBDF696178A3ULL,
		0xB94C1B50CD89EC8FULL,
		0x8130CC481DCF26EDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDFEEF9046B7024E8ULL,
		0x03F9D202F8321F07ULL,
		0x896A4E7C9DB21EC2ULL,
		0x54984656735A8792ULL,
		0xB22D725AFB412C28ULL,
		0xD497FF563B74BB01ULL,
		0x8DFA373CD6E50718ULL,
		0x4FBEBBD2471432D4ULL
	}};
	sign = 0;
	printf("Test Case 494\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 494 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -494;
	} else {
		printf("Test Case 494 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x91D328600256248FULL,
		0x90869761A9A90D82ULL,
		0x1BAE2657607A2FAEULL,
		0x9CBB15FC5CBE2AEEULL,
		0xC234A9F5139E5B73ULL,
		0x9AD8D771085C390CULL,
		0xFFC7EAD2801A53D9ULL,
		0x2A01D0C93C6CD1B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC714B0A8C86D05FDULL,
		0xA1A6F025E06D6D93ULL,
		0x57F4C175BC01D9E4ULL,
		0x58A7B3EB136BFB9DULL,
		0x594A0E20B09F009AULL,
		0xC6DE0FE189E7AE24ULL,
		0xA643B5494249DD11ULL,
		0x16E55594FDEEF9ABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCABE77B739E91E92ULL,
		0xEEDFA73BC93B9FEEULL,
		0xC3B964E1A47855C9ULL,
		0x4413621149522F50ULL,
		0x68EA9BD462FF5AD9ULL,
		0xD3FAC78F7E748AE8ULL,
		0x598435893DD076C7ULL,
		0x131C7B343E7DD80EULL
	}};
	sign = 0;
	printf("Test Case 495\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 495 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -495;
	} else {
		printf("Test Case 495 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1643672FFD576195ULL,
		0x0B150871A662627CULL,
		0x90B5C3EED0E718EEULL,
		0x5912C0127F91A557ULL,
		0xFEBACF38D8BA6B2BULL,
		0x30A30EA3844EC5C1ULL,
		0xCD5A42F8597C3E91ULL,
		0xF46A333B43984953ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA469723CD2BDE72DULL,
		0xC3FDEA56EF9DF526ULL,
		0x37C1D9EE6765155BULL,
		0xD2A2BDA01B3D7251ULL,
		0x9166A764EB51D7C7ULL,
		0x7FD24E4A0139C42DULL,
		0x116098D833BA71A1ULL,
		0x4B84420336CCF697ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x71D9F4F32A997A68ULL,
		0x47171E1AB6C46D55ULL,
		0x58F3EA0069820392ULL,
		0x8670027264543306ULL,
		0x6D5427D3ED689363ULL,
		0xB0D0C05983150194ULL,
		0xBBF9AA2025C1CCEFULL,
		0xA8E5F1380CCB52BCULL
	}};
	sign = 0;
	printf("Test Case 496\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 496 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -496;
	} else {
		printf("Test Case 496 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x83BFDA68DBE45BD6ULL,
		0x5213DE5043960DFDULL,
		0x8AE3B9A55E278DCEULL,
		0x8CF74838E906BE16ULL,
		0x4D0B8EFAC1651B7DULL,
		0x29602E634F4E9DC4ULL,
		0x944C77244D43F607ULL,
		0x4B94BF838A5CB7B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80FB79F79C508C78ULL,
		0x5A55886815A983DEULL,
		0x3552D2C23130DDEFULL,
		0x72F3F3A3B511DEDFULL,
		0xE03F41C13BC12A95ULL,
		0xBCBDEBDAAD7CEB41ULL,
		0x969EB45D86DA1DCAULL,
		0xAFAC20582A3FAE20ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x02C460713F93CF5EULL,
		0xF7BE55E82DEC8A1FULL,
		0x5590E6E32CF6AFDEULL,
		0x1A03549533F4DF37ULL,
		0x6CCC4D3985A3F0E8ULL,
		0x6CA24288A1D1B282ULL,
		0xFDADC2C6C669D83CULL,
		0x9BE89F2B601D0998ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 497\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 497 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -497;
	} else {
		printf("Test Case 497 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCEA2B59F96C7505BULL,
		0xC628E0EAA0F20E55ULL,
		0x907F8A73A3ADC19CULL,
		0xCDE714DFA0CCE2D3ULL,
		0x5F4D6B57210E5BDCULL,
		0x2A996ABAA94B1A8DULL,
		0xD34DE92C49B80D9AULL,
		0x82E0C97A19887AD8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DA5AD2212FED8BDULL,
		0x7B3BF11C8BEAF44AULL,
		0x580214EF481714A6ULL,
		0x6188944875731957ULL,
		0x8A45B0FBD28D3B0DULL,
		0x223C8004E0B5151DULL,
		0xB0F1D9E84E4F0191ULL,
		0x4E93E5770C00B703ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x50FD087D83C8779EULL,
		0x4AECEFCE15071A0BULL,
		0x387D75845B96ACF6ULL,
		0x6C5E80972B59C97CULL,
		0xD507BA5B4E8120CFULL,
		0x085CEAB5C896056FULL,
		0x225C0F43FB690C09ULL,
		0x344CE4030D87C3D5ULL
	}};
	sign = 0;
	printf("Test Case 498\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 498 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -498;
	} else {
		printf("Test Case 498 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1E7CD526B3454266ULL,
		0xA90A194A207D714EULL,
		0x67FBBF13EAC07780ULL,
		0xCCF6FF3D30895967ULL,
		0xCF94578859B78ABEULL,
		0x16444ED1F26E8354ULL,
		0xD369D436B0B6FCECULL,
		0xCCA75298F6FFAAD0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73AB6E7B62FB6AF9ULL,
		0x0A3698F6E4B59067ULL,
		0x3E138719B29DC192ULL,
		0x0D81E89BFB3DC5D3ULL,
		0x0D6304030A55A188ULL,
		0xC55FE6F4FD4DB47DULL,
		0xFF2CBCAEC629F940ULL,
		0x80360DE1333A19DDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAAD166AB5049D76DULL,
		0x9ED380533BC7E0E6ULL,
		0x29E837FA3822B5EEULL,
		0xBF7516A1354B9394ULL,
		0xC23153854F61E936ULL,
		0x50E467DCF520CED7ULL,
		0xD43D1787EA8D03ABULL,
		0x4C7144B7C3C590F2ULL
	}};
	sign = 0;
	printf("Test Case 499\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 499 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -499;
	} else {
		printf("Test Case 499 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDB97B32E91E13A10ULL,
		0xCA7FEBBA010C9F5DULL,
		0xC5089E643041C49AULL,
		0xC48F0AE9C14D41E6ULL,
		0xE46C4942361625B1ULL,
		0x9085FCF6F635B195ULL,
		0x2A01B7147752ED0BULL,
		0x787C4DCFAEC04A19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x838E0E5B2C3171E9ULL,
		0x05BA93A1C3CE0E1CULL,
		0x5F533A5456AF132DULL,
		0xCAD9239A299E83B2ULL,
		0xAD1B9268F54D4EA3ULL,
		0xD5928331033F3B65ULL,
		0x02BD560003CD23C7ULL,
		0xC338B942B4A8B704ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5809A4D365AFC827ULL,
		0xC4C558183D3E9141ULL,
		0x65B5640FD992B16DULL,
		0xF9B5E74F97AEBE34ULL,
		0x3750B6D940C8D70DULL,
		0xBAF379C5F2F67630ULL,
		0x274461147385C943ULL,
		0xB543948CFA179315ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 500\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 500 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -500;
	} else {
		printf("Test Case 500 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}