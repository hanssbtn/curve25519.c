#include "../tests.h"

int32_t curve25519_key_sub_test(void) {
	printf("Key Subtraction Test\n");
	curve25519_key_signed_t r = {};
	curve25519_key_t k1 = {.key64 = {
		0xE554FDAFD63248D9ULL,
		0xF99F4F1E5B45D5FAULL,
		0x7EDC75CB892926BDULL,
		0x3078E78FC6FFE100ULL,
		0xDD0F1FBE6E3C509FULL,
		0x0C621515519C3AF3ULL,
		0x41EDB9F5F8DB8DC6ULL,
		0x4A1F274FAFFEBD86ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x9D65B6D0284552D3ULL,
		0xBDED5E1D3FAB6D80ULL,
		0x3833A192E9B46D5DULL,
		0x7567F97E872CA267ULL,
		0xA249B14CBCB5E9D6ULL,
		0xB46A343A1354C3F9ULL,
		0x3AFE9CB72A194DE8ULL,
		0xDC2E5E7DFE28E42DULL
	}};
	curve25519_key_t k3 = {.key64 = {
		0x47EF46DFADECF606ULL,
		0x3BB1F1011B9A687AULL,
		0x46A8D4389F74B960ULL,
		0xBB10EE113FD33E99ULL,
		0x3AC56E71B18666C8ULL,
		0x57F7E0DB3E4776FAULL,
		0x06EF1D3ECEC23FDDULL,
		0x6DF0C8D1B1D5D959ULL
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
		0xAC90472610FFE43AULL,
		0xED4C24D321E75EA0ULL,
		0x3EB2179D5B908607ULL,
		0xF956A417600EA4ACULL,
		0xA349FA3BCBC295C3ULL,
		0x6B92F09AED8BA8B3ULL,
		0xF1AD1AFD6FD81575ULL,
		0x0D2E721BC12B774AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9990B97B581BC6CCULL,
		0xCA8D140715C6B89DULL,
		0xD9B05286052E4FEFULL,
		0x8C27C51AE14B5D70ULL,
		0x05BF3BAA31302BB2ULL,
		0x5B1ECFD22FC69901ULL,
		0x8EC4E890E8CA5744ULL,
		0x3E1BAC4646D06DA7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x12FF8DAAB8E41D6EULL,
		0x22BF10CC0C20A603ULL,
		0x6501C51756623618ULL,
		0x6D2EDEFC7EC3473BULL,
		0x9D8ABE919A926A11ULL,
		0x107420C8BDC50FB2ULL,
		0x62E8326C870DBE31ULL,
		0xCF12C5D57A5B09A3ULL
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
		0x0E6D5105856A8965ULL,
		0xD841BB05971E7F48ULL,
		0x8880546BC0DB2ED1ULL,
		0x10B5F16385482C68ULL,
		0x30ECC3100BCBD89DULL,
		0x574FC0CA6B38F9DBULL,
		0x554F729D313C012CULL,
		0xDB72156665149F06ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23B5D587B85A519FULL,
		0x6EC099506CAE3ACBULL,
		0x47C4C931EBF88016ULL,
		0x91725841F578D079ULL,
		0x4F78ACD2949458B7ULL,
		0x2C64B81BB5190ED7ULL,
		0xE9EDCA78FE533F67ULL,
		0x8AB4CCDD3889F0D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEAB77B7DCD1037C6ULL,
		0x698121B52A70447CULL,
		0x40BB8B39D4E2AEBBULL,
		0x7F4399218FCF5BEFULL,
		0xE174163D77377FE5ULL,
		0x2AEB08AEB61FEB03ULL,
		0x6B61A82432E8C1C5ULL,
		0x50BD48892C8AAE2FULL
	}};
	sign = 0;
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
		0x44BD66900AD5B810ULL,
		0x4C35E7942326874AULL,
		0x0F8853B602B94BD9ULL,
		0xE601D4A6D1CD3B31ULL,
		0x89B4CD5A7389E0F9ULL,
		0xD76332E02B55AF79ULL,
		0xF2C308CA7DEC3AB1ULL,
		0xE3860035A278E2AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA686F9E981BFDE4ULL,
		0x9092C0C4C95C003EULL,
		0x855B58BB0C69AE5CULL,
		0xCC2D06C99993ABB1ULL,
		0x8321D2A69AE32DCEULL,
		0xA2A3995E1F67A2AAULL,
		0x537477EE2FF3F9AFULL,
		0x8F9DBFC6B3601F41ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7A54F6F172B9BA2CULL,
		0xBBA326CF59CA870BULL,
		0x8A2CFAFAF64F9D7CULL,
		0x19D4CDDD38398F7FULL,
		0x0692FAB3D8A6B32BULL,
		0x34BF99820BEE0CCFULL,
		0x9F4E90DC4DF84102ULL,
		0x53E8406EEF18C36DULL
	}};
	sign = 0;
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
		0xA7FD9ADC3CD91A8BULL,
		0x52F066E3CDAD9834ULL,
		0x2666D18DDF2D060FULL,
		0x0E876744853C182DULL,
		0xC41EBB9C6CD6DD5AULL,
		0x9E923AC9946014EBULL,
		0xD0B6315420949B0BULL,
		0x50EABFCA0CA062BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41EF945FAF484BE5ULL,
		0x91EE7B922D639CE6ULL,
		0x918C71B236DB6808ULL,
		0xB592A4B99BAF4E4CULL,
		0x28AB06995B8EFB1CULL,
		0x32BD8643752D13DDULL,
		0x8118A80593EE15CCULL,
		0xE0F75A4243AC8963ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x660E067C8D90CEA6ULL,
		0xC101EB51A049FB4EULL,
		0x94DA5FDBA8519E06ULL,
		0x58F4C28AE98CC9E0ULL,
		0x9B73B5031147E23DULL,
		0x6BD4B4861F33010EULL,
		0x4F9D894E8CA6853FULL,
		0x6FF36587C8F3D959ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x0A69DF8B4E3EA97AULL,
		0x46EA91EDEC18C1C6ULL,
		0xD199BAD3402ACCDBULL,
		0x8ABA13F927D87B05ULL,
		0x3F803D818271A1BCULL,
		0xE2D5CC915EE02AC8ULL,
		0x636D241C6FF1F819ULL,
		0x6A5EC95E8C4EE347ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61F3C20AC4836220ULL,
		0x922CA8EEA82C9D29ULL,
		0x527DC04057E2A514ULL,
		0x1A93A59D6BAD679CULL,
		0x09582021D78A0662ULL,
		0x73926A132FA22352ULL,
		0x5C0A19345995BD76ULL,
		0x9905C2A65104D317ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA8761D8089BB475AULL,
		0xB4BDE8FF43EC249CULL,
		0x7F1BFA92E84827C6ULL,
		0x70266E5BBC2B1369ULL,
		0x36281D5FAAE79B5AULL,
		0x6F43627E2F3E0776ULL,
		0x07630AE8165C3AA3ULL,
		0xD15906B83B4A1030ULL
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
		0xEA4A41A2257EA662ULL,
		0x51A6E7EE38BF5021ULL,
		0x3463CB59DED7131FULL,
		0x0FDD6CEA3548D17DULL,
		0xC7E3791CB4BA30D7ULL,
		0x895CBBE793F46900ULL,
		0xEF988417955E3818ULL,
		0x8652B45B2B5F3645ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65F5633437DF868EULL,
		0x2F225E29785E6520ULL,
		0x0ED265D6A774F5B5ULL,
		0x0B0D8AE829CD0A07ULL,
		0x8A255006473C3197ULL,
		0xC525ECF420B98FF0ULL,
		0x1CF8FF5F6BE858F9ULL,
		0xA1A24185B5E20859ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8454DE6DED9F1FD4ULL,
		0x228489C4C060EB01ULL,
		0x2591658337621D6AULL,
		0x04CFE2020B7BC776ULL,
		0x3DBE29166D7DFF40ULL,
		0xC436CEF3733AD910ULL,
		0xD29F84B82975DF1EULL,
		0xE4B072D5757D2DECULL
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
		0x2A077287C768DF14ULL,
		0xD7AEAA640CBA6628ULL,
		0x5A42DC13686C5724ULL,
		0x06D09967ABA30C7BULL,
		0xEBC78F056C5C82B2ULL,
		0x2666F03FB3FF04C8ULL,
		0xC716C8741A1E7C8AULL,
		0x8F3C0B19829583B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F322CCC291B54EBULL,
		0x2D82165810627B36ULL,
		0x2DE67ED6DC28D0CFULL,
		0xE95B99F9D0F80FD9ULL,
		0x4AFA50E7CDC39225ULL,
		0x34897F78E40BDD1AULL,
		0x6F1D8A621EBAD378ULL,
		0xD2BFC0338661CFBDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBAD545BB9E4D8A29ULL,
		0xAA2C940BFC57EAF1ULL,
		0x2C5C5D3C8C438655ULL,
		0x1D74FF6DDAAAFCA2ULL,
		0xA0CD3E1D9E98F08CULL,
		0xF1DD70C6CFF327AEULL,
		0x57F93E11FB63A911ULL,
		0xBC7C4AE5FC33B3FAULL
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
		0x7C05A29FC6A366E7ULL,
		0xF311F7D2F329E5BAULL,
		0xCB5AFD1A1A12C767ULL,
		0x712D00EABECFA2E8ULL,
		0xFE7EEEC8C632CD61ULL,
		0x6CABA25C8E80AE9CULL,
		0x2DCAB54FF3079BC9ULL,
		0x1B5176C39DEDC085ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C53034C5B68D94AULL,
		0x0256231A8FD66BF7ULL,
		0x6C8610A84932E0A5ULL,
		0xF8AE7A1724D2895FULL,
		0xFFEBC2B972ECFD55ULL,
		0xA10933705BFA3A75ULL,
		0x4CF0C30C8C7CA44BULL,
		0x41539688136EF0FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6FB29F536B3A8D9DULL,
		0xF0BBD4B8635379C3ULL,
		0x5ED4EC71D0DFE6C2ULL,
		0x787E86D399FD1989ULL,
		0xFE932C0F5345D00BULL,
		0xCBA26EEC32867426ULL,
		0xE0D9F243668AF77DULL,
		0xD9FDE03B8A7ECF86ULL
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
		0xCE5B8BE250C4D689ULL,
		0xA766A2649EFBB1D3ULL,
		0xE0DBAF3401FA75FEULL,
		0xA8CE6C13CEF9828CULL,
		0x6C509CE673FDF190ULL,
		0x43B26F202440A74AULL,
		0xD4CDA31B253D9DA9ULL,
		0xBEEAB666858DEBD9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xABACE798DEF99BFBULL,
		0x9A89A224F3E952C6ULL,
		0xDD07CC7E67AC06FDULL,
		0x9671A330514CF59BULL,
		0x51448DFC506C59CFULL,
		0xEFD484CACCA5C44AULL,
		0x2038D1035ECDEEC3ULL,
		0x3871CB0AE41872A9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x22AEA44971CB3A8EULL,
		0x0CDD003FAB125F0DULL,
		0x03D3E2B59A4E6F01ULL,
		0x125CC8E37DAC8CF1ULL,
		0x1B0C0EEA239197C1ULL,
		0x53DDEA55579AE300ULL,
		0xB494D217C66FAEE5ULL,
		0x8678EB5BA1757930ULL
	}};
	sign = 0;
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
		0x1BDA8ABBDEE43036ULL,
		0x436DB60DE0618651ULL,
		0x81931054E46677A4ULL,
		0x1E71E7D921D39450ULL,
		0xD5FBB1B0F8D4B29CULL,
		0xF56545A91C532553ULL,
		0x4E01551A561436EAULL,
		0x7A96730213AF6798ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6860844166C45BF7ULL,
		0xB1FEA624B4B2F994ULL,
		0x7A04692E700D012EULL,
		0xEED2283929541B1EULL,
		0x0B53207FC9BBF12CULL,
		0x297E1A051D328C37ULL,
		0xB66D7D467295DE10ULL,
		0x6B49828A9DA84CC6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB37A067A781FD43FULL,
		0x916F0FE92BAE8CBCULL,
		0x078EA72674597675ULL,
		0x2F9FBF9FF87F7932ULL,
		0xCAA891312F18C16FULL,
		0xCBE72BA3FF20991CULL,
		0x9793D7D3E37E58DAULL,
		0x0F4CF07776071AD1ULL
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
		0x4CA1B97D3BF5652DULL,
		0x07285A8999EE57C1ULL,
		0xB7F55D46D8A4BA5CULL,
		0xE0F790A6EDED5845ULL,
		0x21D5BDCC31C566A5ULL,
		0x060A3F26BF2FE439ULL,
		0x97F37E76515343EEULL,
		0x30636796C55A0EC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81E9B813F681148EULL,
		0xA069619A3287A21FULL,
		0xD97C36DF9C28F9C8ULL,
		0x76D06B0318E993AEULL,
		0xFB0FBC04298FFF01ULL,
		0xD1FC8B4175E2F212ULL,
		0xE8E6720229A5369AULL,
		0x253287D7A6C4F9FDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCAB801694574509FULL,
		0x66BEF8EF6766B5A1ULL,
		0xDE7926673C7BC093ULL,
		0x6A2725A3D503C496ULL,
		0x26C601C8083567A4ULL,
		0x340DB3E5494CF226ULL,
		0xAF0D0C7427AE0D53ULL,
		0x0B30DFBF1E9514C7ULL
	}};
	sign = 0;
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
		0x0233E8B6C3CE1C18ULL,
		0x4252CC5BC5D0C222ULL,
		0xB446E64B814EBB32ULL,
		0x184E992E4063B6C1ULL,
		0x105AAB458FD81811ULL,
		0x82DD88132B319991ULL,
		0x2D7E794A6C4D5033ULL,
		0x72AC394C2506C307ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x955D2D82325F81A1ULL,
		0x955BA4FD72DB2DFDULL,
		0xADB968D397C07E2DULL,
		0x1F4AB245DD0DFCAFULL,
		0x89EA6B712DB3A9BAULL,
		0x915F8E85039D26D6ULL,
		0x1AC590B53A56B568ULL,
		0xA394ACD828A98EC6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6CD6BB34916E9A77ULL,
		0xACF7275E52F59424ULL,
		0x068D7D77E98E3D04ULL,
		0xF903E6E86355BA12ULL,
		0x86703FD462246E56ULL,
		0xF17DF98E279472BAULL,
		0x12B8E89531F69ACAULL,
		0xCF178C73FC5D3441ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x947BC09B31964C15ULL,
		0xD767732E7D4CC5FAULL,
		0x091992413B122CB1ULL,
		0x98C5FC1A61E09E85ULL,
		0xEC1A309139B4093EULL,
		0xB32DDCCF12D7260FULL,
		0x0DC1D0D2C16798EBULL,
		0x19D4D630877CB2CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF69F39E5E022464BULL,
		0x10AE0B21E26E3C97ULL,
		0x9B75BC6D2529424FULL,
		0x92740868DA258109ULL,
		0x2D620AD3D785EA53ULL,
		0x13B7A6AF597CC1EDULL,
		0x15D482C983045AAFULL,
		0xD5CEA74FCEBDC8C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9DDC86B5517405CAULL,
		0xC6B9680C9ADE8962ULL,
		0x6DA3D5D415E8EA62ULL,
		0x0651F3B187BB1D7BULL,
		0xBEB825BD622E1EEBULL,
		0x9F76361FB95A6422ULL,
		0xF7ED4E093E633E3CULL,
		0x44062EE0B8BEEA0CULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x0BF2A87AA2C028C5ULL,
		0x4CB16515444F37D8ULL,
		0xBE895BBE6BDE3FD6ULL,
		0xFD6544AFFD49209AULL,
		0x8E98E2F2E3F39F0DULL,
		0x485BA545A17E2C88ULL,
		0x69936925E192F173ULL,
		0xB59F0DC03B30C2B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA4D17E0CC1A032BULL,
		0x1791A444A923F8C7ULL,
		0xD7F1256BCEE87752ULL,
		0x2CC1BD6A2ECB1E70ULL,
		0xABA8E224071B0F35ULL,
		0x8975CCC299F226F1ULL,
		0x2AC0F7771F46F6D3ULL,
		0xB3C7AECC6CFB657BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x41A59099D6A6259AULL,
		0x351FC0D09B2B3F10ULL,
		0xE69836529CF5C884ULL,
		0xD0A38745CE7E0229ULL,
		0xE2F000CEDCD88FD8ULL,
		0xBEE5D883078C0596ULL,
		0x3ED271AEC24BFA9FULL,
		0x01D75EF3CE355D38ULL
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
		0x28AE69184BDEF4B0ULL,
		0x12CBC998337839BCULL,
		0x7B9CE2A59B5F52C5ULL,
		0xB4AFFEA164972117ULL,
		0x05CCAD942F58B158ULL,
		0x10D58958DB9CECE5ULL,
		0x85235CB9D54396DFULL,
		0x6AF4C809ACEAFC4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11C55C6FAF11A427ULL,
		0xF7BF4B4ABC71D4F5ULL,
		0x529C9D6885891627ULL,
		0xA487546339C25BCAULL,
		0xA70DAD0630084B8DULL,
		0xD83AA8F9C10C488BULL,
		0xF5DD44EA8CAA2AF4ULL,
		0x35B07392C4A5A3EFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x16E90CA89CCD5089ULL,
		0x1B0C7E4D770664C7ULL,
		0x2900453D15D63C9DULL,
		0x1028AA3E2AD4C54DULL,
		0x5EBF008DFF5065CBULL,
		0x389AE05F1A90A459ULL,
		0x8F4617CF48996BEAULL,
		0x35445476E845585AULL
	}};
	sign = 0;
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
		0x637C8270169243ACULL,
		0xE7ED4B619309B274ULL,
		0xA28348E8E8251611ULL,
		0x730923BF554FC1EBULL,
		0x500DD67575692084ULL,
		0xEAE4ACF77C42A6E0ULL,
		0x45BF07E2CDFCF824ULL,
		0x4334BEF8FDB395D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8303FC8EFF87F342ULL,
		0x2393A1FA06053D92ULL,
		0x8F0A53351CDEB799ULL,
		0xDD87B3011D2B52C1ULL,
		0xC42637CE0B5FA2E2ULL,
		0xEA715A52A6FEFEDCULL,
		0x0E8D19164F4E8FEBULL,
		0xB6EDA4DA5265BD35ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE07885E1170A506AULL,
		0xC459A9678D0474E1ULL,
		0x1378F5B3CB465E78ULL,
		0x958170BE38246F2AULL,
		0x8BE79EA76A097DA1ULL,
		0x007352A4D543A803ULL,
		0x3731EECC7EAE6839ULL,
		0x8C471A1EAB4DD8A0ULL
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
		0x8FCFA1A24B321407ULL,
		0xB7A306484CA7161FULL,
		0x405985EFDD6F7409ULL,
		0xE887DB2038DF301FULL,
		0x68D1CFEC2F560D91ULL,
		0x97F2E7DCAC0F66ECULL,
		0xDA5FACE3A2423BDCULL,
		0x1E8939FB242CC593ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE12DC93B0A59B167ULL,
		0x686593DAC3ACBC16ULL,
		0x0EB42270EDD14049ULL,
		0xA10573830F91C297ULL,
		0x7E3E6FD25915D1EDULL,
		0x37EF226C6CC5D249ULL,
		0xD9C18D1B019DE039ULL,
		0xA292A36AFD20F1D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAEA1D86740D862A0ULL,
		0x4F3D726D88FA5A08ULL,
		0x31A5637EEF9E33C0ULL,
		0x4782679D294D6D88ULL,
		0xEA936019D6403BA4ULL,
		0x6003C5703F4994A2ULL,
		0x009E1FC8A0A45BA3ULL,
		0x7BF69690270BD3BDULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xCFC929062419A8B1ULL,
		0xB0059614088AA95AULL,
		0xFEFC6BFFA6A1EB31ULL,
		0xD49B5BA50F51086AULL,
		0x3C82E73F7FD1C11CULL,
		0xA2F60A861A8043D8ULL,
		0x3A7390FF28C3F4F5ULL,
		0x464613FDAF5C0724ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC724D10C86ABC5EDULL,
		0xA5072D332A731FD9ULL,
		0x5E18FF232850732CULL,
		0xF98B8165B8CCDE01ULL,
		0xDE069960DC8CB5B4ULL,
		0xEE9CF81D7DC9CB2DULL,
		0x7165DF7FE18C2721ULL,
		0x1FB5627E85639B68ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x08A457F99D6DE2C4ULL,
		0x0AFE68E0DE178981ULL,
		0xA0E36CDC7E517805ULL,
		0xDB0FDA3F56842A69ULL,
		0x5E7C4DDEA3450B67ULL,
		0xB45912689CB678AAULL,
		0xC90DB17F4737CDD3ULL,
		0x2690B17F29F86BBBULL
	}};
	sign = 0;
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
		0x1F0AEBCD471CAE77ULL,
		0x7513471475313FBCULL,
		0x723CCE7CB50CDD15ULL,
		0x48BB071625FB04EDULL,
		0x14A81CE5F3221E80ULL,
		0x995B2F90787FA7EFULL,
		0x1896844FB457969AULL,
		0x36DB0D7CB7CA0621ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEACC79A0C7981D0EULL,
		0x68AE08A60070344EULL,
		0x7BE61F64AD2C0BA0ULL,
		0xAE5FC48BB0719C3FULL,
		0xADFCD2D96A06054BULL,
		0xB14A2B7CCAEAAD6BULL,
		0xCCDE627AB8D80733ULL,
		0x8E89D1F7BA7FBBE0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x343E722C7F849169ULL,
		0x0C653E6E74C10B6DULL,
		0xF656AF1807E0D175ULL,
		0x9A5B428A758968ADULL,
		0x66AB4A0C891C1934ULL,
		0xE8110413AD94FA83ULL,
		0x4BB821D4FB7F8F66ULL,
		0xA8513B84FD4A4A40ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x26AC24F2C8E0F9F1ULL,
		0xB6500A7CA4AC996CULL,
		0xB45C0A2136B55A67ULL,
		0xED14E68D223D95ABULL,
		0x70EC6519CCFDCF1EULL,
		0xD5E1C81C717A82E5ULL,
		0xF00FEFE35B5A810CULL,
		0xC2B1495C1572492AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75A4E41C3C443F7BULL,
		0x11AA2A9875DF77BBULL,
		0xF73DBB1DAE500F8EULL,
		0xBC345B51B6E77F12ULL,
		0x126C2EB3AB569418ULL,
		0xE30BE0F189DDB374ULL,
		0x4B7926ECB6564F9CULL,
		0x985E51D5E2B4F647ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB10740D68C9CBA76ULL,
		0xA4A5DFE42ECD21B0ULL,
		0xBD1E4F0388654AD9ULL,
		0x30E08B3B6B561698ULL,
		0x5E80366621A73B06ULL,
		0xF2D5E72AE79CCF71ULL,
		0xA496C8F6A504316FULL,
		0x2A52F78632BD52E3ULL
	}};
	sign = 0;
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
		0x9B5A2F04396BA3A9ULL,
		0x24F4071A972ED8ECULL,
		0xE6A5303A5ED5628FULL,
		0xBCA4B13EEFD94F4FULL,
		0xA53E43FF526A39EDULL,
		0x3049C0D8224D7AAFULL,
		0x75CFD62495473C9CULL,
		0x47477450DF51F42EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FDB364738C8F1BCULL,
		0x6394BE7B541F4323ULL,
		0x1DC19FE2E7DAC229ULL,
		0xFF717A8A6DB211EBULL,
		0x9DEDF33AD472FF97ULL,
		0xF3D74C77A5C211E6ULL,
		0x9897800033E60650ULL,
		0x3FD981708930B18EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8B7EF8BD00A2B1EDULL,
		0xC15F489F430F95C9ULL,
		0xC8E3905776FAA065ULL,
		0xBD3336B482273D64ULL,
		0x075050C47DF73A55ULL,
		0x3C7274607C8B68C9ULL,
		0xDD3856246161364BULL,
		0x076DF2E05621429FULL
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
		0x158BC69EFCF7A186ULL,
		0x46AF47D14AB7E9E0ULL,
		0x9A38D9F62FD9E1ECULL,
		0x3D73210728620935ULL,
		0x423FFD35A40BCBC6ULL,
		0xE202CBFE636A0718ULL,
		0xC2D728CD38527A32ULL,
		0x982A5197BB2E1DD7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB32C29F38B00A92EULL,
		0x910A73DAC4F21D84ULL,
		0x6ED5377D481C7733ULL,
		0xA22BC502C15B2CA9ULL,
		0xC679DFF26A29891EULL,
		0xEC861ECBC425569EULL,
		0x130E1513F737EAFCULL,
		0x6F6587767946A9CCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x625F9CAB71F6F858ULL,
		0xB5A4D3F685C5CC5BULL,
		0x2B63A278E7BD6AB8ULL,
		0x9B475C046706DC8CULL,
		0x7BC61D4339E242A7ULL,
		0xF57CAD329F44B079ULL,
		0xAFC913B9411A8F35ULL,
		0x28C4CA2141E7740BULL
	}};
	sign = 0;
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
		0xF21B8F3471FA0A61ULL,
		0x63CDD9D881EEC1BCULL,
		0xDAD0E6E113627BC1ULL,
		0x1C9BF3058A1C6F35ULL,
		0xEF004101B66AAD65ULL,
		0x227CF8A82E1A44C9ULL,
		0x36413CA5D4FBAA11ULL,
		0x0C2ADA86EB184AD8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E120552A9398D92ULL,
		0x5FBFE7E72F09A918ULL,
		0xDC469A7A1087B165ULL,
		0xE454D34C67611BF4ULL,
		0x8FE0E7038254C4A6ULL,
		0xFB7C9EFDBE5DDC01ULL,
		0xF01C6BE73E7EA2EDULL,
		0x52AF9548DF05ABBEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB40989E1C8C07CCFULL,
		0x040DF1F152E518A4ULL,
		0xFE8A4C6702DACA5CULL,
		0x38471FB922BB5340ULL,
		0x5F1F59FE3415E8BEULL,
		0x270059AA6FBC68C8ULL,
		0x4624D0BE967D0723ULL,
		0xB97B453E0C129F19ULL
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
		0xA7092631414414BFULL,
		0x2BBAD37AC5A0CFBDULL,
		0x771470296835E6F4ULL,
		0x2DE8B65E2D72E41BULL,
		0x523E886CB975E474ULL,
		0xDF7444C2A8C23747ULL,
		0x38C36F1B632FB9F2ULL,
		0xAF45ADEEA344660EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5722943002DAC543ULL,
		0xDB452A41A50962F0ULL,
		0xFEA343A52071E63FULL,
		0xA0560EF1357A3CBFULL,
		0x17EF86306BFBCF1AULL,
		0xA26B92C9A7C9546BULL,
		0xDDC05E6B8BEBDD04ULL,
		0xD14C3D8D80CFE349ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4FE692013E694F7CULL,
		0x5075A93920976CCDULL,
		0x78712C8447C400B4ULL,
		0x8D92A76CF7F8A75BULL,
		0x3A4F023C4D7A1559ULL,
		0x3D08B1F900F8E2DCULL,
		0x5B0310AFD743DCEEULL,
		0xDDF97061227482C4ULL
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
		0x0256DD1AA2C76361ULL,
		0x8E79E35F27B7FD51ULL,
		0xCD1B5B45863D119DULL,
		0x0F436DC06E67C919ULL,
		0x4076237E680562BAULL,
		0x3D6D60FAEBAF72D3ULL,
		0x4977610E2BD73D38ULL,
		0x7B540F87AD25E2C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD84F612E26C0E64BULL,
		0x6330465E454C2B3CULL,
		0x8C2BA4D1D5B506C8ULL,
		0xF03CC2C2B5712EA9ULL,
		0x4C01988C58D5B6ABULL,
		0x91670CE063AC527DULL,
		0x1C0FBCDC265B7186ULL,
		0x3F4A7C2578E313ECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2A077BEC7C067D16ULL,
		0x2B499D00E26BD214ULL,
		0x40EFB673B0880AD5ULL,
		0x1F06AAFDB8F69A70ULL,
		0xF4748AF20F2FAC0EULL,
		0xAC06541A88032055ULL,
		0x2D67A432057BCBB1ULL,
		0x3C0993623442CED5ULL
	}};
	sign = 0;
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
		0x2B1435E7FA0AA589ULL,
		0x5994DFE1E09C2F04ULL,
		0x444D7B90602C0AFCULL,
		0x1296F0DFF1EF8AFEULL,
		0xB66D432E795F7423ULL,
		0x449632ACB7A14E07ULL,
		0x581ED527E369B02CULL,
		0xFB3F16EE15AEB452ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F464B012DD1E1D4ULL,
		0x6A7EA861D650EE10ULL,
		0xCB45910A9237021FULL,
		0x39092B3BA6886386ULL,
		0xC9C6EEC06998BC01ULL,
		0xFA8A3D2EBB3801C8ULL,
		0x60CC12EB1E7E1BE8ULL,
		0xD4716F46E6AB1F6FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDBCDEAE6CC38C3B5ULL,
		0xEF1637800A4B40F3ULL,
		0x7907EA85CDF508DCULL,
		0xD98DC5A44B672777ULL,
		0xECA6546E0FC6B821ULL,
		0x4A0BF57DFC694C3EULL,
		0xF752C23CC4EB9443ULL,
		0x26CDA7A72F0394E2ULL
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
		0x5E95F4CD11CF0EBEULL,
		0xC0E5D95204516494ULL,
		0x6BBBEE9A3231878BULL,
		0x66E1EB9855AB7FDCULL,
		0x4D8C784BDCAD0571ULL,
		0x37F27B7FE0044864ULL,
		0x07FE945F346BF5AAULL,
		0xF955A6A148A4E54AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B4F2354F35A5479ULL,
		0x5F9D1FBC36D90104ULL,
		0x2DD9069ED41D0FDDULL,
		0x734D8AB645816CCBULL,
		0xAF1FA7BB23E79340ULL,
		0x3A7D23D61511256AULL,
		0xF56E222722A98595ULL,
		0x107BB096E6EE7C43ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3346D1781E74BA45ULL,
		0x6148B995CD786390ULL,
		0x3DE2E7FB5E1477AEULL,
		0xF39460E2102A1311ULL,
		0x9E6CD090B8C57230ULL,
		0xFD7557A9CAF322F9ULL,
		0x1290723811C27014ULL,
		0xE8D9F60A61B66906ULL
	}};
	sign = 0;
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
		0xE185D20A68436F47ULL,
		0xD86AFADD8F0BD14EULL,
		0x1EBF827DA624B096ULL,
		0x13EA78B7CE3612B4ULL,
		0x48CE700F82257232ULL,
		0x97EECB6F37F187BBULL,
		0x205B29783FEDD41AULL,
		0xE9216ED99B751C79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B951369C3453ABCULL,
		0x4495B46BB1734143ULL,
		0x71980B12B1C14789ULL,
		0x85D8809788FC7AF8ULL,
		0xADFC6255C7BD9604ULL,
		0x6322F4F9B80B25B2ULL,
		0xA44AD859DF3CF5D3ULL,
		0x713624CFBCAAB30FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x55F0BEA0A4FE348BULL,
		0x93D54671DD98900BULL,
		0xAD27776AF463690DULL,
		0x8E11F820453997BBULL,
		0x9AD20DB9BA67DC2DULL,
		0x34CBD6757FE66208ULL,
		0x7C10511E60B0DE47ULL,
		0x77EB4A09DECA6969ULL
	}};
	sign = 0;
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
		0x7AD33768F72F8197ULL,
		0xD3F135055E5BAF9AULL,
		0x5411EEAD00EF5398ULL,
		0xC5575DECCE8E8F8FULL,
		0x01C755645391EE0AULL,
		0x6B5B58AA0F79CA93ULL,
		0x4B82B47CA200C8FCULL,
		0x4DDEF01F26D08888ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7B330DD6B1EA090ULL,
		0x2C84AAD13CC99E44ULL,
		0x01B8EBC47D698E7AULL,
		0xF77C16FFDE1BA17CULL,
		0xDBA38AF4CFF9ECD1ULL,
		0xDDE519D33428B5B3ULL,
		0x44A96E8D5C8AABCAULL,
		0x33933E3F01A18FD8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9320068B8C10E107ULL,
		0xA76C8A3421921155ULL,
		0x525902E88385C51EULL,
		0xCDDB46ECF072EE13ULL,
		0x2623CA6F83980138ULL,
		0x8D763ED6DB5114DFULL,
		0x06D945EF45761D31ULL,
		0x1A4BB1E0252EF8B0ULL
	}};
	sign = 0;
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
		0xDE0413094597AE90ULL,
		0x2EEFFA7210FB3C35ULL,
		0xAB1CB3656360D97DULL,
		0xC947FC694D9A4F82ULL,
		0x2C7B7FD12A0E960AULL,
		0xCE3D5F6A287F37D8ULL,
		0xC8ED21A210941683ULL,
		0xC1B0BBE2CDFE1B64ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B032283932EF594ULL,
		0x895CFEF1F2F4B850ULL,
		0x493599C1010B6B40ULL,
		0x60D5F852E40A1987ULL,
		0x12389FDBDC37D9B3ULL,
		0x9911052AB8EAF231ULL,
		0xF316945A0C64DFEEULL,
		0x91EA81566531B860ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC300F085B268B8FCULL,
		0xA592FB801E0683E5ULL,
		0x61E719A462556E3CULL,
		0x68720416699035FBULL,
		0x1A42DFF54DD6BC57ULL,
		0x352C5A3F6F9445A7ULL,
		0xD5D68D48042F3695ULL,
		0x2FC63A8C68CC6303ULL
	}};
	sign = 0;
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
		0xDF915144104D72CEULL,
		0xC6126A8BCF2EA3A1ULL,
		0xABC17BEF88870D92ULL,
		0x0F025D0870382648ULL,
		0x3571CD2ED55A8819ULL,
		0x855EBC8E7C71B027ULL,
		0x4F06A2D91D1C4630ULL,
		0x87228E4425B4ECB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF46806CDFBB7B11ULL,
		0x425835DA94BFDCB7ULL,
		0x782347DFE2FF886AULL,
		0x44FEBB2FDC42DC17ULL,
		0xB740759639E78454ULL,
		0x7DC7270517BC0B10ULL,
		0x532EC8B80ADD9D36ULL,
		0xA4235DED2A5CFBF7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x004AD0D73091F7BDULL,
		0x83BA34B13A6EC6EAULL,
		0x339E340FA5878528ULL,
		0xCA03A1D893F54A31ULL,
		0x7E3157989B7303C4ULL,
		0x0797958964B5A516ULL,
		0xFBD7DA21123EA8FAULL,
		0xE2FF3056FB57F0BEULL
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
		0xC87A19015B41EEE1ULL,
		0x9110173AC0B664AFULL,
		0xA4324146F7B70CFCULL,
		0x7CAE1E9B15860FE2ULL,
		0x9E229F19D5BBCC61ULL,
		0x92A15CAD79A544D9ULL,
		0x1875601A20A22400ULL,
		0xEA803155520DC135ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84918DB847440449ULL,
		0x41430698F3854641ULL,
		0xC62E8093E62D523CULL,
		0xD8A4A7AC94A76B27ULL,
		0xF4EE831375560FCCULL,
		0x4A2F9F85F49B3AE9ULL,
		0x6DA1893F3AA90477ULL,
		0x0188779352A46572ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x43E88B4913FDEA98ULL,
		0x4FCD10A1CD311E6EULL,
		0xDE03C0B31189BAC0ULL,
		0xA40976EE80DEA4BAULL,
		0xA9341C066065BC94ULL,
		0x4871BD27850A09EFULL,
		0xAAD3D6DAE5F91F89ULL,
		0xE8F7B9C1FF695BC2ULL
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
		0xE5C2E2EBAC80025EULL,
		0x1B9D592EAE40CA2BULL,
		0x4C096AA81E2F0CB8ULL,
		0x2DA89AC49089E69CULL,
		0x6815ABD90D8BFCADULL,
		0x9311BF4E5AA52372ULL,
		0xA3DCCFEE9C9A674DULL,
		0xAA149F09804B92CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FFEC42A2AAB6800ULL,
		0xA5A6B919B8F44409ULL,
		0xBA59DFBF8F17C41BULL,
		0xF9D54216583CB1C3ULL,
		0xC145B897B034BA7CULL,
		0x2EBEAC836BD090E4ULL,
		0x3AC77A48F110FC5CULL,
		0x897DDA37B9A4B476ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x55C41EC181D49A5EULL,
		0x75F6A014F54C8622ULL,
		0x91AF8AE88F17489CULL,
		0x33D358AE384D34D8ULL,
		0xA6CFF3415D574230ULL,
		0x645312CAEED4928DULL,
		0x691555A5AB896AF1ULL,
		0x2096C4D1C6A6DE56ULL
	}};
	sign = 0;
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
		0xB1EBE23876BEF90EULL,
		0x2F931B5DDF36000EULL,
		0xFBC4A1108F97984FULL,
		0x10CDC1C4F97ECDD0ULL,
		0xE26C86627024BD9AULL,
		0x4269CF883D0C0FECULL,
		0xAD6D0015EFBF7FE4ULL,
		0x126DBEC8FAA4A474ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DCF476852F2090CULL,
		0xCBBE318050CA22D3ULL,
		0x70C35552FC64AD76ULL,
		0x31759F095B9D42B0ULL,
		0x02A2C5CB6F7C5984ULL,
		0x9E18F971BE8BD378ULL,
		0xD54FF78C34A7B6A4ULL,
		0xB4F4EA7A5C0A7E11ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x141C9AD023CCF002ULL,
		0x63D4E9DD8E6BDD3BULL,
		0x8B014BBD9332EAD8ULL,
		0xDF5822BB9DE18B20ULL,
		0xDFC9C09700A86415ULL,
		0xA450D6167E803C74ULL,
		0xD81D0889BB17C93FULL,
		0x5D78D44E9E9A2662ULL
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
		0xCCCCD37F38D3B8C7ULL,
		0xF00176FC20150E9FULL,
		0xE0068CD04D1F3942ULL,
		0xD959CD4E426CE734ULL,
		0xEF9A16BBD638637EULL,
		0xB88F0DF75CA7EC96ULL,
		0x3065ABF4CD17A8F7ULL,
		0xE13CC0AA8F51CFBFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF833373A12AE6152ULL,
		0xC2CE7D9B44B3D870ULL,
		0x8F508897CF44A279ULL,
		0x1395513ADD0670F1ULL,
		0xAFD48683C6EBDA75ULL,
		0x76B27E63945C0B18ULL,
		0xE4CB3ED71F82C4CCULL,
		0x9CB2DEE88E87B5CAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD4999C4526255775ULL,
		0x2D32F960DB61362EULL,
		0x50B604387DDA96C9ULL,
		0xC5C47C1365667643ULL,
		0x3FC590380F4C8909ULL,
		0x41DC8F93C84BE17EULL,
		0x4B9A6D1DAD94E42BULL,
		0x4489E1C200CA19F4ULL
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
		0xB7F60B1105A7DACCULL,
		0xF799F06D308F70E7ULL,
		0x35365F44F9AB320DULL,
		0xDAFD9846F69AE66FULL,
		0x7619B2DBEFE3D2F2ULL,
		0xA5989194E106D51FULL,
		0xF3CF9D21A8392A48ULL,
		0x1A71F54572883767ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA546677655D14680ULL,
		0x12EA9E8D69B504D5ULL,
		0x3F2C09A9940C6FC7ULL,
		0xC9DC643C5FF8F387ULL,
		0x9F709B58C8DC4771ULL,
		0x9BCE743304A29651ULL,
		0xE330C2392E2367AEULL,
		0x433DFCD690BFA1E9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x12AFA39AAFD6944CULL,
		0xE4AF51DFC6DA6C12ULL,
		0xF60A559B659EC246ULL,
		0x1121340A96A1F2E7ULL,
		0xD6A9178327078B81ULL,
		0x09CA1D61DC643ECDULL,
		0x109EDAE87A15C29AULL,
		0xD733F86EE1C8957EULL
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
		0x01E701BE050BDA5DULL,
		0x23E7B29B2FE3AD02ULL,
		0x51C86549AB734BFAULL,
		0x53758BE5540F39ABULL,
		0x12C6E0E9BC116E81ULL,
		0xBABD5789FA5F22A4ULL,
		0x14A87A22CE7E376CULL,
		0xFCD5B08867A7416BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD58AC18C58A16082ULL,
		0x4762258B118D77A7ULL,
		0x2BB4B31693FAEFD4ULL,
		0x987E4F20167CBBF1ULL,
		0xD45E6B2E0993D827ULL,
		0x5FC5176D697AC7E4ULL,
		0xED22EDFA286CB3F6ULL,
		0xE747F38CDE2CD99AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2C5C4031AC6A79DBULL,
		0xDC858D101E56355AULL,
		0x2613B23317785C25ULL,
		0xBAF73CC53D927DBAULL,
		0x3E6875BBB27D9659ULL,
		0x5AF8401C90E45ABFULL,
		0x27858C28A6118376ULL,
		0x158DBCFB897A67D0ULL
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
		0x4A994868D595FCD8ULL,
		0x2A7B0CDF8AA5193CULL,
		0x60A329920719CF3DULL,
		0x338C67DB5724F085ULL,
		0x45B9F4C7ACDFE051ULL,
		0xB7411AF724978FF9ULL,
		0xA566577A502DA923ULL,
		0x028C720CA5F042ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF587A08B5E60F147ULL,
		0x524835C6DEA2F445ULL,
		0xA7A412782B0CC8C7ULL,
		0xDAE687484789F232ULL,
		0xBE7CB129308BDD9BULL,
		0x0807142BD93FBC75ULL,
		0x2DB744BB71E31D8BULL,
		0x3D2BBEBF2D5A83C7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5511A7DD77350B91ULL,
		0xD832D718AC0224F6ULL,
		0xB8FF1719DC0D0675ULL,
		0x58A5E0930F9AFE52ULL,
		0x873D439E7C5402B5ULL,
		0xAF3A06CB4B57D383ULL,
		0x77AF12BEDE4A8B98ULL,
		0xC560B34D7895BEE5ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x44BF3BAFC70CA8F9ULL,
		0x1DB7F7E984DD5DD4ULL,
		0xC0FE946CADB390B4ULL,
		0x3D4E4127EB88BB12ULL,
		0xDB7527F6F61895D6ULL,
		0xC8536B906F5D8539ULL,
		0x5C67FAD694C4C446ULL,
		0x3CC016BC395F6F71ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FB566F12A3D0E64ULL,
		0xC8E9298ED69055A5ULL,
		0xBE2707F25B6D3115ULL,
		0xF0EE5495DCCB3F1EULL,
		0xACD426A6D002F109ULL,
		0xF727103DD36702EEULL,
		0x77FD218B99F6DCECULL,
		0xCE54ECB4C8517FE2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0509D4BE9CCF9A95ULL,
		0x54CECE5AAE4D082FULL,
		0x02D78C7A52465F9EULL,
		0x4C5FEC920EBD7BF4ULL,
		0x2EA101502615A4CCULL,
		0xD12C5B529BF6824BULL,
		0xE46AD94AFACDE759ULL,
		0x6E6B2A07710DEF8EULL
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
		0xC17F10ABE15CABFAULL,
		0x1E73ED265EA34BA0ULL,
		0x1F5492B23D97F65EULL,
		0x0C074614159A7581ULL,
		0xA51743BA983542B3ULL,
		0x1A20E8030DC35207ULL,
		0x64BD7301AB7AD8D2ULL,
		0xA7E1E3AAAADEFA5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF13F99C239104C7DULL,
		0x910265BE50AA5A3CULL,
		0x28BB034FF455CF80ULL,
		0x2B625334FB83C45BULL,
		0xFF98F97D2668E1EBULL,
		0x91346F9A85245E86ULL,
		0xFD3428202DD2C690ULL,
		0x6FA010FE0E3A836BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD03F76E9A84C5F7DULL,
		0x8D7187680DF8F163ULL,
		0xF6998F62494226DDULL,
		0xE0A4F2DF1A16B125ULL,
		0xA57E4A3D71CC60C7ULL,
		0x88EC7868889EF380ULL,
		0x67894AE17DA81241ULL,
		0x3841D2AC9CA476F0ULL
	}};
	sign = 0;
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
		0x003238012B197DEEULL,
		0xB78CE16DD8756DF3ULL,
		0x069BE7AF44C2E2F2ULL,
		0x3174D27204E933E1ULL,
		0x58FF09327C125A85ULL,
		0x6A7DB61872CE4185ULL,
		0xBD53C3D39F09B620ULL,
		0x9602A2162449E58AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x685C0C2C32B26E55ULL,
		0xCD60DF65E9E63797ULL,
		0x776243EF1E729172ULL,
		0x567792D93D467A9AULL,
		0x3945F02EFA1AEDB9ULL,
		0x011BA4C7F3818B8BULL,
		0x4991B23078474B4EULL,
		0x0F7484277DB8BF17ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x97D62BD4F8670F99ULL,
		0xEA2C0207EE8F365BULL,
		0x8F39A3C02650517FULL,
		0xDAFD3F98C7A2B946ULL,
		0x1FB9190381F76CCBULL,
		0x696211507F4CB5FAULL,
		0x73C211A326C26AD2ULL,
		0x868E1DEEA6912673ULL
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
		0x8C5AA510EADDB6F4ULL,
		0x27C8C09B61424592ULL,
		0x8C5FB632040B9263ULL,
		0xB4897EA44B9ECEDFULL,
		0x0B03036443094A25ULL,
		0xE0983C4727754DF9ULL,
		0x361E3DFF67369D31ULL,
		0x2237BDF04E76F7DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42E808BB8B23E535ULL,
		0x490EF93F34BA7D9EULL,
		0x63D39BF199767201ULL,
		0xA12B311428F4408DULL,
		0xB0C83DE5857D7275ULL,
		0xA4F2B1ED4FC613F5ULL,
		0xBE853C218EE17B14ULL,
		0x809C90AC142C6B02ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x49729C555FB9D1BFULL,
		0xDEB9C75C2C87C7F4ULL,
		0x288C1A406A952061ULL,
		0x135E4D9022AA8E52ULL,
		0x5A3AC57EBD8BD7B0ULL,
		0x3BA58A59D7AF3A03ULL,
		0x779901DDD855221DULL,
		0xA19B2D443A4A8CDBULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xF6C89B7D20353F03ULL,
		0xAE4D7B94ABD52B35ULL,
		0xAAA90B3114B0D8FCULL,
		0xF1E56EC7380A57ACULL,
		0x92F9633C950DDCBEULL,
		0x423AF3BD84BC020EULL,
		0x01F31EDD5BA83F0EULL,
		0x86EA1A0BF10F1C80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFD0BF5261BAB7CCULL,
		0x18426291A823D01BULL,
		0x2070C58E7DEF1EAAULL,
		0x31035E993B358368ULL,
		0x4AD950FD726E9901ULL,
		0x6D6807898A23288CULL,
		0x8E77864B28D16EE5ULL,
		0xAB44AC045C11AB1BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x46F7DC2ABE7A8737ULL,
		0x960B190303B15B1AULL,
		0x8A3845A296C1BA52ULL,
		0xC0E2102DFCD4D444ULL,
		0x4820123F229F43BDULL,
		0xD4D2EC33FA98D982ULL,
		0x737B989232D6D028ULL,
		0xDBA56E0794FD7164ULL
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
		0xE55D75C80BA211A8ULL,
		0x60C6C9B6D436A615ULL,
		0x6D61285B643D878EULL,
		0xE00FCAD7B475BD0DULL,
		0x39DDD853CE6806CDULL,
		0x33BC1A5CAB218950ULL,
		0xEA5B4ED1E8FF5B63ULL,
		0x1F24079BC1F3ED7CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4666B8C2650599BULL,
		0x90F3CE1FDF6E9D0FULL,
		0x7136A6C928CD6A1CULL,
		0x1219AA78CF55B48EULL,
		0x8AAAE191FA5FE61DULL,
		0xC046F5BD7EFA8911ULL,
		0x1AE25FC655218618ULL,
		0x4F52810465BC9093ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x20F70A3BE551B80DULL,
		0xCFD2FB96F4C80906ULL,
		0xFC2A81923B701D71ULL,
		0xCDF6205EE520087EULL,
		0xAF32F6C1D40820B0ULL,
		0x7375249F2C27003EULL,
		0xCF78EF0B93DDD54AULL,
		0xCFD186975C375CE9ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xD5462AFE6580090CULL,
		0x066E18B493B1E578ULL,
		0x86A713CF7140D1B3ULL,
		0xA526127DADE99654ULL,
		0x2695EC22B2B8B9D2ULL,
		0xF46C4E75B299DF82ULL,
		0x09CEA20CC6E68976ULL,
		0x49D28219A686AFF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC79EED62639F5F5ULL,
		0xF313CEA08E4554FCULL,
		0xD14BF8F48DDB0B1DULL,
		0x113C6E71C9F77594ULL,
		0x3F28042D26A58822ULL,
		0xB0FFD134040DE176ULL,
		0x81C34BDF27C3BED6ULL,
		0xC29E394D7902B43AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x08CC3C283F461317ULL,
		0x135A4A14056C907CULL,
		0xB55B1ADAE365C695ULL,
		0x93E9A40BE3F220BFULL,
		0xE76DE7F58C1331B0ULL,
		0x436C7D41AE8BFE0BULL,
		0x880B562D9F22CAA0ULL,
		0x873448CC2D83FBB9ULL
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
		0xCFEE62E1A82DA8FCULL,
		0xAF74D067CCC9E638ULL,
		0x78159BBD7DC66595ULL,
		0x67991D845CB0DC1DULL,
		0xE7C03B4AB28BEAE9ULL,
		0x1B67483B4D2DE8B0ULL,
		0x4EA10F6418BAF320ULL,
		0x978050B1EA3DDAA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7578233C11D743CULL,
		0x565EB53FC14770E1ULL,
		0xB7A2D5321ADD8891ULL,
		0x337FA6BC8D3E1CA2ULL,
		0x8757FDC21F64877FULL,
		0xAD26EB518B70A4BAULL,
		0xB8C2CE3F08BB2D6DULL,
		0x3CA0C82EBF052606ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0896E0ADE71034C0ULL,
		0x59161B280B827557ULL,
		0xC072C68B62E8DD04ULL,
		0x341976C7CF72BF7AULL,
		0x60683D889327636AULL,
		0x6E405CE9C1BD43F6ULL,
		0x95DE41250FFFC5B2ULL,
		0x5ADF88832B38B49FULL
	}};
	sign = 0;
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
		0x6ED429D388B1CB5BULL,
		0x9C241D496CC474FDULL,
		0x6E8E64F7813E2B06ULL,
		0x4BE26A5FF8E426F1ULL,
		0x905BCD66BDE3B468ULL,
		0x2B1EC526DCB44195ULL,
		0xC4183E8D262F31CAULL,
		0x7B9E23805B85022EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A45FB75471DB61CULL,
		0x4F7D78A9140FB8F2ULL,
		0xA5BACEEDF923F8E5ULL,
		0x73334BC462E38369ULL,
		0x0397DBF4BCD6CF03ULL,
		0x878C7C22C285EE4EULL,
		0x7A32005824EBD3DFULL,
		0xEDF49FA62590ECBBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD48E2E5E4194153FULL,
		0x4CA6A4A058B4BC0AULL,
		0xC8D39609881A3221ULL,
		0xD8AF1E9B9600A387ULL,
		0x8CC3F172010CE564ULL,
		0xA39249041A2E5347ULL,
		0x49E63E3501435DEAULL,
		0x8DA983DA35F41573ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x06D38757385835F4ULL,
		0x47C78F65698B9253ULL,
		0x0070665110F36A8BULL,
		0x13547C226FFF0A88ULL,
		0xEF5AE0D535378751ULL,
		0x43B931619D4BA325ULL,
		0xEF2001ACEB322DA4ULL,
		0x1DAE88EE8C14B343ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93CF156DDC12EF24ULL,
		0x7BA24849EC49B571ULL,
		0x3B95815494D153D2ULL,
		0x73F14EE5F67D6BBEULL,
		0xAA461FF59604B47CULL,
		0xBA2F908A12D8EA85ULL,
		0x2F536468F98E631BULL,
		0x8B3F1F7B3DDB570AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x730471E95C4546D0ULL,
		0xCC25471B7D41DCE1ULL,
		0xC4DAE4FC7C2216B8ULL,
		0x9F632D3C79819EC9ULL,
		0x4514C0DF9F32D2D4ULL,
		0x8989A0D78A72B8A0ULL,
		0xBFCC9D43F1A3CA88ULL,
		0x926F69734E395C39ULL
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
		0x612EF8401FDE4F7BULL,
		0x5CDECEADD2BD4AE4ULL,
		0x6D0C6435A0CCB360ULL,
		0x7B03DEBFA474BDE4ULL,
		0xF71B64AB57B68E8FULL,
		0x7FDE2364AB9613FFULL,
		0x92B3CB50F8BB1CD0ULL,
		0x49EDC174ECB5B2E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x244E84DCBFB3F899ULL,
		0x721527A3BB4FE643ULL,
		0x99DC41B5E134041DULL,
		0xA364E7C8681B1A66ULL,
		0x9C20A29B1A80FB4BULL,
		0xA2D98E06FC995C03ULL,
		0x4E70F61C0C050A13ULL,
		0xC304A04B7071A08AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3CE07363602A56E2ULL,
		0xEAC9A70A176D64A1ULL,
		0xD330227FBF98AF42ULL,
		0xD79EF6F73C59A37DULL,
		0x5AFAC2103D359343ULL,
		0xDD04955DAEFCB7FCULL,
		0x4442D534ECB612BCULL,
		0x86E921297C441257ULL
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
		0x19C8E60489434678ULL,
		0x61F50F3B68EE382AULL,
		0x8771311E23410AD9ULL,
		0xF36C3BD41D469EA5ULL,
		0xDA0AF4A0CC8A2A53ULL,
		0xCD68B91C1E2C9D02ULL,
		0x5D05ADF68A22E1CCULL,
		0xFB2C6C484DF93E92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC70476ADA8C661BULL,
		0xE78098125328633CULL,
		0xEFE31801DB756F34ULL,
		0x5D26ECB691695FBFULL,
		0x07E4E248882BC668ULL,
		0x793A13E61C224F7DULL,
		0x3EAD238245F64FBAULL,
		0xF76C37FC16622F8DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3D589E99AEB6E05DULL,
		0x7A74772915C5D4EDULL,
		0x978E191C47CB9BA4ULL,
		0x96454F1D8BDD3EE5ULL,
		0xD2261258445E63EBULL,
		0x542EA536020A4D85ULL,
		0x1E588A74442C9212ULL,
		0x03C0344C37970F05ULL
	}};
	sign = 0;
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
		0xFDC01BA331CE6A72ULL,
		0x43CF1BD087F631C7ULL,
		0x6963484A4A247274ULL,
		0xD5E292E6DA17B60AULL,
		0x9E5B78703D9201C4ULL,
		0xAB049016CC6B40F4ULL,
		0xE7A06F898CACA7F6ULL,
		0xF4E65974E5148CC4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CDF05BF082ED34AULL,
		0x8A805B2EB0E16855ULL,
		0xBFD055E8B8328575ULL,
		0x3AFBF3D6A7877A53ULL,
		0xB1A92A69DD360088ULL,
		0x5A130553004233ACULL,
		0x0826C6B48FD9720EULL,
		0x16B7F83132BE44F0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE0E115E4299F9728ULL,
		0xB94EC0A1D714C972ULL,
		0xA992F26191F1ECFEULL,
		0x9AE69F1032903BB6ULL,
		0xECB24E06605C013CULL,
		0x50F18AC3CC290D47ULL,
		0xDF79A8D4FCD335E8ULL,
		0xDE2E6143B25647D4ULL
	}};
	sign = 0;
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
		0xD45C29BB02B5AA9DULL,
		0xC67E0CA1244320A4ULL,
		0xB2AE9EF1DCFD341CULL,
		0x31D019D2DD3527E0ULL,
		0x2C456418E37A5DACULL,
		0x495CC24C5D457E2BULL,
		0x3BB791E462AFD48EULL,
		0x8A7E0626509400F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF66552988BF9AB8CULL,
		0x0FF816DC93B99E6EULL,
		0xFBDB500DC4173898ULL,
		0x915A7753AC012D7AULL,
		0x90C1ADF4AFC39FF1ULL,
		0x4BBF5ED8AEEEECC0ULL,
		0x07F50D6702E21C93ULL,
		0x85E1DAC2A5733AD8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDDF6D72276BBFF11ULL,
		0xB685F5C490898235ULL,
		0xB6D34EE418E5FB84ULL,
		0xA075A27F3133FA65ULL,
		0x9B83B62433B6BDBAULL,
		0xFD9D6373AE56916AULL,
		0x33C2847D5FCDB7FAULL,
		0x049C2B63AB20C61BULL
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
		0xA967B83909369A01ULL,
		0x77F4CC2C1FE95A28ULL,
		0x2C5929B33DEACEB4ULL,
		0x5077CCC8AD4B8350ULL,
		0xFA7EB4A66E73BE8EULL,
		0xDD3F9508586708EDULL,
		0xD088A716D288456DULL,
		0xEE7DB4815CEBBDECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3246A7995DA6FC04ULL,
		0xFB0CCFEDD3E5C5B4ULL,
		0x7BB6B31396B781FBULL,
		0x19839C4F9BF2EC26ULL,
		0x07D9378C839A9B00ULL,
		0x04ECD611713D1D25ULL,
		0x11B20F6D66A20198ULL,
		0x7CEB87E8CCF1CF84ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7721109FAB8F9DFDULL,
		0x7CE7FC3E4C039474ULL,
		0xB0A2769FA7334CB8ULL,
		0x36F4307911589729ULL,
		0xF2A57D19EAD9238EULL,
		0xD852BEF6E729EBC8ULL,
		0xBED697A96BE643D5ULL,
		0x71922C988FF9EE68ULL
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
		0x6F5FC4693AE17A7AULL,
		0x6AF2833C4F3179F4ULL,
		0x60D03D5AFD6FF10CULL,
		0x3EC41115C724426AULL,
		0x656FCB7E2BA0BA84ULL,
		0x66A4CB76772EC29EULL,
		0x4F77352C1CBECFB9ULL,
		0xC21D1A365805CB83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x676C7F90DAD88D52ULL,
		0x2F0118598FB986F7ULL,
		0x75F747D2FFC2AC3CULL,
		0x208C0CBF09EFD081ULL,
		0xDDF8C9F9B2E8A8D7ULL,
		0x2C8B4A4DE4565FBEULL,
		0x3DD0CA27C33BB420ULL,
		0xCB0086998F9ECE5DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x07F344D86008ED28ULL,
		0x3BF16AE2BF77F2FDULL,
		0xEAD8F587FDAD44D0ULL,
		0x1E380456BD3471E8ULL,
		0x8777018478B811ADULL,
		0x3A19812892D862DFULL,
		0x11A66B0459831B99ULL,
		0xF71C939CC866FD26ULL
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
		0x87E1A0C0997324DAULL,
		0xBBEA35CC2D09C10DULL,
		0xD83324AC4A9E646CULL,
		0x815DEAC7A2704927ULL,
		0xC01DC2FEE3F5558BULL,
		0xC94F90D9C9F42AADULL,
		0xEC6799D2CB01E638ULL,
		0x33E56A4A6A6336F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14F81A1AB2623C8AULL,
		0x6D147C96FAA7C260ULL,
		0x410176CEA543C4C3ULL,
		0x8FD2E11751D289E9ULL,
		0xCF9E93A0E4AE1474ULL,
		0x4C51134A74632FF8ULL,
		0xE6204650B675BC90ULL,
		0x2D4382D2B89CE8C3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x72E986A5E710E850ULL,
		0x4ED5B9353261FEADULL,
		0x9731ADDDA55A9FA9ULL,
		0xF18B09B0509DBF3EULL,
		0xF07F2F5DFF474116ULL,
		0x7CFE7D8F5590FAB4ULL,
		0x06475382148C29A8ULL,
		0x06A1E777B1C64E32ULL
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
		0x9E37DCAD41ACA44DULL,
		0xDFFB6B10A92AA26CULL,
		0xFE650FAE37F0F646ULL,
		0x1F6422E0B070EE63ULL,
		0x330E7A8F1330D1B1ULL,
		0xE5E3C8C06F44C2CEULL,
		0xA68F76937B03F2DEULL,
		0x8CD18985076EEF04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E986997413EFBD9ULL,
		0xBE4CD4BC0CF41583ULL,
		0x88FA54FA61E6C1EBULL,
		0x5F0DCA112881B29AULL,
		0x3F75782DAC94FF82ULL,
		0x08C4342A7EF6F0F6ULL,
		0xCDA8DC8ED4F11A62ULL,
		0x13AA4B64BDBC0341ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5F9F7316006DA874ULL,
		0x21AE96549C368CE9ULL,
		0x756ABAB3D60A345BULL,
		0xC05658CF87EF3BC9ULL,
		0xF3990261669BD22EULL,
		0xDD1F9495F04DD1D7ULL,
		0xD8E69A04A612D87CULL,
		0x79273E2049B2EBC2ULL
	}};
	sign = 0;
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
		0x6709B8FF1DEB7444ULL,
		0xA44C602E7069A279ULL,
		0xB0B3488A41C32572ULL,
		0xB862F1F0B89AB576ULL,
		0xA7A267085247D246ULL,
		0x3FB7132A9AB384EDULL,
		0x2914C38450C04482ULL,
		0xBB689149CBFBBD9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A1B02A934222B58ULL,
		0x29C1743C3089EDC1ULL,
		0xC8836670A9427B32ULL,
		0xA5E1CCA2BFCF22D4ULL,
		0xA720710A642F8066ULL,
		0xF1809BDFBED72619ULL,
		0xC76BED0EA30209E9ULL,
		0x070CECE2320D31BCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDCEEB655E9C948ECULL,
		0x7A8AEBF23FDFB4B7ULL,
		0xE82FE2199880AA40ULL,
		0x1281254DF8CB92A1ULL,
		0x0081F5FDEE1851E0ULL,
		0x4E36774ADBDC5ED4ULL,
		0x61A8D675ADBE3A98ULL,
		0xB45BA46799EE8BE2ULL
	}};
	sign = 0;
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
		0x96A2370B79BC8433ULL,
		0x77791BDD14DA9FF2ULL,
		0xFAA97E31E8AB9238ULL,
		0xB7F5E99CF3AFE639ULL,
		0x8FF9BFA50895E7A5ULL,
		0x57101214D5211143ULL,
		0x1F48343422678514ULL,
		0xF4DB6CBFC11C0F2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75080E721B4DE5F2ULL,
		0xEA6142354F237B8EULL,
		0xC5A69CB569547E34ULL,
		0xF88F003B1AB04518ULL,
		0xE5E54975263A93C7ULL,
		0x7239263093E6C11AULL,
		0xCBAB2D0C6A49BBB6ULL,
		0x86A7EAE41CDFAC6FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x219A28995E6E9E41ULL,
		0x8D17D9A7C5B72464ULL,
		0x3502E17C7F571403ULL,
		0xBF66E961D8FFA121ULL,
		0xAA14762FE25B53DDULL,
		0xE4D6EBE4413A5028ULL,
		0x539D0727B81DC95DULL,
		0x6E3381DBA43C62BAULL
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
		0x3F69828CD274D4E7ULL,
		0xCD7A7B096D6BD355ULL,
		0x1AADA2098A9996F7ULL,
		0x7FC3CB5E197DF3FFULL,
		0xEF539DA202AAF0F9ULL,
		0x331710BF7AF4E0E1ULL,
		0xBA9D49EFC7BCDDDCULL,
		0x0A971B5FF0CB3EB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17C86A6958BD245CULL,
		0x2ADC1398231620E8ULL,
		0x9B85BDD200B65C5FULL,
		0x3AF74DB644E9169BULL,
		0xC425E20816301681ULL,
		0x8D503A1A6E8FEA6AULL,
		0x1FCE6574C153D04EULL,
		0xF5F9F94093399950ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x27A1182379B7B08BULL,
		0xA29E67714A55B26DULL,
		0x7F27E43789E33A98ULL,
		0x44CC7DA7D494DD63ULL,
		0x2B2DBB99EC7ADA78ULL,
		0xA5C6D6A50C64F677ULL,
		0x9ACEE47B06690D8DULL,
		0x149D221F5D91A560ULL
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
		0xA266CCDFC1EBAF66ULL,
		0x1496B42A1A1A750AULL,
		0x96695C9C50A87ABAULL,
		0x136F582460714972ULL,
		0x363D1EE316C9409AULL,
		0x3D8660C80C0D7EB4ULL,
		0xC3FB7738526A391CULL,
		0xF81CBC5C33373BC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7325B7219E0289F2ULL,
		0x8907C04D72F0D465ULL,
		0x2862A3B1103CA90AULL,
		0xC80EF4D51C4A65A2ULL,
		0x864288511CC59140ULL,
		0x88D1FCEAE6F67411ULL,
		0x0580070F80ABE1D3ULL,
		0x7A472B9D87A705C1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2F4115BE23E92574ULL,
		0x8B8EF3DCA729A0A5ULL,
		0x6E06B8EB406BD1AFULL,
		0x4B60634F4426E3D0ULL,
		0xAFFA9691FA03AF59ULL,
		0xB4B463DD25170AA2ULL,
		0xBE7B7028D1BE5748ULL,
		0x7DD590BEAB903607ULL
	}};
	sign = 0;
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
		0xED6E6DDDB5C001ACULL,
		0x78091837ACEB3DFFULL,
		0x9DFDF22BE9B63241ULL,
		0x8B103D85C6FFEFD4ULL,
		0x650B1CDDC58A03BAULL,
		0xBF4640D260C9D496ULL,
		0xF0595A76C38A27EDULL,
		0x8D35C8730942EFF2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADD17DDE252CB870ULL,
		0x88FAFD638744C2DDULL,
		0xC1572219D2FAF127ULL,
		0x6FA2E9DE2BB3047FULL,
		0x27DBA55778507820ULL,
		0x237126862247E334ULL,
		0x028524EB827BDA25ULL,
		0xEF37019DE5BA0AB6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3F9CEFFF9093493CULL,
		0xEF0E1AD425A67B22ULL,
		0xDCA6D01216BB4119ULL,
		0x1B6D53A79B4CEB54ULL,
		0x3D2F77864D398B9AULL,
		0x9BD51A4C3E81F162ULL,
		0xEDD4358B410E4DC8ULL,
		0x9DFEC6D52388E53CULL
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
		0xE3F0145773212092ULL,
		0xE3CAD01362A75107ULL,
		0x93C232AE42B13156ULL,
		0x94EF67AC7F2F089BULL,
		0xEE8D8E5394A5BFEBULL,
		0x4A392FE75EAA8512ULL,
		0x18E809AE92F8EACEULL,
		0xF15232AB9149DE5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6B9E923EADD0F92ULL,
		0x55341FB72582E610ULL,
		0xC041898EF8C0F519ULL,
		0xF045A575878BC2EEULL,
		0xC40B00063E15AA4AULL,
		0xFC417FBD6EB4115EULL,
		0x9F0C95828AC505E6ULL,
		0xFB72908066824866ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0D362B3388441100ULL,
		0x8E96B05C3D246AF7ULL,
		0xD380A91F49F03C3DULL,
		0xA4A9C236F7A345ACULL,
		0x2A828E4D569015A0ULL,
		0x4DF7B029EFF673B4ULL,
		0x79DB742C0833E4E7ULL,
		0xF5DFA22B2AC795F6ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x316B13773599116DULL,
		0x2868BFDDC3455E1AULL,
		0xB82CFCF687D60DD5ULL,
		0xAA1BF7714AC6F373ULL,
		0x8E7DB0AB5441B4C2ULL,
		0x6BF3BCE0E2B6073DULL,
		0x0933209C13E0D5DFULL,
		0x505AA1A885D353AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89D9C125815EDCE8ULL,
		0x5DB5E6B235FC5B84ULL,
		0xFD7530A2767882EEULL,
		0xB0879AD83759EFDAULL,
		0x389AD6192DB24AF3ULL,
		0x06E1E5F853B7CEA6ULL,
		0x3DBD4EA44A91EEB7ULL,
		0x849807BF881A00B4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA7915251B43A3485ULL,
		0xCAB2D92B8D490295ULL,
		0xBAB7CC54115D8AE6ULL,
		0xF9945C99136D0398ULL,
		0x55E2DA92268F69CEULL,
		0x6511D6E88EFE3897ULL,
		0xCB75D1F7C94EE728ULL,
		0xCBC299E8FDB952FAULL
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
		0xE80BA30FBB24E927ULL,
		0xC5C4DB986EA65CBFULL,
		0x2DB702634509CC3DULL,
		0x93B908607F17BC07ULL,
		0x3EB103223C95B397ULL,
		0x50F34F436EC0CF8EULL,
		0x177A9E61400C2FDCULL,
		0xAB096B461482648FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AB9D94CA25CA741ULL,
		0xB7D83597F11B33CBULL,
		0x1C1E71F30C81A3BCULL,
		0x59335090EF42C04FULL,
		0xD8BA8B9B3290EBF7ULL,
		0x8497F5EFC3116060ULL,
		0x1CBEADA0F53A0873ULL,
		0xA470CAC8CCD0E5FDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCD51C9C318C841E6ULL,
		0x0DECA6007D8B28F4ULL,
		0x1198907038882881ULL,
		0x3A85B7CF8FD4FBB8ULL,
		0x65F677870A04C7A0ULL,
		0xCC5B5953ABAF6F2DULL,
		0xFABBF0C04AD22768ULL,
		0x0698A07D47B17E91ULL
	}};
	sign = 0;
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
		0xD126CB80A3CABF8BULL,
		0x551CF6A7EA3C379CULL,
		0xF0068838915B2C6FULL,
		0x4BB93AF95E2FFC5EULL,
		0x9C1BE5E766C9D053ULL,
		0xD90A94983CFF8052ULL,
		0x97D19D0BB5EB4D36ULL,
		0xE9346B7B0FA5784CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC976F04E0F4B29FULL,
		0x8B9A10FCA6B0BC31ULL,
		0x145D648947897947ULL,
		0x55667794D1E5D665ULL,
		0xE7EF0E3B773A9DCFULL,
		0x939E85A9914150F0ULL,
		0x8447C9EF1886C94BULL,
		0x6E1CF117B7628CC7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x148F5C7BC2D60CECULL,
		0xC982E5AB438B7B6BULL,
		0xDBA923AF49D1B327ULL,
		0xF652C3648C4A25F9ULL,
		0xB42CD7ABEF8F3283ULL,
		0x456C0EEEABBE2F61ULL,
		0x1389D31C9D6483EBULL,
		0x7B177A635842EB85ULL
	}};
	sign = 0;
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
		0xE9D81D7649D1ADE1ULL,
		0x4B793C37A5189A5FULL,
		0x62C843426476DCA6ULL,
		0x827AFD1C3AA07E47ULL,
		0x383B7454A37E92FFULL,
		0x252D1E79FFEC8F59ULL,
		0xA78AD7D4BADBD907ULL,
		0x328369E81D363934ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x091593682221BA3AULL,
		0xF3B07B7BF818FF95ULL,
		0xAAC1EBB0E88FEA5BULL,
		0xAFE1FE02D2D61809ULL,
		0x5E00D23434163E8EULL,
		0x01B5BF007975B7AFULL,
		0x9D244D27AADC6BFAULL,
		0xD2915393D6444BACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE0C28A0E27AFF3A7ULL,
		0x57C8C0BBACFF9ACAULL,
		0xB80657917BE6F24AULL,
		0xD298FF1967CA663DULL,
		0xDA3AA2206F685470ULL,
		0x23775F798676D7A9ULL,
		0x0A668AAD0FFF6D0DULL,
		0x5FF2165446F1ED88ULL
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
		0x572FFFA450783422ULL,
		0x3AEB7BB0B4180103ULL,
		0x46E5FB9D9A63F1DFULL,
		0xB9A1E82A9A977C2EULL,
		0x72F76E2DA30CD80DULL,
		0x5B2FA7D1C60CC695ULL,
		0x799044FC169B2CA0ULL,
		0x93A3B95677A7E1A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8044FF4CB0C5650FULL,
		0x0F8C170A25FFB427ULL,
		0xB8DA13947214B50BULL,
		0xB39F94A596D2E603ULL,
		0xC812AF4F84B2508DULL,
		0xC0D4F5F0D2BB237FULL,
		0x6B9D0EE84A4E6A29ULL,
		0xC58741C1CA123F91ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD6EB00579FB2CF13ULL,
		0x2B5F64A68E184CDBULL,
		0x8E0BE809284F3CD4ULL,
		0x0602538503C4962AULL,
		0xAAE4BEDE1E5A8780ULL,
		0x9A5AB1E0F351A315ULL,
		0x0DF33613CC4CC276ULL,
		0xCE1C7794AD95A213ULL
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
		0xD2663A09E292C384ULL,
		0xAFC985DD832636D5ULL,
		0x90D5B1A07E3D17D8ULL,
		0x98B93BBCC0F5BB44ULL,
		0x7E6A4F6147C8525DULL,
		0x3E449ABC1AB5E6ACULL,
		0x76BB6034B09A262EULL,
		0xE151FF54C26EAC42ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x755E7F10E0B9DBC2ULL,
		0xB5A37073AE0B1DB8ULL,
		0xA5ED49025597F4BDULL,
		0x2F5C0E36D201E36BULL,
		0xA921A99F4459D6ACULL,
		0xE96F25D99EABCF15ULL,
		0xAD0E75000A0D24DCULL,
		0x1D90BE6CA3EE8EE6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5D07BAF901D8E7C2ULL,
		0xFA261569D51B191DULL,
		0xEAE8689E28A5231AULL,
		0x695D2D85EEF3D7D8ULL,
		0xD548A5C2036E7BB1ULL,
		0x54D574E27C0A1796ULL,
		0xC9ACEB34A68D0151ULL,
		0xC3C140E81E801D5BULL
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
		0x560C335ABB611DB5ULL,
		0x792AFD7140E92B30ULL,
		0xDE22E616587E79D5ULL,
		0xD134E6CB2AC134D0ULL,
		0x07F51B362B9E1AB0ULL,
		0x4E769C1FCF978E2AULL,
		0xD15A886CB5B58A5DULL,
		0x2756A8F8077C813AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CA2C06F6CE6AC5FULL,
		0x2E659FF8447E108AULL,
		0xBB21250B5F7173B0ULL,
		0x7313A7159ADB4E0BULL,
		0xA7085283FDBCEF60ULL,
		0x83B5B580099ACFA1ULL,
		0xD6EC05F7CA510642ULL,
		0x9D30D10E00A76905ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x196972EB4E7A7156ULL,
		0x4AC55D78FC6B1AA6ULL,
		0x2301C10AF90D0625ULL,
		0x5E213FB58FE5E6C5ULL,
		0x60ECC8B22DE12B50ULL,
		0xCAC0E69FC5FCBE88ULL,
		0xFA6E8274EB64841AULL,
		0x8A25D7EA06D51834ULL
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
		0x11E4C68D8DF661CEULL,
		0xE119D0F9C67166F0ULL,
		0x7CCA954BDDA130B0ULL,
		0xD333F25D9BBB665FULL,
		0x5950EEECBC5D153BULL,
		0xEC49A463A2349BAEULL,
		0xCC8FE9B0D8391B6EULL,
		0x0487C346FE896024ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A73B9930F20F2F8ULL,
		0xA479F89FBFF0A25AULL,
		0xC836A571C723AA5BULL,
		0x3F03BFE0D891F1B4ULL,
		0x26852BDA332C000EULL,
		0x33E11A490FD528EEULL,
		0x9E3DE744EDD52573ULL,
		0x49B123D6B813C922ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA7710CFA7ED56ED6ULL,
		0x3C9FD85A0680C495ULL,
		0xB493EFDA167D8655ULL,
		0x9430327CC32974AAULL,
		0x32CBC3128931152DULL,
		0xB8688A1A925F72C0ULL,
		0x2E52026BEA63F5FBULL,
		0xBAD69F7046759702ULL
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
		0x9F6B9E1EB162CCD7ULL,
		0x078BEFF0EFBB4030ULL,
		0xE01E6F01BBF48FFEULL,
		0xDC33A0D17A0B52DFULL,
		0x5483C23C4DAC6CEDULL,
		0xC25558DB025DF032ULL,
		0xEE58FE47FA3F5D1FULL,
		0x37E73E77362FCD3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9183695CC4F0589CULL,
		0xB97248DBF5F92FE5ULL,
		0x4FA89D714102820FULL,
		0x617F03B38B4159E2ULL,
		0xA4BE3A8D59A96213ULL,
		0x17642DD87BF114EDULL,
		0x08B1B82A62DB0AC7ULL,
		0x0BA8AFEEB59B32F9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0DE834C1EC72743BULL,
		0x4E19A714F9C2104BULL,
		0x9075D1907AF20DEEULL,
		0x7AB49D1DEEC9F8FDULL,
		0xAFC587AEF4030ADAULL,
		0xAAF12B02866CDB44ULL,
		0xE5A7461D97645258ULL,
		0x2C3E8E8880949A41ULL
	}};
	sign = 0;
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
		0x581E3D8EF1119442ULL,
		0x48F991806F536F58ULL,
		0x71788EF03E3D5BFBULL,
		0x180AF47B3D30A46EULL,
		0xA7BCDD47EBEAEE68ULL,
		0x09F538007CA9BCE6ULL,
		0x4CF774926608ACE7ULL,
		0x404CF8305B23F006ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1A844EFE0558493ULL,
		0x85C0BAB591459C86ULL,
		0x2FF74AE1D8053B7BULL,
		0x30C327D5FF3EF4FFULL,
		0x89FEA750C44BEC99ULL,
		0x7F07F6E7C69766C2ULL,
		0x4474501F6F8628BBULL,
		0x01FEC3E355C73630ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9675F89F10BC0FAFULL,
		0xC338D6CADE0DD2D1ULL,
		0x4181440E6638207FULL,
		0xE747CCA53DF1AF6FULL,
		0x1DBE35F7279F01CEULL,
		0x8AED4118B6125624ULL,
		0x08832472F682842BULL,
		0x3E4E344D055CB9D6ULL
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
		0xFCB917D7A4CED449ULL,
		0x456F696569EBC1FDULL,
		0x08B83593E5D4350AULL,
		0x9260C5500743CBEEULL,
		0x2A76A2478AFF2BBBULL,
		0x293E653EDCE31CE6ULL,
		0xBD0598F6D1702BC6ULL,
		0xF1CB41222E193114ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x582744255B75BFFDULL,
		0x6EEEAEAB9AFFBA7EULL,
		0x36F2BD3EF4AB3279ULL,
		0xF876AF53D27E8013ULL,
		0x97EE13ADDBDF37A5ULL,
		0x3A8E7CE394E68C6CULL,
		0xB33D0B7C42808F65ULL,
		0x1E3CB7794002E33CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA491D3B24959144CULL,
		0xD680BAB9CEEC077FULL,
		0xD1C57854F1290290ULL,
		0x99EA15FC34C54BDAULL,
		0x92888E99AF1FF415ULL,
		0xEEAFE85B47FC9079ULL,
		0x09C88D7A8EEF9C60ULL,
		0xD38E89A8EE164DD8ULL
	}};
	sign = 0;
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
		0x423B0D36E8D253BFULL,
		0x840839D87435B7B6ULL,
		0x2823F3F0782750F1ULL,
		0x5A2EBABAC007B70CULL,
		0x4CDBA761714288F7ULL,
		0x61D7C6056CB2D150ULL,
		0x2E0DE6C8867B4567ULL,
		0x5AD39F71C50C3B7CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF48177875DB1E3BULL,
		0x517A76C53F99D243ULL,
		0x732408C5867A8ADAULL,
		0xA7B16B59E5BB3986ULL,
		0x00812EB6D8C0EEAEULL,
		0x50A166BC59E85FFDULL,
		0x4B8E7F0D8476A8BAULL,
		0xF9249F333ACDA1A6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x42F2F5BE72F73584ULL,
		0x328DC313349BE572ULL,
		0xB4FFEB2AF1ACC617ULL,
		0xB27D4F60DA4C7D85ULL,
		0x4C5A78AA98819A48ULL,
		0x11365F4912CA7153ULL,
		0xE27F67BB02049CADULL,
		0x61AF003E8A3E99D5ULL
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
		0xCE4405E956E24725ULL,
		0x8BED6BD214791297ULL,
		0x0F401E4245185858ULL,
		0xE9BD51570C6F01CCULL,
		0x3A7424948E7C02A0ULL,
		0x2ACBE0DBDF4B6AA6ULL,
		0xF1655363295C1140ULL,
		0xDB2D6F5077A0F9CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D8F0F60FB8D23A0ULL,
		0xFF90181C6AD09F0AULL,
		0x7B5674101139D3D2ULL,
		0x59B53502C60D1244ULL,
		0x3A530579ACF36163ULL,
		0xDDB0D610E221A9B5ULL,
		0x8CC3A920B067991FULL,
		0x46552781A601EF1AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA0B4F6885B552385ULL,
		0x8C5D53B5A9A8738DULL,
		0x93E9AA3233DE8485ULL,
		0x90081C544661EF87ULL,
		0x00211F1AE188A13DULL,
		0x4D1B0ACAFD29C0F1ULL,
		0x64A1AA4278F47820ULL,
		0x94D847CED19F0AB3ULL
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
		0xE7E9B93856D181E6ULL,
		0x81CBCE1FD7424DC6ULL,
		0x0EFFC868C2D81C0DULL,
		0x4B651E8078E2676AULL,
		0x0ECFEFFFB2BC3AC9ULL,
		0x37A1DF904902FF0BULL,
		0x269D7EB6042A1533ULL,
		0x2C028D662148C197ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52ADA6F63374D870ULL,
		0xCC508B3A6CE02682ULL,
		0x090ACF36508D95FEULL,
		0x97186248B0417ACCULL,
		0x29AD56FF27521D67ULL,
		0xC3B8E438C8BCC314ULL,
		0x6F42BCAE610F82EBULL,
		0x96C4164FF54FB337ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x953C1242235CA976ULL,
		0xB57B42E56A622744ULL,
		0x05F4F932724A860EULL,
		0xB44CBC37C8A0EC9EULL,
		0xE52299008B6A1D61ULL,
		0x73E8FB5780463BF6ULL,
		0xB75AC207A31A9247ULL,
		0x953E77162BF90E5FULL
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
		0x78B3DF31E0AF64F9ULL,
		0xCF18D40D8FC37B94ULL,
		0x13D269822D317790ULL,
		0xC005822F40A57EFBULL,
		0x9DF45F53A030BE94ULL,
		0x78DB8987D6BEED21ULL,
		0x126544E59FF5D166ULL,
		0xD1579452D7EDB45AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43E0E655933EFFCDULL,
		0x4C0CE7F32D6B6AFCULL,
		0xC8E96675D25B3314ULL,
		0x94F6F927B0A327D9ULL,
		0x85CE816F2B2BB212ULL,
		0x47949AA694203789ULL,
		0x4C485EFF4F5851DEULL,
		0x4D5B948002A32BD4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x34D2F8DC4D70652CULL,
		0x830BEC1A62581098ULL,
		0x4AE9030C5AD6447CULL,
		0x2B0E890790025721ULL,
		0x1825DDE475050C82ULL,
		0x3146EEE1429EB598ULL,
		0xC61CE5E6509D7F88ULL,
		0x83FBFFD2D54A8885ULL
	}};
	sign = 0;
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
		0xB0CEBBFFC4B5B47EULL,
		0x42C0FA4F24B28D80ULL,
		0x3851EC594A2F88A1ULL,
		0xA05BF4718ED583E2ULL,
		0x3EBFBC8AE66202D1ULL,
		0xBE3E1CD2F9501956ULL,
		0xF9944F6C0EA522C6ULL,
		0xE9EEE01F78A5E281ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8E6EE06488B44D8ULL,
		0x7D174DC4E60ACEAEULL,
		0x424790DA3B126C60ULL,
		0xA82421E6D3529184ULL,
		0x37041CDD9673B0F5ULL,
		0x201126A44DAD4F73ULL,
		0xC56C9A8BCFE0C3FEULL,
		0xF54E5F926DD9C30AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB7E7CDF97C2A6FA6ULL,
		0xC5A9AC8A3EA7BED1ULL,
		0xF60A5B7F0F1D1C40ULL,
		0xF837D28ABB82F25DULL,
		0x07BB9FAD4FEE51DBULL,
		0x9E2CF62EABA2C9E3ULL,
		0x3427B4E03EC45EC8ULL,
		0xF4A0808D0ACC1F77ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x2F8329293B2BC7C1ULL,
		0x510B5BB4970238DAULL,
		0x57907FB1F7A2B738ULL,
		0xACABC2D1314A4EA9ULL,
		0x2EE7083FDAD5F892ULL,
		0xBA20DBDEA0E98764ULL,
		0x8F6A3B59CD35222FULL,
		0xB45A12FD8AEB2211ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41107B05A6A2F8EDULL,
		0x4527BE87DA6132B5ULL,
		0xF6B3A105E3C7B177ULL,
		0x4CEE219CD1801C1AULL,
		0x2FD8E6941AE89710ULL,
		0x7C1A6087FB25BFF1ULL,
		0x4E0A6B6ED2E263F4ULL,
		0x1FF6AA57F1E275FAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEE72AE239488CED4ULL,
		0x0BE39D2CBCA10624ULL,
		0x60DCDEAC13DB05C1ULL,
		0x5FBDA1345FCA328EULL,
		0xFF0E21ABBFED6182ULL,
		0x3E067B56A5C3C772ULL,
		0x415FCFEAFA52BE3BULL,
		0x946368A59908AC17ULL
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
		0xB2A17FC5CAFCDE49ULL,
		0x82E3EA005DC424EBULL,
		0xBD6AE985060235EDULL,
		0x3482F627163AFE12ULL,
		0xF9046EE02A133999ULL,
		0x6136ADF574D0F35AULL,
		0x55B0A4A699706138ULL,
		0x7738F473940B44BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E5A666F5A53ABE0ULL,
		0xD2B245D3354D0B10ULL,
		0x88F5BC40C37B0811ULL,
		0xFF4DC8A5447CDBEFULL,
		0x498EBCF4F5924AE9ULL,
		0x2154B609B1883F24ULL,
		0x15126709D54D7D7CULL,
		0xC2FD4E6E3BF411EBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6447195670A93269ULL,
		0xB031A42D287719DBULL,
		0x34752D4442872DDBULL,
		0x35352D81D1BE2223ULL,
		0xAF75B1EB3480EEAFULL,
		0x3FE1F7EBC348B436ULL,
		0x409E3D9CC422E3BCULL,
		0xB43BA605581732D1ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x950E33B034BDA949ULL,
		0x8EACB9E54E716CCDULL,
		0x4C9DEF5CC6866176ULL,
		0xB685880A2D246708ULL,
		0x6BB72172F24C1B7BULL,
		0x68A97F101DD028E8ULL,
		0x574C670A09D93484ULL,
		0x453A2A53EC5DB906ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17B4C285119FF7B9ULL,
		0x1F683DA33EACEA5EULL,
		0xAF8229ED51FBF732ULL,
		0x967A733BF0672F40ULL,
		0x21EDB8868BE14545ULL,
		0x9A828506E0BF9C6EULL,
		0x63B858E7D355ADC0ULL,
		0x0E0179F5A4EF4110ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7D59712B231DB190ULL,
		0x6F447C420FC4826FULL,
		0x9D1BC56F748A6A44ULL,
		0x200B14CE3CBD37C7ULL,
		0x49C968EC666AD636ULL,
		0xCE26FA093D108C7AULL,
		0xF3940E22368386C3ULL,
		0x3738B05E476E77F5ULL
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
		0xA325792D1E565034ULL,
		0xB237A68D8AC0BA37ULL,
		0xA80D8D0CFCA46557ULL,
		0xEE53F1AD4BE4CE62ULL,
		0x5DCCD95445CCD563ULL,
		0x3C4BC846BE3B38E9ULL,
		0xFC74EE434E5585B5ULL,
		0xB7CA982001D5A832ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4370535CE5DC65D2ULL,
		0x26EC0AE815CF8282ULL,
		0x3E7B8A41FD8C4F5EULL,
		0x5D4D64A63DD54EFFULL,
		0x4BE04AF7B3D217E2ULL,
		0xC56A7A5689760275ULL,
		0xCBABDB3312E17F74ULL,
		0x2D17CDDC1C48D131ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5FB525D03879EA62ULL,
		0x8B4B9BA574F137B5ULL,
		0x699202CAFF1815F9ULL,
		0x91068D070E0F7F63ULL,
		0x11EC8E5C91FABD81ULL,
		0x76E14DF034C53674ULL,
		0x30C913103B740640ULL,
		0x8AB2CA43E58CD701ULL
	}};
	sign = 0;
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
		0xDE1C13E9E8433569ULL,
		0x10CB83D88CDAB80DULL,
		0x3D48520BF43467F0ULL,
		0xF3FC754BCF041A90ULL,
		0x0ADBA601425D9A9FULL,
		0x8E9AEF09F2B2079CULL,
		0x296C0F803E6913F3ULL,
		0x496EC95CE8C9FF46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21C6A7BF722BC65DULL,
		0x2D974CB759FAFD2CULL,
		0xDC247E9B9F2A85D9ULL,
		0x949156201FF70814ULL,
		0xFACBDAB882294A39ULL,
		0xCAACB97E6B395876ULL,
		0xED04B36D86D77D3EULL,
		0x22E975304A8AD2FFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBC556C2A76176F0CULL,
		0xE334372132DFBAE1ULL,
		0x6123D3705509E216ULL,
		0x5F6B1F2BAF0D127BULL,
		0x100FCB48C0345066ULL,
		0xC3EE358B8778AF25ULL,
		0x3C675C12B79196B4ULL,
		0x2685542C9E3F2C46ULL
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
		0xC1F6ADD64954225AULL,
		0xC3654C0CECADE9ECULL,
		0x40BD7044098E104DULL,
		0xB88280DC96B38140ULL,
		0x9F931D2D3C97A480ULL,
		0x8DAF17647211A106ULL,
		0xD15942B572FFE55FULL,
		0x77ACDC8CDCE6A462ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6ADD243E7FB836FULL,
		0xB3928AF3644E65ADULL,
		0x1C7413588BC8774AULL,
		0x5C2DAC3924874C1AULL,
		0xADF84B304E7CBEE0ULL,
		0x88D8EE81D7385970ULL,
		0x015E330D8C6142BBULL,
		0xC3EFCA6BC053DE4CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFB48DB9261589EEBULL,
		0x0FD2C119885F843EULL,
		0x24495CEB7DC59903ULL,
		0x5C54D4A3722C3526ULL,
		0xF19AD1FCEE1AE5A0ULL,
		0x04D628E29AD94795ULL,
		0xCFFB0FA7E69EA2A4ULL,
		0xB3BD12211C92C616ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xE4F61DCF7F1C0F33ULL,
		0x50D5F93D435A8A8DULL,
		0x3CE2AAD306854322ULL,
		0x8D950C46C2552F05ULL,
		0x1A5D3490EE163228ULL,
		0x2B44DBE44F75CE9DULL,
		0x591C040A97C48A62ULL,
		0x074ABA3705366358ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF822BCD8DEFD4BBULL,
		0xF0F39192C878674EULL,
		0xBE23F913CA336602ULL,
		0x34073AB577779454ULL,
		0x27F4DC7C761BE129ULL,
		0xCD1DC4FF5BFEDA09ULL,
		0x04A87E4EC3A18626ULL,
		0xFE3BEF188CC0EF34ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE573F201F12C3A78ULL,
		0x5FE267AA7AE2233EULL,
		0x7EBEB1BF3C51DD1FULL,
		0x598DD1914ADD9AB0ULL,
		0xF268581477FA50FFULL,
		0x5E2716E4F376F493ULL,
		0x547385BBD423043BULL,
		0x090ECB1E78757424ULL
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
		0x3181F015DF48E89DULL,
		0xD7D008C32AEB0E70ULL,
		0x4949E15F604C4F13ULL,
		0x1349D70779BFC7E4ULL,
		0xD3310B07260AB944ULL,
		0xE5BAA6AFC94A7D5FULL,
		0xFE5B57DF49B9E816ULL,
		0x809BF913D5BACB2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFF400143116D831ULL,
		0xC57A7A78BE603F3FULL,
		0x2E4777706C598C45ULL,
		0x0897170D81877C0EULL,
		0x09FB140FD6643478ULL,
		0x44F980DE4B95BC4FULL,
		0x935D6A89573EF1E1ULL,
		0x6FD7A5A60714DD1BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x518DF001AE32106CULL,
		0x12558E4A6C8ACF30ULL,
		0x1B0269EEF3F2C2CEULL,
		0x0AB2BFF9F8384BD6ULL,
		0xC935F6F74FA684CCULL,
		0xA0C125D17DB4C110ULL,
		0x6AFDED55F27AF635ULL,
		0x10C4536DCEA5EE0FULL
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
		0xD0B3F702D998812DULL,
		0x8AADFB1A4610AE1AULL,
		0x1CEFCDF33BA9FE9FULL,
		0xA8E36EC52551DA04ULL,
		0xC5C31544B391D45EULL,
		0xE845CC98D36E2937ULL,
		0x324E8137B20C02ACULL,
		0x6F1CBC7A34C2FD91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD51D5AF740A257E3ULL,
		0x691216DB0230C2AFULL,
		0xD6965F53DDAA1850ULL,
		0x2F718E4D69908152ULL,
		0x2E99C45F14A37AA1ULL,
		0xD1CA93B2145ED1B7ULL,
		0x1B394FA4DC3543D7ULL,
		0xFE8F2A330F5BCB43ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFB969C0B98F6294AULL,
		0x219BE43F43DFEB6AULL,
		0x46596E9F5DFFE64FULL,
		0x7971E077BBC158B1ULL,
		0x972950E59EEE59BDULL,
		0x167B38E6BF0F5780ULL,
		0x17153192D5D6BED5ULL,
		0x708D92472567324EULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xE13DB0C42C7469B3ULL,
		0x0665F45AA8EA9EA6ULL,
		0x4A21DEEC81F4BAF2ULL,
		0x57E6CA730AB5171AULL,
		0x5631551BA64041C0ULL,
		0x8980762E185F99B4ULL,
		0x10925DF621FA2C00ULL,
		0x2170DE58F2DC9040ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF06B630E2C667EECULL,
		0xB4D54CC73CDCFC3EULL,
		0x3ACE6C7663FF0791ULL,
		0x357E06B14A24B57AULL,
		0x1AF04F8B271A966EULL,
		0x7C17E720AB0C8E6EULL,
		0x549F3D1D11A6E609ULL,
		0xEE5875F933989696ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF0D24DB6000DEAC7ULL,
		0x5190A7936C0DA267ULL,
		0x0F5372761DF5B360ULL,
		0x2268C3C1C09061A0ULL,
		0x3B4105907F25AB52ULL,
		0x0D688F0D6D530B46ULL,
		0xBBF320D9105345F7ULL,
		0x3318685FBF43F9A9ULL
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
		0x1DEAFF92840A7768ULL,
		0x48603BC6400B9807ULL,
		0x591237DDFD486EDEULL,
		0xA884ECD104A7D7C8ULL,
		0x5A6D286A4A83F84FULL,
		0xA49142DFB92782CFULL,
		0x3B6C3163DC2C2543ULL,
		0x67C57701E0AB94DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x756392E06D8B9646ULL,
		0xCEAF4DABB78EB4E7ULL,
		0x5EA63C401D34E8F8ULL,
		0x78A1FA03C9E9D621ULL,
		0x3B28AB58F6423D5AULL,
		0xC05B10F96CC00E74ULL,
		0x5751FBBF51E670B6ULL,
		0xAF456485665F5F21ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA8876CB2167EE122ULL,
		0x79B0EE1A887CE31FULL,
		0xFA6BFB9DE01385E5ULL,
		0x2FE2F2CD3ABE01A6ULL,
		0x1F447D115441BAF5ULL,
		0xE43631E64C67745BULL,
		0xE41A35A48A45B48CULL,
		0xB880127C7A4C35BDULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x5E7C3BA643634946ULL,
		0x408B431BF5A48639ULL,
		0xB809E7B810AA36FAULL,
		0xCD1EABD103E25702ULL,
		0xC92F3F1E14C120DDULL,
		0x66F41D3612BF1F4AULL,
		0x144A84318B9D76F5ULL,
		0xC19688C26FA1F653ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79F313673DDD7207ULL,
		0xD6A9DF3C6DC2E6B7ULL,
		0x38707620A018EDCBULL,
		0xD197C835BA0BF7FEULL,
		0xBF57046743D8F7EAULL,
		0x6C057133F0E8EA99ULL,
		0x73B2B24C0F6C0430ULL,
		0x2512DC563FAE7C79ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE489283F0585D73FULL,
		0x69E163DF87E19F81ULL,
		0x7F9971977091492EULL,
		0xFB86E39B49D65F04ULL,
		0x09D83AB6D0E828F2ULL,
		0xFAEEAC0221D634B1ULL,
		0xA097D1E57C3172C4ULL,
		0x9C83AC6C2FF379D9ULL
	}};
	sign = 0;
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
		0x898DBAFAAFC59D0AULL,
		0xD8BBAB8F5C368D4DULL,
		0x0653224A08F30953ULL,
		0x4AC953A966F644D7ULL,
		0xC6CAE15F1F8DD390ULL,
		0x116E1A8695BD6A9AULL,
		0x20A4AAEDEE37088EULL,
		0x7D8BE648DDC7C1B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0E62424B86BD834ULL,
		0x61F815D5B08D411BULL,
		0xEF238F2E7D489C6DULL,
		0x28F1114DD4AC0309ULL,
		0x13553441BB3DBD97ULL,
		0x21DE53B33557C350ULL,
		0x41FF6B6FCFE57CE9ULL,
		0x0C8F480A1E0B42ADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD8A796D5F759C4D6ULL,
		0x76C395B9ABA94C31ULL,
		0x172F931B8BAA6CE6ULL,
		0x21D8425B924A41CDULL,
		0xB375AD1D645015F9ULL,
		0xEF8FC6D36065A74AULL,
		0xDEA53F7E1E518BA4ULL,
		0x70FC9E3EBFBC7F07ULL
	}};
	sign = 0;
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
		0x4CB634DE69B31234ULL,
		0x40CF0FB36A0CFCB1ULL,
		0xB4E44BB3EF0F2FF6ULL,
		0x507AF8982F1F2A7DULL,
		0x6640013AC8E4BC85ULL,
		0xFD117BC4F6727AE5ULL,
		0x940E19A3A3A8AFA5ULL,
		0xA05DA5B91B3ED334ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4418DF10CFF97CC6ULL,
		0x58CD0F452C2A0170ULL,
		0x0B26BF0682FB620DULL,
		0x79C78F7D08CBAF78ULL,
		0x856E9DF4525977A9ULL,
		0x404252BB561669C9ULL,
		0xD38441DE063B4214ULL,
		0x10312E5296663889ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x089D55CD99B9956EULL,
		0xE802006E3DE2FB41ULL,
		0xA9BD8CAD6C13CDE8ULL,
		0xD6B3691B26537B05ULL,
		0xE0D16346768B44DBULL,
		0xBCCF2909A05C111BULL,
		0xC089D7C59D6D6D91ULL,
		0x902C776684D89AAAULL
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
		0x4D3501697C2AC078ULL,
		0xC8C31E16CC77284AULL,
		0x4B4D6D5F24288DBEULL,
		0x8EF875DE6F9DEABEULL,
		0xFFE412D1ABEC0214ULL,
		0x42DE6B9A5B9EEC12ULL,
		0xD2FE4F2CB5C3CDA2ULL,
		0x8122AE35416E3F28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C79E18E2BF08069ULL,
		0x00A34F209CE1C6E0ULL,
		0x844D463B6963AD4DULL,
		0x6EAE1A2226D338CAULL,
		0x15FEF4679AD7B5BFULL,
		0xF87A448A32C2EAA0ULL,
		0xAA4CACE62D979B71ULL,
		0x56420158841B2544ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00BB1FDB503A400FULL,
		0xC81FCEF62F95616AULL,
		0xC7002723BAC4E071ULL,
		0x204A5BBC48CAB1F3ULL,
		0xE9E51E6A11144C55ULL,
		0x4A64271028DC0172ULL,
		0x28B1A246882C3230ULL,
		0x2AE0ACDCBD5319E4ULL
	}};
	sign = 0;
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
		0x0554AF509A1C8145ULL,
		0x2D06B8A860014697ULL,
		0x57EAC7596B20D2E0ULL,
		0x3D1163B7D94843F9ULL,
		0xFEDE89E443D868F5ULL,
		0xD769C073B201217EULL,
		0x88A0584785EF4A38ULL,
		0xF257EBFDB4B3D798ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2149E63EB9FF71AEULL,
		0x68E6E9B47577A37DULL,
		0xF77DBE1E0954D2E5ULL,
		0xE4C96B57DC45175BULL,
		0x6BA27264A829A0F1ULL,
		0x0CCDC1B8C029ADA6ULL,
		0x4F304977BF7D1B3BULL,
		0xC9A1B8D3E5B5A3E9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE40AC911E01D0F97ULL,
		0xC41FCEF3EA89A319ULL,
		0x606D093B61CBFFFAULL,
		0x5847F85FFD032C9DULL,
		0x933C177F9BAEC803ULL,
		0xCA9BFEBAF1D773D8ULL,
		0x39700ECFC6722EFDULL,
		0x28B63329CEFE33AFULL
	}};
	sign = 0;
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
		0xDF66D013F0B902CCULL,
		0xFD7206754AECBD9EULL,
		0xF8854A9E4C2DBFA2ULL,
		0x27D5D6DC3271C461ULL,
		0xA60F4CA3FDA32FBAULL,
		0xFF0519DB8C03D134ULL,
		0xB284A18683F6A162ULL,
		0xEC611486CD302C41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14AA9056A936837EULL,
		0x076C6EB31BA9CBD1ULL,
		0xA57BB27E4BCBFDCDULL,
		0xF1E831A770EE1AECULL,
		0x1A47A7073E128A67ULL,
		0x9E0C4B3EF592C3B6ULL,
		0x00BB9121C82D71BDULL,
		0x26925D9BE0FF9AA9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCABC3FBD47827F4EULL,
		0xF60597C22F42F1CDULL,
		0x530998200061C1D5ULL,
		0x35EDA534C183A975ULL,
		0x8BC7A59CBF90A552ULL,
		0x60F8CE9C96710D7EULL,
		0xB1C91064BBC92FA5ULL,
		0xC5CEB6EAEC309198ULL
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
		0x11093926C56B2047ULL,
		0x5449D6D6541B0EFEULL,
		0x4506072A5C47010AULL,
		0x9692A7F81E1AB956ULL,
		0xA2023F750BEBA829ULL,
		0xE99E35DCBD8A6330ULL,
		0x5F23657CA6B6CC2AULL,
		0xE69DB1068D862CE5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6AD90371CA075DBEULL,
		0x7B3C188523114511ULL,
		0x11BA1E831955E2D6ULL,
		0x62AF4D1B22C4A626ULL,
		0x2375A141D90F283DULL,
		0x1B7B2CD09EDF914DULL,
		0x58A95EB78098EDC3ULL,
		0xD214A802F109ED6EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA63035B4FB63C289ULL,
		0xD90DBE513109C9ECULL,
		0x334BE8A742F11E33ULL,
		0x33E35ADCFB561330ULL,
		0x7E8C9E3332DC7FECULL,
		0xCE23090C1EAAD1E3ULL,
		0x067A06C5261DDE67ULL,
		0x148909039C7C3F77ULL
	}};
	sign = 0;
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
		0x480B8DE711274D7DULL,
		0x88BE98F0F2D8E0D3ULL,
		0xAACC9D123741BA0EULL,
		0x53A9CE564B062B75ULL,
		0x1BD2580E18DC4FCAULL,
		0x4EEAC21A46A6BC5EULL,
		0x4DFE156DD730472FULL,
		0xF82C0939AC8499C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14FE569BA4BC92EAULL,
		0xA5B744C1F4A9ED32ULL,
		0x79D50659E4F2F441ULL,
		0x5B2C6BABB3F8C4D2ULL,
		0xC4746E2972090125ULL,
		0xDC44EC33D68A7055ULL,
		0x05B801994702B7FFULL,
		0xD85A734916411B90ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x330D374B6C6ABA93ULL,
		0xE307542EFE2EF3A1ULL,
		0x30F796B8524EC5CCULL,
		0xF87D62AA970D66A3ULL,
		0x575DE9E4A6D34EA4ULL,
		0x72A5D5E6701C4C08ULL,
		0x484613D4902D8F2FULL,
		0x1FD195F096437E31ULL
	}};
	sign = 0;
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
		0x771A5CC20924E936ULL,
		0xC2724B7CD8294A18ULL,
		0x3DAC46CAF05E546BULL,
		0xBE7A9605CD5D2788ULL,
		0x6DA1394779DC7027ULL,
		0xC89B4A9F85FBDF35ULL,
		0x2F66B5127AF53AF1ULL,
		0x8548961402EEEA0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C1F4A8722C52B51ULL,
		0xDC24B04FFAE91DEBULL,
		0x894BA79E8C292B7DULL,
		0x2CDE93922FE47B26ULL,
		0xB4B7992019A152CDULL,
		0xF4EF7E52859C153DULL,
		0xCB55A10C55022955ULL,
		0xD882B59B5D190BB7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEAFB123AE65FBDE5ULL,
		0xE64D9B2CDD402C2CULL,
		0xB4609F2C643528EDULL,
		0x919C02739D78AC61ULL,
		0xB8E9A027603B1D5AULL,
		0xD3ABCC4D005FC9F7ULL,
		0x6411140625F3119BULL,
		0xACC5E078A5D5DE57ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xE022D67114753BEDULL,
		0x061479D79FC7CABFULL,
		0xFC1D04C11DFA33D0ULL,
		0x0123342893CEFEA9ULL,
		0xB6A9808C827A6825ULL,
		0x34932C77FD52791BULL,
		0x85FEF70EC7EE2C27ULL,
		0xEE0E227EE7AF9677ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DA0AFDE0EC83AADULL,
		0x37F6B4FA0B3D9374ULL,
		0xCDB821DA39E76389ULL,
		0xC4F05A0839670B6CULL,
		0x34D8CECB3294917AULL,
		0x8E67EF5D895750CCULL,
		0x896156026671581FULL,
		0x58B5D60DAB5684A9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC282269305AD0140ULL,
		0xCE1DC4DD948A374BULL,
		0x2E64E2E6E412D046ULL,
		0x3C32DA205A67F33DULL,
		0x81D0B1C14FE5D6AAULL,
		0xA62B3D1A73FB284FULL,
		0xFC9DA10C617CD407ULL,
		0x95584C713C5911CDULL
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
		0x1790AB15FF82F92AULL,
		0xDD7C658A3032B664ULL,
		0x0AD095D2ACE71E2AULL,
		0xF558C364AC8F7477ULL,
		0xDF189EBC4DDAEB38ULL,
		0xFE964FD48B753E93ULL,
		0xF22B8C741A73FE9BULL,
		0xAEFC00DE719ECC62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9CF0FA1C59D5D4DULL,
		0xC146876F75881AF1ULL,
		0x5A79F126FF590FBBULL,
		0x747DC1FE21A1DD75ULL,
		0xBC93B9DDB2E646D7ULL,
		0x1A473262E5A6C6FDULL,
		0x51D0172C16FB0CC3ULL,
		0xBD0AE670B4702F46ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1DC19B7439E59BDDULL,
		0x1C35DE1ABAAA9B72ULL,
		0xB056A4ABAD8E0E6FULL,
		0x80DB01668AED9701ULL,
		0x2284E4DE9AF4A461ULL,
		0xE44F1D71A5CE7796ULL,
		0xA05B75480378F1D8ULL,
		0xF1F11A6DBD2E9D1CULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x385825EEDBAE8B2AULL,
		0x2BC7D8DC7777FD20ULL,
		0xE4AE9A502D93506EULL,
		0x6972F9A3CE1D7735ULL,
		0x1438478C3D86CDB5ULL,
		0xE4D23DB434168CECULL,
		0xD32B70A8A69D4AF9ULL,
		0x85EBFCE0C766440AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2909B930A847C75ULL,
		0xE26582BE5579D27FULL,
		0x45DBC5DBE5A9B008ULL,
		0x501977F7A1F6C7E5ULL,
		0x131E03B7636F0080ULL,
		0x24B4958FA8C61BB7ULL,
		0xEA27978F037A8034ULL,
		0xDBA0251EF5F4D19FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x85C78A5BD12A0EB5ULL,
		0x4962561E21FE2AA0ULL,
		0x9ED2D47447E9A065ULL,
		0x195981AC2C26AF50ULL,
		0x011A43D4DA17CD35ULL,
		0xC01DA8248B507135ULL,
		0xE903D919A322CAC5ULL,
		0xAA4BD7C1D171726AULL
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
		0x7E41CFE59AA03DD3ULL,
		0xECE5C5CC678BE630ULL,
		0x606E777B1709A06EULL,
		0xE803CEA2D87E3EC5ULL,
		0x52DD111765A9B55BULL,
		0x386F076667F3A253ULL,
		0x004FB1F659DB06B3ULL,
		0x35D6A25FEF12FAD2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8534CA5419C380E0ULL,
		0xA28C64E7C9D4A69EULL,
		0xDA3D9B5C1E9F1D7EULL,
		0xFDCF1548F22ACF71ULL,
		0xD8AEB42D144494E3ULL,
		0xC1A3D6B64CE1A43BULL,
		0x11549074180224F2ULL,
		0xC4785F4A20C7BD86ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF90D059180DCBCF3ULL,
		0x4A5960E49DB73F91ULL,
		0x8630DC1EF86A82F0ULL,
		0xEA34B959E6536F53ULL,
		0x7A2E5CEA51652077ULL,
		0x76CB30B01B11FE17ULL,
		0xEEFB218241D8E1C0ULL,
		0x715E4315CE4B3D4BULL
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
		0x69F499C24F1471E4ULL,
		0x3C95BEB8E1226E57ULL,
		0xF04AF85E19757B70ULL,
		0x68B260E7A4181240ULL,
		0x5235F2480D0C32E4ULL,
		0x9B72228A35544AEAULL,
		0xBBF5E288AD34A4E7ULL,
		0x5C4DCB537A1F1A30ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3689FA855E126325ULL,
		0xC8015DA81710264FULL,
		0xC54E42B9E4507D6FULL,
		0x87028C98F3E250CCULL,
		0x209618F3B6466F11ULL,
		0x2C6544DE12363FB3ULL,
		0x0C5088832336D7A9ULL,
		0xFCE32BD5A753CFE0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x336A9F3CF1020EBFULL,
		0x74946110CA124808ULL,
		0x2AFCB5A43524FE00ULL,
		0xE1AFD44EB035C174ULL,
		0x319FD95456C5C3D2ULL,
		0x6F0CDDAC231E0B37ULL,
		0xAFA55A0589FDCD3EULL,
		0x5F6A9F7DD2CB4A50ULL
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
		0xE45E2EAD21601C78ULL,
		0x65EF16933BBF31EAULL,
		0x2EC0CCC15928B2CDULL,
		0x5D9F5E8F3451F39BULL,
		0xAEF509D681FE6330ULL,
		0x9E034325049AB001ULL,
		0x603956D5532ED255ULL,
		0x4F148115CF0CEE62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D4005147A793675ULL,
		0x228612E5797C9FE9ULL,
		0x0B22EC51D7D8B92EULL,
		0x9EC57213092F90B6ULL,
		0xBA7878126DA2BB87ULL,
		0x57AD1B4569AB62D0ULL,
		0x750399B4DE7C8584ULL,
		0x347520C2786AC18AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x771E2998A6E6E603ULL,
		0x436903ADC2429201ULL,
		0x239DE06F814FF99FULL,
		0xBED9EC7C2B2262E5ULL,
		0xF47C91C4145BA7A8ULL,
		0x465627DF9AEF4D30ULL,
		0xEB35BD2074B24CD1ULL,
		0x1A9F605356A22CD7ULL
	}};
	sign = 0;
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
		0x62F6AD5C8577D7B5ULL,
		0x914B91A3B4670258ULL,
		0x8618D910A9DF84FEULL,
		0x7F1755679D537F27ULL,
		0x40F28A51A3D19E9CULL,
		0x71CA4D8CCE67C897ULL,
		0x82A8B9E3E271A948ULL,
		0x03A5EF8BCBD452CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98637E4964816491ULL,
		0x0D649E70EB602B8CULL,
		0xDD7B6D43059AF020ULL,
		0xF1628885150AEBE7ULL,
		0x535DF7872C2E94ABULL,
		0x93DC44279D1E750BULL,
		0x806DAF2A7787F8C1ULL,
		0xD6347EA2C50DF3F0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCA932F1320F67324ULL,
		0x83E6F332C906D6CBULL,
		0xA89D6BCDA44494DEULL,
		0x8DB4CCE28848933FULL,
		0xED9492CA77A309F0ULL,
		0xDDEE09653149538BULL,
		0x023B0AB96AE9B086ULL,
		0x2D7170E906C65EDEULL
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
		0xFCD7F71E7E101AA0ULL,
		0x9C25A690DBE4D951ULL,
		0x46CF6B0A23BB40A7ULL,
		0x6377A18A22D7B273ULL,
		0xED561EDAE07CB4A1ULL,
		0xF51C0E6B0D4F87C3ULL,
		0x339711453650121DULL,
		0xB0C5CFC12D1114B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38F09BEF9A5658F3ULL,
		0xBDAE0647F1D9505AULL,
		0xCF36CA9776C2B52BULL,
		0xEA6987B744ADC25BULL,
		0x85FC86F58D437BB7ULL,
		0xE6C99ABAD055716CULL,
		0xF531EA8CB3F3159AULL,
		0x2BD8385047E4C3A3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC3E75B2EE3B9C1ADULL,
		0xDE77A048EA0B88F7ULL,
		0x7798A072ACF88B7BULL,
		0x790E19D2DE29F017ULL,
		0x675997E5533938E9ULL,
		0x0E5273B03CFA1657ULL,
		0x3E6526B8825CFC83ULL,
		0x84ED9770E52C5113ULL
	}};
	sign = 0;
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
		0xC6B103484DC1BCF2ULL,
		0x450659DF404C06F5ULL,
		0x5902797AB8348807ULL,
		0x3693127A125F0583ULL,
		0xB528304EC915CBD6ULL,
		0x5D3BB4A4BB2DF319ULL,
		0x5D4FEA17D041B416ULL,
		0xD628D55AC8FA79CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE7684D66B68BBE8ULL,
		0x022C202660014C09ULL,
		0x87B7E165FD7B24F7ULL,
		0x2F671B9CA3E845C8ULL,
		0x4F4441DD771C5FF4ULL,
		0x8B4192482BECEDBDULL,
		0x1E8FB38C5D3CD9DFULL,
		0x0DEAB8F4F251B72CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x183A7E71E259010AULL,
		0x42DA39B8E04ABAECULL,
		0xD14A9814BAB96310ULL,
		0x072BF6DD6E76BFBAULL,
		0x65E3EE7151F96BE2ULL,
		0xD1FA225C8F41055CULL,
		0x3EC0368B7304DA36ULL,
		0xC83E1C65D6A8C2A2ULL
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
		0xC2362B138E7ACA4CULL,
		0x919A4F90960420CAULL,
		0x2729E60E0811DC97ULL,
		0x8C845FFFA6145296ULL,
		0x07921E40720623E8ULL,
		0xE2ED935F4BD22459ULL,
		0x5E6B12024B261D9FULL,
		0xFB486E39A522E676ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0D8B8A7F1CBE92DULL,
		0xC5010652BD3346F0ULL,
		0x1EB233BD61BDFBD4ULL,
		0xF8A48EB5C1BC0079ULL,
		0x61B600362CC35CA5ULL,
		0x0171012398B879ABULL,
		0xB18B0397DD0196A5ULL,
		0x6A83C091B9E7ECEAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x215D726B9CAEE11FULL,
		0xCC99493DD8D0D9DAULL,
		0x0877B250A653E0C2ULL,
		0x93DFD149E458521DULL,
		0xA5DC1E0A4542C742ULL,
		0xE17C923BB319AAADULL,
		0xACE00E6A6E2486FAULL,
		0x90C4ADA7EB3AF98BULL
	}};
	sign = 0;
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
		0xB00718284A97C136ULL,
		0x42BAE406DAFA4F01ULL,
		0x861B18B9DC277F81ULL,
		0x61D08D3DB14ADD3BULL,
		0x6A889C93BF39A3AEULL,
		0x273C53103758A58AULL,
		0x473124B881883F7EULL,
		0x32120047C1D2CBA3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F711E2BCEF86D4EULL,
		0x39B570DC5E80A81FULL,
		0x73C9DF64FF765C99ULL,
		0x8D412776D2DC1138ULL,
		0xBF49DDD212355AB4ULL,
		0x46D62ECE3042F1E7ULL,
		0xADF0F32B267BA3C9ULL,
		0xE2F2F8F6033466C9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA095F9FC7B9F53E8ULL,
		0x0905732A7C79A6E2ULL,
		0x12513954DCB122E8ULL,
		0xD48F65C6DE6ECC03ULL,
		0xAB3EBEC1AD0448F9ULL,
		0xE06624420715B3A2ULL,
		0x9940318D5B0C9BB4ULL,
		0x4F1F0751BE9E64D9ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xE5FDA3EBA5E48A5CULL,
		0x74094C85E26B8605ULL,
		0xBA0F1C6BFFDB8D57ULL,
		0x6B3B8424BA77A061ULL,
		0xB0A3A1B63D88E73EULL,
		0xD84D89C8FC792905ULL,
		0xBFF8E041F07EA58AULL,
		0x020D9DDDFD07151EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x643995D016AAD49AULL,
		0x9E277A16FD0DB0DAULL,
		0x8DB176D2D65D26DFULL,
		0x0C6D44D04C21B8EDULL,
		0x299C49A08325F75CULL,
		0x14126B8C401AA770ULL,
		0xEF5CCA8B5F4AB22FULL,
		0x4E6DEB2116C52B2AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x81C40E1B8F39B5C2ULL,
		0xD5E1D26EE55DD52BULL,
		0x2C5DA599297E6677ULL,
		0x5ECE3F546E55E774ULL,
		0x87075815BA62EFE2ULL,
		0xC43B1E3CBC5E8195ULL,
		0xD09C15B69133F35BULL,
		0xB39FB2BCE641E9F3ULL
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
		0xFA94F744B92351D8ULL,
		0xE8B102536C7541E5ULL,
		0xDAA91A3E39812F60ULL,
		0xAE92128FF016175CULL,
		0x50CEF9B76A5F60ACULL,
		0xC41A91C1CF4CF390ULL,
		0x84C18E096494C2C6ULL,
		0x13E687022DC6A200ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE17E9A6737860C03ULL,
		0xB6FC7747B156840CULL,
		0xEA909206AB522755ULL,
		0x0C2230C72BEF9235ULL,
		0x9B9AEBE706EF1EBEULL,
		0x6D985CA7DEFA3515ULL,
		0xC8E07CBFAEC54B6DULL,
		0xDB9E6F60D84F42A3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x19165CDD819D45D5ULL,
		0x31B48B0BBB1EBDD9ULL,
		0xF01888378E2F080BULL,
		0xA26FE1C8C4268526ULL,
		0xB5340DD0637041EEULL,
		0x56823519F052BE7AULL,
		0xBBE11149B5CF7759ULL,
		0x384817A155775F5CULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x1E2E14EFB8EF1D0DULL,
		0x2C698522E454C5F1ULL,
		0x86E088DCAE314403ULL,
		0xEBB6483B219EE159ULL,
		0x5B54B4C94F6CBCDAULL,
		0x3BB7A8813651BBEAULL,
		0x31DABDF069EA0201ULL,
		0x5B0D616741021458ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6FA756F061330117ULL,
		0x9A1FE125BC075FF0ULL,
		0xD0157CF4FE716C42ULL,
		0x110FF8B2FA9F45F7ULL,
		0x42CD4B65998B22EBULL,
		0xA00B734B85191404ULL,
		0x35E0E10444D48B6CULL,
		0x2178AD745FFA0D50ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAE86BDFF57BC1BF6ULL,
		0x9249A3FD284D6600ULL,
		0xB6CB0BE7AFBFD7C0ULL,
		0xDAA64F8826FF9B61ULL,
		0x18876963B5E199EFULL,
		0x9BAC3535B138A7E6ULL,
		0xFBF9DCEC25157694ULL,
		0x3994B3F2E1080707ULL
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
		0xB8716843B8557C6CULL,
		0xF21C87695C686EF8ULL,
		0x81D7DFABAC7ECDE9ULL,
		0xE6AF2DAED9D2F769ULL,
		0x4F9D0B60181B957AULL,
		0xB7126C70BA725AC8ULL,
		0x05821751634D4326ULL,
		0xB299C507158D0C2BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2F1588DD3998A4DULL,
		0x8763E6E352CEF6F7ULL,
		0xD89AFD56BB420FDBULL,
		0x24FB682D98CF70EFULL,
		0xE1DA107923A59E5AULL,
		0xD3E97C350052DAE4ULL,
		0xC583A44355E7B604ULL,
		0xD1B2F6A289CDE786ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD5800FB5E4BBF21FULL,
		0x6AB8A08609997800ULL,
		0xA93CE254F13CBE0EULL,
		0xC1B3C58141038679ULL,
		0x6DC2FAE6F475F720ULL,
		0xE328F03BBA1F7FE3ULL,
		0x3FFE730E0D658D21ULL,
		0xE0E6CE648BBF24A4ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x21F50D37E5A6009FULL,
		0x1E6FEC41DFADE882ULL,
		0xC0B17326AC905D29ULL,
		0x08F9A8C0B963F6B4ULL,
		0x0458A7D4A4785362ULL,
		0x11925E85D83A1D1CULL,
		0x5FEC266BEA51D344ULL,
		0x3B6F292C97329AF2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF208BA3863CDFAEULL,
		0x2EE3A1D7AE946AE8ULL,
		0x6126B57E9C493FC6ULL,
		0xA1C15A798E7B51AEULL,
		0xBB54B7FD6D202150ULL,
		0x2AB598D81EA18060ULL,
		0x2F678259F0754142ULL,
		0xE151CE9D29999DF8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x72D481945F6920F1ULL,
		0xEF8C4A6A31197D99ULL,
		0x5F8ABDA810471D62ULL,
		0x67384E472AE8A506ULL,
		0x4903EFD737583211ULL,
		0xE6DCC5ADB9989CBBULL,
		0x3084A411F9DC9201ULL,
		0x5A1D5A8F6D98FCFAULL
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
		0x89E3239DFD779CCCULL,
		0x3FEFA93F2B46DEEBULL,
		0x9901E0E9672987C4ULL,
		0xE9D8FED4C149080AULL,
		0xD91B06BC81D77AFAULL,
		0x4FE23583F22AAE03ULL,
		0x7270DEFA9CA14482ULL,
		0x1E0EE51B5CFE6E4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x339932248F7334BFULL,
		0xCF3C495D6B6DDAD2ULL,
		0x65A81BBE301C7A2AULL,
		0x25862B7345ED7247ULL,
		0x3C30D8FA31166EEEULL,
		0x1249600441123E8CULL,
		0x6EC822F53E1D56CFULL,
		0x81C55BCB5CA20F0EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5649F1796E04680DULL,
		0x70B35FE1BFD90419ULL,
		0x3359C52B370D0D99ULL,
		0xC452D3617B5B95C3ULL,
		0x9CEA2DC250C10C0CULL,
		0x3D98D57FB1186F77ULL,
		0x03A8BC055E83EDB3ULL,
		0x9C498950005C5F3FULL
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
		0xB9C7CA01A98CD8B5ULL,
		0x61F2EC271955CFC1ULL,
		0x41D73B4158EEE36DULL,
		0xC3F03F8268DEFD0EULL,
		0x3EF1192806215C30ULL,
		0x28F96CA5B2AE2D65ULL,
		0xF8ED37F1787CEC69ULL,
		0x031B230962E2D8ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x890A5BAE62206E07ULL,
		0x3405FD9EDB15A7E0ULL,
		0xC1B4FE08CB88E9CCULL,
		0x482708F3106EBAF4ULL,
		0x7FDFE40A5E5112B6ULL,
		0xFDD540FD98BC22D9ULL,
		0x89876BAF36E52D79ULL,
		0x7EB16C10D78C5D81ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x30BD6E53476C6AAEULL,
		0x2DECEE883E4027E1ULL,
		0x80223D388D65F9A1ULL,
		0x7BC9368F58704219ULL,
		0xBF11351DA7D0497AULL,
		0x2B242BA819F20A8BULL,
		0x6F65CC424197BEEFULL,
		0x8469B6F88B567B2CULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x2E5C819FD02EAC8EULL,
		0x85AD4CF91B8A197EULL,
		0xB7ACEE624C140C87ULL,
		0x8B238233D112D63AULL,
		0xFFC7CE36BA2A7EF8ULL,
		0xED6378922563B2A3ULL,
		0xA45BB00D2C1A9B23ULL,
		0x0183918A59ADFEDFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0D269AB76E4B384ULL,
		0x691AE248EC0136E7ULL,
		0x2B59CFA9E04A0D15ULL,
		0x6AAD2ACBABD46F67ULL,
		0xF4A98C638AAF1A8BULL,
		0xD4C9B4C85A09341CULL,
		0x61752238B9ED2219ULL,
		0xA91066499C4096F2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7D8A17F45949F90AULL,
		0x1C926AB02F88E296ULL,
		0x8C531EB86BC9FF72ULL,
		0x20765768253E66D3ULL,
		0x0B1E41D32F7B646DULL,
		0x1899C3C9CB5A7E87ULL,
		0x42E68DD4722D790AULL,
		0x58732B40BD6D67EDULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x9BADED9807F12460ULL,
		0x3060CA73091EE8DEULL,
		0xD165964755A06F6FULL,
		0x75689F48F85D437AULL,
		0x709439D1B0D42EAEULL,
		0xCD4972237865FEC6ULL,
		0xC271B7AE27FFAC9EULL,
		0x120FA9515997BBBFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03DE0EA1A476CD58ULL,
		0xB28A1E973A2D7090ULL,
		0xB347FD256B03549BULL,
		0xF8911B38F6EDE573ULL,
		0xDC87BD08E630DB74ULL,
		0xF0388DAC4E281165ULL,
		0x94B2954994C1BF49ULL,
		0x2D69C7801DA7C45FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x97CFDEF6637A5708ULL,
		0x7DD6ABDBCEF1784EULL,
		0x1E1D9921EA9D1AD3ULL,
		0x7CD78410016F5E07ULL,
		0x940C7CC8CAA35339ULL,
		0xDD10E4772A3DED60ULL,
		0x2DBF2264933DED54ULL,
		0xE4A5E1D13BEFF760ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x2995FAC81F673085ULL,
		0x6E25370E8001918DULL,
		0x0D7210621658E7E1ULL,
		0xB0AB8DC3A706DF63ULL,
		0x071680BE990666D2ULL,
		0x76BB87E70E99735BULL,
		0x7655E1D5202FD1F3ULL,
		0x6574878A00DD4E4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23269CACD18B1B95ULL,
		0x0A94E5B710119AC3ULL,
		0xAA4875806C31916FULL,
		0x986718606DCDAF48ULL,
		0x2466EDEEE368AD5FULL,
		0xA5C62572C75F1C17ULL,
		0x56E8BCF3149A6E46ULL,
		0x41DFE1F2B9F0CD8CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x066F5E1B4DDC14F0ULL,
		0x639051576FEFF6CAULL,
		0x63299AE1AA275672ULL,
		0x184475633939301AULL,
		0xE2AF92CFB59DB973ULL,
		0xD0F56274473A5743ULL,
		0x1F6D24E20B9563ACULL,
		0x2394A59746EC80BFULL
	}};
	sign = 0;
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
		0xD55A68F1AEF32BA9ULL,
		0x94E8D63545A97716ULL,
		0xC70212A5EA41E313ULL,
		0x76DED7F656305852ULL,
		0x4786CA36C01A18E4ULL,
		0x176EBA1096FF624AULL,
		0x4599A5D6E6EEA1D9ULL,
		0x4087903DE4FE85DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4034213281078AC5ULL,
		0x8D1DA5A067D33003ULL,
		0x883B9BDA8CC5BB34ULL,
		0x5093B40C78902069ULL,
		0x7C4451792A791566ULL,
		0x40B662B1522A57D9ULL,
		0x68827BB0149F9799ULL,
		0xD08A9D351945119AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x952647BF2DEBA0E4ULL,
		0x07CB3094DDD64713ULL,
		0x3EC676CB5D7C27DFULL,
		0x264B23E9DDA037E9ULL,
		0xCB4278BD95A1037EULL,
		0xD6B8575F44D50A70ULL,
		0xDD172A26D24F0A3FULL,
		0x6FFCF308CBB97440ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x07514FF18829543BULL,
		0x408F60AD0664E2CDULL,
		0x0A4F1B7F6E162890ULL,
		0x3C6E14B2505F1275ULL,
		0xC6F9901126BA151CULL,
		0xA815288CCAF9FE91ULL,
		0x8A1D922DA737CD45ULL,
		0x49578AF8FCA0C4FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x473925992EE9EF50ULL,
		0x8A3EB2315B02D30DULL,
		0xF5CA999BFF85F03AULL,
		0x25ABEBE6ACB586DAULL,
		0x1149E27529704DBBULL,
		0xB3F35A8F7CF64183ULL,
		0xDFD595362665C44AULL,
		0xFA08A4950BBC8F8FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC0182A58593F64EBULL,
		0xB650AE7BAB620FBFULL,
		0x148481E36E903855ULL,
		0x16C228CBA3A98B9AULL,
		0xB5AFAD9BFD49C761ULL,
		0xF421CDFD4E03BD0EULL,
		0xAA47FCF780D208FAULL,
		0x4F4EE663F0E4356BULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x3BAC1E8912DB9CFAULL,
		0x5301FB3494933186ULL,
		0x3387FDE66E2C4D0EULL,
		0x0657ABE26041D240ULL,
		0x1D418449B6B7AB87ULL,
		0xE7BD9BD0F453EA10ULL,
		0xB313FC1F40894288ULL,
		0x9EBC881C2CC10F61ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x433DB23B18501D24ULL,
		0x145D10EBBC415006ULL,
		0x66BD40CC3E9A970BULL,
		0x89F30542C300B2BEULL,
		0xD5A5ED0389A3C29EULL,
		0x94D668CB8865C2E9ULL,
		0x2FF0AAAF5772CC19ULL,
		0xDDAC5C33B45DB7A1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF86E6C4DFA8B7FD6ULL,
		0x3EA4EA48D851E17FULL,
		0xCCCABD1A2F91B603ULL,
		0x7C64A69F9D411F81ULL,
		0x479B97462D13E8E8ULL,
		0x52E733056BEE2726ULL,
		0x8323516FE916766FULL,
		0xC1102BE8786357C0ULL
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
		0xAA4A63B135727301ULL,
		0x56E0F9934FE7B797ULL,
		0x2D3BF9C06980BF65ULL,
		0x126DF08D3A422D2EULL,
		0x34956F4AF2F6FF2BULL,
		0x91969A26EDB1C231ULL,
		0x132D2E569B9E3078ULL,
		0x065324BB25BE298BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57A62B3EAE36451AULL,
		0x54FD3033E6C130C2ULL,
		0xDB66597BB6464B85ULL,
		0xA1B6A324B76801B1ULL,
		0x86457B64409677B5ULL,
		0x8994B4C1099FA38FULL,
		0x67BFEEC079228351ULL,
		0xCBBB9E9BBDDCF8DEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x52A43872873C2DE7ULL,
		0x01E3C95F692686D5ULL,
		0x51D5A044B33A73E0ULL,
		0x70B74D6882DA2B7CULL,
		0xAE4FF3E6B2608775ULL,
		0x0801E565E4121EA1ULL,
		0xAB6D3F96227BAD27ULL,
		0x3A97861F67E130ACULL
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
		0x086F4722E4246EE5ULL,
		0x494B2DF21FEEBD2CULL,
		0x0398CB445BCC3ABEULL,
		0x69044C74BBA7812AULL,
		0x692968E97BB1D723ULL,
		0x0F682E65318E024FULL,
		0xD447506BE744E225ULL,
		0x7E214CD99436A5E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x899BF87B8E3F6D6DULL,
		0x2D89725B933DE6D4ULL,
		0xD3F97CA9FC992372ULL,
		0x5A1D35FD107371C3ULL,
		0x271CF052ED0C5F03ULL,
		0x9382A12A2FAD6EF4ULL,
		0xB7A713AA1DCF8ADEULL,
		0xDA041D3259FEEDFDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7ED34EA755E50178ULL,
		0x1BC1BB968CB0D657ULL,
		0x2F9F4E9A5F33174CULL,
		0x0EE71677AB340F66ULL,
		0x420C78968EA57820ULL,
		0x7BE58D3B01E0935BULL,
		0x1CA03CC1C9755746ULL,
		0xA41D2FA73A37B7EBULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x2F6232D91A5571D1ULL,
		0x75C511CEA4079691ULL,
		0x70975DE74D088536ULL,
		0x7525409E77CB41FEULL,
		0xAE436EDBE368EA25ULL,
		0x70A7A422A9A2AC12ULL,
		0x59BF1B2938035565ULL,
		0xFEF6D14ED5183860ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5F85A39856FBFF5ULL,
		0xEB214AE92A1123DAULL,
		0x530253713D07B00BULL,
		0xA2FDD8728D596D41ULL,
		0xB5D613F5D392635EULL,
		0xDB329BB0281E7F8DULL,
		0x195102CB71FE7086ULL,
		0xD9398A84DD560B0FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3969D89F94E5B1DCULL,
		0x8AA3C6E579F672B6ULL,
		0x1D950A761000D52AULL,
		0xD227682BEA71D4BDULL,
		0xF86D5AE60FD686C6ULL,
		0x9575087281842C84ULL,
		0x406E185DC604E4DEULL,
		0x25BD46C9F7C22D51ULL
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
		0x69506674DE194C83ULL,
		0x2AC06D61E0A27C2DULL,
		0x9B6B22EF81672D90ULL,
		0x0D0A54865FB559F5ULL,
		0x27202196E5D4190EULL,
		0x353488ED8278C5BAULL,
		0x5B88CEFB6D11D496ULL,
		0x5102AFB06926B0D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F8A776DBBABA791ULL,
		0x01F17C0E40188F1EULL,
		0x562C9B8FC9E60848ULL,
		0xDA7AD1BD2D221635ULL,
		0x5A1D38D52F48CE0BULL,
		0xE1B6B922F9BD7C2AULL,
		0xA61B88F7AE7260C9ULL,
		0x21D5AA45B049B130ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x39C5EF07226DA4F2ULL,
		0x28CEF153A089ED0FULL,
		0x453E875FB7812548ULL,
		0x328F82C9329343C0ULL,
		0xCD02E8C1B68B4B02ULL,
		0x537DCFCA88BB498FULL,
		0xB56D4603BE9F73CCULL,
		0x2F2D056AB8DCFFA2ULL
	}};
	sign = 0;
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
		0xE46785E44EBE48CAULL,
		0x36ECC83A1CE0EFABULL,
		0x7B0302A52C9E438DULL,
		0xB81C2F1458CA5C5FULL,
		0x5E28AD3E182ED821ULL,
		0x2A8A6108FA620895ULL,
		0xF5560635FCA7C260ULL,
		0x2E8A46E083DF7632ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D331484D575E9A2ULL,
		0xFEC6ABF52FA5C38EULL,
		0xCC97439BB0AB9BF7ULL,
		0x105CFBE68A30AF84ULL,
		0xAE47D283BE41F096ULL,
		0xDBBAAE74FB69E749ULL,
		0x0ED3BFB1B2C58415ULL,
		0xC3973D3458FD815FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA734715F79485F28ULL,
		0x38261C44ED3B2C1DULL,
		0xAE6BBF097BF2A795ULL,
		0xA7BF332DCE99ACDAULL,
		0xAFE0DABA59ECE78BULL,
		0x4ECFB293FEF8214BULL,
		0xE682468449E23E4AULL,
		0x6AF309AC2AE1F4D3ULL
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
		0x2B73C4C9C47DC9CEULL,
		0xD2A3FF845E4E618DULL,
		0xEDF7C5A23E03AAA4ULL,
		0x765515435E5FCF1EULL,
		0x87AF9C42B3420DD1ULL,
		0xBA3BBB8E8183C6B6ULL,
		0xFF41C33FD7048B9DULL,
		0xA3A8616B8AF2E16DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D2281846011CFB3ULL,
		0x815840F8591509F5ULL,
		0xE007FD38ECE3FE30ULL,
		0x13ACC04941E6BA23ULL,
		0xE33ED416782D00F3ULL,
		0xB12CF46BC7DD3E9DULL,
		0x2DC07DE5D0D415A8ULL,
		0xA6A0224A8D8F96F8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFE514345646BFA1BULL,
		0x514BBE8C05395797ULL,
		0x0DEFC869511FAC74ULL,
		0x62A854FA1C7914FBULL,
		0xA470C82C3B150CDEULL,
		0x090EC722B9A68818ULL,
		0xD181455A063075F5ULL,
		0xFD083F20FD634A75ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x202C423D33027D38ULL,
		0x326E213CD273C8DAULL,
		0xE903A8AC360599A8ULL,
		0x3030D9D5FD778E73ULL,
		0xCFBFDA841A8CDBEDULL,
		0x8AE291306C75075EULL,
		0x2CD0EE32784111ABULL,
		0xED42512865AB1EB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x173BDB10B965C381ULL,
		0x93AA3B8300C14680ULL,
		0x167255BDB21DFA4EULL,
		0x4EF63F77BB1ACCCFULL,
		0x2A60272B8C3BD922ULL,
		0xD31BDDBA069BADB5ULL,
		0xF5397D513806FC74ULL,
		0x6C9BE67B80202390ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x08F0672C799CB9B7ULL,
		0x9EC3E5B9D1B2825AULL,
		0xD29152EE83E79F59ULL,
		0xE13A9A5E425CC1A4ULL,
		0xA55FB3588E5102CAULL,
		0xB7C6B37665D959A9ULL,
		0x379770E1403A1536ULL,
		0x80A66AACE58AFB28ULL
	}};
	sign = 0;
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
		0x854AED2101B352D0ULL,
		0x1CC375804DDF4669ULL,
		0x6463E48D7168476FULL,
		0x8D0F28CC1039CE49ULL,
		0xFEA21A2DD284B60CULL,
		0x0041197154C6F663ULL,
		0xE9B550BD9F91BD6CULL,
		0xAEA1E6FF91719F8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF63D595E3EE2CCDCULL,
		0x9EF699AAF05CB8C7ULL,
		0x3D5467CBA7C5A46CULL,
		0x34382F8E2B665B80ULL,
		0x1BAE7A61F31591ECULL,
		0xE019BFEE957AEFB4ULL,
		0x115D580EC68C05C3ULL,
		0xE78E09C2563C4B5FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8F0D93C2C2D085F4ULL,
		0x7DCCDBD55D828DA1ULL,
		0x270F7CC1C9A2A302ULL,
		0x58D6F93DE4D372C9ULL,
		0xE2F39FCBDF6F2420ULL,
		0x20275982BF4C06AFULL,
		0xD857F8AED905B7A8ULL,
		0xC713DD3D3B35542CULL
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
		0xCC565199373B72B4ULL,
		0x54270465F77C559FULL,
		0x79558C2CE27D0177ULL,
		0x92B7336B78BB69A9ULL,
		0x2FAD78F4B9FFE31DULL,
		0x3AF6421CB1F009E9ULL,
		0x000598751C2A532AULL,
		0x7C61C5BE38CB9BC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x088810FC34D138FCULL,
		0x8FCB4E5EBE33B7C1ULL,
		0x46923FE9BDC0F8DFULL,
		0x5B8AE83F2728A951ULL,
		0x62A17E811EE1CEA8ULL,
		0xFFB0BE18416FF917ULL,
		0x48A0713B1320C41EULL,
		0xC18845A2AFBAA9BFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC3CE409D026A39B8ULL,
		0xC45BB60739489DDEULL,
		0x32C34C4324BC0897ULL,
		0x372C4B2C5192C058ULL,
		0xCD0BFA739B1E1475ULL,
		0x3B458404708010D1ULL,
		0xB765273A09098F0BULL,
		0xBAD9801B8910F207ULL
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
		0xC0416FAA33F2F073ULL,
		0x5C08BC29885457BEULL,
		0x15418621B5C97902ULL,
		0x566501E9C3430B1EULL,
		0xD50FA36ED10978A2ULL,
		0x22AB7670D9AAB659ULL,
		0xFE3B486AF4841354ULL,
		0x2A2DC49227EC7EACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32D190AA4ACA891BULL,
		0x4095C070F4ABF7AEULL,
		0x255D25C7FA4B06F3ULL,
		0x5CAF3CDF677017F6ULL,
		0x2E6ABFEEDE3028F7ULL,
		0x9E038080A74E418DULL,
		0xF34548B64B1CDE56ULL,
		0xF8EF501ED1F3F0D9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8D6FDEFFE9286758ULL,
		0x1B72FBB893A86010ULL,
		0xEFE46059BB7E720FULL,
		0xF9B5C50A5BD2F327ULL,
		0xA6A4E37FF2D94FAAULL,
		0x84A7F5F0325C74CCULL,
		0x0AF5FFB4A96734FDULL,
		0x313E747355F88DD3ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x8D17AA74E425A1CEULL,
		0xBA6025D87F6C2C4CULL,
		0x7660C7F3443C81DEULL,
		0xC3F9FAAE94799686ULL,
		0x3E8DC58A0BC2E64BULL,
		0xBF92A3617E8DFDC0ULL,
		0x071C8E10DB8E69A5ULL,
		0x2D35A5E4EEB33BA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39D2331A4DA5CC1CULL,
		0x087D446BD564DA8DULL,
		0xBEBDB0883E82922AULL,
		0x1FC51DFE7D455E95ULL,
		0x16669CA49658C873ULL,
		0x53F18484E1963F3FULL,
		0x625C9D84DADF642DULL,
		0xF74E21D6257B9363ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5345775A967FD5B2ULL,
		0xB1E2E16CAA0751BFULL,
		0xB7A3176B05B9EFB4ULL,
		0xA434DCB0173437F0ULL,
		0x282728E5756A1DD8ULL,
		0x6BA11EDC9CF7BE81ULL,
		0xA4BFF08C00AF0578ULL,
		0x35E7840EC937A83EULL
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
		0x619501E8C8642ED4ULL,
		0x71322B0A1EC89C3CULL,
		0xEDDEB3B5380B89A4ULL,
		0xEC97BFCA6D044784ULL,
		0xD01D18C7D38B2C13ULL,
		0xFFCCFFFF18EC261BULL,
		0x276444D2979EEEDAULL,
		0xD30F894B37AD582CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA17CF9421913FFFULL,
		0x9C1DE03676ECB29BULL,
		0x5907560AF6A3CD74ULL,
		0xE3B323B61A62D80DULL,
		0xA6ADEDA7CB7133D6ULL,
		0x61EECB61E271E890ULL,
		0x75C0A4DA23915C0CULL,
		0x4DA448BC66AE0134ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB77D3254A6D2EED5ULL,
		0xD5144AD3A7DBE9A0ULL,
		0x94D75DAA4167BC2FULL,
		0x08E49C1452A16F77ULL,
		0x296F2B200819F83DULL,
		0x9DDE349D367A3D8BULL,
		0xB1A39FF8740D92CEULL,
		0x856B408ED0FF56F7ULL
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
		0xEB636DFC0665127DULL,
		0x78E521F76A6F0E83ULL,
		0x283A55C77B0D31F5ULL,
		0xE870A6AD4FA4CD4CULL,
		0x6A64E57467352420ULL,
		0xAFC1231CE314A7D8ULL,
		0x108E322F3F070A42ULL,
		0xBE1808783B209FDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8EC0B4E25889D1BCULL,
		0x110C2996D6B532C1ULL,
		0x07DE019B754E4F05ULL,
		0x8DDD24A31CE73DA8ULL,
		0x5CD719417F4A74A1ULL,
		0x3FF9A0F46433BF6AULL,
		0x740957224AADDF5EULL,
		0x2EB510B7474009D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5CA2B919ADDB40C1ULL,
		0x67D8F86093B9DBC2ULL,
		0x205C542C05BEE2F0ULL,
		0x5A93820A32BD8FA4ULL,
		0x0D8DCC32E7EAAF7FULL,
		0x6FC782287EE0E86EULL,
		0x9C84DB0CF4592AE4ULL,
		0x8F62F7C0F3E09604ULL
	}};
	sign = 0;
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
		0x3BA3CFE80FEE3098ULL,
		0xDE22B72E74FFEB52ULL,
		0x5987AC901ED513F1ULL,
		0xD1FABF0F898BBE38ULL,
		0x54C34EAC63732A8EULL,
		0xC4CE4C1D0B67DD8DULL,
		0x6976FFE6E29F04ABULL,
		0xFE42A8602008BA1DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1ED16AA9E8DC9A35ULL,
		0x6D1D99DE03F2B8CDULL,
		0x7DB53562EEFDC4E5ULL,
		0xB3DCCE8787FFF22BULL,
		0x0B6D61EF20D7247EULL,
		0x261847B185AFDCC4ULL,
		0xA4425C5930245CBEULL,
		0x24D45457909DA867ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1CD2653E27119663ULL,
		0x71051D50710D3285ULL,
		0xDBD2772D2FD74F0CULL,
		0x1E1DF088018BCC0CULL,
		0x4955ECBD429C0610ULL,
		0x9EB6046B85B800C9ULL,
		0xC534A38DB27AA7EDULL,
		0xD96E54088F6B11B5ULL
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
		0x77D41417A43ADB57ULL,
		0xC94F1BACFE7A6A0DULL,
		0x2F5918813F835CECULL,
		0x84223B64EA95C825ULL,
		0x9EDF8C768590A15CULL,
		0x163819928C3794FFULL,
		0x7AB6DD8EA09C7C99ULL,
		0x3754609344CA0F15ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6FF262D5E0DE42AULL,
		0xCF79EC7979F188DEULL,
		0x15EE9314BA754B8AULL,
		0x435C4D8E0EB92D79ULL,
		0x7F967E5ACABCE082ULL,
		0x5552128D7890E05CULL,
		0x8A6F4A1CF0651AC3ULL,
		0x511663475DC832F3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x90D4EDEA462CF72DULL,
		0xF9D52F338488E12EULL,
		0x196A856C850E1161ULL,
		0x40C5EDD6DBDC9AACULL,
		0x1F490E1BBAD3C0DAULL,
		0xC0E6070513A6B4A3ULL,
		0xF0479371B03761D5ULL,
		0xE63DFD4BE701DC21ULL
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
		0x1064C1044C7D5DEDULL,
		0xD87CDA888CC1F202ULL,
		0xAF974A882E78FCE8ULL,
		0xEEF69A60076AC738ULL,
		0x42CE7F8390A45B04ULL,
		0x533EFD986E6CE945ULL,
		0x8AD6AB3B9FDAE0D2ULL,
		0x998B69A54E9B58A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83C22C8398D64F57ULL,
		0x399077572987920DULL,
		0xDEEF296EC763B250ULL,
		0x72B7EF8B661EFC9FULL,
		0x65591CF3D372F3A5ULL,
		0xA77870322C6D08A2ULL,
		0x4E1640F71FB98FE7ULL,
		0x7695C201854DFA0CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8CA29480B3A70E96ULL,
		0x9EEC6331633A5FF4ULL,
		0xD0A8211967154A98ULL,
		0x7C3EAAD4A14BCA98ULL,
		0xDD75628FBD31675FULL,
		0xABC68D6641FFE0A2ULL,
		0x3CC06A44802150EAULL,
		0x22F5A7A3C94D5E97ULL
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
		0x42669922AE1DEEAFULL,
		0x0E9002DABFBE6D26ULL,
		0x62CE9BC5F633093FULL,
		0xDEE3BD03F932E352ULL,
		0xFCC137572830338FULL,
		0xD441C109AECBCC4AULL,
		0xF556B09EB2D64B35ULL,
		0x31688765C1422241ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5225CDE06365082EULL,
		0xC8B005848D38F510ULL,
		0x35D4949E4D5632F0ULL,
		0x4FBC077FCBC7628DULL,
		0xE9251F9050DED5C5ULL,
		0xB7AD6621B6D20965ULL,
		0xE935E0282E2D9CEEULL,
		0x570C2D10BCE54D37ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF040CB424AB8E681ULL,
		0x45DFFD5632857815ULL,
		0x2CFA0727A8DCD64EULL,
		0x8F27B5842D6B80C5ULL,
		0x139C17C6D7515DCAULL,
		0x1C945AE7F7F9C2E5ULL,
		0x0C20D07684A8AE47ULL,
		0xDA5C5A55045CD50AULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x43FD1D61879DF596ULL,
		0x8EE38374A7289D5CULL,
		0x413F0DBEBE9D0F7CULL,
		0xC3A1868C5D81C434ULL,
		0x3F373C75C358D589ULL,
		0xEFC7EEDC11900733ULL,
		0x26D8E5B95AFF5D17ULL,
		0xBD013217FE288244ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x302BFDE77928CA86ULL,
		0x6DA46D9FBF04CDE6ULL,
		0x1E1CA6AB6DD106A5ULL,
		0xBC21905BF5E03E98ULL,
		0x22CD53E94E1FC0FEULL,
		0xF7D4D71D1BEF9DF0ULL,
		0x000FFB3933A7B048ULL,
		0x9CEBBF5532D959D8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x13D11F7A0E752B10ULL,
		0x213F15D4E823CF76ULL,
		0x2322671350CC08D7ULL,
		0x077FF63067A1859CULL,
		0x1C69E88C7539148BULL,
		0xF7F317BEF5A06943ULL,
		0x26C8EA802757ACCEULL,
		0x201572C2CB4F286CULL
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
		0x616BB1C13D0AF0F3ULL,
		0x266F7332D8139A97ULL,
		0xC24AF56EA467AFE9ULL,
		0xAC5503C996F917F7ULL,
		0x3E0784D2ED1B6957ULL,
		0xFAEF946373A21FFEULL,
		0xCB8FD93A84201920ULL,
		0x0650178F81BF88A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD78317BFF5F260C6ULL,
		0x97B638745B882190ULL,
		0x0DFA5D76B6AA84B1ULL,
		0x2B18318FB55ED7D4ULL,
		0x7C6DBE45209BEDA1ULL,
		0x16CA502420873AEDULL,
		0x2A0D6CE7F6F0051DULL,
		0x1CB7125DEA6127D2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x89E89A014718902DULL,
		0x8EB93ABE7C8B7906ULL,
		0xB45097F7EDBD2B37ULL,
		0x813CD239E19A4023ULL,
		0xC199C68DCC7F7BB6ULL,
		0xE425443F531AE510ULL,
		0xA1826C528D301403ULL,
		0xE9990531975E60D6ULL
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
		0x11D1E6E0B9DCAEEEULL,
		0x713C9FF42BBFA6C4ULL,
		0x0282480722778BC8ULL,
		0xC18E07E77F462B49ULL,
		0x5A920479E10D4676ULL,
		0xB71F2D88A5633BDFULL,
		0x87F28B738FE0F87CULL,
		0x1FAEDD4F4A96AEACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4ADA2C1DEFE98ABULL,
		0xBAE70FAC6595B507ULL,
		0x266972A92B0B901EULL,
		0xFFF069E169D81D61ULL,
		0x9E1894F931425182ULL,
		0x64687CE687EC49CEULL,
		0x99CA7C2FB6F1668FULL,
		0xEDD611420309549FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5D24441EDADE1643ULL,
		0xB6559047C629F1BCULL,
		0xDC18D55DF76BFBA9ULL,
		0xC19D9E06156E0DE7ULL,
		0xBC796F80AFCAF4F3ULL,
		0x52B6B0A21D76F210ULL,
		0xEE280F43D8EF91EDULL,
		0x31D8CC0D478D5A0CULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x8966E267B1A2B9AAULL,
		0xE1C7E85180553DC0ULL,
		0x85862CB0566D5E83ULL,
		0xEBA5AC2C674BAC90ULL,
		0x8343C13704920BEFULL,
		0x7F54074B7ABE22C5ULL,
		0x1D0E2ECAE36A2458ULL,
		0x423BAB3DE6ACAFFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD30D1F84FCD3894ULL,
		0xA8B678004BCAA79BULL,
		0x1474EF44BA5F4EDBULL,
		0x05E19E4CF00D6D89ULL,
		0xA024208247598A48ULL,
		0xD3E5DD011A07BFEEULL,
		0xD0359090BF0D7783ULL,
		0xFBD9F1B05B935072ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDC36106F61D58116ULL,
		0x39117051348A9624ULL,
		0x71113D6B9C0E0FA8ULL,
		0xE5C40DDF773E3F07ULL,
		0xE31FA0B4BD3881A7ULL,
		0xAB6E2A4A60B662D6ULL,
		0x4CD89E3A245CACD4ULL,
		0x4661B98D8B195F8CULL
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
		0xB7F0B138F228818DULL,
		0x2BEEB6C14E1E9E39ULL,
		0xFD2150BDADF0663CULL,
		0x9A1D57AB4605F543ULL,
		0xFF91CF62E85FC583ULL,
		0x2AFC05118AA4DFE9ULL,
		0xA695565F43DE14D7ULL,
		0xB43046593DCB9F3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E57AE7AEC0251AAULL,
		0x34ACA8B84CD9F5EFULL,
		0x028739058DCB39C8ULL,
		0x2C0BCFE36703E805ULL,
		0x5384658BEF077FCBULL,
		0xAB3E2C10B0F58DA1ULL,
		0x8DC04752471D7212ULL,
		0x8F9E36A3BEF743DDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x899902BE06262FE3ULL,
		0xF7420E090144A84AULL,
		0xFA9A17B820252C73ULL,
		0x6E1187C7DF020D3EULL,
		0xAC0D69D6F95845B8ULL,
		0x7FBDD900D9AF5248ULL,
		0x18D50F0CFCC0A2C4ULL,
		0x24920FB57ED45B61ULL
	}};
	sign = 0;
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
		0xD41804E192DA0E52ULL,
		0x8B8B367C4211229FULL,
		0x75BD9BDF99598CD3ULL,
		0x1ACA63D0278CD91BULL,
		0xC11279AA41519B30ULL,
		0xBFE57AE85D5F687DULL,
		0x1109FC31F79C0011ULL,
		0x8DD53893EFF83C4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50DC8939376CB245ULL,
		0xB5CF92B50040FD36ULL,
		0xEBDCD4DEDCEA9413ULL,
		0xE1D597002D2BFDD2ULL,
		0x358C06A031A7C65AULL,
		0x4EBC47BF25A205D7ULL,
		0xC32042BC9ABB6B47ULL,
		0x28923A507867660DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x833B7BA85B6D5C0DULL,
		0xD5BBA3C741D02569ULL,
		0x89E0C700BC6EF8BFULL,
		0x38F4CCCFFA60DB48ULL,
		0x8B86730A0FA9D4D5ULL,
		0x7129332937BD62A6ULL,
		0x4DE9B9755CE094CAULL,
		0x6542FE437790D63EULL
	}};
	sign = 0;
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
		0xB9F02BE6ABB79351ULL,
		0xEAE71B80F53B4053ULL,
		0x03B031DB15C41F81ULL,
		0x6614CED3CF4529FEULL,
		0xE472A129B511F8D2ULL,
		0x6A19A6A67C567180ULL,
		0x0585608873EF6D2DULL,
		0x6B0A29B06318E48EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD46C578344E25FCDULL,
		0xF4C02112E7994510ULL,
		0x57410AB1663F7794ULL,
		0xEC2CA8724B7D9477ULL,
		0xED6F516107DFE846ULL,
		0x192F495D76135441ULL,
		0x101B4FBC230C68AAULL,
		0x1FC86328E1A5D0CBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE583D46366D53384ULL,
		0xF626FA6E0DA1FB42ULL,
		0xAC6F2729AF84A7ECULL,
		0x79E8266183C79586ULL,
		0xF7034FC8AD32108BULL,
		0x50EA5D4906431D3EULL,
		0xF56A10CC50E30483ULL,
		0x4B41C687817313C2ULL
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
		0xF15C83AA0D1E24C6ULL,
		0x2C4551CECD5985EEULL,
		0x788D797891C46979ULL,
		0x06C68F6972D39FC0ULL,
		0xD3634F853AEAAB42ULL,
		0x2AB6C7E9BCAAF183ULL,
		0x78515BBADD722EEFULL,
		0x2ADFA937CA3DE043ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65454F598A59D99AULL,
		0x48805D7EDC745395ULL,
		0xC1B93E4D93073F83ULL,
		0x48E07F29E26E2ACFULL,
		0xC97B221C58DEF4C6ULL,
		0x5E2D5B95459424B6ULL,
		0xDE9D4C4DC9368EA0ULL,
		0x61F202C6FFAD64CAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8C17345082C44B2CULL,
		0xE3C4F44FF0E53259ULL,
		0xB6D43B2AFEBD29F5ULL,
		0xBDE6103F906574F0ULL,
		0x09E82D68E20BB67BULL,
		0xCC896C547716CCCDULL,
		0x99B40F6D143BA04EULL,
		0xC8EDA670CA907B78ULL
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
		0xEC6D8DAD4A059DDDULL,
		0xD45CBD6B412E91F3ULL,
		0x2B0EE7FD9B5BD4D8ULL,
		0x014F35DF946EC02AULL,
		0x8C5DCE6B88D450ACULL,
		0x91CBF6A45C668E9CULL,
		0x4BA18FF3CA455281ULL,
		0x449AB8BB56CDC21AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB7D7DBBB3593ADDULL,
		0x505F7EB0338C45EBULL,
		0xE3454BFD040C0663ULL,
		0xF8007D7562B23B99ULL,
		0xA3A9B9C11BC7D48CULL,
		0xBCD501AF45F113F1ULL,
		0x2EBEEE4AB8E3692CULL,
		0xE3D357F0A4F55597ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00F00FF196AC6300ULL,
		0x83FD3EBB0DA24C08ULL,
		0x47C99C00974FCE75ULL,
		0x094EB86A31BC8490ULL,
		0xE8B414AA6D0C7C1FULL,
		0xD4F6F4F516757AAAULL,
		0x1CE2A1A91161E954ULL,
		0x60C760CAB1D86C83ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x7A2D8C992B57B65EULL,
		0xECCA408FBBF04C78ULL,
		0x97050DE75E68F55EULL,
		0xC446931B2D227B5FULL,
		0xB5F5EB2C7ED40D0BULL,
		0x5434FA0BE423727BULL,
		0x68D0B8360BD440AEULL,
		0x760B971177F5965CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34338B4334262836ULL,
		0xFDDA05F1CB6B7D26ULL,
		0xF6EA453B3F033BA0ULL,
		0x1040D6DA751C2D1CULL,
		0x5AD8E1C1619130D5ULL,
		0xA8909AB2785D69B3ULL,
		0x6A13FA9AE8EC082CULL,
		0xB9A688A1C85FC480ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x45FA0155F7318E28ULL,
		0xEEF03A9DF084CF52ULL,
		0xA01AC8AC1F65B9BDULL,
		0xB405BC40B8064E42ULL,
		0x5B1D096B1D42DC36ULL,
		0xABA45F596BC608C8ULL,
		0xFEBCBD9B22E83881ULL,
		0xBC650E6FAF95D1DBULL
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
		0xB63B0FBBA7E0D58DULL,
		0x4147061D40CD9586ULL,
		0xBD626E61F2343835ULL,
		0x40DDE5FB1B7C32F6ULL,
		0x0FA33E1645B30278ULL,
		0x60DC10CCDC26CF71ULL,
		0x5F8E30E1FA74905FULL,
		0xB6B6075BFD9CC2E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F08A5B6238C312CULL,
		0x2356120F00A16A2DULL,
		0xDB6679B3CBA63D21ULL,
		0x8E5AFDEB20837527ULL,
		0x3847DD588778C281ULL,
		0x1FDCBE79CE2882AEULL,
		0x1078FF82D49E39DFULL,
		0x065DB3338601D9E2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x57326A058454A461ULL,
		0x1DF0F40E402C2B59ULL,
		0xE1FBF4AE268DFB14ULL,
		0xB282E80FFAF8BDCEULL,
		0xD75B60BDBE3A3FF6ULL,
		0x40FF52530DFE4CC2ULL,
		0x4F15315F25D65680ULL,
		0xB0585428779AE8FEULL
	}};
	sign = 0;
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
		0x8E39987EF59B705DULL,
		0x630652987A08DB5BULL,
		0x84C6F802902A9EA8ULL,
		0x45BEFCA7BE2B2CD7ULL,
		0x0509402629E62B91ULL,
		0x51156B73634F814CULL,
		0x2F5256B51B127642ULL,
		0x44F46A9A54878526ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B0E39D3CE445A7FULL,
		0x846528C2F64E6B93ULL,
		0x351CD2B018C31E27ULL,
		0x286D8ED1BA05C863ULL,
		0x37BD45BA542E1BB0ULL,
		0x915A4A26BFB060E0ULL,
		0x404EFFE4B4A74BF8ULL,
		0x44FA777FAB06EF52ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x532B5EAB275715DEULL,
		0xDEA129D583BA6FC8ULL,
		0x4FAA255277678080ULL,
		0x1D516DD604256474ULL,
		0xCD4BFA6BD5B80FE1ULL,
		0xBFBB214CA39F206BULL,
		0xEF0356D0666B2A49ULL,
		0xFFF9F31AA98095D3ULL
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
		0xC32998E844CFBE9EULL,
		0x02FA5B63CC6E2E7CULL,
		0x67EB2474B4177BE3ULL,
		0x9817FFFDD363C8BCULL,
		0xB5F4DC2A88B236EFULL,
		0x9E561BB0FD63C9BAULL,
		0x59A8571B79F1D461ULL,
		0xA15A1D4AF18E2269ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01BC8E9FB73C7D64ULL,
		0x0E76E02B6DEF553DULL,
		0x216048B21D111AF6ULL,
		0xBA40266D190D48ADULL,
		0x3992E44421B82B13ULL,
		0xDE2C56D21108397CULL,
		0x9732A8F430D2C095ULL,
		0x8646FE827DB34121ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC16D0A488D93413AULL,
		0xF4837B385E7ED93FULL,
		0x468ADBC2970660ECULL,
		0xDDD7D990BA56800FULL,
		0x7C61F7E666FA0BDBULL,
		0xC029C4DEEC5B903EULL,
		0xC275AE27491F13CBULL,
		0x1B131EC873DAE147ULL
	}};
	sign = 0;
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
		0xDA4599266F0A2E81ULL,
		0x4624867099267D4EULL,
		0x36B0A15304D5A2FCULL,
		0xABF31FBE0CC95B85ULL,
		0xD54A785041A3D5C8ULL,
		0xCA9A6AFD6E5FCDB4ULL,
		0xC0C36BB2E4288776ULL,
		0x5CFE79CFFBB278C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6B038EA3CF3761AULL,
		0x52A12547F15A4507ULL,
		0x61B78EF092CEE783ULL,
		0xECCB10581C4AC087ULL,
		0xA49462D4AD75925CULL,
		0xFBB7DF822B642DEFULL,
		0xC4B483CB6108E174ULL,
		0xCEA08CCC8D3AD29CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE395603C3216B867ULL,
		0xF3836128A7CC3846ULL,
		0xD4F912627206BB78ULL,
		0xBF280F65F07E9AFDULL,
		0x30B6157B942E436BULL,
		0xCEE28B7B42FB9FC5ULL,
		0xFC0EE7E7831FA601ULL,
		0x8E5DED036E77A62AULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xA6F9DE8C402B1831ULL,
		0x4D5D2CF158752856ULL,
		0x91FFF8CDFF80C5B1ULL,
		0xFBAB66AECBCD6448ULL,
		0xBE4D90A8F9EABA27ULL,
		0xDC9DD5E22A527C08ULL,
		0xA6852BCE3F469590ULL,
		0xF371D59D5ECC7714ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD319BD4F93EE568EULL,
		0xE30FCC9D8F49BB7CULL,
		0x852AF699A77DD53AULL,
		0xEB213375BBBE23A9ULL,
		0x72D3242E059829F3ULL,
		0xB2B50C5DEFA43EC7ULL,
		0x3C29375309B50829ULL,
		0x3AA0E1430CC3F418ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD3E0213CAC3CC1A3ULL,
		0x6A4D6053C92B6CD9ULL,
		0x0CD502345802F076ULL,
		0x108A3339100F409FULL,
		0x4B7A6C7AF4529034ULL,
		0x29E8C9843AAE3D41ULL,
		0x6A5BF47B35918D67ULL,
		0xB8D0F45A520882FCULL
	}};
	sign = 0;
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
		0x3AF68F2A5B06A74BULL,
		0x85E047C6A7CCA5AAULL,
		0xC7F3294C899C58AEULL,
		0x3DA76157FB874077ULL,
		0x609E37A59DEA507EULL,
		0xF90A222860D1BABDULL,
		0x9202458F1DDC9252ULL,
		0xFE623EF99940E8C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE132E5B66C0242BULL,
		0xDDAD6F0B07C514F6ULL,
		0x83386622EFA768FCULL,
		0x9BEE797B39838876ULL,
		0x0BBE9B7047147F6EULL,
		0xD99CAE5535BC390DULL,
		0x201FA30C55596F29ULL,
		0x2972C88029681338ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4CE360CEF4468320ULL,
		0xA832D8BBA00790B3ULL,
		0x44BAC32999F4EFB1ULL,
		0xA1B8E7DCC203B801ULL,
		0x54DF9C3556D5D10FULL,
		0x1F6D73D32B1581B0ULL,
		0x71E2A282C8832329ULL,
		0xD4EF76796FD8D58AULL
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
		0x4425C8B27146FF33ULL,
		0x3F57187381518A5CULL,
		0x438AEE8CC9A414BCULL,
		0xA546B8398887E1EDULL,
		0x3AB11CE50339013BULL,
		0xE5BB0E4B0405A9D0ULL,
		0xD8D87E2CC054BCA0ULL,
		0x70FAC640EA0CA3B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40A320C943DF1BCDULL,
		0x9876EBA4314B4FFEULL,
		0xCFB670181DC27D54ULL,
		0x38EF764749D7E98DULL,
		0xFA4C7CF89B0FDBE2ULL,
		0xCF25C9EE63C4147CULL,
		0x377489E3AEF400D2ULL,
		0x29F289FF5769C26FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0382A7E92D67E366ULL,
		0xA6E02CCF50063A5EULL,
		0x73D47E74ABE19767ULL,
		0x6C5741F23EAFF85FULL,
		0x40649FEC68292559ULL,
		0x1695445CA0419553ULL,
		0xA163F4491160BBCEULL,
		0x47083C4192A2E145ULL
	}};
	sign = 0;
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
		0x34FF1879450DCF5DULL,
		0x11972F5B29490A89ULL,
		0x6C61C94F6635494FULL,
		0x7FDC8E50F578A4B7ULL,
		0x0F9D81BB6E5427B3ULL,
		0xFFFD8B06FF4748F8ULL,
		0xA275572C9467AD64ULL,
		0xB8B3CE5E338F7F19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2717851271913CA8ULL,
		0x6E5AD12B82D779C8ULL,
		0xDFD4060144D5BFFEULL,
		0xBEFF76A10837C830ULL,
		0x05F83096109730D7ULL,
		0x12B318281322DBDEULL,
		0x5EEE625D22682BDDULL,
		0x7E2F7F42067D9B7BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0DE79366D37C92B5ULL,
		0xA33C5E2FA67190C1ULL,
		0x8C8DC34E215F8950ULL,
		0xC0DD17AFED40DC86ULL,
		0x09A551255DBCF6DBULL,
		0xED4A72DEEC246D1AULL,
		0x4386F4CF71FF8187ULL,
		0x3A844F1C2D11E39EULL
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
		0x65FEE16276D00998ULL,
		0xF7BAD11121D3EA89ULL,
		0xB1BBDF3BABE90B20ULL,
		0x1437A053E3ACC2A1ULL,
		0x74A606A128D4CDDDULL,
		0xA000EDAC92BE49D8ULL,
		0x7011C8BD1DD63328ULL,
		0x3C24D51BCE5CCA73ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05E0A05B2FAF5E97ULL,
		0x6BB1E59B6AF13C24ULL,
		0xC0BF98690B1BFCA4ULL,
		0xC926A316EFD2FBB2ULL,
		0x1EE46EA72EB0BCE1ULL,
		0xF0E56142CB61685EULL,
		0x4B8D70A764D44745ULL,
		0x74E73B1AC506A227ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x601E41074720AB01ULL,
		0x8C08EB75B6E2AE65ULL,
		0xF0FC46D2A0CD0E7CULL,
		0x4B10FD3CF3D9C6EEULL,
		0x55C197F9FA2410FBULL,
		0xAF1B8C69C75CE17AULL,
		0x24845815B901EBE2ULL,
		0xC73D9A010956284CULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xF2E78785D47E4E1CULL,
		0xB7520EA2230DC81FULL,
		0x998F5B73B4819137ULL,
		0x63BC5270888782FDULL,
		0xF039130BE155C377ULL,
		0x8A0A51FA68A316B5ULL,
		0x91D7B7591D4D2276ULL,
		0x998CEF4FDD21D68DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6D0853C27B67E9AULL,
		0x781ECA0123BADC94ULL,
		0xFF12CD28A71AA0C7ULL,
		0xDDD02DA9EF871A65ULL,
		0x410FFF8FFAD85EC9ULL,
		0xC7F20A1CA902A16BULL,
		0xDA4F24CA1E026F2EULL,
		0xFBD07C7AA9FBB04CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2C170249ACC7CF82ULL,
		0x3F3344A0FF52EB8BULL,
		0x9A7C8E4B0D66F070ULL,
		0x85EC24C699006897ULL,
		0xAF29137BE67D64ADULL,
		0xC21847DDBFA0754AULL,
		0xB788928EFF4AB347ULL,
		0x9DBC72D533262640ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xC7C7E226ECB617A3ULL,
		0xF4CCD2D84D661FF8ULL,
		0xCDE6118EFD6A897BULL,
		0xE1E9DB06F94A02C2ULL,
		0x8E5B032D888877F0ULL,
		0x3A6DC862FD8C921CULL,
		0x22FDF8E296240CDFULL,
		0x2DAC53C6648B61C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32E24D5358B8DDA1ULL,
		0x275C8F895073CFF8ULL,
		0x6B3ECAFAEC1821BEULL,
		0xC850A92539234B80ULL,
		0xC356B34B544232E4ULL,
		0x59F06E206EB504E2ULL,
		0xC7E706255E5A2882ULL,
		0xD3805AC2A9CBE4D0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x94E594D393FD3A02ULL,
		0xCD70434EFCF25000ULL,
		0x62A74694115267BDULL,
		0x199931E1C026B742ULL,
		0xCB044FE23446450CULL,
		0xE07D5A428ED78D39ULL,
		0x5B16F2BD37C9E45CULL,
		0x5A2BF903BABF7CF6ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x84B297C79637E6CDULL,
		0x378835948E420331ULL,
		0x9E086448A49EF111ULL,
		0x011C4915F8CB6C70ULL,
		0x77A0367CE53BB59AULL,
		0x4BB082A1C22B2785ULL,
		0x2128A0F33E521A9DULL,
		0xDD3B3C4ABD421B2DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82E1BECA7460CB3DULL,
		0x7960D8C7B9A3CA34ULL,
		0x3856A8F7AB3C5B9CULL,
		0x8BF44C4280EE7BEEULL,
		0x517144D071C6D78CULL,
		0x8BF4D3E3C0E05D2BULL,
		0x01557B3FFDE95367ULL,
		0x1E651F577FE97B58ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01D0D8FD21D71B90ULL,
		0xBE275CCCD49E38FDULL,
		0x65B1BB50F9629574ULL,
		0x7527FCD377DCF082ULL,
		0x262EF1AC7374DE0DULL,
		0xBFBBAEBE014ACA5AULL,
		0x1FD325B34068C735ULL,
		0xBED61CF33D589FD5ULL
	}};
	sign = 0;
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
		0x42FCFC6FDF25B0E5ULL,
		0x901C6DE3DC4E2D32ULL,
		0xA77DC3CD7E139A03ULL,
		0x564CE07A7F157735ULL,
		0x48E9A0BF171DEC41ULL,
		0xDD435C4478BE3FEFULL,
		0x04C7E99FD86BD4BFULL,
		0x814A5A5F6DA9EA92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF545286928DBD3EFULL,
		0xACE0F72FB1AE1853ULL,
		0x7A1F54E82CE99904ULL,
		0xCF93A01D737E9E9DULL,
		0x3D815A8A8EDF1921ULL,
		0x0DCC96501FACA4EDULL,
		0x89C74839040C1951ULL,
		0xBC7B6C5B3BD8D294ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4DB7D406B649DCF6ULL,
		0xE33B76B42AA014DEULL,
		0x2D5E6EE5512A00FEULL,
		0x86B9405D0B96D898ULL,
		0x0B684634883ED31FULL,
		0xCF76C5F459119B02ULL,
		0x7B00A166D45FBB6EULL,
		0xC4CEEE0431D117FDULL
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
		0xBB35155BB988D533ULL,
		0x50678314D73F220CULL,
		0x63A8AFEEB7AE6075ULL,
		0x76C846614A80879CULL,
		0x207F6EA4B86501BBULL,
		0x7A3A7612C72DFD16ULL,
		0xD5BECE3C08A6C76EULL,
		0x1433B6FA73249DCFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBEDC9DDFB2ACCE9AULL,
		0xFC354297F8E3B6DBULL,
		0xED966F61E1933776ULL,
		0x6DF52EDAAB6116F7ULL,
		0x8420211900A84F55ULL,
		0xD1F71605327DCFFDULL,
		0x9E1F27658A60A38EULL,
		0x561F233D623AA243ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFC58777C06DC0699ULL,
		0x5432407CDE5B6B30ULL,
		0x7612408CD61B28FEULL,
		0x08D317869F1F70A4ULL,
		0x9C5F4D8BB7BCB266ULL,
		0xA843600D94B02D18ULL,
		0x379FA6D67E4623DFULL,
		0xBE1493BD10E9FB8CULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x1A86E371F801E440ULL,
		0x7D81B5EA8AE8B730ULL,
		0xBC59866F8907C2D5ULL,
		0x8166D21E4B02C3CEULL,
		0x471F3DE0F5F38F1EULL,
		0x68EFC2B732A68BA1ULL,
		0x22AED1B279B273E8ULL,
		0xE62648CF95BBCA35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x254C122D3E103106ULL,
		0xF636C943141C9FF3ULL,
		0xA382F0A8744AABD4ULL,
		0xDF5605AC79706B99ULL,
		0x49422F78D1BE58ECULL,
		0xDF266040C401A6D6ULL,
		0x06A2B1E71C1AF617ULL,
		0x2C16C74446BD2C11ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF53AD144B9F1B33AULL,
		0x874AECA776CC173CULL,
		0x18D695C714BD1700ULL,
		0xA210CC71D1925835ULL,
		0xFDDD0E6824353631ULL,
		0x89C962766EA4E4CAULL,
		0x1C0C1FCB5D977DD0ULL,
		0xBA0F818B4EFE9E24ULL
	}};
	sign = 0;
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
		0x6B26B73E07E37B19ULL,
		0xE11515BD3E8C1440ULL,
		0xC655D96DE3AD4AEBULL,
		0x23D4E0F649F08130ULL,
		0x9F05035D6F8868DFULL,
		0x33A4E0FC6475924BULL,
		0xE21AECFB07233E7AULL,
		0xF39AB965F6CCFD25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A4620BB8B959011ULL,
		0x91E4953435CB2BBCULL,
		0xE29F6FA1D4F2340DULL,
		0x8F4187B0A5C6E82DULL,
		0x0B46F09D1FAE1BBEULL,
		0xA0A2520E0D979163ULL,
		0x1048E5F97A1E9F2DULL,
		0x9B12428EA1AC3029ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x60E096827C4DEB08ULL,
		0x4F30808908C0E884ULL,
		0xE3B669CC0EBB16DEULL,
		0x94935945A4299902ULL,
		0x93BE12C04FDA4D20ULL,
		0x93028EEE56DE00E8ULL,
		0xD1D207018D049F4CULL,
		0x588876D75520CCFCULL
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
		0x33A51C743D9F786FULL,
		0x7EAFF765DFCD1741ULL,
		0x02A32B201AC29F35ULL,
		0xCDF837F117EFC638ULL,
		0xE4AAB91D20E6CCB4ULL,
		0xDA4C108C216B7587ULL,
		0x563BC5C25ED2F1ECULL,
		0x606A6EBFD48240B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36911B3DC87EA38DULL,
		0xCA4E236052D16537ULL,
		0x18E19BB1F44D9BBFULL,
		0x19FBA1830E7C71BCULL,
		0x0DDF90AE8CB3CC67ULL,
		0x778F3D854AA7EA9FULL,
		0x3A8A88A64E4E3708ULL,
		0x371DD9EFBD0DA563ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFD1401367520D4E2ULL,
		0xB461D4058CFBB209ULL,
		0xE9C18F6E26750375ULL,
		0xB3FC966E0973547BULL,
		0xD6CB286E9433004DULL,
		0x62BCD306D6C38AE8ULL,
		0x1BB13D1C1084BAE4ULL,
		0x294C94D017749B52ULL
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
		0x5FE99F8CD062580CULL,
		0x756839BC5F58F23EULL,
		0x1943C39266416596ULL,
		0xB80E205385254923ULL,
		0x6EE46900CF0C5CDCULL,
		0xC70FF66EA537BCF7ULL,
		0x705074BB4277F553ULL,
		0xE696571476FD2FD2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C1F82771D9E01E1ULL,
		0x627BFEDF98A527BAULL,
		0x31E0C944E205973CULL,
		0x0ED9F14BCF424E48ULL,
		0x719B542C0E277802ULL,
		0x44EB578F9A706146ULL,
		0xCD545AC786F0086FULL,
		0x16A69178BDA593F2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x53CA1D15B2C4562BULL,
		0x12EC3ADCC6B3CA84ULL,
		0xE762FA4D843BCE5AULL,
		0xA9342F07B5E2FADAULL,
		0xFD4914D4C0E4E4DAULL,
		0x82249EDF0AC75BB0ULL,
		0xA2FC19F3BB87ECE4ULL,
		0xCFEFC59BB9579BDFULL
	}};
	sign = 0;
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
		0xBD88500DE5D72152ULL,
		0x3D3997BEE35CEA66ULL,
		0xAD11A276679E8AD3ULL,
		0x27D805BE091AB383ULL,
		0xA18D2F6ED63B0358ULL,
		0xA54896452E972473ULL,
		0xF3AC6878016E007DULL,
		0xE43BF28213C2623FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8930A1B9B5243E4ULL,
		0x495D8410D7E14E62ULL,
		0x4D603F8639BFD8C7ULL,
		0xD62B60067D3C5D1CULL,
		0x4F399162E9884BE8ULL,
		0xFE68E18A67029435ULL,
		0x5D18F7C587EEF5BFULL,
		0xF1B8FA655FA0F236ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04F545F24A84DD6EULL,
		0xF3DC13AE0B7B9C04ULL,
		0x5FB162F02DDEB20BULL,
		0x51ACA5B78BDE5667ULL,
		0x52539E0BECB2B76FULL,
		0xA6DFB4BAC794903EULL,
		0x969370B2797F0ABDULL,
		0xF282F81CB4217009ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xDA6C5D8E2C2A57CEULL,
		0x442C14172D6B0F17ULL,
		0x1E03E405243BD9DEULL,
		0xA96AE28CC37C20DEULL,
		0x381AB4242E7CE7F6ULL,
		0xBC3EFA4260C6455AULL,
		0x39DB0474E61D7E8DULL,
		0xB62B591C6B97C7DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90558F3E6FD09A49ULL,
		0xBB620C1481F7151FULL,
		0xE2083EEE0E705A78ULL,
		0x6ABD441BB88F79D2ULL,
		0x34443A264F39BADEULL,
		0x4D289B74F09BB762ULL,
		0xB7AE64A7BD86298AULL,
		0xDA36B6B1C6608C40ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4A16CE4FBC59BD85ULL,
		0x88CA0802AB73F9F8ULL,
		0x3BFBA51715CB7F65ULL,
		0x3EAD9E710AECA70BULL,
		0x03D679FDDF432D18ULL,
		0x6F165ECD702A8DF8ULL,
		0x822C9FCD28975503ULL,
		0xDBF4A26AA5373B9BULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xA2836080A66607EBULL,
		0x61E194CD1AB1A94DULL,
		0x38BDC6AF39544AF6ULL,
		0x957F6CAEE1722866ULL,
		0x07B5854391230AA8ULL,
		0x8D9C36B9AEEA9867ULL,
		0xEFC0C6D56CDBB00AULL,
		0x00A50F333205944FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x233CBF6523B45246ULL,
		0x65638EB83A3EAC15ULL,
		0xF4FC947BA0C64F49ULL,
		0x53D87310B9685524ULL,
		0x3D09BA62170BA874ULL,
		0x7D579CA0C5B72398ULL,
		0xA150D7BC8494A28DULL,
		0x64BE00070BFE5494ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7F46A11B82B1B5A5ULL,
		0xFC7E0614E072FD38ULL,
		0x43C13233988DFBACULL,
		0x41A6F99E2809D341ULL,
		0xCAABCAE17A176234ULL,
		0x10449A18E93374CEULL,
		0x4E6FEF18E8470D7DULL,
		0x9BE70F2C26073FBBULL
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
		0x661A5D022C1C546DULL,
		0x5F28B1087B43F847ULL,
		0x6E3590BF92C82610ULL,
		0x0E693DDAE3E76096ULL,
		0x5E567554FB8806F1ULL,
		0xAC1C3E4D8E55FAEAULL,
		0xC4F1903DD5EF3367ULL,
		0xB65EDE850C12D8E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3C8619334CFDDF2ULL,
		0x576D6CE31DEC0E93ULL,
		0x7C1E62C1C4DD0047ULL,
		0x2EFBA7D955BB715CULL,
		0x5309A2F61C1DD224ULL,
		0x95FE5CFB7271CCFEULL,
		0x479B5CFCA10D9CDAULL,
		0x81F4F1F98A91FFEAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB251FB6EF74C767BULL,
		0x07BB44255D57E9B3ULL,
		0xF2172DFDCDEB25C9ULL,
		0xDF6D96018E2BEF39ULL,
		0x0B4CD25EDF6A34CCULL,
		0x161DE1521BE42DECULL,
		0x7D56334134E1968DULL,
		0x3469EC8B8180D8FEULL
	}};
	sign = 0;
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
		0xBE91A4B9986AED2DULL,
		0xBA15B63DD6E0E5A2ULL,
		0x3B618BCC60FEAD3DULL,
		0xAEF3E00BF01208C2ULL,
		0xD7A420F3FBB17E4DULL,
		0x2073153146516832ULL,
		0xC02F253B8EADD8E2ULL,
		0x2AE18A222EF639A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC94BFF0237746BBULL,
		0x5368F2C3AE8CB99CULL,
		0xA2D0AFE17FCEA32FULL,
		0x683C44A788428C35ULL,
		0x150907CFABE81BFDULL,
		0xD30ABFE0F4C281BDULL,
		0x59195ADC625AF2D2ULL,
		0x0DB477D466E4BDAEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF1FCE4C974F3A672ULL,
		0x66ACC37A28542C05ULL,
		0x9890DBEAE1300A0EULL,
		0x46B79B6467CF7C8CULL,
		0xC29B19244FC96250ULL,
		0x4D685550518EE675ULL,
		0x6715CA5F2C52E60FULL,
		0x1D2D124DC8117BFAULL
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
		0xC010B5E7C759831EULL,
		0xE9D3B5AD832385B5ULL,
		0xDFEAE48B93FBFA6DULL,
		0x8CDDD33BF8081BF9ULL,
		0x458F59F28640A6E9ULL,
		0x1782253FB85D76A6ULL,
		0x3BADAA16A9361FC0ULL,
		0xFC197183E6A0CC4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x917D2B66D3A486F5ULL,
		0x6298C05CD6286035ULL,
		0xDDD43422D0373504ULL,
		0x1505D483D4974CBDULL,
		0x42F87CD38026DB94ULL,
		0x733D5BADB0A46BF6ULL,
		0x82273465EA53C4F3ULL,
		0x8234006C118A75ADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2E938A80F3B4FC29ULL,
		0x873AF550ACFB2580ULL,
		0x0216B068C3C4C569ULL,
		0x77D7FEB82370CF3CULL,
		0x0296DD1F0619CB55ULL,
		0xA444C99207B90AB0ULL,
		0xB98675B0BEE25ACCULL,
		0x79E57117D516569EULL
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
		0x4665AB275F93C02DULL,
		0x51CF9F55506F2F9CULL,
		0x96D3423677A8AAB5ULL,
		0x0335B888CA480AA3ULL,
		0x10BE275296438DD6ULL,
		0xFD421124CEF744DCULL,
		0x7079EF7936E6D76CULL,
		0xEFB3332E42922D75ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82BAB5E63079B4F3ULL,
		0xE2F5C656F90B4E2CULL,
		0xED89A03AD2CFC0D2ULL,
		0xFAFE3EC95BE89F6DULL,
		0x48B56BF87F5DADAAULL,
		0x73F044A5C6010081ULL,
		0xBB01FF9A3BCCC2B7ULL,
		0x9DFE54A101423E15ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC3AAF5412F1A0B3AULL,
		0x6ED9D8FE5763E16FULL,
		0xA949A1FBA4D8E9E2ULL,
		0x083779BF6E5F6B35ULL,
		0xC808BB5A16E5E02BULL,
		0x8951CC7F08F6445AULL,
		0xB577EFDEFB1A14B5ULL,
		0x51B4DE8D414FEF5FULL
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
		0x491E459F83B89653ULL,
		0x991E27E3D8F5C395ULL,
		0x39701A66CFA283B8ULL,
		0xB5F954963AF30CC5ULL,
		0xD48C8657E1966D11ULL,
		0xC64F52F3B5EFB4E3ULL,
		0x45616ABF5E70A5D4ULL,
		0x64AAE574EE7CD0E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F48B019087F23D8ULL,
		0xE8A559339A690F45ULL,
		0x41BC2E5A713A8B8FULL,
		0x06060A9359C945C8ULL,
		0xD7AF62D921B7489EULL,
		0xCDA509F9B0F05E2BULL,
		0x327BA030670BBBE3ULL,
		0x95CF382ACEEA9D15ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x39D595867B39727BULL,
		0xB078CEB03E8CB450ULL,
		0xF7B3EC0C5E67F828ULL,
		0xAFF34A02E129C6FCULL,
		0xFCDD237EBFDF2473ULL,
		0xF8AA48FA04FF56B7ULL,
		0x12E5CA8EF764E9F0ULL,
		0xCEDBAD4A1F9233D1ULL
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
		0x36AC20A3A9E14ACBULL,
		0x2F5063028C1DCF90ULL,
		0x449141DC540A02ADULL,
		0x931E62C719CCA251ULL,
		0x73BD0BE8AF65D1A9ULL,
		0xB0CA7965D69B29A3ULL,
		0x41F03EC40D5A23A2ULL,
		0x2D737390F2983DA3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CC8BFEF20FA0C56ULL,
		0x293DC65A29B073ACULL,
		0xD14115862E007C40ULL,
		0xA11966315D5AE1C0ULL,
		0x6FAC9FCEE9EBE838ULL,
		0xA222ADAFAFD86637ULL,
		0x372F96BB5F48D37DULL,
		0xEAE0487C818544E6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA9E360B488E73E75ULL,
		0x06129CA8626D5BE3ULL,
		0x73502C562609866DULL,
		0xF204FC95BC71C090ULL,
		0x04106C19C579E970ULL,
		0x0EA7CBB626C2C36CULL,
		0x0AC0A808AE115025ULL,
		0x42932B147112F8BDULL
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
		0xD61B8CE9447D5EB1ULL,
		0x014EE9847F84F7C3ULL,
		0x0F05647EAE5C064DULL,
		0x9874110E9D4942E8ULL,
		0x638BF79A1971AE28ULL,
		0xF6467312CB9DD454ULL,
		0x195894B01F2BC017ULL,
		0x382D7368B43B98F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9E693C068076B23ULL,
		0xD3348A0B87389022ULL,
		0x600D0275F3D3D2FDULL,
		0x4AAC6E27CD9523AAULL,
		0x82F010B93915CAC5ULL,
		0x8D75A185DE468EE8ULL,
		0x6E0DD9CD821573B9ULL,
		0xABDE5EE189AC1D5EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C34F928DC75F38EULL,
		0x2E1A5F78F84C67A1ULL,
		0xAEF86208BA88334FULL,
		0x4DC7A2E6CFB41F3DULL,
		0xE09BE6E0E05BE363ULL,
		0x68D0D18CED57456BULL,
		0xAB4ABAE29D164C5EULL,
		0x8C4F14872A8F7B95ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x31B2ED4B99D0E1CDULL,
		0x00FC6DADA609B2D1ULL,
		0x3ACC4CCEFA396AE0ULL,
		0xD83ECB02ADD96592ULL,
		0x2BA30B0D4E10E9B9ULL,
		0x43FC1BD463C22184ULL,
		0x853FE8036C81D9C3ULL,
		0xE98DB47789B78CF6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB06E10A422D2114ULL,
		0x27F022F6A7AD438BULL,
		0xB5A514A67F0E7D63ULL,
		0xDC05B3609D5BABA8ULL,
		0x49D220012F1980C2ULL,
		0x2FA225195E62DE43ULL,
		0xBCF85EFE95DCC69CULL,
		0x3F84284AD694B4FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x46AC0C4157A3C0B9ULL,
		0xD90C4AB6FE5C6F45ULL,
		0x852738287B2AED7CULL,
		0xFC3917A2107DB9E9ULL,
		0xE1D0EB0C1EF768F6ULL,
		0x1459F6BB055F4340ULL,
		0xC8478904D6A51327ULL,
		0xAA098C2CB322D7F7ULL
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
		0x42B0BB5F6BE32DA6ULL,
		0xAC5DC4E02C0AB105ULL,
		0xA60DDD12BA0630A3ULL,
		0x5ADFAE4A58D296A2ULL,
		0x06691809FC653CEBULL,
		0x7A5B43E056276E87ULL,
		0x834298EFA0178073ULL,
		0x2505C5CF48F20FD6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EE73FBCA0865473ULL,
		0x037A3DE8A5DD86D8ULL,
		0x270074FE15155062ULL,
		0x6F792C223A369163ULL,
		0xD1FBB1245486DBA0ULL,
		0x7C22BA6D918150BDULL,
		0x7BA3D21E465ADE75ULL,
		0x12C21FBAF8704561ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x33C97BA2CB5CD933ULL,
		0xA8E386F7862D2A2DULL,
		0x7F0D6814A4F0E041ULL,
		0xEB6682281E9C053FULL,
		0x346D66E5A7DE614AULL,
		0xFE388972C4A61DC9ULL,
		0x079EC6D159BCA1FDULL,
		0x1243A6145081CA75ULL
	}};
	sign = 0;
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
		0x89C1C7DC8507C0A7ULL,
		0xA16BBBCE7CE0E867ULL,
		0x4885B0F19AB5335DULL,
		0x196FB63240526B5CULL,
		0x6401C29C1C94F01BULL,
		0x96EAF8496432C02EULL,
		0x03E542D042C9B6CDULL,
		0x9F95A3C89F8FEDE4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55B62DD02834ED45ULL,
		0x2F830D2E1C059D76ULL,
		0xDC0A0E558F86A8F4ULL,
		0x7B3DECACA0DF55ADULL,
		0x2AC44C279D3B54D3ULL,
		0x28979B7C81735DB1ULL,
		0x7D907FC5F2F5DD85ULL,
		0xD4428925C0B46684ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x340B9A0C5CD2D362ULL,
		0x71E8AEA060DB4AF1ULL,
		0x6C7BA29C0B2E8A69ULL,
		0x9E31C9859F7315AEULL,
		0x393D76747F599B47ULL,
		0x6E535CCCE2BF627DULL,
		0x8654C30A4FD3D948ULL,
		0xCB531AA2DEDB875FULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x9EE6B158D839F15BULL,
		0x43DE5E1E134697F6ULL,
		0x6AAF59865D96C62AULL,
		0x72DC9356C94A83EBULL,
		0xFFE180C96942F494ULL,
		0x5A27F8C89025740AULL,
		0xE963D7E87146DA19ULL,
		0xFB5D6E944794573FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00B8CDE6FB965AA3ULL,
		0x7BB925000F9656D5ULL,
		0x02AFF8BD1D72639DULL,
		0xB7024CE2015C0941ULL,
		0x6A982698BF63B9CBULL,
		0xF56EA27DFBC8CE0EULL,
		0x2F466B65AB8A5BA9ULL,
		0x913F50A78141B106ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9E2DE371DCA396B8ULL,
		0xC825391E03B04121ULL,
		0x67FF60C94024628CULL,
		0xBBDA4674C7EE7AAAULL,
		0x95495A30A9DF3AC8ULL,
		0x64B9564A945CA5FCULL,
		0xBA1D6C82C5BC7E6FULL,
		0x6A1E1DECC652A639ULL
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
		0x55193D1F8D38E1C1ULL,
		0xBA3689E63076E141ULL,
		0x0035714DEDDAF059ULL,
		0xBCA5F2FB8153B44CULL,
		0x1A4414EB704F0F15ULL,
		0x53498C46446F4AA2ULL,
		0xE771D6F515FD132FULL,
		0x319AB7C6F2F38F3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C032F5860849B8DULL,
		0x324F6E1BFA206810ULL,
		0x580C384292BD8DE6ULL,
		0x3DE5B2A028B7101EULL,
		0x09D777A8B1E8789BULL,
		0x62929E7DB3B436B1ULL,
		0xA80359144F9E4DBCULL,
		0x1FE62DC94FF6585FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD9160DC72CB44634ULL,
		0x87E71BCA36567930ULL,
		0xA829390B5B1D6273ULL,
		0x7EC0405B589CA42DULL,
		0x106C9D42BE66967AULL,
		0xF0B6EDC890BB13F1ULL,
		0x3F6E7DE0C65EC572ULL,
		0x11B489FDA2FD36DFULL
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
		0x39517C4A45AA29B9ULL,
		0x007176EF06B3C6B8ULL,
		0xBB61A0D1D7FE33F5ULL,
		0x2E1146548E5C4D1BULL,
		0x571DDD9DBE0A8E7BULL,
		0x22AF229995F63B08ULL,
		0xC99AB70CDBDD4C48ULL,
		0xD4FF3DA2F9AE09A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96BC0EEF51A8E973ULL,
		0xD16330330BE98FF3ULL,
		0xBBC87E355E45F6F9ULL,
		0x7E867C996A679E6FULL,
		0xE4A9CC38FA1DA082ULL,
		0x3C998AA63E7259E4ULL,
		0x95EBEBD60D5D8FBEULL,
		0x1B3AFDA062E8F4BEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA2956D5AF4014046ULL,
		0x2F0E46BBFACA36C4ULL,
		0xFF99229C79B83CFBULL,
		0xAF8AC9BB23F4AEABULL,
		0x72741164C3ECEDF8ULL,
		0xE61597F35783E123ULL,
		0x33AECB36CE7FBC89ULL,
		0xB9C4400296C514EAULL
	}};
	sign = 0;
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
		0x53940018D8CEFD7CULL,
		0xBE810AED29ADE601ULL,
		0xCB9A642F63FF08FDULL,
		0x76E6D3AB3879C2B5ULL,
		0x398B00FA532625E2ULL,
		0x574F7426155759C2ULL,
		0x15BC108359BC45B9ULL,
		0x0D6861B7FCE727DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB881F60E29B7432ULL,
		0xC4C1F912BD99B8F9ULL,
		0xE27E449CC1558CD9ULL,
		0x478D7E7DF4230246ULL,
		0x01C080940F2D7BBAULL,
		0xC57A06878D590C90ULL,
		0xB06DD0A954C7A703ULL,
		0x6E55799A02708045ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA80BE0B7F633894AULL,
		0xF9BF11DA6C142D07ULL,
		0xE91C1F92A2A97C23ULL,
		0x2F59552D4456C06EULL,
		0x37CA806643F8AA28ULL,
		0x91D56D9E87FE4D32ULL,
		0x654E3FDA04F49EB5ULL,
		0x9F12E81DFA76A794ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x54B888FCCF793D4CULL,
		0x4335BBAC511549B5ULL,
		0x24C072847524166DULL,
		0xBF7940DAABEB5811ULL,
		0xECFBBD590749FEC0ULL,
		0xBD5028756F2B071DULL,
		0x85C1D1ECAC40D789ULL,
		0x4EDE2AD0DBA51F67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x292D1809C8C07672ULL,
		0xA8C7162C55115EB7ULL,
		0x6D15154D96E50BB6ULL,
		0x4573C5B3F8F2C3F8ULL,
		0x3B5969867B9A9FBBULL,
		0x395337356D76A9F3ULL,
		0x9C9E9176BF76E48EULL,
		0x563FDA2D3FB9C644ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2B8B70F306B8C6DAULL,
		0x9A6EA57FFC03EAFEULL,
		0xB7AB5D36DE3F0AB6ULL,
		0x7A057B26B2F89418ULL,
		0xB1A253D28BAF5F05ULL,
		0x83FCF14001B45D2AULL,
		0xE9234075ECC9F2FBULL,
		0xF89E50A39BEB5922ULL
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
		0xFF1B93D5F694C369ULL,
		0x1DDCCA7F8DD885ADULL,
		0xE47C92C9A8CA0F45ULL,
		0x88BDBB68F9BA8A6EULL,
		0x59E1B23CB4F19148ULL,
		0xA931EA7AE0D90978ULL,
		0xB61C4ED0598D4DF2ULL,
		0x07B19A9037E5B29BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1256138BB3D14D70ULL,
		0x58FDD5EE5FC0F08DULL,
		0x4E82C5F37E8EB1C7ULL,
		0xCFD4349DA96CD10CULL,
		0xE4E6D5C374D1805FULL,
		0x017C4DB9286F9771ULL,
		0xBCE6FB9237A8B527ULL,
		0x61FB20177D405464ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xECC5804A42C375F9ULL,
		0xC4DEF4912E179520ULL,
		0x95F9CCD62A3B5D7DULL,
		0xB8E986CB504DB962ULL,
		0x74FADC79402010E8ULL,
		0xA7B59CC1B8697206ULL,
		0xF935533E21E498CBULL,
		0xA5B67A78BAA55E36ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x87469EA5920874CCULL,
		0xF39592D4E55FE13DULL,
		0x19707E864A930DDFULL,
		0x48CB2F8E4D8DB180ULL,
		0x320620A4140DC63FULL,
		0xB88A99351338CFF4ULL,
		0x5931C0AAC25A6E0AULL,
		0x9A66F07C443D92D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1AA4A3C6F621F86ULL,
		0xBE5ECC4598175250ULL,
		0x680189D5DCC752DCULL,
		0x48F1E28B666D0971ULL,
		0x8163BFA9104A0ACAULL,
		0x72D2B3F3AC71367DULL,
		0x67FC93FC546E7D04ULL,
		0xED5771BC7C010A9FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC59C546922A65546ULL,
		0x3536C68F4D488EECULL,
		0xB16EF4B06DCBBB03ULL,
		0xFFD94D02E720A80EULL,
		0xB0A260FB03C3BB74ULL,
		0x45B7E54166C79976ULL,
		0xF1352CAE6DEBF106ULL,
		0xAD0F7EBFC83C8834ULL
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
		0xEDBD61C2169B0F91ULL,
		0x7CF1CE74A99D6CB1ULL,
		0xCA0B610544BE7168ULL,
		0xBEAD73E8F7FD6D99ULL,
		0x3DD3703EE6B5479FULL,
		0x9D9367CB0AD6E65CULL,
		0xA627ABACDF3DF87FULL,
		0xAAF8F3940B047A0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCEB8C61216C56D82ULL,
		0x99904B03FD46289CULL,
		0xBF3852BEE7204482ULL,
		0xF1F1C380885C9D5BULL,
		0xE662B3B26FDF6339ULL,
		0xBE3D5A99AF2B8447ULL,
		0x3DAD7D4BE1BF81D0ULL,
		0x47F0B8601E09D226ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1F049BAFFFD5A20FULL,
		0xE3618370AC574415ULL,
		0x0AD30E465D9E2CE5ULL,
		0xCCBBB0686FA0D03EULL,
		0x5770BC8C76D5E465ULL,
		0xDF560D315BAB6214ULL,
		0x687A2E60FD7E76AEULL,
		0x63083B33ECFAA7E6ULL
	}};
	sign = 0;
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
		0x4EED9595A289200AULL,
		0x09B44059093F56C1ULL,
		0x058D1B87A91C1828ULL,
		0x99F7A8934F4736E0ULL,
		0x2822DFFB254A0E49ULL,
		0x706C14A8A6C968B6ULL,
		0xBDDE8B6B4497A3B0ULL,
		0xD2002969BAF7FB37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x323EE5F41F3591BDULL,
		0x55C96906406560A3ULL,
		0xE3CABFBE625FEC8FULL,
		0xC99E345E824EBAA3ULL,
		0x26D0CA6033101C1BULL,
		0xBD22E337FBC1290FULL,
		0xB5EDCAC06983AD26ULL,
		0x25A1A7EF7F118F59ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1CAEAFA183538E4DULL,
		0xB3EAD752C8D9F61EULL,
		0x21C25BC946BC2B98ULL,
		0xD0597434CCF87C3CULL,
		0x0152159AF239F22DULL,
		0xB3493170AB083FA7ULL,
		0x07F0C0AADB13F689ULL,
		0xAC5E817A3BE66BDEULL
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
		0xB4A2C60E79528B5CULL,
		0x8BCAA0D441C789B1ULL,
		0xBE5888BDF50C4AFFULL,
		0xE7AC84BA99FC1AFFULL,
		0xF322C67E4BCD0E6AULL,
		0x30CF515787A025CBULL,
		0x5EC91A32092018AFULL,
		0xCC16EBC609E5B996ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x644D0D1242A943CBULL,
		0xDCBCE3E753ACAADEULL,
		0x0D46CEE6BB5759C5ULL,
		0xE8DFE396C355BB9EULL,
		0xF8B5FEED7BCCBA5DULL,
		0xBAF0E3FE80C8192FULL,
		0x10F046B2BEE96A68ULL,
		0x7435BC8DB2DD4177ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5055B8FC36A94791ULL,
		0xAF0DBCECEE1ADED3ULL,
		0xB111B9D739B4F139ULL,
		0xFECCA123D6A65F61ULL,
		0xFA6CC790D000540CULL,
		0x75DE6D5906D80C9BULL,
		0x4DD8D37F4A36AE46ULL,
		0x57E12F385708781FULL
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
		0xBBB36B555F9A52F3ULL,
		0x713BC6F0999A2D94ULL,
		0x59A4449ACD7068C2ULL,
		0x24064E1B42900F53ULL,
		0x37AEE4B86A3B9A5DULL,
		0x9DA4C84EFE2D7912ULL,
		0x54FB23C754072CDDULL,
		0xC8F1BCF8A4B4411AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC7C8A3868C3AF12ULL,
		0x119387B8837CA26EULL,
		0xA9FE434AFA8A59E3ULL,
		0x7ABD0A33666F79A2ULL,
		0x54F72A69ADE01976ULL,
		0xB951DBC159B84B6FULL,
		0x43BF036304534768ULL,
		0x4BAF1E6A535EC7C3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F36E11CF6D6A3E1ULL,
		0x5FA83F38161D8B26ULL,
		0xAFA6014FD2E60EDFULL,
		0xA94943E7DC2095B0ULL,
		0xE2B7BA4EBC5B80E6ULL,
		0xE452EC8DA4752DA2ULL,
		0x113C20644FB3E574ULL,
		0x7D429E8E51557957ULL
	}};
	sign = 0;
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
		0xEBDC0BB836BF777EULL,
		0x099EB2D20AC537F2ULL,
		0x7010EAEFBFE584C1ULL,
		0x18897445F4019135ULL,
		0x1F092A2FB96DD5E9ULL,
		0xB1D7B7450981B53CULL,
		0xC32C5BD7441915ACULL,
		0x0AFC174275B62C50ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x011E537E1F81ED4DULL,
		0x52EBBB7150B1BEE7ULL,
		0xDA7133526E741C27ULL,
		0xECF92ACDD8072653ULL,
		0xF4E260E475FB6637ULL,
		0x91A0FEB3D957E715ULL,
		0x40B07439F48A954CULL,
		0x9E89B0FFBAFB6494ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEABDB83A173D8A31ULL,
		0xB6B2F760BA13790BULL,
		0x959FB79D51716899ULL,
		0x2B9049781BFA6AE1ULL,
		0x2A26C94B43726FB1ULL,
		0x2036B8913029CE26ULL,
		0x827BE79D4F8E8060ULL,
		0x6C726642BABAC7BCULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xB1D882C39DA1AFACULL,
		0xC480FA61EB35A592ULL,
		0x4A356C9A2EACD3D3ULL,
		0x7FD1D744C681B180ULL,
		0x8B9DE0C8BB945F0CULL,
		0x7AA4B1678C73416AULL,
		0xCDED6B12BEDCEDCCULL,
		0xD9DCD6427F03D7C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33316FAD20EE4EFAULL,
		0x95EFBFD95FBD0080ULL,
		0x1D650535A5DFED28ULL,
		0xE04C53D45B5C3864ULL,
		0x2F9733429ADF4953ULL,
		0xB735C88C60F2156EULL,
		0x061F030C7AB37225ULL,
		0xE99F479C2B5FF3D0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7EA713167CB360B2ULL,
		0x2E913A888B78A512ULL,
		0x2CD0676488CCE6ABULL,
		0x9F8583706B25791CULL,
		0x5C06AD8620B515B8ULL,
		0xC36EE8DB2B812BFCULL,
		0xC7CE680644297BA6ULL,
		0xF03D8EA653A3E3F6ULL
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
		0x1214EE06141BCB09ULL,
		0x3CC79D0F45DBCEAAULL,
		0xE9ECE31A613BEBDFULL,
		0x6508E247ABB04C2FULL,
		0x7A0291EA23824CD9ULL,
		0xC7D085EA03AAF073ULL,
		0x3A9D3EB6D2FAA4B6ULL,
		0x1A830E228090DB5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD047251EAD857722ULL,
		0x4C175B735DCF7D0DULL,
		0x98FAEF17F4C194B2ULL,
		0x179117B36C1FE968ULL,
		0x2593640BE362AFB7ULL,
		0x56C58704F0D9F078ULL,
		0xC2F6F16912A07F6AULL,
		0xC9274E3C2CEF1A9AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x41CDC8E7669653E7ULL,
		0xF0B0419BE80C519CULL,
		0x50F1F4026C7A572CULL,
		0x4D77CA943F9062C7ULL,
		0x546F2DDE401F9D22ULL,
		0x710AFEE512D0FFFBULL,
		0x77A64D4DC05A254CULL,
		0x515BBFE653A1C0C1ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x1552D1E47B8F488CULL,
		0x56860436E3598732ULL,
		0xB01DAF8C817C48A8ULL,
		0x9D99FB98E7AB7CE2ULL,
		0x27C8455F5408A19CULL,
		0x671F4BEC8449C419ULL,
		0x6560A32692AA717EULL,
		0x6D2EBD2B12756B97ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFCA71FD2CE40AD1ULL,
		0x8F2909EE14A008A0ULL,
		0xD25FAC821D43B3D9ULL,
		0x36AC91D947875F86ULL,
		0xE28228AE99206432ULL,
		0x2FCF5E474759B141ULL,
		0x4AE109BEF03B5831ULL,
		0x16DD737504B82C17ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x55885FE74EAB3DBBULL,
		0xC75CFA48CEB97E91ULL,
		0xDDBE030A643894CEULL,
		0x66ED69BFA0241D5BULL,
		0x45461CB0BAE83D6AULL,
		0x374FEDA53CF012D7ULL,
		0x1A7F9967A26F194DULL,
		0x565149B60DBD3F80ULL
	}};
	sign = 0;
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
		0x2DF3923875C6347FULL,
		0x29369C4C43497A04ULL,
		0xBD5F2512C038534BULL,
		0xEB8E24644277C852ULL,
		0x63994B770DF5A782ULL,
		0x2520B08D548865D6ULL,
		0xEF72C95BA184B963ULL,
		0xAD5D82DC533D141EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1D0442634200C63ULL,
		0x97F204A8A278145CULL,
		0xB5A5838E9DC93016ULL,
		0xBFC012D2A4A72A14ULL,
		0xE8DC5F9E9E2EDE32ULL,
		0x1510A33566473829ULL,
		0x2A976E6EE42D8A2CULL,
		0xE4507E43177E0FD1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4C234E1241A6281CULL,
		0x914497A3A0D165A7ULL,
		0x07B9A184226F2334ULL,
		0x2BCE11919DD09E3EULL,
		0x7ABCEBD86FC6C950ULL,
		0x10100D57EE412DACULL,
		0xC4DB5AECBD572F37ULL,
		0xC90D04993BBF044DULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xF5035962C70D1FADULL,
		0x728E8BA6DA68F6FEULL,
		0xF9643E3EF6749349ULL,
		0x9219443323BF958FULL,
		0x7FF6D6C8A539B727ULL,
		0x3CD2F733AB0262FDULL,
		0xEB614C219A5D2C86ULL,
		0x4A43F2A2D06A83BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1972EE3C66EF001ULL,
		0xA4ECC9EDCE996C65ULL,
		0xE2FCCDB1332604B6ULL,
		0xC67816D00908C94CULL,
		0x4133DABDE6362D88ULL,
		0x03DC5DE8C6EC5006ULL,
		0x614A278B7B06BEEEULL,
		0xA19AB0BB7086C620ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x436C2A7F009E2FACULL,
		0xCDA1C1B90BCF8A99ULL,
		0x1667708DC34E8E92ULL,
		0xCBA12D631AB6CC43ULL,
		0x3EC2FC0ABF03899EULL,
		0x38F6994AE41612F7ULL,
		0x8A1724961F566D98ULL,
		0xA8A941E75FE3BD9CULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x8B863758F03696EFULL,
		0x972AACC6DF87C364ULL,
		0xA37F0D9BE89567F2ULL,
		0x47481B872A96FF22ULL,
		0x537F3B056BD06C7DULL,
		0xEA1A462918EE9F50ULL,
		0xC18497DC59FAB7CDULL,
		0xEAA41813F8068A33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB4A2A267E7AF517ULL,
		0x0B9D651DEC881FDDULL,
		0xADC0CC0AB06E7334ULL,
		0xE9CCA04BFD7B7DBCULL,
		0x0C384A7909ACA357ULL,
		0x439B3E1A2E4FEC34ULL,
		0xABACD4D6353E968DULL,
		0xBE519608AA9018F6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x903C0D3271BBA1D8ULL,
		0x8B8D47A8F2FFA386ULL,
		0xF5BE41913826F4BEULL,
		0x5D7B7B3B2D1B8165ULL,
		0x4746F08C6223C925ULL,
		0xA67F080EEA9EB31CULL,
		0x15D7C30624BC2140ULL,
		0x2C52820B4D76713DULL
	}};
	sign = 0;
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
		0x6CFB563DE4C840B5ULL,
		0xF7E3513337DD526DULL,
		0x2E0508B5FC9CA83EULL,
		0x6BA303999F17718EULL,
		0xBDFC2C64DF9E8268ULL,
		0x2792CD677EB69371ULL,
		0x692938A16F1FEDD1ULL,
		0xDBCC6E63CE7CE5AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6AAB25F8FCCDCFF9ULL,
		0x9378EDC278DCA700ULL,
		0xD202F3EF88D7412DULL,
		0x1A4B37378CEC6C84ULL,
		0xE17BD9540C7E8E1FULL,
		0x87EAB44C1E52245EULL,
		0x407B059D7310C84CULL,
		0x54A09EE2A6CCCD77ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x02503044E7FA70BCULL,
		0x646A6370BF00AB6DULL,
		0x5C0214C673C56711ULL,
		0x5157CC62122B0509ULL,
		0xDC805310D31FF449ULL,
		0x9FA8191B60646F12ULL,
		0x28AE3303FC0F2584ULL,
		0x872BCF8127B01833ULL
	}};
	sign = 0;
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
		0x3A8EB472CB539296ULL,
		0x78D5B63B6E2EEB78ULL,
		0x3E239FD3FC02F8DEULL,
		0x0F84271790E1FBC1ULL,
		0x368B6A34CC324BD0ULL,
		0x90453C2D39B1AF79ULL,
		0x6C115A66BF65D5E6ULL,
		0x507A95C635A504B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8759C983B581F370ULL,
		0x8A53A87B6189C763ULL,
		0x2C0BDDB848786CE0ULL,
		0xBA6A79EEC083B532ULL,
		0xFE994C9DA33C4C32ULL,
		0x145BCC9F19FDAAD8ULL,
		0xB7CBE204DC37403BULL,
		0x12A94B8047D36C54ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB334EAEF15D19F26ULL,
		0xEE820DC00CA52414ULL,
		0x1217C21BB38A8BFDULL,
		0x5519AD28D05E468FULL,
		0x37F21D9728F5FF9DULL,
		0x7BE96F8E1FB404A0ULL,
		0xB4457861E32E95ABULL,
		0x3DD14A45EDD1985FULL
	}};
	sign = 0;
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
		0x9B00B95FAC413F7FULL,
		0xF48D0445A238B102ULL,
		0xB13AB2993323CA89ULL,
		0xEE7E27C71D96ED4AULL,
		0xC359136BEE782429ULL,
		0xB918F753A95CD741ULL,
		0x41F0A887B00CBE33ULL,
		0x5737E5427770FEFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B14D613500F847EULL,
		0x011C851A5BFFE041ULL,
		0xB65D5CACE345C17EULL,
		0x43B0A424BA03FC9FULL,
		0xFB9E2D14F103359DULL,
		0x8C0FFE0DC3B51EB9ULL,
		0xA3785DD1C29E1755ULL,
		0x2E6C8DC6F59A9A03ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5FEBE34C5C31BB01ULL,
		0xF3707F2B4638D0C1ULL,
		0xFADD55EC4FDE090BULL,
		0xAACD83A26392F0AAULL,
		0xC7BAE656FD74EE8CULL,
		0x2D08F945E5A7B887ULL,
		0x9E784AB5ED6EA6DEULL,
		0x28CB577B81D664FBULL
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
		0xEE4CF0373D7B42A6ULL,
		0xD5E3C7F38EA0CE99ULL,
		0x71D40248BF46DC01ULL,
		0xF92FB1C5ED72A067ULL,
		0x09E18A17BADC97DBULL,
		0xEC09947137548607ULL,
		0x2BC777E20B54B2F2ULL,
		0x990EAE773462462BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6399D1664E02C038ULL,
		0x6B4CCDF745FDC5EFULL,
		0x723AD2090CDF6F35ULL,
		0x71C2A445B307D40DULL,
		0x2974A309DE308A7DULL,
		0xA9B1D889D7A2E54AULL,
		0x0E6EE82DABAF20D0ULL,
		0x66C967414417C5BFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8AB31ED0EF78826EULL,
		0x6A96F9FC48A308AAULL,
		0xFF99303FB2676CCCULL,
		0x876D0D803A6ACC59ULL,
		0xE06CE70DDCAC0D5EULL,
		0x4257BBE75FB1A0BCULL,
		0x1D588FB45FA59222ULL,
		0x32454735F04A806CULL
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
		0x8DE97DCE592A9DA5ULL,
		0x4643456361BCD458ULL,
		0x7BAF8BC696F15012ULL,
		0x3D0582466EE1F025ULL,
		0x2C4D31A97577A911ULL,
		0x82515A5FFD4D565DULL,
		0xEACF3D4543785850ULL,
		0x5897460924D9418DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C06202C589DF39EULL,
		0xEA886601A99BB542ULL,
		0x6E1EC9D009A5451FULL,
		0x6615ABFD6A7F5842ULL,
		0x7EFBB708F9D633DEULL,
		0xE30A48599D4D2282ULL,
		0x90DE913E66ACDABDULL,
		0xD0CF045E380A550CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x21E35DA2008CAA07ULL,
		0x5BBADF61B8211F16ULL,
		0x0D90C1F68D4C0AF2ULL,
		0xD6EFD649046297E3ULL,
		0xAD517AA07BA17532ULL,
		0x9F471206600033DAULL,
		0x59F0AC06DCCB7D92ULL,
		0x87C841AAECCEEC81ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x7EFF9BBEF9BCF5ACULL,
		0x522B10EBC54A9A94ULL,
		0xF82DE501B2618332ULL,
		0x25EC27D7FC2F7A41ULL,
		0xBCF78177779564F0ULL,
		0xAA29B4332997F035ULL,
		0xDFA9FEB20111CEE1ULL,
		0x46086D1347B9792EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16C660EF7A6B520AULL,
		0xE468615B89EB6FB8ULL,
		0x760B36BDA647AE84ULL,
		0x1BFCB589104B1246ULL,
		0xDFE5B21548701DE1ULL,
		0x2808640B6AC8562CULL,
		0x9245B06BDED6200AULL,
		0x2DA94CAD6CFFF61AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x68393ACF7F51A3A2ULL,
		0x6DC2AF903B5F2ADCULL,
		0x8222AE440C19D4ADULL,
		0x09EF724EEBE467FBULL,
		0xDD11CF622F25470FULL,
		0x82215027BECF9A08ULL,
		0x4D644E46223BAED7ULL,
		0x185F2065DAB98314ULL
	}};
	sign = 0;
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
		0x89EFD40A7C9CB95FULL,
		0xDC88FE4ED6F9C364ULL,
		0xEEE2159686916650ULL,
		0x86729CECD2DD9B45ULL,
		0x54FC906F60580FB3ULL,
		0xE4128BAD54E42ED5ULL,
		0xA7783CE0A413BCFFULL,
		0xA1BBC7BB21CFFB8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8539079873FF498BULL,
		0x9CC2A2C2077805E0ULL,
		0x98FD58C0D7BCD439ULL,
		0xBD39B35BA7B0F375ULL,
		0x82C97E3E6F8EEAF2ULL,
		0xBDC3B28D6D296CE9ULL,
		0x01D760E398ECFE6EULL,
		0x54FF5F3F94FB4E35ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04B6CC72089D6FD4ULL,
		0x3FC65B8CCF81BD84ULL,
		0x55E4BCD5AED49217ULL,
		0xC938E9912B2CA7D0ULL,
		0xD2331230F0C924C0ULL,
		0x264ED91FE7BAC1EBULL,
		0xA5A0DBFD0B26BE91ULL,
		0x4CBC687B8CD4AD58ULL
	}};
	sign = 0;
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
		0x605D24BB68DD7F4CULL,
		0x25BBEB9251A4CD14ULL,
		0x7F939D5C69C1DDD3ULL,
		0x8411D5211496E713ULL,
		0xF4C2FD4EB327B049ULL,
		0x2AD62755A9E9B931ULL,
		0xE109DC0449C8A6B5ULL,
		0x3B42C1617F62AA66ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77293F4A582D365AULL,
		0x335A0F61AE388846ULL,
		0x4B526252C8EAD0CCULL,
		0x34E4C2BFE535D6C6ULL,
		0xCD91808F8192D859ULL,
		0xC163625F5264CE3EULL,
		0x4408A7E57F35F97DULL,
		0xA5FB3F1069DF28BAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE933E57110B048F2ULL,
		0xF261DC30A36C44CDULL,
		0x34413B09A0D70D06ULL,
		0x4F2D12612F61104DULL,
		0x27317CBF3194D7F0ULL,
		0x6972C4F65784EAF3ULL,
		0x9D01341ECA92AD37ULL,
		0x95478251158381ACULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xC1D58E92CDE6DB18ULL,
		0xA916B4F87E4B9131ULL,
		0xD36874DCF2831ADBULL,
		0x0206217A386F86C7ULL,
		0xC154CC15551C16A4ULL,
		0x5555A90FFD89E8BEULL,
		0x76D473AF6990CD7AULL,
		0x37F75F197D54BA5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6997FD9676329E5ULL,
		0x3E880518BBA5C2DCULL,
		0xAFB9901546A511FFULL,
		0xDFE32FD6CD47275FULL,
		0xA9EF101414303C93ULL,
		0xAEACC48EB352D237ULL,
		0xA5DB7DBED0A47A09ULL,
		0xA58C13C5A35DC54BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEB3C0EB96683B133ULL,
		0x6A8EAFDFC2A5CE54ULL,
		0x23AEE4C7ABDE08DCULL,
		0x2222F1A36B285F68ULL,
		0x1765BC0140EBDA10ULL,
		0xA6A8E4814A371687ULL,
		0xD0F8F5F098EC5370ULL,
		0x926B4B53D9F6F511ULL
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
		0x294EF81C87052CA0ULL,
		0x1714AAC6692A1A13ULL,
		0x9335B3E74F153BABULL,
		0x6FB8850104ED6FEAULL,
		0xCA179B6590E1F77AULL,
		0x1DFF5C9E0E35E0DEULL,
		0xFAC6953CC297A208ULL,
		0x757A233A4E682E08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0991BFC94878B53BULL,
		0x78477BD2C2F0EC29ULL,
		0x85C82914E7E1555CULL,
		0xC43CAFED78ABB0C9ULL,
		0x75E1FBACCC987424ULL,
		0x8AC5F76639E8B22BULL,
		0x2806AE10834BB166ULL,
		0xC220C04227BA571DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1FBD38533E8C7765ULL,
		0x9ECD2EF3A6392DEAULL,
		0x0D6D8AD26733E64EULL,
		0xAB7BD5138C41BF21ULL,
		0x54359FB8C4498355ULL,
		0x93396537D44D2EB3ULL,
		0xD2BFE72C3F4BF0A1ULL,
		0xB35962F826ADD6EBULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xCBC40149CD894E10ULL,
		0x7C7779A001972502ULL,
		0xDB219AE11E970BEEULL,
		0xBFABC1954D271BD7ULL,
		0xC568A91758B91CF9ULL,
		0x68FC29703F51DBA5ULL,
		0x5DD151A857D4F7CEULL,
		0xFACA51581D0DABFAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x048C23B9F0FAA877ULL,
		0xE23668A2B69D3849ULL,
		0x3FAE307241CDE2A6ULL,
		0x6A1FFC897AA4E365ULL,
		0x0C180452C06CAE47ULL,
		0xF954425E833E6F48ULL,
		0x72134811DBB5AC30ULL,
		0x8A6C2C19FBFF65F2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC737DD8FDC8EA599ULL,
		0x9A4110FD4AF9ECB9ULL,
		0x9B736A6EDCC92947ULL,
		0x558BC50BD2823872ULL,
		0xB950A4C4984C6EB2ULL,
		0x6FA7E711BC136C5DULL,
		0xEBBE09967C1F4B9DULL,
		0x705E253E210E4607ULL
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
		0xA1FE8E9FE9507BA2ULL,
		0x138AA5CC7E00EE5EULL,
		0x03FBACE57F9D6A48ULL,
		0x634616A880B6D04EULL,
		0x2A0D4D99F062AC1CULL,
		0x566F77BE0D07B867ULL,
		0x689E6080B5541728ULL,
		0xE2A7E2A43BCC11B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97E2143A56AAFCC0ULL,
		0x74DD658820C598C2ULL,
		0xC9232A1E4FA01D7CULL,
		0x647C8AC0CA5F0939ULL,
		0x1155E1844527C377ULL,
		0xA662CDDD12A4A882ULL,
		0x575009DEAFBDD12CULL,
		0xD0B2B06270F64F8DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A1C7A6592A57EE2ULL,
		0x9EAD40445D3B559CULL,
		0x3AD882C72FFD4CCBULL,
		0xFEC98BE7B657C714ULL,
		0x18B76C15AB3AE8A4ULL,
		0xB00CA9E0FA630FE5ULL,
		0x114E56A2059645FBULL,
		0x11F53241CAD5C224ULL
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
		0x442FD2543B9982BCULL,
		0xC8E66F531D04568BULL,
		0xB8F119A6FE103716ULL,
		0xC14F523743D76E93ULL,
		0x65F912F422D91916ULL,
		0x46BE03CDFBC67A9EULL,
		0x191205D79706B604ULL,
		0xE6678B5DA7C3E400ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71839EC19A1E86B8ULL,
		0xDCBFE2231F4A2E59ULL,
		0xBED4992DAF9E2D0CULL,
		0x7C20DC0D80F22DC7ULL,
		0x31AE9491773B2C0EULL,
		0x019B7007F1B90E80ULL,
		0x8411CD0D7DF33F57ULL,
		0x259237843FC4E30FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD2AC3392A17AFC04ULL,
		0xEC268D2FFDBA2831ULL,
		0xFA1C80794E720A09ULL,
		0x452E7629C2E540CBULL,
		0x344A7E62AB9DED08ULL,
		0x452293C60A0D6C1EULL,
		0x950038CA191376ADULL,
		0xC0D553D967FF00F0ULL
	}};
	sign = 0;
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
		0xAE72D655DCD1335BULL,
		0x2FD2C2D1E21EF865ULL,
		0x733E76BC0DA6067FULL,
		0xA27177C53C0FC71FULL,
		0xAF59E9CD96AB8523ULL,
		0xE061B7437C6B0E8EULL,
		0x49438429D03E735CULL,
		0x73D07C6DFEF4E6B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF92A77DBB09B6302ULL,
		0x0708F1C3FED1C581ULL,
		0xA610E5AA7C64A304ULL,
		0x6E4E9AF188BBBACDULL,
		0x5BC3B59B33CD6F92ULL,
		0xFE84934D7538A73CULL,
		0x39C4491811A21BD9ULL,
		0x29B434511A08C625ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB5485E7A2C35D059ULL,
		0x28C9D10DE34D32E3ULL,
		0xCD2D91119141637BULL,
		0x3422DCD3B3540C51ULL,
		0x5396343262DE1591ULL,
		0xE1DD23F607326752ULL,
		0x0F7F3B11BE9C5782ULL,
		0x4A1C481CE4EC208EULL
	}};
	sign = 0;
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
		0xEFEB77CF14D87919ULL,
		0xF2D78E2162456209ULL,
		0x7264DE7D0A71734FULL,
		0xAE92F7BCA3EEAE24ULL,
		0x1B21B6D70E2CC1E9ULL,
		0xFC5BC0DB5034B781ULL,
		0xEE32E0CDA12569B2ULL,
		0x9126564985703BC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x199FFC7E9AC6623FULL,
		0x822CBD52C95BEC31ULL,
		0xBF90AF8D936AC7E3ULL,
		0xF630046FF8F52148ULL,
		0xEF7CA8582626B373ULL,
		0x03D0658474FE587FULL,
		0xDE8D19F1E15CE2BDULL,
		0xB7BD55BE9DD0D1B2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD64B7B507A1216DAULL,
		0x70AAD0CE98E975D8ULL,
		0xB2D42EEF7706AB6CULL,
		0xB862F34CAAF98CDBULL,
		0x2BA50E7EE8060E75ULL,
		0xF88B5B56DB365F01ULL,
		0x0FA5C6DBBFC886F5ULL,
		0xD969008AE79F6A16ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x04EF9B495AF2491CULL,
		0x2443807961B062F0ULL,
		0xE03AA313979D429DULL,
		0xFACB2ABE141CF218ULL,
		0x4E786CE5736293A9ULL,
		0xBF26614BD0F60495ULL,
		0xB6C1EFB51BAAEF40ULL,
		0xB401BDA0A34117F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x517CC2EC2EF123FEULL,
		0xF5AA24ECE95925B9ULL,
		0x3FE8014BFCD7F44FULL,
		0x8D6389887C03C645ULL,
		0x240B8F496C668FF4ULL,
		0xCD5F806B443B5DBCULL,
		0x973A2C284D30699CULL,
		0xACEE1DEF999B8273ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB372D85D2C01251EULL,
		0x2E995B8C78573D36ULL,
		0xA052A1C79AC54E4DULL,
		0x6D67A13598192BD3ULL,
		0x2A6CDD9C06FC03B5ULL,
		0xF1C6E0E08CBAA6D9ULL,
		0x1F87C38CCE7A85A3ULL,
		0x07139FB109A5957DULL
	}};
	sign = 0;
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
		0x5D379C1540629F5EULL,
		0x7CBB1D02158C769EULL,
		0x10229AA26849D45EULL,
		0x5AD90365BABB065DULL,
		0xD19B5A7561B586C0ULL,
		0x89A6BBBD49F24B49ULL,
		0xE67FA010982C43E8ULL,
		0xC5B7F6C747F9C1FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC034583DD39402CAULL,
		0x64FA2BB098CEA65EULL,
		0x3C102E36F732E14AULL,
		0x1BC170A2E3F486F4ULL,
		0x685564C51630E062ULL,
		0xFF3A70CDDF3871C7ULL,
		0x8D5A0B2F221E4399ULL,
		0x0C943FADF3297D18ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9D0343D76CCE9C94ULL,
		0x17C0F1517CBDD03FULL,
		0xD4126C6B7116F314ULL,
		0x3F1792C2D6C67F68ULL,
		0x6945F5B04B84A65EULL,
		0x8A6C4AEF6AB9D982ULL,
		0x592594E1760E004EULL,
		0xB923B71954D044E6ULL
	}};
	sign = 0;
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
		0xCD63960399B0A8D4ULL,
		0x47F36B75C1CB505BULL,
		0xC9C62E8139CA2630ULL,
		0xC289D93C1AD53619ULL,
		0x56B0E1EEA9E8298EULL,
		0x7B41711DCF8867ACULL,
		0xA72DF93D10DB3EDEULL,
		0x0F8EBA2674997802ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC29F30657D80E32DULL,
		0xF7481EB818A39649ULL,
		0xF7776BCAE76F22B2ULL,
		0xD96B33FBE507D474ULL,
		0xBFAADB785E6DF491ULL,
		0xE7CBD3AF810A4EC6ULL,
		0x05D27CA0D40B4023ULL,
		0xC846AC816E1E4E5CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0AC4659E1C2FC5A7ULL,
		0x50AB4CBDA927BA12ULL,
		0xD24EC2B6525B037DULL,
		0xE91EA54035CD61A4ULL,
		0x970606764B7A34FCULL,
		0x93759D6E4E7E18E5ULL,
		0xA15B7C9C3CCFFEBAULL,
		0x47480DA5067B29A6ULL
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
		0x4F5E62B2C5BE1070ULL,
		0x791C664E4D5F583EULL,
		0x32680C0A82666837ULL,
		0xF180B7C43D68391AULL,
		0x636A406E546B9570ULL,
		0xB98712FB3F789FA1ULL,
		0xE3EECE9D780612B7ULL,
		0x1F9D506BA2B2C6EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F96E3A59BF91AC5ULL,
		0xF008FB0AF10E3681ULL,
		0x5A5FBD674B4335F9ULL,
		0xDBEFD622B4F1B0A0ULL,
		0x8345FA43FFF5118FULL,
		0x7D89040CE11D4946ULL,
		0x214BF2E00D9AF829ULL,
		0x8A1AAD41F1DB30A7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2FC77F0D29C4F5ABULL,
		0x89136B435C5121BDULL,
		0xD8084EA33723323DULL,
		0x1590E1A188768879ULL,
		0xE024462A547683E1ULL,
		0x3BFE0EEE5E5B565AULL,
		0xC2A2DBBD6A6B1A8EULL,
		0x9582A329B0D79647ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x51DF4878664032E0ULL,
		0x3EF210F8498F8C19ULL,
		0xBF59E7ED0D2C3A60ULL,
		0x10E31134A926363FULL,
		0x93B635D105A26F89ULL,
		0xC0941CE4B235E497ULL,
		0x6EC25276A9087396ULL,
		0x5811F8C2CB164C20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35D4DE81B23A3C15ULL,
		0xF8F3648649640638ULL,
		0x74967A02078C4FD8ULL,
		0xFC9022C8C6F8144AULL,
		0xE03646989476F6C8ULL,
		0x1F41C89BEF399A4AULL,
		0x13A2705C1052155BULL,
		0x13DDEC3904C4AC51ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1C0A69F6B405F6CBULL,
		0x45FEAC72002B85E1ULL,
		0x4AC36DEB059FEA87ULL,
		0x1452EE6BE22E21F5ULL,
		0xB37FEF38712B78C0ULL,
		0xA1525448C2FC4A4CULL,
		0x5B1FE21A98B65E3BULL,
		0x44340C89C6519FCFULL
	}};
	sign = 0;
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
		0x014208BCA815D86CULL,
		0x88B906844C190C68ULL,
		0xD7179F3846052376ULL,
		0x793B1DD872C9D14CULL,
		0x12DEADCE12E40B86ULL,
		0x56BC2A2B85515956ULL,
		0xFC046DF7551BC815ULL,
		0x1FE05543F66B87A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8378FBAB81D241FULL,
		0xDBC8BAF0D2D981A8ULL,
		0x0CBF4AA651587463ULL,
		0x5EDAA2C52F280179ULL,
		0x84C1D9506F27D4E5ULL,
		0xDD875196F16B3C26ULL,
		0x2A5AB403539B4FBCULL,
		0x60CB39C23F2D97CBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x390A7901EFF8B44DULL,
		0xACF04B93793F8ABFULL,
		0xCA585491F4ACAF12ULL,
		0x1A607B1343A1CFD3ULL,
		0x8E1CD47DA3BC36A1ULL,
		0x7934D89493E61D2FULL,
		0xD1A9B9F401807858ULL,
		0xBF151B81B73DEFD9ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xDFE6789E85D0723EULL,
		0x9E148C1CA25ECA1CULL,
		0x60E0E4A946B54F0CULL,
		0x99DA789B79E80F1DULL,
		0xA35B719A0EF3C14CULL,
		0xDBE2028112257C15ULL,
		0x74E8BD2FC59CCE4AULL,
		0xEE5CC99B3BC2CB61ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA47F1E4DE96A3E5DULL,
		0xE1687AFDB7B44F97ULL,
		0x9C73A5AC605A6DEDULL,
		0x0539A06C2E958C50ULL,
		0x862405F74F869A5FULL,
		0x7F0CE021199B364FULL,
		0xA5267558CDC2E04AULL,
		0x7F71E501E292A453ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3B675A509C6633E1ULL,
		0xBCAC111EEAAA7A85ULL,
		0xC46D3EFCE65AE11EULL,
		0x94A0D82F4B5282CCULL,
		0x1D376BA2BF6D26EDULL,
		0x5CD5225FF88A45C6ULL,
		0xCFC247D6F7D9EE00ULL,
		0x6EEAE4995930270DULL
	}};
	sign = 0;
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
		0xE8EA1A238F48546BULL,
		0x160BEF3525999390ULL,
		0x57CB76E8F38D72CCULL,
		0x6B2C7956A8141C41ULL,
		0x0D56A329A419E722ULL,
		0x1F4E3292B7A043AAULL,
		0xF015F316B68D099FULL,
		0x812EC654742D25E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD93F13B70B731942ULL,
		0x44D6349FFBBF8283ULL,
		0xD389DF19841E00A3ULL,
		0xD692FB683AEEB17AULL,
		0x776020BD1FF421F2ULL,
		0x30BDE911581117ADULL,
		0x4153C0F623B981A5ULL,
		0xB322868D39E82115ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0FAB066C83D53B29ULL,
		0xD135BA9529DA110DULL,
		0x844197CF6F6F7228ULL,
		0x94997DEE6D256AC6ULL,
		0x95F6826C8425C52FULL,
		0xEE9049815F8F2BFCULL,
		0xAEC2322092D387F9ULL,
		0xCE0C3FC73A4504D2ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x6861704545F49C5BULL,
		0x48DF2BF0C4E6F036ULL,
		0x8F849D7A9D661FCBULL,
		0xCEC82A0FE5729F63ULL,
		0x6F35A6A6F2BFA3AFULL,
		0x73B42B9DCA18C767ULL,
		0x97A26F49D6F496BCULL,
		0x76EDB126EFBC0182ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x254892894F33DD50ULL,
		0x218DED1BC6F595E7ULL,
		0xD1A9048921CD16DCULL,
		0xA5BFEB865A0B834FULL,
		0x3609468C99DF63D1ULL,
		0x9F7012BCCC9BE8D1ULL,
		0xDB22D85C36CF8D18ULL,
		0xA04CDD91C7E0DFEDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4318DDBBF6C0BF0BULL,
		0x27513ED4FDF15A4FULL,
		0xBDDB98F17B9908EFULL,
		0x29083E898B671C13ULL,
		0x392C601A58E03FDEULL,
		0xD44418E0FD7CDE96ULL,
		0xBC7F96EDA02509A3ULL,
		0xD6A0D39527DB2194ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xBAD83CBFD6C2691FULL,
		0xA43F598CC43DFE5FULL,
		0x96DE24F99B160A3CULL,
		0x26CB6FE5B2D59300ULL,
		0x43C023BD87F3119EULL,
		0xEFC31C0FB8F0FB2FULL,
		0x19C1EB706667D71FULL,
		0xFCC8E5B241B7DED6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F78B7D00FEA314CULL,
		0xF075AA4C5094C2D9ULL,
		0x1C64655D316C74D5ULL,
		0xE4AAFB895612DDF1ULL,
		0xDFE5E6ADFCEEAE89ULL,
		0xA369F08B62E60B4DULL,
		0x25F4E39992D7B5C2ULL,
		0xC60F13A331660945ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2B5F84EFC6D837D3ULL,
		0xB3C9AF4073A93B86ULL,
		0x7A79BF9C69A99566ULL,
		0x4220745C5CC2B50FULL,
		0x63DA3D0F8B046314ULL,
		0x4C592B84560AEFE1ULL,
		0xF3CD07D6D390215DULL,
		0x36B9D20F1051D590ULL
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
		0xEF9E6D14D2FBFB0CULL,
		0xE528BE9F09EF55C2ULL,
		0x61681850DE8CBE99ULL,
		0xCE71218CBB1087BFULL,
		0x62F4F87BF38B8784ULL,
		0xE77A2AE23F8E9303ULL,
		0x1F33DD28241CA74EULL,
		0xC46C7291812AEEF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A82070FE2B509B3ULL,
		0x8A0315083775B2AEULL,
		0x44A165DA362CF75CULL,
		0xA3D998040097C595ULL,
		0xC52F1D68379265F5ULL,
		0xD2388CC17066ADD4ULL,
		0xC537C4339B2B6E0EULL,
		0xA767F06536546118ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x551C6604F046F159ULL,
		0x5B25A996D279A314ULL,
		0x1CC6B276A85FC73DULL,
		0x2A978988BA78C22AULL,
		0x9DC5DB13BBF9218FULL,
		0x15419E20CF27E52EULL,
		0x59FC18F488F13940ULL,
		0x1D04822C4AD68DDAULL
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
		0xDFBDE1E88935AB5DULL,
		0x964CDEC1A8AF9B95ULL,
		0x20DE2A084CD6ED85ULL,
		0xFFD0CF5E2751FDDAULL,
		0x75C2F2179089B716ULL,
		0x396CEC99A085AE93ULL,
		0xAC15E313C8B0B6DBULL,
		0x3B2A99632C7182DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CE37823AB48010BULL,
		0xCE1D5D44F7DECA06ULL,
		0x5ADA7E4CE516D2A4ULL,
		0x8885825A18455AB0ULL,
		0xEF74A74CB99DE1B6ULL,
		0x0A444FAEB5DE8B22ULL,
		0xFB5DA80C82CBBD84ULL,
		0xC3CF509DF776D90EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x82DA69C4DDEDAA52ULL,
		0xC82F817CB0D0D18FULL,
		0xC603ABBB67C01AE0ULL,
		0x774B4D040F0CA329ULL,
		0x864E4ACAD6EBD560ULL,
		0x2F289CEAEAA72370ULL,
		0xB0B83B0745E4F957ULL,
		0x775B48C534FAA9CEULL
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
		0x1A5F5F5A4C99039BULL,
		0x9AAD98395202651CULL,
		0x2D467673BA0A3FADULL,
		0x586375B15C1FE0A7ULL,
		0x4FA8BA8784970AEDULL,
		0x9AED23951B4B8D87ULL,
		0x0B88278F629BF36CULL,
		0x0FDD479D211F703DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C8C668CD8A5A26CULL,
		0xFE1F4F2B227BCD72ULL,
		0x39EE9F42194D4F2EULL,
		0x02BE39ABAE27EBB6ULL,
		0x80766109AE2F0C22ULL,
		0x6E92FA87E116479BULL,
		0xC97EF5EEF4F5F6D0ULL,
		0xFBBFD0EB5BDDE072ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCDD2F8CD73F3612FULL,
		0x9C8E490E2F8697A9ULL,
		0xF357D731A0BCF07EULL,
		0x55A53C05ADF7F4F0ULL,
		0xCF32597DD667FECBULL,
		0x2C5A290D3A3545EBULL,
		0x420931A06DA5FC9CULL,
		0x141D76B1C5418FCAULL
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
		0xFED07CEE5F5131BEULL,
		0xA9CFEC92EDF13351ULL,
		0xACA3976DC2E32BABULL,
		0x4A55C07225262747ULL,
		0xF59B4BB09953AB7BULL,
		0x0A2C3A2236AF4D94ULL,
		0x04133F1FE816F92DULL,
		0xAC042ADC575F157DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78543AA124AEE1D9ULL,
		0x73344034CDACF626ULL,
		0x65FCD82D8D8D9724ULL,
		0xBCCD36A0B268EDC3ULL,
		0x607CCFCA8FE20DB8ULL,
		0xBE446639F57469CFULL,
		0xEB46A5F856C42549ULL,
		0xD5C7DC99D23ACD5EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x867C424D3AA24FE5ULL,
		0x369BAC5E20443D2BULL,
		0x46A6BF4035559487ULL,
		0x8D8889D172BD3984ULL,
		0x951E7BE609719DC2ULL,
		0x4BE7D3E8413AE3C5ULL,
		0x18CC99279152D3E3ULL,
		0xD63C4E428524481EULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x16F5F240277A1710ULL,
		0x9D041AE3CC3DFEBAULL,
		0xF291BCAA7345217BULL,
		0x679134CAEE4FA6D5ULL,
		0xDD41BE353F36AABDULL,
		0x01296BB4298C039CULL,
		0x971CAD75AC7E2862ULL,
		0xDB8025AC0381A80DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29A00CBE3BCBB43DULL,
		0xCDEA9E019D3FAA07ULL,
		0xCAD32F17BE9DF40BULL,
		0x8BBA46A80DECEC2EULL,
		0x2F6A6263D7997632ULL,
		0xB87255CE52B5B206ULL,
		0x770E133F02ADABA0ULL,
		0x467CE2B043AD6FE9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xED55E581EBAE62D3ULL,
		0xCF197CE22EFE54B2ULL,
		0x27BE8D92B4A72D6FULL,
		0xDBD6EE22E062BAA7ULL,
		0xADD75BD1679D348AULL,
		0x48B715E5D6D65196ULL,
		0x200E9A36A9D07CC1ULL,
		0x950342FBBFD43824ULL
	}};
	sign = 0;
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
		0x624011C1A1F6185BULL,
		0x0C90B761A86F54C0ULL,
		0x1ABFC8463687E939ULL,
		0xA27F4A236321D388ULL,
		0x3C811A55E585D150ULL,
		0x7CFD8D58C3B7E2DCULL,
		0xACFBC750568907C3ULL,
		0x5A31E8F68A67E761ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B6EE090C6CD1062ULL,
		0xDE840A2A92C1913AULL,
		0xE9D90B9442DCACE8ULL,
		0xB5CAAF9677271684ULL,
		0xCAFCE628F0F3EBD2ULL,
		0xEAFD8A2E07095B79ULL,
		0xAD37AF9BF622975CULL,
		0x97F75C2A7988E744ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x56D13130DB2907F9ULL,
		0x2E0CAD3715ADC386ULL,
		0x30E6BCB1F3AB3C50ULL,
		0xECB49A8CEBFABD03ULL,
		0x7184342CF491E57DULL,
		0x9200032ABCAE8762ULL,
		0xFFC417B460667066ULL,
		0xC23A8CCC10DF001CULL
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
		0x2651E671B22BAA7FULL,
		0x662D676E035544C8ULL,
		0xB07EC251691944ADULL,
		0xEB78F2B886DB9853ULL,
		0xB4FDEC5FD7F74752ULL,
		0xEAE83230315B2963ULL,
		0x73278C027E222240ULL,
		0x8952EB364A7366C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FCA6465BDA4834FULL,
		0xA79C3B98B16180EDULL,
		0x75A46D263A7C65DCULL,
		0xC238A8D02FD4E0DFULL,
		0x2138DBCCF27D6ED7ULL,
		0x48E49B29C835E11FULL,
		0x361E51C221889C3FULL,
		0xAFB2120D57CB25C1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8687820BF4872730ULL,
		0xBE912BD551F3C3DAULL,
		0x3ADA552B2E9CDED0ULL,
		0x294049E85706B774ULL,
		0x93C51092E579D87BULL,
		0xA203970669254844ULL,
		0x3D093A405C998601ULL,
		0xD9A0D928F2A84103ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x142954138FBD001BULL,
		0x59D4C27218E18F9EULL,
		0x257004D8F8E81785ULL,
		0x6F36AF5E958E773DULL,
		0xAE2AF74FA06158EFULL,
		0x52AA1719A6A36E81ULL,
		0x4BB410BBFCDE09B5ULL,
		0x152510F7E4010D4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x437253DDFE98CBE6ULL,
		0x07A377FD8EB9B8BFULL,
		0xC652BAA0F5D31522ULL,
		0x26F1236F4DAA2A47ULL,
		0x581F3E7DD66184A7ULL,
		0x98DECC06D708E314ULL,
		0x6C6F87D1FA32E5D3ULL,
		0xC86241078A737B96ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD0B7003591243435ULL,
		0x52314A748A27D6DEULL,
		0x5F1D4A3803150263ULL,
		0x48458BEF47E44CF5ULL,
		0x560BB8D1C9FFD448ULL,
		0xB9CB4B12CF9A8B6DULL,
		0xDF4488EA02AB23E1ULL,
		0x4CC2CFF0598D91B5ULL
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
		0xFC8C56BDE683791FULL,
		0x10AF233CC6546520ULL,
		0x89AF922DE05954CFULL,
		0xF0380B4E221C3EADULL,
		0xE63459733ECF84F9ULL,
		0x556110BD57898A3EULL,
		0xADD8C45783289459ULL,
		0x72005AE99C2E029EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7EE2DA7C62F08EB9ULL,
		0xE09B2A9FCFD45816ULL,
		0x1473710B3ED838DFULL,
		0x7B788C8EF37DED59ULL,
		0x32D9B598A0A06854ULL,
		0x857B12B2423B1E53ULL,
		0x8CCE7865A3CFA982ULL,
		0x9B41B821994F526CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7DA97C418392EA66ULL,
		0x3013F89CF6800D0AULL,
		0x753C2122A1811BEFULL,
		0x74BF7EBF2E9E5154ULL,
		0xB35AA3DA9E2F1CA5ULL,
		0xCFE5FE0B154E6BEBULL,
		0x210A4BF1DF58EAD6ULL,
		0xD6BEA2C802DEB032ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xE2AFDFC26834559AULL,
		0x2E8806C30340AF5BULL,
		0xEEF86D917430E9FCULL,
		0xFACF4E61EE40147AULL,
		0xB76F7D92C52E9123ULL,
		0x15ECAE0FC300E898ULL,
		0x43E2D14E9E37D800ULL,
		0x40DF69645735988BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9E8564ED111C090ULL,
		0xA537523559D13BA3ULL,
		0xEC8F35C95E264AE8ULL,
		0x67D5BE396C6C35F8ULL,
		0x4EECE3D0840B260FULL,
		0x8F3018309DCF19B6ULL,
		0x8DBC8B21DB37B79BULL,
		0x36CF42FFDE15E3BFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x08C789739722950AULL,
		0x8950B48DA96F73B8ULL,
		0x026937C8160A9F13ULL,
		0x92F9902881D3DE82ULL,
		0x688299C241236B14ULL,
		0x86BC95DF2531CEE2ULL,
		0xB626462CC3002064ULL,
		0x0A102664791FB4CBULL
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
		0x051A21F4CE0B46E3ULL,
		0x8CCCBC64B491AE63ULL,
		0xAC5BBED9E60271C2ULL,
		0xC2CEADDFD277C65DULL,
		0x04D5A5E20FC9991BULL,
		0xBEE5ABFEEEC0A880ULL,
		0x0840602C43F51B58ULL,
		0x75CCC878DBEE2038ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDAC5B7F7BB16412ULL,
		0x5EB1097893D0AD3FULL,
		0x7D8087DD209F4B46ULL,
		0x52CBB3AA8AAB7533ULL,
		0x0F81562A10F756A6ULL,
		0x22844CD0C4811159ULL,
		0xE82F53D0F6886770ULL,
		0x49C8C51400C01784ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x076DC6755259E2D1ULL,
		0x2E1BB2EC20C10123ULL,
		0x2EDB36FCC563267CULL,
		0x7002FA3547CC512AULL,
		0xF5544FB7FED24275ULL,
		0x9C615F2E2A3F9726ULL,
		0x20110C5B4D6CB3E8ULL,
		0x2C040364DB2E08B3ULL
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
		0x82ECA01D2DDD790FULL,
		0x5B2847C7AE43FABFULL,
		0x1C6260A024B1A2C8ULL,
		0x6183FBF46E2F5CC9ULL,
		0x284C4158AC0AF52DULL,
		0x6571096AAFC6419EULL,
		0x46EB1965F3E548A9ULL,
		0x30B8640FD85163AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEEEC0B0286590F49ULL,
		0xB4E49357A2C386F8ULL,
		0x98641A07F96ADFBDULL,
		0x4054B74380E91C0EULL,
		0xB771F92EF3F34BFEULL,
		0xE3D10B1D0229826AULL,
		0x14E05801CB265BC2ULL,
		0x6A4EFEFEF5A19E51ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9400951AA78469C6ULL,
		0xA643B4700B8073C6ULL,
		0x83FE46982B46C30AULL,
		0x212F44B0ED4640BAULL,
		0x70DA4829B817A92FULL,
		0x819FFE4DAD9CBF33ULL,
		0x320AC16428BEECE6ULL,
		0xC6696510E2AFC55DULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x39D3544FF72E569FULL,
		0x5344044A320F63D0ULL,
		0x624BFD935C369097ULL,
		0x0D5E8383FE1A941AULL,
		0xA80FF70175395827ULL,
		0x4B97FD4DEBAA4D71ULL,
		0x1E4CAB8F31508782ULL,
		0xE6148BE2E6DF15D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBD5F3B028D5A7A9ULL,
		0xEE8AC2ED7BBDFCD1ULL,
		0xE2EA5359D666F39AULL,
		0x4B9EA3445157050CULL,
		0x31E672CBB754C824ULL,
		0x5807EA34F0F70414ULL,
		0x393DE61C066D62F6ULL,
		0x5D1FDA07BF8D80FDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3DFD609FCE58AEF6ULL,
		0x64B9415CB65166FEULL,
		0x7F61AA3985CF9CFCULL,
		0xC1BFE03FACC38F0DULL,
		0x76298435BDE49002ULL,
		0xF3901318FAB3495DULL,
		0xE50EC5732AE3248BULL,
		0x88F4B1DB275194D3ULL
	}};
	sign = 0;
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
		0xDBFDFA38774CFB25ULL,
		0x681267251CC35D63ULL,
		0xC7AD0B71977FB68BULL,
		0x02ADD5F9A1D967F6ULL,
		0x35C2B91C9F0DD50DULL,
		0xE1D146BC8160E940ULL,
		0x4010A7198701E430ULL,
		0xFC044B712AB1C14CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDC545DD2094C260ULL,
		0xD468ED69A9A0BDA8ULL,
		0x91AA4E2DF8976026ULL,
		0x8180B15AA6F3250CULL,
		0x1B2FD8259EF2126DULL,
		0x0DDE08D588C76906ULL,
		0x139A248F152556E1ULL,
		0x6F79830E65A7569AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFE38B45B56B838C5ULL,
		0x93A979BB73229FBAULL,
		0x3602BD439EE85664ULL,
		0x812D249EFAE642EAULL,
		0x1A92E0F7001BC29FULL,
		0xD3F33DE6F899803AULL,
		0x2C76828A71DC8D4FULL,
		0x8C8AC862C50A6AB2ULL
	}};
	sign = 0;
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
		0xAE6929D997F96D41ULL,
		0x9B3D0EE6FFB25299ULL,
		0xD9A8D0366B34C4CEULL,
		0x35D1CD285BAFB51AULL,
		0x269C3F726343FA17ULL,
		0xD7913C74F26BCA25ULL,
		0x56E35C2153C90A24ULL,
		0x026B2225F2902FB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12D93384FB31D4A5ULL,
		0x8EFF5344769E6785ULL,
		0xB70DF8E407E95F8CULL,
		0xF369AB9AB1546B42ULL,
		0x445894BA021C7606ULL,
		0x83020B96F19C6876ULL,
		0x70D21A7D57EFFC33ULL,
		0x5DA59873BAC53454ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9B8FF6549CC7989CULL,
		0x0C3DBBA28913EB14ULL,
		0x229AD752634B6542ULL,
		0x4268218DAA5B49D8ULL,
		0xE243AAB861278410ULL,
		0x548F30DE00CF61AEULL,
		0xE61141A3FBD90DF1ULL,
		0xA4C589B237CAFB64ULL
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
		0xA2ED3BF70C24D991ULL,
		0x40224DEDB2EC1925ULL,
		0xB831A669E7F661AEULL,
		0x1EEE10BD8F3622A3ULL,
		0xBFB351B18AFD76C9ULL,
		0x934383FE5F0E8E38ULL,
		0x32A28A3DFC9E05D3ULL,
		0x500F0CFC83B8C9F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x294E8B0A127F6084ULL,
		0xFB0FDA9F7C9B9D8AULL,
		0x4D7109CCD78C8A2FULL,
		0x2525E35876CD393CULL,
		0xF748751AAD4DA2E2ULL,
		0xF94D68F9C51D856BULL,
		0x57D1E8E89498E942ULL,
		0x41A3B2DA40F38E9FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x799EB0ECF9A5790DULL,
		0x4512734E36507B9BULL,
		0x6AC09C9D1069D77EULL,
		0xF9C82D651868E967ULL,
		0xC86ADC96DDAFD3E6ULL,
		0x99F61B0499F108CCULL,
		0xDAD0A15568051C90ULL,
		0x0E6B5A2242C53B53ULL
	}};
	sign = 0;
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
		0x12C15D3213AA45DCULL,
		0x977AD93D851B426DULL,
		0xED070A706C0A1133ULL,
		0xE22CE5240474946DULL,
		0xD78A7F152DAF52FBULL,
		0xBAAC7E97A70B5E61ULL,
		0x53194A6CB172765DULL,
		0x5E304AD43E434CCAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98AE5B96AA03DF7AULL,
		0x399C74647A924A25ULL,
		0x4ADA3543214E4823ULL,
		0xA3864EDBF89C31D1ULL,
		0xD871EA1704169798ULL,
		0x55488D419DE2EA54ULL,
		0x34EA9689C4804202ULL,
		0x80EE9C6BEDD5830FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7A13019B69A66662ULL,
		0x5DDE64D90A88F847ULL,
		0xA22CD52D4ABBC910ULL,
		0x3EA696480BD8629CULL,
		0xFF1894FE2998BB63ULL,
		0x6563F1560928740CULL,
		0x1E2EB3E2ECF2345BULL,
		0xDD41AE68506DC9BBULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x5EFED1FA6D0088BBULL,
		0x4F2ACA307A5C2B8EULL,
		0x096C8EBC701F40C1ULL,
		0x75A967EFAF06E2F0ULL,
		0x8D571901986F016FULL,
		0xF4671395E0E51A4AULL,
		0x78F83630F4B4592BULL,
		0x1364006F66CFF996ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x997C31DB04E03623ULL,
		0x436B87A47148047AULL,
		0x7C94E8315DB7FDBDULL,
		0x07F5185519FA5934ULL,
		0x8DB756442F603510ULL,
		0x82B543F60815E2A5ULL,
		0xF444391EFD7592CEULL,
		0x979EBD7BD0FDA340ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC582A01F68205298ULL,
		0x0BBF428C09142713ULL,
		0x8CD7A68B12674304ULL,
		0x6DB44F9A950C89BBULL,
		0xFF9FC2BD690ECC5FULL,
		0x71B1CF9FD8CF37A4ULL,
		0x84B3FD11F73EC65DULL,
		0x7BC542F395D25655ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x8F41278094C555C7ULL,
		0x7A58EA79AF325216ULL,
		0xBAC76438F8583E01ULL,
		0x9DBF47D8C5679960ULL,
		0x9B2204F8CBA2641EULL,
		0x0D3AC0BDE0AC4C46ULL,
		0xBD86C20D0A5A1B97ULL,
		0x8C7770DAC8173872ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8E60D628E9F023CULL,
		0xA0EBD990AB5FFA77ULL,
		0x11AE38B9E1D58CA2ULL,
		0x50CCA02CE74C0156ULL,
		0x7CF52D408E95775DULL,
		0x6E947F2DA8C79611ULL,
		0x99B39A5852AB76D8ULL,
		0x402E4DDB3220A768ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x965B1A1E0626538BULL,
		0xD96D10E903D2579EULL,
		0xA9192B7F1682B15EULL,
		0x4CF2A7ABDE1B980AULL,
		0x1E2CD7B83D0CECC1ULL,
		0x9EA6419037E4B635ULL,
		0x23D327B4B7AEA4BEULL,
		0x4C4922FF95F6910AULL
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
		0x69713A5278A2DDDFULL,
		0xCC6C90C18F4838D7ULL,
		0x84A11701486FBD4BULL,
		0x839D8324E1C94178ULL,
		0x64D4C653DA1BBB64ULL,
		0xC7AFC1F9695B97A3ULL,
		0xFF0BDA9ED66171A1ULL,
		0x117CD19961106EFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x680B04B1A477B2B8ULL,
		0x5A6A6652EC859FECULL,
		0x8643EBD366B60124ULL,
		0xB2D7BBCCE32999C4ULL,
		0x940A422BC6D11BB4ULL,
		0x66609B0D37392DBAULL,
		0x4C6B9566B3FC863FULL,
		0x5B72A8BE4851AF64ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x016635A0D42B2B27ULL,
		0x72022A6EA2C298EBULL,
		0xFE5D2B2DE1B9BC27ULL,
		0xD0C5C757FE9FA7B3ULL,
		0xD0CA8428134A9FAFULL,
		0x614F26EC322269E8ULL,
		0xB2A045382264EB62ULL,
		0xB60A28DB18BEBF98ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x6CDEC219CB9583A1ULL,
		0x90927F301939E583ULL,
		0xC3933126C55EAE20ULL,
		0xD330B7D0B9AAB7B2ULL,
		0x45F48212A9E0AE33ULL,
		0x5D3370E02BCAB247ULL,
		0x4371EEC2A1A43B3AULL,
		0x5F2A87FBBB720483ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8A495DF0038A899ULL,
		0xE6E675ED555C480EULL,
		0xCFE68AF7D77F7BACULL,
		0x14F6DFA432C08416ULL,
		0x997A107EF2378DF0ULL,
		0xA6EF43D1CA76E246ULL,
		0xB7FDF26825CDE35FULL,
		0xE0AF2A2FE7CB31C4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x743A2C3ACB5CDB08ULL,
		0xA9AC0942C3DD9D74ULL,
		0xF3ACA62EEDDF3273ULL,
		0xBE39D82C86EA339BULL,
		0xAC7A7193B7A92043ULL,
		0xB6442D0E6153D000ULL,
		0x8B73FC5A7BD657DAULL,
		0x7E7B5DCBD3A6D2BEULL
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
		0x514BA950E9B21C01ULL,
		0xB9779E1BF092D61CULL,
		0x67A2D28D6F75C42AULL,
		0x617BA0BC619C09FAULL,
		0xD4F5F0A6EE1497D1ULL,
		0x53C9752E2B235482ULL,
		0xA0936D7BAFE117C9ULL,
		0xE4A8A2E28C385660ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8A3A9B2A6779DA2ULL,
		0xFF7261AB516BCD2CULL,
		0xCD860FDA6CA85A09ULL,
		0xB0109796E3E164DEULL,
		0xBFD90D42B4E2D5E9ULL,
		0x119BF782B4C9A42CULL,
		0xCE5212715E1A2C95ULL,
		0xCA13F56772235822ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x88A7FF9E433A7E5FULL,
		0xBA053C709F2708EFULL,
		0x9A1CC2B302CD6A20ULL,
		0xB16B09257DBAA51BULL,
		0x151CE3643931C1E7ULL,
		0x422D7DAB7659B056ULL,
		0xD2415B0A51C6EB34ULL,
		0x1A94AD7B1A14FE3DULL
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
		0x9679A48D38ED7B65ULL,
		0x151AD369169CCEA2ULL,
		0x8F8D0EEB4EA62439ULL,
		0x0C4980D51761D0F6ULL,
		0x5E525C95610020E6ULL,
		0x0B9CEA27A9D8F068ULL,
		0x556EA3EB520F900FULL,
		0x7EE17BB00AB086C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DC4B6731C0121F1ULL,
		0xF847660AE3E70E7FULL,
		0x19544737FCA45112ULL,
		0x9341E10279EBDFDCULL,
		0x41C06C690FCE42C1ULL,
		0x2BFEAADA05862A2DULL,
		0xEA422669FD9FCC62ULL,
		0x0409859F1162075CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF8B4EE1A1CEC5974ULL,
		0x1CD36D5E32B5C022ULL,
		0x7638C7B35201D326ULL,
		0x79079FD29D75F11AULL,
		0x1C91F02C5131DE24ULL,
		0xDF9E3F4DA452C63BULL,
		0x6B2C7D81546FC3ACULL,
		0x7AD7F610F94E7F6CULL
	}};
	sign = 0;
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
		0xE29360A826C6CBF7ULL,
		0xEE8A443EC99877A1ULL,
		0x750B6A85F3D48417ULL,
		0xFA71338DAF721F36ULL,
		0xAFAAB05318BBDCFCULL,
		0xC4F94CD2B0B3681EULL,
		0xAD98542DA90C9229ULL,
		0x54ABA48599522FD5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0DD0DBE54E13865ULL,
		0x004CD6F5A8C00139ULL,
		0x715ED7F5E48F8519ULL,
		0xDF7179141E8077FDULL,
		0xADAAA8EA65DE5639ULL,
		0x2CBCE14C457DBF1AULL,
		0x30B6D97E45A9A5B8ULL,
		0x1DA6B8EC1781C555ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x21B652E9D1E59392ULL,
		0xEE3D6D4920D87668ULL,
		0x03AC92900F44FEFEULL,
		0x1AFFBA7990F1A739ULL,
		0x02000768B2DD86C3ULL,
		0x983C6B866B35A904ULL,
		0x7CE17AAF6362EC71ULL,
		0x3704EB9981D06A80ULL
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
		0x3277F70A84D85927ULL,
		0x5145037C6A7A59FAULL,
		0xE212DA3E9A7D26CBULL,
		0xC9696F3F1C26FD50ULL,
		0xD81424A1646FED60ULL,
		0x364B9FA322E1EE1DULL,
		0x43F618C6A9672A73ULL,
		0x0711A118BD381195ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x210643C90C598EB9ULL,
		0x6FB02FF2ED8A81FFULL,
		0x077D791EA32E1532ULL,
		0x735B2E5ECCF9381EULL,
		0x951A6A1DB65EF830ULL,
		0x70AB46DBA6FAC0E5ULL,
		0xF5AA43365F318D52ULL,
		0xC1A88C18434C457CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1171B341787ECA6EULL,
		0xE194D3897CEFD7FBULL,
		0xDA95611FF74F1198ULL,
		0x560E40E04F2DC532ULL,
		0x42F9BA83AE10F530ULL,
		0xC5A058C77BE72D38ULL,
		0x4E4BD5904A359D20ULL,
		0x4569150079EBCC18ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xF6CD1089F713782EULL,
		0x9843E84079290D9AULL,
		0x3D3282709DD5C354ULL,
		0x7DE08D182C2C8796ULL,
		0xF80AE2EFB673DDD7ULL,
		0x632C2E57D9525FA2ULL,
		0xD98CA254ACF32BAEULL,
		0x0DCAC449F2361655ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BB89FD719B545B3ULL,
		0xCAF671DAC7CD114FULL,
		0x4FB946FC272A5C36ULL,
		0xAC48FA1B9C2CAB12ULL,
		0x017CC70098777736ULL,
		0x433E2AD31D5542C6ULL,
		0xF6FDFAFA5FA6FD31ULL,
		0xFC85D789C1C768C8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAB1470B2DD5E327BULL,
		0xCD4D7665B15BFC4BULL,
		0xED793B7476AB671DULL,
		0xD19792FC8FFFDC83ULL,
		0xF68E1BEF1DFC66A0ULL,
		0x1FEE0384BBFD1CDCULL,
		0xE28EA75A4D4C2E7DULL,
		0x1144ECC0306EAD8CULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x2397781F98342B7BULL,
		0x3D495C8DA122942EULL,
		0x37D82BE67B75E27DULL,
		0x43DED3CA1980295CULL,
		0xB0AFF8280EE2E999ULL,
		0x3F7D281AD1C1973BULL,
		0x1A6A3FB66758D9D2ULL,
		0x18157B8F5B4B7739ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30AC0289388CF2FAULL,
		0x366CCF213EF791B8ULL,
		0xF89FA645A517857DULL,
		0x5A647EE2B035024CULL,
		0xBD6790CA265269BCULL,
		0xF54E2C92AD66F139ULL,
		0x0630AADEFA954D27ULL,
		0xDC88F7C2A4109987ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF2EB75965FA73881ULL,
		0x06DC8D6C622B0275ULL,
		0x3F3885A0D65E5D00ULL,
		0xE97A54E7694B270FULL,
		0xF348675DE8907FDCULL,
		0x4A2EFB88245AA601ULL,
		0x143994D76CC38CAAULL,
		0x3B8C83CCB73ADDB2ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xEC3B2FB60D52C4E8ULL,
		0xE2B30843BEB9DACFULL,
		0x157F9344BE58FE22ULL,
		0x951B0F6E048CDB9EULL,
		0xE6FC2BC592CD7885ULL,
		0x68168621AB6E25D6ULL,
		0x482946BAC48689E2ULL,
		0x5710AB0814C73ED2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1FAE472D4589A47ULL,
		0xE02A32B14037A33EULL,
		0x0A1A4C4AB9924C31ULL,
		0xB7F2F6AA3AFA094AULL,
		0xE3130A8C420E713BULL,
		0xADE7C48DAAF8FEDCULL,
		0x3DCC8822D823CAB1ULL,
		0xC28CB0CD3E78ABC9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFA404B4338FA2AA1ULL,
		0x0288D5927E823790ULL,
		0x0B6546FA04C6B1F1ULL,
		0xDD2818C3C992D254ULL,
		0x03E9213950BF0749ULL,
		0xBA2EC194007526FAULL,
		0x0A5CBE97EC62BF30ULL,
		0x9483FA3AD64E9309ULL
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
		0x72537993B00DE076ULL,
		0xC5CE74EA414E874BULL,
		0xFC655C62D3BF1626ULL,
		0xE230DA45E0780039ULL,
		0xE6B16F5600A55E5BULL,
		0x804730BD047F590BULL,
		0xEF41F245F84583A1ULL,
		0x471B9AB55567A7BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5D24B1F9BFB3D1CULL,
		0xE4F41E33DEFED287ULL,
		0xFAAE5DE17C968668ULL,
		0x8A972BB295F1F7E2ULL,
		0xA4C0D873DAB99271ULL,
		0x6EF588A308C1B118ULL,
		0xC9A7F91D6AED3554ULL,
		0xC808133269A5F4ADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCC812E741412A35AULL,
		0xE0DA56B6624FB4C3ULL,
		0x01B6FE8157288FBDULL,
		0x5799AE934A860857ULL,
		0x41F096E225EBCBEAULL,
		0x1151A819FBBDA7F3ULL,
		0x2599F9288D584E4DULL,
		0x7F138782EBC1B310ULL
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
		0x7DA498E89624EC3FULL,
		0xEB7C19719181D776ULL,
		0xA0C8EC86B9C41097ULL,
		0x55AD157482E15471ULL,
		0xD92D6D476A9B775BULL,
		0xA37685503DEEEC42ULL,
		0x94AE19A86570C2B3ULL,
		0x791D8D727B6800BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x061EE0C8738043C0ULL,
		0x8C4DE40AB86FA531ULL,
		0x9954D9B39CBFF843ULL,
		0x7542A65FE28B770FULL,
		0x063810F9E2EC6B3BULL,
		0x0C1F8EA7514A2263ULL,
		0x5F06F265366A98D4ULL,
		0xC2204372B570873CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7785B82022A4A87FULL,
		0x5F2E3566D9123245ULL,
		0x077412D31D041854ULL,
		0xE06A6F14A055DD62ULL,
		0xD2F55C4D87AF0C1FULL,
		0x9756F6A8ECA4C9DFULL,
		0x35A727432F0629DFULL,
		0xB6FD49FFC5F77980ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xF4C02A11C9811993ULL,
		0x759ED398F66E036CULL,
		0x2F79A195F0CBF069ULL,
		0x95CCE555C4DC0C6EULL,
		0x36B94071A3345026ULL,
		0xA899E91D08A0C408ULL,
		0xD2EE165380DC8EEAULL,
		0x4569D94534F397AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B929232EDB72DF5ULL,
		0xB5AAACC5B6A9008AULL,
		0x600FC02BB7484F87ULL,
		0x2061F2F5E497AE40ULL,
		0x303FA5ECB4A566A7ULL,
		0xA3A71CC6851B3F5CULL,
		0xDA395E96063813A1ULL,
		0x86EA17C729EAFC49ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x892D97DEDBC9EB9EULL,
		0xBFF426D33FC502E2ULL,
		0xCF69E16A3983A0E1ULL,
		0x756AF25FE0445E2DULL,
		0x06799A84EE8EE97FULL,
		0x04F2CC56838584ACULL,
		0xF8B4B7BD7AA47B49ULL,
		0xBE7FC17E0B089B60ULL
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
		0x924223017173085AULL,
		0x362B89E116B7FC9FULL,
		0x3309DCBC270AE9DAULL,
		0xB3C302ECF89DFA68ULL,
		0x7BBDC88FE7EE0DB8ULL,
		0x7C3EBF31E33E7157ULL,
		0x8B9AACD6CEFDB68EULL,
		0xD8F083F507C5D8B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50F9E98C2346547EULL,
		0xAA09552910407D08ULL,
		0x6A1890D5FA8BE7EAULL,
		0xDE2D05CF64825854ULL,
		0x16D8719B991725CCULL,
		0xFF3E0F4AB91A831AULL,
		0x855647BD43130C91ULL,
		0x9ADBDAAFBC47C05AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x414839754E2CB3DCULL,
		0x8C2234B806777F97ULL,
		0xC8F14BE62C7F01EFULL,
		0xD595FD1D941BA213ULL,
		0x64E556F44ED6E7EBULL,
		0x7D00AFE72A23EE3DULL,
		0x064465198BEAA9FCULL,
		0x3E14A9454B7E185CULL
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
		0x20EFA10BDEF40B4AULL,
		0x1DC0015B420EA196ULL,
		0xE916D579B2426C9BULL,
		0x4DF40CADC64CEFD2ULL,
		0x775AF056C1B07BC0ULL,
		0x914C1CEECF4C72E9ULL,
		0xD5641BE9F0F22038ULL,
		0x40185E6F89867714ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF0E55BB6A29791EULL,
		0x53301EF1444980F9ULL,
		0xDA940490B3101830ULL,
		0xD6727DCEB4DCD079ULL,
		0xFAA2923D7E66DCF4ULL,
		0x0D6C19C1B01DA723ULL,
		0xE70FE1A0B2D6006DULL,
		0x93C79A4BEE2827AEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x51E14B5074CA922CULL,
		0xCA8FE269FDC5209CULL,
		0x0E82D0E8FF32546AULL,
		0x77818EDF11701F59ULL,
		0x7CB85E1943499ECBULL,
		0x83E0032D1F2ECBC5ULL,
		0xEE543A493E1C1FCBULL,
		0xAC50C4239B5E4F65ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xD1908274003E571CULL,
		0xB2B5AE1A65407448ULL,
		0xC97AF1293C817B39ULL,
		0x2A376DCC5EE5407BULL,
		0xC7B303C27184EC86ULL,
		0xDEC7C90D5F546CF0ULL,
		0x71739167066528A7ULL,
		0x3AD3672F3D4005B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15152F54D306BC0CULL,
		0x5B7CA5C7DC99F6F8ULL,
		0x64AC0A960D456BDDULL,
		0xFAF8A76C1D2EE596ULL,
		0x2E4206073CF49975ULL,
		0x7E5E101DC29AB815ULL,
		0x4FA4700EE4A06637ULL,
		0x1127BABF81097855ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBC7B531F2D379B10ULL,
		0x5739085288A67D50ULL,
		0x64CEE6932F3C0F5CULL,
		0x2F3EC66041B65AE5ULL,
		0x9970FDBB34905310ULL,
		0x6069B8EF9CB9B4DBULL,
		0x21CF215821C4C270ULL,
		0x29ABAC6FBC368D5FULL
	}};
	sign = 0;
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
		0x7F124F9F8D878A63ULL,
		0x87F954F97594AC71ULL,
		0x8556927FFE4B7D30ULL,
		0xB266C62D5DB0696AULL,
		0x15D904CA5242A95DULL,
		0x74271092CDCA8C38ULL,
		0xFA2FA5B4830D01DDULL,
		0x8392D16B5F3DDDAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7CC6D5F9BC17FAFULL,
		0x15FA678F2425153EULL,
		0xAD65C15D62D13DCAULL,
		0xCF2E336C24039CF1ULL,
		0xD62CF70B0144C4F3ULL,
		0x68FE5BFD3F2D9BC3ULL,
		0xD30BF16EECCF4F71ULL,
		0x5DD87D026690B2A6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD745E23FF1C60AB4ULL,
		0x71FEED6A516F9732ULL,
		0xD7F0D1229B7A3F66ULL,
		0xE33892C139ACCC78ULL,
		0x3FAC0DBF50FDE469ULL,
		0x0B28B4958E9CF074ULL,
		0x2723B445963DB26CULL,
		0x25BA5468F8AD2B09ULL
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
		0xAB33B38491DF97CAULL,
		0x6ED8F925ABBE4DAFULL,
		0x0ADED361EF4222D6ULL,
		0xE31F9296897AB68FULL,
		0x8CDFC806E77C9B89ULL,
		0xE94DCE5A08F66321ULL,
		0x21C497F4216EE52FULL,
		0x434DC078C6D50989ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14B5BBD5ABD4FA68ULL,
		0x6E6029229B7CCB1DULL,
		0x9D770194825A636CULL,
		0x8CEF72BE8C26F659ULL,
		0x288C2BACE00BB6BAULL,
		0xBF155313C7DC1DFEULL,
		0xC2A3A3E4CF26455FULL,
		0x62BF6474C3640C22ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x967DF7AEE60A9D62ULL,
		0x0078D00310418292ULL,
		0x6D67D1CD6CE7BF6AULL,
		0x56301FD7FD53C035ULL,
		0x64539C5A0770E4CFULL,
		0x2A387B46411A4523ULL,
		0x5F20F40F52489FD0ULL,
		0xE08E5C040370FD66ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x965CE153D6D85815ULL,
		0xF7801D2788841ED0ULL,
		0xD3B8BD8384FB3D4CULL,
		0x2F427B38226B14A9ULL,
		0x2AA351F7F40DE23BULL,
		0x308B10CE96E09827ULL,
		0x5862359C669E43B2ULL,
		0x6CB4D5FFF5A7DACCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38526EBEB47843FFULL,
		0x8764E11A724E9FDBULL,
		0x9F42A4224AE3AC44ULL,
		0x9D9AE3F9C53D9F1DULL,
		0x83ADC2BF8B785512ULL,
		0x85E7417A385DD617ULL,
		0xEF84D482A4072DF1ULL,
		0x894EC850C4D0934FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5E0A729522601416ULL,
		0x701B3C0D16357EF5ULL,
		0x347619613A179108ULL,
		0x91A7973E5D2D758CULL,
		0xA6F58F3868958D28ULL,
		0xAAA3CF545E82C20FULL,
		0x68DD6119C29715C0ULL,
		0xE3660DAF30D7477CULL
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
		0x9FDE8983368182C6ULL,
		0x61DCF2EC20E738B5ULL,
		0xD6497440F3B71546ULL,
		0x1BD6308329C9F510ULL,
		0x75412D10ABBD8739ULL,
		0x37C0E712D84DE611ULL,
		0x5CAB677558C27828ULL,
		0x59DB3D5030C1A645ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4384C21A31DD6DFEULL,
		0x05C63222518B6A83ULL,
		0xB7332DF927432402ULL,
		0x22EBA95DF0800014ULL,
		0x3C5F4E4D251ACC76ULL,
		0x3E8DFDA48C20E4DCULL,
		0xE9CF9C9223D85BEAULL,
		0x399BC84460FA017BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5C59C76904A414C8ULL,
		0x5C16C0C9CF5BCE32ULL,
		0x1F164647CC73F144ULL,
		0xF8EA87253949F4FCULL,
		0x38E1DEC386A2BAC2ULL,
		0xF932E96E4C2D0135ULL,
		0x72DBCAE334EA1C3DULL,
		0x203F750BCFC7A4C9ULL
	}};
	sign = 0;
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
		0x2FCD3D90169600D0ULL,
		0xBA4B20766D5FBD7FULL,
		0x2932EE7C886B0F62ULL,
		0xD4FB96134430EAA8ULL,
		0xF0542E4ADF6643D9ULL,
		0x9C6FBEE1363EE49EULL,
		0x0D346725065CD1A4ULL,
		0x9E799E94368FF775ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BED4237D8FCFCC1ULL,
		0x73D7C3F2DE9AA702ULL,
		0x08FE8722212693E6ULL,
		0x2E5C6CAE1C87F9ABULL,
		0xBFA8F5243009B062ULL,
		0xF723B01DA606E74CULL,
		0xBC2140415CE8C4B9ULL,
		0x31A394AFCEC11856ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA3DFFB583D99040FULL,
		0x46735C838EC5167CULL,
		0x2034675A67447B7CULL,
		0xA69F296527A8F0FDULL,
		0x30AB3926AF5C9377ULL,
		0xA54C0EC39037FD52ULL,
		0x511326E3A9740CEAULL,
		0x6CD609E467CEDF1EULL
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
		0x9A0C0AEE5A2226B0ULL,
		0x409AF59CE646CDECULL,
		0x18F3262ED0B39DB4ULL,
		0x4C28C601FA1F8F50ULL,
		0xDBDD658C600C79A2ULL,
		0xA0CBD3B7C65EBF04ULL,
		0x1842C5923455EBE2ULL,
		0xF219A920691F654BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6603EC53C4F83A99ULL,
		0x0EEE871D8751D27EULL,
		0xE60290872CA8487AULL,
		0x3E9049B51D8509D2ULL,
		0x6CB6B77940171247ULL,
		0xF9775510A9D56DB8ULL,
		0xC5E44FFB576D43C1ULL,
		0xD11A9C5C9CD28CBFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x34081E9A9529EC17ULL,
		0x31AC6E7F5EF4FB6EULL,
		0x32F095A7A40B553AULL,
		0x0D987C4CDC9A857DULL,
		0x6F26AE131FF5675BULL,
		0xA7547EA71C89514CULL,
		0x525E7596DCE8A820ULL,
		0x20FF0CC3CC4CD88BULL
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
		0xD117A7C42F02FBD8ULL,
		0x5BD00F57EA23B718ULL,
		0x81ECF5F90980A977ULL,
		0x1DB003C26D50F0EFULL,
		0x9D9DD94125D80C58ULL,
		0xAE5927677C9AD5D2ULL,
		0xFB76CC632A1292A1ULL,
		0x0BB2D4EDEF114D7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2720AF79603C0B35ULL,
		0x5EE32D4ECB1647B4ULL,
		0x5E729BCC996710BAULL,
		0x02FFFE5056849701ULL,
		0x2CFA830F4215707CULL,
		0xCA8DC3FAA63975B2ULL,
		0xF3DFD7737F511065ULL,
		0xA966829974182F68ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA9F6F84ACEC6F0A3ULL,
		0xFCECE2091F0D6F64ULL,
		0x237A5A2C701998BCULL,
		0x1AB0057216CC59EEULL,
		0x70A35631E3C29BDCULL,
		0xE3CB636CD6616020ULL,
		0x0796F4EFAAC1823BULL,
		0x624C52547AF91E12ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xC44BD83E9B23EC62ULL,
		0x350C3959DBC64FB5ULL,
		0xC53F27C8BCA0B8A7ULL,
		0x75A437E3A6AF65E5ULL,
		0xF7B3C2E5D08F3B53ULL,
		0x1299C02262B5A7A2ULL,
		0x89A4C2BF6EC686F6ULL,
		0x03B11B94BFFE9955ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6650D73601673F2FULL,
		0xFBB9CD30E0695E0BULL,
		0x74737775319F4B06ULL,
		0x8B22326547083659ULL,
		0xB298D1D85D596DDBULL,
		0xC445C3BC4CE257FFULL,
		0x0AD33887B1079999ULL,
		0x72EBE7C0A0010E8FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5DFB010899BCAD33ULL,
		0x39526C28FB5CF1AAULL,
		0x50CBB0538B016DA0ULL,
		0xEA82057E5FA72F8CULL,
		0x451AF10D7335CD77ULL,
		0x4E53FC6615D34FA3ULL,
		0x7ED18A37BDBEED5CULL,
		0x90C533D41FFD8AC6ULL
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
		0x1C9A16E7101E1CE3ULL,
		0x76CBB5D25AA22158ULL,
		0xA782C7F3725628A5ULL,
		0x75EEBD2D193472B7ULL,
		0x10AD011558AF08F8ULL,
		0x1A85E97C6F51C8D7ULL,
		0xCE51C7433758F4DBULL,
		0x416358C6BA4C1D94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC6078077881F9EAULL,
		0xE8F35B191AAF8CCEULL,
		0x493DDD78CAC1666BULL,
		0x41C98A619AD1238FULL,
		0xC4A34AE104BBF332ULL,
		0x49780D1A662F5AB1ULL,
		0x2AD7623C8A024C6AULL,
		0x2DD64B44AA89C763ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x50399EDF979C22F9ULL,
		0x8DD85AB93FF29489ULL,
		0x5E44EA7AA794C239ULL,
		0x342532CB7E634F28ULL,
		0x4C09B63453F315C6ULL,
		0xD10DDC6209226E25ULL,
		0xA37A6506AD56A870ULL,
		0x138D0D820FC25631ULL
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
		0x118998140BE74F31ULL,
		0x53EE7E8C7DD8315EULL,
		0x285EEEC1A4A635F5ULL,
		0x1DC76D243A856C4BULL,
		0xAC790406896A5FBEULL,
		0xBE1ACB1E297E3746ULL,
		0x993576C8F183AC1FULL,
		0x9563B24C3E4CD8B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96946FFBFD8EA4ECULL,
		0x1ADC2835740F3107ULL,
		0xA9FBE05ABA00C6BEULL,
		0x3C38770F3244CEE9ULL,
		0xB4C3AC39DCE641D0ULL,
		0xF39416F5920B0545ULL,
		0x4E30156849170D85ULL,
		0x8260AB7F6BE54ADDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7AF528180E58AA45ULL,
		0x3912565709C90056ULL,
		0x7E630E66EAA56F37ULL,
		0xE18EF61508409D61ULL,
		0xF7B557CCAC841DEDULL,
		0xCA86B42897733200ULL,
		0x4B056160A86C9E99ULL,
		0x130306CCD2678DD7ULL
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
		0x560D3ABF5AADBC0CULL,
		0x6827029A73D3E978ULL,
		0x7791E0F808520040ULL,
		0x25D6D68455C146AFULL,
		0xE4CD1375A00A3ABDULL,
		0x907A610714AA572DULL,
		0xF5055B1D2794C6C2ULL,
		0x723C7DAB6CED6629ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CFEA1EB1883AC62ULL,
		0xF41786DC5A44CE9FULL,
		0xE80DD2A5472D1DE7ULL,
		0x7B9AFBD19D899048ULL,
		0x5359B4D0BB328C86ULL,
		0xB1974D9C73DF5617ULL,
		0xE685DF19AB7BD916ULL,
		0x7FF84DC45F8CEAB9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC90E98D4422A0FAAULL,
		0x740F7BBE198F1AD8ULL,
		0x8F840E52C124E258ULL,
		0xAA3BDAB2B837B666ULL,
		0x91735EA4E4D7AE36ULL,
		0xDEE3136AA0CB0116ULL,
		0x0E7F7C037C18EDABULL,
		0xF2442FE70D607B70ULL
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
		0x4929B651EE2DB7B6ULL,
		0xD239B34CB321B299ULL,
		0xE677FDF93E4DD7F9ULL,
		0x2090E509CD4F3573ULL,
		0x0371C83841E9E225ULL,
		0xF73308A0807C4E75ULL,
		0xC16B7957640399BDULL,
		0xD8966864ED277EE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x196A6E76A08C1DFFULL,
		0x47DBD811853FB123ULL,
		0x04CA1E41769ABF2BULL,
		0xD76A266CB095FFFCULL,
		0x01175FAABBD6B460ULL,
		0xFF0337EB2C5C7BC5ULL,
		0x04C4F2800C168C5DULL,
		0x792F72AD50434780ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2FBF47DB4DA199B7ULL,
		0x8A5DDB3B2DE20176ULL,
		0xE1ADDFB7C7B318CEULL,
		0x4926BE9D1CB93577ULL,
		0x025A688D86132DC4ULL,
		0xF82FD0B5541FD2B0ULL,
		0xBCA686D757ED0D5FULL,
		0x5F66F5B79CE43767ULL
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
		0x39961E88340D4D9BULL,
		0xBF98108BB8D9FB2CULL,
		0x7E464C8C923E091AULL,
		0x369D496252792C90ULL,
		0x2416CDE22E8EB0B8ULL,
		0x08B96F8725B0518EULL,
		0x8E1EF595C53CB654ULL,
		0xC371D8F53C1879BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBAF40608817490CAULL,
		0xEFD1358916A911BBULL,
		0xFE9779583E48158CULL,
		0xA199C8AD3276C066ULL,
		0xC13E8D73F3A7551AULL,
		0x0E09982834A7D963ULL,
		0x075C832B7619E2C3ULL,
		0x76E0BD0300E40512ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7EA2187FB298BCD1ULL,
		0xCFC6DB02A230E970ULL,
		0x7FAED33453F5F38DULL,
		0x950380B520026C29ULL,
		0x62D8406E3AE75B9DULL,
		0xFAAFD75EF108782AULL,
		0x86C2726A4F22D390ULL,
		0x4C911BF23B3474A8ULL
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
		0xA9AAE1F1FDAA2CEEULL,
		0x9FD106CFC97E4691ULL,
		0x99EBD5109EB9A249ULL,
		0xB8BC0CADA9DE0BFFULL,
		0xC8CB7E71B3ED705DULL,
		0xBDC80D0945534A49ULL,
		0xF7D390EB7E47D65FULL,
		0x683B5951C776649BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4385BC9AEA961B58ULL,
		0x5B4B84CCA7764C19ULL,
		0xDEEEA2503D5E649BULL,
		0xB9F47E6EEEE3606AULL,
		0x562C3E21D8D1F8D0ULL,
		0x6EBE1CC702655F20ULL,
		0xCD1B8F08684D33A8ULL,
		0xE7C11679C2FE789FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6625255713141196ULL,
		0x448582032207FA78ULL,
		0xBAFD32C0615B3DAEULL,
		0xFEC78E3EBAFAAB94ULL,
		0x729F404FDB1B778CULL,
		0x4F09F04242EDEB29ULL,
		0x2AB801E315FAA2B7ULL,
		0x807A42D80477EBFCULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x0B4CDB6822F6EACCULL,
		0xCAD3C5F859CA39FCULL,
		0x407BA595CFCCBBFAULL,
		0x44B9410E9698F0F7ULL,
		0x657811CDB53733ABULL,
		0x4092D163C82441C5ULL,
		0x166C7CF6154897A8ULL,
		0x059B957A1C999F3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B4B18730676E2CBULL,
		0xE769F5165E7E74B0ULL,
		0x4CB60A51603199F4ULL,
		0xDCFA4EA8EBA5B9B1ULL,
		0xB75317931761567EULL,
		0xD7BA7B54F71A3AEDULL,
		0xEA1D68F31ABA3018ULL,
		0x434217D1A761AAE6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC001C2F51C800801ULL,
		0xE369D0E1FB4BC54BULL,
		0xF3C59B446F9B2205ULL,
		0x67BEF265AAF33745ULL,
		0xAE24FA3A9DD5DD2CULL,
		0x68D8560ED10A06D7ULL,
		0x2C4F1402FA8E678FULL,
		0xC2597DA87537F453ULL
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
		0x49D4B9EF45A2FF75ULL,
		0x5F656CC290E1588EULL,
		0xF5CB315D9EE4E542ULL,
		0xF2004170CC0E726DULL,
		0x6D0D58E1725452B4ULL,
		0x84ECF186437B1E58ULL,
		0x22C39683EA38F12BULL,
		0x9861C36526667670ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x859410D94021870FULL,
		0xF29DDCC90AECE5D3ULL,
		0x35483892B731567FULL,
		0xE4BE9C08D9F3EB83ULL,
		0x0CB96D054481F871ULL,
		0x45DAA1449C76E51AULL,
		0x871E5F7FA96C78E6ULL,
		0x52FA005151341F8FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC440A91605817866ULL,
		0x6CC78FF985F472BAULL,
		0xC082F8CAE7B38EC2ULL,
		0x0D41A567F21A86EAULL,
		0x6053EBDC2DD25A43ULL,
		0x3F125041A704393EULL,
		0x9BA5370440CC7845ULL,
		0x4567C313D53256E0ULL
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
		0x6648FF8AC4C92850ULL,
		0x104E4DB102C24996ULL,
		0x58BD5FBC08ABAF01ULL,
		0x1B9FDE7CD7C5BBB0ULL,
		0x80511C3A3A1CB329ULL,
		0x37B88594FE5A335DULL,
		0x356F679BA7EC63A6ULL,
		0xE56CF7EEECFAF9D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1768E2AC82FF04FULL,
		0xF7B7D26EBD1197ECULL,
		0xACB70187D66D8A7AULL,
		0x1C27C5D61DBABBE2ULL,
		0x627D9A2B8B151BD1ULL,
		0x8CACFB1A48C237AEULL,
		0x011569A8C83F2D57ULL,
		0x0D473B06C273C561ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x74D2715FFC993801ULL,
		0x18967B4245B0B1A9ULL,
		0xAC065E34323E2486ULL,
		0xFF7818A6BA0AFFCDULL,
		0x1DD3820EAF079757ULL,
		0xAB0B8A7AB597FBAFULL,
		0x3459FDF2DFAD364EULL,
		0xD825BCE82A873477ULL
	}};
	sign = 0;
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
		0x0FD32B5C25954891ULL,
		0xA1CDEB390381A95BULL,
		0x390F8675AA777448ULL,
		0xF071FFCC0638913FULL,
		0x537C91E7B3F4C2B7ULL,
		0xC8149BD083E0E60BULL,
		0x95F42556F0CE1D01ULL,
		0xCA89FE3EAD266155ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18C093A11BDCF833ULL,
		0x0062AA9FEB8C7012ULL,
		0xCBDF60D0FF5552D6ULL,
		0xC1D6708F844C346BULL,
		0xE2EC36C596BD0E80ULL,
		0x50C8B97AFA1BCAAFULL,
		0x7206D4D24B425CC7ULL,
		0x48D5E07E09917CE9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF71297BB09B8505EULL,
		0xA16B409917F53948ULL,
		0x6D3025A4AB222172ULL,
		0x2E9B8F3C81EC5CD3ULL,
		0x70905B221D37B437ULL,
		0x774BE25589C51B5BULL,
		0x23ED5084A58BC03AULL,
		0x81B41DC0A394E46CULL
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
		0xE877823B1396CD61ULL,
		0xDF0F49CD12777EF9ULL,
		0xCC3C8279D5E97072ULL,
		0xABD7EA69F2D68BDEULL,
		0x8BFD7D047E3E5DA8ULL,
		0x25AB0C10DBC72758ULL,
		0xCEFC8F8E6E140790ULL,
		0xED4721ECCB91211CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35993A4465870F64ULL,
		0x9D5F598ED081A6FAULL,
		0x95256E445332609BULL,
		0x8F09E0FC59D7C93BULL,
		0x49AB4028EADAB552ULL,
		0x81A363E2191112E5ULL,
		0x0358993FB7C70D0AULL,
		0x42811F97DC9CCF01ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB2DE47F6AE0FBDFDULL,
		0x41AFF03E41F5D7FFULL,
		0x3717143582B70FD7ULL,
		0x1CCE096D98FEC2A3ULL,
		0x42523CDB9363A856ULL,
		0xA407A82EC2B61473ULL,
		0xCBA3F64EB64CFA85ULL,
		0xAAC60254EEF4521BULL
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
		0x29DD19C1405852EFULL,
		0x111B04D15422B12BULL,
		0xB6D39C80FBED6A88ULL,
		0xA8F389C4D32DE686ULL,
		0x9A6583470E8813B4ULL,
		0x2891FB7054D7E3FCULL,
		0xB27BFDB764BDB5FBULL,
		0x918AE231D2FDBBEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFFF40C956C40A07ULL,
		0xEAB103EA28C4395BULL,
		0xD9B5C9B6FA20D261ULL,
		0x35E218C0D0F2B752ULL,
		0x6071DBC21746AEF2ULL,
		0x9A6C9A6716FBF231ULL,
		0x799CE2541DD61A16ULL,
		0xED29C829E0119AA9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x79DDD8F7E99448E8ULL,
		0x266A00E72B5E77CFULL,
		0xDD1DD2CA01CC9826ULL,
		0x73117104023B2F33ULL,
		0x39F3A784F74164C2ULL,
		0x8E2561093DDBF1CBULL,
		0x38DF1B6346E79BE4ULL,
		0xA4611A07F2EC2144ULL
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
		0x10A9A2DA8493A88EULL,
		0x83102936103E5CC5ULL,
		0xE1F3DA0A732B2353ULL,
		0x0D53CC622DA723C1ULL,
		0xF668D6168B6245BBULL,
		0x7AC53DFF332B7E29ULL,
		0x61E6832C3A581C4AULL,
		0xA0BAA037543B1F4FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61312EAA767FF96DULL,
		0x2AFC66413D94ECFAULL,
		0x53D0FA51FD2F8E5BULL,
		0xA512D36A6A7A69E8ULL,
		0x3E92F4B1C8B8EB54ULL,
		0x2ED9EEE841729A0BULL,
		0x3E00C12724CD2C1BULL,
		0x972DB43723D73A41ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAF7874300E13AF21ULL,
		0x5813C2F4D2A96FCAULL,
		0x8E22DFB875FB94F8ULL,
		0x6840F8F7C32CB9D9ULL,
		0xB7D5E164C2A95A66ULL,
		0x4BEB4F16F1B8E41EULL,
		0x23E5C205158AF02FULL,
		0x098CEC003063E50EULL
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
		0x039D9BEF54574A27ULL,
		0x5C3FA8035B850CB5ULL,
		0x226519BFFBC8B124ULL,
		0xA95F49024382DB67ULL,
		0x14F33360EA5CDE1BULL,
		0x61D6CD119B5CFD1CULL,
		0xAAF05BCDEF88ABD7ULL,
		0x0756ED3E4CA4AD8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x746A5277C24B1A9DULL,
		0x19CD779C6E328E33ULL,
		0x20021CBF0EA434FEULL,
		0x559EE24AE560F5E0ULL,
		0x489A8A71E528F859ULL,
		0xF6A966461E04C961ULL,
		0x6658A42FF3DB7673ULL,
		0xD1B42DEB6FAE06B8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8F334977920C2F8AULL,
		0x42723066ED527E81ULL,
		0x0262FD00ED247C26ULL,
		0x53C066B75E21E587ULL,
		0xCC58A8EF0533E5C2ULL,
		0x6B2D66CB7D5833BAULL,
		0x4497B79DFBAD3563ULL,
		0x35A2BF52DCF6A6D2ULL
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
		0x1E79404D6DD451D4ULL,
		0xD8DBEF1C2737AB24ULL,
		0x8C8649776AA18C4BULL,
		0x2A718281D07D288BULL,
		0xD012996AA128C04FULL,
		0xC77C14CF7D33F27DULL,
		0x30676F622CA547FAULL,
		0xE484B9FEF4366D38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CACC9847B83CAE9ULL,
		0xF887A07AF5D9A986ULL,
		0xFD7A7F0756D4F060ULL,
		0x52B0CC7452242715ULL,
		0x4A32F2BBA3774074ULL,
		0x627EC2C29683183FULL,
		0xEFBEC4DB8BBE1462ULL,
		0x71256B3954FC791EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE1CC76C8F25086EBULL,
		0xE0544EA1315E019DULL,
		0x8F0BCA7013CC9BEAULL,
		0xD7C0B60D7E590175ULL,
		0x85DFA6AEFDB17FDAULL,
		0x64FD520CE6B0DA3EULL,
		0x40A8AA86A0E73398ULL,
		0x735F4EC59F39F419ULL
	}};
	sign = 0;
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
		0xC0DC498C28880127ULL,
		0x8A010CC2E5CD40F5ULL,
		0x8F12ACB107D39FFFULL,
		0x689A99951F6D1203ULL,
		0x014F4DB150D17CC3ULL,
		0xB67229F5E327EDD8ULL,
		0x4D2BB72A4FA931BDULL,
		0x7FA5FF077F857C0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C62C3A371D9D547ULL,
		0xFA94365D4F65B657ULL,
		0x3202A0FABD5BE339ULL,
		0xCCD1639CA47B7E4BULL,
		0x7E0BB3C64CC80577ULL,
		0x49576F984151B7BFULL,
		0xD542D825F6F7953DULL,
		0x8199B2887BFA5ACAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x847985E8B6AE2BE0ULL,
		0x8F6CD66596678A9EULL,
		0x5D100BB64A77BCC5ULL,
		0x9BC935F87AF193B8ULL,
		0x834399EB0409774BULL,
		0x6D1ABA5DA1D63618ULL,
		0x77E8DF0458B19C80ULL,
		0xFE0C4C7F038B213FULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x813061AA12C2EC3BULL,
		0xBA5ABE3CE8D8596BULL,
		0x420066FEBB1921A0ULL,
		0xCBCE7F5FD8EFAAADULL,
		0xE23F0B516A90CE75ULL,
		0x134716D34AF8978DULL,
		0x7964E190FD667D85ULL,
		0xD65B00B87591BC5BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9CA02A4A59E13925ULL,
		0x891B6C4E7B9F196FULL,
		0x254ECE8974EAC96BULL,
		0xE26B2D0969816FEBULL,
		0x23AD5E1A0A7585C7ULL,
		0x675D090AE828C672ULL,
		0xCD90EC821A0509BEULL,
		0x8C5D21132102D312ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE490375FB8E1B316ULL,
		0x313F51EE6D393FFBULL,
		0x1CB19875462E5835ULL,
		0xE96352566F6E3AC2ULL,
		0xBE91AD37601B48ADULL,
		0xABEA0DC862CFD11BULL,
		0xABD3F50EE36173C6ULL,
		0x49FDDFA5548EE948ULL
	}};
	sign = 0;
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
		0xF771D204E5D35F0EULL,
		0x39DEB25B4A738B04ULL,
		0x76443925328D81C6ULL,
		0x7C22CBA16CD4B73AULL,
		0x649289A0C2571780ULL,
		0xED4303B34C78C22DULL,
		0x3D640BF58DF2B60FULL,
		0x242169113B5F8E69ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D16A27511FF31CEULL,
		0x8A3804C025CD57DFULL,
		0xDA779D5AC0270D6AULL,
		0x8A08C88B7A619EDFULL,
		0x281D8D333F0F6714ULL,
		0x7A60F42E930B7DC4ULL,
		0x5F6340EFEED53D28ULL,
		0xE39D5D01A84DF790ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAA5B2F8FD3D42D40ULL,
		0xAFA6AD9B24A63325ULL,
		0x9BCC9BCA7266745BULL,
		0xF21A0315F273185AULL,
		0x3C74FC6D8347B06BULL,
		0x72E20F84B96D4469ULL,
		0xDE00CB059F1D78E7ULL,
		0x40840C0F931196D8ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xB404469648CCD4C2ULL,
		0xF39C28E610907EA1ULL,
		0x56E70D83DD4276CEULL,
		0x1AD3FEFB03B7E6CDULL,
		0xAAB18EB6898F2E46ULL,
		0x500ECF8DC506CB1CULL,
		0xE992CC1AE39EDCB2ULL,
		0x6FEE7AFA462751F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D85F591B8ED4284ULL,
		0x3BD51B440548D98CULL,
		0x9ED776311889E797ULL,
		0x4276F285C9193EC5ULL,
		0x4AD32F9D1CCE672CULL,
		0xE4417819443012BFULL,
		0xC3D4B4AF1D715420ULL,
		0xABAAF5B28F2D9BC2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x567E51048FDF923EULL,
		0xB7C70DA20B47A515ULL,
		0xB80F9752C4B88F37ULL,
		0xD85D0C753A9EA807ULL,
		0x5FDE5F196CC0C719ULL,
		0x6BCD577480D6B85DULL,
		0x25BE176BC62D8891ULL,
		0xC4438547B6F9B632ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x582923EFE3615E73ULL,
		0x5B4391C30D2FA90EULL,
		0x4EDE1C701685FB6CULL,
		0x85BCA2F013200C2CULL,
		0x6DB0D52EB2573895ULL,
		0x1DEA1BBC0DFFE916ULL,
		0x3E4AEFF656409A8CULL,
		0x68EC3D9523468AA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7549A5A2D303F735ULL,
		0x2A472D32CE7577B4ULL,
		0x4DFD2354AD164E6AULL,
		0x3509F2B2BF71D3C0ULL,
		0xBBBAD4D979CB3FC8ULL,
		0x41A0019DF5D8B0BFULL,
		0x250DFB573378CD29ULL,
		0x075272D0E610885CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE2DF7E4D105D673EULL,
		0x30FC64903EBA3159ULL,
		0x00E0F91B696FAD02ULL,
		0x50B2B03D53AE386CULL,
		0xB1F60055388BF8CDULL,
		0xDC4A1A1E18273856ULL,
		0x193CF49F22C7CD62ULL,
		0x6199CAC43D360246ULL
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
		0xA63BE74840E84B9BULL,
		0xD6D40163CDDD7B59ULL,
		0x23B9FCE75164050AULL,
		0xE6204A50D532B6C0ULL,
		0x024926081C192ECDULL,
		0x29B7E114F4E000CFULL,
		0x1395ACC71C2A8552ULL,
		0xE946A9C9F2B9E592ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA4A8B2551C463F2ULL,
		0x4DA7020856F924E7ULL,
		0x4B8FDBE0B58025E6ULL,
		0x0725A425AF3E0F03ULL,
		0x70DE7F0ACA38F5BDULL,
		0x6883FB853D887B4AULL,
		0xA643E523C339019BULL,
		0x0640925BF22A3CA5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFBF15C22EF23E7A9ULL,
		0x892CFF5B76E45671ULL,
		0xD82A21069BE3DF24ULL,
		0xDEFAA62B25F4A7BCULL,
		0x916AA6FD51E03910ULL,
		0xC133E58FB7578584ULL,
		0x6D51C7A358F183B6ULL,
		0xE306176E008FA8ECULL
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
		0x21B55775C8D26A6BULL,
		0xD634D3FA6837E103ULL,
		0x48BE18B34F37B80CULL,
		0xAAF54A239BC5E39BULL,
		0x6F99C6512757C347ULL,
		0xBB193923632A5496ULL,
		0xF74FA4B997AC67BEULL,
		0xE32F7DC2A90F1360ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF25EF7644AF97E12ULL,
		0x9FB03286FEE6E2A6ULL,
		0x9CD39AA241CCB81BULL,
		0x173CE485D0F299DFULL,
		0xB22FC29D1D57C3AFULL,
		0x02D6664F3F0191D4ULL,
		0x0AABC53C62AD5EB2ULL,
		0xF88218452679AA51ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2F5660117DD8EC59ULL,
		0x3684A1736950FE5CULL,
		0xABEA7E110D6AFFF1ULL,
		0x93B8659DCAD349BBULL,
		0xBD6A03B409FFFF98ULL,
		0xB842D2D42428C2C1ULL,
		0xECA3DF7D34FF090CULL,
		0xEAAD657D8295690FULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x7EA51E0FA45CA249ULL,
		0x34825C7A003F2B9AULL,
		0x4069FA897891BA4CULL,
		0x5FAAC84473BEF8BFULL,
		0xC0BF6DCE06488A2DULL,
		0x30ECED2894ED4A34ULL,
		0x41083A37C09677D2ULL,
		0xBB80E7E9B645D92CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F23934B1A5C8173ULL,
		0xE18D05E7D676B35BULL,
		0xC6DDCA60FA77DC5DULL,
		0x1ACA063294F73213ULL,
		0x651761A5962681C8ULL,
		0x6B4CC18896C9B6ACULL,
		0x2FB4B21882AA9C61ULL,
		0x6E1309A33F9E6D4AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4F818AC48A0020D6ULL,
		0x52F5569229C8783FULL,
		0x798C30287E19DDEEULL,
		0x44E0C211DEC7C6ABULL,
		0x5BA80C2870220865ULL,
		0xC5A02B9FFE239388ULL,
		0x1153881F3DEBDB70ULL,
		0x4D6DDE4676A76BE2ULL
	}};
	sign = 0;
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
		0x77C488F3D164E43AULL,
		0xB60E950E1BAF2936ULL,
		0x9C8EF9D2041CE6D1ULL,
		0x66755EF1751AE9B7ULL,
		0x99A5B61611EF517BULL,
		0xB9AA3C5EB29DCDDEULL,
		0xD27D7C6425DEDA78ULL,
		0x5DDB04AFAF33B63DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3016D67E390EE0BCULL,
		0x92CE8D2D6F8C483BULL,
		0x4EE089B74306516DULL,
		0x4853FF085964EB73ULL,
		0x72337DF6B894924CULL,
		0x360878DCB49A1368ULL,
		0x41962F0AF75604ADULL,
		0x2D658CA472500554ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x47ADB2759856037EULL,
		0x234007E0AC22E0FBULL,
		0x4DAE701AC1169564ULL,
		0x1E215FE91BB5FE44ULL,
		0x2772381F595ABF2FULL,
		0x83A1C381FE03BA76ULL,
		0x90E74D592E88D5CBULL,
		0x3075780B3CE3B0E9ULL
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
		0x92DD84E498CDE0CFULL,
		0xACB845DBD9355B7EULL,
		0x8E9EC082808771C7ULL,
		0xD53F855A2A4A561BULL,
		0x2C775DB705E3E31BULL,
		0x0C78AAE98D7452A1ULL,
		0xBE5294F22929E6B0ULL,
		0x790936BAA5E8984DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F09A89B33F8FC16ULL,
		0xA2E2863AD29DA8E3ULL,
		0xDB9A188E188CC36FULL,
		0xF12553B03781CF26ULL,
		0x86D8BC764F4FFBBCULL,
		0x47783927C3B0F718ULL,
		0x21FEFF13D79CD4D5ULL,
		0x6B3B51EDC92FD9DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x03D3DC4964D4E4B9ULL,
		0x09D5BFA10697B29BULL,
		0xB304A7F467FAAE58ULL,
		0xE41A31A9F2C886F4ULL,
		0xA59EA140B693E75EULL,
		0xC50071C1C9C35B88ULL,
		0x9C5395DE518D11DAULL,
		0x0DCDE4CCDCB8BE72ULL
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
		0x8A5FBCF67FD7A23FULL,
		0xDF57608BE74245F0ULL,
		0xA0905E81CB249E22ULL,
		0x50BE5E8AEE222340ULL,
		0x31BB09D2C483544FULL,
		0xD6CFE18B810C83B8ULL,
		0xA4E3FF75F2408264ULL,
		0xF74994FF0BC40EFBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7AA6FDDA5D6AC139ULL,
		0xB6A6F01BD3A12A06ULL,
		0xCEBF20D0EAE79705ULL,
		0x9AE971FC0F99B647ULL,
		0xF1B5AD41A9057B4CULL,
		0x1B3E132DE0411E22ULL,
		0x32C413459C718A8AULL,
		0x4728B3D42529874DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0FB8BF1C226CE106ULL,
		0x28B0707013A11BEAULL,
		0xD1D13DB0E03D071DULL,
		0xB5D4EC8EDE886CF8ULL,
		0x40055C911B7DD902ULL,
		0xBB91CE5DA0CB6595ULL,
		0x721FEC3055CEF7DAULL,
		0xB020E12AE69A87AEULL
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
		0x08D3E26AE7DB30BCULL,
		0x54F21A22F882E357ULL,
		0xD2D90B5FEB6A8BC8ULL,
		0x2D5C35C9B44E2602ULL,
		0x73EAAA02783B6863ULL,
		0x5968E1C828878263ULL,
		0x91B5975241A36A10ULL,
		0xAA36F7DFCCDB4C30ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8EC6E750CF6937BAULL,
		0xFABA55AF10872F8BULL,
		0x94A3183661E0DA16ULL,
		0x2CA9B41C74697841ULL,
		0x63A8977CA08C0410ULL,
		0x935BFCB719F549DAULL,
		0x1759EFABC3BAFC49ULL,
		0xCF8E8D1E2CB59526ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7A0CFB1A1871F902ULL,
		0x5A37C473E7FBB3CBULL,
		0x3E35F3298989B1B1ULL,
		0x00B281AD3FE4ADC1ULL,
		0x10421285D7AF6453ULL,
		0xC60CE5110E923889ULL,
		0x7A5BA7A67DE86DC6ULL,
		0xDAA86AC1A025B70AULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x79C95157276D5B58ULL,
		0x0E917C552A65902AULL,
		0x5FF3ECED18AFA20DULL,
		0x400A81B9F7E5E735ULL,
		0xDAE8F5F5BDA744B5ULL,
		0x620DC01FA6B6DBA5ULL,
		0xE40871948C6816DCULL,
		0x410C462AF1BC11E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1003B02FD3123EA3ULL,
		0x7D63D68EAF1C2147ULL,
		0x9FB6349D1CFD93C8ULL,
		0x57D52A24F92112EDULL,
		0x5EF925D757EC4B6FULL,
		0x6A56188168003218ULL,
		0x1734291646542281ULL,
		0xB897EF524C2298B7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x69C5A127545B1CB5ULL,
		0x912DA5C67B496EE3ULL,
		0xC03DB84FFBB20E44ULL,
		0xE8355794FEC4D447ULL,
		0x7BEFD01E65BAF945ULL,
		0xF7B7A79E3EB6A98DULL,
		0xCCD4487E4613F45AULL,
		0x887456D8A5997931ULL
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
		0xF0B8C855C9059A09ULL,
		0xC5EEEE946BD6EB76ULL,
		0xFA79BAD6AC1CC9CAULL,
		0xDC25900BD6FA2766ULL,
		0x5051A6313A9DE861ULL,
		0xD251F0E3BC8D0FE5ULL,
		0x8F111D6F72B7F9E5ULL,
		0x92DC6E5113F26FBBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE1E4FF0008BF055ULL,
		0x037DD659672E38AEULL,
		0x69FE837812A1D389ULL,
		0x194CC99ED984B6E3ULL,
		0x73C11BE33DDE6934ULL,
		0x646B54B03BA63B40ULL,
		0xC09A5B75AE85ED62ULL,
		0x41DFCD45A7958C51ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x029A7865C879A9B4ULL,
		0xC271183B04A8B2C8ULL,
		0x907B375E997AF641ULL,
		0xC2D8C66CFD757083ULL,
		0xDC908A4DFCBF7F2DULL,
		0x6DE69C3380E6D4A4ULL,
		0xCE76C1F9C4320C83ULL,
		0x50FCA10B6C5CE369ULL
	}};
	sign = 0;
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
		0x6716567B1C501B43ULL,
		0x4D2B9B1CB1785EB8ULL,
		0x4482B940D883B755ULL,
		0x5A9C4E98C88D7F84ULL,
		0x2F8CE8AEEA50CAB8ULL,
		0xDEB96B9381ECF971ULL,
		0x60811C60E75234DCULL,
		0x6DD6594056EE3D4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7BE54E766DD0E492ULL,
		0x2927BA60334BAE15ULL,
		0x5FEDB248E858A7AEULL,
		0xEE3E04D566E3E172ULL,
		0x23230A3BFA5D367DULL,
		0x613B974563D3C649ULL,
		0xF6AA8E01E0C0E7C1ULL,
		0x8967E1991A485DD7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEB310804AE7F36B1ULL,
		0x2403E0BC7E2CB0A2ULL,
		0xE49506F7F02B0FA7ULL,
		0x6C5E49C361A99E11ULL,
		0x0C69DE72EFF3943AULL,
		0x7D7DD44E1E193328ULL,
		0x69D68E5F06914D1BULL,
		0xE46E77A73CA5DF75ULL
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
		0xF01D760E9B304C28ULL,
		0x56A71F687302A5CBULL,
		0x9CB7B6D7CC5562D1ULL,
		0xA67D25F286FF352DULL,
		0xADB25D8D608B7F72ULL,
		0xF47F31EB7DDB4C16ULL,
		0xB8376FAE3203884BULL,
		0xA451126E79B5E602ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71452E3867EEB55BULL,
		0x4DB46B6B41BB863CULL,
		0xE4A467DE6F4D817BULL,
		0x420F5CA427230DAAULL,
		0x9F00E487E18F0503ULL,
		0xDAD569B6E82E7ABDULL,
		0xA582840708A6E387ULL,
		0x84D4AF5F9CB6D0D3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7ED847D6334196CDULL,
		0x08F2B3FD31471F8FULL,
		0xB8134EF95D07E156ULL,
		0x646DC94E5FDC2782ULL,
		0x0EB179057EFC7A6FULL,
		0x19A9C83495ACD159ULL,
		0x12B4EBA7295CA4C4ULL,
		0x1F7C630EDCFF152FULL
	}};
	sign = 0;
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
		0xA8E5A785B8B6E959ULL,
		0x1D507AD5C5E1AEEFULL,
		0x303AAC43E5C6E746ULL,
		0x4F41AA2E91FD2C56ULL,
		0xE2710B5B05E37632ULL,
		0xC94D7308A3812EC2ULL,
		0x267DA07588DF2644ULL,
		0xD9BA76C1B213D14BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x201DA5D5DA85B7F6ULL,
		0x0E54FDB881FF70FEULL,
		0x1FFC27EF059AB3CDULL,
		0xFFFDB1C201BC04F6ULL,
		0x2CE4684E203AE7E9ULL,
		0x1D5ED35646916B33ULL,
		0x26377B19700B6C61ULL,
		0x3B6F2110939B6C53ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x88C801AFDE313163ULL,
		0x0EFB7D1D43E23DF1ULL,
		0x103E8454E02C3379ULL,
		0x4F43F86C90412760ULL,
		0xB58CA30CE5A88E48ULL,
		0xABEE9FB25CEFC38FULL,
		0x0046255C18D3B9E3ULL,
		0x9E4B55B11E7864F8ULL
	}};
	sign = 0;
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
		0x79B0C1F3BB88AE34ULL,
		0xEEE41AFB57BD807AULL,
		0xC835FF5F38A4EE5AULL,
		0x6D9952F96FB2ED6CULL,
		0x6FF3A69646767FF2ULL,
		0xD0725EAE58382ECDULL,
		0x5B5201751377BABBULL,
		0xBAB573401BD3B27BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD49E744EFA98B026ULL,
		0x374E3C92CE6AD178ULL,
		0xAD24C4EDE042CF39ULL,
		0x45C0EF8AC38429B9ULL,
		0xBF6DA75FEBDC72EFULL,
		0x2463E806B9249FF4ULL,
		0xE4CE9DD902C1D564ULL,
		0x9D10EB5CCB474986ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA5124DA4C0EFFE0EULL,
		0xB795DE688952AF01ULL,
		0x1B113A7158621F21ULL,
		0x27D8636EAC2EC3B3ULL,
		0xB085FF365A9A0D03ULL,
		0xAC0E76A79F138ED8ULL,
		0x7683639C10B5E557ULL,
		0x1DA487E3508C68F4ULL
	}};
	sign = 0;
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
		0x61FD91671AE592F2ULL,
		0xFB4B8CBA472887AAULL,
		0xA0A36A4A8F37C40CULL,
		0x170D65D13E03C701ULL,
		0xB1467830FD63795AULL,
		0x9265F6F63C23E560ULL,
		0xB586DF4A6CC8BF56ULL,
		0x25735E34C7C9AB23ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89C89440186A9745ULL,
		0xE271EF4D64A1606FULL,
		0x801175AD64CD2830ULL,
		0xEE57ACB9072A5ECCULL,
		0x775EE254A4D6CE55ULL,
		0x86376A5E8C841FD6ULL,
		0x8AFCBD0BDF57753EULL,
		0xD744E67B7F54921BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD834FD27027AFBADULL,
		0x18D99D6CE287273AULL,
		0x2091F49D2A6A9BDCULL,
		0x28B5B91836D96835ULL,
		0x39E795DC588CAB04ULL,
		0x0C2E8C97AF9FC58AULL,
		0x2A8A223E8D714A18ULL,
		0x4E2E77B948751908ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xDE455FE2495692BFULL,
		0x4585B101FE337A9CULL,
		0x81D513418EF078F5ULL,
		0x56AE0D99AFCF0C6EULL,
		0x7ADCCA3D189075A7ULL,
		0xE0D149EE000D1C9FULL,
		0xBA5D17866F1F3F5BULL,
		0x7F374EC9A98B1546ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81AE05E6FD1007CFULL,
		0xB8961ECEFFD93B77ULL,
		0x8E96D7C93E358158ULL,
		0xE1EA0536FFEAFB35ULL,
		0x838957C6196C1E13ULL,
		0xCEF21C8AD37C317AULL,
		0xF1BAFD4338CCF66AULL,
		0xA3014645AD5A35FCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5C9759FB4C468AF0ULL,
		0x8CEF9232FE5A3F25ULL,
		0xF33E3B7850BAF79CULL,
		0x74C40862AFE41138ULL,
		0xF7537276FF245793ULL,
		0x11DF2D632C90EB24ULL,
		0xC8A21A43365248F1ULL,
		0xDC360883FC30DF49ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xC3C9080A19DB4030ULL,
		0xA5DC8B8158EBEF31ULL,
		0xD36E1BB2D3C05F7FULL,
		0x9269FC35F2AE6310ULL,
		0xAF8D67477C488931ULL,
		0xB3E3EB374F3D5B6BULL,
		0x7D7AC5CB65C075E6ULL,
		0x230C990EB35BCD1FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6931E0D9F7F954EULL,
		0x0ADBF9BBCC291939ULL,
		0x771902211C4B55DAULL,
		0x2FFDA2F6EDAE7772ULL,
		0x8E848D7A5083B401ULL,
		0x1DC0755DBDB8BC6BULL,
		0x168C581CB86106AFULL,
		0x0EFDF2DB8A106970ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFD35E9FC7A5BAAE2ULL,
		0x9B0091C58CC2D5F7ULL,
		0x5C551991B77509A5ULL,
		0x626C593F04FFEB9EULL,
		0x2108D9CD2BC4D530ULL,
		0x962375D991849F00ULL,
		0x66EE6DAEAD5F6F37ULL,
		0x140EA633294B63AFULL
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
		0xD275A7A49B17C6EEULL,
		0x6C81591FED5F9428ULL,
		0x2AC882510D755B8EULL,
		0x1D42C44164658A0FULL,
		0xD630CF5E1C681842ULL,
		0x42050AF29D803738ULL,
		0xD20401EB600FED3DULL,
		0x6AF86D42B1092534ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDD66E0693A8760FULL,
		0xDCAD773FEA9A2F85ULL,
		0xA2CD28FAC9F25DA9ULL,
		0xF2EE57C952A6C694ULL,
		0x64BBE5BDC5AA28D2ULL,
		0xC6580F051D75BCB6ULL,
		0xB8A91D487FA8364FULL,
		0x3B04D2E1D2B8FAA0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE49F399E076F50DFULL,
		0x8FD3E1E002C564A2ULL,
		0x87FB59564382FDE4ULL,
		0x2A546C7811BEC37AULL,
		0x7174E9A056BDEF6FULL,
		0x7BACFBED800A7A82ULL,
		0x195AE4A2E067B6EDULL,
		0x2FF39A60DE502A94ULL
	}};
	sign = 0;
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
		0xA11A201C3B85A9D2ULL,
		0x9FF9AB6B0B3AC3A9ULL,
		0x524B5C7A7DEDD151ULL,
		0xEDBA1E48C9896DE7ULL,
		0xC03E1CD7EB942585ULL,
		0x6B532EC33C9D8ED8ULL,
		0xDDA7CA08E0CE8889ULL,
		0x73EE3241DE4F255DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40590132B6DDC956ULL,
		0x7AAAF7456218DCF5ULL,
		0x9FD84AB40DF0B188ULL,
		0xEF190E3C78A97E82ULL,
		0x1007480DFE98B7DCULL,
		0x7B72B19F0BCB4292ULL,
		0xA92F22CA383CABF7ULL,
		0x4FA749D882A22F6BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x60C11EE984A7E07CULL,
		0x254EB425A921E6B4ULL,
		0xB27311C66FFD1FC9ULL,
		0xFEA1100C50DFEF64ULL,
		0xB036D4C9ECFB6DA8ULL,
		0xEFE07D2430D24C46ULL,
		0x3478A73EA891DC91ULL,
		0x2446E8695BACF5F2ULL
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
		0xBECA54EA70DBA960ULL,
		0x5AEF6C55008D9D98ULL,
		0xC890FE7B542F5175ULL,
		0xE36CF3238C48FED6ULL,
		0x838965D2175E8607ULL,
		0x1AD9500B58696F20ULL,
		0x6925E02F2768B9F9ULL,
		0x18806C8FDCB19892ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF23725207C407548ULL,
		0xE843802842E7F75FULL,
		0xD35459266D91E095ULL,
		0x35AEE089BCCFD511ULL,
		0x3C7E13BB0AC9804AULL,
		0xFD35D2248264440EULL,
		0x4ECE14DD49EFCD77ULL,
		0xB51FE19E4159BE00ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCC932FC9F49B3418ULL,
		0x72ABEC2CBDA5A638ULL,
		0xF53CA554E69D70DFULL,
		0xADBE1299CF7929C4ULL,
		0x470B52170C9505BDULL,
		0x1DA37DE6D6052B12ULL,
		0x1A57CB51DD78EC81ULL,
		0x63608AF19B57DA92ULL
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
		0xF2A1FE49A71A6E63ULL,
		0xA955249D3B3B2F5DULL,
		0x803A4E9501166F0FULL,
		0xABBD36C11566A7E3ULL,
		0xBB54CEF108079F88ULL,
		0x9F08A1DFF36C20FEULL,
		0x20B3C94AA64868F2ULL,
		0x0039DBF8C3DDF78EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC663601438CD1A1ULL,
		0xEF76C93410A2762EULL,
		0x2FFD1C9226F547D9ULL,
		0x66BBFFEB1FEDAE1FULL,
		0xDE9B6DC5A1747034ULL,
		0x6C6D062FA4B55E2BULL,
		0x0ED0C6DE865AA0CAULL,
		0x6FCC606FF45CF1C5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x363BC848638D9CC2ULL,
		0xB9DE5B692A98B92FULL,
		0x503D3202DA212735ULL,
		0x450136D5F578F9C4ULL,
		0xDCB9612B66932F54ULL,
		0x329B9BB04EB6C2D2ULL,
		0x11E3026C1FEDC828ULL,
		0x906D7B88CF8105C9ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x53278372A5B945D6ULL,
		0xD15685DDE8C4D390ULL,
		0xF8915E6B76D810EFULL,
		0x26D03465F45FF1C0ULL,
		0xFFDFC562B249322EULL,
		0x047D7FBE0DD5DAF5ULL,
		0x3E70196A73B9A216ULL,
		0xFEF1577E84923F27ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32B6FF32EADDF659ULL,
		0xF5E4FCCF619BD4BCULL,
		0xB9A43852B828B876ULL,
		0x9F3F024CED667947ULL,
		0x90BF9D4EA81509FEULL,
		0x0C9A25654DFA56E0ULL,
		0x76D9D510331B6770ULL,
		0xD8973ED1BBB772B3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2070843FBADB4F7DULL,
		0xDB71890E8728FED4ULL,
		0x3EED2618BEAF5878ULL,
		0x8791321906F97879ULL,
		0x6F2028140A34282FULL,
		0xF7E35A58BFDB8415ULL,
		0xC796445A409E3AA5ULL,
		0x265A18ACC8DACC73ULL
	}};
	sign = 0;
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
		0xDF57641D890D84CEULL,
		0x7892D2FAB1D4ADEAULL,
		0xF1807741836C26AAULL,
		0x9C9FA293F86BBE5FULL,
		0xCBF70A237EAA0B5CULL,
		0x87550053C3292705ULL,
		0x8AE76B4BE1DBBFFEULL,
		0xC05E04A4E096B6C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FAC310C48E11733ULL,
		0x4670E323D8AA1B03ULL,
		0x57BA7747BCCCFB37ULL,
		0x1B56801FB1801ADCULL,
		0x2448CED33AE4D92CULL,
		0x94D24347D0F01D39ULL,
		0xA8D40DC7201A5758ULL,
		0x98F3E49727182234ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAFAB3311402C6D9BULL,
		0x3221EFD6D92A92E7ULL,
		0x99C5FFF9C69F2B73ULL,
		0x8149227446EBA383ULL,
		0xA7AE3B5043C53230ULL,
		0xF282BD0BF23909CCULL,
		0xE2135D84C1C168A5ULL,
		0x276A200DB97E948FULL
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
		0xCBB85EA74F76CB38ULL,
		0x75689A7CEBFCABB8ULL,
		0x5CCEF96692F8B46DULL,
		0xE3F4E45BEA09B834ULL,
		0x30300AF12147A348ULL,
		0x1340091FF23E2804ULL,
		0xDC4B47A070CF8464ULL,
		0x40122C63BEAC9DFEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71B4EA438F672604ULL,
		0x06A3601B1F171E47ULL,
		0xB63061873EDD866FULL,
		0xCBBB5FEF2D6FDFA9ULL,
		0xFC5B2ABA0F213C99ULL,
		0x2685A1C733A5A1FAULL,
		0xAB30FE3878CC0855ULL,
		0xDDAEA02A261E734FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5A037463C00FA534ULL,
		0x6EC53A61CCE58D71ULL,
		0xA69E97DF541B2DFEULL,
		0x1839846CBC99D88AULL,
		0x33D4E037122666AFULL,
		0xECBA6758BE988609ULL,
		0x311A4967F8037C0EULL,
		0x62638C39988E2AAFULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xE965F9089161281AULL,
		0xA2A2541C54DA0054ULL,
		0x689F834D5DE93DCDULL,
		0xD4050BA6E217C934ULL,
		0x007448E522056C5FULL,
		0x504D4BF7B113807AULL,
		0xF10D85B21728996FULL,
		0x326C27DBC625600DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65D5CA5A0A16D306ULL,
		0x449547FAC50CB9CCULL,
		0x6B0521E6A9A7B281ULL,
		0x49E3B45C031868D1ULL,
		0xA231BF4FE41EBA9BULL,
		0x5378C79B139D66AEULL,
		0xB7F4A34DCE79CB3EULL,
		0xF5545484E8EAACD5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x83902EAE874A5514ULL,
		0x5E0D0C218FCD4688ULL,
		0xFD9A6166B4418B4CULL,
		0x8A21574ADEFF6062ULL,
		0x5E4289953DE6B1C4ULL,
		0xFCD4845C9D7619CBULL,
		0x3918E26448AECE30ULL,
		0x3D17D356DD3AB338ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xC94AF6371313864AULL,
		0x4DF287E91D3879E6ULL,
		0xA62CED46B2C2FE97ULL,
		0x6136CED9BCC29D50ULL,
		0xFECBAB8482AA83EBULL,
		0x3B2E2DB24C203E12ULL,
		0xF48C2D1488EFF91CULL,
		0xC660FA0E6F04E287ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x647C3DC1BCA5F071ULL,
		0x7A9261B98E0F265FULL,
		0x0BB3FAFB5820353EULL,
		0x62E7B473ACD93B82ULL,
		0x4A6B7F0F8E27745CULL,
		0xFE3000C5BE5D2938ULL,
		0x5F6B513F89D7B41FULL,
		0x1C61F1118672E640ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x64CEB875566D95D9ULL,
		0xD360262F8F295387ULL,
		0x9A78F24B5AA2C958ULL,
		0xFE4F1A660FE961CEULL,
		0xB4602C74F4830F8EULL,
		0x3CFE2CEC8DC314DAULL,
		0x9520DBD4FF1844FCULL,
		0xA9FF08FCE891FC47ULL
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
		0x7309A5F61B0FD672ULL,
		0xD6A0EE69B63A75E6ULL,
		0x3D41007B8FDF7999ULL,
		0x4C3B4BFF415D45D3ULL,
		0x9ABBB1BA146B48D3ULL,
		0x88A6C7FBEB9C5627ULL,
		0x098E9D9A8E43C113ULL,
		0x2A4F6E9534280F38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F17BB00D42EFF8BULL,
		0xCD8E907BC03E18AFULL,
		0x56C146D7FD71E145ULL,
		0x3C9AA3E84B05477FULL,
		0xDAF1CD766B351042ULL,
		0x0211F609A356DA7EULL,
		0x0DD299E0204675A3ULL,
		0xC8C4A244EA473898ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x53F1EAF546E0D6E7ULL,
		0x09125DEDF5FC5D37ULL,
		0xE67FB9A3926D9854ULL,
		0x0FA0A816F657FE53ULL,
		0xBFC9E443A9363891ULL,
		0x8694D1F248457BA8ULL,
		0xFBBC03BA6DFD4B70ULL,
		0x618ACC5049E0D69FULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xB2E87FB96CA2B33FULL,
		0xA60CC3D8F3C8A5EBULL,
		0xE44BDEECAAA0E60FULL,
		0xDF0E62506CF952A4ULL,
		0x2BE7465040B95CFEULL,
		0xD29E13F4132519DEULL,
		0x2644FA710840FF03ULL,
		0xDA190B2E57DF049DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10A902CAC3CBEA0FULL,
		0x863A3B5F9ED8CAB1ULL,
		0x8ACC599A40AE45B2ULL,
		0x1F81896A3AB7F859ULL,
		0x560EC5632DE00C72ULL,
		0x873912C450B23B27ULL,
		0x5C9FE26B6DF840D6ULL,
		0x2408B4AD6874C114ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA23F7CEEA8D6C930ULL,
		0x1FD2887954EFDB3AULL,
		0x597F855269F2A05DULL,
		0xBF8CD8E632415A4BULL,
		0xD5D880ED12D9508CULL,
		0x4B65012FC272DEB6ULL,
		0xC9A518059A48BE2DULL,
		0xB6105680EF6A4388ULL
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
		0x31E0E5EA75BFFE9BULL,
		0x1815684F90251BB7ULL,
		0x75E8BE807378DEDDULL,
		0x719ECE3D9E9A5D86ULL,
		0x34C604A344FDD004ULL,
		0x12F193C37AE1F22AULL,
		0xA1942CB31DB42A1CULL,
		0xEC8E94B6DF4C0140ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x303EFF442DD78E37ULL,
		0x3ECAA37A67DD4702ULL,
		0x455AE0E0EE35CF7FULL,
		0xD8B8B7F8729E4E10ULL,
		0x9ECE11070DB5E504ULL,
		0x25FE88203A72F4E4ULL,
		0x1B5FD26335CAF6CFULL,
		0xD9244D4DE308D73BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01A1E6A647E87064ULL,
		0xD94AC4D52847D4B5ULL,
		0x308DDD9F85430F5DULL,
		0x98E616452BFC0F76ULL,
		0x95F7F39C3747EAFFULL,
		0xECF30BA3406EFD45ULL,
		0x86345A4FE7E9334CULL,
		0x136A4768FC432A05ULL
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
		0x932EC42EEA8C20B7ULL,
		0x0AEAF2AE4C60D12FULL,
		0x36D939A121C4A3B3ULL,
		0xDE4B32024B2FE8B3ULL,
		0x1D18D597FA3492E5ULL,
		0x24B0EE7B24DF979FULL,
		0x976158841A747F2AULL,
		0x48337B26C744B24EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E439582D883358DULL,
		0xF682501851BB243FULL,
		0x26081EF170D8BFA8ULL,
		0x3E427FCB3E79FCFEULL,
		0xD40C2FBA88CA9534ULL,
		0xF9CFAF62E4053C95ULL,
		0xC7E7E44E9C0872E3ULL,
		0xD926BA2DA7BC43C6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x24EB2EAC1208EB2AULL,
		0x1468A295FAA5ACF0ULL,
		0x10D11AAFB0EBE40AULL,
		0xA008B2370CB5EBB5ULL,
		0x490CA5DD7169FDB1ULL,
		0x2AE13F1840DA5B09ULL,
		0xCF7974357E6C0C46ULL,
		0x6F0CC0F91F886E87ULL
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
		0x42E32EA079C0454CULL,
		0x61DB3706FE4FD825ULL,
		0x74D095DF319D2B7EULL,
		0xD83BCF611B261F8BULL,
		0x897F42F711BB7782ULL,
		0xAE31B32DF5934687ULL,
		0x6C86860130A51BC1ULL,
		0x3E749BB8EA7BA6B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9DFB467B34FD925ULL,
		0x126CD8A4C97C4E51ULL,
		0x9F9C90AC3FAC98F1ULL,
		0x3E0461F17619160AULL,
		0x0385F0EAE059572DULL,
		0xCFE0DE0CC1A4335BULL,
		0x9A144E6103B8FD53ULL,
		0x7D3EA23002E369E3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x59037A38C6706C27ULL,
		0x4F6E5E6234D389D3ULL,
		0xD5340532F1F0928DULL,
		0x9A376D6FA50D0980ULL,
		0x85F9520C31622055ULL,
		0xDE50D52133EF132CULL,
		0xD27237A02CEC1E6DULL,
		0xC135F988E7983CCDULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x082FA76AC3824560ULL,
		0x9B4A1A8D9FB85865ULL,
		0xC98BBDB16BD73E56ULL,
		0xB13B15009766D6BEULL,
		0x2B7A23FDA1E9743AULL,
		0xB200844025BA2DC1ULL,
		0xE71246CCB54E4AD8ULL,
		0xB6C68FAECD453300ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC592EAEB7AF7D9DBULL,
		0x00854630C7FE643FULL,
		0x627FE90DC4EE563BULL,
		0x7211BA00BBFD0C16ULL,
		0x5498F6A0C6C317FDULL,
		0xFFA5028C0109720BULL,
		0xD2D02C93EAC2D44FULL,
		0x72D184367A54E447ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x429CBC7F488A6B85ULL,
		0x9AC4D45CD7B9F425ULL,
		0x670BD4A3A6E8E81BULL,
		0x3F295AFFDB69CAA8ULL,
		0xD6E12D5CDB265C3DULL,
		0xB25B81B424B0BBB5ULL,
		0x14421A38CA8B7688ULL,
		0x43F50B7852F04EB9ULL
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
		0x833ACB6817A42930ULL,
		0x8A1EF19C81C2CABEULL,
		0xCDC24BD4E12F3D6FULL,
		0xB99307391BACAD69ULL,
		0x2C6AD4B8511B9CF0ULL,
		0x92F0D2452A319658ULL,
		0x78C54F78DAEAEB8FULL,
		0x77E1667D817BC402ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7DF4B3B5694FAD4ULL,
		0x0F044529FECD614DULL,
		0xC9C1B9A54487529FULL,
		0xC247C81912BE4FF4ULL,
		0x2B30C39088A05C0AULL,
		0x9377B5BB2DAF6B31ULL,
		0x42E218D97DF5E431ULL,
		0xE381C9CAF4C62087ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8B5B802CC10F2E5CULL,
		0x7B1AAC7282F56970ULL,
		0x0400922F9CA7EAD0ULL,
		0xF74B3F2008EE5D75ULL,
		0x013A1127C87B40E5ULL,
		0xFF791C89FC822B27ULL,
		0x35E3369F5CF5075DULL,
		0x945F9CB28CB5A37BULL
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
		0xB187A24C3733C694ULL,
		0x028EC3C67256827CULL,
		0xC069E5970F98A400ULL,
		0x3B2774AB9C996A53ULL,
		0xE7CA79E89E7318BCULL,
		0xA906F8628B601A6FULL,
		0xD06745FBAC04D6E0ULL,
		0xDD492F34EA8F6834ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x199C57650C5E1C62ULL,
		0x722D75ABBADD5ECCULL,
		0x603A01E7959E2013ULL,
		0x798FB6B21F541044ULL,
		0x3D39628D03E241EFULL,
		0xB3E7B80D3DC17349ULL,
		0x4BB4396EE64546C7ULL,
		0x1786453C83AFF09BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x97EB4AE72AD5AA32ULL,
		0x90614E1AB77923B0ULL,
		0x602FE3AF79FA83ECULL,
		0xC197BDF97D455A0FULL,
		0xAA91175B9A90D6CCULL,
		0xF51F40554D9EA726ULL,
		0x84B30C8CC5BF9018ULL,
		0xC5C2E9F866DF7799ULL
	}};
	sign = 0;
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
		0x6F54D4BF6FC503B5ULL,
		0x679C49B17B77E449ULL,
		0x3F192D9513D8B561ULL,
		0x21E43A271F19BA42ULL,
		0xC64BAEFA273ED130ULL,
		0xCB7D12F3487463EEULL,
		0x3F43F0E93419B63CULL,
		0xE633BC6A4974345BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E5AD07433BFA2BFULL,
		0x90267659FBFBCB66ULL,
		0x5B0DF80315D10247ULL,
		0x269E253F5334DBCCULL,
		0x698647DBE3EA0916ULL,
		0xBC454A1C5E855546ULL,
		0x556B398A4FA9EE8BULL,
		0xB78DBF874B33C844ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD0FA044B3C0560F6ULL,
		0xD775D3577F7C18E2ULL,
		0xE40B3591FE07B319ULL,
		0xFB4614E7CBE4DE75ULL,
		0x5CC5671E4354C819ULL,
		0x0F37C8D6E9EF0EA8ULL,
		0xE9D8B75EE46FC7B1ULL,
		0x2EA5FCE2FE406C16ULL
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
		0xEF27B789E6E19F72ULL,
		0x4A3DF618E8A38732ULL,
		0x0E9E9AF762129220ULL,
		0x62C4C696986B07F6ULL,
		0xAC92CFDFCA3563E5ULL,
		0xA52275562F208389ULL,
		0x94293B04C72DE4C6ULL,
		0x651F53DC30D5F801ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA14C57CCFAD94F55ULL,
		0x3C4CFE56793DDD21ULL,
		0x01E3E8D952845D57ULL,
		0x066196BB21AD4134ULL,
		0x152BDAAFD2B74A49ULL,
		0xDAAD16400207E639ULL,
		0xAED0A421B3E47247ULL,
		0x8B66D1250C799BE7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4DDB5FBCEC08501DULL,
		0x0DF0F7C26F65AA11ULL,
		0x0CBAB21E0F8E34C9ULL,
		0x5C632FDB76BDC6C2ULL,
		0x9766F52FF77E199CULL,
		0xCA755F162D189D50ULL,
		0xE55896E31349727EULL,
		0xD9B882B7245C5C19ULL
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
		0x8E4A75B27C23C161ULL,
		0x39018D308E7D1114ULL,
		0x6F39DBB5ED5ED8C8ULL,
		0x39AA88B15CB186B5ULL,
		0x0B550526DC4295E3ULL,
		0x6B6B2F2959AA03ACULL,
		0x4CF0D56E0DBE67E8ULL,
		0xB78059CBFE68AC36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC8BD38B4C67CB99ULL,
		0xC2478B9551A924D6ULL,
		0x6873730FF665EF3AULL,
		0x84EAD9081A876ED1ULL,
		0x39BDE123C8566C8FULL,
		0x40381017D116F5E7ULL,
		0xA95923B099467EDDULL,
		0x9BED4328799EC988ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD1BEA2272FBBF5C8ULL,
		0x76BA019B3CD3EC3DULL,
		0x06C668A5F6F8E98DULL,
		0xB4BFAFA9422A17E4ULL,
		0xD197240313EC2953ULL,
		0x2B331F1188930DC4ULL,
		0xA397B1BD7477E90BULL,
		0x1B9316A384C9E2ADULL
	}};
	sign = 0;
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
		0x8EBEFE9EDAC0B57EULL,
		0xAE861237226D21F5ULL,
		0xBB265868CD9DBD1BULL,
		0xE7FE7E3A3E7249D5ULL,
		0x74DE8140B7CC8AD8ULL,
		0xEDD3C043B471CFFAULL,
		0xF02BF427F76B9C43ULL,
		0xFE8C425B19162DBDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED906B714A5A4A52ULL,
		0x4CC30953B4877A0EULL,
		0x76145A4026C7CE9CULL,
		0xDCFB22DDCC70B430ULL,
		0x9612B337EA35AFAAULL,
		0x5CE20CDE5370C567ULL,
		0x227AB34B59FC6084ULL,
		0xF751FF10C77E32BFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA12E932D90666B2CULL,
		0x61C308E36DE5A7E6ULL,
		0x4511FE28A6D5EE7FULL,
		0x0B035B5C720195A5ULL,
		0xDECBCE08CD96DB2EULL,
		0x90F1B36561010A92ULL,
		0xCDB140DC9D6F3BBFULL,
		0x073A434A5197FAFEULL
	}};
	sign = 0;
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
		0xD31CD62CB2AE5094ULL,
		0x476F00211A274388ULL,
		0x145B37806091DB64ULL,
		0x646AB04D672D16A0ULL,
		0x6084863FAE8CD63FULL,
		0xB1748BA883EFEB9DULL,
		0x6796BF2213D87C9CULL,
		0x85511CBD875D084FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86D276B19AE9301EULL,
		0x8A3D5A56F6C5CE10ULL,
		0x064E9EF8BFB5A78DULL,
		0xA6D57B5D74AA978EULL,
		0xBB97FC1155AF0A61ULL,
		0x0B0F545F14DFD0E4ULL,
		0x530EDCD50EEED1C7ULL,
		0xD2F4FB6E8309F479ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4C4A5F7B17C52076ULL,
		0xBD31A5CA23617578ULL,
		0x0E0C9887A0DC33D6ULL,
		0xBD9534EFF2827F12ULL,
		0xA4EC8A2E58DDCBDDULL,
		0xA66537496F101AB8ULL,
		0x1487E24D04E9AAD5ULL,
		0xB25C214F045313D6ULL
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
		0x2CEE7B9AA4F721C5ULL,
		0xBCED7713985E6F89ULL,
		0x515F0B08DAE6B726ULL,
		0x2B5FF28FB403F06AULL,
		0x7F74569DABD9A049ULL,
		0xD45F1327742BBAA3ULL,
		0x1FFA5981895B728AULL,
		0xE9DE8DD03F7EDE43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA40A1957CF859B98ULL,
		0x9D5A7A4B10E61D91ULL,
		0x38A22D0B41AB8062ULL,
		0xCD912B1767060DF7ULL,
		0x038CB9A321CD2FFDULL,
		0xCD0BE099F6697615ULL,
		0x266DF63D05987109ULL,
		0xA743E2BD7A241F94ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x88E46242D571862DULL,
		0x1F92FCC8877851F7ULL,
		0x18BCDDFD993B36C4ULL,
		0x5DCEC7784CFDE273ULL,
		0x7BE79CFA8A0C704BULL,
		0x0753328D7DC2448EULL,
		0xF98C634483C30181ULL,
		0x429AAB12C55ABEAEULL
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
		0xE2461DA4A95F6ABAULL,
		0xEE524EFE7A3D5BD8ULL,
		0xE324DE9B1C607BC3ULL,
		0xECB75DF6D9E5E237ULL,
		0xF59A8A10B0E66C45ULL,
		0xDE64C85E7916A7BDULL,
		0xD3978BF2754DB235ULL,
		0x30F66B801B585972ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4FF57384B38E431ULL,
		0xB5BB95BE1F7A277CULL,
		0x1C2D84DB0E02062CULL,
		0xB61A5FE5406B3392ULL,
		0x952B6B52854AC0B1ULL,
		0x6A28B8E1A58B36A3ULL,
		0x38525DECE87C6127ULL,
		0xF4F748D5E76AFC86ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFD46C66C5E268689ULL,
		0x3896B9405AC3345BULL,
		0xC6F759C00E5E7597ULL,
		0x369CFE11997AAEA5ULL,
		0x606F1EBE2B9BAB94ULL,
		0x743C0F7CD38B711AULL,
		0x9B452E058CD1510EULL,
		0x3BFF22AA33ED5CECULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xBBA42C74BA323900ULL,
		0x3EF441C7D8317B8AULL,
		0xF18637334B452F2FULL,
		0x77B66147D7E3B7AFULL,
		0xC801C8CB91FCA2DCULL,
		0xD55435F19FEEE30DULL,
		0xF6E722AC12FB834CULL,
		0x6E9E729BFF89A6B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D4CE5132A482C4FULL,
		0x29159B6D14B5D324ULL,
		0xD97732A7D1988E54ULL,
		0xC8E6D7B8976B0D19ULL,
		0xCBC127D645968303ULL,
		0xB49FBF0F0845DFCAULL,
		0xCEDBFB28AE847B2BULL,
		0x9E8138842B19AC1BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6E5747618FEA0CB1ULL,
		0x15DEA65AC37BA866ULL,
		0x180F048B79ACA0DBULL,
		0xAECF898F4078AA96ULL,
		0xFC40A0F54C661FD8ULL,
		0x20B476E297A90342ULL,
		0x280B278364770821ULL,
		0xD01D3A17D46FFA99ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x0FF4A7A1EA41C7BAULL,
		0x07211949757F2EEDULL,
		0x55C14B7DCD4A8606ULL,
		0x74EA6C5DCB4EA5A1ULL,
		0xB397AD825C3568B4ULL,
		0xDE78C9906869CBC4ULL,
		0x8BD2C3CC598C9DE1ULL,
		0x780DBE3C801C40C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3852C343E7F72197ULL,
		0xC776C9DED55DA096ULL,
		0xA0F3D2C0B113C4F8ULL,
		0x03062DB2636A7B05ULL,
		0x885261CE04DEF7A8ULL,
		0x4AB840E8A7A2E9ECULL,
		0xA0FB77A5A7E262C4ULL,
		0x246D55423B7709C5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD7A1E45E024AA623ULL,
		0x3FAA4F6AA0218E56ULL,
		0xB4CD78BD1C36C10DULL,
		0x71E43EAB67E42A9BULL,
		0x2B454BB45756710CULL,
		0x93C088A7C0C6E1D8ULL,
		0xEAD74C26B1AA3B1DULL,
		0x53A068FA44A536FFULL
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
		0x310078F8CA73CF9EULL,
		0x70C4A7FDA0C327D5ULL,
		0x850EC531C51061A1ULL,
		0x8FD82B81A35E7D67ULL,
		0x2F1D2817F2AD1F06ULL,
		0x01F265759214BAA4ULL,
		0x0F071B636A579F55ULL,
		0xD844C437929BFFFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x105A10C2576E4661ULL,
		0xE9F47A66E97E5D2EULL,
		0x0B3686E999B19BB9ULL,
		0xDB9DB6E20EB1FB72ULL,
		0x347E6BB98BF886D8ULL,
		0xEE5EF7566C78E097ULL,
		0x2FB2D6C58FAA9957ULL,
		0xFF9D4F6AAB046F78ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x20A668367305893DULL,
		0x86D02D96B744CAA7ULL,
		0x79D83E482B5EC5E7ULL,
		0xB43A749F94AC81F5ULL,
		0xFA9EBC5E66B4982DULL,
		0x13936E1F259BDA0CULL,
		0xDF54449DDAAD05FDULL,
		0xD8A774CCE7979083ULL
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
		0x32C44B903BDA8747ULL,
		0x57896258B1D2F708ULL,
		0x3AAE360ED7671CBBULL,
		0x7598629DAE411D5DULL,
		0x5B2304ACD476D89DULL,
		0xF5659B6BA66376BFULL,
		0xB55A484E91AD060DULL,
		0xD5ACA17CE547A2CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99A01AC41C279456ULL,
		0x93D23CE3A26FCF20ULL,
		0xC4D1F26274973E16ULL,
		0xFFB50C69474290B0ULL,
		0xBEB92FC6A70B7CD5ULL,
		0x3636C9B01D6FAA0DULL,
		0xA81E03D6939E42C6ULL,
		0x000F181DB60AE366ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x992430CC1FB2F2F1ULL,
		0xC3B725750F6327E7ULL,
		0x75DC43AC62CFDEA4ULL,
		0x75E3563466FE8CACULL,
		0x9C69D4E62D6B5BC7ULL,
		0xBF2ED1BB88F3CCB1ULL,
		0x0D3C4477FE0EC347ULL,
		0xD59D895F2F3CBF68ULL
	}};
	sign = 0;
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
		0x0253215350398834ULL,
		0x76FB3D9AF69FA5ADULL,
		0xCC76D3460F2A38EAULL,
		0x0A3F3F650D592100ULL,
		0x06FD510A08D1C328ULL,
		0x0C18F8667968D8E9ULL,
		0xFF5BE25EAD17DA20ULL,
		0x5FC38B82746C61AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x384DC6F68DAAC17EULL,
		0x52D5B6A6FB84EBE1ULL,
		0xE74A01B194BF4836ULL,
		0xCF324D08DB092B6AULL,
		0x07468D156DBE0A8EULL,
		0xF4C106F27FDD9E3FULL,
		0x488FCA6978490A13ULL,
		0xE67BAEA2EB660A8FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCA055A5CC28EC6B6ULL,
		0x242586F3FB1AB9CBULL,
		0xE52CD1947A6AF0B4ULL,
		0x3B0CF25C324FF595ULL,
		0xFFB6C3F49B13B899ULL,
		0x1757F173F98B3AA9ULL,
		0xB6CC17F534CED00CULL,
		0x7947DCDF8906571BULL
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
		0x3FACE700B491FF59ULL,
		0xA4FE3FC25C9FCD78ULL,
		0xE52E62C36FC7BB23ULL,
		0x4088C073747322D3ULL,
		0x03EF794D74F25A4FULL,
		0x3B83034FE5463B0FULL,
		0x1198028BC295C4E6ULL,
		0xB4F50C2A6F084888ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A3B3E97A6CE3E8DULL,
		0xA3113A676BB6ECA7ULL,
		0xE86B36B665EAA750ULL,
		0xE8D138545129275EULL,
		0xCEC3CCCDBAE3A38FULL,
		0x361CE509FB9594B6ULL,
		0x1DD14987A1AE90DBULL,
		0xF8EABE6BDA351382ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF571A8690DC3C0CCULL,
		0x01ED055AF0E8E0D0ULL,
		0xFCC32C0D09DD13D3ULL,
		0x57B7881F2349FB74ULL,
		0x352BAC7FBA0EB6BFULL,
		0x05661E45E9B0A658ULL,
		0xF3C6B90420E7340BULL,
		0xBC0A4DBE94D33505ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x20B4CB3A0C9E92B8ULL,
		0xEBBC148E45671655ULL,
		0xDE7C61FBF2B59905ULL,
		0x014FEAC4B5C8BFDDULL,
		0x9D6E84503D3C6C24ULL,
		0x4EAFC34A0663BE46ULL,
		0xD09955532F641709ULL,
		0x9688D3774CBC2EB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x283DA7F44EBE69B8ULL,
		0xF0E48B071331119DULL,
		0xF532FDB7F9577D2FULL,
		0x0A188B775780D09DULL,
		0x98C202381A2F305BULL,
		0x6F8E90F80017C419ULL,
		0x3FD6DAF42003A4BAULL,
		0x7DE8032A5E7F7237ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF8772345BDE02900ULL,
		0xFAD78987323604B7ULL,
		0xE9496443F95E1BD5ULL,
		0xF7375F4D5E47EF3FULL,
		0x04AC8218230D3BC8ULL,
		0xDF213252064BFA2DULL,
		0x90C27A5F0F60724EULL,
		0x18A0D04CEE3CBC7FULL
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
		0x08B3754A2A3A855AULL,
		0x70FB18029397E220ULL,
		0x248B603FA1CC3FB5ULL,
		0x61283B891062AA40ULL,
		0xCC64D072B75410DDULL,
		0xF38E8ADE59B45FA8ULL,
		0x72EB26B9902B199BULL,
		0xDF256D78F942973FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DDCC2FA3EE1799FULL,
		0xE467EFEC1FC1C68FULL,
		0x9A0BC4FE8C7D6A94ULL,
		0x553F3400E28C4F43ULL,
		0x380914DC99E75FABULL,
		0x72DBFFCB524C2230ULL,
		0xF73531506466E791ULL,
		0xF16CA44790CB9F46ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAAD6B24FEB590BBBULL,
		0x8C93281673D61B90ULL,
		0x8A7F9B41154ED520ULL,
		0x0BE907882DD65AFCULL,
		0x945BBB961D6CB132ULL,
		0x80B28B1307683D78ULL,
		0x7BB5F5692BC4320AULL,
		0xEDB8C9316876F7F8ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x7FCFC00F6A1C1190ULL,
		0x7B70D7B94D6656A1ULL,
		0x36E44AF2CA3B34E2ULL,
		0xCB5948C81DC4131DULL,
		0x70E6B9C89476AF45ULL,
		0xF809330BFFB1E243ULL,
		0xA6BDE5255926E57CULL,
		0xC773DAC0C6D745C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80F6DEA4322D76BFULL,
		0xEDBA01817B66755EULL,
		0x0C9B1F8F487083FEULL,
		0x24F8F43D9D805A14ULL,
		0x46C642163CEC6D93ULL,
		0x1E2BD7A87B8322CAULL,
		0x7EF3ED26602C8808ULL,
		0x8B88EEA5C4BB003AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFED8E16B37EE9AD1ULL,
		0x8DB6D637D1FFE142ULL,
		0x2A492B6381CAB0E3ULL,
		0xA660548A8043B909ULL,
		0x2A2077B2578A41B2ULL,
		0xD9DD5B63842EBF79ULL,
		0x27C9F7FEF8FA5D74ULL,
		0x3BEAEC1B021C4586ULL
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
		0x56922D3B84B2BDBFULL,
		0xB3C9DEFD16ABCF65ULL,
		0xA9FCC15CE429B39EULL,
		0xA5E57788C54F74EEULL,
		0xA2C03019E43BD0F0ULL,
		0xE5F1FC06A3B0FE28ULL,
		0x0F3C88CA243C27ADULL,
		0x5FA91DA39E9A61D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FA262FED4375216ULL,
		0x57F2099E7DA113E8ULL,
		0x072466CBF3CE6E47ULL,
		0x005703E02F3553B8ULL,
		0x858DC22A99CE0B4FULL,
		0x113806241387E084ULL,
		0x15C64A9043FADC95ULL,
		0x23B7DD2A2BC8B2FCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x06EFCA3CB07B6BA9ULL,
		0x5BD7D55E990ABB7DULL,
		0xA2D85A90F05B4557ULL,
		0xA58E73A8961A2136ULL,
		0x1D326DEF4A6DC5A1ULL,
		0xD4B9F5E290291DA4ULL,
		0xF9763E39E0414B18ULL,
		0x3BF1407972D1AED3ULL
	}};
	sign = 0;
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
		0x715B030FD537112AULL,
		0xC8AA1D529644071DULL,
		0x9693A2A53C3FD467ULL,
		0xE59FB2634C0743B0ULL,
		0x05526BB40034FDA2ULL,
		0xF5C8BA4DEA59A29FULL,
		0xF198FFE1998FC49DULL,
		0x37C6F8F2B1C8B3C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BFA18CF590C6F08ULL,
		0x89317A815CD05B27ULL,
		0x15E3D7821875FAAAULL,
		0x4FC5D919E98CC39AULL,
		0x8B4D58D91BB117A2ULL,
		0x554696D51F468620ULL,
		0x62F8878FA8DBF2BAULL,
		0x88F24FE532F53402ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2560EA407C2AA222ULL,
		0x3F78A2D13973ABF6ULL,
		0x80AFCB2323C9D9BDULL,
		0x95D9D949627A8016ULL,
		0x7A0512DAE483E600ULL,
		0xA0822378CB131C7EULL,
		0x8EA07851F0B3D1E3ULL,
		0xAED4A90D7ED37FC6ULL
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
		0xAA9CA3F587508263ULL,
		0xE808BF2EF73AEBEDULL,
		0x820EE9E4C9BC8302ULL,
		0x2CBFD2D7F6CD149AULL,
		0xCF5AB52D1D4E03EFULL,
		0x911849FC40F269ACULL,
		0x5B6B667BC281892CULL,
		0x76A7882980A06B5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0C51BB4202B3BD4ULL,
		0x80A83D0419BA57A7ULL,
		0xCACF3C49D7FF83D5ULL,
		0x660CA30AA103FAABULL,
		0x91D628462FE4C25EULL,
		0x2539EB56F4CED76FULL,
		0xC96F1F189A9D6A12ULL,
		0x386EBDA9412EBE3AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE9D788416725468FULL,
		0x6760822ADD809445ULL,
		0xB73FAD9AF1BCFF2DULL,
		0xC6B32FCD55C919EEULL,
		0x3D848CE6ED694190ULL,
		0x6BDE5EA54C23923DULL,
		0x91FC476327E41F1AULL,
		0x3E38CA803F71AD22ULL
	}};
	sign = 0;
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
		0x764CA9383511BD0FULL,
		0x55D398B3D9E8889FULL,
		0xC88E72BD4B8C7BF5ULL,
		0x8CF3C6A5B2282F16ULL,
		0x5A0A6E58A2574075ULL,
		0xE38795B912E62392ULL,
		0xB925D82F60C8E1CCULL,
		0xEF7452BCBEFD173EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70A342614D482A8AULL,
		0x7BF8C182D8662AA5ULL,
		0xDD217EC06F744764ULL,
		0x45350B919D39EC0BULL,
		0xBCF8AD5A71E48761ULL,
		0x3216C5E66FF155C3ULL,
		0x3CF962A7C15B89BEULL,
		0x86488F43C14BB6E6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x05A966D6E7C99285ULL,
		0xD9DAD73101825DFAULL,
		0xEB6CF3FCDC183490ULL,
		0x47BEBB1414EE430AULL,
		0x9D11C0FE3072B914ULL,
		0xB170CFD2A2F4CDCEULL,
		0x7C2C75879F6D580EULL,
		0x692BC378FDB16058ULL
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
		0x584CADD0A03C658DULL,
		0xB222524E6D65A620ULL,
		0x18D706F90F3807B9ULL,
		0x20F1CC626545057CULL,
		0xD1F31E60CD59276FULL,
		0x29CAEFE937643488ULL,
		0x25707BC60CFAD714ULL,
		0x1D4CF8661E400743ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA9C487A95374751ULL,
		0xEC2C2D4E3EC30EEEULL,
		0x3EB5F30ABB434ECAULL,
		0x205DBBD9BB720A78ULL,
		0xCD2A8257E6A797EFULL,
		0x370F659C32C17B87ULL,
		0xA9D7CC3A2C0274C6ULL,
		0x15809CA26260E747ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6DB065560B051E3CULL,
		0xC5F625002EA29731ULL,
		0xDA2113EE53F4B8EEULL,
		0x00941088A9D2FB03ULL,
		0x04C89C08E6B18F80ULL,
		0xF2BB8A4D04A2B901ULL,
		0x7B98AF8BE0F8624DULL,
		0x07CC5BC3BBDF1FFBULL
	}};
	sign = 0;
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
		0x9E90FA3B140FAA0DULL,
		0x6F1FCD68C6EF2409ULL,
		0x3A06192B97D8AE80ULL,
		0xC834A3B943B3B781ULL,
		0x637ABC937F1A1520ULL,
		0xC756DB4BDC1E9C71ULL,
		0x538E8D1A7C03FEE1ULL,
		0xB298C64300B0B2EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8883C7834DC9DF28ULL,
		0x8E04B4E0EF81FCE9ULL,
		0x44955CD60FBBDFD7ULL,
		0x9807F77AA176A905ULL,
		0xC83FEBC54C52FB18ULL,
		0x54C15F613AF13C83ULL,
		0x0A6914EF2A92B29AULL,
		0x6E40FC11CECC1752ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x160D32B7C645CAE5ULL,
		0xE11B1887D76D2720ULL,
		0xF570BC55881CCEA8ULL,
		0x302CAC3EA23D0E7BULL,
		0x9B3AD0CE32C71A08ULL,
		0x72957BEAA12D5FEDULL,
		0x4925782B51714C47ULL,
		0x4457CA3131E49B9DULL
	}};
	sign = 0;
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
		0xDBB5ED8E5D75389DULL,
		0x3AE931756AE41E27ULL,
		0xEA2C02021AA7DC55ULL,
		0x0569D9B2F4FB84C2ULL,
		0x6810D370E39E0C43ULL,
		0x75E14F2F50CE9F28ULL,
		0x6DAFF4F377AE9020ULL,
		0x1D17C4177E1C21EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2AA91E8514CDA01ULL,
		0xE5534C176CC78966ULL,
		0xEDDF439454D5D8BCULL,
		0x2FEEA14C1F6B9ADEULL,
		0x51F1A1FB109CBE3CULL,
		0x9042077D836998CBULL,
		0xC6BE64792A70946DULL,
		0x663D41A7444383CEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x390B5BA60C285E9CULL,
		0x5595E55DFE1C94C1ULL,
		0xFC4CBE6DC5D20398ULL,
		0xD57B3866D58FE9E3ULL,
		0x161F3175D3014E06ULL,
		0xE59F47B1CD65065DULL,
		0xA6F1907A4D3DFBB2ULL,
		0xB6DA827039D89E1FULL
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
		0x94AE032122A12231ULL,
		0xB5783B1BCEAC9F54ULL,
		0xFD2D2A5BC4A97B17ULL,
		0x8AD5DE3B4DC3E607ULL,
		0xE5348DA47431B1B6ULL,
		0xE626228318F0F9F7ULL,
		0x07105BF9147A151DULL,
		0x60A425548250358CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD89667DAE2EADA0AULL,
		0xD847E0AA14E2FB0CULL,
		0x276DFA2E0F72CE01ULL,
		0x4F875A9BEEA7D3E9ULL,
		0xC231D4CAC896CAE1ULL,
		0x12700D15C377E8DBULL,
		0x0388C102E387990BULL,
		0xCCB75D14B7BAE930ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBC179B463FB64827ULL,
		0xDD305A71B9C9A447ULL,
		0xD5BF302DB536AD15ULL,
		0x3B4E839F5F1C121EULL,
		0x2302B8D9AB9AE6D5ULL,
		0xD3B6156D5579111CULL,
		0x03879AF630F27C12ULL,
		0x93ECC83FCA954C5CULL
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
		0x172DD91C342E0828ULL,
		0xFE50128A5F08BF60ULL,
		0xBD8A61BC7711E0A1ULL,
		0xCDB5F24947E0AFF4ULL,
		0xC32B0B1BBA4AA8A0ULL,
		0x356151805822C60BULL,
		0xEE89453602B5DE8FULL,
		0xBCDDA0FCA2EC9CADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32970719C6C0176EULL,
		0x2C25A2042AAA5BBDULL,
		0x84B40E4226152C92ULL,
		0x0BDE36DF9F209729ULL,
		0xEE1159E9C24B96C8ULL,
		0x40B19C0C80F9A087ULL,
		0xB674A1A232E8B106ULL,
		0x0A27327970F758E3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE496D2026D6DF0BAULL,
		0xD22A7086345E63A2ULL,
		0x38D6537A50FCB40FULL,
		0xC1D7BB69A8C018CBULL,
		0xD519B131F7FF11D8ULL,
		0xF4AFB573D7292583ULL,
		0x3814A393CFCD2D88ULL,
		0xB2B66E8331F543CAULL
	}};
	sign = 0;
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
		0x21A3814ACCF7542FULL,
		0x622D73389E47D4CFULL,
		0xC774E065A28A0DE8ULL,
		0xF72B7EE0C19605B0ULL,
		0xFB82F3CED97D26D1ULL,
		0x3254DC97E5E65DACULL,
		0xE162F14FD8B8F3CFULL,
		0x7000C9F3D68511A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE6476CE17D50A8EULL,
		0xBE6536EA1AC1244CULL,
		0xC5A64E4EE62375A4ULL,
		0x3986503CF40F8780ULL,
		0x6E1EE99014EF0DFAULL,
		0x25214EDCFF6DAB71ULL,
		0xB4DE54F0D0E28240ULL,
		0x7A5C349D3F684615ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x233F0A7CB52249A1ULL,
		0xA3C83C4E8386B082ULL,
		0x01CE9216BC669843ULL,
		0xBDA52EA3CD867E30ULL,
		0x8D640A3EC48E18D7ULL,
		0x0D338DBAE678B23BULL,
		0x2C849C5F07D6718FULL,
		0xF5A49556971CCB8FULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x066397388F4C4D1AULL,
		0xFB363019F12D6791ULL,
		0x166D4ABAFFD9EBFCULL,
		0x436684B7E68160DFULL,
		0x67D810832C1A3DDDULL,
		0xF77734A1820879A7ULL,
		0xF671F850F9871347ULL,
		0xF4FF7B4EA95C45FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF78EC221B6D2DFDCULL,
		0x310203AEBD587D8AULL,
		0x2962E20F5839CC27ULL,
		0x1855C474CDC9FADBULL,
		0xC903A6FE05EC701FULL,
		0xD64D11F2ECA608A7ULL,
		0x81CD222E498BAF85ULL,
		0xABC5407E445174A0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0ED4D516D8796D3EULL,
		0xCA342C6B33D4EA06ULL,
		0xED0A68ABA7A01FD5ULL,
		0x2B10C04318B76603ULL,
		0x9ED46985262DCDBEULL,
		0x212A22AE956270FFULL,
		0x74A4D622AFFB63C2ULL,
		0x493A3AD0650AD15BULL
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
		0xE7A6A15065F0CA8CULL,
		0x7F01D692F6E213FDULL,
		0x253A30967C0B1A3CULL,
		0x20125CC0515E8D58ULL,
		0x9C39810E37E11B6EULL,
		0xA2E4E10CB8162B4FULL,
		0xF3E5C3869CC619ABULL,
		0x55A077573D1EF907ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC903C7CA4E30F371ULL,
		0xFFA887153369AAA6ULL,
		0x5817D52B7CE836E8ULL,
		0x84F067F3F0906B12ULL,
		0x300BB5C932109C19ULL,
		0xBC3BA4098312ED8DULL,
		0x8F3081531FE05F30ULL,
		0x423BFBFD7FEB5F33ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1EA2D98617BFD71BULL,
		0x7F594F7DC3786957ULL,
		0xCD225B6AFF22E353ULL,
		0x9B21F4CC60CE2245ULL,
		0x6C2DCB4505D07F54ULL,
		0xE6A93D0335033DC2ULL,
		0x64B542337CE5BA7AULL,
		0x13647B59BD3399D4ULL
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
		0x5B51A6E2E08E184EULL,
		0x00097652824630DBULL,
		0xFC389BDA66F1D114ULL,
		0xF5F51DCDCA428E46ULL,
		0x84DBE759C5CB73B5ULL,
		0xCC745165F5399459ULL,
		0xCDB68ADE45F95E3EULL,
		0xF2C06350E4F99C85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF7243AD7AB54441ULL,
		0xE778C4B6937E3795ULL,
		0x0B8A8333DDF8BC64ULL,
		0x0ECC071C282871D9ULL,
		0xE846DC1958B86B7CULL,
		0x90E97ED6B176AFE2ULL,
		0xF3D562AE9F465ACAULL,
		0x75C1E0130F05EC4AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9BDF633565D8D40DULL,
		0x1890B19BEEC7F945ULL,
		0xF0AE18A688F914AFULL,
		0xE72916B1A21A1C6DULL,
		0x9C950B406D130839ULL,
		0x3B8AD28F43C2E476ULL,
		0xD9E1282FA6B30374ULL,
		0x7CFE833DD5F3B03AULL
	}};
	sign = 0;
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
		0xDDFF5C66CCF91A21ULL,
		0xDE3546AE58FEF573ULL,
		0x69FBD70FDD87A710ULL,
		0x79AD4A4DAA812164ULL,
		0xBADDAACF2DFA2924ULL,
		0x825B9165ECDC95FFULL,
		0x6178FDD98F63EC78ULL,
		0x4DC596220216EBD4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08420CC757C5B1B9ULL,
		0x483D106CE528F80CULL,
		0x4659DCAEDFC14EE9ULL,
		0xB8F3203C8576E26AULL,
		0xD70EBBDD08C7EAE0ULL,
		0xD90B04EA72AFBCCCULL,
		0x9405151FDC572157ULL,
		0xF609CA55437E8930ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD5BD4F9F75336868ULL,
		0x95F8364173D5FD67ULL,
		0x23A1FA60FDC65827ULL,
		0xC0BA2A11250A3EFAULL,
		0xE3CEEEF225323E43ULL,
		0xA9508C7B7A2CD932ULL,
		0xCD73E8B9B30CCB20ULL,
		0x57BBCBCCBE9862A3ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x1137FCC7D25D5617ULL,
		0x0FA901630094A48FULL,
		0x2D3A6A48E62C7EE3ULL,
		0x1B7E56E00B04390FULL,
		0xB39B5ABA6B7997FAULL,
		0x1EE1651B7BFC7866ULL,
		0x0E76A224BF020EC8ULL,
		0x469716725F795012ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x466A1D4E58475846ULL,
		0x74627F7139C77F57ULL,
		0x3C94A0F338491B00ULL,
		0x16B8B8B42AA23A66ULL,
		0xBAD07C248FB1A04AULL,
		0x1523A937842E9888ULL,
		0x657FF341B781922BULL,
		0xBDEFFA9BE67FE2AFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCACDDF797A15FDD1ULL,
		0x9B4681F1C6CD2537ULL,
		0xF0A5C955ADE363E2ULL,
		0x04C59E2BE061FEA8ULL,
		0xF8CADE95DBC7F7B0ULL,
		0x09BDBBE3F7CDDFDDULL,
		0xA8F6AEE307807C9DULL,
		0x88A71BD678F96D62ULL
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
		0xB948C00C87B51D3FULL,
		0x43F7C7123EA19458ULL,
		0x44BE5F598DC50E1EULL,
		0xBA66834C9A6205E4ULL,
		0xD6163B6D4C25FFFCULL,
		0x167E29ED6E30E280ULL,
		0x02CB08538401333DULL,
		0x7D47C04489662D56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x934C482A8E9AE4CEULL,
		0xB6F7EF8ADC907B98ULL,
		0xF278A3AEE5AA7F12ULL,
		0x30A87644E8D21A18ULL,
		0x4DD96271873B0AB3ULL,
		0x4EFEAA4DDA6318EEULL,
		0x4A25EB15FFF447A6ULL,
		0xAFD5051FA59E500CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x25FC77E1F91A3871ULL,
		0x8CFFD787621118C0ULL,
		0x5245BBAAA81A8F0BULL,
		0x89BE0D07B18FEBCBULL,
		0x883CD8FBC4EAF549ULL,
		0xC77F7F9F93CDC992ULL,
		0xB8A51D3D840CEB96ULL,
		0xCD72BB24E3C7DD49ULL
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
		0xD3DC1B8C5BF7288EULL,
		0xE4E009BF8BC79390ULL,
		0x5CDE38E36BBAE9D3ULL,
		0x7093477CF2DA1B7CULL,
		0x7A2ACAB67C259906ULL,
		0x1534659BE3662E34ULL,
		0x9E326557681C6C90ULL,
		0xEC32F3E2D29D90CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE280C40BCCA3727ULL,
		0xEA085A6401C4FAF2ULL,
		0x3DFBB85CA4D48719ULL,
		0x766ACD8AE215D17DULL,
		0x6976DFF871E95218ULL,
		0xF1F4DB9D5141BA3DULL,
		0xD8822D4F0EC8E916ULL,
		0x2D72A5EFA87003A2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD5B40F4B9F2CF167ULL,
		0xFAD7AF5B8A02989DULL,
		0x1EE28086C6E662B9ULL,
		0xFA2879F210C449FFULL,
		0x10B3EABE0A3C46EDULL,
		0x233F89FE922473F7ULL,
		0xC5B0380859538379ULL,
		0xBEC04DF32A2D8D2AULL
	}};
	sign = 0;
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
		0xE47B5B70E9191CF5ULL,
		0xE1A47ED486DCC8EBULL,
		0xDD57A638F12ED656ULL,
		0xDBED98D0BFABECCFULL,
		0x3037B27CB91BA62AULL,
		0x24CDC5351557B076ULL,
		0x519F9796DB933551ULL,
		0x950D3A8F568D06F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE906A7CF42F93741ULL,
		0xCB4DBAD8E1982440ULL,
		0xE3CF2903994C085FULL,
		0x78999A8B33FE4230ULL,
		0xB7B744AF2938EB6CULL,
		0xC8C04C95D7B0549AULL,
		0x5C63DCA8173BF9F8ULL,
		0x9EBA089AC17E606FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFB74B3A1A61FE5B4ULL,
		0x1656C3FBA544A4AAULL,
		0xF9887D3557E2CDF7ULL,
		0x6353FE458BADAA9EULL,
		0x78806DCD8FE2BABEULL,
		0x5C0D789F3DA75BDBULL,
		0xF53BBAEEC4573B58ULL,
		0xF65331F4950EA687ULL
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
		0x22DCF07C25ADF5F9ULL,
		0x54B422D8F8F477C1ULL,
		0x5A13AE7839167AC2ULL,
		0x7E8107BEC9D0CF08ULL,
		0xC9876DB6E741B8E7ULL,
		0xE0CFA4A8BADAF68CULL,
		0xC1D4B5858A13D2C3ULL,
		0xCD976DB4497592E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6301B07C4B1AAA0EULL,
		0x22A47262B9AC84EFULL,
		0x9B1546C6BA318863ULL,
		0xAD7553A394532564ULL,
		0x91840109FB7F2600ULL,
		0xDFB966E05AE6B6B2ULL,
		0xE7F473CE6017670BULL,
		0xA0761586753D26C6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBFDB3FFFDA934BEBULL,
		0x320FB0763F47F2D1ULL,
		0xBEFE67B17EE4F25FULL,
		0xD10BB41B357DA9A3ULL,
		0x38036CACEBC292E6ULL,
		0x01163DC85FF43FDAULL,
		0xD9E041B729FC6BB8ULL,
		0x2D21582DD4386C1FULL
	}};
	sign = 0;
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
		0xBEAB1B60D6D5EC26ULL,
		0xACEE3B2798921CA9ULL,
		0x4106B6F8F529DE21ULL,
		0x60A7C9D50180BD38ULL,
		0x85DEDE7DD43D2481ULL,
		0x0A3AFDC1E818FA27ULL,
		0xF9E14AE5E666223BULL,
		0xECF9EBBE56DB202DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDBE8B2AF80875554ULL,
		0xDDBE8DC9A645AEB6ULL,
		0xF9FB17E37D79BB37ULL,
		0x892A202F6FB455BDULL,
		0x096EF6A39AC0A375ULL,
		0x96DC67342BDF652CULL,
		0xE4E6843D8DEBE1B0ULL,
		0x750E625C7127F3C1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE2C268B1564E96D2ULL,
		0xCF2FAD5DF24C6DF2ULL,
		0x470B9F1577B022E9ULL,
		0xD77DA9A591CC677AULL,
		0x7C6FE7DA397C810BULL,
		0x735E968DBC3994FBULL,
		0x14FAC6A8587A408AULL,
		0x77EB8961E5B32C6CULL
	}};
	sign = 0;
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
		0xA4EF60F068D13964ULL,
		0x64B33469C3FADB2CULL,
		0x156B776CA33D30D7ULL,
		0x6EEFD05409247A99ULL,
		0x0A7C1760E782A03CULL,
		0x7E72B67A7C71528FULL,
		0xA55BDA198A84D969ULL,
		0x98BE9735F85134C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0505DA5699DCED55ULL,
		0x08FFC68AF18927C4ULL,
		0x049F647959246E17ULL,
		0x081F9940E6C66A19ULL,
		0xDAF7CC876DCD0E72ULL,
		0xBC5ADE71B5620D07ULL,
		0x34825B534D93BD79ULL,
		0xC5936B432D0823ABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9FE98699CEF44C0FULL,
		0x5BB36DDED271B368ULL,
		0x10CC12F34A18C2C0ULL,
		0x66D03713225E1080ULL,
		0x2F844AD979B591CAULL,
		0xC217D808C70F4587ULL,
		0x70D97EC63CF11BEFULL,
		0xD32B2BF2CB491119ULL
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
		0x54CF5B5C18F9CA31ULL,
		0x8038B115C635AE35ULL,
		0xEFDB6AA9C4021C77ULL,
		0xC0B5AE620DD609C1ULL,
		0xD7B4C7D2A5CEF5F0ULL,
		0xD100A16B104C74EEULL,
		0x69E1ED7E4D4E939EULL,
		0x6E70F3C628260A06ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x489BC37249C176A9ULL,
		0x203FB2E757B219ADULL,
		0x452449F2BB8E3F44ULL,
		0xB45317588FBBD17BULL,
		0x49EAAF352E622EBAULL,
		0xD0E20A58F452DA53ULL,
		0x7979FF27774A2A1BULL,
		0x2AFE8C52677FCA29ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C3397E9CF385388ULL,
		0x5FF8FE2E6E839488ULL,
		0xAAB720B70873DD33ULL,
		0x0C6297097E1A3846ULL,
		0x8DCA189D776CC736ULL,
		0x001E97121BF99A9BULL,
		0xF067EE56D6046983ULL,
		0x43726773C0A63FDCULL
	}};
	sign = 0;
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
		0x4312B350AD3615D1ULL,
		0x883D1801656F5EE5ULL,
		0xE7F853BBE946BABBULL,
		0xE86C3A67576C4A79ULL,
		0xE5B27A3EA21C9961ULL,
		0x39CB9CD4F5CE65AAULL,
		0x4C1181703AE43379ULL,
		0x23662748E39D21CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA299619BC932BD71ULL,
		0x6D94784FBE6D67ADULL,
		0x4A26EFB24D71AF23ULL,
		0x1CBC186E7585BC93ULL,
		0x1B715DA59D93B0B9ULL,
		0xF98FC1281C522A9FULL,
		0x493FA039443282B8ULL,
		0x01F1C58221D9283DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA07951B4E4035860ULL,
		0x1AA89FB1A701F737ULL,
		0x9DD164099BD50B98ULL,
		0xCBB021F8E1E68DE6ULL,
		0xCA411C990488E8A8ULL,
		0x403BDBACD97C3B0BULL,
		0x02D1E136F6B1B0C0ULL,
		0x217461C6C1C3F98FULL
	}};
	sign = 0;
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
		0xB08DA35F68F67CC5ULL,
		0x3B7B12B17E1E03D3ULL,
		0x3E782A1DDD6EDCE4ULL,
		0x626EE22A5B459E38ULL,
		0xBBFA56A2241CABA8ULL,
		0x008DF791537253F5ULL,
		0x415EE8E0986000A8ULL,
		0xDE68074C171E2639ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA98EF9BCD25E7B6DULL,
		0xCB94C042F6C8FBBFULL,
		0xD8E2BEA4BEFAAD12ULL,
		0x53641CA90B9A40E6ULL,
		0xB32678900B8525CDULL,
		0x8AFBDB00E1CC0B27ULL,
		0x2A92652926AAD1C2ULL,
		0x1AC6581B29E22A0BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x06FEA9A296980158ULL,
		0x6FE6526E87550814ULL,
		0x65956B791E742FD1ULL,
		0x0F0AC5814FAB5D51ULL,
		0x08D3DE12189785DBULL,
		0x75921C9071A648CEULL,
		0x16CC83B771B52EE5ULL,
		0xC3A1AF30ED3BFC2EULL
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
		0xF2431548EBF90DBFULL,
		0x05FB4609ACE26AA0ULL,
		0x95DCF779C9ED72CFULL,
		0x3C01F6F715DBEBACULL,
		0x4C8E065D6AE06352ULL,
		0x08F9C43155AD3AAFULL,
		0x9438BA02A03D5499ULL,
		0x80E060C31157F432ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9406D00C00177DB2ULL,
		0x327A335AA453D44FULL,
		0x5D6774C0BE62040AULL,
		0x3B321C33E2DD402FULL,
		0x8181B3DDC5C343E6ULL,
		0xB5A964F83A620FB3ULL,
		0xC1A818BD5D61BBEFULL,
		0xBDA121F36A00DD5EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5E3C453CEBE1900DULL,
		0xD38112AF088E9651ULL,
		0x387582B90B8B6EC4ULL,
		0x00CFDAC332FEAB7DULL,
		0xCB0C527FA51D1F6CULL,
		0x53505F391B4B2AFBULL,
		0xD290A14542DB98A9ULL,
		0xC33F3ECFA75716D3ULL
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
		0x3D0109FD32F27D1DULL,
		0xF2DE02794A1FDB0AULL,
		0xEC7CB3065277C326ULL,
		0x538C156218C470F0ULL,
		0xCBF57B5E93C60068ULL,
		0x8270257DA5787561ULL,
		0x26030EC314AEEC86ULL,
		0xFA04FC6F51606E0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA7A99EA54640598ULL,
		0xCDC65BC770888CD4ULL,
		0x5DD1C94735A26C99ULL,
		0x6AD05A4080855BD7ULL,
		0xB75DD9A3E8B5B6DDULL,
		0x85FDFACC5FC0F3E5ULL,
		0x66FA9EC1CEDD8513ULL,
		0xC0C73C966ECEFF94ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x42867012DE8E7785ULL,
		0x2517A6B1D9974E35ULL,
		0x8EAAE9BF1CD5568DULL,
		0xE8BBBB21983F1519ULL,
		0x1497A1BAAB10498AULL,
		0xFC722AB145B7817CULL,
		0xBF08700145D16772ULL,
		0x393DBFD8E2916E75ULL
	}};
	sign = 0;
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
		0x1AABC1C829DC992CULL,
		0x09A57D7EF017CBFFULL,
		0xE6848CAE1AB696D6ULL,
		0xF211A62235D645F2ULL,
		0x659D893EBD20C7BBULL,
		0xCA0B70341B17BFCFULL,
		0xC7E40D3733F379D4ULL,
		0x97877A0614A98B38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C5DBC7AFD765845ULL,
		0x74D4E01EEE54D177ULL,
		0x224108CC02724A41ULL,
		0xDB3F687BF9008E68ULL,
		0xD59E54121B616D71ULL,
		0x402DBD0F276C93F2ULL,
		0xA564DD475CE1E39EULL,
		0xE212A716C1911119ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBE4E054D2C6640E7ULL,
		0x94D09D6001C2FA87ULL,
		0xC44383E218444C94ULL,
		0x16D23DA63CD5B78AULL,
		0x8FFF352CA1BF5A4AULL,
		0x89DDB324F3AB2BDCULL,
		0x227F2FEFD7119636ULL,
		0xB574D2EF53187A1FULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xB4E9B0A8A658E1ADULL,
		0x51F70483B5666092ULL,
		0x5E8CCD1878DB260EULL,
		0xC5FD64058031203DULL,
		0xAA6CBFC8A40AB897ULL,
		0x5E0EF36383FDAF94ULL,
		0xD4F6FA085D27CF0FULL,
		0x4FDC572705A733D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A8F74A2DA0DEB2EULL,
		0x5377580D59D1F461ULL,
		0x085247B4D327FD31ULL,
		0x287AE8909D1C4A60ULL,
		0xE6A0F788E83343B3ULL,
		0xC67216457016C867ULL,
		0xC1EE9AE6269C69D7ULL,
		0xAD8EA3914D7E751DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAA5A3C05CC4AF67FULL,
		0xFE7FAC765B946C31ULL,
		0x563A8563A5B328DCULL,
		0x9D827B74E314D5DDULL,
		0xC3CBC83FBBD774E4ULL,
		0x979CDD1E13E6E72CULL,
		0x13085F22368B6537ULL,
		0xA24DB395B828BEB6ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x740FADE89C7699B0ULL,
		0x1E39E9833ABAE14FULL,
		0x19A5D9E175C63D69ULL,
		0xCA5C0D04E5C86F34ULL,
		0xB4393EEF714D1033ULL,
		0xAE321198DD50B242ULL,
		0xF6DADAA4E3667470ULL,
		0xFE7E9D123930EA56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x796F6732644DB74DULL,
		0xFB4C182F0B87C6EBULL,
		0xC6D4725EDD25E2C1ULL,
		0x1349BCB26A724961ULL,
		0xD06234EEB0818EC5ULL,
		0xAA26351BD09EB3A3ULL,
		0xEC96BA69E0235145ULL,
		0xFB69272702BE08F6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFAA046B63828E263ULL,
		0x22EDD1542F331A63ULL,
		0x52D1678298A05AA7ULL,
		0xB71250527B5625D2ULL,
		0xE3D70A00C0CB816EULL,
		0x040BDC7D0CB1FE9EULL,
		0x0A44203B0343232BULL,
		0x031575EB3672E160ULL
	}};
	sign = 0;
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
		0x2B2A7542D69350FFULL,
		0x3623494B7105BF9CULL,
		0x3D3D4039D902C387ULL,
		0x29931EAE0D79233EULL,
		0x6E8AA6D5B185CFA6ULL,
		0x675E3A4422461B6EULL,
		0x940108FE8F260DB8ULL,
		0x6E78017A9BA7A1CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF465FD5FCBB043C8ULL,
		0x0939B2BF00421DEBULL,
		0xF762A49177324E68ULL,
		0x0C98B0F4EE51DE40ULL,
		0x4382F4C0B84A7F9AULL,
		0xF10CA1C4DE88F15DULL,
		0x8F4885C69948EECDULL,
		0xA07C0FD68C74432EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x36C477E30AE30D37ULL,
		0x2CE9968C70C3A1B0ULL,
		0x45DA9BA861D0751FULL,
		0x1CFA6DB91F2744FDULL,
		0x2B07B214F93B500CULL,
		0x7651987F43BD2A11ULL,
		0x04B88337F5DD1EEAULL,
		0xCDFBF1A40F335E9CULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xA4501531963A9899ULL,
		0x12C8A71EA7839269ULL,
		0x6CE8ABFA5D4C0C8DULL,
		0x86167EC13C79CA01ULL,
		0xED701EBB37B31AF9ULL,
		0x0985F2B41C5057D5ULL,
		0x497F8AAC6701D5F2ULL,
		0xD094076D481C5132ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x876BF10F9F944A07ULL,
		0x0F968300E4096CB4ULL,
		0x150B3B414DA5A85AULL,
		0x657F3538EBA30664ULL,
		0x7B590EF318DE5DABULL,
		0xF687F40976013C6AULL,
		0xAEFB73CAD32C37A4ULL,
		0x44AFA47D83F110D4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1CE42421F6A64E92ULL,
		0x0332241DC37A25B5ULL,
		0x57DD70B90FA66433ULL,
		0x2097498850D6C39DULL,
		0x72170FC81ED4BD4EULL,
		0x12FDFEAAA64F1B6BULL,
		0x9A8416E193D59E4DULL,
		0x8BE462EFC42B405DULL
	}};
	sign = 0;
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
		0x19EC3D7FDF441750ULL,
		0x4E6C91FACBC2F8ACULL,
		0xA6F70E3EA8B9ABE1ULL,
		0x81E02DC2A0658880ULL,
		0xA8F8D200C78CBA81ULL,
		0x41A5A0AE01EF5DCFULL,
		0xCB777874145344E5ULL,
		0x2A748A341E0A48F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB02B1181596A8984ULL,
		0x1FF2635652F8FB6DULL,
		0x7A325D7500984708ULL,
		0x7CE9514205BC82F3ULL,
		0x7536D49E96E39CD6ULL,
		0x0825873FE783D36AULL,
		0x5DCD5D0CA7037F2DULL,
		0x291032854F7CD8F4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x69C12BFE85D98DCCULL,
		0x2E7A2EA478C9FD3EULL,
		0x2CC4B0C9A82164D9ULL,
		0x04F6DC809AA9058DULL,
		0x33C1FD6230A91DABULL,
		0x3980196E1A6B8A65ULL,
		0x6DAA1B676D4FC5B8ULL,
		0x016457AECE8D7000ULL
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
		0xE1E073CAE508CEA4ULL,
		0x28607AB4A8270226ULL,
		0x87EA541744480307ULL,
		0x77EA7521CF4ED3C3ULL,
		0x9A2D891C2A7824CAULL,
		0xCF3498503F444F6FULL,
		0x313F323C01C60776ULL,
		0x3012C1AFE7656F00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE131B7F15FE5143FULL,
		0x4B84235192C9E344ULL,
		0x58F372285BBEFE2AULL,
		0x0C04B214A249E3B7ULL,
		0xCB66FB02A404FC47ULL,
		0xA611FFEDF5AE2CEFULL,
		0x6C65FEE4072713F7ULL,
		0x4B80B329586B7BC0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00AEBBD98523BA65ULL,
		0xDCDC5763155D1EE2ULL,
		0x2EF6E1EEE88904DCULL,
		0x6BE5C30D2D04F00CULL,
		0xCEC68E1986732883ULL,
		0x292298624996227FULL,
		0xC4D93357FA9EF37FULL,
		0xE4920E868EF9F33FULL
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
		0xA62BFC8EED34AE99ULL,
		0x14AD9BF5131664DAULL,
		0x9749DE731FB16A12ULL,
		0xCC4B43410056F802ULL,
		0x77EF69C6367B2F57ULL,
		0x7254BA8EBFBBD155ULL,
		0xD56B9967A3DA2520ULL,
		0xC5FDD517575AF94BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30242D8744B5F126ULL,
		0xB6783132477BCF3DULL,
		0x98ADA0AE7411C76AULL,
		0x82EDE5F4BDAED79FULL,
		0x22555AF82C19A574ULL,
		0x29603175F4A00F44ULL,
		0xB7F9653140BEB88FULL,
		0x4492A22018837D0FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7607CF07A87EBD73ULL,
		0x5E356AC2CB9A959DULL,
		0xFE9C3DC4AB9FA2A7ULL,
		0x495D5D4C42A82062ULL,
		0x559A0ECE0A6189E3ULL,
		0x48F48918CB1BC211ULL,
		0x1D723436631B6C91ULL,
		0x816B32F73ED77C3CULL
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
		0x4E3C16A871710E61ULL,
		0xB2A7FFD25FAB810CULL,
		0xCD598233DCF488C4ULL,
		0xF3CD79D18E52FC2EULL,
		0xC47BF86797C8F201ULL,
		0x3317C73C0B93BC61ULL,
		0x907C0AECD5245095ULL,
		0x0A8B700D3F7979CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5E1BA3A8C258E93ULL,
		0x112BE3D9E86919B4ULL,
		0x5BF26D1E4C988AD5ULL,
		0x0BB5F56668C3554AULL,
		0x2EA88E42B8E354ECULL,
		0x97B92D46F58BD555ULL,
		0x3FE96896AA677889ULL,
		0xDC616CDCA6E151E2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x685A5C6DE54B7FCEULL,
		0xA17C1BF877426757ULL,
		0x71671515905BFDEFULL,
		0xE817846B258FA6E4ULL,
		0x95D36A24DEE59D15ULL,
		0x9B5E99F51607E70CULL,
		0x5092A2562ABCD80BULL,
		0x2E2A0330989827ECULL
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
		0x671174D89B7EA67EULL,
		0xF53FBCDE771859EFULL,
		0xEBC5194F7815AD76ULL,
		0x90C4ECD72AA91559ULL,
		0xDD36EBB0D3083209ULL,
		0x7566CC9D776AD779ULL,
		0x7C5DDE74F824B426ULL,
		0xE6D403AC443D51A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D6347B212F55D9BULL,
		0x12AA6B63B8F0407BULL,
		0xD112932B0D20CD82ULL,
		0x1DD1E57285042B58ULL,
		0xADFFBFFDAA7C0E6AULL,
		0x8FF2BF92202160CAULL,
		0xF9B0735DD087017AULL,
		0x5346819F96F467D8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x59AE2D26888948E3ULL,
		0xE295517ABE281974ULL,
		0x1AB286246AF4DFF4ULL,
		0x72F30764A5A4EA01ULL,
		0x2F372BB3288C239FULL,
		0xE5740D0B574976AFULL,
		0x82AD6B17279DB2ABULL,
		0x938D820CAD48E9CEULL
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
		0x180673D9D8650B79ULL,
		0xDFDA0CBB3493C863ULL,
		0xA5010261F1A005B8ULL,
		0x6CA4515FF53DC0CDULL,
		0xC97D29000080B18DULL,
		0x11756E81A26937A0ULL,
		0x6496A6CC6E18D286ULL,
		0x21CEB99B78216602ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDFE99F2197A565EULL,
		0xEE801ACA5A9F225DULL,
		0x51A9540AE67F482FULL,
		0xDD836CBB8722BBA5ULL,
		0xD90261C5E9C74040ULL,
		0x6126855B18855270ULL,
		0x9AC33CE594C95CAAULL,
		0xE1CEEB9AC2B953CFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1A07D9E7BEEAB51BULL,
		0xF159F1F0D9F4A605ULL,
		0x5357AE570B20BD88ULL,
		0x8F20E4A46E1B0528ULL,
		0xF07AC73A16B9714CULL,
		0xB04EE92689E3E52FULL,
		0xC9D369E6D94F75DBULL,
		0x3FFFCE00B5681232ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x4164A2B04C109A57ULL,
		0xC59F9A76E83F2C4AULL,
		0xA58FA44DF803F6DDULL,
		0x71A03FA77B85765BULL,
		0x27F4A1D9BD76AEF5ULL,
		0xDB4E0714FF4D5685ULL,
		0x07ECA06BCC584A60ULL,
		0xBF99391D93C85BF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37D6C277C94BC604ULL,
		0x0CEE555ACDE3468AULL,
		0xA6DE5FBF3CFD3E94ULL,
		0x0A7014F4CA0EEEA0ULL,
		0xF238609F27A8188BULL,
		0x75A15A5E12D6E25FULL,
		0xE8680224F6A71374ULL,
		0xA23347876265BF50ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x098DE03882C4D453ULL,
		0xB8B1451C1A5BE5C0ULL,
		0xFEB1448EBB06B849ULL,
		0x67302AB2B17687BAULL,
		0x35BC413A95CE966AULL,
		0x65ACACB6EC767425ULL,
		0x1F849E46D5B136ECULL,
		0x1D65F19631629CA3ULL
	}};
	sign = 0;
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
		0x41345427C76C90F1ULL,
		0x511DFE712C1846BCULL,
		0xA3F8ABD337B17360ULL,
		0x5AE90EDA3526DB9EULL,
		0x91E6F4254C357E3AULL,
		0xF2CB9C9E9B65C264ULL,
		0xFCCC6A4AE5DB1DD8ULL,
		0xCF6FDA233C78E5D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB277AAA4FF450AD4ULL,
		0xAC09E8E0D4196DE8ULL,
		0x4C812316882C409CULL,
		0x64606238FFB31BF1ULL,
		0xDF0F2946152F79B7ULL,
		0x3FB5069B091F4258ULL,
		0xD995D7ABAA64890DULL,
		0xAE5A6FC86E5956E0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8EBCA982C827861DULL,
		0xA514159057FED8D3ULL,
		0x577788BCAF8532C3ULL,
		0xF688ACA13573BFADULL,
		0xB2D7CADF37060482ULL,
		0xB31696039246800BULL,
		0x2336929F3B7694CBULL,
		0x21156A5ACE1F8EF4ULL
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
		0xEF275AB1EC040614ULL,
		0x4A840F331D1C4B55ULL,
		0x3F74C193B1BAB652ULL,
		0x5BB6C213DAFBAB29ULL,
		0x2B5F09EA97D11665ULL,
		0xF345C3601163984BULL,
		0x2A55DDEF52F5A4A8ULL,
		0xB93539AB4E7CE24DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DC9918BDCB2FD7AULL,
		0x33EA5279E7D813BFULL,
		0xD675FA0319CEE81CULL,
		0xD0E8E511C528BCCDULL,
		0x2F0722ED0B37E4AFULL,
		0x024CD8312E7942B1ULL,
		0x782F6BAEB8226FB4ULL,
		0x2BB335C344AADB4EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA15DC9260F51089AULL,
		0x1699BCB935443796ULL,
		0x68FEC79097EBCE36ULL,
		0x8ACDDD0215D2EE5BULL,
		0xFC57E6FD8C9931B5ULL,
		0xF0F8EB2EE2EA5599ULL,
		0xB22672409AD334F4ULL,
		0x8D8203E809D206FEULL
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
		0x93D4AD7CDA885B14ULL,
		0xEA6653AB26FD9225ULL,
		0x54D534FE50B12607ULL,
		0xD847B12F3C592DABULL,
		0x093ADFB6F5CC374FULL,
		0x9A0DF604F0874D01ULL,
		0x478A3624C9F584F0ULL,
		0x13521B8C4156329DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x075E4E96CC58D495ULL,
		0x836BABAA58020B6CULL,
		0xFFB81C1EAC0CD7E2ULL,
		0x722CA864DD51D51FULL,
		0xDB2A3E49178502F2ULL,
		0xFAA014B5B5821F33ULL,
		0x1EF5C15FC6430CB7ULL,
		0x49F5C9B89C267C89ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8C765EE60E2F867FULL,
		0x66FAA800CEFB86B9ULL,
		0x551D18DFA4A44E25ULL,
		0x661B08CA5F07588BULL,
		0x2E10A16DDE47345DULL,
		0x9F6DE14F3B052DCDULL,
		0x289474C503B27838ULL,
		0xC95C51D3A52FB614ULL
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
		0xFEC072FFED09CE27ULL,
		0x9F5F74F9871F77B7ULL,
		0xD6E35F549147D4A2ULL,
		0xCB9A0247FE0D60DEULL,
		0x509AC9FFE7C072BBULL,
		0xB35265CACA3E709DULL,
		0xC1E11A86DBE3737DULL,
		0x1A005912947E6199ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF238787B1F7E30DULL,
		0x325ED9F87D412431ULL,
		0x0B2AB37C6F89498BULL,
		0x945848DF458F3E87ULL,
		0xCD9A4430D3FF3A34ULL,
		0x3D34CE3011811338ULL,
		0x631714A7C28D6171ULL,
		0x6A49625C6CA44009ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFF9CEB783B11EB1AULL,
		0x6D009B0109DE5385ULL,
		0xCBB8ABD821BE8B17ULL,
		0x3741B968B87E2257ULL,
		0x830085CF13C13887ULL,
		0x761D979AB8BD5D64ULL,
		0x5ECA05DF1956120CULL,
		0xAFB6F6B627DA2190ULL
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
		0xBF80FE2118A2A89AULL,
		0x1126B25E90FB06EFULL,
		0x82191D9FBDEC503AULL,
		0xCB511F09577BEBAFULL,
		0x4C6A5AECF2E41BB2ULL,
		0x7913E91C9DE960F9ULL,
		0x70D67673FC442757ULL,
		0x9CFBA26D0CD34D8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F22AD03F5ABB3FEULL,
		0x079560DC5B2D4E6CULL,
		0x5A50A4E782A8E308ULL,
		0x8367B6843F031111ULL,
		0x0F3542004E709DDDULL,
		0x2A7011314A44B287ULL,
		0x27CCD8079587C078ULL,
		0xBCD1945BA2BB992BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x305E511D22F6F49CULL,
		0x0991518235CDB883ULL,
		0x27C878B83B436D32ULL,
		0x47E968851878DA9EULL,
		0x3D3518ECA4737DD5ULL,
		0x4EA3D7EB53A4AE72ULL,
		0x49099E6C66BC66DFULL,
		0xE02A0E116A17B464ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x6EB11B8F87A250F6ULL,
		0x428945943FDDEA2AULL,
		0x63CEFCB4CC7FF2C0ULL,
		0x5E63F4DE2A6E29EEULL,
		0xCC495773DE89D7A6ULL,
		0xF7F82D2E6B811480ULL,
		0x664C2A504A18AA16ULL,
		0x2BFC281F7763A598ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99FC1AB9C596BB29ULL,
		0xAEA1F6F2C9FE5DECULL,
		0xFE2B1DD489F6393EULL,
		0x99F2C6F0E9486F4AULL,
		0xDFCF4B7CDB2B2195ULL,
		0xF3B6DD179E96BEB9ULL,
		0x11CF91D14DAA9F20ULL,
		0xC4AA6EE086BD5549ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD4B500D5C20B95CDULL,
		0x93E74EA175DF8C3DULL,
		0x65A3DEE04289B981ULL,
		0xC4712DED4125BAA3ULL,
		0xEC7A0BF7035EB610ULL,
		0x04415016CCEA55C6ULL,
		0x547C987EFC6E0AF6ULL,
		0x6751B93EF0A6504FULL
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
		0x0EE93FFF94FEF1E5ULL,
		0xC6481CC167DF71B5ULL,
		0xFCE8647A2FF499D1ULL,
		0x820F749547E3AE56ULL,
		0x116404B656421C20ULL,
		0x9E897D914A12F102ULL,
		0xDB979C9528D876F0ULL,
		0x1306D86EE96F5D58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFCB243B08412D9EULL,
		0xEC3BBD0C3D92E231ULL,
		0xEC2EB090AE495115ULL,
		0x0125F2A7D6082363ULL,
		0x6262122D3556974CULL,
		0xBAFBD7009BFFBF6EULL,
		0x7F30D08FF37646E4ULL,
		0x652AEADEBC7DE597ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5F1E1BC48CBDC447ULL,
		0xDA0C5FB52A4C8F83ULL,
		0x10B9B3E981AB48BBULL,
		0x80E981ED71DB8AF3ULL,
		0xAF01F28920EB84D4ULL,
		0xE38DA690AE133193ULL,
		0x5C66CC053562300BULL,
		0xADDBED902CF177C1ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x3CEB08411D6FE496ULL,
		0x7901D3D222A0AB31ULL,
		0x8E3DAE4E52254673ULL,
		0x9BF5A2097C58E85AULL,
		0x90EBA5A783FC91A1ULL,
		0xA442B6752C41B269ULL,
		0xE5E386169966C87AULL,
		0xCB412B13144B2AADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8208EF60961EC10ULL,
		0x0675952CB3F21F4FULL,
		0xDA094BEF91D34C43ULL,
		0x6D75C43A845A0627ULL,
		0x634D7582CAEC2BA8ULL,
		0x5FD94CD739172CF7ULL,
		0x78B248F3C111D46FULL,
		0x40D41164A6120388ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x64CA794B140DF886ULL,
		0x728C3EA56EAE8BE1ULL,
		0xB434625EC051FA30ULL,
		0x2E7FDDCEF7FEE232ULL,
		0x2D9E3024B91065F9ULL,
		0x4469699DF32A8572ULL,
		0x6D313D22D854F40BULL,
		0x8A6D19AE6E392725ULL
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
		0x75A6C8A7F81FA676ULL,
		0x738211DBC7CDB6B1ULL,
		0x2CB4172B1F9D26F8ULL,
		0x4638762623BC9727ULL,
		0xA0E805B098A970D7ULL,
		0xE5E8D938EF1CADF2ULL,
		0x6E29BF2ECB0F9B38ULL,
		0x792833CB7792C91CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69359DBA69E8B200ULL,
		0x3C51555E9B3384D5ULL,
		0x194B550A1D46317CULL,
		0x794EFDB607DF7C00ULL,
		0x033BE775B837DFFAULL,
		0xC5C8FFFA80F86E2CULL,
		0x0CC12A8B5F4CE16CULL,
		0xCCA0004B388EC0E9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C712AED8E36F476ULL,
		0x3730BC7D2C9A31DCULL,
		0x1368C2210256F57CULL,
		0xCCE978701BDD1B27ULL,
		0x9DAC1E3AE07190DCULL,
		0x201FD93E6E243FC6ULL,
		0x616894A36BC2B9CCULL,
		0xAC8833803F040833ULL
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
		0xE66727B71A773D31ULL,
		0xDA95C3EF22317082ULL,
		0x5438D1C7A555EA0CULL,
		0xB0C83A4FA5921091ULL,
		0x1DAA57668E20B81AULL,
		0x35962B61E6452C4AULL,
		0x6B779D15244A84E4ULL,
		0x0E4DE308521CBCF9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0706D9F0AB45CDA2ULL,
		0xD6A8136CC26DF985ULL,
		0xD828C48CEC86FBA4ULL,
		0x48A870FB8C2BF373ULL,
		0x7F0B2FCB9F8CD5A3ULL,
		0xB58C046456256C25ULL,
		0x72665847F62CD748ULL,
		0xA102D7C8F5899230ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDF604DC66F316F8FULL,
		0x03EDB0825FC376FDULL,
		0x7C100D3AB8CEEE68ULL,
		0x681FC95419661D1DULL,
		0x9E9F279AEE93E277ULL,
		0x800A26FD901FC024ULL,
		0xF91144CD2E1DAD9BULL,
		0x6D4B0B3F5C932AC8ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x0915BB407B5FC988ULL,
		0xDB049C29B666D822ULL,
		0xF70CCA44D945D762ULL,
		0x5F0E2F0205D99668ULL,
		0xDF4C9F05F62F6A9CULL,
		0xE352B6796A774175ULL,
		0x82F752C34A78DEE1ULL,
		0xF9F968DFA6C9B112ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AF9C6963CDE7A0DULL,
		0x3FAFEBB8C9E1DF4BULL,
		0xD1625240617D8F62ULL,
		0xD612C7CE87F89B3DULL,
		0x00D6AEA75D9885ABULL,
		0x14FA208D308CE1AAULL,
		0x4535780DB7EDB1D2ULL,
		0xDF441791BFA40FAFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEE1BF4AA3E814F7BULL,
		0x9B54B070EC84F8D6ULL,
		0x25AA780477C84800ULL,
		0x88FB67337DE0FB2BULL,
		0xDE75F05E9896E4F0ULL,
		0xCE5895EC39EA5FCBULL,
		0x3DC1DAB5928B2D0FULL,
		0x1AB5514DE725A163ULL
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
		0x026309852EC32338ULL,
		0x790D256A7ED1A342ULL,
		0x15DEA04C441C296BULL,
		0x5461229D9BA168DFULL,
		0xF362BC163D604851ULL,
		0x2E174D017D03E8D7ULL,
		0x92977FFF697CD0EAULL,
		0xD8AE1526719A7DD3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F0721B7C57AB903ULL,
		0x8AE5010BFC8E82A6ULL,
		0x2474D6F5FD46D9FAULL,
		0x037BF8FFC09AFAF4ULL,
		0x9184D7D9F416110CULL,
		0x9219951742B06BDBULL,
		0x63D02171E344A9A5ULL,
		0xBC27846120325A05ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x635BE7CD69486A35ULL,
		0xEE28245E8243209BULL,
		0xF169C95646D54F70ULL,
		0x50E5299DDB066DEAULL,
		0x61DDE43C494A3745ULL,
		0x9BFDB7EA3A537CFCULL,
		0x2EC75E8D86382744ULL,
		0x1C8690C5516823CEULL
	}};
	sign = 0;
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
		0x4A4DB1040473F88BULL,
		0x8F0EE384649BFB7BULL,
		0x54BF4FB469E6A59BULL,
		0x09285E121E722810ULL,
		0x5881086948735709ULL,
		0x61D1554E42A27F3AULL,
		0x4DEE584616A3D0F3ULL,
		0x560D685A7642826BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9835EE63D6B95AEFULL,
		0x6A8B01C9D1FA6FEEULL,
		0x6D577583D9F00CF2ULL,
		0xFCCDEC08F4B05F62ULL,
		0xE38F7B6822205B49ULL,
		0x97291B646E6132B7ULL,
		0x10D3325AA9CEFBE8ULL,
		0x355F6E3BDA134A23ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB217C2A02DBA9D9CULL,
		0x2483E1BA92A18B8CULL,
		0xE767DA308FF698A9ULL,
		0x0C5A720929C1C8ADULL,
		0x74F18D012652FBBFULL,
		0xCAA839E9D4414C82ULL,
		0x3D1B25EB6CD4D50AULL,
		0x20ADFA1E9C2F3848ULL
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
		0xDE9F60688BAFBC05ULL,
		0xA1E396B510B34133ULL,
		0x2F8B92271E444668ULL,
		0xD06E230072228AE7ULL,
		0x38E0645392329AACULL,
		0x0872B99AA770F2D1ULL,
		0x3659360C0E524ECDULL,
		0x868A8A5E63B49BB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6AFE77F249E3F47ULL,
		0xFC783CDA9E17EA7CULL,
		0xE91676516510A072ULL,
		0x2A7A723383388661ULL,
		0xDDCF2C4DE7E0F521ULL,
		0x8464D943E3270FE0ULL,
		0x0EEEF04F3E23A6C4ULL,
		0xF1FDB6257EBF1D4DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE7EF78E967117CBEULL,
		0xA56B59DA729B56B6ULL,
		0x46751BD5B933A5F5ULL,
		0xA5F3B0CCEEEA0485ULL,
		0x5B113805AA51A58BULL,
		0x840DE056C449E2F0ULL,
		0x276A45BCD02EA808ULL,
		0x948CD438E4F57E6AULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x0F545726C130A0D8ULL,
		0x0CBC5089054B5357ULL,
		0xEC38C10C64987C1EULL,
		0x3F5E660E2CA12E39ULL,
		0xCDA178AF945098F8ULL,
		0x06AA346B2F428919ULL,
		0x8E0D8DDE685BE17CULL,
		0x287E0E9F348292E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D92F05DC24F247FULL,
		0xA2D60D82DA40D5BCULL,
		0x45A1AE596896174BULL,
		0x77D121AEE69421FDULL,
		0xADC62A94E97BD06DULL,
		0x4869AD2B0E23AB22ULL,
		0x4A2543356DD85830ULL,
		0x05B4E0CA078865BEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x91C166C8FEE17C59ULL,
		0x69E643062B0A7D9AULL,
		0xA69712B2FC0264D2ULL,
		0xC78D445F460D0C3CULL,
		0x1FDB4E1AAAD4C88AULL,
		0xBE408740211EDDF7ULL,
		0x43E84AA8FA83894BULL,
		0x22C92DD52CFA2D23ULL
	}};
	sign = 0;
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
		0x1E75DA20664EEB42ULL,
		0xE4FB80B1234CFB9DULL,
		0xDD95F15D6EF90C72ULL,
		0x746022F79C9DB97BULL,
		0xDCE5A8C775979115ULL,
		0x646C33B65004D236ULL,
		0x9F966587A56FB176ULL,
		0x60AA158FE900C280ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB801DD4216F91F00ULL,
		0xE09C93E1A40044B5ULL,
		0xD043401DB9A0086DULL,
		0x9461F145DE70528EULL,
		0xE70A4F7E6B47043CULL,
		0x4A1771D5B7CCA2E3ULL,
		0x2FC72FA2C963DE5AULL,
		0xA2006C724B7C6CC0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6673FCDE4F55CC42ULL,
		0x045EECCF7F4CB6E7ULL,
		0x0D52B13FB5590405ULL,
		0xDFFE31B1BE2D66EDULL,
		0xF5DB59490A508CD8ULL,
		0x1A54C1E098382F52ULL,
		0x6FCF35E4DC0BD31CULL,
		0xBEA9A91D9D8455C0ULL
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
		0xE1C30EEDB8C643E2ULL,
		0xFFEAC126ACE9AF50ULL,
		0x3A868D9204EB8F2CULL,
		0x561C8BFDF517730AULL,
		0xC4B0D102C4E31A4CULL,
		0x6018FBD52F26B1E0ULL,
		0x356BB02C19D06987ULL,
		0xD6EA25151E12282BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC20747E21C77A612ULL,
		0x0EA494EA815E4444ULL,
		0x10C0CB5E5A9132CAULL,
		0xDA6AE5BABE1E81FBULL,
		0xA6449479C3BB641FULL,
		0x64ED87AC099A7955ULL,
		0x8E8C07126C45B369ULL,
		0x9B052911A567EC5BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1FBBC70B9C4E9DD0ULL,
		0xF1462C3C2B8B6B0CULL,
		0x29C5C233AA5A5C62ULL,
		0x7BB1A64336F8F10FULL,
		0x1E6C3C890127B62CULL,
		0xFB2B7429258C388BULL,
		0xA6DFA919AD8AB61DULL,
		0x3BE4FC0378AA3BCFULL
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
		0x562D69732F3FD5E4ULL,
		0xF58DBDD9B0726179ULL,
		0xF7F2E90B7CFA5905ULL,
		0xB5C11630A70AA6E0ULL,
		0x50AB07D5A023354EULL,
		0x442F7D38001C6F71ULL,
		0x6A04591B129AE6A8ULL,
		0xD6483F5D4E875362ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFAF6E03754C7FCEAULL,
		0x7138019CD818D908ULL,
		0x1F3D74BD67632420ULL,
		0xD83CB0A42F35026CULL,
		0xA28A517CB01C6739ULL,
		0x27316AC8B7188AABULL,
		0xAC59AF53F980420FULL,
		0xC5575035E68D3CE4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5B36893BDA77D8FAULL,
		0x8455BC3CD8598870ULL,
		0xD8B5744E159734E5ULL,
		0xDD84658C77D5A474ULL,
		0xAE20B658F006CE14ULL,
		0x1CFE126F4903E4C5ULL,
		0xBDAAA9C7191AA499ULL,
		0x10F0EF2767FA167DULL
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
		0xFC886CD00BDCECF8ULL,
		0x2050F4444B447AA4ULL,
		0xF5FBF5FE32AFBD86ULL,
		0x00E67C4401AD1726ULL,
		0xF070390ADBEEF942ULL,
		0xB3BD6663FE8BD767ULL,
		0x16C0EE9EDD0BDAAFULL,
		0x6402E3DC1AFFA4C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x768B133C48BADD09ULL,
		0x0973AE6652DF8672ULL,
		0x482A375292BC7887ULL,
		0x056DCF2407546240ULL,
		0x9F630C216DAD9991ULL,
		0x776550EB71A27823ULL,
		0xA6072CF53F66C8A9ULL,
		0xFF839476D0B11200ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x85FD5993C3220FEFULL,
		0x16DD45DDF864F432ULL,
		0xADD1BEAB9FF344FFULL,
		0xFB78AD1FFA58B4E6ULL,
		0x510D2CE96E415FB0ULL,
		0x3C5815788CE95F44ULL,
		0x70B9C1A99DA51206ULL,
		0x647F4F654A4E92C5ULL
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
		0x34279979766EF616ULL,
		0x8EFADF75B5D0956CULL,
		0x937680516F2D5611ULL,
		0x6AB500F66DA91D50ULL,
		0xC5D9550F3EA55F7AULL,
		0xDA1024F647ADA3A8ULL,
		0xED0F023CB4F222EAULL,
		0x77EA05FD8802B87FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8220F52EF72C4C43ULL,
		0x074AF0D55E6B4791ULL,
		0x42BC3594BCF8CF86ULL,
		0xC7ADD03E9CF5A866ULL,
		0xDB887EFB9386E250ULL,
		0xD93CDE59E696E6C1ULL,
		0xDC808EA331ED190CULL,
		0x6D7531047D8F7C78ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB206A44A7F42A9D3ULL,
		0x87AFEEA057654DDAULL,
		0x50BA4ABCB234868BULL,
		0xA30730B7D0B374EAULL,
		0xEA50D613AB1E7D29ULL,
		0x00D3469C6116BCE6ULL,
		0x108E7399830509DEULL,
		0x0A74D4F90A733C07ULL
	}};
	sign = 0;
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
		0x3A74E7CDDD5CEE65ULL,
		0x46C4BBD4F18C1337ULL,
		0x9E680082729ADEF2ULL,
		0x9574E7DAFEC9F4EFULL,
		0xD8FFF0D6AE38E900ULL,
		0xEC1DB1ED596C0D32ULL,
		0x7F0B3FF44EFC2DFAULL,
		0x54472382EC156265ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07F375667556CA73ULL,
		0xC27B93A9D7B6F458ULL,
		0x94A563DB2066A46AULL,
		0x3C4BBEE525F9880CULL,
		0x64E880150E24A343ULL,
		0x97A7147A29CEC146ULL,
		0x7755269558066F4BULL,
		0xB11220EA1F10D8A4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x32817267680623F2ULL,
		0x8449282B19D51EDFULL,
		0x09C29CA752343A87ULL,
		0x592928F5D8D06CE3ULL,
		0x741770C1A01445BDULL,
		0x54769D732F9D4BECULL,
		0x07B6195EF6F5BEAFULL,
		0xA3350298CD0489C1ULL
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
		0x61DEEAB89D91DCE5ULL,
		0xF2A3378239FAABA5ULL,
		0xEE03BBCF29BE099AULL,
		0xF2F3B23543A84319ULL,
		0xA149155DEAA7C874ULL,
		0x577B30A556ADEDEAULL,
		0xAE33003E5E0FAFD6ULL,
		0xAE788BAF3FA8CC7CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A3DED4A26E5A360ULL,
		0x59D86606319370FDULL,
		0xB5D6870ECD0FC916ULL,
		0x817F252FC4874F40ULL,
		0x2747E1196DBAB6A3ULL,
		0x391FEB3B7B86CB38ULL,
		0xAA38A3400665B756ULL,
		0x4B33B7C2B946CACCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x27A0FD6E76AC3985ULL,
		0x98CAD17C08673AA8ULL,
		0x382D34C05CAE4084ULL,
		0x71748D057F20F3D9ULL,
		0x7A0134447CED11D1ULL,
		0x1E5B4569DB2722B2ULL,
		0x03FA5CFE57A9F880ULL,
		0x6344D3EC866201B0ULL
	}};
	sign = 0;
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
		0x3D95E9C61997D570ULL,
		0x48C553997FAF67F4ULL,
		0x0884308A29026F4CULL,
		0xB8F80BF24FACE9D3ULL,
		0xBC1F49FB5D7500ADULL,
		0x91F28A1647271E68ULL,
		0xF8BDB5D88CDF6738ULL,
		0x1B55C843FE8DA9ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3313433CF622FDC4ULL,
		0x3711268A334B3429ULL,
		0x2409BE59BF4485ACULL,
		0x9C95810CDFF18C2AULL,
		0xAABB6A356C0F80EBULL,
		0xCC981B006B17AF97ULL,
		0x6E129757BD12244EULL,
		0xFD2E68F126712185ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A82A6892374D7ACULL,
		0x11B42D0F4C6433CBULL,
		0xE47A723069BDE9A0ULL,
		0x1C628AE56FBB5DA8ULL,
		0x1163DFC5F1657FC2ULL,
		0xC55A6F15DC0F6ED1ULL,
		0x8AAB1E80CFCD42E9ULL,
		0x1E275F52D81C8827ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xBE51613292ADED1FULL,
		0xAA9D0349D1C663F4ULL,
		0x3A95643DE61CEF08ULL,
		0xA6F6300E07FC9987ULL,
		0x54D384D7EE96D6BDULL,
		0xF0561E414E3C4542ULL,
		0x93F12E0CC1669B8FULL,
		0x085F163DBFC8948FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x285475DB80BBA5F8ULL,
		0x58142DA3A9139169ULL,
		0x91DA5654ED1DB6E8ULL,
		0x5BBB41C5C92366A5ULL,
		0xBC0DB737F7857EBDULL,
		0x67DA50A4975F595BULL,
		0x1B05D66F9AFCBFF4ULL,
		0xC30F7AF152643C67ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x95FCEB5711F24727ULL,
		0x5288D5A628B2D28BULL,
		0xA8BB0DE8F8FF3820ULL,
		0x4B3AEE483ED932E1ULL,
		0x98C5CD9FF7115800ULL,
		0x887BCD9CB6DCEBE6ULL,
		0x78EB579D2669DB9BULL,
		0x454F9B4C6D645828ULL
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
		0x341DB8DFEF489D8FULL,
		0x74BC1F1CDE5C31D2ULL,
		0xCCCA3036E971235DULL,
		0xB86FCA09AC8B55F6ULL,
		0x27D20614D8591347ULL,
		0x2EDB5575C0D24FE2ULL,
		0xE9C8CC867E481997ULL,
		0xA896B52450AB0927ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1FE335DC61932666ULL,
		0xF4BAB4934751FC00ULL,
		0x3AB28D58CCF0AE55ULL,
		0x1616C97F046F69A3ULL,
		0xAF686802B919D744ULL,
		0x0E0E30F52DFCB1BCULL,
		0x9F034C8DCA5BD720ULL,
		0x2877F71DF3FF768BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x143A83038DB57729ULL,
		0x80016A89970A35D2ULL,
		0x9217A2DE1C807507ULL,
		0xA259008AA81BEC53ULL,
		0x78699E121F3F3C03ULL,
		0x20CD248092D59E25ULL,
		0x4AC57FF8B3EC4277ULL,
		0x801EBE065CAB929CULL
	}};
	sign = 0;
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
		0xBE8459EF1E4B797DULL,
		0x4B6254FF54E61B3DULL,
		0x666BCA2A0658D6CBULL,
		0x8A78B8953520A05EULL,
		0x11D6CFFF87EF56FCULL,
		0x4D465F04A3668D90ULL,
		0x842B9F759B4F8194ULL,
		0x89B8916EF90A2BABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6FC21D283E389E8BULL,
		0xF5F66705C8EF7FC7ULL,
		0xE76AC80125E57A47ULL,
		0x66B4F8141FA9045BULL,
		0x700BBA9D7466F4BFULL,
		0xD63D6DDF9F6F687DULL,
		0x6EDDACBD489125ACULL,
		0xEDAADF14C5A2CE84ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4EC23CC6E012DAF2ULL,
		0x556BEDF98BF69B76ULL,
		0x7F010228E0735C83ULL,
		0x23C3C08115779C02ULL,
		0xA1CB15621388623DULL,
		0x7708F12503F72512ULL,
		0x154DF2B852BE5BE7ULL,
		0x9C0DB25A33675D27ULL
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
		0x3DD72AB31B40D400ULL,
		0x38315902CF765BCAULL,
		0xC4FC9A174969526EULL,
		0x1EAFF674B4B6C458ULL,
		0x46D89F0467E0B56EULL,
		0xF607A94775904329ULL,
		0xF00E9E4DC32343D0ULL,
		0x324376A97897C5D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x625E9764CCAEF529ULL,
		0xEECD0A8FEC24A147ULL,
		0xBFE9801E01AB9625ULL,
		0x75F425A3C7A53F94ULL,
		0x0674FB7391D35188ULL,
		0x6F4857FBD2A036C6ULL,
		0x025C05EC1D92C94AULL,
		0xB567DF0A13F630CAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDB78934E4E91DED7ULL,
		0x49644E72E351BA82ULL,
		0x051319F947BDBC48ULL,
		0xA8BBD0D0ED1184C4ULL,
		0x4063A390D60D63E5ULL,
		0x86BF514BA2F00C63ULL,
		0xEDB29861A5907A86ULL,
		0x7CDB979F64A1950AULL
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
		0xB40DCE4822C7D0CDULL,
		0x26ED9C1BD3D40DFDULL,
		0x8D3D73C3A17B06F8ULL,
		0x1F25789DA682C0FFULL,
		0xC1299387755F2DEEULL,
		0xEF4FF6C1A705FBDFULL,
		0x7871C43A2D53F312ULL,
		0xBA4DE0AEF763C3DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E0C1C8B518EFA7BULL,
		0xE85ACD36C9506E9AULL,
		0xBB72D08DAD7D850FULL,
		0x250F130E36D0201EULL,
		0x2DDD3916D434D0F3ULL,
		0xA2FAD500F250388BULL,
		0x631450C57172AB68ULL,
		0x3A9C3F50EA8688FBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA601B1BCD138D652ULL,
		0x3E92CEE50A839F63ULL,
		0xD1CAA335F3FD81E8ULL,
		0xFA16658F6FB2A0E0ULL,
		0x934C5A70A12A5CFAULL,
		0x4C5521C0B4B5C354ULL,
		0x155D7374BBE147AAULL,
		0x7FB1A15E0CDD3ADFULL
	}};
	sign = 0;
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
		0xA3AAD78F7A82BBDBULL,
		0x0FABCA3DA1609953ULL,
		0x4EEA555A7878C434ULL,
		0x5278B250050AF793ULL,
		0xC28240DA00423F42ULL,
		0xE7CB68F9B88A32A6ULL,
		0x0520AEEC8B47C7C3ULL,
		0x401889CCABE4BBBAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE7498C5CCCB9E17ULL,
		0x5E6B28AFF14A3646ULL,
		0xEA62D2F29B31B72DULL,
		0x3F41DCCC58A15026ULL,
		0x255E7C52AE9AA8DBULL,
		0x2EDF4848123D13FDULL,
		0xAF7862F1FA6C65B7ULL,
		0x32A3351E58F2D284ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD5363EC9ADB71DC4ULL,
		0xB140A18DB016630CULL,
		0x64878267DD470D06ULL,
		0x1336D583AC69A76CULL,
		0x9D23C48751A79667ULL,
		0xB8EC20B1A64D1EA9ULL,
		0x55A84BFA90DB620CULL,
		0x0D7554AE52F1E935ULL
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
		0xFD0F7AD1BF1DE651ULL,
		0x6E45A9864C894186ULL,
		0x1A897F88275F62FEULL,
		0xF7FC31D32CAD6FABULL,
		0x4D9D3C89C00E6FA5ULL,
		0x5EA6B0B10C6D5394ULL,
		0x621A41479FC956E1ULL,
		0xDF9DED87ABF99B50ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1FD4D24560C23B6ULL,
		0xF7EC61EEA5C58A93ULL,
		0xBC554CA8E5C44C8AULL,
		0x0D09B23DF6ABCF8DULL,
		0x29FFB114B5672EA0ULL,
		0x79C30B2EEBBFD2D0ULL,
		0x05FE8534D38A058FULL,
		0x753EB511D8C3684FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1B122DAD6911C29BULL,
		0x76594797A6C3B6F3ULL,
		0x5E3432DF419B1673ULL,
		0xEAF27F953601A01DULL,
		0x239D8B750AA74105ULL,
		0xE4E3A58220AD80C4ULL,
		0x5C1BBC12CC3F5151ULL,
		0x6A5F3875D3363301ULL
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
		0x5178735718C9B7BCULL,
		0x922E4BE18D82677AULL,
		0x57780FFA63EBB419ULL,
		0x11D18ADDD26C74D0ULL,
		0x4A3769388ABFEEB7ULL,
		0x1CC5D93478F88CDDULL,
		0x54AF4245BCCC8F39ULL,
		0x602AD2D1F463CA25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD60B2979AC818C5ULL,
		0x9B2973635FCBF60CULL,
		0x758C2C95584F5780ULL,
		0x16A5CBC2A69A1DCBULL,
		0x1B77EC3B21BA0BABULL,
		0x51243F0FB78E2DC3ULL,
		0x8527205F760FA9D3ULL,
		0x5E612AF4DB8BDA3FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5417C0BF7E019EF7ULL,
		0xF704D87E2DB6716DULL,
		0xE1EBE3650B9C5C98ULL,
		0xFB2BBF1B2BD25704ULL,
		0x2EBF7CFD6905E30BULL,
		0xCBA19A24C16A5F1AULL,
		0xCF8821E646BCE565ULL,
		0x01C9A7DD18D7EFE5ULL
	}};
	sign = 0;
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
		0x2E37E9B859435845ULL,
		0x75AC15EA6B01ADABULL,
		0x37D75A5961BA6F0BULL,
		0x9EE808FF843C2225ULL,
		0xFE94010A109BC7B7ULL,
		0x2C41EEB24B6F6A41ULL,
		0xBDDC8CAC79194C24ULL,
		0x01A6BF6729F50C43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89D42E5F1B34B17BULL,
		0x8B25EEF3CA672932ULL,
		0xDE4479CA48DD5CD7ULL,
		0x4A4C4830D4AF53F3ULL,
		0x8ED0184598E81AAAULL,
		0xB53B9F68C2A8164DULL,
		0xB81B87F8508FCA6CULL,
		0xD20D16D5BCA923B9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA463BB593E0EA6CAULL,
		0xEA8626F6A09A8478ULL,
		0x5992E08F18DD1233ULL,
		0x549BC0CEAF8CCE31ULL,
		0x6FC3E8C477B3AD0DULL,
		0x77064F4988C753F4ULL,
		0x05C104B4288981B7ULL,
		0x2F99A8916D4BE88AULL
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
		0xD23BE27BF2FD7F0CULL,
		0x025797F477E8158FULL,
		0xBFE7015AA05F09FBULL,
		0xFD7891A35160D722ULL,
		0xC6D4B4BD755C2FE2ULL,
		0x9F4BA9915B9F3A3BULL,
		0x3D03C8D376E981CEULL,
		0x854370E0C9EF43D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC0128EFC79D75BFULL,
		0x73B9241E1FCA7AD4ULL,
		0x0690EBE67F1351F7ULL,
		0x1FC1F697AF151EF0ULL,
		0x94ADFF1543C73996ULL,
		0x675E77D4B3C92441ULL,
		0x04D15BBF3BC6846AULL,
		0x5D5623ED63E76857ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x163AB98C2B60094DULL,
		0x8E9E73D6581D9ABBULL,
		0xB9561574214BB803ULL,
		0xDDB69B0BA24BB832ULL,
		0x3226B5A83194F64CULL,
		0x37ED31BCA7D615FAULL,
		0x38326D143B22FD64ULL,
		0x27ED4CF36607DB7AULL
	}};
	sign = 0;
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
		0x99A8B6739B0549A1ULL,
		0x3C38198C39A79AF5ULL,
		0x53A32668655CCAD2ULL,
		0x608F2A3BB3B74EF5ULL,
		0x9322EB209FDC4CC0ULL,
		0x26CDF5CA5DE38E0AULL,
		0xA9A8189FB422A740ULL,
		0x8931E957D397718EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7AB34D1F5647542FULL,
		0x41FEA8E129E3E55BULL,
		0xEAF78372B3AF0BD0ULL,
		0xD10F50B384D470A5ULL,
		0x671393D48AD5AC3BULL,
		0x0304D008860953FCULL,
		0x0DF4CBFA84453991ULL,
		0x360C70DB7CCF715AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1EF5695444BDF572ULL,
		0xFA3970AB0FC3B59AULL,
		0x68ABA2F5B1ADBF01ULL,
		0x8F7FD9882EE2DE4FULL,
		0x2C0F574C1506A084ULL,
		0x23C925C1D7DA3A0EULL,
		0x9BB34CA52FDD6DAFULL,
		0x5325787C56C80034ULL
	}};
	sign = 0;
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
		0xAF78F23604331FABULL,
		0x03D052F6D9D1BB7CULL,
		0xD70FC1AE7DEB4FE9ULL,
		0xA0B70A1B09431D5DULL,
		0xFF492A580EE0DFCFULL,
		0x137D910C38B817EBULL,
		0x35DCF8473881BD7AULL,
		0xF37F7CF842CCE4B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C230C64805C59AFULL,
		0x8BCB360CA4F37A06ULL,
		0x72AE4F02B0FADC2AULL,
		0x218FA942F6018C97ULL,
		0xF5208B7040C88955ULL,
		0x6BAFCF0A9A1220DFULL,
		0xC5DA790979CE15A3ULL,
		0xC4E6F39BD99B5103ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7355E5D183D6C5FCULL,
		0x78051CEA34DE4176ULL,
		0x646172ABCCF073BEULL,
		0x7F2760D8134190C6ULL,
		0x0A289EE7CE18567AULL,
		0xA7CDC2019EA5F70CULL,
		0x70027F3DBEB3A7D6ULL,
		0x2E98895C693193AEULL
	}};
	sign = 0;
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
		0x6F2607404D6CF27AULL,
		0xD4D47745BC813AB4ULL,
		0x5E9B05ED40027423ULL,
		0x40785C020CBE1596ULL,
		0x6ECAEEEBCE55B662ULL,
		0x2901C39344EF525DULL,
		0xA8ECF93902B5D63EULL,
		0xE1D2BF4F44388BB5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E67B92602FBE45DULL,
		0x5B51797A97FD2312ULL,
		0x120298730854515DULL,
		0x8CCF7A68829C9966ULL,
		0x468022FA134B952FULL,
		0x5304FC856F11EDF1ULL,
		0xD940AA7CCA04C4BFULL,
		0xCCAED9403CDC9816ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD0BE4E1A4A710E1DULL,
		0x7982FDCB248417A1ULL,
		0x4C986D7A37AE22C6ULL,
		0xB3A8E1998A217C30ULL,
		0x284ACBF1BB0A2132ULL,
		0xD5FCC70DD5DD646CULL,
		0xCFAC4EBC38B1117EULL,
		0x1523E60F075BF39EULL
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
		0x5599C717C12C6F5CULL,
		0x11144664A016FF9BULL,
		0xAABEE77CDB1C4D62ULL,
		0x8E3EFE9E9F5F6119ULL,
		0xD5AE00B2D62EBF1CULL,
		0xE302AF5AC7CDF754ULL,
		0xC5B116AB15F7348BULL,
		0x5FB4A12B29125EB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2D413A0082AD9B7ULL,
		0x2BBD33070D98E092ULL,
		0xED3542F73A46D938ULL,
		0xE08147B19E06B634ULL,
		0x3E6D42CEE9E58DFBULL,
		0x23DB7B8871D037D2ULL,
		0xC10468DF000E2B6CULL,
		0x4E3F82CF5C8C16DAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB2C5B377B90195A5ULL,
		0xE557135D927E1F08ULL,
		0xBD89A485A0D57429ULL,
		0xADBDB6ED0158AAE4ULL,
		0x9740BDE3EC493120ULL,
		0xBF2733D255FDBF82ULL,
		0x04ACADCC15E9091FULL,
		0x11751E5BCC8647DAULL
	}};
	sign = 0;
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
		0x7023A13951D80AB1ULL,
		0x73519AEFB6D4FF82ULL,
		0xD6A5686AEBBAB8DEULL,
		0x362D1C3E2A702E63ULL,
		0xD6468A65A4D27A7FULL,
		0xA63CE2607A5060BFULL,
		0x1E78B357462A995DULL,
		0xC8D611B16369FB26ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B5921D8FC10E85AULL,
		0x97B97F06F13C9CBCULL,
		0xC99BFC37AE80B766ULL,
		0xC22E5A84E242BB0EULL,
		0xA4D32D32816683EDULL,
		0x55336C7648505839ULL,
		0xE845D74D7A64C868ULL,
		0xA7B193EF23AA6BC2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x44CA7F6055C72257ULL,
		0xDB981BE8C59862C6ULL,
		0x0D096C333D3A0177ULL,
		0x73FEC1B9482D7355ULL,
		0x31735D33236BF691ULL,
		0x510975EA32000886ULL,
		0x3632DC09CBC5D0F5ULL,
		0x21247DC23FBF8F63ULL
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
		0xC5F2D0CAAA9D897EULL,
		0xF998832E023EE77EULL,
		0xED012DE86BAEBE72ULL,
		0xF3A7633882E2278FULL,
		0x17BAD1681CC89922ULL,
		0x58033F60C10CF51FULL,
		0x2C3EE983C41AD013ULL,
		0xFDBD598BE85F6FFEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B3354FEAC635EFBULL,
		0x45C474AA9601F42BULL,
		0x3FFF9BC988F65D51ULL,
		0x9AF3D4F53321791FULL,
		0x889678557BA4DECEULL,
		0xD7F1AE4EAD086458ULL,
		0x8C56750DD980ECEEULL,
		0x79AE4DA9E58273CCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9ABF7BCBFE3A2A83ULL,
		0xB3D40E836C3CF353ULL,
		0xAD01921EE2B86121ULL,
		0x58B38E434FC0AE70ULL,
		0x8F245912A123BA54ULL,
		0x80119112140490C6ULL,
		0x9FE87475EA99E324ULL,
		0x840F0BE202DCFC31ULL
	}};
	sign = 0;
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
		0xD25CB0C1E3DD4713ULL,
		0xB38D330C7D492447ULL,
		0x787B704F67A66408ULL,
		0x2C0845F6049433EEULL,
		0xA00F088202252E66ULL,
		0x50FFD1F1B30626FEULL,
		0x270B251A6D495712ULL,
		0x3839B2630070FA7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FB1EDA58207C7BAULL,
		0x626D28E94E8DFB28ULL,
		0xB61E150630A68903ULL,
		0x91D1FFC916C5888BULL,
		0x42268501CCE0F707ULL,
		0x4E3DC1C3709510B7ULL,
		0x0746289B65E55EDCULL,
		0x1E037A41FE0E1B40ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA2AAC31C61D57F59ULL,
		0x51200A232EBB291FULL,
		0xC25D5B4936FFDB05ULL,
		0x9A36462CEDCEAB62ULL,
		0x5DE883803544375EULL,
		0x02C2102E42711647ULL,
		0x1FC4FC7F0763F836ULL,
		0x1A3638210262DF3AULL
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
		0xA9A1775CDACCF2F5ULL,
		0x215FD887869EA944ULL,
		0xEFA0E604E009E2ABULL,
		0x4889740BBC4F69E3ULL,
		0x3B68B1512D3BC9D0ULL,
		0xFA9AECFD12B0EABDULL,
		0xD5C64EFA1A8204E8ULL,
		0x2F67E958A8B7F983ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10319203770992D9ULL,
		0x7D3D024B2835D94AULL,
		0xA443B30A7AD469A8ULL,
		0x4269DB8FB805519BULL,
		0x7BA0831838979DE4ULL,
		0x276D6E3F4D6E99D6ULL,
		0x4307B3BD49FC6136ULL,
		0x1031DDA0CA049E10ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x996FE55963C3601CULL,
		0xA422D63C5E68CFFAULL,
		0x4B5D32FA65357902ULL,
		0x061F987C044A1848ULL,
		0xBFC82E38F4A42BECULL,
		0xD32D7EBDC54250E6ULL,
		0x92BE9B3CD085A3B2ULL,
		0x1F360BB7DEB35B73ULL
	}};
	sign = 0;
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
		0x922F25A777FB75DBULL,
		0x3413DBC9A06BA433ULL,
		0xAF1821BEDEFA52E2ULL,
		0x032282B4827C796CULL,
		0xD81C17A62BB1EFACULL,
		0x3504CED84A859F29ULL,
		0x4011AB86940E05EEULL,
		0xBF70C5055F0D1117ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2DC5579A44E27B2ULL,
		0x6D44116FA535A1BEULL,
		0xA484DE4E64090BFBULL,
		0x757C1AB3B48E5A3BULL,
		0x99AF8DA5149B0DB8ULL,
		0x84663BB93F9CE173ULL,
		0x9BB21F39C9AEC921ULL,
		0xDF664D2F4AD5D0D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAF52D02DD3AD4E29ULL,
		0xC6CFCA59FB360274ULL,
		0x0A9343707AF146E6ULL,
		0x8DA66800CDEE1F31ULL,
		0x3E6C8A011716E1F3ULL,
		0xB09E931F0AE8BDB6ULL,
		0xA45F8C4CCA5F3CCCULL,
		0xE00A77D614374040ULL
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
		0x80D8C7EE74FD8EBCULL,
		0xB966724F05BAD2A2ULL,
		0x08B96A9860C97E9FULL,
		0xC997E3B2AA3146E1ULL,
		0x98D9BEA64A32A44AULL,
		0x8E89361951E090BEULL,
		0x335E2AB4389A7C9FULL,
		0x69EC453289ED79BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25F52C0DDA38BE16ULL,
		0xF1A4B20DC1E75A35ULL,
		0x0D2D559A0C0B0CF1ULL,
		0x7A36AA002AC42506ULL,
		0x2DB3888B2A3CD304ULL,
		0xEBB85E3159FE9E47ULL,
		0xBA5D2D1538D1515FULL,
		0xCC1BA71AFF7C8047ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5AE39BE09AC4D0A6ULL,
		0xC7C1C04143D3786DULL,
		0xFB8C14FE54BE71ADULL,
		0x4F6139B27F6D21DAULL,
		0x6B26361B1FF5D146ULL,
		0xA2D0D7E7F7E1F277ULL,
		0x7900FD9EFFC92B3FULL,
		0x9DD09E178A70F974ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x44EE32CC00960727ULL,
		0x7C761A545CDF890FULL,
		0x4D3E77E72D3B3DE7ULL,
		0x9EC3A8BB71964858ULL,
		0x73CC1032CE08EA02ULL,
		0x98BD4594D00D993BULL,
		0x55172F5422FA29F9ULL,
		0xF7666A412AC4E1FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD2D51D9D73C69ADULL,
		0xF117DE71DC29795CULL,
		0xDC7A5E800CAFADF5ULL,
		0xA27E19DEC0E12A10ULL,
		0xB51F23D0ABF1F9FFULL,
		0x00D895F62A16CAB5ULL,
		0xBD1EEB271E840C8EULL,
		0xC19251C3552249F6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x67C0E0F229599D7AULL,
		0x8B5E3BE280B60FB2ULL,
		0x70C41967208B8FF1ULL,
		0xFC458EDCB0B51E47ULL,
		0xBEACEC622216F002ULL,
		0x97E4AF9EA5F6CE85ULL,
		0x97F8442D04761D6BULL,
		0x35D4187DD5A29804ULL
	}};
	sign = 0;
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
		0x32BC5BF5E8E327FDULL,
		0x7505E03BFC72728BULL,
		0xD1D2AB566F784F5CULL,
		0x30DBE74EF194E0A3ULL,
		0x78CC776D38350622ULL,
		0xBB3AE2DE90EF71B5ULL,
		0x8D38E55F294C7141ULL,
		0x1FF4299DD8BD4340ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9999C398976BBBB4ULL,
		0x5419DCB6AFAE02BCULL,
		0x7A5C782668E0B4EEULL,
		0xC4BE77AAFC60DD7CULL,
		0x0349A1A88A2D3CD6ULL,
		0xBB302F1BD09D980BULL,
		0x0B751A446631FF75ULL,
		0xFBDE148D39C76ECBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9922985D51776C49ULL,
		0x20EC03854CC46FCEULL,
		0x5776333006979A6EULL,
		0x6C1D6FA3F5340327ULL,
		0x7582D5C4AE07C94BULL,
		0x000AB3C2C051D9AAULL,
		0x81C3CB1AC31A71CCULL,
		0x241615109EF5D475ULL
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
		0x42E57D261410DF34ULL,
		0xA8A5A8A612DC8F88ULL,
		0xBBCE049A3F041713ULL,
		0x91C148F322D68961ULL,
		0x07211DE50CC9C315ULL,
		0x3D2FBFD6FC380DBEULL,
		0x435ED37DA62BB340ULL,
		0x51BEA812BD236997ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBBCBF84D32C3524ULL,
		0xF05531A596FCA95CULL,
		0xBCFDF76E706F5FBDULL,
		0x8AC6FB5FE84EF2E7ULL,
		0x53EA7F4BE15A12F0ULL,
		0x27A1344340BECCCCULL,
		0x854A0AB9F670274BULL,
		0xAC2792063EC9D015ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8728BDA140E4AA10ULL,
		0xB85077007BDFE62BULL,
		0xFED00D2BCE94B755ULL,
		0x06FA4D933A879679ULL,
		0xB3369E992B6FB025ULL,
		0x158E8B93BB7940F1ULL,
		0xBE14C8C3AFBB8BF5ULL,
		0xA597160C7E599981ULL
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
		0xA26CEBD957B758CCULL,
		0x946E75518C527001ULL,
		0xD38CB5889624DA64ULL,
		0x9CEA9D25B297CFECULL,
		0x268D23DFD495CACAULL,
		0x20809D11A139BDA7ULL,
		0xA12815AE9F757921ULL,
		0xF39D8199CBA03ACFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6989344F1F24488ULL,
		0xE5DEB5D648570CA8ULL,
		0xEB2BD32E1799BFA0ULL,
		0x3C3ACB71277F064EULL,
		0x153264F92583B147ULL,
		0x99B20FF002887916ULL,
		0xC0DEC324BF655EC2ULL,
		0xAE03CA602EA3C6F3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCBD4589465C51444ULL,
		0xAE8FBF7B43FB6358ULL,
		0xE860E25A7E8B1AC3ULL,
		0x60AFD1B48B18C99DULL,
		0x115ABEE6AF121983ULL,
		0x86CE8D219EB14491ULL,
		0xE0495289E0101A5EULL,
		0x4599B7399CFC73DBULL
	}};
	sign = 0;
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
		0x7E52F1F99FD59472ULL,
		0x5854117BBA01B598ULL,
		0x4D1B30B9CB21F1DDULL,
		0x54C115AF7E437326ULL,
		0x523A75B1AA5E560BULL,
		0x11B005219FA487D6ULL,
		0x671FBA7B606F56D9ULL,
		0x3CA8F65692B9B3CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC777DA36B3B85197ULL,
		0x494FF8DD3FF2891FULL,
		0x2C24B766EFECB684ULL,
		0x4B3B2EFA93505B37ULL,
		0x31FB5CA692DE9A10ULL,
		0x285FFA9654441641ULL,
		0xA7E49B154223B3AAULL,
		0x6CB502FF3F33544DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB6DB17C2EC1D42DBULL,
		0x0F04189E7A0F2C78ULL,
		0x20F67952DB353B59ULL,
		0x0985E6B4EAF317EFULL,
		0x203F190B177FBBFBULL,
		0xE9500A8B4B607195ULL,
		0xBF3B1F661E4BA32EULL,
		0xCFF3F35753865F80ULL
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
		0xE72E9550D7139714ULL,
		0x826BD80FF804C03EULL,
		0xD96218F6E5EC54E2ULL,
		0x9895AACEF019930CULL,
		0xA22EA641103655B7ULL,
		0x359C8CB1142FAE01ULL,
		0x3378CF0A5574ACE2ULL,
		0xAFCF8A5593AA1628ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45F742B2E1E590FBULL,
		0x60F41E01912F3259ULL,
		0xC6DCFE4DEB5D7645ULL,
		0xA6E57D1383B925C6ULL,
		0x9C5E2CC1F73124D4ULL,
		0xF53BE999F0832C40ULL,
		0x01315F8F3F870DC6ULL,
		0x91223C118B0D181AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA137529DF52E0619ULL,
		0x2177BA0E66D58DE5ULL,
		0x12851AA8FA8EDE9DULL,
		0xF1B02DBB6C606D46ULL,
		0x05D0797F190530E2ULL,
		0x4060A31723AC81C1ULL,
		0x32476F7B15ED9F1BULL,
		0x1EAD4E44089CFE0EULL
	}};
	sign = 0;
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
		0x7B6775CB4D08E4FAULL,
		0x4AFC32489C0883F7ULL,
		0x1A99D0F09C58E919ULL,
		0x2849644AE4081522ULL,
		0x4409A4B051230CC2ULL,
		0x3AF90CC7B62CF63AULL,
		0x49D9D10680D6CA40ULL,
		0x99AFED950B6E8386ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98F05B76B0EA599DULL,
		0x6E075DA86BB6FFD8ULL,
		0x2291720D594A3730ULL,
		0x6675212B7F4E5EA3ULL,
		0xE26793D67C166C07ULL,
		0x90A5786E88E08DBEULL,
		0x886A3CFCBD3D5E9FULL,
		0x5A75BE44E9E4FA42ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE2771A549C1E8B5DULL,
		0xDCF4D4A03051841EULL,
		0xF8085EE3430EB1E8ULL,
		0xC1D4431F64B9B67EULL,
		0x61A210D9D50CA0BAULL,
		0xAA5394592D4C687BULL,
		0xC16F9409C3996BA0ULL,
		0x3F3A2F5021898943ULL
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
		0x635C2A30ECAE2F8EULL,
		0x67DA2FB4A2B75E25ULL,
		0xB29444A235C29EB5ULL,
		0x074767DA6C4EC1AFULL,
		0x2FD157D96CD16626ULL,
		0x72AB0B02A88D3442ULL,
		0x03C09BAF1692CC6EULL,
		0x37437B94078EA5EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80A3BD5E253E3A4DULL,
		0xEBF7F12461059E90ULL,
		0xBE7F28DCB66F89DFULL,
		0xA476224BB7E77C66ULL,
		0x002F57A7C0CC9A73ULL,
		0x892D40F90A16A995ULL,
		0xD036AFEB352AD3B9ULL,
		0x56DCFD8A55774BD3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE2B86CD2C76FF541ULL,
		0x7BE23E9041B1BF94ULL,
		0xF4151BC57F5314D5ULL,
		0x62D1458EB4674548ULL,
		0x2FA20031AC04CBB2ULL,
		0xE97DCA099E768AADULL,
		0x3389EBC3E167F8B4ULL,
		0xE0667E09B2175A1AULL
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
		0x15F39CD76ABED05AULL,
		0xAA307D706BE94489ULL,
		0x681E05B5E84FABEDULL,
		0x56A5AE2AC259E87DULL,
		0x40A1C65D359CD3FDULL,
		0xC991E4AC20A733C2ULL,
		0xA14A2A1C121EC4A6ULL,
		0x1DD94434D3717C67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46C188ECA8B01A07ULL,
		0xA7F55E65E767A449ULL,
		0x10F5C51E4C88694DULL,
		0x25FC66FA6CAA98A4ULL,
		0xC418700CD781849CULL,
		0x2876C77AEA765EB0ULL,
		0x0A827ED97F1C19B4ULL,
		0x19E356AD4F35D6C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCF3213EAC20EB653ULL,
		0x023B1F0A8481A03FULL,
		0x572840979BC742A0ULL,
		0x30A9473055AF4FD9ULL,
		0x7C8956505E1B4F61ULL,
		0xA11B1D313630D511ULL,
		0x96C7AB429302AAF2ULL,
		0x03F5ED87843BA5A5ULL
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
		0x1DF110D52E1CC929ULL,
		0xFE5F6E7E53349ECFULL,
		0x50D4BD992A48D7E5ULL,
		0x52A33440C7243235ULL,
		0xF85C375A9A783921ULL,
		0x52EC951196338B87ULL,
		0x1122A72F1333B564ULL,
		0x2324A8FA1D38818FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FF25F24B2295625ULL,
		0xEE04C7A5254D4BA6ULL,
		0xD1B30D83724AE1F0ULL,
		0xEB51F4604A9E821BULL,
		0x3D5157991BEEC15EULL,
		0xCD7E99946219D65DULL,
		0x6922C997971B4A4DULL,
		0x2DBEDCE7515FA8B1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8DFEB1B07BF37304ULL,
		0x105AA6D92DE75328ULL,
		0x7F21B015B7FDF5F5ULL,
		0x67513FE07C85B019ULL,
		0xBB0ADFC17E8977C2ULL,
		0x856DFB7D3419B52AULL,
		0xA7FFDD977C186B16ULL,
		0xF565CC12CBD8D8DDULL
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
		0xFF4DAA6C9EE7E94BULL,
		0x1E2B60BF7D980AEFULL,
		0xBB14311830D44250ULL,
		0xAC8AE74141DA1B0DULL,
		0xE4CE7EC55D348267ULL,
		0x2E1A8D601370C6E7ULL,
		0x204BC7C6B02463F6ULL,
		0xB61820A0B2070655ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13628A7BF601C1D9ULL,
		0xE76C38EFCABA7318ULL,
		0x00F2250E1521B595ULL,
		0x211934B2F8482E28ULL,
		0x3C97885FF5FF3EDEULL,
		0x58AF2321E45FB608ULL,
		0x6ECE3847587F947BULL,
		0x3CF2FBB261C4B83EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEBEB1FF0A8E62772ULL,
		0x36BF27CFB2DD97D7ULL,
		0xBA220C0A1BB28CBAULL,
		0x8B71B28E4991ECE5ULL,
		0xA836F66567354389ULL,
		0xD56B6A3E2F1110DFULL,
		0xB17D8F7F57A4CF7AULL,
		0x792524EE50424E16ULL
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
		0x2599F469F54616F4ULL,
		0x33821724E21B6E99ULL,
		0x13E3F7E225BD8696ULL,
		0xEAA119871BBC6C18ULL,
		0x46099F90B8A75ACAULL,
		0x8098F81BCE86818EULL,
		0xB97791D9C48F9CAAULL,
		0x2BF15CEEA00B609EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0653AC7779B1669DULL,
		0x77EEAF1AA149395FULL,
		0x69019BBF1F7D8098ULL,
		0x9B14E1C86D6CD2DBULL,
		0x66694B03F8ED8CB8ULL,
		0xD2D0659ACA7A6BCAULL,
		0x9881B1A4FA6A920AULL,
		0x6911869E694AC58EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1F4647F27B94B057ULL,
		0xBB93680A40D2353AULL,
		0xAAE25C23064005FDULL,
		0x4F8C37BEAE4F993CULL,
		0xDFA0548CBFB9CE12ULL,
		0xADC89281040C15C3ULL,
		0x20F5E034CA250A9FULL,
		0xC2DFD65036C09B10ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x467B0560EB184AB5ULL,
		0x03B60ED005E913B6ULL,
		0xF7D71A23CF7E18B4ULL,
		0xBB5303BAD15DC1E6ULL,
		0xA32384D15F66745AULL,
		0xAF410CF55FBB2B6EULL,
		0xFD71B786DAADFF77ULL,
		0x03ADF31FC621FDABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99FBCFBABF0FEC26ULL,
		0x1CC70E684ED26E0BULL,
		0xC461B5ED06E9B515ULL,
		0xAE1AF2D6D54D39A7ULL,
		0xCB990814DAAFB7FDULL,
		0x9A37DAEE9C2F89A5ULL,
		0x5031C75DCAE7FB4CULL,
		0xA192DF94B32747B4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAC7F35A62C085E8FULL,
		0xE6EF0067B716A5AAULL,
		0x33756436C894639EULL,
		0x0D3810E3FC10883FULL,
		0xD78A7CBC84B6BC5DULL,
		0x15093206C38BA1C8ULL,
		0xAD3FF0290FC6042BULL,
		0x621B138B12FAB5F7ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x955BC63C96D3D7F4ULL,
		0x1A2C07EE37CEF15EULL,
		0x648EB84C269BB2E9ULL,
		0x07FA74B02D150573ULL,
		0x8904A77B133FD43AULL,
		0x34FF79C262EE4795ULL,
		0xE246BF9CA5EC9506ULL,
		0xA551DD82744687C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1369C15C5A7E6737ULL,
		0xC79B0959B573097FULL,
		0x017C3F9C27475FF3ULL,
		0xE4EB413D443C92BCULL,
		0xB4B3AEC095B2A876ULL,
		0x7C5BE8F6E6AFE863ULL,
		0xCE5910EE12C43093ULL,
		0xBE48606D9D770BD8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x81F204E03C5570BDULL,
		0x5290FE94825BE7DFULL,
		0x631278AFFF5452F5ULL,
		0x230F3372E8D872B7ULL,
		0xD450F8BA7D8D2BC3ULL,
		0xB8A390CB7C3E5F31ULL,
		0x13EDAEAE93286472ULL,
		0xE7097D14D6CF7BF0ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xC636BD0FA385E200ULL,
		0x60BD73699F8B1A4FULL,
		0x744B4FD51A3FE700ULL,
		0x1CE4A826DD0615C4ULL,
		0x30F20F9FCAA30C65ULL,
		0xF060E37B299F4938ULL,
		0xC4C056C538CCF1B0ULL,
		0xF7D87190EE01D1E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA10DA3F659FC907BULL,
		0x886547175532B8E5ULL,
		0x54A1FDA29D84CC0AULL,
		0x6B2DF587C00DD53BULL,
		0xEF545DE40BF49B34ULL,
		0x20F362FFD56227F7ULL,
		0xFE1EB36AA22EFA28ULL,
		0xE974D3D64C4D2E9AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2529191949895185ULL,
		0xD8582C524A58616AULL,
		0x1FA952327CBB1AF5ULL,
		0xB1B6B29F1CF84089ULL,
		0x419DB1BBBEAE7130ULL,
		0xCF6D807B543D2140ULL,
		0xC6A1A35A969DF788ULL,
		0x0E639DBAA1B4A34EULL
	}};
	sign = 0;
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
		0xBB27D052A8E6C70FULL,
		0x8F568F963CDD546EULL,
		0x960C94DBA17EA326ULL,
		0x3C6B027EA0E9B6A2ULL,
		0xDA1C5828085CF9D4ULL,
		0x9B1FB49A2094C7B6ULL,
		0x54C5228CBC810310ULL,
		0x6B4CC949E231626CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE85D5F2FAB9EAA4BULL,
		0x8546A28301E34044ULL,
		0xB745B9E4C1EDFF06ULL,
		0x606E398AFADE5355ULL,
		0xB0FE876E9B5A77F5ULL,
		0x6E3F1CD3B742D132ULL,
		0x2B3D0A51032BE3ACULL,
		0x7C64537E72513685ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD2CA7122FD481CC4ULL,
		0x0A0FED133AFA1429ULL,
		0xDEC6DAF6DF90A420ULL,
		0xDBFCC8F3A60B634CULL,
		0x291DD0B96D0281DEULL,
		0x2CE097C66951F684ULL,
		0x2988183BB9551F64ULL,
		0xEEE875CB6FE02BE7ULL
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
		0x1DBEE3ACB6ED47EFULL,
		0x50AFDC90430E11E6ULL,
		0x29380A51A4CBF7D2ULL,
		0x4D5581FD40A0E15FULL,
		0x6D18BA7339C85853ULL,
		0x6524392D6D8CC3ADULL,
		0x3ADCA21DCA357FE5ULL,
		0x4BB305AE40C0AA73ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC2230318C72B6A8ULL,
		0x7AA85458EC07475AULL,
		0x20C6D5BC54217E26ULL,
		0xDF8DDB07E9DF884EULL,
		0x5CE0D4CCA0450EFBULL,
		0x5B27C048736F5ACBULL,
		0xE81CA1C2AC480EDAULL,
		0xC8E1FEFE39CA80F0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x219CB37B2A7A9147ULL,
		0xD60788375706CA8BULL,
		0x0871349550AA79ABULL,
		0x6DC7A6F556C15911ULL,
		0x1037E5A699834957ULL,
		0x09FC78E4FA1D68E2ULL,
		0x52C0005B1DED710BULL,
		0x82D106B006F62982ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x00B3F1E09CDCCB66ULL,
		0x4F8883DECDB4FE2EULL,
		0x8CFCEDFB3D8A5350ULL,
		0x971FF202E0AF0A9DULL,
		0x20E64744F9D21351ULL,
		0x59C2CABE4A151414ULL,
		0x92EB61C025E8C232ULL,
		0xB8C529D5860922B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C1F12CECDDD3535ULL,
		0x027E4E212388FFE2ULL,
		0x37F23C73347F4FC9ULL,
		0x70C10E4D2F5056DEULL,
		0xEC188DF815DC78D5ULL,
		0xEF5931415D870E19ULL,
		0xEC7BD72223CD32C8ULL,
		0x0EFA8ECAD1016066ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF494DF11CEFF9631ULL,
		0x4D0A35BDAA2BFE4BULL,
		0x550AB188090B0387ULL,
		0x265EE3B5B15EB3BFULL,
		0x34CDB94CE3F59A7CULL,
		0x6A69997CEC8E05FAULL,
		0xA66F8A9E021B8F69ULL,
		0xA9CA9B0AB507C24BULL
	}};
	sign = 0;
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
		0xD58798DE5654A44FULL,
		0xDE6E8902DF17CBD4ULL,
		0x82C00923F92D147AULL,
		0x3F0721F7650D7871ULL,
		0x88751AA028E75D44ULL,
		0x9715A94AD2B7E79BULL,
		0x248C62FD04E813CBULL,
		0x252EF88AC35B3D59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75C098430817BA6DULL,
		0xEE732C32B795507CULL,
		0x665287EF89681662ULL,
		0x962A1D677AF01176ULL,
		0x4DCDA9109CE49BC7ULL,
		0x691C9DD8E9343B5DULL,
		0x76FFB8C8EE1642EDULL,
		0x4368DC06F5BBE6EDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5FC7009B4E3CE9E2ULL,
		0xEFFB5CD027827B58ULL,
		0x1C6D81346FC4FE17ULL,
		0xA8DD048FEA1D66FBULL,
		0x3AA7718F8C02C17CULL,
		0x2DF90B71E983AC3EULL,
		0xAD8CAA3416D1D0DEULL,
		0xE1C61C83CD9F566BULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x082279F2C5E8BD0FULL,
		0x6864641AA1773FFCULL,
		0xF8EC76ECCBD99920ULL,
		0x85A5F34E24245C32ULL,
		0x2E0CB62E9BC79914ULL,
		0x15D364CB0BFA083FULL,
		0xF58CEF6659755B05ULL,
		0xFB26B4140EE1EB93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDE8304502741135ULL,
		0xB2327C7D45069051ULL,
		0x1A03A9284D5B358FULL,
		0x84E7995659CB6D27ULL,
		0xA8FA691FB7A5BF3CULL,
		0x3D03EF75C8301641ULL,
		0x2C3F8084298C89D9ULL,
		0x01BC2A625528A6E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A3A49ADC374ABDAULL,
		0xB631E79D5C70AFAAULL,
		0xDEE8CDC47E7E6390ULL,
		0x00BE59F7CA58EF0BULL,
		0x85124D0EE421D9D8ULL,
		0xD8CF755543C9F1FDULL,
		0xC94D6EE22FE8D12BULL,
		0xF96A89B1B9B944AEULL
	}};
	sign = 0;
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
		0x3AF30223495C8386ULL,
		0x415B00F9C4A43AC3ULL,
		0x03BC795679167929ULL,
		0xD103064E7E837625ULL,
		0x29A268465071E2B1ULL,
		0x3B2EB269EB8E754DULL,
		0x8E987F578E33DC86ULL,
		0x7A3E7D507EC7125FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB988D7B0C544C971ULL,
		0x79AA6503D232B72EULL,
		0x83F25B3C4A6AD00DULL,
		0xB806D5F479488F51ULL,
		0xF8A276DC984D78FFULL,
		0xEF42CFC3925FEBD1ULL,
		0x022FC77DD89427C8ULL,
		0x4792F37121A3F0B8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x816A2A728417BA15ULL,
		0xC7B09BF5F2718394ULL,
		0x7FCA1E1A2EABA91BULL,
		0x18FC305A053AE6D3ULL,
		0x30FFF169B82469B2ULL,
		0x4BEBE2A6592E897BULL,
		0x8C68B7D9B59FB4BDULL,
		0x32AB89DF5D2321A7ULL
	}};
	sign = 0;
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
		0x2A7F47715B4F6F9DULL,
		0x2E3576CEF74AFAF5ULL,
		0x9915A6931EBB617DULL,
		0xD43E6EEE855B6812ULL,
		0x42FC38657C1414B6ULL,
		0xF8AFEFDA7B19E4F2ULL,
		0xED98E4E4F46EB6B4ULL,
		0xDF6D7C099E49F14CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E8F1CDC5AC5824BULL,
		0xDA00886D33CB8013ULL,
		0xEFCCA3B013EF7773ULL,
		0x1B89245A5DF7C4F2ULL,
		0x58B21305972A6A16ULL,
		0x403374202F37398FULL,
		0x440EB503FE3350E8ULL,
		0xF7D9B662899B2BDBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFBF02A950089ED52ULL,
		0x5434EE61C37F7AE1ULL,
		0xA94902E30ACBEA09ULL,
		0xB8B54A942763A31FULL,
		0xEA4A255FE4E9AAA0ULL,
		0xB87C7BBA4BE2AB62ULL,
		0xA98A2FE0F63B65CCULL,
		0xE793C5A714AEC571ULL
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
		0x4F7970E6F72F541AULL,
		0xE5301C298FF7F5E7ULL,
		0xECE2EC5211E8F7C0ULL,
		0x22BF6A4C89614E25ULL,
		0x30F3315CC047F8D1ULL,
		0x3E0BECEAE94E346BULL,
		0xCCAB5AAA385B2D8CULL,
		0x65D0FB94A2FF07A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC49D270D541CC6D2ULL,
		0xFF084C91173C3BB9ULL,
		0x96973134D774BDD9ULL,
		0x706BA0196F5B3582ULL,
		0x5542EA061993CF26ULL,
		0xB1583A426C85C921ULL,
		0xD5C1E441D751F977ULL,
		0xD2EA03EF0801532AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8ADC49D9A3128D48ULL,
		0xE627CF9878BBBA2DULL,
		0x564BBB1D3A7439E6ULL,
		0xB253CA331A0618A3ULL,
		0xDBB04756A6B429AAULL,
		0x8CB3B2A87CC86B49ULL,
		0xF6E9766861093414ULL,
		0x92E6F7A59AFDB47AULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x91DD8C78EABE8489ULL,
		0x46D5620B4E0111F7ULL,
		0xF41FFFAAC9A85B5BULL,
		0xFBF115CF2FC049FDULL,
		0x2CCBAB9F0B147F40ULL,
		0xCA3EB8E33F3BECA8ULL,
		0xC4337BAFA69B95DAULL,
		0x10010422EE324651ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0371E65ABDC918E7ULL,
		0x2158CC61E347A0EDULL,
		0x305E3EDEED42F856ULL,
		0xA03E8D2629321078ULL,
		0x10EF1E940C8956B9ULL,
		0x300F6841C4DB797DULL,
		0x5413C0A42F65A1BAULL,
		0xC59256504FDB3180ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8E6BA61E2CF56BA2ULL,
		0x257C95A96AB9710AULL,
		0xC3C1C0CBDC656305ULL,
		0x5BB288A9068E3985ULL,
		0x1BDC8D0AFE8B2887ULL,
		0x9A2F50A17A60732BULL,
		0x701FBB0B7735F420ULL,
		0x4A6EADD29E5714D1ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x166405E3B87518EDULL,
		0xAACA28D5091ACF0EULL,
		0xB166862B53DA82CDULL,
		0x3A2E042A9D05F12EULL,
		0x4F1EA1904BAD4043ULL,
		0xB22398BCE037C281ULL,
		0xC8A90C72730533CAULL,
		0xE26AC3F313E6205EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE56468B68625E337ULL,
		0x4615654B2667F777ULL,
		0x4F79A69254CAEF65ULL,
		0x601FCBC56BE95FB8ULL,
		0x703A0148FD377927ULL,
		0x902948B769C5E82EULL,
		0xFE35DA5DC9A9907EULL,
		0xE5F222CF116FB79FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x30FF9D2D324F35B6ULL,
		0x64B4C389E2B2D796ULL,
		0x61ECDF98FF0F9368ULL,
		0xDA0E3865311C9176ULL,
		0xDEE4A0474E75C71BULL,
		0x21FA50057671DA52ULL,
		0xCA733214A95BA34CULL,
		0xFC78A124027668BEULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xDA52ED3B0AE6C3EBULL,
		0xC903D41A901A7225ULL,
		0xBFC3197573307F47ULL,
		0xD82C01FFDD740B11ULL,
		0x95C4D4731E878B10ULL,
		0x4E62397F8F4FF24EULL,
		0xBE80A0F3DD082597ULL,
		0x35FFDD1B131AB025ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB52746173E1862FULL,
		0xBACF0555FDA2165BULL,
		0xB60C9B43E2F94326ULL,
		0x7703853D7E41AB12ULL,
		0x7F6FE4C0069DFCCCULL,
		0x66B7386054429081ULL,
		0x143631F3FD8AEDF0ULL,
		0xB205F3B34E040C61ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFF0078D997053DBCULL,
		0x0E34CEC492785BC9ULL,
		0x09B67E3190373C21ULL,
		0x61287CC25F325FFFULL,
		0x1654EFB317E98E44ULL,
		0xE7AB011F3B0D61CDULL,
		0xAA4A6EFFDF7D37A6ULL,
		0x83F9E967C516A3C4ULL
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
		0x435A01C698DDED65ULL,
		0xE71A28CB1C7C95DEULL,
		0x4FD3ADA42BC71156ULL,
		0x4E0AC155EBB6207CULL,
		0xB7989BD7C2BB0957ULL,
		0x58E2B07C97B46829ULL,
		0x3B6C48C71F5559C2ULL,
		0xB883606AFFEF9E68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F8DBDC57DDC1888ULL,
		0x888BFE61A29C7C92ULL,
		0x9C393309FCE925C6ULL,
		0x9665F9493D51CC60ULL,
		0xC39FFCC2777FE068ULL,
		0xD42EB3BBF495B3D7ULL,
		0x7FD99DB42FFAA5F9ULL,
		0xD2DBEE0DDAACA9F5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD3CC44011B01D4DDULL,
		0x5E8E2A6979E0194BULL,
		0xB39A7A9A2EDDEB90ULL,
		0xB7A4C80CAE64541BULL,
		0xF3F89F154B3B28EEULL,
		0x84B3FCC0A31EB451ULL,
		0xBB92AB12EF5AB3C8ULL,
		0xE5A7725D2542F472ULL
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
		0xBAA64A2E7916D3BCULL,
		0xBB5DA96D0FD19855ULL,
		0xD53D06E3DE1CC879ULL,
		0x4B5A309A2DAF4BEFULL,
		0xAFB186A81B9D68C1ULL,
		0xBDAD7F36646E6385ULL,
		0xE8492E3279624805ULL,
		0x8B6C70A2A1F818CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8E2656620A3D0CCULL,
		0xD9BE7B307E94FFCDULL,
		0x2D4C7C44B971B4D7ULL,
		0xD3E2BDA2562526A8ULL,
		0x226689E607187935ULL,
		0x7E7DDC6AED51CE8CULL,
		0x2F916C3F4D519E4EULL,
		0x7F03EBB13569DD21ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01C3E4C8587302F0ULL,
		0xE19F2E3C913C9888ULL,
		0xA7F08A9F24AB13A1ULL,
		0x777772F7D78A2547ULL,
		0x8D4AFCC21484EF8BULL,
		0x3F2FA2CB771C94F9ULL,
		0xB8B7C1F32C10A9B7ULL,
		0x0C6884F16C8E3BAAULL
	}};
	sign = 0;
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
		0x0C1184551D605900ULL,
		0xEB4047692C443648ULL,
		0x4C59213F416DD5E4ULL,
		0x165EE6FA46F01A7DULL,
		0xFEE96DA88C41C3C3ULL,
		0xB259CD95D479A4C5ULL,
		0x1275A8A7D53B1FE8ULL,
		0x19B6105C1674BC0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D2E655DFCDFF668ULL,
		0x5C1145CC646D7734ULL,
		0x96F300EA1769FA3AULL,
		0xBEBC1E385A7ED54FULL,
		0x9E1403CFD26E0C77ULL,
		0x19B42C2C96AF2F46ULL,
		0xBBAB4F88CC45CB02ULL,
		0x13C30A4A2642C42CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7EE31EF720806298ULL,
		0x8F2F019CC7D6BF13ULL,
		0xB56620552A03DBAAULL,
		0x57A2C8C1EC71452DULL,
		0x60D569D8B9D3B74BULL,
		0x98A5A1693DCA757FULL,
		0x56CA591F08F554E6ULL,
		0x05F30611F031F7E2ULL
	}};
	sign = 0;
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
		0xFE975F6B29C67154ULL,
		0x6DF8549EA2770152ULL,
		0x84B24721ADDC5831ULL,
		0x931128A5FF0005B6ULL,
		0x4AA458302C716150ULL,
		0xDBAFDC6787CA06B4ULL,
		0xF9AD02E969BF1B20ULL,
		0x51713976F2CB0157ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x291B6FD8E9DF01A1ULL,
		0xBCE237D6AED7C2C6ULL,
		0x73988EA49EA7BE64ULL,
		0x59869C70B0A7018BULL,
		0xE3875B685F1D5D2DULL,
		0x926142AC812833F3ULL,
		0xA3315AA6067FB96AULL,
		0xBC7F29D0B588A12CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD57BEF923FE76FB3ULL,
		0xB1161CC7F39F3E8CULL,
		0x1119B87D0F3499CCULL,
		0x398A8C354E59042BULL,
		0x671CFCC7CD540423ULL,
		0x494E99BB06A1D2C0ULL,
		0x567BA843633F61B6ULL,
		0x94F20FA63D42602BULL
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
		0x352EC4735FBA894EULL,
		0x71236F4068CEB5B5ULL,
		0xD9F6E5DE13FF27A0ULL,
		0xA8605FF04366C01DULL,
		0x528F21A8C6B06C3CULL,
		0x841D51F9FB66CFEFULL,
		0xDBA8B46BB819E251ULL,
		0xB69BCD484F8EC248ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x326D2AC0EE94EE41ULL,
		0xAA8E53C3F67B415EULL,
		0x12796150D9E3B8BAULL,
		0xB0E14D8FC1CED95AULL,
		0x7C1FA0ADE8A31E21ULL,
		0xAFDB3DA03455E962ULL,
		0x9479EC1B5C506630ULL,
		0xEE1CE4959F3C394DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x02C199B271259B0DULL,
		0xC6951B7C72537457ULL,
		0xC77D848D3A1B6EE5ULL,
		0xF77F12608197E6C3ULL,
		0xD66F80FADE0D4E1AULL,
		0xD4421459C710E68CULL,
		0x472EC8505BC97C20ULL,
		0xC87EE8B2B05288FBULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xAE6EE02BB0F077ADULL,
		0x08B286BF0372F391ULL,
		0xB339300FDBA9ABAFULL,
		0xDC7BADEDADFEFE97ULL,
		0x17A7AA2CEBF9E8C9ULL,
		0x0191F5CD8C889DDDULL,
		0x9082110BCFD8FE2AULL,
		0x2C52F5AF5EFD5966ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C2BBBCBA269A13DULL,
		0x6AD76037E626E8BEULL,
		0x094A9F6DBD7298D8ULL,
		0xFC16611A6D77A0A4ULL,
		0x9986DD63D05E7317ULL,
		0xF966E9DDC9A61B79ULL,
		0x59BF2AE1BA431672ULL,
		0x3BBF14490A653F97ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x124324600E86D670ULL,
		0x9DDB26871D4C0AD3ULL,
		0xA9EE90A21E3712D6ULL,
		0xE0654CD340875DF3ULL,
		0x7E20CCC91B9B75B1ULL,
		0x082B0BEFC2E28263ULL,
		0x36C2E62A1595E7B7ULL,
		0xF093E166549819CFULL
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
		0x4CF1D3E77BDCAB8CULL,
		0x384CC99FEE9005B2ULL,
		0x4E142B954EF8C262ULL,
		0xB782DB401B2F0D70ULL,
		0x0AB0C0374F7184A0ULL,
		0x836B15D141DDE172ULL,
		0x635301B73B6FB778ULL,
		0x6A4E342F86B0D9FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5766D62CAB4AD9FDULL,
		0xC45F07A7AB6F5604ULL,
		0x51F8629F337BB255ULL,
		0x62FB961C62748D15ULL,
		0x6CEDC9AE16EABD67ULL,
		0xBFC364AC0756EB5FULL,
		0xE7E7E5443AF5D760ULL,
		0xEA15B8C32452E732ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF58AFDBAD091D18FULL,
		0x73EDC1F84320AFADULL,
		0xFC1BC8F61B7D100CULL,
		0x54874523B8BA805AULL,
		0x9DC2F6893886C739ULL,
		0xC3A7B1253A86F612ULL,
		0x7B6B1C730079E017ULL,
		0x80387B6C625DF2C7ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x4E6DB6AAAFC39C4DULL,
		0xF4318086B7B8B60AULL,
		0x0D2E9C93E38E66D2ULL,
		0xF967F2BA263B5009ULL,
		0x0EF65481948CF6CCULL,
		0x6C0EE52246AF408CULL,
		0x11A4DEAF9D27898DULL,
		0x7A1A68E8B9B1F217ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x741EBE4B88A502F4ULL,
		0xDA1A807EC4114E24ULL,
		0x91BE6058B7C6E63DULL,
		0x718C5DF007193A83ULL,
		0xABC4E8E3983FAE50ULL,
		0xD74BF764B9A83082ULL,
		0x55BF56E96B556D03ULL,
		0xAEB212E02291B1A7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDA4EF85F271E9959ULL,
		0x1A170007F3A767E5ULL,
		0x7B703C3B2BC78095ULL,
		0x87DB94CA1F221585ULL,
		0x63316B9DFC4D487CULL,
		0x94C2EDBD8D071009ULL,
		0xBBE587C631D21C89ULL,
		0xCB6856089720406FULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x7420498B27CFD662ULL,
		0x00BEC0A3442FEDFEULL,
		0x95E3004598BC966DULL,
		0x74ECFE618367D48CULL,
		0xBC68BA40AF9B0712ULL,
		0x4D5A1CE1CAD9B55BULL,
		0xEB629EC233AA2BD1ULL,
		0xC5E65C3FF4455949ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E0F279382931A40ULL,
		0x3535391CE6A2D879ULL,
		0x1261DAF515C04282ULL,
		0xCD0584EB7A088C6FULL,
		0x5AAED3CA33AE9022ULL,
		0x2AC13D12AE478BECULL,
		0x516B74F29CB6A585ULL,
		0x32983DA3BD97E1DDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x061121F7A53CBC22ULL,
		0xCB8987865D8D1585ULL,
		0x8381255082FC53EAULL,
		0xA7E77976095F481DULL,
		0x61B9E6767BEC76EFULL,
		0x2298DFCF1C92296FULL,
		0x99F729CF96F3864CULL,
		0x934E1E9C36AD776CULL
	}};
	sign = 0;
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
		0x8E9A8B8A0B344EC3ULL,
		0xA82E3BE4D674F485ULL,
		0x5B56B0B4848E4128ULL,
		0x2A008F6E8844DE69ULL,
		0x760C85FA5A0FD00BULL,
		0x7D2557A90DCC36B0ULL,
		0x8CD0D6EE059523F1ULL,
		0xCA5AB81A78B73594ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68FD1F361F72C947ULL,
		0x4FAFD88D4CA838CFULL,
		0x08CFBC2EE6708F0CULL,
		0xC985CED17EABAC36ULL,
		0xE5FBA749F0D5F1F0ULL,
		0x76F10EAD0B273A6CULL,
		0x5F2AA58F70B793FBULL,
		0x68E1C5F192A5D5C9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x259D6C53EBC1857CULL,
		0x587E635789CCBBB6ULL,
		0x5286F4859E1DB21CULL,
		0x607AC09D09993233ULL,
		0x9010DEB06939DE1AULL,
		0x063448FC02A4FC43ULL,
		0x2DA6315E94DD8FF6ULL,
		0x6178F228E6115FCBULL
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
		0x018F4732E12C32F5ULL,
		0x431A42BDE1F12F3FULL,
		0x4E2CCF18196F4913ULL,
		0x7F8EC750C23DB01DULL,
		0xF9B4765A52CF6E44ULL,
		0x9D652FF17D12F825ULL,
		0x266A9C54783E9D7DULL,
		0x59688034180BEE24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x287B219A24EA6917ULL,
		0x1C5BCB10739074D0ULL,
		0x7DEA979BCFF9D54BULL,
		0xE3420B869AF484F1ULL,
		0x82818A0A34F310C9ULL,
		0x23D377BA153B05F1ULL,
		0x2428D72BFFB97713ULL,
		0x0546FF4CA53AB588ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD9142598BC41C9DEULL,
		0x26BE77AD6E60BA6EULL,
		0xD042377C497573C8ULL,
		0x9C4CBBCA27492B2BULL,
		0x7732EC501DDC5D7AULL,
		0x7991B83767D7F234ULL,
		0x0241C5287885266AULL,
		0x542180E772D1389CULL
	}};
	sign = 0;
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
		0x9C7490D35D9EBDA9ULL,
		0x58681C515038CD57ULL,
		0x1D34C6CE7FA15A9EULL,
		0x19ECA63CD656F2E3ULL,
		0x3CB4DA1C44307119ULL,
		0xB49F14239EABD2C9ULL,
		0x87B77348EE05F594ULL,
		0x336FECE1BCC74475ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCA334CBF63BF159ULL,
		0xD8145AB9162ABE68ULL,
		0xFFA9BF339C6B5148ULL,
		0x671D41FB035D3665ULL,
		0x5F605AEADD64C389ULL,
		0x1C6CE363D0B74754ULL,
		0x73133FB48B3EDD0AULL,
		0x6366788058DC28C1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9FD15C076762CC50ULL,
		0x8053C1983A0E0EEEULL,
		0x1D8B079AE3360955ULL,
		0xB2CF6441D2F9BC7DULL,
		0xDD547F3166CBAD8FULL,
		0x983230BFCDF48B74ULL,
		0x14A4339462C7188AULL,
		0xD009746163EB1BB4ULL
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
		0x535F25901EE5E0E5ULL,
		0x93D7BC31FCD40270ULL,
		0xECE76A58FD26524DULL,
		0x681B31F52B9B5E0AULL,
		0xFE68AEFA393A2237ULL,
		0x53F77737DCB8ABD2ULL,
		0xE910FCF35F2D1775ULL,
		0x088461CE02BD7321ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1796C5E767569CBULL,
		0x584DEA962CBD3F1CULL,
		0xBCE76D1A7C22B262ULL,
		0x9012153247FB7EE6ULL,
		0x2328A6135BD84916ULL,
		0x17F2B050319D7A2EULL,
		0xFA231E04CCF65534ULL,
		0x5B414EE6E1E56A9AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x81E5B931A870771AULL,
		0x3B89D19BD016C353ULL,
		0x2FFFFD3E81039FEBULL,
		0xD8091CC2E39FDF24ULL,
		0xDB4008E6DD61D920ULL,
		0x3C04C6E7AB1B31A4ULL,
		0xEEEDDEEE9236C241ULL,
		0xAD4312E720D80886ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x8B421B56AF8BA87AULL,
		0xE24ADF8C2C12259AULL,
		0x1F6D246EBB6251D7ULL,
		0x08270FFFD55BC264ULL,
		0x84B1DCB8BEE95E7AULL,
		0x93744BB50B39FC7DULL,
		0x9400C41215F297ABULL,
		0x8A5252D648AE1366ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF98B2C57CCD85DFULL,
		0x215891CFF3954687ULL,
		0xC3026CD401196666ULL,
		0xBCC5B6E5E31F96F0ULL,
		0x7658C6491EF849C8ULL,
		0x159ED7F6A5BED11CULL,
		0xE951FAE09C0812E6ULL,
		0x5065B9D4622137FBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xABA9689132BE229BULL,
		0xC0F24DBC387CDF12ULL,
		0x5C6AB79ABA48EB71ULL,
		0x4B615919F23C2B73ULL,
		0x0E59166F9FF114B1ULL,
		0x7DD573BE657B2B61ULL,
		0xAAAEC93179EA84C5ULL,
		0x39EC9901E68CDB6AULL
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
		0xC104227FD86DE2CFULL,
		0xA4B42F52204ACFA0ULL,
		0xBF649C7CC6A10C30ULL,
		0x4E1C0E8974325575ULL,
		0x05E7EEDD38D08896ULL,
		0x40EF9262062A93A0ULL,
		0x93F8BDB19EB33BA2ULL,
		0x515B57B58152AA7FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6F5EF9583E7F001ULL,
		0x070486B55F4AAFDDULL,
		0xA927A0CB195E85B9ULL,
		0x033D5753E0202E09ULL,
		0x993D38598B21935BULL,
		0xC3C3B4B8A447DC3AULL,
		0x29C1CA773842C343ULL,
		0x0C6B8231FE0CF915ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDA0E32EA5485F2CEULL,
		0x9DAFA89CC1001FC2ULL,
		0x163CFBB1AD428677ULL,
		0x4ADEB7359412276CULL,
		0x6CAAB683ADAEF53BULL,
		0x7D2BDDA961E2B765ULL,
		0x6A36F33A6670785EULL,
		0x44EFD5838345B16AULL
	}};
	sign = 0;
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
		0xF2FE5B8C94B2459CULL,
		0x129802F3A92E8078ULL,
		0xE29AB91D2523F463ULL,
		0xFB8EDC4F6CD1B3ADULL,
		0x933C593B20BD928FULL,
		0x598E016C8F647B95ULL,
		0x06249AB3D5C7F22BULL,
		0xD21C265DA9365079ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DDD7DEBD95DBA98ULL,
		0xF32313716FF0C801ULL,
		0x1C82B8C68F11F9A8ULL,
		0x53F65226659A8486ULL,
		0x59298FBB3B9A163BULL,
		0x867F481BA3B036F2ULL,
		0x02FE73CFD7512475ULL,
		0x1DADB9690E217D5AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6520DDA0BB548B04ULL,
		0x1F74EF82393DB877ULL,
		0xC61800569611FABAULL,
		0xA7988A2907372F27ULL,
		0x3A12C97FE5237C54ULL,
		0xD30EB950EBB444A3ULL,
		0x032626E3FE76CDB5ULL,
		0xB46E6CF49B14D31FULL
	}};
	sign = 0;
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
		0x8CD13A7EB16DCF66ULL,
		0x70AD152701C7A954ULL,
		0xF0567F2714752339ULL,
		0x8B2A23A9737E26B8ULL,
		0xED362E359400A94AULL,
		0x22FD20A6DE3E6922ULL,
		0x3C9CDAF17AC80213ULL,
		0xC0B6916322C52EBBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE97D7854A1D2FD20ULL,
		0x40A0866BD75D6B04ULL,
		0x1A492D31126BE985ULL,
		0xB756318E3596EA13ULL,
		0xD5CF2EDCA9BC982DULL,
		0x59A0CDDADBA64326ULL,
		0xE61EBFC5FE87D94EULL,
		0xBAE9AAAF78B185ACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA353C22A0F9AD246ULL,
		0x300C8EBB2A6A3E4FULL,
		0xD60D51F6020939B4ULL,
		0xD3D3F21B3DE73CA5ULL,
		0x1766FF58EA44111CULL,
		0xC95C52CC029825FCULL,
		0x567E1B2B7C4028C4ULL,
		0x05CCE6B3AA13A90EULL
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
		0x70A92C54C2D35032ULL,
		0x0DE3FC8C3A209E9AULL,
		0x0C78C10E239793D9ULL,
		0xF8579F50812A9DACULL,
		0xD00DF53D45B04968ULL,
		0x6998582970596604ULL,
		0x76ADA3380DA21CC6ULL,
		0xE3381CC4433166FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8A33DE30B835EDAULL,
		0x9CFB20CED0DC9AAAULL,
		0xDBEC5971E02E5A36ULL,
		0xD690870CAF713F83ULL,
		0xE56C475163072982ULL,
		0x6023F2B8F0F6D871ULL,
		0xADB6E508DA4CC25CULL,
		0x027151F78ADB8D45ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9805EE71B74FF158ULL,
		0x70E8DBBD694403EFULL,
		0x308C679C436939A2ULL,
		0x21C71843D1B95E28ULL,
		0xEAA1ADEBE2A91FE6ULL,
		0x097465707F628D92ULL,
		0xC8F6BE2F33555A6AULL,
		0xE0C6CACCB855D9B8ULL
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
		0x595D992F50746E42ULL,
		0x8E8B14CE1AB2A61FULL,
		0xB503D371F476D43CULL,
		0x5FEAE9397B3858ADULL,
		0x22D9032F36754674ULL,
		0xE8C98E2DA558E746ULL,
		0xF38D6162DA3DB01FULL,
		0x3A1D21F26588617FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5895ABF95A456023ULL,
		0x22D3B56604120693ULL,
		0x2F93BF20577C5177ULL,
		0xFD31564F7FA8C0E5ULL,
		0x0CF04D4920A465B8ULL,
		0x2DCDE38987C7757EULL,
		0x4FF222346B56648EULL,
		0xFB89198CB7B5EDEEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00C7ED35F62F0E1FULL,
		0x6BB75F6816A09F8CULL,
		0x857014519CFA82C5ULL,
		0x62B992E9FB8F97C8ULL,
		0x15E8B5E615D0E0BBULL,
		0xBAFBAAA41D9171C8ULL,
		0xA39B3F2E6EE74B91ULL,
		0x3E940865ADD27391ULL
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
		0x8BD3645B3090D607ULL,
		0x6B20F111246D5078ULL,
		0x8DA4E4EDE3DEB799ULL,
		0x8D0AC833CC4EAFA0ULL,
		0xD9A1B14502211DEDULL,
		0x3FA4BB10EBE9D0AFULL,
		0xC380DBEC9C1944D0ULL,
		0x7B35AF5A8214351FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF1CC02040A64F5FULL,
		0x837D909A2007D761ULL,
		0xF757D5A763368BE5ULL,
		0x97469D4EF195BC4BULL,
		0xA40211FA1580E552ULL,
		0x2EAA0BC8925D82CAULL,
		0xDD39004744144C9BULL,
		0x26E2E4C7ADF6FC3DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8CB6A43AEFEA86A8ULL,
		0xE7A3607704657916ULL,
		0x964D0F4680A82BB3ULL,
		0xF5C42AE4DAB8F354ULL,
		0x359F9F4AECA0389AULL,
		0x10FAAF48598C4DE5ULL,
		0xE647DBA55804F835ULL,
		0x5452CA92D41D38E1ULL
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
		0x9B39A63E4484EB3EULL,
		0xE757DF7A02EE866CULL,
		0x6C104C493F9048E8ULL,
		0xFC02F3144FE9FBC5ULL,
		0x7347101A6E09F765ULL,
		0x0870D0568B33952BULL,
		0x339F3D329BA2DF94ULL,
		0xFA7843BCAAC7A444ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA44BE4C84A2F3B9ULL,
		0xF284A432B5A0F277ULL,
		0x1C7C2976B5A88DD6ULL,
		0x2E1B067C69EB568CULL,
		0x30586FA7CB663C26ULL,
		0xABCC7AEBC289E151ULL,
		0xC3F008DC6AEB963CULL,
		0x81DAC0E0DC2CF0E6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB0F4E7F1BFE1F785ULL,
		0xF4D33B474D4D93F4ULL,
		0x4F9422D289E7BB11ULL,
		0xCDE7EC97E5FEA539ULL,
		0x42EEA072A2A3BB3FULL,
		0x5CA4556AC8A9B3DAULL,
		0x6FAF345630B74957ULL,
		0x789D82DBCE9AB35DULL
	}};
	sign = 0;
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
		0xCB5375939BFF9664ULL,
		0x869738F4C57DCFFDULL,
		0x5CDFF41CF8E7724CULL,
		0xFEC4F7D9B3AB3AB8ULL,
		0xB79EEB7256AA9B70ULL,
		0xA8162EAAB0A058D5ULL,
		0x15F243AB755B15DFULL,
		0x5C1D3025535D85BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8F903B08153DBBAULL,
		0x2F9BA1485AC527CEULL,
		0xD118D9E9DBC9518EULL,
		0xF7BD8FE1E882B5A2ULL,
		0x1BC75994AE98D9E4ULL,
		0xFC473251F079FBC3ULL,
		0xBDBC3744C961F6D3ULL,
		0xD555BC2032137ADDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF25A71E31AABBAAAULL,
		0x56FB97AC6AB8A82EULL,
		0x8BC71A331D1E20BEULL,
		0x070767F7CB288515ULL,
		0x9BD791DDA811C18CULL,
		0xABCEFC58C0265D12ULL,
		0x58360C66ABF91F0BULL,
		0x86C77405214A0AE1ULL
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
		0x3FE682F1BA8BC82EULL,
		0x129336ADD3DCF9F1ULL,
		0xBD9590BE31D57924ULL,
		0x7130115836AB56F4ULL,
		0x04B2E0CAADD8A868ULL,
		0xB066BB39B346EB1DULL,
		0x5655934EFA31AB49ULL,
		0x1338420F6A0E7318ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59E6A96A0711CE50ULL,
		0x907D15BAA755B1B6ULL,
		0xA9A82C65E89AA3B5ULL,
		0x19327806B1B1BDA5ULL,
		0xEA21300204714ABFULL,
		0x9B031A33F1A2AEF5ULL,
		0xB976F7F1B98D0953ULL,
		0x7FD63376508DA3B2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE5FFD987B379F9DEULL,
		0x821620F32C87483AULL,
		0x13ED6458493AD56EULL,
		0x57FD995184F9994FULL,
		0x1A91B0C8A9675DA9ULL,
		0x1563A105C1A43C27ULL,
		0x9CDE9B5D40A4A1F6ULL,
		0x93620E991980CF65ULL
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
		0x873B022C01097134ULL,
		0xFF22941AB1B872D2ULL,
		0x63664FAD3D7D4FB4ULL,
		0xB69996779ED84FF2ULL,
		0x06CE7E48E92D88FDULL,
		0x57B8589EF4985716ULL,
		0x3406D1426DFEAFB2ULL,
		0x82875B5048B47DDAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46E6D4B92B2222CBULL,
		0x5CF8260547B74927ULL,
		0x69671DE8CAC984E1ULL,
		0x5015B3D2A1B8FCD9ULL,
		0x594F117761491CFDULL,
		0xACD74A9C8BAA6E07ULL,
		0x9EB972742A1B5029ULL,
		0x9A5B06C279B3D960ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40542D72D5E74E69ULL,
		0xA22A6E156A0129ABULL,
		0xF9FF31C472B3CAD3ULL,
		0x6683E2A4FD1F5318ULL,
		0xAD7F6CD187E46C00ULL,
		0xAAE10E0268EDE90EULL,
		0x954D5ECE43E35F88ULL,
		0xE82C548DCF00A479ULL
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
		0x68B9DA87AF740A72ULL,
		0x5D6F557523AB3D06ULL,
		0x4DF24AF3CEF4C0A4ULL,
		0xE0C9C4035779C278ULL,
		0x9A6554840DAD762EULL,
		0x3D1EF3984BE8F85DULL,
		0x2FB55E3E8785B054ULL,
		0x24EC7F1DD67F8990ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA529579EAD834962ULL,
		0x8B6CC103F1AD5EE8ULL,
		0xB8A3924162825802ULL,
		0x95BF83893B08D88BULL,
		0x03ED83521E233BE9ULL,
		0x0673F6787F481FEEULL,
		0x86BE76CF7A6AC78CULL,
		0xAA33535068D48318ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC39082E901F0C110ULL,
		0xD202947131FDDE1DULL,
		0x954EB8B26C7268A1ULL,
		0x4B0A407A1C70E9ECULL,
		0x9677D131EF8A3A45ULL,
		0x36AAFD1FCCA0D86FULL,
		0xA8F6E76F0D1AE8C8ULL,
		0x7AB92BCD6DAB0677ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xB0BA53CF44B6D421ULL,
		0xA4546988D3672D3AULL,
		0x8F8F02EC57986C88ULL,
		0x05565EBD214735F2ULL,
		0x0FFAC05CB9A53810ULL,
		0xD0390E5F90D8D037ULL,
		0x5B2107DF93F590A3ULL,
		0x93AF840627ED1937ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6518AE9930367068ULL,
		0x42347BD1503239BFULL,
		0x80F43BFE4D0E63DEULL,
		0x71761B024B0D2908ULL,
		0xF66F7B56AD97FA2CULL,
		0x57D1EC7441548313ULL,
		0x2F7FE3B2FE1C50CAULL,
		0x911A4A4AEDCA3C9FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4BA1A536148063B9ULL,
		0x621FEDB78334F37BULL,
		0x0E9AC6EE0A8A08AAULL,
		0x93E043BAD63A0CEAULL,
		0x198B45060C0D3DE3ULL,
		0x786721EB4F844D23ULL,
		0x2BA1242C95D93FD9ULL,
		0x029539BB3A22DC98ULL
	}};
	sign = 0;
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
		0xF5F556D1634BC0E9ULL,
		0xE1E73DDFD012A432ULL,
		0x37477E76CB808236ULL,
		0x2E2CCDCB6510C805ULL,
		0x68B806119258DA51ULL,
		0x664CBD583C7414C2ULL,
		0x363B9948B9CD4A40ULL,
		0x1AE226B907C765ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2D319DC9F827234ULL,
		0xE5E76557BB77210FULL,
		0x6C7EFC35C615F58EULL,
		0xC32993D5A51467B1ULL,
		0x9B94B2D1682E41AEULL,
		0xCB8834B2FBE3D137ULL,
		0x10E37098229B6CBFULL,
		0xD26BEC2A447E33CAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x13223CF4C3C94EB5ULL,
		0xFBFFD888149B8323ULL,
		0xCAC88241056A8CA7ULL,
		0x6B0339F5BFFC6053ULL,
		0xCD2353402A2A98A2ULL,
		0x9AC488A54090438AULL,
		0x255828B09731DD80ULL,
		0x48763A8EC34931E1ULL
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
		0xCC73C685859F16C8ULL,
		0x58732DAC20E45773ULL,
		0x6079722BBEBC75CDULL,
		0x3E70B97FFAEDBC1DULL,
		0x8D0FFC080019E78BULL,
		0xAACE083F456A1195ULL,
		0x310107E6C0E629F8ULL,
		0x3EDB5D4203354A68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6D095328BFF39ABULL,
		0x8D9CB9574239F9A3ULL,
		0xB5BE3D1A5D286C49ULL,
		0xB5DA26B056197D71ULL,
		0x1B1905CF07BBE4E3ULL,
		0x87F08517AF516C35ULL,
		0x8028829C2092E851ULL,
		0xBA11067029E43D42ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x15A33152F99FDD1DULL,
		0xCAD67454DEAA5DD0ULL,
		0xAABB351161940983ULL,
		0x889692CFA4D43EABULL,
		0x71F6F638F85E02A7ULL,
		0x22DD83279618A560ULL,
		0xB0D8854AA05341A7ULL,
		0x84CA56D1D9510D25ULL
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
		0xCDE1D03D84E65658ULL,
		0x2D7BE4BCA4CBB285ULL,
		0xA3708648F4DF794FULL,
		0x8625E691A2DA57FBULL,
		0x343DF62336B7213FULL,
		0x34FE3FF887DC1ACEULL,
		0xABED955A02835E61ULL,
		0x5B0DEC8427D4A1D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64C4799C648BD7AAULL,
		0xA34316B236EB7BAFULL,
		0x99D9753566E24746ULL,
		0x8AD953C73B5D4A47ULL,
		0xB5933D8E2320951BULL,
		0x89F8B13FC3051EBFULL,
		0x8F1BE8CEA8EB7B32ULL,
		0x5006B307E1668416ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x691D56A1205A7EAEULL,
		0x8A38CE0A6DE036D6ULL,
		0x099711138DFD3208ULL,
		0xFB4C92CA677D0DB4ULL,
		0x7EAAB89513968C23ULL,
		0xAB058EB8C4D6FC0EULL,
		0x1CD1AC8B5997E32EULL,
		0x0B07397C466E1DBBULL
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
		0x1BF3E95E3BD2F41BULL,
		0xC5A7A8ADF4EEDD34ULL,
		0xE9839EE11EA9A5A5ULL,
		0x31ACCE98FC57DF44ULL,
		0x11041F44E000B049ULL,
		0x6F542AA0BA5CCE4BULL,
		0x4F2C74B75509498FULL,
		0x5DD0AA6E7E043705ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0A6BAD3D181B01AULL,
		0x243C313FD5EEB30EULL,
		0xA98883818231205FULL,
		0x15023C6855FB910BULL,
		0x07074EB1053D0E9BULL,
		0xD382627AEE253CDEULL,
		0x5AC3ACF7D0C505DCULL,
		0xE27906F81641BE9DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7B4D2E8A6A514401ULL,
		0xA16B776E1F002A25ULL,
		0x3FFB1B5F9C788546ULL,
		0x1CAA9230A65C4E39ULL,
		0x09FCD093DAC3A1AEULL,
		0x9BD1C825CC37916DULL,
		0xF468C7BF844443B2ULL,
		0x7B57A37667C27867ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x8ACD79713867F63EULL,
		0x467F4BBAB600E680ULL,
		0x5674DE4E704463C3ULL,
		0x88A3B179C0D90286ULL,
		0x87A8C431FC7C95BEULL,
		0x2259D657C1A3659EULL,
		0x3BDE1B2487F01957ULL,
		0x50EAC4102223CAFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E8670BA1C6DF13FULL,
		0xA8A7FD114E7E88C2ULL,
		0xFBF68D45292CEF4AULL,
		0x88435440C3776005ULL,
		0xA29AAB297A86CA81ULL,
		0x846CE7FE984E890FULL,
		0xF15A94199F2580FFULL,
		0xE24E44DE450B593FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6C4708B71BFA04FFULL,
		0x9DD74EA967825DBEULL,
		0x5A7E510947177478ULL,
		0x00605D38FD61A280ULL,
		0xE50E190881F5CB3DULL,
		0x9DECEE592954DC8EULL,
		0x4A83870AE8CA9857ULL,
		0x6E9C7F31DD1871BFULL
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
		0x457CF322A19D75C5ULL,
		0x1D0A5C0DBB7E15D5ULL,
		0x2F7989EB8A61361DULL,
		0x3542B02185611721ULL,
		0x3331CBDF431C2351ULL,
		0xD236BA23965462D1ULL,
		0x9D6E3A4E83689F7FULL,
		0x9055C6470E21FB3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24990F82B3CB9042ULL,
		0x9114E48C1D0B594FULL,
		0x115E20EB7AD2B090ULL,
		0x3C8965FCB210D32CULL,
		0x4D4BB665C328495AULL,
		0x9D5F63A0CCAC54A8ULL,
		0xECE0360A7738F0FCULL,
		0x7E9ABC52E040A7C3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x20E3E39FEDD1E583ULL,
		0x8BF577819E72BC86ULL,
		0x1E1B69000F8E858CULL,
		0xF8B94A24D35043F5ULL,
		0xE5E615797FF3D9F6ULL,
		0x34D75682C9A80E28ULL,
		0xB08E04440C2FAE83ULL,
		0x11BB09F42DE15377ULL
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
		0x0D41F9EDEB18C1A6ULL,
		0xA6D237C49A06A05FULL,
		0x1804EC6E2D01FD70ULL,
		0xFFC9C42586983420ULL,
		0x131E67497082AB4AULL,
		0xD75630E8633674F3ULL,
		0x03CD900A51CDB3DEULL,
		0x4B33D617BEC6B47BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF1309C74FE4AAE4ULL,
		0xFDD3C81F31E84FD1ULL,
		0xECFC74DCBF1C91CBULL,
		0xE65A81EBFAD0AE93ULL,
		0xBD58324DEFABBBE3ULL,
		0x15345DE61FD66F1EULL,
		0xF50D0AAAC21B4242ULL,
		0xF5F6730FAEB72FC5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5E2EF0269B3416C2ULL,
		0xA8FE6FA5681E508DULL,
		0x2B0877916DE56BA4ULL,
		0x196F42398BC7858CULL,
		0x55C634FB80D6EF67ULL,
		0xC221D302436005D4ULL,
		0x0EC0855F8FB2719CULL,
		0x553D6308100F84B5ULL
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
		0xFECD48A69E5C30E2ULL,
		0xFFDF5CDCA7B84F6EULL,
		0xAF6241357F7C8A30ULL,
		0x0FA38985ED0D5246ULL,
		0xE729A872363C4607ULL,
		0x10FA4C42E7779295ULL,
		0x683AEAA88815F360ULL,
		0xCAF689E42F7528B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2126634AD4F4A564ULL,
		0x80E48F21FE72F42BULL,
		0x19E011D62EFFEF0CULL,
		0x1C2DA8D1DD3DF12FULL,
		0xE5E9361B2E91A715ULL,
		0x9F2B26A13FE2598BULL,
		0xD727629A5084683BULL,
		0x7DECAF1EE1421278ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDDA6E55BC9678B7EULL,
		0x7EFACDBAA9455B43ULL,
		0x95822F5F507C9B24ULL,
		0xF375E0B40FCF6117ULL,
		0x0140725707AA9EF1ULL,
		0x71CF25A1A795390AULL,
		0x9113880E37918B24ULL,
		0x4D09DAC54E331637ULL
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
		0x4DB799369D3665B0ULL,
		0xE1E937A23CCCC939ULL,
		0x287BAB5D0C3A1356ULL,
		0x4768D7B1455F3160ULL,
		0xC42621FA903711FAULL,
		0xCD4113FD7CAEAEA5ULL,
		0x45BE8222198E18EBULL,
		0xB884FEF11D038D99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD540429A3BA7C11ULL,
		0xE18CB5624115A192ULL,
		0x3A5737B4F451898FULL,
		0x5F6C8988824537BEULL,
		0x1AB8537F1C07548EULL,
		0xBD33A8258353941CULL,
		0x1BC2A44201FAD723ULL,
		0x477F260D8E156FCAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7063950CF97BE99FULL,
		0x005C823FFBB727A6ULL,
		0xEE2473A817E889C7ULL,
		0xE7FC4E28C319F9A1ULL,
		0xA96DCE7B742FBD6BULL,
		0x100D6BD7F95B1A89ULL,
		0x29FBDDE0179341C8ULL,
		0x7105D8E38EEE1DCFULL
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
		0x9F9EF12B2F7EF64EULL,
		0x61CA4E6CC1B9164FULL,
		0xED9C9620367BC8A8ULL,
		0xCD22BB5764EB143CULL,
		0xCDD293FF487DF97AULL,
		0x03A039A38126E7DAULL,
		0xC1A280B8AA41614DULL,
		0xB418EF1908DD3A38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA71BE97993CF4777ULL,
		0xCB27B31A7ECFF53BULL,
		0x23108F6B47ACC916ULL,
		0x5A17CB9770998F7CULL,
		0xA96E9D94C1C6358EULL,
		0x5D6E8C98B8263A7DULL,
		0x30B0649E7A07C449ULL,
		0xAA2891618D42B136ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF88307B19BAFAED7ULL,
		0x96A29B5242E92113ULL,
		0xCA8C06B4EECEFF91ULL,
		0x730AEFBFF45184C0ULL,
		0x2463F66A86B7C3ECULL,
		0xA631AD0AC900AD5DULL,
		0x90F21C1A30399D03ULL,
		0x09F05DB77B9A8902ULL
	}};
	sign = 0;
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
		0x90BE23C9F9E574B4ULL,
		0xE49F85CE00B90980ULL,
		0x5BD8D8C2BFB51D5EULL,
		0x4B1FF969BD455931ULL,
		0xF37DB7A9E08F58B5ULL,
		0x9D92459A3A3ACD24ULL,
		0xB11E615BE9EB72DEULL,
		0xE881F72EA61DFFB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3705CD1B235CE4EULL,
		0x997AF7F35631FF25ULL,
		0x26A8A8AC183924B5ULL,
		0xCD6DCBC369AE83B9ULL,
		0x6281255C73F31800ULL,
		0xF31755464010EC82ULL,
		0x95E995B498886792ULL,
		0xF94D786AAD5E6F48ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAD4DC6F847AFA666ULL,
		0x4B248DDAAA870A5AULL,
		0x35303016A77BF8A9ULL,
		0x7DB22DA65396D578ULL,
		0x90FC924D6C9C40B4ULL,
		0xAA7AF053FA29E0A2ULL,
		0x1B34CBA751630B4BULL,
		0xEF347EC3F8BF9070ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x3328E5C934EFB710ULL,
		0xE86A0B2AC6B8F030ULL,
		0x3CE57BD666CEC07DULL,
		0xD88074DA0EB8FD96ULL,
		0xC68CB57CAD98DF30ULL,
		0xFB9C2AA8353C4746ULL,
		0x6708C70D0BD8B95FULL,
		0x941AC00BCA293C3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73B68203EC5EB578ULL,
		0x3263332570260E95ULL,
		0xD53D60AA5FA1B3ABULL,
		0x892C3AFE1280BC39ULL,
		0x54E526E90ABC709BULL,
		0xB81BC827A75AA049ULL,
		0x748DAB7145F9A938ULL,
		0xA9631AB77B7532C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBF7263C548910198ULL,
		0xB606D8055692E19AULL,
		0x67A81B2C072D0CD2ULL,
		0x4F5439DBFC38415CULL,
		0x71A78E93A2DC6E95ULL,
		0x438062808DE1A6FDULL,
		0xF27B1B9BC5DF1027ULL,
		0xEAB7A5544EB4097BULL
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
		0xF1EF320DAC0F28A2ULL,
		0x9A0B7174A8662974ULL,
		0x30C1397DBAB3F2FAULL,
		0x8A9291E01AD889B8ULL,
		0x2EEC430CDA917BA2ULL,
		0x0DE6EE4BCE759358ULL,
		0xA6717B507378B329ULL,
		0xCE42C9E44ABB5637ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88CADBB975E97FB1ULL,
		0xBBCF8C74BD4439E6ULL,
		0x3FEA136EB9D5FF5AULL,
		0x96D17C62203FC13EULL,
		0x785CF49CA020732BULL,
		0x97D64D47755731B7ULL,
		0x074DDD54AA276E71ULL,
		0x572B5F8A9988FF9EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x692456543625A8F1ULL,
		0xDE3BE4FFEB21EF8EULL,
		0xF0D7260F00DDF39FULL,
		0xF3C1157DFA98C879ULL,
		0xB68F4E703A710876ULL,
		0x7610A104591E61A0ULL,
		0x9F239DFBC95144B7ULL,
		0x77176A59B1325699ULL
	}};
	sign = 0;
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
		0x766EE0B1CFAACDA2ULL,
		0xFA2BC47E6A155013ULL,
		0x64AD5662361C1F83ULL,
		0x3FB5854424BE4ED0ULL,
		0x5F8BE40AD8F3FCAEULL,
		0x33EFF0DEE054DB73ULL,
		0xA0EAAAED6E055682ULL,
		0xEAE0C5DA1E5FDC9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08E31A102ADAB37EULL,
		0xE535E2D69CDECC32ULL,
		0xA2EC67861885AB8DULL,
		0xF7DCB901EEF27A94ULL,
		0xCF8821F618B5DF6BULL,
		0xEE5A4F68138D1072ULL,
		0x423AA25F573AC57FULL,
		0x00DE1FFB47523F6EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6D8BC6A1A4D01A24ULL,
		0x14F5E1A7CD3683E1ULL,
		0xC1C0EEDC1D9673F6ULL,
		0x47D8CC4235CBD43BULL,
		0x9003C214C03E1D42ULL,
		0x4595A176CCC7CB00ULL,
		0x5EB0088E16CA9102ULL,
		0xEA02A5DED70D9D2EULL
	}};
	sign = 0;
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
		0x84002F27F0B589A3ULL,
		0xA5029622A66DFA29ULL,
		0xF63515BFDB7EBBF7ULL,
		0x53209B9816249CDFULL,
		0x6415C43937E5CFC5ULL,
		0xBA05578366C66A99ULL,
		0xE178A9A01FD3825CULL,
		0x31B1D4CD4CD20E83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D162AB025522B91ULL,
		0x9E9FF9CDA5236AF9ULL,
		0x6D634F46E7A9CBBCULL,
		0xD974A10370B4CF01ULL,
		0x8658C0C807B27048ULL,
		0x969E0D129ACF82FEULL,
		0x16FB1630CF7ADF5DULL,
		0xDA711BB85C6DCD61ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x56EA0477CB635E12ULL,
		0x06629C55014A8F30ULL,
		0x88D1C678F3D4F03BULL,
		0x79ABFA94A56FCDDEULL,
		0xDDBD037130335F7CULL,
		0x23674A70CBF6E79AULL,
		0xCA7D936F5058A2FFULL,
		0x5740B914F0644122ULL
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
		0xFE75F0CA962A899EULL,
		0xE958435CB2F2600EULL,
		0x795FFF1CF7F75DF8ULL,
		0xCF064A38D25EE3C8ULL,
		0xBEE96C6AB3848E19ULL,
		0xDB4034EB05C111BBULL,
		0x4EB4F80699A2124EULL,
		0xB5DD34F0A143644EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9296897FAFE7BE30ULL,
		0x1E549D8244C2ADEDULL,
		0x5E008B31CC475E09ULL,
		0xAD4F4E8E04841AE3ULL,
		0xA76F2C12E050DD0FULL,
		0x9B1EEEEACC687B90ULL,
		0x653508C1C1496767ULL,
		0xE1756DCAFA978AECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6BDF674AE642CB6EULL,
		0xCB03A5DA6E2FB221ULL,
		0x1B5F73EB2BAFFFEFULL,
		0x21B6FBAACDDAC8E5ULL,
		0x177A4057D333B10AULL,
		0x402146003958962BULL,
		0xE97FEF44D858AAE7ULL,
		0xD467C725A6ABD961ULL
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
		0xFF5A5221F55071E6ULL,
		0x126A244B1EFF34B6ULL,
		0xA669971F768C3CE1ULL,
		0x073929E9C11E9CB5ULL,
		0x0DBF42670CF60BBFULL,
		0xBBB71A10ADD2F49BULL,
		0x526C4C801A7D768BULL,
		0x5A90B842B4A102E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x502E2E5A08508EFCULL,
		0x2F96059DB857CD63ULL,
		0x72B8D30447AA72A6ULL,
		0x10F0FD53D9FAEB4CULL,
		0xAB5C55DCD181D0F2ULL,
		0xC927A9D9B4425FF3ULL,
		0x029CABA1E98FD34DULL,
		0x664CF79AC4049E33ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAF2C23C7ECFFE2EAULL,
		0xE2D41EAD66A76753ULL,
		0x33B0C41B2EE1CA3AULL,
		0xF6482C95E723B169ULL,
		0x6262EC8A3B743ACCULL,
		0xF28F7036F99094A7ULL,
		0x4FCFA0DE30EDA33DULL,
		0xF443C0A7F09C64AFULL
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
		0xA57B27DD48EC8D40ULL,
		0x8AF58799FD00F0F6ULL,
		0x10386A3B7B3603FAULL,
		0x74E77154FFD80534ULL,
		0x0EBC9FB03C69DEF5ULL,
		0x89EE33335953D027ULL,
		0xF35A5DFA69D29A26ULL,
		0x2AA7CE53FAAD0C36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7AEEFE3B8052851CULL,
		0x796BE1557878AECEULL,
		0xCFC45B0BF37235D6ULL,
		0x9579194E9AA7F015ULL,
		0x5509F003279F34AFULL,
		0x433C91A9EEAA7DD4ULL,
		0xCC43E5181C2FC4DEULL,
		0x5299E49710AF8A72ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2A8C29A1C89A0824ULL,
		0x1189A64484884228ULL,
		0x40740F2F87C3CE24ULL,
		0xDF6E58066530151EULL,
		0xB9B2AFAD14CAAA45ULL,
		0x46B1A1896AA95252ULL,
		0x271678E24DA2D548ULL,
		0xD80DE9BCE9FD81C4ULL
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
		0x9AF8D32084521BB0ULL,
		0xBDD948C548FF51EAULL,
		0x788351932BC30587ULL,
		0xAC4554AFC9FB3CF4ULL,
		0x9C86014E238C20D1ULL,
		0x335AD18BAF30EBC4ULL,
		0x0AF2B82A7E4BE8FDULL,
		0x9932BE634A22CF29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB70E859A27044AAULL,
		0x0F5E3DC6EA922FEEULL,
		0x4C6FD7966437A3EDULL,
		0x37F8CB88B3FD91FFULL,
		0xD2C4D668E2086436ULL,
		0x69B472BFA22E9956ULL,
		0xBC9D1FDEE3BF333DULL,
		0x8D619C6C25452646ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCF87EAC6E1E1D706ULL,
		0xAE7B0AFE5E6D21FBULL,
		0x2C1379FCC78B619AULL,
		0x744C892715FDAAF5ULL,
		0xC9C12AE54183BC9BULL,
		0xC9A65ECC0D02526DULL,
		0x4E55984B9A8CB5BFULL,
		0x0BD121F724DDA8E2ULL
	}};
	sign = 0;
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
		0xD015974A7144A42CULL,
		0x843D1FA001F98576ULL,
		0x86153A849FFF74A8ULL,
		0xA84FBBE85C6D3682ULL,
		0x3F844D85ABD878D4ULL,
		0x529C1F47E0EFC2F6ULL,
		0xAFAE04D146674111ULL,
		0xB8AC944821670624ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24570817DD376C1EULL,
		0xFEE3E5D159400777ULL,
		0x0B7BD9C0D007E8D0ULL,
		0x61A2A7E4F7E9EC5DULL,
		0xD36AA5C44FE12CB3ULL,
		0x7782D81A5928D870ULL,
		0x0AFF5DB98507E560ULL,
		0x37DCC3ACC23F687DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xABBE8F32940D380EULL,
		0x855939CEA8B97DFFULL,
		0x7A9960C3CFF78BD7ULL,
		0x46AD140364834A25ULL,
		0x6C19A7C15BF74C21ULL,
		0xDB19472D87C6EA85ULL,
		0xA4AEA717C15F5BB0ULL,
		0x80CFD09B5F279DA7ULL
	}};
	sign = 0;
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
		0xD052CBC8BB33EFB6ULL,
		0x065FE853E00BD5D5ULL,
		0x74B84DC2923E37F9ULL,
		0x9A2F8554485D89E5ULL,
		0x2D9CEABFAE4223C3ULL,
		0xAAADA33C167D981EULL,
		0x39593C530B52636CULL,
		0xD62BAA9EF1CBD546ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE57F9D7105D0E866ULL,
		0x11495D6297F0FE0FULL,
		0xA0F12BEA0D4F5668ULL,
		0x339013CE04DA4C55ULL,
		0x79319B8A9D89F73AULL,
		0x9264A17F2C0ABFB2ULL,
		0xAAB34766207BF659ULL,
		0xA842220B2D92EBE0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEAD32E57B5630750ULL,
		0xF5168AF1481AD7C5ULL,
		0xD3C721D884EEE190ULL,
		0x669F718643833D8FULL,
		0xB46B4F3510B82C89ULL,
		0x184901BCEA72D86BULL,
		0x8EA5F4ECEAD66D13ULL,
		0x2DE98893C438E965ULL
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
		0x1A65B5F5AC9E317CULL,
		0xA363C017F8A9B5B7ULL,
		0x3489A2626DDDF563ULL,
		0x1995CDC26E8305E8ULL,
		0xC52386E7E2362432ULL,
		0xCD96696AA9073AEDULL,
		0x8860266D06C37D0EULL,
		0x7828D852F63AEDF6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B70837067A108F4ULL,
		0xAB36637DE859B88FULL,
		0x6A52C28A0D2E85BDULL,
		0x6204581EEBB1430AULL,
		0x70D36B8D72D92977ULL,
		0x73D607387C7555A9ULL,
		0x970EDC9CB9AC58A5ULL,
		0xBBB5052AEB73DE8AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9EF5328544FD2888ULL,
		0xF82D5C9A104FFD27ULL,
		0xCA36DFD860AF6FA5ULL,
		0xB79175A382D1C2DDULL,
		0x54501B5A6F5CFABAULL,
		0x59C062322C91E544ULL,
		0xF15149D04D172469ULL,
		0xBC73D3280AC70F6BULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x499D56570437FEDCULL,
		0x052B6AE81A12AC11ULL,
		0xFE78F564DED12182ULL,
		0x25BEA60A0838BFFCULL,
		0xCC0CBBAA04F985C9ULL,
		0xF8F6A108B3CA6CEBULL,
		0x1C16AD6075412E4DULL,
		0x549845B75EA20790ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95D538AC4210B137ULL,
		0x555DA510AD9D8F02ULL,
		0xBD4D57E6BAD7516FULL,
		0xF07D25634DDEF4D9ULL,
		0x4DAF4DC7B491DD57ULL,
		0x7878916AADF82B59ULL,
		0xAB51571C76E476CEULL,
		0x64ED90B34D98C146ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB3C81DAAC2274DA5ULL,
		0xAFCDC5D76C751D0EULL,
		0x412B9D7E23F9D012ULL,
		0x354180A6BA59CB23ULL,
		0x7E5D6DE25067A871ULL,
		0x807E0F9E05D24192ULL,
		0x70C55643FE5CB77FULL,
		0xEFAAB50411094649ULL
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
		0x0FD5C9C65525A471ULL,
		0x2E2CD39045FA81B8ULL,
		0xEAB7F6DE2043BC9FULL,
		0x0C25D0A14AF6B3B1ULL,
		0xE3CEB723A7EBB98EULL,
		0x3A2212F5518BE6C1ULL,
		0x2656BFF549BA6ACCULL,
		0xB03A5C8019C8B43CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA40CF60011FF544CULL,
		0x7A830C6841BBEF93ULL,
		0x9407732F81422B28ULL,
		0x759E233B79EC78A2ULL,
		0xED51E4545030FD8BULL,
		0x5E13E7831CC6017EULL,
		0x87215A99E3C0CC9BULL,
		0x1617CBF09C3D0943ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6BC8D3C643265025ULL,
		0xB3A9C728043E9224ULL,
		0x56B083AE9F019176ULL,
		0x9687AD65D10A3B0FULL,
		0xF67CD2CF57BABC02ULL,
		0xDC0E2B7234C5E542ULL,
		0x9F35655B65F99E30ULL,
		0x9A22908F7D8BAAF8ULL
	}};
	sign = 0;
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
		0xA2136A110F8C22E1ULL,
		0x1DCD5F8140A359BDULL,
		0x841F72DDF21407DAULL,
		0xD7CD4AD430DFD372ULL,
		0x4A503AD8F6BC539DULL,
		0x9E966851915FE741ULL,
		0x255156599E750B2CULL,
		0xDF7E71DC43DDDB90ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9AD0492C17C928A0ULL,
		0xBDDCD4341CE19FA5ULL,
		0xADD43CD97F6F1301ULL,
		0x131EA4CFAAE32206ULL,
		0x860B50D51AAF3C51ULL,
		0x89200992EFB96929ULL,
		0xDC7B54B017BE5E2DULL,
		0x72CBF876B6FD9C39ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x074320E4F7C2FA41ULL,
		0x5FF08B4D23C1BA18ULL,
		0xD64B360472A4F4D8ULL,
		0xC4AEA60485FCB16BULL,
		0xC444EA03DC0D174CULL,
		0x15765EBEA1A67E17ULL,
		0x48D601A986B6ACFFULL,
		0x6CB279658CE03F56ULL
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
		0x8EA923B570A1B53BULL,
		0xA2984C10160B8597ULL,
		0x39F55A7C5CEADDFAULL,
		0xE5716EE367FAFEA2ULL,
		0x44D56CBEA0DBD8DEULL,
		0x99F9E11C878034ACULL,
		0x725EC7B65FB07B9AULL,
		0x426A170C401534EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA36356DF96456F19ULL,
		0x2ACC919D11D58F62ULL,
		0xA738828E14119376ULL,
		0x3D96B6B047ED87C1ULL,
		0x65264A9F119E45E4ULL,
		0x587005776CCEB29BULL,
		0x6C0042F1E1B1DBC0ULL,
		0x47EDF6AEC7F9AF81ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEB45CCD5DA5C4622ULL,
		0x77CBBA730435F634ULL,
		0x92BCD7EE48D94A84ULL,
		0xA7DAB833200D76E0ULL,
		0xDFAF221F8F3D92FAULL,
		0x4189DBA51AB18210ULL,
		0x065E84C47DFE9FDAULL,
		0xFA7C205D781B856AULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xB25EBFDC19535225ULL,
		0x5D7E246DD26808DBULL,
		0x28E0EEE35A19CAF8ULL,
		0x5105721BD930BCD4ULL,
		0x447C1C33D478911BULL,
		0xF4EB32335D387769ULL,
		0x3D3C6FB6B722AC18ULL,
		0xF0541A6720B93877ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC20CF8F73FCDFE03ULL,
		0xF657A0B8AB8B49D4ULL,
		0xD1C5F094A1550561ULL,
		0x283B931B33892AFDULL,
		0xF5F8697D736CB650ULL,
		0x4C5568E523408E62ULL,
		0x388B28EE5321014CULL,
		0xF749859F99D81F29ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF051C6E4D9855422ULL,
		0x672683B526DCBF06ULL,
		0x571AFE4EB8C4C596ULL,
		0x28C9DF00A5A791D6ULL,
		0x4E83B2B6610BDACBULL,
		0xA895C94E39F7E906ULL,
		0x04B146C86401AACCULL,
		0xF90A94C786E1194EULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x0CD973DFE2A632EEULL,
		0x8D07C9EB8C80FEF7ULL,
		0x57AD030CFDDBA2FDULL,
		0x22E7149EF91774ECULL,
		0xDD60BB5301C17A25ULL,
		0xE1C9DFE542F59E5EULL,
		0xFC5EBF820554EAADULL,
		0x0D745EDB0362E83DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97427A28907CE7F7ULL,
		0x8C41D62EB47694ACULL,
		0xEA825C8847B215A3ULL,
		0xF2B9AEAE3F9D0D22ULL,
		0xFCC39E5D1D06102EULL,
		0x84F4DE21248E5A56ULL,
		0x069AB173C9C05A19ULL,
		0x785BD7EE7DBD13A8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7596F9B752294AF7ULL,
		0x00C5F3BCD80A6A4AULL,
		0x6D2AA684B6298D5AULL,
		0x302D65F0B97A67C9ULL,
		0xE09D1CF5E4BB69F6ULL,
		0x5CD501C41E674407ULL,
		0xF5C40E0E3B949094ULL,
		0x951886EC85A5D495ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xF85D53B8CC83CF1DULL,
		0xA16D39C47EBE3174ULL,
		0x0DDA6ABC8543B3A5ULL,
		0x012F065868345C62ULL,
		0xACB2DF0013E1D510ULL,
		0x0D66010892238192ULL,
		0x374E8A98C016FA73ULL,
		0xABE26CCE49DDA711ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA061967975B19636ULL,
		0xE0F65373358F30FDULL,
		0x69EF5FE12FC5B13EULL,
		0x37A4D2A4CB581AA9ULL,
		0x8CFE7DD07BE4432BULL,
		0x59C6D31EC5861D9BULL,
		0x1BDF24CD3A01C018ULL,
		0x0FEAA5F602208AC3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x57FBBD3F56D238E7ULL,
		0xC076E651492F0077ULL,
		0xA3EB0ADB557E0266ULL,
		0xC98A33B39CDC41B8ULL,
		0x1FB4612F97FD91E4ULL,
		0xB39F2DE9CC9D63F7ULL,
		0x1B6F65CB86153A5AULL,
		0x9BF7C6D847BD1C4EULL
	}};
	sign = 0;
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
		0x3109E819475E0517ULL,
		0xD4616EBEA1EA9794ULL,
		0x0D3234F4EB5C74F0ULL,
		0xAC40B75026411D72ULL,
		0xDBAE9C23B09939B2ULL,
		0x3278550DE3CB8AB6ULL,
		0x5315D1269D32B73CULL,
		0x9488A219E1377704ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA8DD7CC13270196ULL,
		0xC6AE0581CBC2711CULL,
		0xCCB8E1323B067902ULL,
		0x79E2212099110A54ULL,
		0xCF9C0855FE9CDF29ULL,
		0x6B50B2BC01C6C0BBULL,
		0x940436B05E28FFE1ULL,
		0xEEA6B17FC6D4CC8FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x867C104D34370381ULL,
		0x0DB3693CD6282677ULL,
		0x407953C2B055FBEEULL,
		0x325E962F8D30131DULL,
		0x0C1293CDB1FC5A89ULL,
		0xC727A251E204C9FBULL,
		0xBF119A763F09B75AULL,
		0xA5E1F09A1A62AA74ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x1205FEFC53E07A76ULL,
		0x06552D30A1565502ULL,
		0x8FF38B5332E0D788ULL,
		0x10070FF0A90BFF5CULL,
		0x65BDE7A02DC824FFULL,
		0x77141420E7CBCB12ULL,
		0xC7E1C4946C6B7D2DULL,
		0x76A84594C080A301ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA14E4A1BC4A8930BULL,
		0x65CC816EC614C0DAULL,
		0xA04671B91090ADD9ULL,
		0x81FB44ADE138E232ULL,
		0x70707F816B0C1B42ULL,
		0xBFDED3E43A9EDE55ULL,
		0xAAED86AEAC195FE8ULL,
		0xF2836375152833C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x70B7B4E08F37E76BULL,
		0xA088ABC1DB419427ULL,
		0xEFAD199A225029AEULL,
		0x8E0BCB42C7D31D29ULL,
		0xF54D681EC2BC09BCULL,
		0xB735403CAD2CECBCULL,
		0x1CF43DE5C0521D44ULL,
		0x8424E21FAB586F3FULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x4E04C4CAA329256CULL,
		0x9EB331062581158BULL,
		0x2F7ACF0EE7BC88C8ULL,
		0xAE5F24D277E39159ULL,
		0x83B5FEA7CF518DE6ULL,
		0x0123A3D969FF6B41ULL,
		0x8D2586D9F772DA39ULL,
		0x39DAEB577159075CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x697FA9CEC361F56EULL,
		0xE9F839CE44015431ULL,
		0xA3EEB661F1A9B814ULL,
		0x59EB28EA1A3CF56EULL,
		0x72470044ECD50502ULL,
		0x805410D47D1B8557ULL,
		0x0B50F61F8A1ACBB7ULL,
		0x84AD0E0529BE418FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE4851AFBDFC72FFEULL,
		0xB4BAF737E17FC159ULL,
		0x8B8C18ACF612D0B3ULL,
		0x5473FBE85DA69BEAULL,
		0x116EFE62E27C88E4ULL,
		0x80CF9304ECE3E5EAULL,
		0x81D490BA6D580E81ULL,
		0xB52DDD52479AC5CDULL
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