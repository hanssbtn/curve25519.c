#include "../tests.h"

int32_t curve25519_key_sub_inplace_test(void) {
	printf("Inplace Key Subtraction Test\n");
	curve25519_key_signed_t k1 = {.key = {.key64 = {
		0x8F12B9063E523143ULL,
		0x0C5ADB9F7D7BF274ULL,
		0xC7EB4FC5A3BE0A19ULL,
		0xBF38FD7DBB2A0E73ULL,
		0x0C2FA42F4EE246F9ULL,
		0xCCC5081149F21532ULL,
		0x656231613EBA6000ULL,
		0xF05B50955A748B13ULL
	}}};
	curve25519_key_t k2 = {.key64 = {
		0xB64236F686BDC7D2ULL,
		0x5196A873BB8288BAULL,
		0x8B4FE458D1B296CFULL,
		0xAD1CF18CD0F8C796ULL,
		0x9B2179712B8F40BCULL,
		0x7E4CFBA00B2C80F9ULL,
		0x05E589B9E1091A35ULL,
		0xEC26CE2A406C8B05ULL
	}};
	curve25519_key_t k3 = {.key64 = {
		0xD8D0820FB7946971ULL,
		0xBAC4332BC1F969B9ULL,
		0x3C9B6B6CD20B7349ULL,
		0x121C0BF0EA3146DDULL,
		0x710E2ABE2353063DULL,
		0x4E780C713EC59438ULL,
		0x5F7CA7A75DB145CBULL,
		0x0434826B1A08000EULL
	}};
	int sign = 0;
	printf("Test Case 1\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	int borrow = curve25519_key_sub_inplace(&k1, &k2);
	int32_t res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 1 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x2F6A805735C8386FULL,
		0x4E7B19E74C78B424ULL,
		0x362C0DA3871EA8D3ULL,
		0x697120841D1108F6ULL,
		0x66B0E7A516385068ULL,
		0x14A03577D93EBF0BULL,
		0x2B35590B64793047ULL,
		0x59F09064668D14A7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x216C8E4A1DA0C89BULL,
		0xAD5337A89236CC94ULL,
		0x3E5194890FA13F08ULL,
		0x016D61ABBBAF643FULL,
		0xC235FFA8242F153DULL,
		0x37AA68495E1B4E73ULL,
		0x232A6CECC0085BC7ULL,
		0x3EE8A1B620141146ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0DFDF20D18276FD4ULL,
		0xA127E23EBA41E790ULL,
		0xF7DA791A777D69CAULL,
		0x6803BED86161A4B6ULL,
		0xA47AE7FCF2093B2BULL,
		0xDCF5CD2E7B237097ULL,
		0x080AEC1EA470D47FULL,
		0x1B07EEAE46790361ULL
	}};
	sign = 0;
	printf("Test Case 2\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 2 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x90F172404DC857B5ULL,
		0xE9517E318FA87F36ULL,
		0x316A079D6C93FBCEULL,
		0x920FF1CC76E1FCD0ULL,
		0x7FBB9AEBB8FF170CULL,
		0x199E5A01EB6F776BULL,
		0x59DB7954679C7EF0ULL,
		0x7FB2EAB5C239507FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3522F2799CF40462ULL,
		0xD90971918D80AF7CULL,
		0x83343D61E5DE12C4ULL,
		0xD304D762E4F217B8ULL,
		0xD88A4053BBE73322ULL,
		0x3A22882CA319F4BAULL,
		0xA1E5C142A69DEF86ULL,
		0xCA91A0CEE62571CAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5BCE7FC6B0D45353ULL,
		0x10480CA00227CFBAULL,
		0xAE35CA3B86B5E90AULL,
		0xBF0B1A6991EFE517ULL,
		0xA7315A97FD17E3E9ULL,
		0xDF7BD1D5485582B0ULL,
		0xB7F5B811C0FE8F69ULL,
		0xB52149E6DC13DEB4ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 3\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 3 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD5A84445C9F9411EULL,
		0xDB2919E6DC868C61ULL,
		0x45B6339527E5F467ULL,
		0x61286FCF8490ADEDULL,
		0x14D342ABC7671E91ULL,
		0x0715F84696D7FD0BULL,
		0xFC3CC4C521791BB9ULL,
		0x3226ED6959216EB7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x326647BC59854CF1ULL,
		0xD0508A0CCA6A30D5ULL,
		0xCEC2AB65E4BCB9A8ULL,
		0x0203D73F2B83A4E9ULL,
		0xC1B8BDA96E66D016ULL,
		0x7C5CFF374BD783FFULL,
		0xB2B4AD688B82FF30ULL,
		0xA7CAEE6BAB3D6B62ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA341FC897073F42DULL,
		0x0AD88FDA121C5B8CULL,
		0x76F3882F43293ABFULL,
		0x5F249890590D0903ULL,
		0x531A850259004E7BULL,
		0x8AB8F90F4B00790BULL,
		0x4988175C95F61C88ULL,
		0x8A5BFEFDADE40355ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 4\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 4 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1FC406503F6DDBF1ULL,
		0xE221BB68CF64B84FULL,
		0xE29A004C70DD7DD4ULL,
		0x0B2E4FCFDE4B09E1ULL,
		0xF8FDBD0C2D2C0A51ULL,
		0x7ECFD4DFED77CC74ULL,
		0xD389666EE1D304A0ULL,
		0x184AC00AE9734534ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x27665A1C63F7E1A7ULL,
		0xB29C1474B6552072ULL,
		0x8C5264274D082A76ULL,
		0x0ADFCF3899CE132EULL,
		0x28D1C589CAE64045ULL,
		0xC8658A9352E905FDULL,
		0x21C418951B92FB96ULL,
		0xB2889E52C22E0648ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF85DAC33DB75FA4AULL,
		0x2F85A6F4190F97DCULL,
		0x56479C2523D5535EULL,
		0x004E8097447CF6B3ULL,
		0xD02BF7826245CA0CULL,
		0xB66A4A4C9A8EC677ULL,
		0xB1C54DD9C6400909ULL,
		0x65C221B827453EECULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 5\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 5 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x375E26A3BF5DC00CULL,
		0x16B2742CC2ED7CBAULL,
		0xC1D1208187F47BBAULL,
		0x5FC54F8198152F0EULL,
		0x69297A5858B62FD3ULL,
		0x66F5E87AE38AC747ULL,
		0x6BC90DD5D0F6C0ADULL,
		0xA1A071AA8DDA2073ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDE01B255633153FULL,
		0x628DD8220D40D4F9ULL,
		0xAE8877E2AE3CFAC8ULL,
		0xA020E93061B1E2D3ULL,
		0xDF7B031A2D118ACDULL,
		0xB08F93221DB84F84ULL,
		0xD54396A0C97E4BB1ULL,
		0x213389B590B6A7F0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x797E0B7E692AAACDULL,
		0xB4249C0AB5ACA7C0ULL,
		0x1348A89ED9B780F1ULL,
		0xBFA4665136634C3BULL,
		0x89AE773E2BA4A505ULL,
		0xB6665558C5D277C2ULL,
		0x96857735077874FBULL,
		0x806CE7F4FD237882ULL
	}};
	sign = 0;
	printf("Test Case 6\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 6 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x50C3C7221CB05187ULL,
		0x3BDFB512BC3AE74AULL,
		0x93C9F7B6E16EDE6BULL,
		0x4A78BA3B49EE054BULL,
		0xE40BAF182E522641ULL,
		0xEBF5FC58B3222BE2ULL,
		0x98C2EB5A660D1541ULL,
		0xFDA37DEBF3CE5D57ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B7329F2AD2E9310ULL,
		0x59149A1FD4437236ULL,
		0x27364B08852571BCULL,
		0xA20A2C1851A19E2DULL,
		0x740189E10FEB210FULL,
		0x344A42E021B8E438ULL,
		0x9DD1D71BF17B9722ULL,
		0x54C42E561392C150ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB5509D2F6F81BE77ULL,
		0xE2CB1AF2E7F77513ULL,
		0x6C93ACAE5C496CAEULL,
		0xA86E8E22F84C671EULL,
		0x700A25371E670531ULL,
		0xB7ABB978916947AAULL,
		0xFAF1143E74917E1FULL,
		0xA8DF4F95E03B9C06ULL
	}};
	sign = 0;
	printf("Test Case 7\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 7 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0CEF22DF8BADCE20ULL,
		0x8CDE9C4A2F911E09ULL,
		0x038F57C1C01D99EAULL,
		0xAF924A560E882ABFULL,
		0x3C8E7486B75827D1ULL,
		0x5786373FC26AB8E4ULL,
		0xCF235BCAD56BE1B8ULL,
		0xD044B0CB75058547ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA071614AEC894DEBULL,
		0xD2428D53B5F39336ULL,
		0xFBE11653C5DDDE06ULL,
		0x304ED8AA2A1640B9ULL,
		0x8C80651B19D86F77ULL,
		0x3BF02087344AF239ULL,
		0x51C33C08B28189C8ULL,
		0x74AE7C5D0BC4B0EAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6C7DC1949F248035ULL,
		0xBA9C0EF6799D8AD2ULL,
		0x07AE416DFA3FBBE3ULL,
		0x7F4371ABE471EA05ULL,
		0xB00E0F6B9D7FB85AULL,
		0x1B9616B88E1FC6AAULL,
		0x7D601FC222EA57F0ULL,
		0x5B96346E6940D45DULL
	}};
	sign = 0;
	printf("Test Case 8\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 8 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x8F79BF9D3EC888D0ULL,
		0xF1D8C62B350B975BULL,
		0x1AFDA775E67226B7ULL,
		0xBA974C5EAF42F775ULL,
		0x9E612DED92751880ULL,
		0x21034DA02EA0E21EULL,
		0x0498A766CF6FB368ULL,
		0x74C1A44283D6D87BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB806A3DE67D6C43ULL,
		0xCD71E2A73C54924BULL,
		0x0984BFA693CF4DCAULL,
		0xCF2980E9DCC4CF9FULL,
		0xA985D40D3A8C2610ULL,
		0xC452789CBEDEF19FULL,
		0xA99DE7D70272D30AULL,
		0x72BD957218D727E7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC3F9555F584B1C8DULL,
		0x2466E383F8B7050FULL,
		0x1178E7CF52A2D8EDULL,
		0xEB6DCB74D27E27D6ULL,
		0xF4DB59E057E8F26FULL,
		0x5CB0D5036FC1F07EULL,
		0x5AFABF8FCCFCE05DULL,
		0x02040ED06AFFB093ULL
	}};
	sign = 0;
	printf("Test Case 9\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 9 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x411BC4F68532B179ULL,
		0xD9ABBCB3828D6B5AULL,
		0x06697F78C0A2E92EULL,
		0x218127460F8C9299ULL,
		0xDA57952F82B10609ULL,
		0x5246673AA6F0A75BULL,
		0x61E5A3745AADDB99ULL,
		0xF4E7D13C40B70FB9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BA385E95CEDCC70ULL,
		0x3953024BB43E9BBAULL,
		0xE81212D981680FD5ULL,
		0x5AE670F0A9A00BF2ULL,
		0x4E6DC897498B88C0ULL,
		0x8A5B5832B8FBEE19ULL,
		0x146DA597E918C2F5ULL,
		0x0AB83885A6048118ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x25783F0D2844E509ULL,
		0xA058BA67CE4ECFA0ULL,
		0x1E576C9F3F3AD959ULL,
		0xC69AB65565EC86A6ULL,
		0x8BE9CC9839257D48ULL,
		0xC7EB0F07EDF4B942ULL,
		0x4D77FDDC719518A3ULL,
		0xEA2F98B69AB28EA1ULL
	}};
	sign = 0;
	printf("Test Case 10\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 10 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x234B063D71ABB8EFULL,
		0x450D2BC8AF56AD63ULL,
		0x314871B406743090ULL,
		0xB6444F0C5E34FC88ULL,
		0xCB5DE5F4BCC7C1B2ULL,
		0xE52B556115CF28BDULL,
		0xDF20050EC1E1C812ULL,
		0xEA90CACEB2CCAE30ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB76212DE1A1DA2F0ULL,
		0x1CD67FBD4F5E9029ULL,
		0xF31777607C6E8884ULL,
		0x59FC0DCF1CE0765FULL,
		0xCE3D770672FFD53AULL,
		0x754615A7558BC97CULL,
		0x6CBDB70180C5D9E6ULL,
		0x35E7C0D887537A65ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6BE8F35F578E15FFULL,
		0x2836AC0B5FF81D39ULL,
		0x3E30FA538A05A80CULL,
		0x5C48413D41548628ULL,
		0xFD206EEE49C7EC78ULL,
		0x6FE53FB9C0435F40ULL,
		0x72624E0D411BEE2CULL,
		0xB4A909F62B7933CBULL
	}};
	sign = 0;
	printf("Test Case 11\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 11 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB3CE0D7CC2DEFE79ULL,
		0x4678A2F397A028CFULL,
		0x85DA0E9EBA787AB2ULL,
		0xD296088A34E94F8FULL,
		0x7EC1741792C95FF8ULL,
		0x052B89E64F0837A4ULL,
		0x283C2E9852EF896DULL,
		0xDED334B340C5530BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x02B6523CDEF86E10ULL,
		0x1F402EE6DBB5208DULL,
		0xD573E34C190E5299ULL,
		0x2E52567E1F9B2B9BULL,
		0x63B762E56EDC9D48ULL,
		0x49BF17B3EC168311ULL,
		0xC0CFA3A06F3C30CDULL,
		0xD14FF4FE1A490E02ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB117BB3FE3E69069ULL,
		0x2738740CBBEB0842ULL,
		0xB0662B52A16A2819ULL,
		0xA443B20C154E23F3ULL,
		0x1B0A113223ECC2B0ULL,
		0xBB6C723262F1B493ULL,
		0x676C8AF7E3B3589FULL,
		0x0D833FB5267C4508ULL
	}};
	sign = 0;
	printf("Test Case 12\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 12 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x8E3345C777D78F9EULL,
		0x473AB37B778010B8ULL,
		0xF2A0B6C46D1DB45FULL,
		0x6E7D55F49A1C0228ULL,
		0x43344643030EEC26ULL,
		0xC3528D2B21B6B16DULL,
		0x6DC21A5DFC7F3DCFULL,
		0xDBD98B01E595FC07ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3083B20081FA7B5ULL,
		0x2557CA2814AF61F5ULL,
		0x25FE4D1CFC659124ULL,
		0xB64B3B41DF50C14AULL,
		0x4D61191633989525ULL,
		0x3688275D0C246F0AULL,
		0x884F8A7B20754132ULL,
		0x0A936C8706C20B01ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9B2B0AA76FB7E7E9ULL,
		0x21E2E95362D0AEC2ULL,
		0xCCA269A770B8233BULL,
		0xB8321AB2BACB40DEULL,
		0xF5D32D2CCF765700ULL,
		0x8CCA65CE15924262ULL,
		0xE5728FE2DC09FC9DULL,
		0xD1461E7ADED3F105ULL
	}};
	sign = 0;
	printf("Test Case 13\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 13 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x21AE0E0E7B34D9B6ULL,
		0x7C71373D4F0D0277ULL,
		0x99B5224462C77B18ULL,
		0xCD08D9415A944BACULL,
		0xEA7D0DCBDBD154E1ULL,
		0x2E47D41453CF3B0EULL,
		0xFFB80293DC964993ULL,
		0xF182B25CB215A9A5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CEC95B98B55CC97ULL,
		0x61C8E7720794119DULL,
		0xAC7F94DA996BC0B4ULL,
		0xEBC289026193ED4DULL,
		0xC43E91D9EDAA98CAULL,
		0x3CB983981A702BD0ULL,
		0xB39DEF4CE4394C8FULL,
		0xD51E465130A41C28ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE4C17854EFDF0D1FULL,
		0x1AA84FCB4778F0D9ULL,
		0xED358D69C95BBA64ULL,
		0xE146503EF9005E5EULL,
		0x263E7BF1EE26BC16ULL,
		0xF18E507C395F0F3EULL,
		0x4C1A1346F85CFD03ULL,
		0x1C646C0B81718D7DULL
	}};
	sign = 0;
	printf("Test Case 14\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 14 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x88745517C3688D9FULL,
		0x45B89FF257A69142ULL,
		0xC7A90518DC5C7E66ULL,
		0x4D5FFB36C9B52F72ULL,
		0x1AA7BEAD24B64D88ULL,
		0x9FE538A3FAE4861CULL,
		0xB2061EABD91D46F0ULL,
		0x5CB72CB41C9C7453ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B3FBCE81EEB5569ULL,
		0x8F746AB901433E13ULL,
		0x1D3C48F7144F66CEULL,
		0x44EA9D641952CE9EULL,
		0x78A71ABDAFA4BE70ULL,
		0x032A31F26D622B2BULL,
		0xFEFE2DAD6A77CEFBULL,
		0xB3E211BC26681D5DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4D34982FA47D3836ULL,
		0xB64435395663532FULL,
		0xAA6CBC21C80D1797ULL,
		0x08755DD2B06260D4ULL,
		0xA200A3EF75118F18ULL,
		0x9CBB06B18D825AF0ULL,
		0xB307F0FE6EA577F5ULL,
		0xA8D51AF7F63456F5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 15\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 15 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE2E5AEC505566B08ULL,
		0xC4E42D0C0AEAAF23ULL,
		0x37CC6806F1643EDEULL,
		0x2B11E9ADD8E85E7AULL,
		0x02DEA65C63707361ULL,
		0x5C535BE93FA5C5C3ULL,
		0xB90A74719A275EEBULL,
		0x2FCC616681C064DEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5522AB51D4EF97E1ULL,
		0x2C7CBEE9A4A56884ULL,
		0x46A0ADF1EA5DAE33ULL,
		0xBD3F9D74A2CA71D1ULL,
		0x736CD1350CAF3C8DULL,
		0xE90CCE0F240575AEULL,
		0x518908C27D57CE2FULL,
		0x9BDFC0735E5CB421ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8DC303733066D327ULL,
		0x98676E226645469FULL,
		0xF12BBA15070690ABULL,
		0x6DD24C39361DECA8ULL,
		0x8F71D52756C136D3ULL,
		0x73468DDA1BA05014ULL,
		0x67816BAF1CCF90BBULL,
		0x93ECA0F32363B0BDULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 16\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 16 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x151B63C1E7DD611DULL,
		0x933AA0EE4767794BULL,
		0x5855ED4F4B7774D7ULL,
		0xD1047281F48E0468ULL,
		0x0ED29ADDF874557BULL,
		0x80C775F01ADD3F0EULL,
		0x741305B1C3BF2744ULL,
		0xB99D1DBAABB776ABULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8AD5F8997E953947ULL,
		0x05E183873B5E7E76ULL,
		0x83DD90F32FE1F2B3ULL,
		0x071E847CF64A0EC7ULL,
		0xB1E7414531FD6494ULL,
		0x09CA1333EB789135ULL,
		0xFBFC8EED13C0FC09ULL,
		0xCA02748729024503ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8A456B28694827D6ULL,
		0x8D591D670C08FAD4ULL,
		0xD4785C5C1B958224ULL,
		0xC9E5EE04FE43F5A0ULL,
		0x5CEB5998C676F0E7ULL,
		0x76FD62BC2F64ADD8ULL,
		0x781676C4AFFE2B3BULL,
		0xEF9AA93382B531A7ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 17\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 17 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x3C6F1760BFB733C2ULL,
		0x6EF5C109342578EAULL,
		0xE8027096400D0C4DULL,
		0xC98A6D9F426D6727ULL,
		0x54D3CACFF14E6D6AULL,
		0x4F55FCB0B4D37E4BULL,
		0xF7C182FE82864910ULL,
		0x4A30FA8338059AFEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x48D7D38B0C6B7020ULL,
		0x7C08BA428D09AA43ULL,
		0x370FB964908AAF41ULL,
		0x519AB9244AEF6129ULL,
		0xFD0A07091D22D6E3ULL,
		0x20BC33A95B0F51F2ULL,
		0x440BA316BA371A90ULL,
		0x8570140DA3C9A7C5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF39743D5B34BC3A2ULL,
		0xF2ED06C6A71BCEA6ULL,
		0xB0F2B731AF825D0BULL,
		0x77EFB47AF77E05FEULL,
		0x57C9C3C6D42B9687ULL,
		0x2E99C90759C42C58ULL,
		0xB3B5DFE7C84F2E80ULL,
		0xC4C0E675943BF339ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 18\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 18 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6C34520324128150ULL,
		0x3680259C77EFCFA7ULL,
		0xC86B81716AE757BBULL,
		0xFEF4A3BFA06948F0ULL,
		0xEEFC927AC6739E6DULL,
		0x8DB17F64FFE44808ULL,
		0x99506119388F0159ULL,
		0x2C3B89176B3067B0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE61EE62F054164FULL,
		0x9C288C5A1C6A5E2FULL,
		0x4B490281D3CC0EAAULL,
		0xC787CB8E8B03E904ULL,
		0x1967FC3853007985ULL,
		0xD1CBACEFA03D7E14ULL,
		0xD7E1A9AA8C892D6AULL,
		0x7724B0FB53918AB0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBDD263A033BE6B01ULL,
		0x9A5799425B857177ULL,
		0x7D227EEF971B4910ULL,
		0x376CD83115655FECULL,
		0xD5949642737324E8ULL,
		0xBBE5D2755FA6C9F4ULL,
		0xC16EB76EAC05D3EEULL,
		0xB516D81C179EDCFFULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 19\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 19 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4050D6ED6A7A9F3EULL,
		0x42D064BADA5D3886ULL,
		0xCBDB612E8991DB66ULL,
		0xC56E41FDC0C9418EULL,
		0xD15D4BBF46442026ULL,
		0xAA91C62A1146395EULL,
		0x86C81694D6D3C8E4ULL,
		0xA2B920D5226DF5F7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3DA5781359171A8ULL,
		0x30AA502A0D66D2AAULL,
		0x129E7C6526AD49DFULL,
		0x3194F8B8FE9F9943ULL,
		0xBCFF5ECF8A48FC63ULL,
		0x402ED79FE82BF949ULL,
		0x78D2883959D1F12FULL,
		0x4F9941FE155F9929ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8C767F6C34E92D96ULL,
		0x12261490CCF665DBULL,
		0xB93CE4C962E49187ULL,
		0x93D94944C229A84BULL,
		0x145DECEFBBFB23C3ULL,
		0x6A62EE8A291A4015ULL,
		0x0DF58E5B7D01D7B5ULL,
		0x531FDED70D0E5CCEULL
	}};
	sign = 0;
	printf("Test Case 20\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 20 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x98EF6B272EADF7F0ULL,
		0x892DBCA15028F4EBULL,
		0x1C71077C0C4633B8ULL,
		0xEEC7C8F79932A681ULL,
		0xD8662689488C20DFULL,
		0xD7972E42FD428B8AULL,
		0xC09E17D51A0210FDULL,
		0xFD6F3E23DB2B2E57ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1DA7B024A8E2B58ULL,
		0x92E21E3936BEEFA6ULL,
		0xF862C539A3FABA68ULL,
		0x82814074ABD9A9D3ULL,
		0xDD30028EC50DD1C2ULL,
		0x111F92429A506DC0ULL,
		0x35A232EF005AADEAULL,
		0xB928B5BB7DF2018FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC714F024E41FCC98ULL,
		0xF64B9E68196A0544ULL,
		0x240E4242684B794FULL,
		0x6C468882ED58FCADULL,
		0xFB3623FA837E4F1DULL,
		0xC6779C0062F21DC9ULL,
		0x8AFBE4E619A76313ULL,
		0x444688685D392CC8ULL
	}};
	sign = 0;
	printf("Test Case 21\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 21 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x221148C9321FA864ULL,
		0xD58A2E57F79F28C6ULL,
		0xC6DE25761DF40DF0ULL,
		0xF01323A732224EECULL,
		0xF19005885498AF06ULL,
		0x5D16E20BBE7ABDEEULL,
		0x84B4E5E957EB966DULL,
		0x1B1F909A1ABA4FF2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x95674D430BFC53A2ULL,
		0x11FD4B106216B86EULL,
		0x27944A5B0869E41EULL,
		0x0E714551440D1649ULL,
		0x24D4DE6EFACF0780ULL,
		0x9BB030772C6965BEULL,
		0x8A42BEDB7D98E4E3ULL,
		0xD258849F73C8F66FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8CA9FB86262354C2ULL,
		0xC38CE34795887057ULL,
		0x9F49DB1B158A29D2ULL,
		0xE1A1DE55EE1538A3ULL,
		0xCCBB271959C9A786ULL,
		0xC166B19492115830ULL,
		0xFA72270DDA52B189ULL,
		0x48C70BFAA6F15982ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 22\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 22 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9C18A5869BC1273AULL,
		0x99571511331AC6ABULL,
		0x0BB74C7F5244E53BULL,
		0x4179C8F4463634A9ULL,
		0xAFCC65C4F59A8AA2ULL,
		0x9B895346DA0E6AF1ULL,
		0x90FD7AF4C1D5DB8AULL,
		0x625C540CB073B154ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3BEB0A8D608EBAFULL,
		0x80C5CCED50C4757BULL,
		0x8078E2DE5DD25158ULL,
		0x78644D1974D1D240ULL,
		0x80F16DC905A38E77ULL,
		0x0CE539E5AA78F1EDULL,
		0x347505446C38DB85ULL,
		0x51B34C5E690033B5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE859F4DDC5B83B8BULL,
		0x18914823E256512FULL,
		0x8B3E69A0F47293E3ULL,
		0xC9157BDAD1646268ULL,
		0x2EDAF7FBEFF6FC2AULL,
		0x8EA419612F957904ULL,
		0x5C8875B0559D0005ULL,
		0x10A907AE47737D9FULL
	}};
	sign = 0;
	printf("Test Case 23\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 23 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA4B0BA7D50AE9110ULL,
		0x46C208D92BD9B77EULL,
		0xDE14A853BFF51050ULL,
		0xC99F706AF5EE1F44ULL,
		0x1D126343FD5D0667ULL,
		0x503B6580588DFDBAULL,
		0x6B72CAF36A81926BULL,
		0x64EE394CDC21900CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x14CDAC77264E8CFFULL,
		0x8D1438DF8C027C64ULL,
		0x3F3209DDE96AC483ULL,
		0x5933AB0AC87A022AULL,
		0xEC599B9788D73F68ULL,
		0x3A34184591C21D7DULL,
		0xFB5B7289679529D6ULL,
		0x47CD4127BEC48CB5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8FE30E062A600411ULL,
		0xB9ADCFF99FD73B1AULL,
		0x9EE29E75D68A4BCCULL,
		0x706BC5602D741D1AULL,
		0x30B8C7AC7485C6FFULL,
		0x16074D3AC6CBE03CULL,
		0x7017586A02EC6895ULL,
		0x1D20F8251D5D0356ULL
	}};
	sign = 0;
	printf("Test Case 24\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 24 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD843A660E96127A1ULL,
		0x8EA3BB54FFB5A40AULL,
		0xCE5729981A8A5180ULL,
		0xB7DB35C61C417AA3ULL,
		0x57409B0F8C75C315ULL,
		0xB5EE8B325875606CULL,
		0x002458D7C900DCC9ULL,
		0xEC76F18178924170ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5E6EE8F5AE1E10CULL,
		0xBF4D9543915E41D1ULL,
		0xE0515550588D97EEULL,
		0x8B2EC8D79DFC3207ULL,
		0xAE2EBBC25BC716DFULL,
		0x2CD584D6AB26FBE1ULL,
		0x6B7B3D2D3EBFD5B7ULL,
		0xC5CA89F65F067026ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x325CB7D18E7F4695ULL,
		0xCF5626116E576239ULL,
		0xEE05D447C1FCB991ULL,
		0x2CAC6CEE7E45489BULL,
		0xA911DF4D30AEAC36ULL,
		0x8919065BAD4E648AULL,
		0x94A91BAA8A410712ULL,
		0x26AC678B198BD149ULL
	}};
	sign = 0;
	printf("Test Case 25\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 25 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xAAE653534FEE8E81ULL,
		0xB0F26842732EC99AULL,
		0x33F7FB7798FD8458ULL,
		0x4967DFDF17AC014BULL,
		0xE2D744AAA36730D0ULL,
		0x2BB03523CA011142ULL,
		0x8932411324C90D0FULL,
		0xF3A7100664A4D99DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD009E915EF5204D9ULL,
		0x75C09D7B975F237CULL,
		0xB38EE707352BA55BULL,
		0xA3425123F41FCB45ULL,
		0x35528D853AA8D174ULL,
		0x7A74C539DFF3F2C8ULL,
		0x247306D57FFCDBABULL,
		0x59E070DD2BE233E4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDADC6A3D609C89A8ULL,
		0x3B31CAC6DBCFA61DULL,
		0x8069147063D1DEFDULL,
		0xA6258EBB238C3605ULL,
		0xAD84B72568BE5F5BULL,
		0xB13B6FE9EA0D1E7AULL,
		0x64BF3A3DA4CC3163ULL,
		0x99C69F2938C2A5B9ULL
	}};
	sign = 0;
	printf("Test Case 26\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 26 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x65FEB871E8936861ULL,
		0xE3D5086F6E5F3141ULL,
		0x3BBEF49CDA7AC045ULL,
		0xB2568CE43CB688A7ULL,
		0x7BF5D9A36DDB9A9EULL,
		0x0856BB1C1E3AF918ULL,
		0xC695D6391ADCB8A8ULL,
		0x6AC0D40C8E377E39ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x88840CFBA506F795ULL,
		0x1A0B22B1ABF6D531ULL,
		0x2635A9B001C59817ULL,
		0x94CD94CDB518F856ULL,
		0x014DFF08D8FDEF26ULL,
		0xFE3D338F323509F6ULL,
		0xEA55E11C3C231F30ULL,
		0xEEAD77D4A25899EFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDD7AAB76438C70CCULL,
		0xC9C9E5BDC2685C0FULL,
		0x15894AECD8B5282EULL,
		0x1D88F816879D9051ULL,
		0x7AA7DA9A94DDAB78ULL,
		0x0A19878CEC05EF22ULL,
		0xDC3FF51CDEB99977ULL,
		0x7C135C37EBDEE449ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 27\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 27 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1D4C5488C3BD57C9ULL,
		0x14FAA7D4017A5E67ULL,
		0x6E23063E6F7DCA56ULL,
		0x9537946D3B09237DULL,
		0x536A560B35EAD78EULL,
		0x36E4B5F119F60B8FULL,
		0x24D4C022200190ACULL,
		0xC399E8E3DA1D401BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4710E01520C7046BULL,
		0x37FA8619B93BB211ULL,
		0x7084993A7EFCF0AEULL,
		0x8940DEC1CB55A5E9ULL,
		0x95CEBF0D10DA9224ULL,
		0x1FE1FEA942377FE0ULL,
		0xBAEFED61595C60B5ULL,
		0x894150425819003AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD63B7473A2F6535EULL,
		0xDD0021BA483EAC55ULL,
		0xFD9E6D03F080D9A7ULL,
		0x0BF6B5AB6FB37D93ULL,
		0xBD9B96FE2510456AULL,
		0x1702B747D7BE8BAEULL,
		0x69E4D2C0C6A52FF7ULL,
		0x3A5898A182043FE0ULL
	}};
	sign = 0;
	printf("Test Case 28\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 28 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1ABF0373A6C2FA50ULL,
		0xEEE992CC5E53ED11ULL,
		0xBA21BB37EA0FA0A4ULL,
		0x604BDF4FE2F14791ULL,
		0xEAFF1FCF7DB838D0ULL,
		0xE16C8E30D807B82FULL,
		0x15E573604358A3E2ULL,
		0xAD5018D0E3D8895FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A5D773E1A22D15DULL,
		0xA6C980A551DB864EULL,
		0xCDBC87B97BA6244BULL,
		0xD71849D0D4E9710FULL,
		0xDC3E6EF66663E77BULL,
		0x5B7050BFA135CADCULL,
		0xFC85BB4F5582ABB4ULL,
		0xC41B82AF97FF316FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD0618C358CA028F3ULL,
		0x482012270C7866C2ULL,
		0xEC65337E6E697C59ULL,
		0x8933957F0E07D681ULL,
		0x0EC0B0D917545154ULL,
		0x85FC3D7136D1ED53ULL,
		0x195FB810EDD5F82EULL,
		0xE93496214BD957EFULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 29\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 29 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF45A819119B4EEAFULL,
		0xB11E7B8AE2B1FE23ULL,
		0xA62942E3402146EFULL,
		0xA1533C2F34AC3D0BULL,
		0x5AA2FA5F49BAF07AULL,
		0x76D70FA1616081E9ULL,
		0xA89DF3106FE3A489ULL,
		0x6781211D508F5452ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE20DCB10C9B3F210ULL,
		0xAF2B8C21A7272D9EULL,
		0x47F5647526EE07C6ULL,
		0x5F63A6757B45134AULL,
		0x635AE58CC2B6713CULL,
		0x652172E2163BC85BULL,
		0xCEC97C090787B1BEULL,
		0x1CD4FD0CA8DD705EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x124CB6805000FC9FULL,
		0x01F2EF693B8AD085ULL,
		0x5E33DE6E19333F29ULL,
		0x41EF95B9B96729C1ULL,
		0xF74814D287047F3EULL,
		0x11B59CBF4B24B98DULL,
		0xD9D47707685BF2CBULL,
		0x4AAC2410A7B1E3F3ULL
	}};
	sign = 0;
	printf("Test Case 30\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 30 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA4723C961007525BULL,
		0x72CB42CF3EED9E84ULL,
		0x85E8DD81C1179ACFULL,
		0x7011862BF49590DDULL,
		0xF34B202BFF32021EULL,
		0x4D6083430554AFEAULL,
		0x289A0027DCB859F7ULL,
		0xEAB231C97C5AC008ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x74AAD57D26EB5DDBULL,
		0x42F4638E34E30DB9ULL,
		0xBADC0880CC0D20FAULL,
		0x405403E9E984162CULL,
		0x2FBF30683F29F5C8ULL,
		0x31E87F050F3553DDULL,
		0x6F6B1A83A12A9F40ULL,
		0xC4159128E184CEEAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2FC76718E91BF480ULL,
		0x2FD6DF410A0A90CBULL,
		0xCB0CD500F50A79D5ULL,
		0x2FBD82420B117AB0ULL,
		0xC38BEFC3C0080C56ULL,
		0x1B78043DF61F5C0DULL,
		0xB92EE5A43B8DBAB7ULL,
		0x269CA0A09AD5F11DULL
	}};
	sign = 0;
	printf("Test Case 31\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 31 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xDE1E07B3FBB45FBAULL,
		0x1195D23875221487ULL,
		0xF2EF0C2248D1B805ULL,
		0x193EDA9BDFF72C3DULL,
		0xD87AC7EE5A8164E0ULL,
		0xEF365B8DD12E0EDCULL,
		0x6EF818CE6A74CC02ULL,
		0xEA1325F8774F87C5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x93CBFC432862046AULL,
		0x7FDEAE86156E93DDULL,
		0x44316F1D2C024589ULL,
		0xA70E12753BA6FEC5ULL,
		0x9D12FBF5FD3D8D85ULL,
		0xAC4C9E558C48CA31ULL,
		0x269C62BEAB56D34AULL,
		0xBBFB9FF6A07E24C7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4A520B70D3525B50ULL,
		0x91B723B25FB380AAULL,
		0xAEBD9D051CCF727BULL,
		0x7230C826A4502D78ULL,
		0x3B67CBF85D43D75AULL,
		0x42E9BD3844E544ABULL,
		0x485BB60FBF1DF8B8ULL,
		0x2E178601D6D162FEULL
	}};
	sign = 0;
	printf("Test Case 32\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 32 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x2B2B3F8B9410ACCFULL,
		0x967C97F2FBC41A8BULL,
		0xC5CBBAECB5D94E6DULL,
		0xC2EC5BB49FA42977ULL,
		0x89F4301C890C416EULL,
		0xAA892AB5BADB3EC6ULL,
		0x88CE08E93752BDFFULL,
		0x9FA8E9E3F53B9D50ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC88C305EAE3B6DCULL,
		0x1E1E14572C124EF2ULL,
		0xCD1F7B28A4548B1FULL,
		0x12CE38E84C26C6C3ULL,
		0xBE5F136BCF22E3CFULL,
		0x9A0CEB8682FAF7CFULL,
		0xE5D176D0AA99C989ULL,
		0x7E243C7C3C8D4BD0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5EA27C85A92CF5F3ULL,
		0x785E839BCFB1CB98ULL,
		0xF8AC3FC41184C34EULL,
		0xB01E22CC537D62B3ULL,
		0xCB951CB0B9E95D9FULL,
		0x107C3F2F37E046F6ULL,
		0xA2FC92188CB8F476ULL,
		0x2184AD67B8AE517FULL
	}};
	sign = 0;
	printf("Test Case 33\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 33 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE62C14ABC0C88773ULL,
		0x31EF94C984367828ULL,
		0x9DA94A2197420A7CULL,
		0xAEA031EAB4E038DBULL,
		0xC185F04DF2E37669ULL,
		0xB7FF5697BF55647FULL,
		0xFBEF3D64866B4FD1ULL,
		0x34C449851D0CC241ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x33241BE8D2687D4AULL,
		0x1BB9558B5C03BBF2ULL,
		0xAA733E1F41BB4D04ULL,
		0xD027877D02913DAEULL,
		0xC069B0181B52AEA2ULL,
		0x390E62C1E279524DULL,
		0xCD6E529A108EEAEDULL,
		0xD7354D15D3573410ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB307F8C2EE600A29ULL,
		0x16363F3E2832BC36ULL,
		0xF3360C025586BD78ULL,
		0xDE78AA6DB24EFB2CULL,
		0x011C4035D790C7C6ULL,
		0x7EF0F3D5DCDC1232ULL,
		0x2E80EACA75DC64E4ULL,
		0x5D8EFC6F49B58E31ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 34\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 34 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4BBCD93E86A4DFBAULL,
		0x03B8562FC30C010EULL,
		0x6B86C574B4F4353AULL,
		0x48ABCD2FAE68DADFULL,
		0xDF6C3E9D7B5A7163ULL,
		0xB7BFD1E1B92ECBF7ULL,
		0x3C34CC15C146AA40ULL,
		0xDFB27A675896E1CFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x73EE78EB3514C725ULL,
		0x6783C0704D633D4EULL,
		0x925D9CE8155C4E75ULL,
		0x337B9B516BCDCDA9ULL,
		0xF96A91BA4FBC0808ULL,
		0xF784DA0B3BDE4958ULL,
		0x51BE70D558858D86ULL,
		0xF7FFAEF05038DD55ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD7CE605351901895ULL,
		0x9C3495BF75A8C3BFULL,
		0xD929288C9F97E6C4ULL,
		0x153031DE429B0D35ULL,
		0xE601ACE32B9E695BULL,
		0xC03AF7D67D50829EULL,
		0xEA765B4068C11CB9ULL,
		0xE7B2CB77085E0479ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 35\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 35 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xEC7AC4B49CC89FA4ULL,
		0x14FD358DFA226BE1ULL,
		0x9E635C257DD970C6ULL,
		0x56AB79DEC615B867ULL,
		0x431F0D34C0436F91ULL,
		0x1370421640FCBC44ULL,
		0xD874846851019760ULL,
		0x554BE7DAB70A49EBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2412FD2D9591E1FEULL,
		0x4DDEA26E606D618FULL,
		0xCA46CCCC0709CD46ULL,
		0xA1C77EE0FDF45043ULL,
		0x74A9898348F04757ULL,
		0xF15C01A1125C5768ULL,
		0x50AA9C510F070E6BULL,
		0x872FE1A7F593B7A9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC867C7870736BDA6ULL,
		0xC71E931F99B50A52ULL,
		0xD41C8F5976CFA37FULL,
		0xB4E3FAFDC8216823ULL,
		0xCE7583B177532839ULL,
		0x221440752EA064DBULL,
		0x87C9E81741FA88F4ULL,
		0xCE1C0632C1769242ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 36\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 36 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6B7FEB16BCDC4F4FULL,
		0x12B9B540F5398711ULL,
		0x6B09B0A7520AA44EULL,
		0x0DA5F93B045558C5ULL,
		0xE55A0443574D8524ULL,
		0xD24CB6BB592E7AD0ULL,
		0x482BDCDA46AF749CULL,
		0x31E314DEF988FBFCULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xABED88BBD1E388FBULL,
		0x1A698C08B86B03F4ULL,
		0x7E34CD04D5EBC622ULL,
		0xFACD741299CE266FULL,
		0x4EE9CA5E534AD267ULL,
		0x11DCE837247DE309ULL,
		0x10741E77A6D94AEBULL,
		0x52F984B55C5A297BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBF92625AEAF8C654ULL,
		0xF85029383CCE831CULL,
		0xECD4E3A27C1EDE2BULL,
		0x12D885286A873255ULL,
		0x967039E50402B2BCULL,
		0xC06FCE8434B097C7ULL,
		0x37B7BE629FD629B1ULL,
		0xDEE990299D2ED281ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 37\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 37 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x8D6BDDF3DE67F57DULL,
		0xB1B84745C4F0C9A5ULL,
		0x647E5569A434EF14ULL,
		0x6A56900AC373BDC9ULL,
		0x9409926B3FBFDFF1ULL,
		0x542342DDD834D061ULL,
		0x1958D7FB9BE3E60BULL,
		0x3B81E45ABBCCD000ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x338FFA9A554CAF1CULL,
		0xB7429FB0436AD7E8ULL,
		0x71BF941BA76740FBULL,
		0x4EB28BED6BE4274BULL,
		0x1BD59849AFA9087FULL,
		0xF23FC8F92A096233ULL,
		0x7225FA6E4E1E7AE6ULL,
		0xCE4685361CDE444DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x59DBE359891B4661ULL,
		0xFA75A7958185F1BDULL,
		0xF2BEC14DFCCDAE18ULL,
		0x1BA4041D578F967DULL,
		0x7833FA219016D772ULL,
		0x61E379E4AE2B6E2EULL,
		0xA732DD8D4DC56B24ULL,
		0x6D3B5F249EEE8BB2ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 38\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 38 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x34A16F30051F9E63ULL,
		0xBBD3B38615B871A2ULL,
		0x9920BB6565E695A4ULL,
		0xD05AD9C5E7BD2B45ULL,
		0xE7327888C46111B8ULL,
		0x28503A39335C190DULL,
		0x8B5E1723EAEC11E2ULL,
		0xBBD9D2B90255AF85ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4E0C12F6D53B251ULL,
		0xE9475D6BFEB5CE1FULL,
		0x882761518D82263DULL,
		0xDAD2F86F0688A100ULL,
		0x724146B2212A64E6ULL,
		0x77EA05983A0DE2F2ULL,
		0x3E4D41069EA87C41ULL,
		0xF7BD4B167346116AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7FC0AE0097CBEC12ULL,
		0xD28C561A1702A382ULL,
		0x10F95A13D8646F66ULL,
		0xF587E156E1348A45ULL,
		0x74F131D6A336ACD1ULL,
		0xB06634A0F94E361BULL,
		0x4D10D61D4C4395A0ULL,
		0xC41C87A28F0F9E1BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 39\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 39 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA386C5492429F721ULL,
		0x9C5B13E748A35869ULL,
		0x2F8510A026863001ULL,
		0xADEB3B59CAA3EFEBULL,
		0xEBCE70452A1045E2ULL,
		0x0688E5E2B9E196F4ULL,
		0x299BC9A9662C61ACULL,
		0x336A761C5A59BB8DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD937FE632126C11DULL,
		0x9AF76F84446C28E7ULL,
		0x7D020B902227B5D7ULL,
		0xAEB07891301B62BCULL,
		0x7753A6F360987C01ULL,
		0x37293EFA777930DFULL,
		0xC35FBBE1177B8312ULL,
		0x40AF6670E0A0FCD8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCA4EC6E603033604ULL,
		0x0163A46304372F81ULL,
		0xB2830510045E7A2AULL,
		0xFF3AC2C89A888D2EULL,
		0x747AC951C977C9E0ULL,
		0xCF5FA6E842686615ULL,
		0x663C0DC84EB0DE99ULL,
		0xF2BB0FAB79B8BEB4ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 40\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 40 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x87E5E10722AB3DB4ULL,
		0x13E0DF7278F720C8ULL,
		0xA5EBD88DC920DFF1ULL,
		0xBEDCF01BCC15FB94ULL,
		0x96D740FCBBD6FC96ULL,
		0xEECE8FD5D909130BULL,
		0x8A427A839E286CECULL,
		0x0EA4A75328FAB5A7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FC4FD6A4D7154ECULL,
		0x1DB14ABA3F9E2B89ULL,
		0xDF8BA3222374D095ULL,
		0x9E42FAA3ECCD7A0EULL,
		0xBF9F929C668068D5ULL,
		0x6EF5E2890C559B46ULL,
		0xA924E47D71AD1A42ULL,
		0x7B7DADFF84AB668FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4820E39CD539E8C8ULL,
		0xF62F94B83958F53FULL,
		0xC660356BA5AC0F5BULL,
		0x2099F577DF488185ULL,
		0xD737AE60555693C1ULL,
		0x7FD8AD4CCCB377C4ULL,
		0xE11D96062C7B52AAULL,
		0x9326F953A44F4F17ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 41\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 41 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF09C74570C03D24CULL,
		0x3236D5D5081771E3ULL,
		0x4F42F138C2846266ULL,
		0x4BDA2FE1272E3865ULL,
		0x5BE0ACA69188E49AULL,
		0x521A92F81417D58DULL,
		0x9CDDB285FA209C62ULL,
		0x65D6730147AB95A0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDB89CF29AB751BCULL,
		0xA07EF22A5E0747E1ULL,
		0x41F165F8B4D3CAEDULL,
		0x6597ADECEFEAF3F6ULL,
		0x248B3988B96349B5ULL,
		0x9E0194582E019A94ULL,
		0x1945DF5A68660A5CULL,
		0xE1AAE59B93D4E192ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x12E3D764714C8090ULL,
		0x91B7E3AAAA102A02ULL,
		0x0D518B400DB09778ULL,
		0xE64281F43743446FULL,
		0x3755731DD8259AE4ULL,
		0xB418FE9FE6163AF9ULL,
		0x8397D32B91BA9205ULL,
		0x842B8D65B3D6B40EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 42\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 42 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA6955592049A1A7FULL,
		0x8F2F64025E0D92ABULL,
		0xA975C58EF646935BULL,
		0xDDFFFA80B548A129ULL,
		0xC4D07CE6A32CA8CCULL,
		0xB10713456B790B8DULL,
		0x7BCC2E7BF8AC46FDULL,
		0xE135407916E036A2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x346B02BE58874CF5ULL,
		0x27401BDCB0277F3CULL,
		0x0447445AF34FF291ULL,
		0x41A10C74810FC455ULL,
		0x02330B77E2910073ULL,
		0x1B65525E1AAC5C34ULL,
		0x106DC56684F1F442ULL,
		0xDE16F4D0D4F62530ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x722A52D3AC12CD8AULL,
		0x67EF4825ADE6136FULL,
		0xA52E813402F6A0CAULL,
		0x9C5EEE0C3438DCD4ULL,
		0xC29D716EC09BA859ULL,
		0x95A1C0E750CCAF59ULL,
		0x6B5E691573BA52BBULL,
		0x031E4BA841EA1172ULL
	}};
	sign = 0;
	printf("Test Case 43\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 43 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB0960513A8E727E0ULL,
		0xDEFF3CEBB4DB8417ULL,
		0x731E66CB0CED00F3ULL,
		0x51618A336754F251ULL,
		0xC8B8C371E9BA9542ULL,
		0x1144F536F010287BULL,
		0xC1F2992C6AAF6118ULL,
		0xDC398085EA8F25E1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x048685C50439CEAFULL,
		0x6A76C50FAC2DC2D3ULL,
		0x0935DDBAA5CAF23DULL,
		0x657ECF4A100A0E88ULL,
		0x36F08AD8DBDBB6D0ULL,
		0x054F65ABF2821565ULL,
		0x1F344238879CE1ECULL,
		0x71ACE9EC8EFF5AF8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAC0F7F4EA4AD5931ULL,
		0x748877DC08ADC144ULL,
		0x69E8891067220EB6ULL,
		0xEBE2BAE9574AE3C9ULL,
		0x91C838990DDEDE71ULL,
		0x0BF58F8AFD8E1316ULL,
		0xA2BE56F3E3127F2CULL,
		0x6A8C96995B8FCAE9ULL
	}};
	sign = 0;
	printf("Test Case 44\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 44 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xAB1447EBFF423BC1ULL,
		0x0820514A79D6A27FULL,
		0xCC954849D8502F1FULL,
		0xE589A3A5D70FFBAFULL,
		0xE6589417854EC008ULL,
		0x89C9CE29D6762033ULL,
		0xD04EB84CFDC79268ULL,
		0x01F2D2B281CADFACULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7680488C7567144ULL,
		0xC84360AC54B21560ULL,
		0xA71311EFD0BC5913ULL,
		0x1BD116DBD9ADD601ULL,
		0x4403189AF78CFB11ULL,
		0xAED0A77F579616CAULL,
		0x23C9F850D61E3A1DULL,
		0xFDBBFD802290A62CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE3AC436337EBCA7DULL,
		0x3FDCF09E25248D1EULL,
		0x2582365A0793D60BULL,
		0xC9B88CC9FD6225AEULL,
		0xA2557B7C8DC1C4F7ULL,
		0xDAF926AA7EE00969ULL,
		0xAC84BFFC27A9584AULL,
		0x0436D5325F3A3980ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 45\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 45 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6D0606E7694677FDULL,
		0x96344AE1A5D6FF17ULL,
		0x3A4791FCC1E54E93ULL,
		0x96FDB30D9984DB2AULL,
		0x566E7DE2F79A21AAULL,
		0x8C3DA1CC63FC24B7ULL,
		0xDE227BDC99A1B088ULL,
		0x3AB368DEA40EF675ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F1AC9743DDFFECDULL,
		0x6D2508A846475113ULL,
		0x6AA11D16FDD1929AULL,
		0x52F7A914E5D03236ULL,
		0x0652FBFDE5371973ULL,
		0x0DA4C043DBD411A3ULL,
		0x5BB13947459108C1ULL,
		0x00A401A8281A8D73ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1DEB3D732B667930ULL,
		0x290F42395F8FAE04ULL,
		0xCFA674E5C413BBF9ULL,
		0x440609F8B3B4A8F3ULL,
		0x501B81E512630837ULL,
		0x7E98E18888281314ULL,
		0x827142955410A7C7ULL,
		0x3A0F67367BF46902ULL
	}};
	sign = 0;
	printf("Test Case 46\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 46 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xAFA9FDFEED795626ULL,
		0xFCA014B08EFB3ED7ULL,
		0xE01B5CCF463ED430ULL,
		0xD34150F576688C14ULL,
		0x017AF62936D248D1ULL,
		0xF385F79B6A6859F0ULL,
		0x5DF18B0C29FEED4DULL,
		0xFAABBC9EAE995419ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4FD5231A7D6425EULL,
		0x181FB29EF8C72D02ULL,
		0x191031EE9DD90C03ULL,
		0xDBC20E9D39CCD7DAULL,
		0xAA89EB28B69CD916ULL,
		0xA48BA85326E816A3ULL,
		0x2AC56CB73DC16055ULL,
		0x5CDE035647C6EF83ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0AACABCD45A313C8ULL,
		0xE4806211963411D5ULL,
		0xC70B2AE0A865C82DULL,
		0xF77F42583C9BB43AULL,
		0x56F10B0080356FBAULL,
		0x4EFA4F484380434CULL,
		0x332C1E54EC3D8CF8ULL,
		0x9DCDB94866D26496ULL
	}};
	sign = 0;
	printf("Test Case 47\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 47 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x76CA22AD44C3B6AEULL,
		0xCF64C046B29946CEULL,
		0x51E7795BA74C1A29ULL,
		0x2D3E7C36CA569317ULL,
		0xDE8D31C4B6E38CF0ULL,
		0x0010D196AE95A9A8ULL,
		0xB4088E55F364CCFDULL,
		0xB5C177E618ADDA8DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9840658B413F6AFBULL,
		0xFE859CC24AB73F6CULL,
		0x587231ED959150E0ULL,
		0xD84A454CC431EA34ULL,
		0xB9BA748DA3EFA7CAULL,
		0xC59681C3788CA0E5ULL,
		0x282E57853D612D6FULL,
		0x50212C8BD264B56FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDE89BD2203844BB3ULL,
		0xD0DF238467E20761ULL,
		0xF975476E11BAC948ULL,
		0x54F436EA0624A8E2ULL,
		0x24D2BD3712F3E525ULL,
		0x3A7A4FD3360908C3ULL,
		0x8BDA36D0B6039F8DULL,
		0x65A04B5A4649251EULL
	}};
	sign = 0;
	printf("Test Case 48\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 48 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC37D672F4EA5F240ULL,
		0x6D2AFFD7EBF9EDDCULL,
		0x2466F5A57B88EC30ULL,
		0x646FAC6D3C723886ULL,
		0x7CA8DB8C76745A80ULL,
		0x2AD6A02768223CEEULL,
		0x985458D52FCB6A1BULL,
		0xF2B8DAA58F9F340DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3AA5A276F3BD1FFULL,
		0xB6D6E817D1E024AAULL,
		0x0F5143A47AA678C1ULL,
		0x88B3B1FFEF035708ULL,
		0xFC54F78197E8EE8CULL,
		0x87BB30B235E6E0B3ULL,
		0x635DC0F2C0AA81DBULL,
		0x510AF9390171E7F3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCFD30D07DF6A2041ULL,
		0xB65417C01A19C931ULL,
		0x1515B20100E2736EULL,
		0xDBBBFA6D4D6EE17EULL,
		0x8053E40ADE8B6BF3ULL,
		0xA31B6F75323B5C3AULL,
		0x34F697E26F20E83FULL,
		0xA1ADE16C8E2D4C1AULL
	}};
	sign = 0;
	printf("Test Case 49\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 49 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7505BA84831F44C5ULL,
		0xB6EDD9D543F74639ULL,
		0x00C94717BB4F8820ULL,
		0xF4A9F768B3802FF6ULL,
		0x2D5DE1CF3A26CB77ULL,
		0xDA8D8E02C10520EBULL,
		0x8E8272CE91CA82BDULL,
		0xE87BFD650ED4B8A4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DE3893D0E0D594EULL,
		0xA5DE86666A402593ULL,
		0x7F73E615E6C954ABULL,
		0x3D28AB61DF33C117ULL,
		0x8AE29C31B54CFA24ULL,
		0xF66CF32936657D48ULL,
		0x827E500F95EC0BC0ULL,
		0x5904514FC5A7191CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF72231477511EB77ULL,
		0x110F536ED9B720A5ULL,
		0x81556101D4863375ULL,
		0xB7814C06D44C6EDEULL,
		0xA27B459D84D9D153ULL,
		0xE4209AD98A9FA3A2ULL,
		0x0C0422BEFBDE76FCULL,
		0x8F77AC15492D9F88ULL
	}};
	sign = 0;
	printf("Test Case 50\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 50 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF0B0796833DF9C61ULL,
		0xB2C5F4D454288306ULL,
		0xC102BE0772A50B44ULL,
		0x309C272714E87A90ULL,
		0xF5D27AF822BD7BE9ULL,
		0x94CF911AE8D0E020ULL,
		0x0A8A6D5882912517ULL,
		0xDAAFDD3A43E0CD80ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x566A8AB62370B496ULL,
		0x83F8C34E3649B13EULL,
		0x57F3D48D8DC2EED1ULL,
		0x1E9A75C9AC6EAFE3ULL,
		0xD8EDF1739184FF6EULL,
		0xC42B0AEA037DF6EAULL,
		0x5BC2F7BE45171ED0ULL,
		0xCA63E92AE0565B1AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9A45EEB2106EE7CBULL,
		0x2ECD31861DDED1C8ULL,
		0x690EE979E4E21C73ULL,
		0x1201B15D6879CAADULL,
		0x1CE4898491387C7BULL,
		0xD0A48630E552E936ULL,
		0xAEC7759A3D7A0646ULL,
		0x104BF40F638A7265ULL
	}};
	sign = 0;
	printf("Test Case 51\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 51 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -51;
	} else {
		printf("Test Case 51 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x059912E24347B53CULL,
		0x1766F3857BFFCF80ULL,
		0xFCB4F2315002E266ULL,
		0x0C0926A5E7581ACFULL,
		0x42D617C13F15C3F8ULL,
		0x293AD21A78595ABBULL,
		0x7560EFD34810EE49ULL,
		0x35126131130BA554ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x12FB20949BD49503ULL,
		0xF0FEA9E318FDB487ULL,
		0xC81710867BCD5EA7ULL,
		0xD2ACD40838E1DD8AULL,
		0x26D3A8AFBAF127E7ULL,
		0xB5D59B52F0575CB8ULL,
		0x64E6CF993B05F3FFULL,
		0xF8C4EE99F326F746ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF29DF24DA7732039ULL,
		0x266849A263021AF8ULL,
		0x349DE1AAD43583BEULL,
		0x395C529DAE763D45ULL,
		0x1C026F1184249C10ULL,
		0x736536C78801FE03ULL,
		0x107A203A0D0AFA49ULL,
		0x3C4D72971FE4AE0EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 52\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 52 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -52;
	} else {
		printf("Test Case 52 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x66EB3D0065736D64ULL,
		0x9D93CE04379767AAULL,
		0x17921CAA124284C1ULL,
		0xCE0AD1E2B21ABC4EULL,
		0x3055E6A69E40CECAULL,
		0x612849186DD08A04ULL,
		0xF2CEBE42E93A49ACULL,
		0x09FDBF7FC20AFEFBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD296AE013BA1C965ULL,
		0xA65273B1580545E3ULL,
		0x4EC0D44AF3842036ULL,
		0x9F163B034BA8C9E3ULL,
		0xF38F2FBD9C52C9BCULL,
		0x9E5755072A9A52BBULL,
		0x622A1DDD25D7E25AULL,
		0x6B1486C142E3DCC8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x94548EFF29D1A3FFULL,
		0xF7415A52DF9221C6ULL,
		0xC8D1485F1EBE648AULL,
		0x2EF496DF6671F26AULL,
		0x3CC6B6E901EE050EULL,
		0xC2D0F41143363748ULL,
		0x90A4A065C3626751ULL,
		0x9EE938BE7F272233ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 53\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 53 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -53;
	} else {
		printf("Test Case 53 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x53C5797DDDACAE59ULL,
		0x49E95C7E8DEE2741ULL,
		0x5B6E00FEC6E7B865ULL,
		0x9E78AB9AF31E93E5ULL,
		0x922214AF28D07B35ULL,
		0xB9562DD7812452ADULL,
		0x34F50A3C2AE24926ULL,
		0x76CAA1495931555AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB3E18D62EAE733AULL,
		0xD168A77BB74F94C7ULL,
		0xCFDA29274F3E9702ULL,
		0x9FCB761DCDE90921ULL,
		0x31491F6C08ED60B2ULL,
		0xBC1667B563790A7DULL,
		0x94F4EC1882AFC4ADULL,
		0x83E6E7A5D13F0672ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x988760A7AEFE3B1FULL,
		0x7880B502D69E9279ULL,
		0x8B93D7D777A92162ULL,
		0xFEAD357D25358AC3ULL,
		0x60D8F5431FE31A82ULL,
		0xFD3FC6221DAB4830ULL,
		0xA0001E23A8328478ULL,
		0xF2E3B9A387F24EE7ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 54\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 54 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -54;
	} else {
		printf("Test Case 54 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xBEB0435564399C49ULL,
		0x2E37C1024E998F0FULL,
		0x539C14EBD0043FA8ULL,
		0x0066B299098FAEB2ULL,
		0x1DDF19ABF257AB0EULL,
		0xD075C40FCA2B9BCFULL,
		0xBEEFBDDB4221DD7BULL,
		0x88C87E94CB1E4B12ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x22A353B3466070D3ULL,
		0x3E6A7BBFF6CBD3FDULL,
		0xD3E7A54929CEB976ULL,
		0x820ABA8678D0C324ULL,
		0xC9AE56E77F843F60ULL,
		0xE9473CF0C892529FULL,
		0x401661DE42BD2E36ULL,
		0x0E72322F72B3754EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9C0CEFA21DD92B76ULL,
		0xEFCD454257CDBB12ULL,
		0x7FB46FA2A6358631ULL,
		0x7E5BF81290BEEB8DULL,
		0x5430C2C472D36BADULL,
		0xE72E871F0199492FULL,
		0x7ED95BFCFF64AF44ULL,
		0x7A564C65586AD5C4ULL
	}};
	sign = 0;
	printf("Test Case 55\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 55 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -55;
	} else {
		printf("Test Case 55 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA2E2A5CD9918FCD5ULL,
		0x8A2A0421CC723753ULL,
		0xF85C932A5D6EDF8CULL,
		0xB6B88D09D6E2AB64ULL,
		0xB3B6BA01CD3A0DE6ULL,
		0xC60598C9822123CCULL,
		0xB0F70BB49A0B9AD9ULL,
		0x892EBAD7F1F86FDAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x377CF2DA63E41BD4ULL,
		0x29307C5236229FBDULL,
		0x5173092F8315AA7AULL,
		0xA2D24E2E5EEDEEF9ULL,
		0x34FD86333CFCE1CCULL,
		0x31EDCD1FCB223D46ULL,
		0x96F01A70D1C72F8DULL,
		0xA3914794602679CFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6B65B2F33534E101ULL,
		0x60F987CF964F9796ULL,
		0xA6E989FADA593512ULL,
		0x13E63EDB77F4BC6BULL,
		0x7EB933CE903D2C1AULL,
		0x9417CBA9B6FEE686ULL,
		0x1A06F143C8446B4CULL,
		0xE59D734391D1F60BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 56\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 56 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -56;
	} else {
		printf("Test Case 56 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0728DC5B5B14DA89ULL,
		0xB0C930D563FFC104ULL,
		0xE50ABFC1880FECC2ULL,
		0x3EE012185BB14F92ULL,
		0x6DC9E8EFA6292E14ULL,
		0x0C4F02033E7DA3FDULL,
		0xC724D25C3C2DF026ULL,
		0x217876E3628148C4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x74B2DE3196AD83D1ULL,
		0x34ACC5E38CEDB915ULL,
		0xC2D17934C10B9DBCULL,
		0x6FEB9B6C5332FB52ULL,
		0xA510B5A968D09540ULL,
		0x1AFEF838BB847460ULL,
		0x3BD51D9DCFC879A4ULL,
		0x90A6B33C67E20E97ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9275FE29C46756B8ULL,
		0x7C1C6AF1D71207EEULL,
		0x2239468CC7044F06ULL,
		0xCEF476AC087E5440ULL,
		0xC8B933463D5898D3ULL,
		0xF15009CA82F92F9CULL,
		0x8B4FB4BE6C657681ULL,
		0x90D1C3A6FA9F3A2DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 57\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 57 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -57;
	} else {
		printf("Test Case 57 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB879FC3BF58A5FC7ULL,
		0x4EB67F2AEC92E853ULL,
		0xB53B1C52785F5720ULL,
		0x5D5CD430DE2E938EULL,
		0x344D1FE8B1609508ULL,
		0x353032FA1876CAA6ULL,
		0xF2F44EDD4B99BFD9ULL,
		0x9C22716040B223DFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6822EF70FCED905ULL,
		0x9E0CC8E738A07780ULL,
		0x6978D26E3EC9B748ULL,
		0xE1CA4D839A0BE71BULL,
		0x9BBCDC7ADCFB87EDULL,
		0xAF734476D7AB76D3ULL,
		0x78797BA3F8FF9E8DULL,
		0xF492523AE73B1880ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01F7CD44E5BB86C2ULL,
		0xB0A9B643B3F270D3ULL,
		0x4BC249E439959FD7ULL,
		0x7B9286AD4422AC73ULL,
		0x9890436DD4650D1AULL,
		0x85BCEE8340CB53D2ULL,
		0x7A7AD339529A214BULL,
		0xA7901F2559770B5FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 58\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 58 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -58;
	} else {
		printf("Test Case 58 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xCED711AAB44A4ADEULL,
		0x548C12696883EBC6ULL,
		0x1A747A7AFB1ED8EFULL,
		0x8C3CCA3FA4D1ACC5ULL,
		0xA878C37F44CE79BEULL,
		0x60A474686C362A1BULL,
		0xA01426B589CF870DULL,
		0x846E0A8356D86ADEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAED81F40CF21DF97ULL,
		0xF42DFA2DC1040F45ULL,
		0x864E0D4AAF2BF200ULL,
		0x2F01E0EE74D32839ULL,
		0x5495EE989188DB73ULL,
		0x93A43861C3D0B277ULL,
		0x1B92014D19CF174FULL,
		0xEBBE233287144E48ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1FFEF269E5286B47ULL,
		0x605E183BA77FDC81ULL,
		0x94266D304BF2E6EEULL,
		0x5D3AE9512FFE848BULL,
		0x53E2D4E6B3459E4BULL,
		0xCD003C06A86577A4ULL,
		0x8482256870006FBDULL,
		0x98AFE750CFC41C96ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 59\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 59 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -59;
	} else {
		printf("Test Case 59 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xCAB84D96A119C638ULL,
		0xAB1800982EAEC696ULL,
		0x657CE8CDFA41F10BULL,
		0x80D06EFF03597821ULL,
		0x4823A1496F576381ULL,
		0x9E6C3CA73D9A389EULL,
		0x2B1B1087A3154A6DULL,
		0xD3A29805AD2420BFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x38DE4274E9716552ULL,
		0x4DB83B364CD8763AULL,
		0x868647024E21F95EULL,
		0xA78764C7F4A0B492ULL,
		0x3AA3E20CA12B2D54ULL,
		0x108243F2010F8A7FULL,
		0x1469468B4DF7DDA3ULL,
		0xF343182773CED5D5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x91DA0B21B7A860E6ULL,
		0x5D5FC561E1D6505CULL,
		0xDEF6A1CBAC1FF7ADULL,
		0xD9490A370EB8C38EULL,
		0x0D7FBF3CCE2C362CULL,
		0x8DE9F8B53C8AAE1FULL,
		0x16B1C9FC551D6CCAULL,
		0xE05F7FDE39554AEAULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 60\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 60 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -60;
	} else {
		printf("Test Case 60 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5DEDD0BC5F0BBA51ULL,
		0x0724E4DF4EAB5CC5ULL,
		0x5985DF851E0F4526ULL,
		0x393517225BB18FF8ULL,
		0x57DD9775E5578D0DULL,
		0x2E8904BE83351D53ULL,
		0x63C8808428188572ULL,
		0x1752FFECC557760EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x824C76BFAC3AC17EULL,
		0x449D5115ACF87A20ULL,
		0xA4B63427CB174DA8ULL,
		0xF261316071CD2150ULL,
		0xBFFD08A9F64D6FEDULL,
		0x183AD83BBD2B201AULL,
		0x8F44E3D7DA7383FBULL,
		0x88EFCCBCCE6A5310ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDBA159FCB2D0F8D3ULL,
		0xC28793C9A1B2E2A4ULL,
		0xB4CFAB5D52F7F77DULL,
		0x46D3E5C1E9E46EA7ULL,
		0x97E08ECBEF0A1D1FULL,
		0x164E2C82C609FD38ULL,
		0xD4839CAC4DA50177ULL,
		0x8E63332FF6ED22FDULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 61\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 61 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -61;
	} else {
		printf("Test Case 61 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA3ACAAE60237F966ULL,
		0xF35BCB7469E94835ULL,
		0xBFD7D65AE0698F21ULL,
		0x81931432427C0014ULL,
		0x7EAA3EF160B67DBDULL,
		0x99FD888604E5CB1CULL,
		0x68A8A81C8C8864F2ULL,
		0xAEF29FA373A10B0BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC038C34F77E21C43ULL,
		0x420EC36425EFA679ULL,
		0x8C8E62D8804FD821ULL,
		0x85BE26E0EB4AF5C8ULL,
		0xF3301DB5F47E2B8FULL,
		0xC1BD19058E95B26AULL,
		0xC439D9F1787842D6ULL,
		0x2659AF65BD5D4DA5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE373E7968A55DD23ULL,
		0xB14D081043F9A1BBULL,
		0x334973826019B700ULL,
		0xFBD4ED5157310A4CULL,
		0x8B7A213B6C38522DULL,
		0xD8406F80765018B1ULL,
		0xA46ECE2B1410221BULL,
		0x8898F03DB643BD65ULL
	}};
	sign = 0;
	printf("Test Case 62\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 62 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -62;
	} else {
		printf("Test Case 62 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE7BA419F41075A01ULL,
		0x2A4D27A1B044C0EDULL,
		0x1100F7848C097C12ULL,
		0x83DEB4C2546A6DF6ULL,
		0x625C7B8D3B34AF84ULL,
		0x1EA05B7692E4FAD4ULL,
		0xBEC305B211AD0F79ULL,
		0xE1D65682E83452E6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8B810133AE4A562ULL,
		0x4BAAE0231ED64F83ULL,
		0xC71C627969FF0C35ULL,
		0xA5F4681D63654C7BULL,
		0x97273E3D7CDDDA62ULL,
		0x9FCAED510F19642FULL,
		0xAC382EE8E7AAB24EULL,
		0x8C564230E2B162CDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3F02318C0622B49FULL,
		0xDEA2477E916E716AULL,
		0x49E4950B220A6FDCULL,
		0xDDEA4CA4F105217AULL,
		0xCB353D4FBE56D521ULL,
		0x7ED56E2583CB96A4ULL,
		0x128AD6C92A025D2AULL,
		0x558014520582F019ULL
	}};
	sign = 0;
	printf("Test Case 63\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 63 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -63;
	} else {
		printf("Test Case 63 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x173EE4E5F5B5AC9AULL,
		0x9B8D2381D8FB874EULL,
		0xF908C27CD77A8F3DULL,
		0x8B9CF0FC01D352D9ULL,
		0x29C4C3E4FACC77CBULL,
		0x8D18B1542AEB9966ULL,
		0x275EBD9FCF66BFFEULL,
		0x9510FC211DC03D63ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x01880E83D3627D13ULL,
		0x364012E61B300150ULL,
		0x044EB0421D7CF5BDULL,
		0x2340A14325B4C84FULL,
		0x1CF88BF79AF779BDULL,
		0x9712CD3515F6924FULL,
		0xB739A869EE5F01DCULL,
		0x0548BA4545CEB713ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x15B6D66222532F87ULL,
		0x654D109BBDCB85FEULL,
		0xF4BA123AB9FD9980ULL,
		0x685C4FB8DC1E8A8AULL,
		0x0CCC37ED5FD4FE0EULL,
		0xF605E41F14F50717ULL,
		0x70251535E107BE21ULL,
		0x8FC841DBD7F1864FULL
	}};
	sign = 0;
	printf("Test Case 64\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 64 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -64;
	} else {
		printf("Test Case 64 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x443A174790B2AC24ULL,
		0x5854DA67E72A2A81ULL,
		0x90341FCFE72A5F3AULL,
		0xF24AFF15560FD8D3ULL,
		0xADA3327321C4D920ULL,
		0x6B99C0FB467E845DULL,
		0x152CBEB4BFE9EDD0ULL,
		0x3A0E2923FCB30D24ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE536AC4630841912ULL,
		0x40C99878DABCDB38ULL,
		0x8708560F28856AC9ULL,
		0xB7185F53D42E3DB6ULL,
		0xFAFFF102BF5E3AD2ULL,
		0xB6A4BB43FC949B75ULL,
		0xC3C494BA55A5099FULL,
		0x5ADC225862FED8ACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5F036B01602E9312ULL,
		0x178B41EF0C6D4F48ULL,
		0x092BC9C0BEA4F471ULL,
		0x3B329FC181E19B1DULL,
		0xB2A3417062669E4EULL,
		0xB4F505B749E9E8E7ULL,
		0x516829FA6A44E430ULL,
		0xDF3206CB99B43477ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 65\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 65 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -65;
	} else {
		printf("Test Case 65 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD1F095F31A3222E8ULL,
		0x5666086BBB289064ULL,
		0x2329AC0DF46D2412ULL,
		0x81405BE7D475A4C3ULL,
		0xC4E127ABA768C500ULL,
		0x69BA6238BC9EEF02ULL,
		0x6819C0A3455DF26AULL,
		0x5D65589B15DE29B6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x11A058BD25F5E9C7ULL,
		0xCAEBF1FAC4086B56ULL,
		0x9B61309BD965A08BULL,
		0x9AC3A488578C4997ULL,
		0x16289CFB021E6AA5ULL,
		0x50140144512A9310ULL,
		0xC6749448E14311D5ULL,
		0x71D6705C6C5CCB85ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC0503D35F43C3921ULL,
		0x8B7A1670F720250EULL,
		0x87C87B721B078386ULL,
		0xE67CB75F7CE95B2BULL,
		0xAEB88AB0A54A5A5AULL,
		0x19A660F46B745BF2ULL,
		0xA1A52C5A641AE095ULL,
		0xEB8EE83EA9815E30ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 66\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 66 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -66;
	} else {
		printf("Test Case 66 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4CA399FCE0B7C383ULL,
		0xA275FB50BD3DE89EULL,
		0x0152E9FDC1D7E951ULL,
		0xE81B8385A8FDF05EULL,
		0xD8A4F05B29E7AEE7ULL,
		0xA4235AC7C2B617D7ULL,
		0xD88762606E87CF2AULL,
		0x2EA1DF4FEF9312A8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEE54432D03E8148ULL,
		0x5AA32CDB76D2581FULL,
		0x042354453EF7BDEFULL,
		0x9A6F99A095349FA0ULL,
		0x5D4CABE6DE0E3E9AULL,
		0x6F3FBA8A795C8A71ULL,
		0x0F124E2B3E4D1215ULL,
		0x61C746F5219A1236ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6DBE55CA1079423BULL,
		0x47D2CE75466B907EULL,
		0xFD2F95B882E02B62ULL,
		0x4DABE9E513C950BDULL,
		0x7B5844744BD9704DULL,
		0x34E3A03D49598D66ULL,
		0xC9751435303ABD15ULL,
		0xCCDA985ACDF90072ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 67\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 67 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -67;
	} else {
		printf("Test Case 67 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x58A8CCE591A2D7BDULL,
		0x85758245D1E66CB6ULL,
		0xE01A03BCABEF77CDULL,
		0x03D13CC0B24370E0ULL,
		0x77ACEA1C70353511ULL,
		0x27BA016DF8B083D9ULL,
		0x87522131E229F54FULL,
		0xA9520D94A76C6F0FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x684C2B107B5A5158ULL,
		0xA92D589BAC52A622ULL,
		0x9B3D089CF167EC62ULL,
		0x16203C2B79D80C36ULL,
		0x6DB2D9F5643C9A9FULL,
		0x6E8F7420574BBCAAULL,
		0xBE8B06CE9B62DBA7ULL,
		0xBA4852AD8091789DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF05CA1D516488665ULL,
		0xDC4829AA2593C693ULL,
		0x44DCFB1FBA878B6AULL,
		0xEDB10095386B64AAULL,
		0x09FA10270BF89A71ULL,
		0xB92A8D4DA164C72FULL,
		0xC8C71A6346C719A7ULL,
		0xEF09BAE726DAF671ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 68\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 68 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -68;
	} else {
		printf("Test Case 68 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xAAE676DAB120CE68ULL,
		0xA9FCF8A02444EDC7ULL,
		0x9EC2F39B9687CEDDULL,
		0xC4EABE3A0FC6697AULL,
		0x97D2E653ED6D56F7ULL,
		0xB0674D316DC3F288ULL,
		0xC19B951DF3B80DAEULL,
		0x56DFE0E687968561ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DF38EFD2323385CULL,
		0x131E1F8CCD6AB1BBULL,
		0x5A62FD91E45D0084ULL,
		0x0B0630C5D9B7C562ULL,
		0x212FB2CD39B14B92ULL,
		0x85CDA00DCC6D35CDULL,
		0x8F565E9B09A05226ULL,
		0xCCD20693DE6C818CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9CF2E7DD8DFD960CULL,
		0x96DED91356DA3C0CULL,
		0x445FF609B22ACE59ULL,
		0xB9E48D74360EA418ULL,
		0x76A33386B3BC0B65ULL,
		0x2A99AD23A156BCBBULL,
		0x32453682EA17BB88ULL,
		0x8A0DDA52A92A03D5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 69\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 69 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -69;
	} else {
		printf("Test Case 69 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0DB0CB9660790A83ULL,
		0xE4FA74FBB6976DD7ULL,
		0x1E0104D1AE91FF71ULL,
		0xFFC2769B07368363ULL,
		0x20F309B19AF38A7CULL,
		0xBAA4947D14310FA9ULL,
		0xF0A04B3F3CC77063ULL,
		0x8F9FC53E42732E45ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC301122DBE8A7602ULL,
		0xBF9756884E087D4EULL,
		0x145FCF3D41CA5CACULL,
		0x49F8EC17C77943DEULL,
		0x963A19260C54126DULL,
		0x4DF91832B12B9F7EULL,
		0x04D75460348C5DAAULL,
		0xE070FD1D609CB645ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4AAFB968A1EE9481ULL,
		0x25631E73688EF088ULL,
		0x09A135946CC7A2C5ULL,
		0xB5C98A833FBD3F85ULL,
		0x8AB8F08B8E9F780FULL,
		0x6CAB7C4A6305702AULL,
		0xEBC8F6DF083B12B9ULL,
		0xAF2EC820E1D67800ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 70\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 70 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -70;
	} else {
		printf("Test Case 70 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x8D115B3AF1AE3F1BULL,
		0x84C69E5637AE7116ULL,
		0x8450EE18106379CAULL,
		0x28D3BC90F996EEB9ULL,
		0x8948A6A5C5D1ABA7ULL,
		0xD07F6AA45E332067ULL,
		0x7601DE1B1B4B3B29ULL,
		0x76DBCF6E2178CE5CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCDA9C5A2B34830EULL,
		0x6B92319C60897A20ULL,
		0x95885732B67AD5B8ULL,
		0xD3D90D4A0825C66CULL,
		0xF63682F0A637132FULL,
		0xECD42B53D6F5304DULL,
		0x1A39F1BE878F01E6ULL,
		0x80E03E081C1CE48CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC036BEE0C679BC0DULL,
		0x19346CB9D724F6F5ULL,
		0xEEC896E559E8A412ULL,
		0x54FAAF46F171284CULL,
		0x931223B51F9A9877ULL,
		0xE3AB3F50873DF019ULL,
		0x5BC7EC5C93BC3942ULL,
		0xF5FB9166055BE9D0ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 71\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 71 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -71;
	} else {
		printf("Test Case 71 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x05AC52579D1BED3DULL,
		0x5AD6FEDE93AAA013ULL,
		0x8D1EB555FDD1A8BCULL,
		0xBA9B6D72F8528AF7ULL,
		0xCE0A928DF8A1B1A7ULL,
		0x7DAEA86CB1D11D20ULL,
		0x24A16DA4CE5869DDULL,
		0x7C5BBE6903FB9AB7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x32BBBA41ADAD2E49ULL,
		0x2719689D79E24021ULL,
		0x60BE5895FAAB23CFULL,
		0xC5DB71B3777CFCA5ULL,
		0x267DC0D38774AF89ULL,
		0x97B4A4D0FDD831CAULL,
		0x0337FFE136834A6CULL,
		0xA96494290E780BF4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD2F09815EF6EBEF4ULL,
		0x33BD964119C85FF1ULL,
		0x2C605CC0032684EDULL,
		0xF4BFFBBF80D58E52ULL,
		0xA78CD1BA712D021DULL,
		0xE5FA039BB3F8EB56ULL,
		0x21696DC397D51F70ULL,
		0xD2F72A3FF5838EC3ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 72\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 72 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -72;
	} else {
		printf("Test Case 72 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xDD0BF3697E1CDF9EULL,
		0x4108FAC432E1E94CULL,
		0x6AD6A9DF8BD49C07ULL,
		0x1E519480431E32D6ULL,
		0x53BF8C7FB42355E0ULL,
		0x20F7ADF9D787D39FULL,
		0x50592E0B67BEAD5EULL,
		0xB17A1A332084EA3CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB7AD9CB424FC8B9ULL,
		0x138680FC7E8AF662ULL,
		0xAFFABBF22B867466ULL,
		0xE705F7D356F491FFULL,
		0x68A89365E436CBD4ULL,
		0xA082064D2798EA9FULL,
		0x8FE740A8B94A54E3ULL,
		0x423DD44BEBB76D11ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2191199E3BCD16E5ULL,
		0x2D8279C7B456F2EAULL,
		0xBADBEDED604E27A1ULL,
		0x374B9CACEC29A0D6ULL,
		0xEB16F919CFEC8A0BULL,
		0x8075A7ACAFEEE8FFULL,
		0xC071ED62AE74587AULL,
		0x6F3C45E734CD7D2AULL
	}};
	sign = 0;
	printf("Test Case 73\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 73 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -73;
	} else {
		printf("Test Case 73 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x895C6B4FEBE8752AULL,
		0x9DA98FE22F52462DULL,
		0x3700B6B524E09AC4ULL,
		0x2506B428A8FEDD8CULL,
		0xA5BEA7D61224FC76ULL,
		0x73494BCF36BEBC74ULL,
		0x582350658A6A3C73ULL,
		0x8C7591BC75FA8D56ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x204A3203397EA56BULL,
		0x318921F842F6F594ULL,
		0xD80464CBF52A4FC7ULL,
		0x198FEE7595006673ULL,
		0x17921AEB3BE43493ULL,
		0x68D77C5C05BE9794ULL,
		0x00FB28FBA704910DULL,
		0xBC3572EE82AF5374ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6912394CB269CFBFULL,
		0x6C206DE9EC5B5099ULL,
		0x5EFC51E92FB64AFDULL,
		0x0B76C5B313FE7718ULL,
		0x8E2C8CEAD640C7E3ULL,
		0x0A71CF73310024E0ULL,
		0x57282769E365AB66ULL,
		0xD0401ECDF34B39E2ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 74\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 74 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -74;
	} else {
		printf("Test Case 74 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE683305E6A8D9E01ULL,
		0xBCFCE428347340CAULL,
		0x4CB8616916CF7BA4ULL,
		0x090D4F75FB440482ULL,
		0x1BF66610F4FBC08BULL,
		0xB0DA4B6F8A4D40FEULL,
		0xE20B4906F353A70EULL,
		0x536465DCF4F0B4EFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x588463121503EB16ULL,
		0x0D3A3D6B71AF203EULL,
		0x71233E59D1C2EBE4ULL,
		0xC940D53FAE3800CDULL,
		0x54C1D7D264E89056ULL,
		0xAFCF428E2A9F62E9ULL,
		0xD996DFCFA7FEEDABULL,
		0x9889B38B798F18AEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8DFECD4C5589B2EBULL,
		0xAFC2A6BCC2C4208CULL,
		0xDB95230F450C8FC0ULL,
		0x3FCC7A364D0C03B4ULL,
		0xC7348E3E90133034ULL,
		0x010B08E15FADDE14ULL,
		0x087469374B54B963ULL,
		0xBADAB2517B619C41ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 75\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 75 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -75;
	} else {
		printf("Test Case 75 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA3A2C142B389CE05ULL,
		0x5B7AE928F78D7F53ULL,
		0xAB486225431E6B94ULL,
		0x5EA7976C6379DDCCULL,
		0x5AA41A65379F5D4AULL,
		0x10A64C328FBAC015ULL,
		0xC6A64C7BC40E490BULL,
		0xB996BD4A2A265550ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BBF36561B865C5BULL,
		0xD729273741D87294ULL,
		0x647ABF892DB6C56DULL,
		0xF8AB34BF93C38C22ULL,
		0x96EB1804690C988DULL,
		0x5C84C409463A324BULL,
		0xA13C9FAB6DA89566ULL,
		0x049A9ED58D469031ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x17E38AEC980371AAULL,
		0x8451C1F1B5B50CBFULL,
		0x46CDA29C1567A626ULL,
		0x65FC62ACCFB651AAULL,
		0xC3B90260CE92C4BCULL,
		0xB421882949808DC9ULL,
		0x2569ACD05665B3A4ULL,
		0xB4FC1E749CDFC51FULL
	}};
	sign = 0;
	printf("Test Case 76\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 76 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -76;
	} else {
		printf("Test Case 76 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4B71605C383DA2C6ULL,
		0xB22B9568DD8656A2ULL,
		0xB5C17F4D6765C0AAULL,
		0xA7DEE79813DAACF8ULL,
		0x26517373EA15BBABULL,
		0xF048A079AA661D71ULL,
		0x5E196F543B860B91ULL,
		0x0EB344ECEDD57A22ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB448D2F96EB5ACE8ULL,
		0x1EFD420D5EA813B9ULL,
		0xD431FDCBF211C3E7ULL,
		0x2C5C4F617C587E08ULL,
		0xDA9C2E3ABC8AA5FCULL,
		0x87E78BDE2C1F8735ULL,
		0x279EFFEA90C7ECE0ULL,
		0x1533D0775A702EE4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x97288D62C987F5DEULL,
		0x932E535B7EDE42E8ULL,
		0xE18F81817553FCC3ULL,
		0x7B82983697822EEFULL,
		0x4BB545392D8B15AFULL,
		0x6861149B7E46963BULL,
		0x367A6F69AABE1EB1ULL,
		0xF97F747593654B3EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 77\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 77 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -77;
	} else {
		printf("Test Case 77 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x50E6EE8F4BD4E682ULL,
		0x940313C4A1D2168EULL,
		0x1B3FDEBEFE9B2FC0ULL,
		0x424574A33E080314ULL,
		0x5F58DF9F390E6C0CULL,
		0x76727B967F17A37DULL,
		0x8A6FD45770D6B215ULL,
		0xB2C753ACEA76C360ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF67A1E18FBF54BBULL,
		0xCE0BC155B6DDAC4AULL,
		0x247A20ED51939CBBULL,
		0xCBAEFFCBA92DECE2ULL,
		0x53FB8D905E01BC69ULL,
		0xAEA24B7C7381233CULL,
		0xDF8B55A6360299A5ULL,
		0x3678EE74F9CA8A91ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x817F4CADBC1591C7ULL,
		0xC5F7526EEAF46A43ULL,
		0xF6C5BDD1AD079304ULL,
		0x769674D794DA1631ULL,
		0x0B5D520EDB0CAFA2ULL,
		0xC7D0301A0B968041ULL,
		0xAAE47EB13AD4186FULL,
		0x7C4E6537F0AC38CEULL
	}};
	sign = 0;
	printf("Test Case 78\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 78 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -78;
	} else {
		printf("Test Case 78 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE80252408928F281ULL,
		0xE24C6E8DCF8787C2ULL,
		0x56526AAB872570D9ULL,
		0x4A339E8C89B2A359ULL,
		0xE76D19F0F6DCCE72ULL,
		0x7E5480CDE473548CULL,
		0xA1FFBAE4706BF681ULL,
		0x723479300D4138B0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x230B9955877CE386ULL,
		0xE6D39F9B970F515AULL,
		0x6D31E4AE7B49B474ULL,
		0x0D9FB728FB0B683CULL,
		0xE29A6B695C882B31ULL,
		0xE249FADBBFEA2FA1ULL,
		0x573D63087A626AB4ULL,
		0x6460B0D356790EDCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC4F6B8EB01AC0EFBULL,
		0xFB78CEF238783668ULL,
		0xE92085FD0BDBBC64ULL,
		0x3C93E7638EA73B1CULL,
		0x04D2AE879A54A341ULL,
		0x9C0A85F2248924EBULL,
		0x4AC257DBF6098BCCULL,
		0x0DD3C85CB6C829D4ULL
	}};
	sign = 0;
	printf("Test Case 79\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 79 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -79;
	} else {
		printf("Test Case 79 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xBD9A81C3AB0D1647ULL,
		0x5A4316623121675DULL,
		0x7CE7D29011B0FBD6ULL,
		0x3A84775C9A8FF67FULL,
		0xBAA911EC780C723BULL,
		0xB38053AE866B30AEULL,
		0x4E9BD8CB93208C99ULL,
		0x0F62F029E32CC7FDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B1222AEBF6172AFULL,
		0x88F9520609950303ULL,
		0x8CE2963B7DB3758BULL,
		0xF31E5925A24F59F9ULL,
		0xEA19458B434C611EULL,
		0x6582244AEAD9E363ULL,
		0x6BFF2EEB442BC9FEULL,
		0x867EE75FE5956614ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x42885F14EBABA398ULL,
		0xD149C45C278C645AULL,
		0xF0053C5493FD864AULL,
		0x47661E36F8409C85ULL,
		0xD08FCC6134C0111CULL,
		0x4DFE2F639B914D4AULL,
		0xE29CA9E04EF4C29BULL,
		0x88E408C9FD9761E8ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 80\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 80 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -80;
	} else {
		printf("Test Case 80 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE401D6BAB647B99FULL,
		0xFFE0B6DE332F6496ULL,
		0x17796B3F4652C3C0ULL,
		0xAD04D94B36388AB3ULL,
		0x617AE90C232CA0DCULL,
		0x0FEC5877FCBCC01CULL,
		0x4E6BB28459F22C0FULL,
		0x54347A98A9ED8BE5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x884F2ADCB553DE36ULL,
		0xB43631644F183236ULL,
		0x59372EA8827AAF98ULL,
		0x504AE51EF5859F50ULL,
		0xEFC661D9781AFDE8ULL,
		0x6B13A20F967706B7ULL,
		0x440654CBAFAB607EULL,
		0x038E217B26531032ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5BB2ABDE00F3DB69ULL,
		0x4BAA8579E4173260ULL,
		0xBE423C96C3D81428ULL,
		0x5CB9F42C40B2EB62ULL,
		0x71B48732AB11A2F4ULL,
		0xA4D8B6686645B964ULL,
		0x0A655DB8AA46CB90ULL,
		0x50A6591D839A7BB3ULL
	}};
	sign = 0;
	printf("Test Case 81\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 81 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -81;
	} else {
		printf("Test Case 81 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xEAB2DE72EE58CFFAULL,
		0xE6544DAE36EB606AULL,
		0xA12046930A38774DULL,
		0x6F444A8E08CA8B22ULL,
		0x824783E56AA3D15AULL,
		0xEA7A0C06F20E68C9ULL,
		0x8787CE75052A5D51ULL,
		0xF5D5C6C61B2D7B62ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x43420734C05041E8ULL,
		0x5E86C7363C04A41DULL,
		0xF7AED1814C9ABBBEULL,
		0x96FF0F8619605F27ULL,
		0x94FE8D4356C697E4ULL,
		0xB2EFB1970E77FF1DULL,
		0xE360A96A566242FBULL,
		0x59C2D3094BDB5130ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA770D73E2E088E12ULL,
		0x87CD8677FAE6BC4DULL,
		0xA9717511BD9DBB8FULL,
		0xD8453B07EF6A2BFAULL,
		0xED48F6A213DD3975ULL,
		0x378A5A6FE39669ABULL,
		0xA427250AAEC81A56ULL,
		0x9C12F3BCCF522A31ULL
	}};
	sign = 0;
	printf("Test Case 82\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 82 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -82;
	} else {
		printf("Test Case 82 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB63B02D801D5D981ULL,
		0x6529B541B8CCD2BEULL,
		0x935FE4B65ADE6E0BULL,
		0x1455E9AC9807740EULL,
		0x05C52FD75E6CAF96ULL,
		0xB5D1510B0098ED72ULL,
		0x67E86F71CA569063ULL,
		0x4599FC5579040F88ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x08680C32F1C179B7ULL,
		0x73F903F599106F5AULL,
		0xAA173D3851DBA619ULL,
		0xFFC6894DFE14B5FCULL,
		0x6D230F748687A6BCULL,
		0xE2D300E0F84B790EULL,
		0xAF13E481EB7B980DULL,
		0x3CEBF513EF27FD13ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xADD2F6A510145FCAULL,
		0xF130B14C1FBC6364ULL,
		0xE948A77E0902C7F1ULL,
		0x148F605E99F2BE11ULL,
		0x98A22062D7E508D9ULL,
		0xD2FE502A084D7463ULL,
		0xB8D48AEFDEDAF855ULL,
		0x08AE074189DC1274ULL
	}};
	sign = 0;
	printf("Test Case 83\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 83 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -83;
	} else {
		printf("Test Case 83 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC97432BA86455C0CULL,
		0x21CBE54AE4F5F4F5ULL,
		0xB82C67D9FEE261D0ULL,
		0xCC8405D248C5BBDAULL,
		0xD45A4F4831BF0876ULL,
		0x367FF41D175E76C9ULL,
		0x67B6B07CC98CC397ULL,
		0x09E29645F7044CA8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0907EF3A8903BCBFULL,
		0x251B6432AEEF1642ULL,
		0x738E7F118E28B100ULL,
		0xCFDFD07C6B9EAA1FULL,
		0xF2BF67D0663E3905ULL,
		0x989990240FBF8FD7ULL,
		0x9DC632479FDAEA1DULL,
		0xD1464F90D9CF32CDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC06C437FFD419F4DULL,
		0xFCB081183606DEB3ULL,
		0x449DE8C870B9B0CFULL,
		0xFCA43555DD2711BBULL,
		0xE19AE777CB80CF70ULL,
		0x9DE663F9079EE6F1ULL,
		0xC9F07E3529B1D979ULL,
		0x389C46B51D3519DAULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 84\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 84 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -84;
	} else {
		printf("Test Case 84 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x65EEC741CD6A3A5BULL,
		0xA72980806B3D1B51ULL,
		0x66FDFB12B653BD84ULL,
		0xD0A54F8DC1BA3AA0ULL,
		0xC36E7A6555DF6798ULL,
		0x49A3C3DCFFD8FD78ULL,
		0x4B84EA902ACAA01EULL,
		0x3F4EAAC163E2A80CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DB18446F1410ED2ULL,
		0x7E045158CD9DEB4AULL,
		0x34B231BE08B253B7ULL,
		0xACFE344435DC8FBBULL,
		0x1C545DA73CF17C0FULL,
		0xD68A0295523B254CULL,
		0x3FCC360F5A7BBEABULL,
		0x3CBC47D782ED4247ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x383D42FADC292B89ULL,
		0x29252F279D9F3007ULL,
		0x324BC954ADA169CDULL,
		0x23A71B498BDDAAE5ULL,
		0xA71A1CBE18EDEB89ULL,
		0x7319C147AD9DD82CULL,
		0x0BB8B480D04EE172ULL,
		0x029262E9E0F565C5ULL
	}};
	sign = 0;
	printf("Test Case 85\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 85 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -85;
	} else {
		printf("Test Case 85 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xBA46771120FB8419ULL,
		0x6CCE3411C322B7CBULL,
		0x86C173E0BFE2FC59ULL,
		0x6467A0D1441E5F4CULL,
		0x8CCBB52AF07073DBULL,
		0xABDE0CB073B63F44ULL,
		0xC119111FDDC5C5B9ULL,
		0x29F374B0B7A279ADULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFACBB2FA983144FDULL,
		0xC72C5600E78831B0ULL,
		0x37CC7953D9309B4FULL,
		0xE16F65329583CA07ULL,
		0x7A940766DC17B75EULL,
		0xED13EDD23C775375ULL,
		0xD63F253B6FC60717ULL,
		0x091B88407D402EAAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBF7AC41688CA3F1CULL,
		0xA5A1DE10DB9A861AULL,
		0x4EF4FA8CE6B26109ULL,
		0x82F83B9EAE9A9545ULL,
		0x1237ADC41458BC7CULL,
		0xBECA1EDE373EEBCFULL,
		0xEAD9EBE46DFFBEA1ULL,
		0x20D7EC703A624B02ULL
	}};
	sign = 0;
	printf("Test Case 86\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 86 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -86;
	} else {
		printf("Test Case 86 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6477BD033CA055A3ULL,
		0x5B0D32A74EEF1B89ULL,
		0x142FFF61FA9D9EADULL,
		0x1F2198BE541D73E1ULL,
		0x4FD755F35E4E8920ULL,
		0x79CE48411035095BULL,
		0xA3B7F5B8694C8F6BULL,
		0xFB6CBA20EF571F90ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD02CF69A50037683ULL,
		0xCA498CFE8963916CULL,
		0x9F229496B7E160CFULL,
		0x14396B2E161EE6A5ULL,
		0x1387A378166196A0ULL,
		0x63D40BD30DB6B747ULL,
		0x604AD7ADDD8E8415ULL,
		0xB5F2668651934AAEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x944AC668EC9CDF20ULL,
		0x90C3A5A8C58B8A1CULL,
		0x750D6ACB42BC3DDDULL,
		0x0AE82D903DFE8D3BULL,
		0x3C4FB27B47ECF280ULL,
		0x15FA3C6E027E5214ULL,
		0x436D1E0A8BBE0B56ULL,
		0x457A539A9DC3D4E2ULL
	}};
	sign = 0;
	printf("Test Case 87\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 87 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -87;
	} else {
		printf("Test Case 87 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x425344FE668155F5ULL,
		0x481042D76B5B8437ULL,
		0xE9549E61A9C16623ULL,
		0xBFC70D24B70D25BDULL,
		0x2B33054DE2343360ULL,
		0xB2ED529ACE2EE3C9ULL,
		0x44559B736423F0A5ULL,
		0x5B5255B76010851EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC8ACD576D4579F7ULL,
		0xB130A2D96000DE73ULL,
		0x5509013746C65BABULL,
		0x73789947E5E12291ULL,
		0x897DDDDB1E90C21BULL,
		0xA5C6823F1876DACCULL,
		0x72B2998D56603484ULL,
		0x98100593A3D01ED7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x95C877A6F93BDBFEULL,
		0x96DF9FFE0B5AA5C3ULL,
		0x944B9D2A62FB0A77ULL,
		0x4C4E73DCD12C032CULL,
		0xA1B52772C3A37145ULL,
		0x0D26D05BB5B808FCULL,
		0xD1A301E60DC3BC21ULL,
		0xC3425023BC406646ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 88\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 88 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -88;
	} else {
		printf("Test Case 88 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x36F998612775CA97ULL,
		0xF21010E127DB550BULL,
		0x9E4E074D11BE203CULL,
		0x811A5FB3685E762EULL,
		0x2381371BA96CB843ULL,
		0xF522CF1D6D50027DULL,
		0x424D3A12A637E5DEULL,
		0x48A41775DE6D8759ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DB2C67CCD19842FULL,
		0x5F0D99153C1B8317ULL,
		0x57D903741CC93077ULL,
		0x3EEE940AB53A74E5ULL,
		0x7ACC1E9738E1F69DULL,
		0x687B7362DBB274BFULL,
		0xAFE05C542A7429E3ULL,
		0x2A8D191035BC776FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1946D1E45A5C4668ULL,
		0x930277CBEBBFD1F4ULL,
		0x467503D8F4F4EFC5ULL,
		0x422BCBA8B3240149ULL,
		0xA8B51884708AC1A6ULL,
		0x8CA75BBA919D8DBDULL,
		0x926CDDBE7BC3BBFBULL,
		0x1E16FE65A8B10FE9ULL
	}};
	sign = 0;
	printf("Test Case 89\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 89 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -89;
	} else {
		printf("Test Case 89 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xAAFC6F1F91C13DF4ULL,
		0x07401E82B78A2D6DULL,
		0xE9F7AAB939E6CCBAULL,
		0x9C67DE503968306CULL,
		0xEC3FFD9A06F8F78BULL,
		0x441A810FC8AA0A35ULL,
		0x0A2B7526EA23CBC4ULL,
		0x190DF90D65C967CDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DF3C0C249A81017ULL,
		0x76894745499E0C6EULL,
		0x17C1C4C92E7B2330ULL,
		0x3A75655BAB09C79BULL,
		0x64E550755A698BD5ULL,
		0x6BC45FD1C60724A0ULL,
		0x9410D4D0F17F8D6EULL,
		0xF8345DB68632C4B4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0D08AE5D48192DDDULL,
		0x90B6D73D6DEC20FFULL,
		0xD235E5F00B6BA989ULL,
		0x61F278F48E5E68D1ULL,
		0x875AAD24AC8F6BB6ULL,
		0xD856213E02A2E595ULL,
		0x761AA055F8A43E55ULL,
		0x20D99B56DF96A318ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 90\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 90 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -90;
	} else {
		printf("Test Case 90 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x853B561579DDDF84ULL,
		0x52831CAED7335310ULL,
		0x0559C2A591AC09A4ULL,
		0xB103C7F99A8FEF0CULL,
		0x0E8B54B1A488420EULL,
		0x037E60CD9938D447ULL,
		0x37004FDBE172F59AULL,
		0x1DEF2F72E501C3DAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x215527009175E952ULL,
		0x18F323279DF42AFCULL,
		0x6899B0270C6CA1E9ULL,
		0x78A4DFED2A6C664CULL,
		0x39E4A66205ED8687ULL,
		0x37C7E5D7A6662518ULL,
		0xA8678E0C575108A4ULL,
		0x2C4C0CE9D5412E2DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x63E62F14E867F632ULL,
		0x398FF987393F2814ULL,
		0x9CC0127E853F67BBULL,
		0x385EE80C702388BFULL,
		0xD4A6AE4F9E9ABB87ULL,
		0xCBB67AF5F2D2AF2EULL,
		0x8E98C1CF8A21ECF5ULL,
		0xF1A322890FC095ACULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 91\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 91 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -91;
	} else {
		printf("Test Case 91 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1727CF52975AF257ULL,
		0x9FACD918891948A3ULL,
		0x4868EAF029CA0DDCULL,
		0x6BC6D8CB61E2D559ULL,
		0x07F6F4241EF050B7ULL,
		0x9DA0522805D58246ULL,
		0x20AED61045D13815ULL,
		0x3F7F3476CF37A141ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E9F1CA9CE76D470ULL,
		0x4C62972A9089D5F3ULL,
		0x1F113FE896AD7EFDULL,
		0x9609F06DBF9E38FDULL,
		0x0EEA6FC90FFBD724ULL,
		0xD6AA10815914AADCULL,
		0x62CBA87714F8328BULL,
		0x78A652895DA60228ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8888B2A8C8E41DE7ULL,
		0x534A41EDF88F72AFULL,
		0x2957AB07931C8EDFULL,
		0xD5BCE85DA2449C5CULL,
		0xF90C845B0EF47992ULL,
		0xC6F641A6ACC0D769ULL,
		0xBDE32D9930D90589ULL,
		0xC6D8E1ED71919F18ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 92\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 92 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -92;
	} else {
		printf("Test Case 92 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xDE2251940CD42403ULL,
		0x855C46BA895DD8A8ULL,
		0x0FAF0300C28DF56CULL,
		0x096DBCD6F3AD2509ULL,
		0x5A61806658E6710EULL,
		0x716B6285F2BDAB11ULL,
		0x9257048BECBC68DFULL,
		0x2B887E8BBF560FB9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CBD29D6A0A969FFULL,
		0x615C4E58793594C5ULL,
		0x70BCF62DC27C9C2DULL,
		0x2DE2128DB41D6C38ULL,
		0xB818CD4C880AC8F7ULL,
		0x5388838D7FC68C56ULL,
		0x6FBDD2DA339B5A1AULL,
		0x09DE060B5CBEC5E0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC16527BD6C2ABA04ULL,
		0x23FFF862102843E3ULL,
		0x9EF20CD30011593FULL,
		0xDB8BAA493F8FB8D0ULL,
		0xA248B319D0DBA816ULL,
		0x1DE2DEF872F71EBAULL,
		0x229931B1B9210EC5ULL,
		0x21AA7880629749D9ULL
	}};
	sign = 0;
	printf("Test Case 93\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 93 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -93;
	} else {
		printf("Test Case 93 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF69B1688A313D471ULL,
		0x0B84606CADA95321ULL,
		0x8AB4B28FF88A5690ULL,
		0x7225B936B5AA2DCCULL,
		0x4E0E22D83D359B60ULL,
		0x1ED7F4602DC21F72ULL,
		0xB39FCD9E4C01D024ULL,
		0xF3C5965131397904ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4161F6228092E28ULL,
		0xAB3407CCFBE26F01ULL,
		0xDE00781498AE3910ULL,
		0x340BF3AF060F81BDULL,
		0x13396F9AFEFF709EULL,
		0xF989C17E29D023B8ULL,
		0x1880A22370B4B73FULL,
		0xFE6FBB0F256743BDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0284F7267B0AA649ULL,
		0x6050589FB1C6E420ULL,
		0xACB43A7B5FDC1D7FULL,
		0x3E19C587AF9AAC0EULL,
		0x3AD4B33D3E362AC2ULL,
		0x254E32E203F1FBBAULL,
		0x9B1F2B7ADB4D18E4ULL,
		0xF555DB420BD23547ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 94\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 94 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -94;
	} else {
		printf("Test Case 94 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xABDBDF5649DB5ED9ULL,
		0x057892883CF47295ULL,
		0xDF1DCC470AC136DBULL,
		0x239E59024BD94852ULL,
		0x8B065A51D97C4B9AULL,
		0x42E1B936F138022CULL,
		0x68485876AC3A38DAULL,
		0x3DB60E730DA1FFDDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x266DCC903B4E98E0ULL,
		0x7A0C354CBDB7BB3CULL,
		0x8B5797E6E659E658ULL,
		0xDFB0DCE043EA4F4DULL,
		0x81E816AEE5601A4BULL,
		0x1F922B16ECE5BE6DULL,
		0x5A4464A50AC0B75DULL,
		0x1C4527D067634788ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x856E12C60E8CC5F9ULL,
		0x8B6C5D3B7F3CB759ULL,
		0x53C6346024675082ULL,
		0x43ED7C2207EEF905ULL,
		0x091E43A2F41C314EULL,
		0x234F8E20045243BFULL,
		0x0E03F3D1A179817DULL,
		0x2170E6A2A63EB855ULL
	}};
	sign = 0;
	printf("Test Case 95\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 95 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -95;
	} else {
		printf("Test Case 95 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x97541A07E7C13ACDULL,
		0x9F8B56E1EAA98D03ULL,
		0xD77B5C83329E1ABAULL,
		0x01FE8182657D6079ULL,
		0xFDE213E3435B161EULL,
		0x230C0994DB6868BBULL,
		0x20CCC5E3BE99E7E6ULL,
		0x93BCFBD1343E392AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1156D4B6FDDD8CB6ULL,
		0xAA52D8CD666BB8B7ULL,
		0xEF1DE251C45F7459ULL,
		0x0FA2BDBAFF963A8DULL,
		0x44B12B73518AA653ULL,
		0xCCAE9536262F3186ULL,
		0x421587BD92A6AC64ULL,
		0x40804CF593BABE32ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x85FD4550E9E3AE17ULL,
		0xF5387E14843DD44CULL,
		0xE85D7A316E3EA660ULL,
		0xF25BC3C765E725EBULL,
		0xB930E86FF1D06FCAULL,
		0x565D745EB5393735ULL,
		0xDEB73E262BF33B81ULL,
		0x533CAEDBA0837AF7ULL
	}};
	sign = 0;
	printf("Test Case 96\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 96 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -96;
	} else {
		printf("Test Case 96 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE42BB08A4796417CULL,
		0x9DA3B99D569FC84DULL,
		0x9E6C8752F7205882ULL,
		0x7B7CACF3A0ACDD8BULL,
		0x97160423290946C1ULL,
		0xD005321CBFF8FF2DULL,
		0x739C24C45DC65EEBULL,
		0x0CACB59CC3F8F3E3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC941BA5BC608C3BCULL,
		0xFC2CACC53B2A8EAFULL,
		0x87ED1C39C8C205F6ULL,
		0x9AAADBAAA460182FULL,
		0x0B1C1DC248D05220ULL,
		0x7CA8DD75320B8188ULL,
		0x04A335B735538E7EULL,
		0xC1356FD6A5BF63C8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1AE9F62E818D7DC0ULL,
		0xA1770CD81B75399EULL,
		0x167F6B192E5E528BULL,
		0xE0D1D148FC4CC55CULL,
		0x8BF9E660E038F4A0ULL,
		0x535C54A78DED7DA5ULL,
		0x6EF8EF0D2872D06DULL,
		0x4B7745C61E39901BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 97\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 97 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -97;
	} else {
		printf("Test Case 97 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4DCEBEBC1F98E667ULL,
		0xB14CE9465DEC986BULL,
		0x43BD9D2734E0325AULL,
		0xF23949BC3979FD89ULL,
		0x5370379DD2476255ULL,
		0x01A7DD5EDE600C02ULL,
		0x598A7393F3D7CBC4ULL,
		0xA8BE9F4CED0A5225ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1ADE1696C0CA871ULL,
		0x23F3297B5403C6CFULL,
		0x0707F4D39A248ECAULL,
		0xFC84603802DF36E5ULL,
		0xDD6C5C0DC7772309ULL,
		0xA5065F303EA8D5C2ULL,
		0x7B6B22E25548A58DULL,
		0x9CCB6F2EE2E0AF00ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5C20DD52B38C3DF6ULL,
		0x8D59BFCB09E8D19BULL,
		0x3CB5A8539ABBA390ULL,
		0xF5B4E984369AC6A4ULL,
		0x7603DB900AD03F4BULL,
		0x5CA17E2E9FB7363FULL,
		0xDE1F50B19E8F2636ULL,
		0x0BF3301E0A29A324ULL
	}};
	sign = 0;
	printf("Test Case 98\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 98 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -98;
	} else {
		printf("Test Case 98 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x147AA06F0F2F2AD5ULL,
		0x5D3AE95544D4EC18ULL,
		0x43E639AAC0FD7DD5ULL,
		0x8CD01E53A70DE99EULL,
		0x63CBE13ED0D4B4F8ULL,
		0x94C79465D1C2272EULL,
		0xD7AB6BF8ED11643EULL,
		0x886CB4388FDA5293ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x68A0586E5977433DULL,
		0x68E0EE885EAA90FAULL,
		0xA9DCD381C77EA045ULL,
		0x8F2A97C98C8013E5ULL,
		0xB6B92A671D992420ULL,
		0x855595E7C3055E40ULL,
		0x2A6A5151D504C5C4ULL,
		0x5E9026231D18D29CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xABDA4800B5B7E798ULL,
		0xF459FACCE62A5B1DULL,
		0x9A096628F97EDD8FULL,
		0xFDA5868A1A8DD5B8ULL,
		0xAD12B6D7B33B90D7ULL,
		0x0F71FE7E0EBCC8EDULL,
		0xAD411AA7180C9E7AULL,
		0x29DC8E1572C17FF7ULL
	}};
	sign = 0;
	printf("Test Case 99\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 99 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -99;
	} else {
		printf("Test Case 99 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB225E0FB251F6A7EULL,
		0x8F697D168B590F23ULL,
		0x043DCE8CA6A375F5ULL,
		0x698D6343A7ACD13EULL,
		0xB9DE8E3FC2A8EE87ULL,
		0x337CBA92ADF916AFULL,
		0x3E714BDA8E8CFF1EULL,
		0x1FE14AC6EDDC16C8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3346ADD34811A947ULL,
		0xB5A2C5DE271370BEULL,
		0x7F836EFF023B8147ULL,
		0x9F9DFA9E69AE35E1ULL,
		0x362D5FED1C6A1478ULL,
		0x8DBA3D2BE1A8B810ULL,
		0xC7651731D8579519ULL,
		0x37552F51AD3A1BE2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7EDF3327DD0DC137ULL,
		0xD9C6B73864459E65ULL,
		0x84BA5F8DA467F4ADULL,
		0xC9EF68A53DFE9B5CULL,
		0x83B12E52A63EDA0EULL,
		0xA5C27D66CC505E9FULL,
		0x770C34A8B6356A04ULL,
		0xE88C1B7540A1FAE5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 100\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 100 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -100;
	} else {
		printf("Test Case 100 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x3791669A6471458EULL,
		0x91CDDEC55A5F249FULL,
		0x24C0596A703C675AULL,
		0x1BD1B378F48FB361ULL,
		0x3ECE0349FCCD8A05ULL,
		0x8F4F7734EFF987ADULL,
		0x658F3D7BBE7299EBULL,
		0x028375FB9D33751CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x617D7AB47F946C3AULL,
		0x49655C52CAAB8ED7ULL,
		0x0E2152F99C67F39AULL,
		0xC431B74EF0DB4C58ULL,
		0xE3D0826F94193361ULL,
		0xAAA46F458E82E241ULL,
		0xB5EB276B7A75E703ULL,
		0xE7B1D700BD3D614AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD613EBE5E4DCD954ULL,
		0x486882728FB395C7ULL,
		0x169F0670D3D473C0ULL,
		0x579FFC2A03B46709ULL,
		0x5AFD80DA68B456A3ULL,
		0xE4AB07EF6176A56BULL,
		0xAFA4161043FCB2E7ULL,
		0x1AD19EFADFF613D1ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 101\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 101 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -101;
	} else {
		printf("Test Case 101 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6EDD94941590D395ULL,
		0xF300002350F9FD21ULL,
		0x249CF0B9BB616084ULL,
		0xBE1F6F86AF0ED400ULL,
		0x2CF75A9082CD920DULL,
		0x5E8D39174D4AC521ULL,
		0x2A3CE48E1CE25BF1ULL,
		0xA8487D7507ACB699ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CD49086AC0D7E05ULL,
		0x75194F62C558C68DULL,
		0x19EACFA5626205E3ULL,
		0x6EC36C71ED38EA9DULL,
		0x88068B557D51C1FDULL,
		0x45965E8D3988B3D8ULL,
		0xEE4FE66355F3CD64ULL,
		0xB4C6BEB686389725ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2209040D69835590ULL,
		0x7DE6B0C08BA13694ULL,
		0x0AB2211458FF5AA1ULL,
		0x4F5C0314C1D5E963ULL,
		0xA4F0CF3B057BD010ULL,
		0x18F6DA8A13C21148ULL,
		0x3BECFE2AC6EE8E8DULL,
		0xF381BEBE81741F73ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 102\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 102 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -102;
	} else {
		printf("Test Case 102 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x672BF3DCCE7A4EBEULL,
		0xD8D5D5FFEB7C2012ULL,
		0x1C9DC9F2B4FAD472ULL,
		0xEDFF5EE5AAFD2DE2ULL,
		0x42525A756267F6DAULL,
		0xCCB52505A5102193ULL,
		0xDCA06BEDD7C08F89ULL,
		0x048432EF4D44121BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x45D966FE35800C4AULL,
		0x0E3E877AE9EF5FD9ULL,
		0x65433448652699C3ULL,
		0x668B2FE95F74E23DULL,
		0xA073843283E7D1C0ULL,
		0x2ADE683592C0D3EAULL,
		0x5732B87CF77BC240ULL,
		0xF27FB3A45BE2D7BBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x21528CDE98FA4274ULL,
		0xCA974E85018CC039ULL,
		0xB75A95AA4FD43AAFULL,
		0x87742EFC4B884BA4ULL,
		0xA1DED642DE80251AULL,
		0xA1D6BCD0124F4DA8ULL,
		0x856DB370E044CD49ULL,
		0x12047F4AF1613A60ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 103\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 103 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -103;
	} else {
		printf("Test Case 103 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x2163503837701099ULL,
		0x2F45E7C41F0D65E5ULL,
		0xCD535F8B009F1197ULL,
		0x605098D23A0BF43BULL,
		0xDE42DD651AF4760BULL,
		0xDA36443BFF58567BULL,
		0x51E26B7494AF969FULL,
		0x327EF48C0E146838ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3884FD3A049D5A99ULL,
		0x3312E7BB43C5F72AULL,
		0x4104A4C318B1A378ULL,
		0x4E4B51AA7C5D580BULL,
		0xCCC542C18F2AC39EULL,
		0x2BB1E3E72669A409ULL,
		0xC567D929F8F06141ULL,
		0x478B2B09607C1900ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE8DE52FE32D2B600ULL,
		0xFC330008DB476EBAULL,
		0x8C4EBAC7E7ED6E1EULL,
		0x12054727BDAE9C30ULL,
		0x117D9AA38BC9B26DULL,
		0xAE846054D8EEB272ULL,
		0x8C7A924A9BBF355EULL,
		0xEAF3C982AD984F37ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 104\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 104 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -104;
	} else {
		printf("Test Case 104 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x105A8BE70E866D62ULL,
		0xFA35B3010F9EBA19ULL,
		0x8D13DC320E69949CULL,
		0x00DCEA0C24726A3DULL,
		0xDA03F87FA16E7103ULL,
		0xDA5A4C410B36D4EDULL,
		0x893B95AAD336A33BULL,
		0xCCC6FE9A10DFC17CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x92FCBBD0CC94CF5DULL,
		0xB9FA69D5A213C2F6ULL,
		0x29C6CE5BC0468572ULL,
		0x9F67F9B90CCD5B19ULL,
		0x01A46FAFE859D541ULL,
		0xFF95E455BAB25356ULL,
		0x8567351A6663436BULL,
		0x5D6C0ABC99CB0B2CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7D5DD01641F19E05ULL,
		0x403B492B6D8AF722ULL,
		0x634D0DD64E230F2AULL,
		0x6174F05317A50F24ULL,
		0xD85F88CFB9149BC1ULL,
		0xDAC467EB50848197ULL,
		0x03D460906CD35FCFULL,
		0x6F5AF3DD7714B650ULL
	}};
	sign = 0;
	printf("Test Case 105\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 105 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -105;
	} else {
		printf("Test Case 105 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE2FD6AE7DCACDD37ULL,
		0xCEC52CEE992D0D72ULL,
		0xFDF64C2314BCB20EULL,
		0xDE9D5BE9FC98C280ULL,
		0xF4A44B407E51BFAFULL,
		0x115B6621840B07E7ULL,
		0xCC16442627FE8020ULL,
		0x4FA4B45F6D3EBBD1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA63D76481EA7CAEULL,
		0xEA59BF7364EB042BULL,
		0x8F5AFB3C4FD2614EULL,
		0x6C9FC9243288BF60ULL,
		0x544223B735798362ULL,
		0x238CF8704C8655F2ULL,
		0xE537F4AE9FC5BBD2ULL,
		0x31F54D790C383C48ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x289993835AC26089ULL,
		0xE46B6D7B34420947ULL,
		0x6E9B50E6C4EA50BFULL,
		0x71FD92C5CA100320ULL,
		0xA062278948D83C4DULL,
		0xEDCE6DB13784B1F5ULL,
		0xE6DE4F778838C44DULL,
		0x1DAF66E661067F88ULL
	}};
	sign = 0;
	printf("Test Case 106\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 106 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -106;
	} else {
		printf("Test Case 106 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9993B26D47602F1BULL,
		0x253F7464AD9FDCD6ULL,
		0xF9A62A8D1851C649ULL,
		0xA4202580A6F81D2BULL,
		0xAD9F8127F77265D3ULL,
		0x8982F87697B9C994ULL,
		0x8BDA80C27F2C959CULL,
		0x66CB56656BF42084ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x17F3FF732C1F28BDULL,
		0x6D28E7A9339D7D70ULL,
		0xC94D07DFA4560244ULL,
		0xF69D3591977B9C0BULL,
		0x574942F921276B9FULL,
		0xFE774420327E93FFULL,
		0xCB596DE88A64AC4CULL,
		0x759426BA8ADB6582ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x819FB2FA1B41065EULL,
		0xB8168CBB7A025F66ULL,
		0x305922AD73FBC404ULL,
		0xAD82EFEF0F7C8120ULL,
		0x56563E2ED64AFA33ULL,
		0x8B0BB456653B3595ULL,
		0xC08112D9F4C7E94FULL,
		0xF1372FAAE118BB01ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 107\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 107 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -107;
	} else {
		printf("Test Case 107 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xFBC184ECB91A939DULL,
		0x44C46C2E86559452ULL,
		0x4085F79DAB9F23AAULL,
		0x9A2172C273EA3589ULL,
		0xA022DC62E6E22269ULL,
		0x5267216878D9AF9DULL,
		0xA249A7101FB0F48FULL,
		0xFB2FECD0792A1EA6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD269D5F42F2965B4ULL,
		0x8800A27FBC90750DULL,
		0x4F9D608FEAAF7DAFULL,
		0x246245DE52C0ED48ULL,
		0x4CF6D2CED71872C3ULL,
		0x1DE4C3F7509A0B47ULL,
		0x60EC313B4CD43CAEULL,
		0x015E8F74A0FB3A7CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2957AEF889F12DE9ULL,
		0xBCC3C9AEC9C51F45ULL,
		0xF0E8970DC0EFA5FAULL,
		0x75BF2CE421294840ULL,
		0x532C09940FC9AFA6ULL,
		0x34825D71283FA456ULL,
		0x415D75D4D2DCB7E1ULL,
		0xF9D15D5BD82EE42AULL
	}};
	sign = 0;
	printf("Test Case 108\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 108 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -108;
	} else {
		printf("Test Case 108 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE28694EC09862CF8ULL,
		0x6FE527EA1060181FULL,
		0x52014CC3454135B2ULL,
		0x7A0AA5CC8CF91E45ULL,
		0x228C37C0F664185CULL,
		0x19252D81E8B59392ULL,
		0xB119127C862E22F0ULL,
		0x09A6662BBEAFC406ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB8084150E6AA74BULL,
		0xD3B1C50292AE28E5ULL,
		0x84A3C46873BE663EULL,
		0xA93B616F2617020CULL,
		0x83B2C8F0EA68154FULL,
		0xFFF148F373E9D636ULL,
		0x57131AE11C2DA9C0ULL,
		0x04AD3004C6FC0539ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x170610D6FB1B85ADULL,
		0x9C3362E77DB1EF3AULL,
		0xCD5D885AD182CF73ULL,
		0xD0CF445D66E21C38ULL,
		0x9ED96ED00BFC030CULL,
		0x1933E48E74CBBD5BULL,
		0x5A05F79B6A00792FULL,
		0x04F93626F7B3BECDULL
	}};
	sign = 0;
	printf("Test Case 109\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 109 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -109;
	} else {
		printf("Test Case 109 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA76DB034597355F3ULL,
		0xAB2B3F747E66EDE4ULL,
		0x8ADEBA96CDE755B3ULL,
		0xDB22A5AA0B13F024ULL,
		0x96F11578C7FC0A8CULL,
		0xE36C6240419ACA25ULL,
		0x1BB530A616C097F2ULL,
		0x6AEDC9B2DCD35C01ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FEF7596576E533AULL,
		0xB0AABF6E179966E6ULL,
		0xBBE4330587B63E15ULL,
		0x75EE342E00BEE80FULL,
		0xF45744F82E553C8DULL,
		0xF40A0E11D477E296ULL,
		0xE80E1494D6204922ULL,
		0x243DA49F052C02C4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x077E3A9E020502B9ULL,
		0xFA80800666CD86FEULL,
		0xCEFA87914631179DULL,
		0x6534717C0A550814ULL,
		0xA299D08099A6CDFFULL,
		0xEF62542E6D22E78EULL,
		0x33A71C1140A04ECFULL,
		0x46B02513D7A7593CULL
	}};
	sign = 0;
	printf("Test Case 110\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 110 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -110;
	} else {
		printf("Test Case 110 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF53ABA8DCB10A8D7ULL,
		0x32127C3885DA5800ULL,
		0x9E4C661E1A1DABA7ULL,
		0x2874A5530481299EULL,
		0xED92C7DD3040C54BULL,
		0x4E5AB198B5485007ULL,
		0xD170784611CC19CCULL,
		0x950D683E22640552ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x353C1F89E7307204ULL,
		0xF1810D8987616F3BULL,
		0xAA0116C2F46D5FBCULL,
		0x7489F333F89A6D8DULL,
		0x0FCBE9B748FC5D58ULL,
		0x244FD0FEB68B053AULL,
		0x2DF49BE1C9740070ULL,
		0x17C5A5735BA42A76ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBFFE9B03E3E036D3ULL,
		0x40916EAEFE78E8C5ULL,
		0xF44B4F5B25B04BEAULL,
		0xB3EAB21F0BE6BC10ULL,
		0xDDC6DE25E74467F2ULL,
		0x2A0AE099FEBD4ACDULL,
		0xA37BDC644858195CULL,
		0x7D47C2CAC6BFDADCULL
	}};
	sign = 0;
	printf("Test Case 111\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 111 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -111;
	} else {
		printf("Test Case 111 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4E2CBE3C517CF761ULL,
		0xC51872E78FC182CBULL,
		0xF69DCB54A946E5FFULL,
		0x92506D7F1A683821ULL,
		0x2F61E7BCB33F0C09ULL,
		0x79A8C4E13CCE4A14ULL,
		0xB4EA54B3D170E6C8ULL,
		0x528E0807E4A34DAFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC52614BDBDB7AE87ULL,
		0x038B4FBD40CE6267ULL,
		0x25B7176E89CB25A8ULL,
		0x45F0FA44B04FB5BEULL,
		0x7B5935EA8BA3103DULL,
		0x49BC7D8971256886ULL,
		0xCD0792C42CD52435ULL,
		0xDE0298D907C60D7CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8906A97E93C548DAULL,
		0xC18D232A4EF32063ULL,
		0xD0E6B3E61F7BC057ULL,
		0x4C5F733A6A188263ULL,
		0xB408B1D2279BFBCCULL,
		0x2FEC4757CBA8E18DULL,
		0xE7E2C1EFA49BC293ULL,
		0x748B6F2EDCDD4032ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 112\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 112 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -112;
	} else {
		printf("Test Case 112 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF04BF408E6887394ULL,
		0x4D5B56DA2D831C40ULL,
		0xCBF101D37E4EED03ULL,
		0xADB9213CB7936301ULL,
		0x982D0EF7D28266DBULL,
		0x94AEC627A2B7A3DDULL,
		0xE28566E3F55DC2E4ULL,
		0xC77F9E5335A6A569ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6BA03693A507573CULL,
		0x7649599F025F9727ULL,
		0xD050D59F3E51B6F9ULL,
		0xEFE67F5C2F06113BULL,
		0x8C364F0734166CCBULL,
		0xE1401EFE6CFEB0DFULL,
		0xA54285A681BE4F7DULL,
		0x428116162AE3D232ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x84ABBD7541811C58ULL,
		0xD711FD3B2B238519ULL,
		0xFBA02C343FFD3609ULL,
		0xBDD2A1E0888D51C5ULL,
		0x0BF6BFF09E6BFA0FULL,
		0xB36EA72935B8F2FEULL,
		0x3D42E13D739F7366ULL,
		0x84FE883D0AC2D337ULL
	}};
	sign = 0;
	printf("Test Case 113\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 113 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -113;
	} else {
		printf("Test Case 113 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF4E2A38B627A28C7ULL,
		0x6AE94724487D25DBULL,
		0x287D303155B4C3AEULL,
		0x3D3BD58A4B3E4CBBULL,
		0xECBCBF157FB23EEBULL,
		0x5BD18ABB1844655EULL,
		0x2136AD0C93382906ULL,
		0x8F32060CB3281196ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3633B46860BF28CBULL,
		0x3C278E46CA2A4136ULL,
		0xBFC50F7D947F4250ULL,
		0xF8D37AC7D75EB886ULL,
		0x963A4EA384600CDCULL,
		0xF318F6B305296972ULL,
		0x812E997811EBBE2AULL,
		0x4237F98182691E28ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBEAEEF2301BAFFFCULL,
		0x2EC1B8DD7E52E4A5ULL,
		0x68B820B3C135815EULL,
		0x44685AC273DF9434ULL,
		0x56827071FB52320EULL,
		0x68B89408131AFBECULL,
		0xA0081394814C6ADBULL,
		0x4CFA0C8B30BEF36DULL
	}};
	sign = 0;
	printf("Test Case 114\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 114 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -114;
	} else {
		printf("Test Case 114 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x672B75DFFA0FE3F8ULL,
		0x8CE2D5CD856E8BEAULL,
		0x9257F34901960C20ULL,
		0xA77B55DAADB0B7BCULL,
		0xC4225A980644C847ULL,
		0xBC14E22B441E6FB4ULL,
		0x82FE2A3C38821B19ULL,
		0x194519ECE7F25964ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x73768FA5370A3C60ULL,
		0xCE6CA6E236BDD2BCULL,
		0x2075A727A7CCDC3AULL,
		0x44BAE54E18ED4EB3ULL,
		0xCEE108797F8A7E07ULL,
		0xEDF15D10A62EC56FULL,
		0x3B8BF7981A0100D2ULL,
		0xEDA5481B5FDA242EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF3B4E63AC305A798ULL,
		0xBE762EEB4EB0B92DULL,
		0x71E24C2159C92FE5ULL,
		0x62C0708C94C36909ULL,
		0xF541521E86BA4A40ULL,
		0xCE23851A9DEFAA44ULL,
		0x477232A41E811A46ULL,
		0x2B9FD1D188183536ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 115\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 115 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -115;
	} else {
		printf("Test Case 115 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6A7FB10B0B008E38ULL,
		0x7BE7160E55DBD739ULL,
		0x852367FBB74F08D5ULL,
		0x5FAF9318574DB720ULL,
		0x167585A0F006CCADULL,
		0x9C2B82A06E7F03D6ULL,
		0x7FF7CE2C21AAB095ULL,
		0xE15917218EC5E61AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E2A7252749687DFULL,
		0x04A2C7DC26676AA8ULL,
		0x9367EF0EBC210C90ULL,
		0x1ED70EAC4EB1671DULL,
		0x5D28B523C64668EBULL,
		0x89FA98AF3DBB3748ULL,
		0x3738C3CC302ED0C6ULL,
		0x265CD3C3E4EA18AEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2C553EB8966A0659ULL,
		0x77444E322F746C91ULL,
		0xF1BB78ECFB2DFC45ULL,
		0x40D8846C089C5002ULL,
		0xB94CD07D29C063C2ULL,
		0x1230E9F130C3CC8DULL,
		0x48BF0A5FF17BDFCFULL,
		0xBAFC435DA9DBCD6CULL
	}};
	sign = 0;
	printf("Test Case 116\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 116 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -116;
	} else {
		printf("Test Case 116 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE94FA2EE9D5619FCULL,
		0x9BE30F343C7DD31EULL,
		0x9603A2A63E7EAD58ULL,
		0x9105B2C8E153C623ULL,
		0x4A6BB3366F43ED33ULL,
		0xD422522782843265ULL,
		0xAD2988D34945BD1AULL,
		0xB71C8F05DC1753DAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x060B693FDE9906CAULL,
		0xB8542FC55766C11AULL,
		0x07EF1B99812BC4C3ULL,
		0xF13CB9D5F5EA5827ULL,
		0x79675A7D664C658FULL,
		0xFC1A9FC683DA8AF8ULL,
		0xD739AF36BA2639DCULL,
		0xC14249C3393ACA65ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE34439AEBEBD1332ULL,
		0xE38EDF6EE5171204ULL,
		0x8E14870CBD52E894ULL,
		0x9FC8F8F2EB696DFCULL,
		0xD10458B908F787A3ULL,
		0xD807B260FEA9A76CULL,
		0xD5EFD99C8F1F833DULL,
		0xF5DA4542A2DC8974ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 117\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 117 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -117;
	} else {
		printf("Test Case 117 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x00F4BB959E3D7250ULL,
		0x4270EE6E23BAA134ULL,
		0xE9EE19ED4F452A1BULL,
		0xF0132D4EF95E0527ULL,
		0x7F78971D10A5258FULL,
		0x673E487297E45886ULL,
		0xE724634008A16C8DULL,
		0x010319B900A8032AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x93B2EBB8E9F9589CULL,
		0x80B360D8E17E2EEFULL,
		0x32554251D88691C7ULL,
		0xAA91CC6C3C258CDAULL,
		0x1321DE0595F84193ULL,
		0x7EB576BEB5D89B84ULL,
		0x53E77D930D5797D0ULL,
		0x72C00964B70997FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6D41CFDCB44419B4ULL,
		0xC1BD8D95423C7244ULL,
		0xB798D79B76BE9853ULL,
		0x458160E2BD38784DULL,
		0x6C56B9177AACE3FCULL,
		0xE888D1B3E20BBD02ULL,
		0x933CE5ACFB49D4BCULL,
		0x8E431054499E6B2CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 118\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 118 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -118;
	} else {
		printf("Test Case 118 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xDC551C22C5FD9140ULL,
		0x541FDA74BDB9D9B4ULL,
		0x5FA0BFF1501A6D83ULL,
		0x01CB0FFFB0EAC013ULL,
		0xC94F6EA192E901EDULL,
		0x52A44D6D5BAEA9D9ULL,
		0x639996E546AE80EAULL,
		0x87ECFBFA2C8988AAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0620BEB50F1955BFULL,
		0xB269361E77864A6AULL,
		0xAB98E4D1DBFD6143ULL,
		0x3AB44F21F3C85274ULL,
		0x059D526215678E37ULL,
		0xB36DA8598C77A243ULL,
		0x6CAC34FB52A7597FULL,
		0x2FAF898AE21BBC7FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD6345D6DB6E43B81ULL,
		0xA1B6A45646338F4AULL,
		0xB407DB1F741D0C3FULL,
		0xC716C0DDBD226D9EULL,
		0xC3B21C3F7D8173B5ULL,
		0x9F36A513CF370796ULL,
		0xF6ED61E9F407276AULL,
		0x583D726F4A6DCC2AULL
	}};
	sign = 0;
	printf("Test Case 119\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 119 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -119;
	} else {
		printf("Test Case 119 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x980E1FFA13DB603BULL,
		0x9C15FD978D14D5C7ULL,
		0x26A669CCC8D0F228ULL,
		0x74246BE17FB3C89CULL,
		0xCC2B21528BBEA173ULL,
		0x3897199126FF3D8FULL,
		0x55047A2EB9AFADE3ULL,
		0xEC9C9B14C63D62C1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA9ECAEA378D6ED7ULL,
		0x6B1E2C50AD41814EULL,
		0x8C6DB6438E03E61FULL,
		0xC3CDCBCC94B0DAE7ULL,
		0xF513181EFE5631AAULL,
		0x79DA194309272016ULL,
		0xFAF32874F275C69BULL,
		0x9A0125BDAB52175EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDD6F550FDC4DF164ULL,
		0x30F7D146DFD35478ULL,
		0x9A38B3893ACD0C09ULL,
		0xB056A014EB02EDB4ULL,
		0xD71809338D686FC8ULL,
		0xBEBD004E1DD81D78ULL,
		0x5A1151B9C739E747ULL,
		0x529B75571AEB4B62ULL
	}};
	sign = 0;
	printf("Test Case 120\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 120 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -120;
	} else {
		printf("Test Case 120 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0F0138347F13CFCEULL,
		0x810E2FD25DEE4341ULL,
		0x8D56606FB361B3DAULL,
		0xAB769BA48499AF19ULL,
		0x26E76F7D95D346D7ULL,
		0xC5505C5578DF4A4CULL,
		0x14D9E03BDD40C76BULL,
		0x53EC6E0BEE0269B9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DAC5A319CBDF876ULL,
		0xB310AE0E5D4FE16BULL,
		0xC7E8B82ECF329367ULL,
		0x9D4CB4C38A37F6CBULL,
		0xBD1FF5EF27901DB7ULL,
		0xD0A327C849AAECC3ULL,
		0x679B76E7D90E0A2EULL,
		0x36BC5CFCCD75AB5BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8154DE02E255D758ULL,
		0xCDFD81C4009E61D5ULL,
		0xC56DA840E42F2072ULL,
		0x0E29E6E0FA61B84DULL,
		0x69C7798E6E432920ULL,
		0xF4AD348D2F345D88ULL,
		0xAD3E69540432BD3CULL,
		0x1D30110F208CBE5DULL
	}};
	sign = 0;
	printf("Test Case 121\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 121 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -121;
	} else {
		printf("Test Case 121 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xAD0EEF953C976E46ULL,
		0x8F775992EAA273B6ULL,
		0xDDAEA1F3130959F8ULL,
		0xAB2CC19AB3A4E4F5ULL,
		0x4D2ABDC70A6C01A4ULL,
		0xAC0B0AD8EA121974ULL,
		0x1C422A36B1140064ULL,
		0xB0254FA07B210EACULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F675B67920B0BC3ULL,
		0x4DCC0F77416F8E83ULL,
		0x9FDE0E0A8BB896F5ULL,
		0xAC8ACC43807F632BULL,
		0x6B9D968D5AE684B3ULL,
		0x7CC3CAE0E6E04ECCULL,
		0x4253791C511DC5EDULL,
		0x238946A5E755E297ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0DA7942DAA8C6283ULL,
		0x41AB4A1BA932E533ULL,
		0x3DD093E88750C303ULL,
		0xFEA1F557332581CAULL,
		0xE18D2739AF857CF0ULL,
		0x2F473FF80331CAA7ULL,
		0xD9EEB11A5FF63A77ULL,
		0x8C9C08FA93CB2C14ULL
	}};
	sign = 0;
	printf("Test Case 122\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 122 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -122;
	} else {
		printf("Test Case 122 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x52CDFD3AA04F0AADULL,
		0x57D42C81F53F1107ULL,
		0x0F69C3652658708EULL,
		0x9C1896DC37ED7BA0ULL,
		0x81C678E64BF18BD8ULL,
		0x4FE3AC5251288178ULL,
		0x6B6E12F380729AF9ULL,
		0x7F960DB1AC75F0A3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x98125B3CA6DC4C56ULL,
		0x3BF2A597C64B18E6ULL,
		0xC96B753ECE74EDEAULL,
		0xEE360DCEFCDB8821ULL,
		0x492E1B6C6DD1B899ULL,
		0x4B132A2D06BEC924ULL,
		0xE919AFB79B4AFA3DULL,
		0x9707395360B42F7CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBABBA1FDF972BE57ULL,
		0x1BE186EA2EF3F820ULL,
		0x45FE4E2657E382A4ULL,
		0xADE2890D3B11F37EULL,
		0x38985D79DE1FD33EULL,
		0x04D082254A69B854ULL,
		0x8254633BE527A0BCULL,
		0xE88ED45E4BC1C126ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 123\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 123 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -123;
	} else {
		printf("Test Case 123 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x09C35180AD812D66ULL,
		0xF32385CBCF32E1E7ULL,
		0xDCD1D8F2A80A1D37ULL,
		0xED5EFCBA45C540E8ULL,
		0x9F214BB6C74D720DULL,
		0x87A350BC38BF0CE3ULL,
		0x06E77632E86E738FULL,
		0x306B51B91B923137ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A0F5F238A829A81ULL,
		0x975B4BF03B150BC1ULL,
		0xEBD7B7E64DE20CB7ULL,
		0x7A0A82A74DCB9E36ULL,
		0x25C10F3DD8AE03BFULL,
		0x8A9DBD890BE6AFC8ULL,
		0xE155003E31FC3FE0ULL,
		0xF1CD9C53EDABB5BFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9FB3F25D22FE92E5ULL,
		0x5BC839DB941DD625ULL,
		0xF0FA210C5A281080ULL,
		0x73547A12F7F9A2B1ULL,
		0x79603C78EE9F6E4EULL,
		0xFD0593332CD85D1BULL,
		0x259275F4B67233AEULL,
		0x3E9DB5652DE67B77ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 124\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 124 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -124;
	} else {
		printf("Test Case 124 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC752C90FDFA34E2EULL,
		0x8BE6555716D8C279ULL,
		0x668614EEEC703F68ULL,
		0xA09946CEC171399EULL,
		0x06E178B5CD5F56A2ULL,
		0x786A8E0529DF9AE5ULL,
		0x6FC6A5A162132AA6ULL,
		0x4557DAB723E30E76ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2728F316A2D91A5AULL,
		0xB600A9FB21A13EB7ULL,
		0xB4712CFF33037AF2ULL,
		0x7AD2458F86391394ULL,
		0xEE8132412690915DULL,
		0x6FC06E32A4F1430FULL,
		0x250D1F37B6757148ULL,
		0x2C9A51805AAD94AAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA029D5F93CCA33D4ULL,
		0xD5E5AB5BF53783C2ULL,
		0xB214E7EFB96CC475ULL,
		0x25C7013F3B382609ULL,
		0x18604674A6CEC545ULL,
		0x08AA1FD284EE57D5ULL,
		0x4AB98669AB9DB95EULL,
		0x18BD8936C93579CCULL
	}};
	sign = 0;
	printf("Test Case 125\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 125 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -125;
	} else {
		printf("Test Case 125 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x087D87A246CE2C6EULL,
		0xBDF89A9C51724F73ULL,
		0xAA32207E7BADB460ULL,
		0x5889A5B90D27D0B2ULL,
		0xD955EDD503F76F3EULL,
		0x77EE0B349F5954D2ULL,
		0x826E04C32F993C6CULL,
		0x227C967F51D0797BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x53D220E4D2778593ULL,
		0x8C1CA010AAB926FAULL,
		0x104099D859D54F73ULL,
		0xD818B934344331D0ULL,
		0x10FD554D8562FF06ULL,
		0x6286E3249115D80BULL,
		0x940C5068204AD244ULL,
		0x40CB75F0F9FF48D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB4AB66BD7456A6DBULL,
		0x31DBFA8BA6B92878ULL,
		0x99F186A621D864EDULL,
		0x8070EC84D8E49EE2ULL,
		0xC85898877E947037ULL,
		0x156728100E437CC7ULL,
		0xEE61B45B0F4E6A28ULL,
		0xE1B1208E57D130A4ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 126\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 126 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -126;
	} else {
		printf("Test Case 126 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD0A84DD8FD8EEC34ULL,
		0x0DF9D31220F639A4ULL,
		0x612E67639099E619ULL,
		0x0539D0705F8B91A2ULL,
		0x9C26E7C92A42A9A0ULL,
		0x448BC094B0A8AA5CULL,
		0xFB9031074DD0E333ULL,
		0x297B56B20DA589BBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x98C92B1670CBAB53ULL,
		0x89D1B4A65926387CULL,
		0x19F511534846BDCBULL,
		0x90DCB8003D5E8365ULL,
		0x3D0BB5D5CD8CC48EULL,
		0xBB71F4DBB7CDC53DULL,
		0x9694EBC57DFA482CULL,
		0x8921A7B8A83E35BEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x37DF22C28CC340E1ULL,
		0x84281E6BC7D00128ULL,
		0x473956104853284DULL,
		0x745D1870222D0E3DULL,
		0x5F1B31F35CB5E511ULL,
		0x8919CBB8F8DAE51FULL,
		0x64FB4541CFD69B06ULL,
		0xA059AEF9656753FDULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 127\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 127 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -127;
	} else {
		printf("Test Case 127 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE510019A4C2179BEULL,
		0x3DDD3DFFEDE390F3ULL,
		0x781F9F889ED7FDF5ULL,
		0xD47B3D97F44BF029ULL,
		0xC74EC81CEC669153ULL,
		0x1CDF3799B5C5DFCFULL,
		0x4EF50B2E68932860ULL,
		0x7CBA29500B9295FDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BF6BA4E64219B63ULL,
		0x78656BB186DF34C7ULL,
		0x15F2C4707BE6FB42ULL,
		0xEFB60DADD4616EBCULL,
		0xFDB5A77DF4FCD39AULL,
		0xB4C49156A0E45E4DULL,
		0x41F98708D342A8ACULL,
		0xA428860681A01129ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9919474BE7FFDE5BULL,
		0xC577D24E67045C2CULL,
		0x622CDB1822F102B2ULL,
		0xE4C52FEA1FEA816DULL,
		0xC999209EF769BDB8ULL,
		0x681AA64314E18181ULL,
		0x0CFB842595507FB3ULL,
		0xD891A34989F284D4ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 128\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 128 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -128;
	} else {
		printf("Test Case 128 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x357E57B7905E0D2CULL,
		0xFD69A258C0B23541ULL,
		0x369C54749FE7418FULL,
		0xC7122E542E68BC05ULL,
		0x2EC4C282FC570DCAULL,
		0x6DAF0AB87B952FF3ULL,
		0x041D193405384111ULL,
		0x10C3154FBE932A60ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6B765B724BFB13EULL,
		0xA41085A06ED24A0BULL,
		0xFEF9B55F3625C02EULL,
		0xE687398A4CBD1E1AULL,
		0x79500081969FA538ULL,
		0x757103BE4E4ADD7EULL,
		0x1B917C039A88D464ULL,
		0x1D8538B2ED9D6773ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6EC6F2006B9E5BEEULL,
		0x59591CB851DFEB35ULL,
		0x37A29F1569C18161ULL,
		0xE08AF4C9E1AB9DEAULL,
		0xB574C20165B76891ULL,
		0xF83E06FA2D4A5274ULL,
		0xE88B9D306AAF6CACULL,
		0xF33DDC9CD0F5C2ECULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 129\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 129 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -129;
	} else {
		printf("Test Case 129 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x12892E60C72DC835ULL,
		0x1C22564A57754338ULL,
		0xD74DB0C21A97499BULL,
		0xF3E14F25E32BB51DULL,
		0x91912C7340F93537ULL,
		0x2C8B84D3F65E244DULL,
		0xE5D7EC4097B1BAB9ULL,
		0x648CCA0FE5E3341AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B4798542F3B10C7ULL,
		0x3D67216117A5D7AAULL,
		0x187496B61F9ACE11ULL,
		0x02A51BFA1EA3AAE4ULL,
		0x7BE7374D0BA3E2D9ULL,
		0x0458E1E4EC658894ULL,
		0x3EEE9115E3C0135AULL,
		0x04F888353E92ECB3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8741960C97F2B76EULL,
		0xDEBB34E93FCF6B8DULL,
		0xBED91A0BFAFC7B89ULL,
		0xF13C332BC4880A39ULL,
		0x15A9F5263555525EULL,
		0x2832A2EF09F89BB9ULL,
		0xA6E95B2AB3F1A75FULL,
		0x5F9441DAA7504767ULL
	}};
	sign = 0;
	printf("Test Case 130\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 130 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -130;
	} else {
		printf("Test Case 130 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x787E96FFD4614D43ULL,
		0xF05157C8DEE7EB9FULL,
		0x5087A71FA11E205FULL,
		0x5EA0ABA754417F5BULL,
		0x463EF05AE200C66DULL,
		0x3BE67D71C0EA4261ULL,
		0x7295D0AF09CE0343ULL,
		0x943285CE451990D3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA10EA3CD2129B193ULL,
		0x977546E276D72986ULL,
		0x7A4F080A541DB71EULL,
		0x3913652160010A13ULL,
		0xB265EA8E7B5C7CF6ULL,
		0x601361DAB81B0AEFULL,
		0xF34E2A61870E5B0AULL,
		0x2F60557BB5699526ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD76FF332B3379BB0ULL,
		0x58DC10E66810C218ULL,
		0xD6389F154D006941ULL,
		0x258D4685F4407547ULL,
		0x93D905CC66A44977ULL,
		0xDBD31B9708CF3771ULL,
		0x7F47A64D82BFA838ULL,
		0x64D230528FAFFBACULL
	}};
	sign = 0;
	printf("Test Case 131\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 131 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -131;
	} else {
		printf("Test Case 131 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x34CE7A8588ECA0E3ULL,
		0xF2B2B207C8CF407CULL,
		0x697C5806D35363CEULL,
		0x390C861D85206F7AULL,
		0xBF928D812525DC98ULL,
		0x6737ABB8E02C1890ULL,
		0x6B9F8D735DE3FFF7ULL,
		0xF897F1D5B5D59E86ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x15AAC074D7156B18ULL,
		0x86724E38905B2C32ULL,
		0xCF446E757B81146BULL,
		0xFF198940170DC558ULL,
		0x415B6EBD2F58A34BULL,
		0xE06013F84A3C7932ULL,
		0x8C17C87F7F0E7CCAULL,
		0x7379C275D9732011ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1F23BA10B1D735CBULL,
		0x6C4063CF3874144AULL,
		0x9A37E99157D24F63ULL,
		0x39F2FCDD6E12AA21ULL,
		0x7E371EC3F5CD394CULL,
		0x86D797C095EF9F5EULL,
		0xDF87C4F3DED5832CULL,
		0x851E2F5FDC627E74ULL
	}};
	sign = 0;
	printf("Test Case 132\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 132 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -132;
	} else {
		printf("Test Case 132 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xFE161A5C108B38ABULL,
		0xD34A79B090B7FDCDULL,
		0x19076C93E3925815ULL,
		0xBFD8115327254270ULL,
		0x615533174B64FBE7ULL,
		0xC561F8DB67509098ULL,
		0x267D6317B0BC491DULL,
		0x4D3808A87844734CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x54D792D8FFD95837ULL,
		0x73FDD6505FF0971AULL,
		0x292EE16C9CAF87ACULL,
		0x7042E11CDF0A68B7ULL,
		0xDC204BAFE07AEB4BULL,
		0xF2C4940BD51C90DBULL,
		0xD01156ADDF499109ULL,
		0xF93B90236B3056E0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA93E878310B1E074ULL,
		0x5F4CA36030C766B3ULL,
		0xEFD88B2746E2D069ULL,
		0x4F953036481AD9B8ULL,
		0x8534E7676AEA109CULL,
		0xD29D64CF9233FFBCULL,
		0x566C0C69D172B813ULL,
		0x53FC78850D141C6BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 133\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 133 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -133;
	} else {
		printf("Test Case 133 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xCBD8C5C83A8EDE3AULL,
		0x5578046ECCB632C1ULL,
		0x4970C464C37BF86AULL,
		0x090D72D7D3F38F60ULL,
		0xFD96D470D6B81650ULL,
		0xF119565E239281A0ULL,
		0x4275F07B3447FD88ULL,
		0xCD31517622BCB9D6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x819CF3ADD582A9C9ULL,
		0xFC9BBF254700FE5FULL,
		0x92E070E5A967B993ULL,
		0xCFB45815D7FF1C2FULL,
		0xA93040AED04A72F4ULL,
		0x0CC64749473277A5ULL,
		0xDF98CB647E96A0B3ULL,
		0xA610DBCE94FC3DA6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4A3BD21A650C3471ULL,
		0x58DC454985B53462ULL,
		0xB690537F1A143ED6ULL,
		0x39591AC1FBF47330ULL,
		0x546693C2066DA35BULL,
		0xE4530F14DC6009FBULL,
		0x62DD2516B5B15CD5ULL,
		0x272075A78DC07C2FULL
	}};
	sign = 0;
	printf("Test Case 134\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 134 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -134;
	} else {
		printf("Test Case 134 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x850EB5BB6B141450ULL,
		0xD540A00B962B9686ULL,
		0x4828E88C0844A1D2ULL,
		0x45ABA298493842F6ULL,
		0xA3D7AABCFC45733EULL,
		0xEF2A06291B0D7135ULL,
		0xF994A13754EA9981ULL,
		0x750D557B1959D3C1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E965C5B29CA7762ULL,
		0xFED0BB95C9A69DACULL,
		0xD4A238A84D93144EULL,
		0xF1FB5DDAC876990CULL,
		0x445B239F0EF52FEFULL,
		0x4E7169CF66E440E5ULL,
		0x6B4913FA054DF0A2ULL,
		0x32D7E13409A8813FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1678596041499CEEULL,
		0xD66FE475CC84F8DAULL,
		0x7386AFE3BAB18D83ULL,
		0x53B044BD80C1A9E9ULL,
		0x5F7C871DED50434EULL,
		0xA0B89C59B4293050ULL,
		0x8E4B8D3D4F9CA8DFULL,
		0x423574470FB15282ULL
	}};
	sign = 0;
	printf("Test Case 135\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 135 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -135;
	} else {
		printf("Test Case 135 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xBF1FC35EF84AE388ULL,
		0x4BE51B47946B0125ULL,
		0xADDE98028212CA47ULL,
		0x9312328F3B0BA645ULL,
		0x81E9D73FE3A7DD07ULL,
		0x9344BC61406146A0ULL,
		0x65555D89D8BD4DD4ULL,
		0x063956C530BE65D6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE18294B7135C560ULL,
		0x06DE2C4C431E3117ULL,
		0x230B4ECFEB57E4DCULL,
		0x2BCBF1AD7E927804ULL,
		0xE859DA08325D3FA0ULL,
		0xB9D8DCC5C9C0BD45ULL,
		0xA2BC41EC52C09FE9ULL,
		0x92CD17C30738AB84ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE1079A1387151E28ULL,
		0x4506EEFB514CD00DULL,
		0x8AD3493296BAE56BULL,
		0x674640E1BC792E41ULL,
		0x998FFD37B14A9D67ULL,
		0xD96BDF9B76A0895AULL,
		0xC2991B9D85FCADEAULL,
		0x736C3F022985BA51ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 136\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 136 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -136;
	} else {
		printf("Test Case 136 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE761CA2468BC0C9FULL,
		0xC82839F02E93409FULL,
		0xCC0D22084FBCAC9CULL,
		0xA6A65D996A7FB8D9ULL,
		0x7C25C65996F0DEF6ULL,
		0x8AE8AC10E5EBFF8EULL,
		0x01B4862B661BE0EDULL,
		0x32DA6CCCB1DCDB8FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x80E80D3576202820ULL,
		0x517C367AA8656F85ULL,
		0xDB8CA5189245EA5FULL,
		0x522EF166EAA6CCB4ULL,
		0x0C893858A882EE2AULL,
		0xFE5FB4FDD58F4BAEULL,
		0x8E31D18175D0CC8DULL,
		0xC75C938C44E8F43DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6679BCEEF29BE47FULL,
		0x76AC0375862DD11AULL,
		0xF0807CEFBD76C23DULL,
		0x54776C327FD8EC24ULL,
		0x6F9C8E00EE6DF0CCULL,
		0x8C88F713105CB3E0ULL,
		0x7382B4A9F04B145FULL,
		0x6B7DD9406CF3E751ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 137\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 137 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -137;
	} else {
		printf("Test Case 137 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4F91D7ABF61F44CAULL,
		0xB16CAB3AB693EC9CULL,
		0xFFB976E143E8DB31ULL,
		0x004CF6745E8E6A52ULL,
		0xCEF93E0CA99BB037ULL,
		0x9DB5C7CBDBB45AABULL,
		0x29D67D790C1F0EE7ULL,
		0xB145D0BEEAB336CEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x661E82B65E77F685ULL,
		0x9A003792C4D30A8FULL,
		0xD897890B00E8FBF8ULL,
		0xED347E3F713BB9F7ULL,
		0x1BA7D2AAB8917F0DULL,
		0xCF2CBC437A62281FULL,
		0x67D0499080DB01E0ULL,
		0x631120381958E781ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE97354F597A74E45ULL,
		0x176C73A7F1C0E20CULL,
		0x2721EDD642FFDF39ULL,
		0x13187834ED52B05BULL,
		0xB3516B61F10A3129ULL,
		0xCE890B886152328CULL,
		0xC20633E88B440D06ULL,
		0x4E34B086D15A4F4CULL
	}};
	sign = 0;
	printf("Test Case 138\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 138 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -138;
	} else {
		printf("Test Case 138 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x2852D96D1A6922F6ULL,
		0x553F5149CDF814D6ULL,
		0x94D794F0F26D01F6ULL,
		0xE603F2AD35561771ULL,
		0x07690F8E202C57D9ULL,
		0x26910F1E67E27367ULL,
		0x4EA5ED0E79FADFF3ULL,
		0xF920A0A887CFBFBFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2880DD92CA10949ULL,
		0xCAD7DC2FF6DB3B8FULL,
		0x5136ABD16FE702DCULL,
		0x705CE71BC2D7892CULL,
		0x27698A1066DDD93FULL,
		0x3B80D2F0EA70BF89ULL,
		0x557B86C41C9237B8ULL,
		0x5FDD886423CD8A83ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x65CACB93EDC819ADULL,
		0x8A677519D71CD946ULL,
		0x43A0E91F8285FF19ULL,
		0x75A70B91727E8E45ULL,
		0xDFFF857DB94E7E9AULL,
		0xEB103C2D7D71B3DDULL,
		0xF92A664A5D68A83AULL,
		0x994318446402353BULL
	}};
	sign = 0;
	printf("Test Case 139\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 139 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -139;
	} else {
		printf("Test Case 139 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x55BCD3AD796E630EULL,
		0x745F86911913C664ULL,
		0xC6221204FC935118ULL,
		0x73F1839B655C1123ULL,
		0x9BF41CE24042BCEFULL,
		0x38251BB471A84C15ULL,
		0x229C2AE7979CB5C1ULL,
		0xD8CDBB8417EBF5EEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xACF0B5B512CA8EC0ULL,
		0x950BCD82838EADC4ULL,
		0x1BCB6CCB083F3DB6ULL,
		0xD629B95554F2FB6FULL,
		0xAFA1E2602FFC62BAULL,
		0xC1B6B7E505777FD8ULL,
		0x0F067648BD65C038ULL,
		0x2E3936B9F58341EBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA8CC1DF866A3D44EULL,
		0xDF53B90E9585189FULL,
		0xAA56A539F4541361ULL,
		0x9DC7CA46106915B4ULL,
		0xEC523A8210465A34ULL,
		0x766E63CF6C30CC3CULL,
		0x1395B49EDA36F588ULL,
		0xAA9484CA2268B403ULL
	}};
	sign = 0;
	printf("Test Case 140\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 140 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -140;
	} else {
		printf("Test Case 140 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF7BC53965F06C80CULL,
		0x42DF98BB837C2A1EULL,
		0xD654CFDA7FAC0C76ULL,
		0x66703A887CC223C8ULL,
		0x472B080BD07D2773ULL,
		0x7DA41BE167734DF1ULL,
		0xD74B711535D131A1ULL,
		0x2353E575AF94C8DDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FA512D623A06AACULL,
		0x56C7BE4CB3DE1763ULL,
		0xB77A76064348791DULL,
		0xDE0CC816192387A3ULL,
		0x2CD59A54D069E308ULL,
		0x02D2780296DA7F6AULL,
		0x32ABFBF118DA33C7ULL,
		0xD0016CF63AECB357ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x981740C03B665D60ULL,
		0xEC17DA6ECF9E12BBULL,
		0x1EDA59D43C639358ULL,
		0x88637272639E9C25ULL,
		0x1A556DB70013446AULL,
		0x7AD1A3DED098CE87ULL,
		0xA49F75241CF6FDDAULL,
		0x5352787F74A81586ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 141\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 141 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -141;
	} else {
		printf("Test Case 141 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x454227EC755BA742ULL,
		0x9B2383D990F5D975ULL,
		0x0B1E88182D4ED615ULL,
		0x8D481C5D493A59ACULL,
		0x26CAEAF9CE13C2FEULL,
		0x4C1C0A3447463CCBULL,
		0xC2D5FA6204C382F4ULL,
		0x0E3833EA25ADA26BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDAD3B04E6BE8312CULL,
		0x90F821A268E813B8ULL,
		0xD01C142FC4E84E12ULL,
		0x5D4895EA7D176240ULL,
		0x408EBD2B80BE0424ULL,
		0x0B476AB1804F23ABULL,
		0x790E1209646E2786ULL,
		0xD9847869F83F5876ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6A6E779E09737616ULL,
		0x0A2B6237280DC5BCULL,
		0x3B0273E868668803ULL,
		0x2FFF8672CC22F76BULL,
		0xE63C2DCE4D55BEDAULL,
		0x40D49F82C6F7191FULL,
		0x49C7E858A0555B6EULL,
		0x34B3BB802D6E49F5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 142\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 142 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -142;
	} else {
		printf("Test Case 142 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xDD027DAFE341962DULL,
		0xEF8061C8E34B2D6FULL,
		0x54F38F48CDA4F00BULL,
		0xE96C8D6741B1E77AULL,
		0x8511380FA992F442ULL,
		0xB4D9BF6F5CA6501FULL,
		0x6FB0F7F54D6972A7ULL,
		0x8A34DBF50C393177ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC50C271DB18A7E2ULL,
		0x373A77705452FE1EULL,
		0xEF5F23C27FAC520CULL,
		0xF0943643767FDF9BULL,
		0xC6EB3335425B286DULL,
		0x885A85A2DC8F21D6ULL,
		0x34E5CD25AF45E583ULL,
		0x5A3BE98792173027ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE0B1BB3E0828EE4BULL,
		0xB845EA588EF82F50ULL,
		0x65946B864DF89DFFULL,
		0xF8D85723CB3207DEULL,
		0xBE2604DA6737CBD4ULL,
		0x2C7F39CC80172E48ULL,
		0x3ACB2ACF9E238D24ULL,
		0x2FF8F26D7A220150ULL
	}};
	sign = 0;
	printf("Test Case 143\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 143 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -143;
	} else {
		printf("Test Case 143 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xFFBB56268C8C55F9ULL,
		0xE4AE71BC90B3A9CFULL,
		0xF3D5E06CDEEBB346ULL,
		0x22C91D42F29E500FULL,
		0x2DA546BEC3F49390ULL,
		0xDEFC45B3BA1C09E9ULL,
		0xB026ED9EA742813CULL,
		0xEA210E8015B9869DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB7E3E4972C3F25BULL,
		0xE682C67B0FC831DFULL,
		0x1B3062789A787CF6ULL,
		0xFDC0CB4DC51A9C17ULL,
		0x399514B10868996EULL,
		0xD14B61C939E6865BULL,
		0xC58FED69EBC44AA3ULL,
		0x2385796E98A9E578ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x443D17DD19C8639EULL,
		0xFE2BAB4180EB77F0ULL,
		0xD8A57DF44473364FULL,
		0x250851F52D83B3F8ULL,
		0xF410320DBB8BFA21ULL,
		0x0DB0E3EA8035838DULL,
		0xEA970034BB7E3699ULL,
		0xC69B95117D0FA124ULL
	}};
	sign = 0;
	printf("Test Case 144\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 144 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -144;
	} else {
		printf("Test Case 144 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x415D7BFF9BA29C8BULL,
		0x754AD3862BB70302ULL,
		0x7ACB4207C55EF860ULL,
		0x303142B2105C1762ULL,
		0xFB270FA8C94C72A5ULL,
		0x2A962BDE45C4AD77ULL,
		0xCB456A9ED572AED4ULL,
		0x48DF54798813C671ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x185E9B6BB57A0085ULL,
		0x4274F14909E1DCE6ULL,
		0x689C94A12EF1A974ULL,
		0xF1E92099CD08BF5DULL,
		0xEC11B37678A8F98DULL,
		0x2CBA740B64BD93B3ULL,
		0x8456959C30830B06ULL,
		0xE99657FD2A9F2716ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x28FEE093E6289C06ULL,
		0x32D5E23D21D5261CULL,
		0x122EAD66966D4EECULL,
		0x3E48221843535805ULL,
		0x0F155C3250A37917ULL,
		0xFDDBB7D2E10719C4ULL,
		0x46EED502A4EFA3CDULL,
		0x5F48FC7C5D749F5BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 145\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 145 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -145;
	} else {
		printf("Test Case 145 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x3F9CA8532822912DULL,
		0x94D0EC5B7AFDD741ULL,
		0x6AF4463C30FF34EBULL,
		0x7C2358CA20C29266ULL,
		0xD43815C44F6A836FULL,
		0x7BFE398687440337ULL,
		0xBB32220E05B09804ULL,
		0x8647293E3014C8DEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x818F37EA039FBE39ULL,
		0x491709B28E7A9901ULL,
		0x57B6C0F4371A9260ULL,
		0xFCF5EEC9393645C8ULL,
		0xD0EED319283230B9ULL,
		0x8654A8FE884B890CULL,
		0xF6F44941DF5C3E65ULL,
		0x564786FD4B018CEFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBE0D70692482D2F4ULL,
		0x4BB9E2A8EC833E3FULL,
		0x133D8547F9E4A28BULL,
		0x7F2D6A00E78C4C9EULL,
		0x034942AB273852B5ULL,
		0xF5A99087FEF87A2BULL,
		0xC43DD8CC2654599EULL,
		0x2FFFA240E5133BEEULL
	}};
	sign = 0;
	printf("Test Case 146\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 146 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -146;
	} else {
		printf("Test Case 146 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC7C989D86C1C470FULL,
		0x8004AB70936144A2ULL,
		0x115A8EEFD390E578ULL,
		0xFC4C739996D108A0ULL,
		0x976E3D0179F73033ULL,
		0xEAFC3C20D7B5B300ULL,
		0xAB8EEC4D34139D62ULL,
		0x3CE307C57E366181ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x89D04765C06B3BB5ULL,
		0x131B7394CE1B0775ULL,
		0x61DACA45E6362603ULL,
		0xEFE641E53D9463A1ULL,
		0x94551F99CDBF7471ULL,
		0x1D34E62AD6BF08A7ULL,
		0x1F9D83E74CB5522CULL,
		0x7A9ADD7B3A268FBEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3DF94272ABB10B5AULL,
		0x6CE937DBC5463D2DULL,
		0xAF7FC4A9ED5ABF75ULL,
		0x0C6631B4593CA4FEULL,
		0x03191D67AC37BBC2ULL,
		0xCDC755F600F6AA59ULL,
		0x8BF16865E75E4B36ULL,
		0xC2482A4A440FD1C3ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 147\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 147 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -147;
	} else {
		printf("Test Case 147 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF1F743072633249CULL,
		0x64B62DB4AE23C46BULL,
		0xE6F022E6266B932CULL,
		0x5DC17AFFF68CBE8FULL,
		0xD53AFAC5163FE281ULL,
		0xE77B798CD2F6A513ULL,
		0xBB2CC74FE52563FAULL,
		0x38BF9FEEBF04E886ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9ECB6A35A8C9AEC8ULL,
		0xD3112D72AC854881ULL,
		0xF130CC9E100AAC5DULL,
		0xC71101EDC4F8F10BULL,
		0x49AC4E8BBEE1A970ULL,
		0xF12F2BFF533F3773ULL,
		0x4BBD6E986E852A19ULL,
		0x8433ECB5716E9192ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x532BD8D17D6975D4ULL,
		0x91A50042019E7BEAULL,
		0xF5BF56481660E6CEULL,
		0x96B079123193CD83ULL,
		0x8B8EAC39575E3910ULL,
		0xF64C4D8D7FB76DA0ULL,
		0x6F6F58B776A039E0ULL,
		0xB48BB3394D9656F4ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 148\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 148 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -148;
	} else {
		printf("Test Case 148 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x00EF0D81C52C689DULL,
		0x768DDDEDDD1210E0ULL,
		0x94B433BFB334C741ULL,
		0xB2CC347A142FDD86ULL,
		0xCC0BF3DF3A999E53ULL,
		0x7D8973B2C4156CB2ULL,
		0xDD08641BD4E6A788ULL,
		0x0612033F482F1558ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DB1C71718EB690CULL,
		0xA9EB3EFABEF167F9ULL,
		0x9E2D686B84490120ULL,
		0x5F8C9A0F66A225D3ULL,
		0x9359F4F75F8B9601ULL,
		0x22519675CE14FFCCULL,
		0x8974FFD4D5C01FA2ULL,
		0x1361D7818F306B3AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD33D466AAC40FF91ULL,
		0xCCA29EF31E20A8E6ULL,
		0xF686CB542EEBC620ULL,
		0x533F9A6AAD8DB7B2ULL,
		0x38B1FEE7DB0E0852ULL,
		0x5B37DD3CF6006CE6ULL,
		0x53936446FF2687E6ULL,
		0xF2B02BBDB8FEAA1EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 149\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 149 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -149;
	} else {
		printf("Test Case 149 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD2125E55B626FDC1ULL,
		0xB9C46CFEDEB1E2B8ULL,
		0x762E5AD96FE7C4CAULL,
		0x6E46D1E2428CB3E2ULL,
		0x631DA21E3F20B92FULL,
		0xCC97451FFD0CC486ULL,
		0x479597D12322A21DULL,
		0xD9800A393E486CC7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x23B1DD0625824C40ULL,
		0xB08E6842BEA4C376ULL,
		0xC0AF8B8DFEF656C7ULL,
		0x7420E390961920FFULL,
		0xD1CEFB9A29D537CAULL,
		0x4BA7B3C397CF7651ULL,
		0x4E0680FE544C2450ULL,
		0x33489F65A804381DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAE60814F90A4B181ULL,
		0x093604BC200D1F42ULL,
		0xB57ECF4B70F16E03ULL,
		0xFA25EE51AC7392E2ULL,
		0x914EA684154B8164ULL,
		0x80EF915C653D4E34ULL,
		0xF98F16D2CED67DCDULL,
		0xA6376AD3964434A9ULL
	}};
	sign = 0;
	printf("Test Case 150\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 150 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -150;
	} else {
		printf("Test Case 150 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x32A8AED113B9E0B5ULL,
		0x542143D739C42D27ULL,
		0x5A78E3FDFAA70D24ULL,
		0x2A45973D8BA4A68CULL,
		0xBF33C95029821032ULL,
		0x7B5645D5322FD014ULL,
		0x7487FB7191F64E73ULL,
		0xAB20F748DC3E6292ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3117075113A49325ULL,
		0x0429D5A5FB2D901FULL,
		0x6291D459C3CC3509ULL,
		0x61FEFCBFC9FC4942ULL,
		0xAD60928478DFC7B8ULL,
		0x3A4A6061B771E8D2ULL,
		0xFEDFE7E585504003ULL,
		0xF3E623CC8186EE02ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0191A78000154D90ULL,
		0x4FF76E313E969D08ULL,
		0xF7E70FA436DAD81BULL,
		0xC8469A7DC1A85D49ULL,
		0x11D336CBB0A24879ULL,
		0x410BE5737ABDE742ULL,
		0x75A8138C0CA60E70ULL,
		0xB73AD37C5AB7748FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 151\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 151 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -151;
	} else {
		printf("Test Case 151 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x810F6E033EAFF4AEULL,
		0x8C9FC988E180C274ULL,
		0xA46DC4796C4BE221ULL,
		0x9EF5BF846800FB5EULL,
		0xE4EA87980C9CF827ULL,
		0x36DCC9CCD9ACC06CULL,
		0xB2EC2ADBB24D6186ULL,
		0x3F02DF054170D6B2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x68C26AB546E20F5BULL,
		0xC00F31E08CA81B55ULL,
		0x05DAE33D923B381BULL,
		0x263C925896BBD268ULL,
		0x828BB91B2C7440BAULL,
		0x9FAABE54A6039162ULL,
		0x810F3C789E9AEFD9ULL,
		0xC7C8003DF5553603ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x184D034DF7CDE553ULL,
		0xCC9097A854D8A71FULL,
		0x9E92E13BDA10AA05ULL,
		0x78B92D2BD14528F6ULL,
		0x625ECE7CE028B76DULL,
		0x97320B7833A92F0AULL,
		0x31DCEE6313B271ACULL,
		0x773ADEC74C1BA0AFULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 152\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 152 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -152;
	} else {
		printf("Test Case 152 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0B36568FBE2BD4FCULL,
		0x7DBC55C9853BA041ULL,
		0x6CF7803917E0BE1FULL,
		0x2A672EA74242E679ULL,
		0xC8CE4AE2B7089399ULL,
		0x9B1DA4967688F7F4ULL,
		0x9E50FF2DB700B41EULL,
		0x1E6BF2FE83D8E9F9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2615CFC893CCDDBULL,
		0x4B32B001266890E4ULL,
		0xB18BFB7A989C83FBULL,
		0x95AC03FB7C234CFCULL,
		0x3FCB849C13D2C127ULL,
		0x141A16F626F8BC0FULL,
		0xC3BE6A44A69D0776ULL,
		0x1B809C0FFD900B92ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x38D4F99334EF0721ULL,
		0x3289A5C85ED30F5CULL,
		0xBB6B84BE7F443A24ULL,
		0x94BB2AABC61F997CULL,
		0x8902C646A335D271ULL,
		0x87038DA04F903BE5ULL,
		0xDA9294E91063ACA8ULL,
		0x02EB56EE8648DE66ULL
	}};
	sign = 0;
	printf("Test Case 153\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 153 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -153;
	} else {
		printf("Test Case 153 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7C49667B60EDA0EBULL,
		0xD27FD1F2146DA3FFULL,
		0x26B75C7603B4A7A9ULL,
		0x235CC3B806F8C333ULL,
		0x9C57D43C06A086E0ULL,
		0xD0C4D53D482CB5F4ULL,
		0xDAE5B858F5E07B63ULL,
		0x69215D6D2E84649BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC8AD1A80B0A6759ULL,
		0x1F9ED820EB3F0C5FULL,
		0x153CE0A9608721F3ULL,
		0x65C85C627F8D1881ULL,
		0x6FE0640E68813977ULL,
		0xA10C25C09506CC25ULL,
		0x16D142FEBE6EDB77ULL,
		0x73CE277ACA3BAEBCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9FBE94D355E33992ULL,
		0xB2E0F9D1292E979FULL,
		0x117A7BCCA32D85B6ULL,
		0xBD946755876BAAB2ULL,
		0x2C77702D9E1F4D68ULL,
		0x2FB8AF7CB325E9CFULL,
		0xC414755A37719FECULL,
		0xF55335F26448B5DFULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 154\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 154 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -154;
	} else {
		printf("Test Case 154 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x10E956E6FEAC309DULL,
		0x2332EEC913C2AD7DULL,
		0xCA3939ECEA14233FULL,
		0x335F14C860E2F573ULL,
		0xACE9D1B8B3E27BEFULL,
		0x9F12B13B01283165ULL,
		0x8488512F149C0638ULL,
		0x155180E34282E672ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6AEC622393AAEA2BULL,
		0x168D31B182A58D7EULL,
		0xD054577FFD99561BULL,
		0xBD8FD902AFDFDCEDULL,
		0x77E45A90D1ED4E4BULL,
		0x0D5EB1EBB632A8B4ULL,
		0x52498ADB6123D3C6ULL,
		0xA7349DA331EC15E3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA5FCF4C36B014672ULL,
		0x0CA5BD17911D1FFEULL,
		0xF9E4E26CEC7ACD24ULL,
		0x75CF3BC5B1031885ULL,
		0x35057727E1F52DA3ULL,
		0x91B3FF4F4AF588B1ULL,
		0x323EC653B3783272ULL,
		0x6E1CE3401096D08FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 155\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 155 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -155;
	} else {
		printf("Test Case 155 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xDBC20A984205A799ULL,
		0x8DB260B724BA8EAAULL,
		0xF66C94A6FC7C65AAULL,
		0x97473A067B1883AEULL,
		0xBF6708C7D7720388ULL,
		0x1758718648E3AA21ULL,
		0xFF7CF2842F1F8F7BULL,
		0xCB1B52667B7C62FEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6BA0D4E6D9B5E1CAULL,
		0x1B4B4A9D58786DD8ULL,
		0xA6B074039570D42BULL,
		0x2D4B064525242BD1ULL,
		0xCEDAD1B722962AA4ULL,
		0x1A6C030DA03D1F7FULL,
		0x22F6C3089EEAA538ULL,
		0x6977971282774788ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x702135B1684FC5CFULL,
		0x72671619CC4220D2ULL,
		0x4FBC20A3670B917FULL,
		0x69FC33C155F457DDULL,
		0xF08C3710B4DBD8E4ULL,
		0xFCEC6E78A8A68AA1ULL,
		0xDC862F7B9034EA42ULL,
		0x61A3BB53F9051B76ULL
	}};
	sign = 0;
	printf("Test Case 156\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 156 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -156;
	} else {
		printf("Test Case 156 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xED2FB4734DCC6CF4ULL,
		0xDCD8E4D0E6C6D2BAULL,
		0x49D04C6747986E0AULL,
		0x6A56A723B44A442BULL,
		0x5767CDF7EAB3698AULL,
		0xC04367022C8B5C64ULL,
		0xF119D4C085B396BAULL,
		0xADAE4C583F451C06ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x10B5CBE443A39072ULL,
		0xFA2C4E8E3C0608A8ULL,
		0xCFC268DE6E2E0B26ULL,
		0x25859973F3C93A60ULL,
		0xD107C3D23A3A8A38ULL,
		0x5368D7950F2CF1C9ULL,
		0x97CB3DA8912B446CULL,
		0xEF5C6B5142565608ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDC79E88F0A28DC82ULL,
		0xE2AC9642AAC0CA12ULL,
		0x7A0DE388D96A62E3ULL,
		0x44D10DAFC08109CAULL,
		0x86600A25B078DF52ULL,
		0x6CDA8F6D1D5E6A9AULL,
		0x594E9717F488524EULL,
		0xBE51E106FCEEC5FEULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 157\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 157 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -157;
	} else {
		printf("Test Case 157 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6483DA2159BFA4C8ULL,
		0x9C101B779A04F93FULL,
		0x3ED5B27F4D9FF242ULL,
		0x6D783D4E9BE70E1FULL,
		0x02EB4B1576D4E77EULL,
		0x0D1AFC7F7EC1A5D8ULL,
		0x704930EF7E5D1D70ULL,
		0xF35408A418E9FC44ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x53F23AB5CF0AC06EULL,
		0x2716ACB616667B9AULL,
		0xF5059787E26A6F65ULL,
		0x39BC50FCC5836919ULL,
		0x60F2538EFC2A61DDULL,
		0x8D2C0E0BD955A801ULL,
		0xA93D3167F8FEA439ULL,
		0x678F148D9FC03E73ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x10919F6B8AB4E45AULL,
		0x74F96EC1839E7DA5ULL,
		0x49D01AF76B3582DDULL,
		0x33BBEC51D663A505ULL,
		0xA1F8F7867AAA85A1ULL,
		0x7FEEEE73A56BFDD6ULL,
		0xC70BFF87855E7936ULL,
		0x8BC4F4167929BDD0ULL
	}};
	sign = 0;
	printf("Test Case 158\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 158 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -158;
	} else {
		printf("Test Case 158 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x29776B62FFCD85DCULL,
		0x0358CB48F3D42544ULL,
		0xAD6D49C3100B708CULL,
		0x892D1B3C5982C049ULL,
		0xAB05EC551C895B25ULL,
		0xA1F73B7A689C3D5FULL,
		0xEDF1C50A2D83188FULL,
		0x92E2F70E3B7441AFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F41092EA9EDAAB3ULL,
		0x5EAB661EDF619E17ULL,
		0x2001294548F5C737ULL,
		0x36D55A9FFA135C5DULL,
		0xCDBD041FEFE83437ULL,
		0x24D303004C0B4F4BULL,
		0xDDD4A7D450CD8CAAULL,
		0xCC11A2C2D18326C5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8A36623455DFDB29ULL,
		0xA4AD652A1472872CULL,
		0x8D6C207DC715A954ULL,
		0x5257C09C5F6F63ECULL,
		0xDD48E8352CA126EEULL,
		0x7D24387A1C90EE13ULL,
		0x101D1D35DCB58BE5ULL,
		0xC6D1544B69F11AEAULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 159\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 159 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -159;
	} else {
		printf("Test Case 159 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD061101D15755662ULL,
		0x3D05F2E20EC7F61EULL,
		0x523B0321F2C224E7ULL,
		0x988A0D6E7470515CULL,
		0xDA427E7B9F2D380BULL,
		0xB107C8A380B3F29FULL,
		0xF824BF9365F51B28ULL,
		0x4D876150615E695DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4844CE3EB688FE67ULL,
		0xC4CF9229ACA71B4BULL,
		0xA020464344B7E0E7ULL,
		0xB0348C2EF8981D28ULL,
		0x4E13C3261123DAB9ULL,
		0x08154CFCC1D1E1E9ULL,
		0xCD0EBB6EF008D186ULL,
		0xE7543726BA2983EAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x881C41DE5EEC57FBULL,
		0x783660B86220DAD3ULL,
		0xB21ABCDEAE0A43FFULL,
		0xE855813F7BD83433ULL,
		0x8C2EBB558E095D51ULL,
		0xA8F27BA6BEE210B6ULL,
		0x2B16042475EC49A2ULL,
		0x66332A29A734E573ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 160\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 160 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -160;
	} else {
		printf("Test Case 160 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF057A560B6AE4D16ULL,
		0x7332C13B91643608ULL,
		0xE334061CA3C5DD3DULL,
		0x7763C0DCE9F130D2ULL,
		0x2DAD04C10DEDE650ULL,
		0xD4FE2186434D1F2EULL,
		0x4CD64675C8799B13ULL,
		0xD4E2AB2977A36D1FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5C4F0EF33F1B443ULL,
		0xB15676ED709B3882ULL,
		0x66487273FA5D5DFBULL,
		0x347A90F19BFE5236ULL,
		0xE7E06C9761B9FCEDULL,
		0x0271932967903CADULL,
		0x1765AC7414DD8A6AULL,
		0x147244D2E01934B7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2A92B47182BC98D3ULL,
		0xC1DC4A4E20C8FD86ULL,
		0x7CEB93A8A9687F41ULL,
		0x42E92FEB4DF2DE9CULL,
		0x45CC9829AC33E963ULL,
		0xD28C8E5CDBBCE280ULL,
		0x35709A01B39C10A9ULL,
		0xC0706656978A3868ULL
	}};
	sign = 0;
	printf("Test Case 161\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 161 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -161;
	} else {
		printf("Test Case 161 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x23AA25D0B264942EULL,
		0x72C264125A874AE6ULL,
		0x93CA52BD30E746F1ULL,
		0x1E04F9B70A8289F9ULL,
		0xC27930093B4BC67DULL,
		0x4A7A5F87746EA934ULL,
		0x952C4E5121333122ULL,
		0xA133E16DD85D52A5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA815CE001A6D9F68ULL,
		0xCA08C572081477EFULL,
		0xDA00255C5B3ABE6CULL,
		0x863CFB28E081CFE5ULL,
		0x74598417F88EA12CULL,
		0xBEF36D7BBCD72438ULL,
		0x4FADE6E61A1213A1ULL,
		0x2A8EC0BF45E55630ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7B9457D097F6F4C6ULL,
		0xA8B99EA05272D2F6ULL,
		0xB9CA2D60D5AC8884ULL,
		0x97C7FE8E2A00BA13ULL,
		0x4E1FABF142BD2550ULL,
		0x8B86F20BB79784FCULL,
		0x457E676B07211D80ULL,
		0x76A520AE9277FC75ULL
	}};
	sign = 0;
	printf("Test Case 162\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 162 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -162;
	} else {
		printf("Test Case 162 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB33F0052F3D57007ULL,
		0x2F3716AF3046A8A0ULL,
		0x66ABAB65C4657172ULL,
		0xDDB7ED65C124BA68ULL,
		0xC8FA396CEC67C7EAULL,
		0x8AA6E75479FF3F72ULL,
		0x6E87D42099B73134ULL,
		0x11AA5A7282EFCB2FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6780AC7A20B213DULL,
		0xFD5D178E472C85A9ULL,
		0xA8954FB7075425D7ULL,
		0xC6BBE82F6213A233ULL,
		0xDC635FB7208A73EFULL,
		0x0D339972B4BBCD76ULL,
		0x94A58F60F114FB4FULL,
		0x75597061207C978DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBCC6F58B51CA4ECAULL,
		0x31D9FF20E91A22F6ULL,
		0xBE165BAEBD114B9AULL,
		0x16FC05365F111834ULL,
		0xEC96D9B5CBDD53FBULL,
		0x7D734DE1C54371FBULL,
		0xD9E244BFA8A235E5ULL,
		0x9C50EA11627333A1ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 163\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 163 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -163;
	} else {
		printf("Test Case 163 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9E8270E3F8B4D853ULL,
		0x8AEA6809447F6234ULL,
		0xE1FDF19C920D61A8ULL,
		0xBA8341F6AD15AFFDULL,
		0x3E5B2A3E8D2DC532ULL,
		0xA09A82E0CF90B516ULL,
		0x5CA3F547DAC5D553ULL,
		0xC990E043FBF890EBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6FE200515602F59BULL,
		0xB97C72D7F01BDC16ULL,
		0xCD35401E7C6F73C8ULL,
		0x95ED282DA25BD24CULL,
		0xCB406BC12D5665C2ULL,
		0x088E7E18EE8D1285ULL,
		0x211FE0764171AF61ULL,
		0xAF7009D74341B471ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2EA07092A2B1E2B8ULL,
		0xD16DF5315463861EULL,
		0x14C8B17E159DEDDFULL,
		0x249619C90AB9DDB1ULL,
		0x731ABE7D5FD75F70ULL,
		0x980C04C7E103A290ULL,
		0x3B8414D1995425F2ULL,
		0x1A20D66CB8B6DC7AULL
	}};
	sign = 0;
	printf("Test Case 164\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 164 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -164;
	} else {
		printf("Test Case 164 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE8766306624B1376ULL,
		0xCBD76136F9636B34ULL,
		0xB8FF924E429EB565ULL,
		0x199ADD502B86A023ULL,
		0x7CA6D781BB2C9EF1ULL,
		0xCC5C03CF84AE51E9ULL,
		0x6BB7AF54F4DFF9D5ULL,
		0x0FFF25CA1677A868ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE04F8E5B6E0DDCEDULL,
		0x6F55945AA9C8D63DULL,
		0x1BE8205230B20C65ULL,
		0xFFCDF85FCF709087ULL,
		0x855051DE72F643D7ULL,
		0x6C47843BB6D71CDAULL,
		0x0F03EB39A4995475ULL,
		0xAEE65B5049ECB2ACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0826D4AAF43D3689ULL,
		0x5C81CCDC4F9A94F7ULL,
		0x9D1771FC11ECA900ULL,
		0x19CCE4F05C160F9CULL,
		0xF75685A348365B19ULL,
		0x60147F93CDD7350EULL,
		0x5CB3C41B5046A560ULL,
		0x6118CA79CC8AF5BCULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 165\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 165 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -165;
	} else {
		printf("Test Case 165 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x563A5482995AF6FAULL,
		0x979BB99AC77C39C3ULL,
		0x316BA4204C9FA99DULL,
		0xA52A9897C62F6FEFULL,
		0x65485F741675895DULL,
		0x2FCEEAE48BE2F2B3ULL,
		0x896FE3F40652C07EULL,
		0x7408F5A088E274C0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x490F24C514772FFEULL,
		0x5BBF4EA0FADED4F9ULL,
		0x6F066184516A73B8ULL,
		0xE5C56ADC4D78B166ULL,
		0x4FC8AB1D9ED7EB54ULL,
		0xF900E03E3D598BBAULL,
		0xD61C8281622CB065ULL,
		0x541B418836059E8BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0D2B2FBD84E3C6FCULL,
		0x3BDC6AF9CC9D64CAULL,
		0xC265429BFB3535E5ULL,
		0xBF652DBB78B6BE88ULL,
		0x157FB456779D9E08ULL,
		0x36CE0AA64E8966F9ULL,
		0xB3536172A4261018ULL,
		0x1FEDB41852DCD634ULL
	}};
	sign = 0;
	printf("Test Case 166\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 166 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -166;
	} else {
		printf("Test Case 166 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x266A9D863738CBA7ULL,
		0x159D381F7348623DULL,
		0x542EE7C6606079C4ULL,
		0x60C0E6688761E475ULL,
		0x4C3A54836DBD65CFULL,
		0x32E806F39BE6D18FULL,
		0xC6C21B11D2A4BE42ULL,
		0x27FD0C6B21D7D839ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B0A01B0A3094A65ULL,
		0xDAF5D0EA637874E3ULL,
		0xB7C81506C37AB5DCULL,
		0x71595F9BD2546088ULL,
		0x713A1E1756F889B9ULL,
		0x9B508CF571C2DDB3ULL,
		0xDDAD21DC7D86DA01ULL,
		0x2B3819B7EDCAED2BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFB609BD5942F8142ULL,
		0x3AA767350FCFED59ULL,
		0x9C66D2BF9CE5C3E7ULL,
		0xEF6786CCB50D83ECULL,
		0xDB00366C16C4DC15ULL,
		0x979779FE2A23F3DBULL,
		0xE914F935551DE440ULL,
		0xFCC4F2B3340CEB0DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 167\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 167 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -167;
	} else {
		printf("Test Case 167 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x39DCAF8EB1984348ULL,
		0xBE542EC7FDA3D0C0ULL,
		0x353D524436140D50ULL,
		0xB5A52BC1673DA125ULL,
		0x8044032809C02AD1ULL,
		0x3E0CCB3D00DEEEA0ULL,
		0x14701C459C3CAB5EULL,
		0x0088F04448EE7957ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D0CD82F91C84E26ULL,
		0x0360ACA1F1DD53C1ULL,
		0xC1802C8BA07D1301ULL,
		0xFF1C899161125ED8ULL,
		0x251C4BDC09D89CB9ULL,
		0x36D179668F983C61ULL,
		0x94C422584CF7CEF7ULL,
		0xF777489B50948A0DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1CCFD75F1FCFF522ULL,
		0xBAF382260BC67CFFULL,
		0x73BD25B89596FA4FULL,
		0xB688A230062B424CULL,
		0x5B27B74BFFE78E17ULL,
		0x073B51D67146B23FULL,
		0x7FABF9ED4F44DC67ULL,
		0x0911A7A8F859EF49ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 168\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 168 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -168;
	} else {
		printf("Test Case 168 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4CFD5FA5DDDB4426ULL,
		0x109BF541043FEA81ULL,
		0xAF0855784496E3EFULL,
		0x67EACB03A41F6E53ULL,
		0x74AAC0171C46B10EULL,
		0xE84A061D0626288FULL,
		0x7A99B37231D92265ULL,
		0x6498586CEAEEEA4EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4730DAF445048E3AULL,
		0x35EFC298973F1920ULL,
		0x70F59D7E2AD69999ULL,
		0xD4EBDF2B4B526994ULL,
		0xC4833F0E86172E3CULL,
		0x84072B6DFEAB5290ULL,
		0x83FE6F1892B673B6ULL,
		0x3E437025122D6C20ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x05CC84B198D6B5ECULL,
		0xDAAC32A86D00D161ULL,
		0x3E12B7FA19C04A55ULL,
		0x92FEEBD858CD04BFULL,
		0xB0278108962F82D1ULL,
		0x6442DAAF077AD5FEULL,
		0xF69B44599F22AEAFULL,
		0x2654E847D8C17E2DULL
	}};
	sign = 0;
	printf("Test Case 169\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 169 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -169;
	} else {
		printf("Test Case 169 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x277FF870CDA28159ULL,
		0xE9701E93D1DE3152ULL,
		0xEEC1B4B4E9BBA2A0ULL,
		0xFFE0AC8C99216066ULL,
		0xB92B653A37D6808EULL,
		0xB311B856D68C77BEULL,
		0xADF8067DBB93C480ULL,
		0x7B981A1B09D016DBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x93D75E030A3075B9ULL,
		0x25F1D84532CFEC04ULL,
		0x3750378DB9241B61ULL,
		0x60CCF0D1B7F377BAULL,
		0xC24CB4E2461E7712ULL,
		0x61AA572099829261ULL,
		0x781191D2F59CB2E0ULL,
		0xB84806B77FA98B14ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x93A89A6DC3720BA0ULL,
		0xC37E464E9F0E454DULL,
		0xB7717D273097873FULL,
		0x9F13BBBAE12DE8ACULL,
		0xF6DEB057F1B8097CULL,
		0x516761363D09E55CULL,
		0x35E674AAC5F711A0ULL,
		0xC35013638A268BC7ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 170\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 170 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -170;
	} else {
		printf("Test Case 170 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x8DF55E85503EAB85ULL,
		0xF726A5CA741493A5ULL,
		0x3319FA7A9D4A5E66ULL,
		0xDBB9DEC2A99D22B4ULL,
		0xED43C9A6E9C50F35ULL,
		0x29C0A962305848F9ULL,
		0x95B9FC6D0BC2DFF1ULL,
		0x7931616C5561080DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8983970FC29BF0CULL,
		0x3756A8DE789BE5DFULL,
		0x736ED9E499AE93F3ULL,
		0xB884AA3BDBAF5F76ULL,
		0x2D7B7E0E4E0DC248ULL,
		0x2EE873AE80E77392ULL,
		0xD57C468E75A98A02ULL,
		0xABEA8276DD9E327EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA55D25145414EC79ULL,
		0xBFCFFCEBFB78ADC5ULL,
		0xBFAB2096039BCA73ULL,
		0x23353486CDEDC33DULL,
		0xBFC84B989BB74CEDULL,
		0xFAD835B3AF70D567ULL,
		0xC03DB5DE961955EEULL,
		0xCD46DEF577C2D58EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 171\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 171 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -171;
	} else {
		printf("Test Case 171 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC14AB50CF150382EULL,
		0x826E753C769FE79DULL,
		0x2C60015E6D7B03A0ULL,
		0xE2D7F164581188A5ULL,
		0x2D5D456437A3E44CULL,
		0x2E8EE266E690C3CDULL,
		0x404BB0FB7DFF750AULL,
		0xA0A299B87046B0A7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D84FA9AB1F4A365ULL,
		0x00B6C370F54217B6ULL,
		0xE3E672CBE09F02EDULL,
		0x694871F6DC34F254ULL,
		0x1BDC104EE93934CEULL,
		0x5529734FC5E0D6F5ULL,
		0x2BCFEB925C6E078DULL,
		0xCC005C99BB5CC706ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x33C5BA723F5B94C9ULL,
		0x81B7B1CB815DCFE7ULL,
		0x48798E928CDC00B3ULL,
		0x798F7F6D7BDC9650ULL,
		0x118135154E6AAF7EULL,
		0xD9656F1720AFECD8ULL,
		0x147BC56921916D7CULL,
		0xD4A23D1EB4E9E9A1ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 172\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 172 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -172;
	} else {
		printf("Test Case 172 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x26BFB84765205C83ULL,
		0x5B9E34EC5EFE2770ULL,
		0x2D5702FA3943E0D0ULL,
		0x453D4895FEEE41C6ULL,
		0x43C08D45D66501D4ULL,
		0xAF8AF143ED042A2DULL,
		0x59C8348BF9FA8884ULL,
		0xCAADCE6080DA40DFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x87CD9D796FD6CBE7ULL,
		0xB08C04627D967C31ULL,
		0x14245A08F6A8F501ULL,
		0x3B1A7A809DEDB60AULL,
		0x5F23BBCFC98DD9F2ULL,
		0x236BC3F69B0991A0ULL,
		0xA9D200CC6CB87CF1ULL,
		0xCE55ED76010EC1A6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9EF21ACDF549909CULL,
		0xAB123089E167AB3EULL,
		0x1932A8F1429AEBCEULL,
		0x0A22CE1561008BBCULL,
		0xE49CD1760CD727E2ULL,
		0x8C1F2D4D51FA988CULL,
		0xAFF633BF8D420B93ULL,
		0xFC57E0EA7FCB7F38ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 173\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 173 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -173;
	} else {
		printf("Test Case 173 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x66B1E0A7090E33C9ULL,
		0xF78513E1C9988D82ULL,
		0x25C6ACAFF72A77ECULL,
		0x08EA52C439FA80C7ULL,
		0x01C63D276A267F76ULL,
		0x600B25D43CB3623CULL,
		0x8182C0C6949D44C6ULL,
		0xF52228F162A54F64ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0BDF5E55593A3ABULL,
		0x257D0BA59452A78BULL,
		0xCD748C4C5DC3147AULL,
		0xFE46F4D8AA12B055ULL,
		0xC706C1C2466121E4ULL,
		0x467C3C9E651D0C35ULL,
		0x2ED850D514E0CB6EULL,
		0x455E765E0F22F3BBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA5F3EAC1B37A901EULL,
		0xD208083C3545E5F6ULL,
		0x5852206399676372ULL,
		0x0AA35DEB8FE7D071ULL,
		0x3ABF7B6523C55D91ULL,
		0x198EE935D7965606ULL,
		0x52AA6FF17FBC7958ULL,
		0xAFC3B29353825BA9ULL
	}};
	sign = 0;
	printf("Test Case 174\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 174 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -174;
	} else {
		printf("Test Case 174 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE448B9298D62F8EAULL,
		0x3D53A9842B32873CULL,
		0xFA2FBB67C9392FCBULL,
		0x16F4B47049AC0500ULL,
		0xD980801620CF0CCCULL,
		0x5D9ABB80BF975D13ULL,
		0xC18163724BCD1BE7ULL,
		0x911A379BE9FFBD76ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x56B5894AA9133529ULL,
		0x3FC945BCE9ADBF20ULL,
		0x18ECAA70A39A1B1DULL,
		0x61D6F808242C7F59ULL,
		0x634A734B1E611835ULL,
		0xF25D984F0C334E3BULL,
		0x46B3CD32CD53B6EBULL,
		0x01747F84E56B0091ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8D932FDEE44FC3C1ULL,
		0xFD8A63C74184C81CULL,
		0xE14310F7259F14ADULL,
		0xB51DBC68257F85A7ULL,
		0x76360CCB026DF496ULL,
		0x6B3D2331B3640ED8ULL,
		0x7ACD963F7E7964FBULL,
		0x8FA5B8170494BCE5ULL
	}};
	sign = 0;
	printf("Test Case 175\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 175 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -175;
	} else {
		printf("Test Case 175 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x775C1AD58FF0975BULL,
		0x75066B6A4E862449ULL,
		0xF206370A4149EE96ULL,
		0xA2D23E77097EC53AULL,
		0x110D84AF86C50E4BULL,
		0x51E3C3A68BA99758ULL,
		0x2C90F4E89146D1F6ULL,
		0x2B4C5AC39F9D79C6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EF00345953FD64EULL,
		0x80E3F9B5B4B57C14ULL,
		0xDD03863A580103B8ULL,
		0xEF5648EAD08C1DD2ULL,
		0xA5C6A812DABD527BULL,
		0x8A84563A6A89CAF3ULL,
		0x76FB79E63744D63CULL,
		0x1A2C6014538B949EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x286C178FFAB0C10DULL,
		0xF42271B499D0A835ULL,
		0x1502B0CFE948EADDULL,
		0xB37BF58C38F2A768ULL,
		0x6B46DC9CAC07BBCFULL,
		0xC75F6D6C211FCC64ULL,
		0xB5957B025A01FBB9ULL,
		0x111FFAAF4C11E527ULL
	}};
	sign = 0;
	printf("Test Case 176\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 176 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -176;
	} else {
		printf("Test Case 176 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x3A8E2D9CD8291B00ULL,
		0x6C14A822E4CB8A8CULL,
		0xEC4699FDA045BDA9ULL,
		0x1CE42565BAD6C6F3ULL,
		0x43C72F5EAB961AE8ULL,
		0x239A3C0EF93DBD5CULL,
		0x1F8DB6B9AC00F8DDULL,
		0x888518D6D5DEA826ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3952E15D18E4DE9ULL,
		0xEBC9015CB2CE0AB7ULL,
		0x475089D915780484ULL,
		0x151C5DCA31DE1F0FULL,
		0x5CB9885C86DEF7F9ULL,
		0x8AC609DE5EE7EC87ULL,
		0x558141DEF84F315CULL,
		0x870F6BDB0B146BF7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x56F8FF87069ACD17ULL,
		0x804BA6C631FD7FD4ULL,
		0xA4F610248ACDB924ULL,
		0x07C7C79B88F8A7E4ULL,
		0xE70DA70224B722EFULL,
		0x98D432309A55D0D4ULL,
		0xCA0C74DAB3B1C780ULL,
		0x0175ACFBCACA3C2EULL
	}};
	sign = 0;
	printf("Test Case 177\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 177 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -177;
	} else {
		printf("Test Case 177 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x44CF4F457FE56202ULL,
		0xA2693466F0A8EFBFULL,
		0xCC5B2DCA632481D2ULL,
		0xD63FA35997194305ULL,
		0xD918E4BF481178A8ULL,
		0xC5594891C5BA4AABULL,
		0x9CDA2FD86048FA39ULL,
		0x91C0D8EF89538B38ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCAAD6F66A9C72E2DULL,
		0x8352EE5CB24586B7ULL,
		0xBB65433DE20AAE98ULL,
		0xC6A90BF193976095ULL,
		0x09ED245A5F76C1E1ULL,
		0x212509B59FA64BB0ULL,
		0xF50315D21CFC90D4ULL,
		0x2F476CDD915C5818ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7A21DFDED61E33D5ULL,
		0x1F16460A3E636907ULL,
		0x10F5EA8C8119D33AULL,
		0x0F9697680381E270ULL,
		0xCF2BC064E89AB6C7ULL,
		0xA4343EDC2613FEFBULL,
		0xA7D71A06434C6965ULL,
		0x62796C11F7F7331FULL
	}};
	sign = 0;
	printf("Test Case 178\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 178 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -178;
	} else {
		printf("Test Case 178 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD66DB5A5A034246AULL,
		0x89CD5945928D8CBCULL,
		0x082A5D1C8BCC9306ULL,
		0xF0AC727303C3630BULL,
		0x26960960EFB2F612ULL,
		0x58CB379AA5396885ULL,
		0x9AF05CC7BC28F460ULL,
		0xD5089B68084887FDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB56BE7B2346A1EB1ULL,
		0xEBDD594DE8E5E8F1ULL,
		0x46680D5C97703E30ULL,
		0x973BE0E4D0EF6689ULL,
		0x1AB9266ED035428AULL,
		0x00D6BADFC8944639ULL,
		0xE7087303EF05DC7CULL,
		0x6B3332F852F132A8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2101CDF36BCA05B9ULL,
		0x9DEFFFF7A9A7A3CBULL,
		0xC1C24FBFF45C54D5ULL,
		0x5970918E32D3FC81ULL,
		0x0BDCE2F21F7DB388ULL,
		0x57F47CBADCA5224CULL,
		0xB3E7E9C3CD2317E4ULL,
		0x69D5686FB5575554ULL
	}};
	sign = 0;
	printf("Test Case 179\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 179 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -179;
	} else {
		printf("Test Case 179 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x28C76351B4195EF9ULL,
		0x5B240E2EAC1404D8ULL,
		0xCDF353B4A6E59FB4ULL,
		0xC4DBF9C7F26BB309ULL,
		0xD18432DBB0093035ULL,
		0xC56A12D572962B0AULL,
		0x6BAD507E60F4E8DEULL,
		0x2C1080E0944EE40BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x957478DCA5CB6F38ULL,
		0xC83569F962740224ULL,
		0x318A16A85CE675D2ULL,
		0x1C3655F3AC86ACE2ULL,
		0x17644E16F3888CB6ULL,
		0xED15B05BEB569DC6ULL,
		0x222D1A52EC4F38FDULL,
		0x7B0FA883E2334DA1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9352EA750E4DEFC1ULL,
		0x92EEA43549A002B3ULL,
		0x9C693D0C49FF29E1ULL,
		0xA8A5A3D445E50627ULL,
		0xBA1FE4C4BC80A37FULL,
		0xD8546279873F8D44ULL,
		0x4980362B74A5AFE0ULL,
		0xB100D85CB21B966AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 180\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 180 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -180;
	} else {
		printf("Test Case 180 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5B6DB925797531AAULL,
		0xAEAE27DEFBC73407ULL,
		0xEA487A1BE4A7AD92ULL,
		0x0DAEBBCC077338EBULL,
		0x95BD1C7BBF7FD976ULL,
		0xA7E82BA2D140357DULL,
		0x61062A00257FA99FULL,
		0x83E0108253D37845ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x112DCC65C00E5FF1ULL,
		0x2AD5FC576F3ECFEEULL,
		0xFFAD8C988891ED09ULL,
		0x94B5CBB04A97B78DULL,
		0x4AD4FBB356B2FA7FULL,
		0x88AC022981627C94ULL,
		0xD257BF3E0E5157D3ULL,
		0xF1986209A1478980ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4A3FECBFB966D1B9ULL,
		0x83D82B878C886419ULL,
		0xEA9AED835C15C089ULL,
		0x78F8F01BBCDB815DULL,
		0x4AE820C868CCDEF6ULL,
		0x1F3C29794FDDB8E9ULL,
		0x8EAE6AC2172E51CCULL,
		0x9247AE78B28BEEC4ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 181\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 181 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -181;
	} else {
		printf("Test Case 181 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x15DF6238DD6C6A33ULL,
		0xBD25882ABAC19B08ULL,
		0x3D63280A0AE22B24ULL,
		0x108537E3C28127AAULL,
		0x98C300D44BAEEE8EULL,
		0xB3C89E966FEBCFDDULL,
		0x3565AC4BFCE0C7C1ULL,
		0x90D6629167FD005EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x42C71CE93F261A9CULL,
		0x8169A7C2D4D42590ULL,
		0xCB05DADAB429794AULL,
		0x8377F19F7C376D0EULL,
		0x26428E04C557CC37ULL,
		0xC4B904264C18CCC5ULL,
		0x4B5C1A630A0C1BD3ULL,
		0x902EBDE256894F3FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD318454F9E464F97ULL,
		0x3BBBE067E5ED7577ULL,
		0x725D4D2F56B8B1DAULL,
		0x8D0D46444649BA9BULL,
		0x728072CF86572256ULL,
		0xEF0F9A7023D30318ULL,
		0xEA0991E8F2D4ABEDULL,
		0x00A7A4AF1173B11EULL
	}};
	sign = 0;
	printf("Test Case 182\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 182 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -182;
	} else {
		printf("Test Case 182 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xCD95581F4E93A0D6ULL,
		0x2B85798E3EF4F048ULL,
		0x5ED7258F32E508BBULL,
		0xCF2074E3CD563CB7ULL,
		0xC69712ECC6C487ADULL,
		0x4E3F1F705C3B141BULL,
		0x87566A671A656311ULL,
		0xF961A540BA97F769ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x136A8BAE27867805ULL,
		0x52E6F8A479CF67FAULL,
		0xC8BC58030654AD5DULL,
		0x3224030450EAFAD5ULL,
		0x118F87222F96404BULL,
		0x049FEC82A8C83DEEULL,
		0x30DD7B6566E18565ULL,
		0xFD366524C4BAD02FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBA2ACC71270D28D1ULL,
		0xD89E80E9C525884EULL,
		0x961ACD8C2C905B5DULL,
		0x9CFC71DF7C6B41E1ULL,
		0xB5078BCA972E4762ULL,
		0x499F32EDB372D62DULL,
		0x5678EF01B383DDACULL,
		0xFC2B401BF5DD273AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 183\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 183 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -183;
	} else {
		printf("Test Case 183 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF33A48BA25A828A6ULL,
		0xB6E0A21B2D2FB6D9ULL,
		0x59BFB97593CF1FECULL,
		0x2C11AC371EA567A5ULL,
		0x1B44E6CD96771AF0ULL,
		0x4F8E4479456D21DAULL,
		0x2C0A874889EEC58CULL,
		0xCA09C8E4A9722F71ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE61843674E73167ULL,
		0xFD8EB1C168090C9DULL,
		0xF7D77E1015C324B1ULL,
		0x84827467686CD4E7ULL,
		0x08FECCEFFA89EAFBULL,
		0xA17124E3350679A0ULL,
		0x71536CD0D7EE3C15ULL,
		0x7338A9B692A4B19CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF4D8C483B0C0F73FULL,
		0xB951F059C526AA3BULL,
		0x61E83B657E0BFB3AULL,
		0xA78F37CFB63892BDULL,
		0x124619DD9BED2FF4ULL,
		0xAE1D1F961066A83AULL,
		0xBAB71A77B2008976ULL,
		0x56D11F2E16CD7DD4ULL
	}};
	sign = 0;
	printf("Test Case 184\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 184 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -184;
	} else {
		printf("Test Case 184 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE504CADD8F916937ULL,
		0x14B39DFA15EEC964ULL,
		0x6064EEE1000B6520ULL,
		0xB385C2CF298E9C49ULL,
		0x78AB999ED59B337FULL,
		0xED1B9B8391F635BEULL,
		0xDA9EDD806098F7AAULL,
		0x7B64BDA4380582BBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFE2879A0456687DULL,
		0x1256F114683DE0E7ULL,
		0x7156D50844F6844DULL,
		0x5BBDA3DCE642FAB6ULL,
		0xDD862BF433079EFFULL,
		0x239FC6AE38A32138ULL,
		0xC4734A39C71C6BB8ULL,
		0xD4252F53526349B5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x252243438B3B00BAULL,
		0x025CACE5ADB0E87DULL,
		0xEF0E19D8BB14E0D3ULL,
		0x57C81EF2434BA192ULL,
		0x9B256DAAA2939480ULL,
		0xC97BD4D559531485ULL,
		0x162B9346997C8BF2ULL,
		0xA73F8E50E5A23906ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 185\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 185 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -185;
	} else {
		printf("Test Case 185 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6BC00218B6EA6AA2ULL,
		0xB861690EDB5BCC3DULL,
		0x558A3528376D8187ULL,
		0x1A354948B5816389ULL,
		0x54768D906D8D01C2ULL,
		0xCFF793F468C4F39FULL,
		0x1853CEDAE4F123FAULL,
		0x000B555549B86D48ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA39F8BBF64F7F901ULL,
		0xB37F7A9A805799CAULL,
		0xA6DB85A1DFE59537ULL,
		0x2F84875D5F8B1F74ULL,
		0x4476B0DD83C45EB1ULL,
		0xDCBAC955AACA0FB5ULL,
		0x28515267327A314EULL,
		0xF2F86390F61560A5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC820765951F271A1ULL,
		0x04E1EE745B043272ULL,
		0xAEAEAF865787EC50ULL,
		0xEAB0C1EB55F64414ULL,
		0x0FFFDCB2E9C8A310ULL,
		0xF33CCA9EBDFAE3EAULL,
		0xF0027C73B276F2ABULL,
		0x0D12F1C453A30CA2ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 186\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 186 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -186;
	} else {
		printf("Test Case 186 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x57DDFDF463DCDE46ULL,
		0xDDDB93C18524CF96ULL,
		0x413330DF888BBF71ULL,
		0xE675351A662E2483ULL,
		0xC8C558CAC26DB076ULL,
		0xF5721BDBACD64BDDULL,
		0x0BDF6A34AE3FABAEULL,
		0xBAF475008375A3E7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x84157FC9ABD0B994ULL,
		0xE5E46A1936E9073EULL,
		0xC2B8CEE23EA89D6EULL,
		0x53246A32FA401B79ULL,
		0x303EF94749BC7579ULL,
		0x35A0CF543BE2C690ULL,
		0xEEB2F0099FD5C19FULL,
		0x21BC2BAB3B28E467ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD3C87E2AB80C24B2ULL,
		0xF7F729A84E3BC857ULL,
		0x7E7A61FD49E32202ULL,
		0x9350CAE76BEE0909ULL,
		0x98865F8378B13AFDULL,
		0xBFD14C8770F3854DULL,
		0x1D2C7A2B0E69EA0FULL,
		0x99384955484CBF7FULL
	}};
	sign = 0;
	printf("Test Case 187\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 187 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -187;
	} else {
		printf("Test Case 187 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1A257CB6E907CB67ULL,
		0xD60CC27BD0163D70ULL,
		0xB67CF46E19586A54ULL,
		0xEC00F11C124D464DULL,
		0x4F4BB1AFBCBA4A2AULL,
		0x5859AB9342A226E6ULL,
		0x86B7B2DD21CF4A93ULL,
		0x57998DC7411D2C75ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E0FE77528896FE7ULL,
		0xDA12C5DA07DB65B6ULL,
		0xC4A413A20ECFD840ULL,
		0x5E4FA671BA23781FULL,
		0x1FD822943557BDF8ULL,
		0x29978336C2D434A6ULL,
		0xD31FC878C28F7A4FULL,
		0x83A547D3C5B86149ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9C159541C07E5B80ULL,
		0xFBF9FCA1C83AD7B9ULL,
		0xF1D8E0CC0A889213ULL,
		0x8DB14AAA5829CE2DULL,
		0x2F738F1B87628C32ULL,
		0x2EC2285C7FCDF240ULL,
		0xB397EA645F3FD044ULL,
		0xD3F445F37B64CB2BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 188\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 188 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -188;
	} else {
		printf("Test Case 188 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x07ACF2C4BB6E59A5ULL,
		0x8639A939D3B5D5B3ULL,
		0xFCF2E72414D5D21BULL,
		0x02D837FFE4619A7AULL,
		0xBD9D1739237E7453ULL,
		0x4CA67548E3924259ULL,
		0x1510B8BFE5CF61A4ULL,
		0xAA1A726E975E6529ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA834CD32694CCE9ULL,
		0x1328EC785F9887ACULL,
		0x8B1D98F5C08CBAF9ULL,
		0xECA3805C3A2348E3ULL,
		0xF9E39D7CD299F04CULL,
		0xB5BAE977743CF7CDULL,
		0xB30625DC757339C0ULL,
		0x4F8E8920665033A2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0D29A5F194D98CBCULL,
		0x7310BCC1741D4E06ULL,
		0x71D54E2E54491722ULL,
		0x1634B7A3AA3E5197ULL,
		0xC3B979BC50E48406ULL,
		0x96EB8BD16F554A8BULL,
		0x620A92E3705C27E3ULL,
		0x5A8BE94E310E3186ULL
	}};
	sign = 0;
	printf("Test Case 189\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 189 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -189;
	} else {
		printf("Test Case 189 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6AAC68E46ACF47B5ULL,
		0xFE09DE64A1FA354BULL,
		0xEEDE78E1B8B4B972ULL,
		0x1C5F351FF13ED698ULL,
		0x75B8BD8520C54473ULL,
		0x74D678637BB0FBABULL,
		0x002D21A885C0B052ULL,
		0x0BA058259B383723ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x568FA33F8C1D7F00ULL,
		0x40B410538000D7D9ULL,
		0xCFF80F97397C823CULL,
		0xBF289DE9999EE225ULL,
		0xAF282BDBA8D084E3ULL,
		0x77428DF7A637E640ULL,
		0x45F828016E39148EULL,
		0xDA946BFB7B8AD19EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x141CC5A4DEB1C8B5ULL,
		0xBD55CE1121F95D72ULL,
		0x1EE6694A7F383736ULL,
		0x5D369736579FF473ULL,
		0xC69091A977F4BF8FULL,
		0xFD93EA6BD579156AULL,
		0xBA34F9A717879BC3ULL,
		0x310BEC2A1FAD6584ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 190\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 190 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -190;
	} else {
		printf("Test Case 190 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA2FEBD4BECD4184CULL,
		0xE97CF0161A6D6EB7ULL,
		0x57D08CA1AC685031ULL,
		0x1C99841C68C6D31FULL,
		0x50B9407E9309B039ULL,
		0x0383AC3934729325ULL,
		0xF5A1BE6CBC5177E9ULL,
		0xD29518A66A7FED0AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x355C2CAE4BDD5CDBULL,
		0xB43265E442585CAAULL,
		0x6F941F237112B349ULL,
		0xA5919577B27B1294ULL,
		0x8B06A949DDA02A1DULL,
		0x78669773CFC9965EULL,
		0x7F6DC5A857CCC65EULL,
		0x783A146CF72BD8F4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6DA2909DA0F6BB71ULL,
		0x354A8A31D815120DULL,
		0xE83C6D7E3B559CE8ULL,
		0x7707EEA4B64BC08AULL,
		0xC5B29734B569861BULL,
		0x8B1D14C564A8FCC6ULL,
		0x7633F8C46484B18AULL,
		0x5A5B043973541416ULL
	}};
	sign = 0;
	printf("Test Case 191\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 191 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -191;
	} else {
		printf("Test Case 191 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x556179D7E258AD66ULL,
		0x2A2CEDBDF751490BULL,
		0x7B4F1169D021EE0DULL,
		0xA3ADEA8923AB19A7ULL,
		0xCCF042D997390163ULL,
		0xF85915C43D8FA646ULL,
		0x784E2F780CEC0C7FULL,
		0xFF70A2759FB221ECULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x69044A1505C69FEBULL,
		0xFBE25599A6EC6E4AULL,
		0xAC5206CBCEAA56DFULL,
		0xB9D510635BAE3B07ULL,
		0x78C98CA2B3B9E629ULL,
		0x0A26F74AF1753937ULL,
		0x53E1C69508D9C6D6ULL,
		0x0F94E05AB904DBE4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEC5D2FC2DC920D7BULL,
		0x2E4A98245064DAC0ULL,
		0xCEFD0A9E0177972DULL,
		0xE9D8DA25C7FCDE9FULL,
		0x5426B636E37F1B39ULL,
		0xEE321E794C1A6D0FULL,
		0x246C68E3041245A9ULL,
		0xEFDBC21AE6AD4608ULL
	}};
	sign = 0;
	printf("Test Case 192\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 192 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -192;
	} else {
		printf("Test Case 192 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1B3D3F4874504DBDULL,
		0xB77BD31ACA710CA6ULL,
		0xE899743593D073DCULL,
		0xC12AD8D7F53551F8ULL,
		0xDE6DFA4333E0DB71ULL,
		0x3EA47327EB3BD99DULL,
		0x41DAC06A32B67835ULL,
		0xE2118F4EF48F6A9BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E675E4DD56961D1ULL,
		0x302E15ED8D54344BULL,
		0xDA2CC44853A190DFULL,
		0xCE0BFE73EEE77803ULL,
		0x80D30F6312FFE383ULL,
		0xA8BABCDEE8765DCAULL,
		0x75A1C2C9B4E90060ULL,
		0x8B7AD5A9918F9C84ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFCD5E0FA9EE6EBECULL,
		0x874DBD2D3D1CD85AULL,
		0x0E6CAFED402EE2FDULL,
		0xF31EDA64064DD9F5ULL,
		0x5D9AEAE020E0F7EDULL,
		0x95E9B64902C57BD3ULL,
		0xCC38FDA07DCD77D4ULL,
		0x5696B9A562FFCE16ULL
	}};
	sign = 0;
	printf("Test Case 193\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 193 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -193;
	} else {
		printf("Test Case 193 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x016ECCBD58D0096BULL,
		0x0662D365AA3AC85DULL,
		0x373C6F7133C60A73ULL,
		0x4629DCAE75CD7969ULL,
		0xFDECD44A83C78DEAULL,
		0xC36AC29C01C6AF7FULL,
		0x0734F0958A74C85EULL,
		0xA5D77D44F95D4B14ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F72A21E2A870EBFULL,
		0x00F88995E6C18565ULL,
		0x42F8BC063B043EB2ULL,
		0x5EBDCF9D3608820DULL,
		0xDCF14367AC1D93F0ULL,
		0x5C5DB18BEC3A2A06ULL,
		0x79A575C524A21169ULL,
		0x23C7186D46888F30ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x91FC2A9F2E48FAACULL,
		0x056A49CFC37942F7ULL,
		0xF443B36AF8C1CBC1ULL,
		0xE76C0D113FC4F75BULL,
		0x20FB90E2D7A9F9F9ULL,
		0x670D1110158C8579ULL,
		0x8D8F7AD065D2B6F5ULL,
		0x821064D7B2D4BBE3ULL
	}};
	sign = 0;
	printf("Test Case 194\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 194 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -194;
	} else {
		printf("Test Case 194 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1F118A45E73CF090ULL,
		0xCD26875230039B63ULL,
		0x555433897BBED77CULL,
		0xB24B8606A24A9214ULL,
		0xA193A1E1FF6797A4ULL,
		0x85491E00D13A183EULL,
		0xD4F5CF566CD57287ULL,
		0x50E1D002E9DDEC5EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C71819334C60809ULL,
		0xE3B946008B4D7C6EULL,
		0xEACD44018C714BA6ULL,
		0xD644D056BB041377ULL,
		0x7D3C2AC8AEA4251DULL,
		0x3AB2585BCF7B1C53ULL,
		0x9B18A5852B9B2162ULL,
		0x8F2F25AE45BA617CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF2A008B2B276E887ULL,
		0xE96D4151A4B61EF4ULL,
		0x6A86EF87EF4D8BD5ULL,
		0xDC06B5AFE7467E9CULL,
		0x2457771950C37286ULL,
		0x4A96C5A501BEFBEBULL,
		0x39DD29D1413A5125ULL,
		0xC1B2AA54A4238AE2ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 195\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 195 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -195;
	} else {
		printf("Test Case 195 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5771546EC1DC0DBDULL,
		0x9AC5625AF147F6EDULL,
		0x3742717F8AC955A0ULL,
		0x463194815F5FCB3FULL,
		0xB596872611E1E411ULL,
		0x45CF59494FE61A3DULL,
		0x05F2A6FFFDE37443ULL,
		0xDD066CDAC9CD629DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x88E6D6985C1503E8ULL,
		0xD0A257B88BF69F0FULL,
		0xC600C469CA39288BULL,
		0xA1494E8735C834A7ULL,
		0xDD56013EC31D5CE2ULL,
		0x6984E22594416959ULL,
		0x9EFA22DD50413B39ULL,
		0xF05644CCDD08A6A9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCE8A7DD665C709D5ULL,
		0xCA230AA2655157DDULL,
		0x7141AD15C0902D14ULL,
		0xA4E845FA29979697ULL,
		0xD84085E74EC4872EULL,
		0xDC4A7723BBA4B0E3ULL,
		0x66F88422ADA23909ULL,
		0xECB0280DECC4BBF3ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 196\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 196 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -196;
	} else {
		printf("Test Case 196 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9A29CBF7676772F5ULL,
		0x09072B2AEE8E807EULL,
		0xFF0EA203E1A8F22AULL,
		0x4DBD2BDECF2B2A63ULL,
		0x31B256A4D37331FAULL,
		0x1DAE680750709F2AULL,
		0x7CF3572BA68ADBDFULL,
		0x8944514E98503707ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x05713C3BEE9DA8BFULL,
		0x5CF96374683426F7ULL,
		0x8DFC77070482D89BULL,
		0x935F34E2CAE11964ULL,
		0x246F74B2AE6062CDULL,
		0x9194D36728F7553DULL,
		0x943567761321EC67ULL,
		0x1EC84AD527FDE257ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x94B88FBB78C9CA36ULL,
		0xAC0DC7B6865A5987ULL,
		0x71122AFCDD26198EULL,
		0xBA5DF6FC044A10FFULL,
		0x0D42E1F22512CF2CULL,
		0x8C1994A0277949EDULL,
		0xE8BDEFB59368EF77ULL,
		0x6A7C0679705254AFULL
	}};
	sign = 0;
	printf("Test Case 197\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 197 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -197;
	} else {
		printf("Test Case 197 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x78CB0DDD370A1E52ULL,
		0x5A3D7A7BB528E219ULL,
		0xCE32E598F3F8B3B1ULL,
		0x3FF9C7820C7E60BBULL,
		0xB49BE6648A360088ULL,
		0x8DA071EF4EA9B827ULL,
		0xC7087555F5CED9EAULL,
		0xE6105E8AC22EBB9DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A461CCB726D8749ULL,
		0xD5A1ABB77A2CC293ULL,
		0x8CDA577E3C0991B9ULL,
		0x6A0CAEF1EBE59474ULL,
		0xCF9FFDC8E57E2CBBULL,
		0x0351FDDD20444CD6ULL,
		0x1C336CDEFEA76095ULL,
		0x508653D0601F1BB1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E84F111C49C9709ULL,
		0x849BCEC43AFC1F86ULL,
		0x41588E1AB7EF21F7ULL,
		0xD5ED18902098CC47ULL,
		0xE4FBE89BA4B7D3CCULL,
		0x8A4E74122E656B50ULL,
		0xAAD50876F7277955ULL,
		0x958A0ABA620F9FECULL
	}};
	sign = 0;
	printf("Test Case 198\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 198 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -198;
	} else {
		printf("Test Case 198 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD9590A0C43C5C2BFULL,
		0x3B443A9EF7B0EAD3ULL,
		0x4ECAE2B405B9874BULL,
		0xB3424C56D4417833ULL,
		0x5BF438BE5EB46D3EULL,
		0x48AE8818D88B44FCULL,
		0x706DF67DCAD1A338ULL,
		0xF39DD79CBAD04935ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x400881E58AB7FF76ULL,
		0xCC8D57FF741E4054ULL,
		0x7E1FDB7F9E55F7A5ULL,
		0xD3F9F250021193DDULL,
		0x1E0C7878AE73FCD7ULL,
		0x2C04743E0E1EB8DFULL,
		0xA571DDF3F3BFDB3CULL,
		0xAB7388D0A33DE1FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x99508826B90DC349ULL,
		0x6EB6E29F8392AA7FULL,
		0xD0AB073467638FA5ULL,
		0xDF485A06D22FE455ULL,
		0x3DE7C045B0407066ULL,
		0x1CAA13DACA6C8C1DULL,
		0xCAFC1889D711C7FCULL,
		0x482A4ECC17926736ULL
	}};
	sign = 0;
	printf("Test Case 199\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 199 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -199;
	} else {
		printf("Test Case 199 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0B10F67DAF619735ULL,
		0x324CA0C681A1132DULL,
		0xA5F204679F0223A2ULL,
		0xE839200C09123D36ULL,
		0x3F6A54269A581CA2ULL,
		0x293625B3EE58864DULL,
		0x593CF383515744A1ULL,
		0x6A63A43BC28B870CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB0C04C975A4B243ULL,
		0xF1FEAE69FFD9B346ULL,
		0xCBAD01E706E4AD20ULL,
		0x2C11A96ED2ADAD97ULL,
		0x755E373B8062DE18ULL,
		0x83D827AAFA6C330FULL,
		0x5C21CAC78D5FF029ULL,
		0xB6084BA184996622ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1004F1B439BCE4F2ULL,
		0x404DF25C81C75FE6ULL,
		0xDA450280981D7681ULL,
		0xBC27769D36648F9EULL,
		0xCA0C1CEB19F53E8AULL,
		0xA55DFE08F3EC533DULL,
		0xFD1B28BBC3F75477ULL,
		0xB45B589A3DF220E9ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 200\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 200 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -200;
	} else {
		printf("Test Case 200 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x8B2F0D3516D3E2CBULL,
		0x2ABB9B27CB580650ULL,
		0x61D960312553B582ULL,
		0x45D6E197B9B0DBD6ULL,
		0x5540BB653E255834ULL,
		0x0AA634514D3FCEEAULL,
		0x0C7EFDF0B3054AE5ULL,
		0x0BD09E83E5E5DDC8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF29F055EB1A09F9ULL,
		0x7BDEBE6EA2AA02A3ULL,
		0xA0C95FE2FD9894C4ULL,
		0x0C70741DC15D85D4ULL,
		0x03144C99C82034C2ULL,
		0x807BF8D5AFE766B0ULL,
		0x39E6DBE107B034F7ULL,
		0xE83B88ECC3979C2BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBC051CDF2BB9D8D2ULL,
		0xAEDCDCB928AE03ACULL,
		0xC110004E27BB20BDULL,
		0x39666D79F8535601ULL,
		0x522C6ECB76052372ULL,
		0x8A2A3B7B9D58683AULL,
		0xD298220FAB5515EDULL,
		0x23951597224E419CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 201\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 201 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -201;
	} else {
		printf("Test Case 201 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x17544F1CC748C852ULL,
		0x25387A31C26787C9ULL,
		0x6B47C13AE5F56431ULL,
		0x3DEF60D91DF2DE0FULL,
		0x9383740E60E8182CULL,
		0xAEF00E203D177F55ULL,
		0x42D641827C9D6AB1ULL,
		0x2978E6D58843DCBFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x40B8E4BD3DFEC960ULL,
		0x866B736ACFFDE2FBULL,
		0x398BFAE7E341F28BULL,
		0x89A9C19709F6E28FULL,
		0x0B1B0EF313814EFFULL,
		0x9BBEFA9F5423BE39ULL,
		0x39B3BC07F0EE95ACULL,
		0x676EA6E47624C2F2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD69B6A5F8949FEF2ULL,
		0x9ECD06C6F269A4CDULL,
		0x31BBC65302B371A5ULL,
		0xB4459F4213FBFB80ULL,
		0x8868651B4D66C92CULL,
		0x13311380E8F3C11CULL,
		0x0922857A8BAED505ULL,
		0xC20A3FF1121F19CDULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 202\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 202 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -202;
	} else {
		printf("Test Case 202 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x84EFADADE902A3B9ULL,
		0x3D7B81B9176C85B9ULL,
		0x0DE9A77114ABADC7ULL,
		0x3AE135FD886BF53EULL,
		0x6406BB072AA212AEULL,
		0xAE9E10E01672EA4AULL,
		0x2984C62CB033BC2FULL,
		0xA299D732E6D664FBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA18CC2C428F28A85ULL,
		0x50BA2DC5A53C7DC5ULL,
		0xDCBD3BDB3340BE35ULL,
		0x4E063A3BD4413C90ULL,
		0xA0C15CAC7B004B6EULL,
		0xCEA0A4FFDEF5CB6CULL,
		0x73613B477F26AA4EULL,
		0xBDF583FBE56CF0E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE362EAE9C0101934ULL,
		0xECC153F3723007F3ULL,
		0x312C6B95E16AEF91ULL,
		0xECDAFBC1B42AB8ADULL,
		0xC3455E5AAFA1C73FULL,
		0xDFFD6BE0377D1EDDULL,
		0xB6238AE5310D11E0ULL,
		0xE4A4533701697415ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 203\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 203 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -203;
	} else {
		printf("Test Case 203 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xBE6130FC770E79BEULL,
		0x77B163299E4B309AULL,
		0x3B283A20E4ECF9BDULL,
		0x3D57CE304B18B587ULL,
		0xD0100F9D1D601CB9ULL,
		0xABE087E01962B576ULL,
		0x0080798553B2D766ULL,
		0xD0ABA2B705166895ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9DFBDE218EB87AAULL,
		0xD6485C9B9ACAAC46ULL,
		0x3A1371EBA74753CAULL,
		0xD14C9FED24D756A1ULL,
		0x9365826DFDA31083ULL,
		0xF02F6398B75BFCC1ULL,
		0xE5AB8CB7B5CB4C88ULL,
		0xF690B9BFD81BEDFAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD481731A5E22F214ULL,
		0xA169068E03808453ULL,
		0x0114C8353DA5A5F2ULL,
		0x6C0B2E4326415EE6ULL,
		0x3CAA8D2F1FBD0C35ULL,
		0xBBB124476206B8B5ULL,
		0x1AD4ECCD9DE78ADDULL,
		0xDA1AE8F72CFA7A9AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 204\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 204 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -204;
	} else {
		printf("Test Case 204 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x10E12AE4DC2E39C1ULL,
		0x9442F57156E4B717ULL,
		0x9A671490D550E21CULL,
		0x289641F5E40836E6ULL,
		0x813E452ACAC93AE5ULL,
		0xB4FF1FC5B19C337FULL,
		0xBD8C967101B6CAB4ULL,
		0xF1B86A3250630A7BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF95950F5C04D95B9ULL,
		0xB4F465C122EA5CF6ULL,
		0x5049A2778743272FULL,
		0xE27AF67CCA178FB1ULL,
		0x9A534007E16A0114ULL,
		0xE2E244F651475067ULL,
		0x8554C6C861EAD6FBULL,
		0x3EF678D64706E6EAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1787D9EF1BE0A408ULL,
		0xDF4E8FB033FA5A20ULL,
		0x4A1D72194E0DBAECULL,
		0x461B4B7919F0A735ULL,
		0xE6EB0522E95F39D0ULL,
		0xD21CDACF6054E317ULL,
		0x3837CFA89FCBF3B8ULL,
		0xB2C1F15C095C2391ULL
	}};
	sign = 0;
	printf("Test Case 205\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 205 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -205;
	} else {
		printf("Test Case 205 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x45F39BE52D50E52AULL,
		0x286638B000B8DDBDULL,
		0x098274942954108DULL,
		0x0249A997B9917175ULL,
		0xBBFD109F8D69F2BCULL,
		0x5AA0D39AC9F11107ULL,
		0x2D0C4A44BE0D4470ULL,
		0x56B43E70D389C8C6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x458AC1056F7EF031ULL,
		0xA5044EF3E922DBE1ULL,
		0x5014C29BFA7D3BF1ULL,
		0x4DF5CF327FD4FCAAULL,
		0xC6DAAA9B4F037E85ULL,
		0x424BFAC09B3627A9ULL,
		0x415FF35B0919D91CULL,
		0xE4E01A1202411F31ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0068DADFBDD1F4F9ULL,
		0x8361E9BC179601DCULL,
		0xB96DB1F82ED6D49BULL,
		0xB453DA6539BC74CAULL,
		0xF52266043E667436ULL,
		0x1854D8DA2EBAE95DULL,
		0xEBAC56E9B4F36B54ULL,
		0x71D4245ED148A994ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 206\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 206 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -206;
	} else {
		printf("Test Case 206 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x01E5B843A85040DDULL,
		0x12BB15680A060474ULL,
		0x253EA5F740E85FECULL,
		0x868953CBA63F732EULL,
		0x5E5954D0CD5534EAULL,
		0x69551E9D63D46EE9ULL,
		0x054815D65137B66AULL,
		0x582DF7EC34469744ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8617EFD14B6167CBULL,
		0xF65AA43DDFF65BEBULL,
		0xEE9A23F91C240DBBULL,
		0xE220E793EB5E1D86ULL,
		0xB035BF967BB5C19FULL,
		0x4D2574392D3E36A7ULL,
		0xE83B704A19A1B9BCULL,
		0xFB220E146F26F8C5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7BCDC8725CEED912ULL,
		0x1C60712A2A0FA888ULL,
		0x36A481FE24C45230ULL,
		0xA4686C37BAE155A7ULL,
		0xAE23953A519F734AULL,
		0x1C2FAA6436963841ULL,
		0x1D0CA58C3795FCAEULL,
		0x5D0BE9D7C51F9E7EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 207\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 207 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -207;
	} else {
		printf("Test Case 207 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xFB7B0EB3A3E134CCULL,
		0x696A4C1C6EF451B1ULL,
		0x92B4BEA0F51D033CULL,
		0x8DE69BF0264C386BULL,
		0xCB8EE190A0E2CF07ULL,
		0x92C1EF7BFBEB7E71ULL,
		0x473518F28F87AB02ULL,
		0x70F0C96E3320C52DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA4A7F0C8F561824ULL,
		0x3B964A84A514A9E0ULL,
		0x1C6D716A35EEA6E8ULL,
		0x4B1B736B0BAAC997ULL,
		0x84B471F9C7D71AC3ULL,
		0xA438966F873488F5ULL,
		0x7EA54F1F01459B79ULL,
		0xA8C32C8D9BD4EA4AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01308FA7148B1CA8ULL,
		0x2DD40197C9DFA7D1ULL,
		0x76474D36BF2E5C54ULL,
		0x42CB28851AA16ED4ULL,
		0x46DA6F96D90BB444ULL,
		0xEE89590C74B6F57CULL,
		0xC88FC9D38E420F88ULL,
		0xC82D9CE0974BDAE2ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 208\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 208 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -208;
	} else {
		printf("Test Case 208 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6133EC27E8F4BF15ULL,
		0xBA50A6F92EE1E183ULL,
		0xFA29C76620234611ULL,
		0x3B665C29CA511418ULL,
		0x21AE94F9D188AA42ULL,
		0xD5E482218801DEA7ULL,
		0x13706C5729973B45ULL,
		0x692980DF6B6AB7AEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3BE7CD3DD56BBCCULL,
		0xB74600E888AA929BULL,
		0x0D2267AE649D4CD6ULL,
		0x7B716226EE5B252BULL,
		0x3ED8396E561FA9B7ULL,
		0xDB96A9A2EE886A3DULL,
		0x269EF320726DC8BFULL,
		0xE6A31FFC2ACA3FADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8D756F540B9E0349ULL,
		0x030AA610A6374EE7ULL,
		0xED075FB7BB85F93BULL,
		0xBFF4FA02DBF5EEEDULL,
		0xE2D65B8B7B69008AULL,
		0xFA4DD87E99797469ULL,
		0xECD17936B7297285ULL,
		0x828660E340A07800ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 209\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 209 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -209;
	} else {
		printf("Test Case 209 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD738C519F2F6A5D1ULL,
		0xD7590797CF79915EULL,
		0x045BF3D50F967C4EULL,
		0x438CFAA512002EFFULL,
		0x087CB6D420F65D37ULL,
		0xC4233BC7D5B16FFAULL,
		0xEB973AC40C32153CULL,
		0xB245D14EC414A424ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2F3D8E41166FFEEULL,
		0xAA132A21679A665FULL,
		0xB6AC54364DC41575ULL,
		0x63887CBA3992BA92ULL,
		0x6251A7016EF5A961ULL,
		0xFB1FDA5767D6272AULL,
		0x2AC89DA03A30FA92ULL,
		0x9FDB3C67AFB00A7AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF444EC35E18FA5E3ULL,
		0x2D45DD7667DF2AFEULL,
		0x4DAF9F9EC1D266D9ULL,
		0xE0047DEAD86D746CULL,
		0xA62B0FD2B200B3D5ULL,
		0xC90361706DDB48CFULL,
		0xC0CE9D23D2011AA9ULL,
		0x126A94E7146499AAULL
	}};
	sign = 0;
	printf("Test Case 210\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 210 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -210;
	} else {
		printf("Test Case 210 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0257E235B57C9335ULL,
		0xE73C6B746D46ABA3ULL,
		0x5FBC9F62EE4DC25DULL,
		0xA52B9A36A80FAE0FULL,
		0x81E53CEE4B3103E2ULL,
		0xBE00C1BEBA8EF3F3ULL,
		0x1D0A0B739D57187CULL,
		0x4A82E7D2A0A04DC8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x555C0661324BC2B0ULL,
		0xE3D875247AC0B636ULL,
		0x9C19815DCD198AC7ULL,
		0x71F2FD711AEE9603ULL,
		0x56ABF7EC56C5DE25ULL,
		0x85DE583E7681823EULL,
		0x7C0ACD151D92C1A5ULL,
		0x4C61CC66EB9563E2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xACFBDBD48330D085ULL,
		0x0363F64FF285F56CULL,
		0xC3A31E0521343796ULL,
		0x33389CC58D21180BULL,
		0x2B394501F46B25BDULL,
		0x38226980440D71B5ULL,
		0xA0FF3E5E7FC456D7ULL,
		0xFE211B6BB50AE9E5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 211\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 211 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -211;
	} else {
		printf("Test Case 211 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0ACE73BE0C348BFAULL,
		0x376999A3127C183DULL,
		0x0E88CEFAE42754FAULL,
		0x3948F8F090E76ED3ULL,
		0xD86D3683A01FF746ULL,
		0x52A5C68ECE5D5266ULL,
		0x840F0D89A1E79D6AULL,
		0x94311A88DF68393FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B15973B32E6BDE1ULL,
		0x162A16FD01114D33ULL,
		0xEED001AB5C53FA7EULL,
		0x5334ECFF6269F421ULL,
		0x75F9F06AF8EECFFBULL,
		0xCE0AC1C93643DCB5ULL,
		0xB53B7BED079CDF33ULL,
		0x24B9B8635A2D14E9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9FB8DC82D94DCE19ULL,
		0x213F82A6116ACB09ULL,
		0x1FB8CD4F87D35A7CULL,
		0xE6140BF12E7D7AB1ULL,
		0x62734618A731274AULL,
		0x849B04C5981975B1ULL,
		0xCED3919C9A4ABE36ULL,
		0x6F776225853B2455ULL
	}};
	sign = 0;
	printf("Test Case 212\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 212 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -212;
	} else {
		printf("Test Case 212 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xCB765EB0CC57D82BULL,
		0x3A6ADA761812041CULL,
		0x432F0005ADB5C855ULL,
		0xF4094C0D1A6A5BC2ULL,
		0x84C8CD4100AB41FCULL,
		0x235B1B1DF01F3733ULL,
		0x296A39DB9EA06B11ULL,
		0x10ADC0FE3BF0CDB5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8648B81F4BE7D944ULL,
		0xB76DE5F47487978BULL,
		0xA107AA2CEEEE224AULL,
		0xFEF75DD78DB43E04ULL,
		0x82D4D5EDBA53349BULL,
		0x9E6B2F7E1626642CULL,
		0x06D0CAB17174ABDCULL,
		0x5A974A70532C78C1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x452DA691806FFEE7ULL,
		0x82FCF481A38A6C91ULL,
		0xA22755D8BEC7A60AULL,
		0xF511EE358CB61DBDULL,
		0x01F3F75346580D60ULL,
		0x84EFEB9FD9F8D307ULL,
		0x22996F2A2D2BBF34ULL,
		0xB616768DE8C454F4ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 213\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 213 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -213;
	} else {
		printf("Test Case 213 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF426E982EFA321CCULL,
		0xC811A97D84D60E0AULL,
		0x5DD6C2CE94183229ULL,
		0x3C3E542B130C20D5ULL,
		0x31A21E4D8E0201D5ULL,
		0x14963EFAE4B2BD0BULL,
		0x57CE0826C9A8ADFAULL,
		0x5FC6A4B9FC0B9684ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA28D2E7C15D771AULL,
		0xECF7BB6EC8D57856ULL,
		0xFD97FAF9AA88C298ULL,
		0x48BF24AADC7F8BB7ULL,
		0x7ADAE696314744C5ULL,
		0xCB2EE0A957C201C2ULL,
		0x9BF8D84261B29B4BULL,
		0x89D106755ABE4A0BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x39FE169B2E45AAB2ULL,
		0xDB19EE0EBC0095B4ULL,
		0x603EC7D4E98F6F90ULL,
		0xF37F2F80368C951DULL,
		0xB6C737B75CBABD0FULL,
		0x49675E518CF0BB48ULL,
		0xBBD52FE467F612AEULL,
		0xD5F59E44A14D4C78ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 214\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 214 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -214;
	} else {
		printf("Test Case 214 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xFFB77EFF7E409153ULL,
		0x4328416A4C95A50EULL,
		0x8D091A1568EC6CC6ULL,
		0x727008BD498EB24FULL,
		0x6B5AFDA8D14BF55CULL,
		0x0E9410589A42A8A2ULL,
		0x07E27DFAD2E503E2ULL,
		0xF0840FEE2650AD64ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA093FCD698E9E35CULL,
		0x1AF1170DDD758DF3ULL,
		0xEBAEB973BD10594DULL,
		0x7A367D6A43202226ULL,
		0x7E75744B865C3207ULL,
		0xA3771FFFEE2AF2BAULL,
		0x39BB36A110129298ULL,
		0x736E14C5D5DA3653ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5F238228E556ADF7ULL,
		0x28372A5C6F20171BULL,
		0xA15A60A1ABDC1379ULL,
		0xF8398B53066E9028ULL,
		0xECE5895D4AEFC354ULL,
		0x6B1CF058AC17B5E7ULL,
		0xCE274759C2D27149ULL,
		0x7D15FB2850767710ULL
	}};
	sign = 0;
	printf("Test Case 215\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 215 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -215;
	} else {
		printf("Test Case 215 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC26E0B1499D9D199ULL,
		0xC8F31B5694A9A316ULL,
		0xD32297596323CE17ULL,
		0x99AEF7200056FB1BULL,
		0xF6E45818C05AEA0FULL,
		0xF9258AF46308F259ULL,
		0x99C5CAE39203C263ULL,
		0xF1B7F1DB7C718068ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x553D65DCA84BC967ULL,
		0x48273EF98E78557EULL,
		0x6302B9AC14AB73F6ULL,
		0xC17A7BF5332164A0ULL,
		0x370C1B65DF594E54ULL,
		0x2E60269F3EAAC8AFULL,
		0x92F4196BB9F94C24ULL,
		0xA30F716B3371CFD4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6D30A537F18E0832ULL,
		0x80CBDC5D06314D98ULL,
		0x701FDDAD4E785A21ULL,
		0xD8347B2ACD35967BULL,
		0xBFD83CB2E1019BBAULL,
		0xCAC56455245E29AAULL,
		0x06D1B177D80A763FULL,
		0x4EA8807048FFB094ULL
	}};
	sign = 0;
	printf("Test Case 216\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 216 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -216;
	} else {
		printf("Test Case 216 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xCDA6248BEFEAF347ULL,
		0xE8F65605F318657EULL,
		0x76A18A8FE74D2A71ULL,
		0x893ED9470F6B94C1ULL,
		0x60E1DDC769D61E22ULL,
		0xD9AA4BBEB03EFD48ULL,
		0x85D2337FE0B5C452ULL,
		0x9B948854D893B6D1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x63EE9EB3028C05FCULL,
		0x6C7E03861D7C71FAULL,
		0x5804316AD55FBB05ULL,
		0x7BD9FDF9BBD8D76DULL,
		0x9E52D2ADA9843394ULL,
		0xB6113C1DA3216413ULL,
		0x5CB9FCB381A0B876ULL,
		0x53CF8CCD75468BC6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x69B785D8ED5EED4BULL,
		0x7C78527FD59BF384ULL,
		0x1E9D592511ED6F6CULL,
		0x0D64DB4D5392BD54ULL,
		0xC28F0B19C051EA8EULL,
		0x23990FA10D1D9934ULL,
		0x291836CC5F150BDCULL,
		0x47C4FB87634D2B0BULL
	}};
	sign = 0;
	printf("Test Case 217\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 217 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -217;
	} else {
		printf("Test Case 217 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7F0781127BB84B18ULL,
		0xC5A199D617D31183ULL,
		0x95B74399FB352300ULL,
		0x734396EC935E30D5ULL,
		0x5BC374162D904D3EULL,
		0xF96A18A37436E5FCULL,
		0x47EBF5B82C12D6FAULL,
		0x085310D3BBF7BF7BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x96829356E7E0BF64ULL,
		0x8A31D3B5C579EFCBULL,
		0x4935A1D32457F669ULL,
		0x90A27169629044B5ULL,
		0x8FD9EAE81B26523AULL,
		0x14B4677F955BA582ULL,
		0xE94E0304EAE6344CULL,
		0x0B80AB454B7EE2EBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE884EDBB93D78BB4ULL,
		0x3B6FC620525921B7ULL,
		0x4C81A1C6D6DD2C97ULL,
		0xE2A1258330CDEC20ULL,
		0xCBE9892E1269FB03ULL,
		0xE4B5B123DEDB4079ULL,
		0x5E9DF2B3412CA2AEULL,
		0xFCD2658E7078DC8FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 218\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 218 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -218;
	} else {
		printf("Test Case 218 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xAB5C29B9A24FEBB7ULL,
		0x7EB5A60B949DA87EULL,
		0x04D7753205D27B4CULL,
		0x5CF6E1ABCFDC6D59ULL,
		0x0ED995B9DE6F4CB7ULL,
		0x7C14676D1005A0FCULL,
		0x2DEDE2522D132D02ULL,
		0x725C6EB2242ADE62ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x833613838A937832ULL,
		0xF3A79700A3BFA148ULL,
		0x9CC1FC37FDA51593ULL,
		0x0C70FE6CDDE37CC7ULL,
		0x7303FA56F75D827FULL,
		0x8FE04742B658BFDBULL,
		0x924092AB85F91AC5ULL,
		0x28BB1EA676F13866ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2826163617BC7385ULL,
		0x8B0E0F0AF0DE0736ULL,
		0x681578FA082D65B8ULL,
		0x5085E33EF1F8F091ULL,
		0x9BD59B62E711CA38ULL,
		0xEC34202A59ACE120ULL,
		0x9BAD4FA6A71A123CULL,
		0x49A1500BAD39A5FBULL
	}};
	sign = 0;
	printf("Test Case 219\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 219 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -219;
	} else {
		printf("Test Case 219 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9C401A63FB68A0B5ULL,
		0x8023993AB13404C2ULL,
		0xEAF46C7282A19443ULL,
		0xA236B4B52F021699ULL,
		0x79FCF5A4280316F8ULL,
		0x946605B9B277DE75ULL,
		0x8042C9A63E1C899AULL,
		0xF024FECFDA80EBF3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x922DDC015B02CF3EULL,
		0x6606EC9E3078404FULL,
		0x7D8C56DD8D70E27BULL,
		0x13C1FB9F004E88CDULL,
		0xF727527B280F277DULL,
		0x78C0BE2D938FB4BCULL,
		0x475F5B2353308723ULL,
		0x13BB1279BE6B81CCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A123E62A065D177ULL,
		0x1A1CAC9C80BBC473ULL,
		0x6D681594F530B1C8ULL,
		0x8E74B9162EB38DCCULL,
		0x82D5A328FFF3EF7BULL,
		0x1BA5478C1EE829B8ULL,
		0x38E36E82EAEC0277ULL,
		0xDC69EC561C156A27ULL
	}};
	sign = 0;
	printf("Test Case 220\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 220 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -220;
	} else {
		printf("Test Case 220 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x08E35B7600116F0EULL,
		0xE83D1D7AD56BE8CAULL,
		0xF3A75C9E566E0EF8ULL,
		0x93E7D57A2421C9B1ULL,
		0x13EA234139DC3DABULL,
		0x1A118FD5E0D99FB7ULL,
		0x90AA47EA59DD0A9EULL,
		0xAD917D7D4CCC1C54ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD203C7E7C55619A4ULL,
		0xDCBC8FC4028822DCULL,
		0x975DAA84F25975CEULL,
		0xF02604F1707D9654ULL,
		0x5B68167A8720A0EAULL,
		0x9AF3642AB0F26D77ULL,
		0x8B30C069FC748266ULL,
		0xBBA0EB0005C8A595ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x36DF938E3ABB556AULL,
		0x0B808DB6D2E3C5EDULL,
		0x5C49B2196414992AULL,
		0xA3C1D088B3A4335DULL,
		0xB8820CC6B2BB9CC0ULL,
		0x7F1E2BAB2FE7323FULL,
		0x057987805D688837ULL,
		0xF1F0927D470376BFULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 221\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 221 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -221;
	} else {
		printf("Test Case 221 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE2E618D631F88C4BULL,
		0x7B1194A3D64084E9ULL,
		0xDDA2CDBA2BEBB0EAULL,
		0x7763EBEAA4E9D424ULL,
		0x8A293B7ECF13A1C9ULL,
		0x81F3F0795D8EA433ULL,
		0x9A3EBBC008E4D1FBULL,
		0xA27DDA31BA43DA7BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A193B8E7FDD5577ULL,
		0x78A0C33163FAF582ULL,
		0xC56EFC2E39172872ULL,
		0x911D8A84CA0D1A99ULL,
		0xC541D49CD44CE608ULL,
		0xA02A0E0289AA2DEEULL,
		0xF29A8AB1379C3157ULL,
		0x7B7011151D3CAAA7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x98CCDD47B21B36D4ULL,
		0x0270D17272458F67ULL,
		0x1833D18BF2D48878ULL,
		0xE6466165DADCB98BULL,
		0xC4E766E1FAC6BBC0ULL,
		0xE1C9E276D3E47644ULL,
		0xA7A4310ED148A0A3ULL,
		0x270DC91C9D072FD3ULL
	}};
	sign = 0;
	printf("Test Case 222\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 222 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -222;
	} else {
		printf("Test Case 222 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB9B3F2C51FB996FBULL,
		0x3AE76C2D17469CB3ULL,
		0x6524AEFCF207BC74ULL,
		0x415D5096D60664B6ULL,
		0x3B3A1FE89E671B46ULL,
		0x8400E01AEC14016CULL,
		0x1C6631949EA6414EULL,
		0x45962DB1151B9371ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C439EA93FFE35DFULL,
		0x097CA0E9F7C38B2DULL,
		0x33538C9DA54EAE7CULL,
		0x37392EA2392DBB49ULL,
		0xFCEE920D8DB30EC5ULL,
		0x2DDFA6F9EEA4628EULL,
		0xDA87B14C24E0BF45ULL,
		0x1110C2D6D1B8D767ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3D70541BDFBB611CULL,
		0x316ACB431F831186ULL,
		0x31D1225F4CB90DF8ULL,
		0x0A2421F49CD8A96DULL,
		0x3E4B8DDB10B40C81ULL,
		0x56213920FD6F9EDDULL,
		0x41DE804879C58209ULL,
		0x34856ADA4362BC09ULL
	}};
	sign = 0;
	printf("Test Case 223\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 223 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -223;
	} else {
		printf("Test Case 223 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4F147DFEB9094057ULL,
		0x0B1086FDD8BEEE0AULL,
		0xEF437DEBE06CE98EULL,
		0x55E91CA49198A548ULL,
		0xB62337D8F20E55FEULL,
		0x84DFE91D6940DF18ULL,
		0xB0B46D94A5B1633DULL,
		0x9550EECE5F01D990ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9B0D64E710A796EULL,
		0x798BF5D01D15F984ULL,
		0x16430DC7704D231FULL,
		0x53F3FE0C969B6CD7ULL,
		0xFA8F59FD578DAC33ULL,
		0xD8568B85E1527EA6ULL,
		0x2C5D257410653C60ULL,
		0x4DDE313CD1D01BC3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9563A7B047FEC6E9ULL,
		0x9184912DBBA8F485ULL,
		0xD9007024701FC66EULL,
		0x01F51E97FAFD3871ULL,
		0xBB93DDDB9A80A9CBULL,
		0xAC895D9787EE6071ULL,
		0x84574820954C26DCULL,
		0x4772BD918D31BDCDULL
	}};
	sign = 0;
	printf("Test Case 224\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 224 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -224;
	} else {
		printf("Test Case 224 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x93355C35BD6F7B57ULL,
		0xCB6B2CDA2A055E88ULL,
		0xE6E86B1E05127DE5ULL,
		0xBF437F3A93C106F6ULL,
		0x80BF4EFFBCF52B09ULL,
		0x4EF732E744E1B4A3ULL,
		0x11C23A9DD9EBB75BULL,
		0x3ACDB9F206D16438ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE66A575CE39C1DA9ULL,
		0x04EB6B836E5FCD0DULL,
		0x28B71F70EA795F5BULL,
		0xDCA259270EB9921CULL,
		0x3334BDA102C1341EULL,
		0x18C16EB389865939ULL,
		0x9D3385C390817934ULL,
		0x9605F24AF256CB20ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xACCB04D8D9D35DAEULL,
		0xC67FC156BBA5917AULL,
		0xBE314BAD1A991E8AULL,
		0xE2A12613850774DAULL,
		0x4D8A915EBA33F6EAULL,
		0x3635C433BB5B5B6AULL,
		0x748EB4DA496A3E27ULL,
		0xA4C7C7A7147A9917ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 225\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 225 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -225;
	} else {
		printf("Test Case 225 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9077ECBD2FF5B610ULL,
		0xDDA7FA330AF9210BULL,
		0x8D12AA72398C968BULL,
		0x17D0B82EADBB9866ULL,
		0x6DC61C6D6F9E9E7FULL,
		0x1E0210C838251936ULL,
		0x300F6F6EFA58CD56ULL,
		0x290109228FBBD7DAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3884C77372712528ULL,
		0x291FD7F33D675156ULL,
		0x0885FBDF8E376A9FULL,
		0x01FD31D3DD74C889ULL,
		0xDA839658672BE7A7ULL,
		0x6AA0889AB4E2622CULL,
		0x4E532CFA359EC0B3ULL,
		0xC805D7F302A7CD20ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x57F32549BD8490E8ULL,
		0xB488223FCD91CFB5ULL,
		0x848CAE92AB552BECULL,
		0x15D3865AD046CFDDULL,
		0x934286150872B6D8ULL,
		0xB361882D8342B709ULL,
		0xE1BC4274C4BA0CA2ULL,
		0x60FB312F8D140AB9ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 226\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 226 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -226;
	} else {
		printf("Test Case 226 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x17DD13A631639D00ULL,
		0xE5048EF735541DC8ULL,
		0x710F532461DA1CEAULL,
		0x3B92DC7F8155922AULL,
		0x4A2F6926C2AAEB68ULL,
		0x11C4B26375B06EECULL,
		0x7955DC3BECEDB18BULL,
		0xF8EB3B3DC6DDE930ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8E1D36D6E6E535BULL,
		0xA4D25337B2D70199ULL,
		0xC36A18779C4CB3DFULL,
		0x74E4C241EF7792C6ULL,
		0x90DCD9259B38AF40ULL,
		0xCB911662E6FB73F4ULL,
		0x1F937F40B5E2AB95ULL,
		0x7235CEDA165B4EEBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6EFB4038C2F549A5ULL,
		0x40323BBF827D1C2EULL,
		0xADA53AACC58D690BULL,
		0xC6AE1A3D91DDFF63ULL,
		0xB952900127723C27ULL,
		0x46339C008EB4FAF7ULL,
		0x59C25CFB370B05F5ULL,
		0x86B56C63B0829A45ULL
	}};
	sign = 0;
	printf("Test Case 227\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 227 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -227;
	} else {
		printf("Test Case 227 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7BE0F9BCCF973C5EULL,
		0xB620538B2B6FD375ULL,
		0x6E19DEE887D1FFC2ULL,
		0x894AE12A2009D6E1ULL,
		0x7402106C864F89C7ULL,
		0x4854A45D26C1DFC3ULL,
		0x7C6CD305D1424379ULL,
		0x6510DA707542CF56ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D4D08A04B4C66AFULL,
		0x83C98B4F501DEA21ULL,
		0xAA91BA9CC91C44D6ULL,
		0xE328E3CBDAA39B3BULL,
		0xC3B9987FD154D1CFULL,
		0x3E635E2AD46FD706ULL,
		0xF2E8764B8AAA168FULL,
		0xD551CA23C7FF6E2AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4E93F11C844AD5AFULL,
		0x3256C83BDB51E954ULL,
		0xC388244BBEB5BAECULL,
		0xA621FD5E45663BA5ULL,
		0xB04877ECB4FAB7F7ULL,
		0x09F14632525208BCULL,
		0x89845CBA46982CEAULL,
		0x8FBF104CAD43612BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 228\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 228 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -228;
	} else {
		printf("Test Case 228 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9D11D7BB8FE73D0BULL,
		0xAE825D2DE70253BDULL,
		0xE5CA0A15DC09C9D7ULL,
		0x32DDB1F6AA58F745ULL,
		0xF4D0AD25C5FAE4C0ULL,
		0x8B8B86B47453D545ULL,
		0x373EC1D0EB228AF6ULL,
		0xCC3CF57BF4276B26ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x13EF0150F3FFCC1BULL,
		0x2F73E30059C94DBCULL,
		0x2AADCF28267B1C7EULL,
		0xB52BB431B1824093ULL,
		0x25BAA9BFFB876C78ULL,
		0x90D9F0355578FA73ULL,
		0xF40FC51E498D8AB6ULL,
		0x45F81DD508578F32ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8922D66A9BE770F0ULL,
		0x7F0E7A2D8D390601ULL,
		0xBB1C3AEDB58EAD59ULL,
		0x7DB1FDC4F8D6B6B2ULL,
		0xCF160365CA737847ULL,
		0xFAB1967F1EDADAD2ULL,
		0x432EFCB2A195003FULL,
		0x8644D7A6EBCFDBF3ULL
	}};
	sign = 0;
	printf("Test Case 229\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 229 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -229;
	} else {
		printf("Test Case 229 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x3CD8040B7AC099C2ULL,
		0xD2C572EFFCD0B9EFULL,
		0x67CD322333457CBFULL,
		0xC5605DC35A3F5237ULL,
		0xA00A739AFD03127FULL,
		0x1E0A44D24BC95132ULL,
		0x7F2685A2A2ADE3CDULL,
		0x5372358EA84B2280ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE06CCAD502C5EF6CULL,
		0xC70453CFF67424D4ULL,
		0x21657D82FA012F76ULL,
		0xE19F7E5F7E443999ULL,
		0x604B42F137CE0631ULL,
		0x40151F314ED99F0CULL,
		0xA243EE0EB1F5AB13ULL,
		0xB83777E1FE62B42FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5C6B393677FAAA56ULL,
		0x0BC11F20065C951AULL,
		0x4667B4A039444D49ULL,
		0xE3C0DF63DBFB189EULL,
		0x3FBF30A9C5350C4DULL,
		0xDDF525A0FCEFB226ULL,
		0xDCE29793F0B838B9ULL,
		0x9B3ABDACA9E86E50ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 230\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 230 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -230;
	} else {
		printf("Test Case 230 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5B145546FBFB2841ULL,
		0x1C1020D8A3056973ULL,
		0x915D982E3EF35323ULL,
		0x079E85F15A40836FULL,
		0x5E873CC052E7B221ULL,
		0xB4573748481B8275ULL,
		0x6AC112BB24548AC7ULL,
		0x817BE6FDC8904831ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAEDA167E59520E2BULL,
		0xDD786D02D3D00912ULL,
		0x3413BB793C5D10D0ULL,
		0x18E0A6D4FB6786BAULL,
		0xB81E5E877A41B28BULL,
		0x7A8A193BD55FCA3DULL,
		0x07CD5933A77AF845ULL,
		0xC325D155A975690FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAC3A3EC8A2A91A16ULL,
		0x3E97B3D5CF356060ULL,
		0x5D49DCB502964252ULL,
		0xEEBDDF1C5ED8FCB5ULL,
		0xA668DE38D8A5FF95ULL,
		0x39CD1E0C72BBB837ULL,
		0x62F3B9877CD99282ULL,
		0xBE5615A81F1ADF22ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 231\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 231 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -231;
	} else {
		printf("Test Case 231 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xEC1FCFCBA480BC3CULL,
		0xB1B4D6545489965BULL,
		0x056FAFCF469D84D9ULL,
		0xCCE54778C2188B56ULL,
		0x2C41A8C4B123CD66ULL,
		0x753C43113739C188ULL,
		0xE0BF04059CD2EA75ULL,
		0x96371CB343054D34ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x895C42D7896DC689ULL,
		0x897ABA8C3879EA29ULL,
		0xCDF49F4BE19B3A0EULL,
		0x3C5E6AF0793178FBULL,
		0xEEA6B7C8132A8E27ULL,
		0xF338F7351E7065FFULL,
		0x795674E931BE31CAULL,
		0x44EDE4B1598289C9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x62C38CF41B12F5B3ULL,
		0x283A1BC81C0FAC32ULL,
		0x377B108365024ACBULL,
		0x9086DC8848E7125AULL,
		0x3D9AF0FC9DF93F3FULL,
		0x82034BDC18C95B88ULL,
		0x67688F1C6B14B8AAULL,
		0x51493801E982C36BULL
	}};
	sign = 0;
	printf("Test Case 232\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 232 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -232;
	} else {
		printf("Test Case 232 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1BCF1C93FA1C918EULL,
		0x3424E05C724FD3C6ULL,
		0xA1317D0D30D2E9ABULL,
		0x0CE9E25C5A93A702ULL,
		0x4D19D9DC12D37667ULL,
		0x02BB4BFF2BC1DF11ULL,
		0xF076C8EEB11AFAD1ULL,
		0xB2958E3EC5694871ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE98688408CC0BDBULL,
		0xE1BBB6C46737AB53ULL,
		0xBDAC66EF9A241C8FULL,
		0xB134947CFB0C52ACULL,
		0x9343659EEA523671ULL,
		0xB0E9F99F84CE8DF9ULL,
		0xB534D71A9BC3DDA2ULL,
		0x3F3110FE8D746D82ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4D36B40FF15085B3ULL,
		0x526929980B182872ULL,
		0xE385161D96AECD1BULL,
		0x5BB54DDF5F875455ULL,
		0xB9D6743D28813FF5ULL,
		0x51D1525FA6F35117ULL,
		0x3B41F1D415571D2EULL,
		0x73647D4037F4DAEFULL
	}};
	sign = 0;
	printf("Test Case 233\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 233 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -233;
	} else {
		printf("Test Case 233 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9210A1B581645841ULL,
		0x04CE3DBF658A0879ULL,
		0xEA66091975045997ULL,
		0xD54965CD5CFA3A8AULL,
		0x86EF401447D02A83ULL,
		0x2A152C5D01F5A357ULL,
		0x5E4C6341254BF5E8ULL,
		0x9A8FFBB2C93C361DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD278CA8571523A33ULL,
		0xF4BA869985C0B1EEULL,
		0x9EB153964D3A0370ULL,
		0x2D87EBE3CDF26B2FULL,
		0x73B8FE6C6BA5C932ULL,
		0xC61E5764098389A6ULL,
		0xF1CF18415CFFD4ACULL,
		0x6B70F24B45B27DCDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBF97D73010121E0EULL,
		0x1013B725DFC9568AULL,
		0x4BB4B58327CA5626ULL,
		0xA7C179E98F07CF5BULL,
		0x133641A7DC2A6151ULL,
		0x63F6D4F8F87219B1ULL,
		0x6C7D4AFFC84C213BULL,
		0x2F1F09678389B84FULL
	}};
	sign = 0;
	printf("Test Case 234\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 234 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -234;
	} else {
		printf("Test Case 234 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4B2D7828FF8944F6ULL,
		0xF480FC9627FECA79ULL,
		0xE5191556C43C26CEULL,
		0x63C3AB0E6CC20D00ULL,
		0x9A3505BFD9D3E638ULL,
		0xA1443B029FA6E2C9ULL,
		0x3CB5B18C82AB7528ULL,
		0x1460054FA0249FCEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x38331214B0B8BC37ULL,
		0x73089611B3AB23EBULL,
		0x7FC5DDD07A5808EDULL,
		0xD500DFD4896944CBULL,
		0xD9E63F2E104C3BF2ULL,
		0x1E8D098881B72C72ULL,
		0xD57045FBEF8A94F3ULL,
		0xB82296D7A27FF276ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x12FA66144ED088BFULL,
		0x817866847453A68EULL,
		0x6553378649E41DE1ULL,
		0x8EC2CB39E358C835ULL,
		0xC04EC691C987AA45ULL,
		0x82B7317A1DEFB656ULL,
		0x67456B909320E035ULL,
		0x5C3D6E77FDA4AD57ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 235\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 235 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -235;
	} else {
		printf("Test Case 235 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD6EB691FD702C3B8ULL,
		0xB8886BF7A5FC7C70ULL,
		0x921737850F31FA85ULL,
		0xF050CBC93ACD152BULL,
		0x393B0416D7AAF117ULL,
		0x22C5ADEB222117C3ULL,
		0x7644A10DA34206E3ULL,
		0x4A40CBB0B9A64EEBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x698D0C90D28A5E85ULL,
		0x2729187FF5D9C11EULL,
		0xE980CEE336517F25ULL,
		0x8D4D01586CC11B21ULL,
		0x6AE3BA61DD1798B0ULL,
		0x98BAB7487E59CD07ULL,
		0x25B43B7AF08BB536ULL,
		0x5E092D717B8244B2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6D5E5C8F04786533ULL,
		0x915F5377B022BB52ULL,
		0xA89668A1D8E07B60ULL,
		0x6303CA70CE0BFA09ULL,
		0xCE5749B4FA935867ULL,
		0x8A0AF6A2A3C74ABBULL,
		0x50906592B2B651ACULL,
		0xEC379E3F3E240A39ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 236\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 236 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -236;
	} else {
		printf("Test Case 236 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA74743ADE1CF4603ULL,
		0x488946F9B06128BFULL,
		0x1F6AB90C0815B704ULL,
		0x633FEC528440F709ULL,
		0xFB461D8D83401DDCULL,
		0x872B90336B44BAC6ULL,
		0x4A30CA8ED8DE0868ULL,
		0xCD837A34E20ABA4DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD77803466F48D36ULL,
		0x3AEBEB88ADFDF3F2ULL,
		0x9484E3A0D18D9D9EULL,
		0x33952ABE6A02B090ULL,
		0x7C568C6CDE65CAB1ULL,
		0x8F003B7D6019844BULL,
		0xF0F319C57BD973FDULL,
		0x0110E164B4426FCEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA9CFC3797ADAB8CDULL,
		0x0D9D5B71026334CCULL,
		0x8AE5D56B36881966ULL,
		0x2FAAC1941A3E4678ULL,
		0x7EEF9120A4DA532BULL,
		0xF82B54B60B2B367BULL,
		0x593DB0C95D04946AULL,
		0xCC7298D02DC84A7EULL
	}};
	sign = 0;
	printf("Test Case 237\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 237 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -237;
	} else {
		printf("Test Case 237 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x8BC1434D4148657EULL,
		0x0E6FB79AF89C265EULL,
		0x834B6B28794434D4ULL,
		0xBC944503D0569C60ULL,
		0x1C706789F6C620C7ULL,
		0x2F3BB76C5E98B619ULL,
		0x1A863681A668BED9ULL,
		0x2A5DF49E3403DF86ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2BE8C203F9B1BB19ULL,
		0xD12D1D28C27A436EULL,
		0xD9C2D8082778AFD5ULL,
		0xBCF1C46D6EC61F26ULL,
		0xE3604F85A20E7439ULL,
		0xA80904BACD6762C8ULL,
		0xF8FAF2E0795D274AULL,
		0x67DC40A74CAD04E0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5FD881494796AA65ULL,
		0x3D429A723621E2F0ULL,
		0xA988932051CB84FEULL,
		0xFFA2809661907D39ULL,
		0x3910180454B7AC8DULL,
		0x8732B2B191315350ULL,
		0x218B43A12D0B978EULL,
		0xC281B3F6E756DAA5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 238\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 238 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -238;
	} else {
		printf("Test Case 238 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF2FE27B7E49F29C0ULL,
		0x8B241E2833EBB59BULL,
		0x0E8F68C5FF8B9224ULL,
		0xECBECCCC10B2DCADULL,
		0x8005E3B78CBC8E39ULL,
		0xDFB107DF92714E00ULL,
		0x6B3530E63A1DDA8EULL,
		0xC1825E9F8A4E03C0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C638223A35EA3CDULL,
		0x997D0038C75F4DB9ULL,
		0xC366AE02DCC8B85CULL,
		0xAB2C9ADFE15037D3ULL,
		0x3482AAE3C054BD0EULL,
		0x7286254BB9D573C2ULL,
		0x4A566A9F29D74A06ULL,
		0xF2F81064FCFC716EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x769AA594414085F3ULL,
		0xF1A71DEF6C8C67E2ULL,
		0x4B28BAC322C2D9C7ULL,
		0x419231EC2F62A4D9ULL,
		0x4B8338D3CC67D12BULL,
		0x6D2AE293D89BDA3EULL,
		0x20DEC64710469088ULL,
		0xCE8A4E3A8D519252ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 239\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 239 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -239;
	} else {
		printf("Test Case 239 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x362F5503FD028939ULL,
		0x5ECDB1E9B19413E9ULL,
		0x85284AB9C66662A6ULL,
		0x3985F5882738B7A5ULL,
		0x273690CD364C838BULL,
		0x460A7366EBB4AEC5ULL,
		0x251B1E0C0E868408ULL,
		0xF3D7C82E1983C3BAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x26C52F1B9ADC2F63ULL,
		0xE3BE913F1F019EE8ULL,
		0x7033428ED8193596ULL,
		0x20FF5ED7290FE9A1ULL,
		0x9FFF0D59A522EA98ULL,
		0x4D9689B4170A0D1BULL,
		0x24640EE9C321E52FULL,
		0x39CEFD1989B2ADCCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F6A25E8622659D6ULL,
		0x7B0F20AA92927501ULL,
		0x14F5082AEE4D2D0FULL,
		0x188696B0FE28CE04ULL,
		0x87378373912998F3ULL,
		0xF873E9B2D4AAA1A9ULL,
		0x00B70F224B649ED8ULL,
		0xBA08CB148FD115EEULL
	}};
	sign = 0;
	printf("Test Case 240\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 240 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -240;
	} else {
		printf("Test Case 240 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xCF7571BDD64B9AFFULL,
		0x14568DA1FCBAB1E0ULL,
		0xF8510FA31F5FE4C6ULL,
		0xD0F478FAAB633628ULL,
		0xA94B578347EA0A2AULL,
		0x7003D0430EDDD7E3ULL,
		0xF9CF03A3C9662BE4ULL,
		0xAB82BB00E652D0F1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x152025E6FDEE625EULL,
		0x3F09F0ADAC7C0AFDULL,
		0xF9C315E17D67A8ABULL,
		0x579538D4BB68B7BDULL,
		0x009955DDE29ABD66ULL,
		0x1497CF9F2FDF2237ULL,
		0x7FEDA3C11754D830ULL,
		0x4BAC8171CD61856CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBA554BD6D85D38A1ULL,
		0xD54C9CF4503EA6E3ULL,
		0xFE8DF9C1A1F83C1AULL,
		0x795F4025EFFA7E6AULL,
		0xA8B201A5654F4CC4ULL,
		0x5B6C00A3DEFEB5ACULL,
		0x79E15FE2B21153B4ULL,
		0x5FD6398F18F14B85ULL
	}};
	sign = 0;
	printf("Test Case 241\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 241 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -241;
	} else {
		printf("Test Case 241 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x12F043A3805E05E8ULL,
		0xD4402596A30ECA98ULL,
		0x35218B0A7DA2BB38ULL,
		0xCC7E2993D0D3E76AULL,
		0xDFAC4719B6B0825AULL,
		0x9E23C59C385EAEEDULL,
		0x202AE3DE131A8C76ULL,
		0x15DD2876F0D678C2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9765862FDE61BA64ULL,
		0x543E582CD2BEA0B2ULL,
		0x91FABB6D31A406EBULL,
		0x348490F5B209C338ULL,
		0xFE717C79C091B316ULL,
		0x5CEE0269E07CF686ULL,
		0xF15803DBA7E3EFE0ULL,
		0xAEFF91BEECF91E7FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7B8ABD73A1FC4B84ULL,
		0x8001CD69D05029E5ULL,
		0xA326CF9D4BFEB44DULL,
		0x97F9989E1ECA2431ULL,
		0xE13ACA9FF61ECF44ULL,
		0x4135C33257E1B866ULL,
		0x2ED2E0026B369C96ULL,
		0x66DD96B803DD5A42ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 242\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 242 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -242;
	} else {
		printf("Test Case 242 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x2684C82FB44A0460ULL,
		0x3154D07A37C9C9F6ULL,
		0x140ACA0CD6F2997DULL,
		0x89D5D0E1C61DBCE4ULL,
		0x7DD441BE16870DBAULL,
		0xD2E7963AF3F3A92FULL,
		0x8F42F8166EF18B52ULL,
		0xE2C184C91296337FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x875204040888A563ULL,
		0xEB36A829F46B5F2FULL,
		0x1874F3629FE0BED6ULL,
		0xF8D905795B3D235CULL,
		0x0BCEE50F0188B880ULL,
		0xD0C10AAD0AD0CC2AULL,
		0xB478D9EE5285D8E4ULL,
		0x3597FFE71EC342D2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9F32C42BABC15EFDULL,
		0x461E2850435E6AC6ULL,
		0xFB95D6AA3711DAA6ULL,
		0x90FCCB686AE09987ULL,
		0x72055CAF14FE5539ULL,
		0x02268B8DE922DD05ULL,
		0xDACA1E281C6BB26EULL,
		0xAD2984E1F3D2F0ACULL
	}};
	sign = 0;
	printf("Test Case 243\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 243 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -243;
	} else {
		printf("Test Case 243 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4D8D73589E89B46DULL,
		0xA4EA89CCC90A91E8ULL,
		0x84AAFD75C9263C97ULL,
		0xD1CD299A8E616B72ULL,
		0xEC05F2E156F84D47ULL,
		0x26F34185991D3D5BULL,
		0x6EC3E1BC83AD790FULL,
		0xB86F6E0B37149DD9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B9FDB25C484695FULL,
		0xD358430479B4D839ULL,
		0x42C38DF7DC2A8831ULL,
		0x606DEBB53CA27AEFULL,
		0x59A1FF3C907D61F6ULL,
		0x06205470DCBD0010ULL,
		0x9A58691DF01CA948ULL,
		0xEC561539E35E8B8AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x31ED9832DA054B0EULL,
		0xD19246C84F55B9AFULL,
		0x41E76F7DECFBB465ULL,
		0x715F3DE551BEF083ULL,
		0x9263F3A4C67AEB51ULL,
		0x20D2ED14BC603D4BULL,
		0xD46B789E9390CFC7ULL,
		0xCC1958D153B6124EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 244\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 244 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -244;
	} else {
		printf("Test Case 244 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x55A1987B6AB2ECFFULL,
		0x38DA4DF19DDB7F4AULL,
		0xB5034429C998797CULL,
		0xB55DB405FCFD9DF9ULL,
		0x9B9C3277BEF865F2ULL,
		0x31062FF4ED86E5C6ULL,
		0xA6B96BC20F28B3D8ULL,
		0x149915D34A61151FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1C5E3247AA83793ULL,
		0xFE6DCE9AC5E7A814ULL,
		0x3907E435B219382DULL,
		0x1ABC5321440CC744ULL,
		0xEE1E0C06A3335573ULL,
		0x2F2A5E905C78A7EBULL,
		0x920F8208717976BCULL,
		0x95C538FF92C9D33BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x73DBB556F00AB56CULL,
		0x3A6C7F56D7F3D735ULL,
		0x7BFB5FF4177F414EULL,
		0x9AA160E4B8F0D6B5ULL,
		0xAD7E26711BC5107FULL,
		0x01DBD164910E3DDAULL,
		0x14A9E9B99DAF3D1CULL,
		0x7ED3DCD3B79741E4ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 245\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 245 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -245;
	} else {
		printf("Test Case 245 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6B425695205921A8ULL,
		0x6BCD3F54D3DCEE7DULL,
		0xD3C9523055FB8F09ULL,
		0xDAB55D1D61EBD54DULL,
		0xED5C815CC8C56062ULL,
		0x7EF4A1415B82A49AULL,
		0x8C273A5897EF207AULL,
		0x21979589E0685319ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA5ED3837BCF8BB0ULL,
		0x160EA9D732CA815FULL,
		0x51888CF3F8277D41ULL,
		0x945FB718C5607AB2ULL,
		0x0F3780C3B35593D1ULL,
		0x4AABA3A0C4350BD9ULL,
		0xCEE0838C7CC6950CULL,
		0xFEDDBEEDF82AE4A3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC0E38311A48995F8ULL,
		0x55BE957DA1126D1DULL,
		0x8240C53C5DD411C8ULL,
		0x4655A6049C8B5A9BULL,
		0xDE250099156FCC91ULL,
		0x3448FDA0974D98C1ULL,
		0xBD46B6CC1B288B6EULL,
		0x22B9D69BE83D6E75ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 246\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 246 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -246;
	} else {
		printf("Test Case 246 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xDE14A642019E24CEULL,
		0xBF3DE2D091C4C023ULL,
		0x03465A599B316352ULL,
		0xB9A95812CF81A606ULL,
		0x1A9F0D6967384834ULL,
		0x59A3170F3AA393CBULL,
		0xF089A5BDA15C2405ULL,
		0x623C8172DCEA5C7CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4168859E0645E130ULL,
		0x5A4BFDDDF38DD7F9ULL,
		0x3EC0B460A8B0B7B1ULL,
		0x0B91C05EB6386CABULL,
		0x740B29191A26D2F4ULL,
		0xE403A9046C62D39DULL,
		0x95C59062A4B66004ULL,
		0xD8051191CF238583ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9CAC20A3FB58439EULL,
		0x64F1E4F29E36E82AULL,
		0xC485A5F8F280ABA1ULL,
		0xAE1797B41949395AULL,
		0xA693E4504D117540ULL,
		0x759F6E0ACE40C02DULL,
		0x5AC4155AFCA5C400ULL,
		0x8A376FE10DC6D6F9ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 247\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 247 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -247;
	} else {
		printf("Test Case 247 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4150BC2EA739264EULL,
		0x39F99E1B16256E7DULL,
		0xD0BAFDA059119038ULL,
		0xC9B1C730D4E0B04CULL,
		0x89F9EAC0FA1C0A71ULL,
		0xB6B9D065FD29B7D4ULL,
		0x57953B1B4B015629ULL,
		0xBEF450B0C75BAAA7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4554F04E7412C56BULL,
		0x6E6279DEF372973AULL,
		0xC2062B4A15144598ULL,
		0xAE579B38E8CABEF4ULL,
		0xF078A058D797723CULL,
		0x1CEED76416B5EF37ULL,
		0x7F9A61B80EE9158EULL,
		0xB92232DF6DBCAFEFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFBFBCBE0332660E3ULL,
		0xCB97243C22B2D742ULL,
		0x0EB4D25643FD4A9FULL,
		0x1B5A2BF7EC15F158ULL,
		0x99814A6822849835ULL,
		0x99CAF901E673C89CULL,
		0xD7FAD9633C18409BULL,
		0x05D21DD1599EFAB7ULL
	}};
	sign = 0;
	printf("Test Case 248\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 248 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -248;
	} else {
		printf("Test Case 248 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA37997C42C6DA87DULL,
		0x7DD3C87B700D9BBEULL,
		0x00A61D8260FEFD21ULL,
		0x04DD086B662BB971ULL,
		0x2CDB13F7F378FEB4ULL,
		0xB2EE8F2E407AC053ULL,
		0x3019D6E6FA0C973FULL,
		0xAC8969E278BDF2AEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB6DE8C832CE5AF0ULL,
		0x7905E743087D4CF8ULL,
		0x839AEFEEFA2AA9DDULL,
		0xE7F2C821ECF04492ULL,
		0x2DCD35296359CE09ULL,
		0x5323FE80471DF9BBULL,
		0x8B3899D7C8180416ULL,
		0x519670D3FD04BB73ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE80BAEFBF99F4D8DULL,
		0x04CDE13867904EC5ULL,
		0x7D0B2D9366D45344ULL,
		0x1CEA4049793B74DEULL,
		0xFF0DDECE901F30AAULL,
		0x5FCA90ADF95CC697ULL,
		0xA4E13D0F31F49329ULL,
		0x5AF2F90E7BB9373AULL
	}};
	sign = 0;
	printf("Test Case 249\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 249 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -249;
	} else {
		printf("Test Case 249 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD246B87D11277323ULL,
		0x0DA00A28D12CBECDULL,
		0xEA7C38D67CD5E5DFULL,
		0x59701AB5170F76F0ULL,
		0x19B0B49BBBDD5448ULL,
		0xCE8B74C7734FF194ULL,
		0x2D0D968B7F3087C8ULL,
		0xE87EF927A35F5FA2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CEF29F103B8BA29ULL,
		0x430E1C0D656B1684ULL,
		0xC8999265E4552BF0ULL,
		0x3C0F6161A91CFF28ULL,
		0x095B167511AD1CE4ULL,
		0x78F693B641FA4616ULL,
		0xF797EB31506B826AULL,
		0xDE6C1F683A3B0ECBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB5578E8C0D6EB8FAULL,
		0xCA91EE1B6BC1A849ULL,
		0x21E2A6709880B9EEULL,
		0x1D60B9536DF277C8ULL,
		0x10559E26AA303764ULL,
		0x5594E1113155AB7EULL,
		0x3575AB5A2EC5055EULL,
		0x0A12D9BF692450D6ULL
	}};
	sign = 0;
	printf("Test Case 250\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 250 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -250;
	} else {
		printf("Test Case 250 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x68CFED6BB9306111ULL,
		0xECCC76DFD534FFE1ULL,
		0x5ED485A72AA659A5ULL,
		0x10EF2D612B8BC362ULL,
		0xC73CDE10AB923BB2ULL,
		0x8C0E82BE19245C2CULL,
		0x18643D658D5EA39EULL,
		0xB0C87A5893FB2C40ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CF3DB9566D2FD97ULL,
		0x4FA7DCA8BB933FA8ULL,
		0xAFAEC4572B28F00BULL,
		0xBF4A29FE3622F03AULL,
		0x42DA479BF6FE0412ULL,
		0x0D29850AFF332384ULL,
		0xAD9F3AABDCAB9DA2ULL,
		0x21EE5BDD586B47B4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDBDC11D6525D637AULL,
		0x9D249A3719A1C038ULL,
		0xAF25C14FFF7D699AULL,
		0x51A50362F568D327ULL,
		0x84629674B494379FULL,
		0x7EE4FDB319F138A8ULL,
		0x6AC502B9B0B305FCULL,
		0x8EDA1E7B3B8FE48BULL
	}};
	sign = 0;
	printf("Test Case 251\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 251 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -251;
	} else {
		printf("Test Case 251 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB10F40C5C1D66FBEULL,
		0xD7FF5A9899A2A5E4ULL,
		0xA936CCEA2F34DD45ULL,
		0xA219EAE36D9BE6DBULL,
		0x7185B7560CE21421ULL,
		0xA61BE1119C005226ULL,
		0x0F5A0FAC0007D986ULL,
		0x5D149093AB38933EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5767979F5DCEA2BULL,
		0x6383D39F38AC1D34ULL,
		0xAAE0D7CFF1C2E88CULL,
		0x1113680FA6FFA4C4ULL,
		0x976394661FCD2C4AULL,
		0x796B0D6E666F9DFDULL,
		0xEA198B6F7B669AA8ULL,
		0xE2B2FBF3AC2CABDCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCB98C74BCBF98593ULL,
		0x747B86F960F688AFULL,
		0xFE55F51A3D71F4B9ULL,
		0x910682D3C69C4216ULL,
		0xDA2222EFED14E7D7ULL,
		0x2CB0D3A33590B428ULL,
		0x2540843C84A13EDEULL,
		0x7A61949FFF0BE761ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 252\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 252 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -252;
	} else {
		printf("Test Case 252 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x8310FECBFC8629F2ULL,
		0x9997C611B1CADE29ULL,
		0x3B11DBB997B72C6AULL,
		0x6B799F9B39615BA7ULL,
		0xDAC948298D2E61E7ULL,
		0xE4DAC24C4E4F0EF8ULL,
		0x464F914623A1FA08ULL,
		0xDA4B0B1FFCB59781ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBE6E0FE5B84F421ULL,
		0xB4BF7ACE54DC62D4ULL,
		0x0997211BB0DDACE3ULL,
		0x160FF3F91148D0C0ULL,
		0x416D17ED1499B1E9ULL,
		0x07A1B97869F6FA57ULL,
		0x69EF36067775903AULL,
		0x96BE8561B1421792ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB72A1DCDA10135D1ULL,
		0xE4D84B435CEE7B54ULL,
		0x317ABA9DE6D97F86ULL,
		0x5569ABA228188AE7ULL,
		0x995C303C7894AFFEULL,
		0xDD3908D3E45814A1ULL,
		0xDC605B3FAC2C69CEULL,
		0x438C85BE4B737FEEULL
	}};
	sign = 0;
	printf("Test Case 253\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 253 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -253;
	} else {
		printf("Test Case 253 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7F97A88313253A79ULL,
		0x26CE288543D054FCULL,
		0xC46418EBCA1815DCULL,
		0x06B7F91EDEA1FF3FULL,
		0xB69B0C230A4DDC93ULL,
		0x0604203B5F5E4A1EULL,
		0xE9574C6FC72B71D4ULL,
		0x1F18265777446D3DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x38DC6532AFF2CA9BULL,
		0x9D7B9C5F02AE4144ULL,
		0x69F723364075C298ULL,
		0x717FADAD887F6D2FULL,
		0x4E5B78239E96416CULL,
		0x4504DA346267A74AULL,
		0x4B31D06A0CC43573ULL,
		0x0149F07E3466A8F6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x46BB435063326FDEULL,
		0x89528C26412213B8ULL,
		0x5A6CF5B589A25343ULL,
		0x95384B7156229210ULL,
		0x683F93FF6BB79B26ULL,
		0xC0FF4606FCF6A2D4ULL,
		0x9E257C05BA673C60ULL,
		0x1DCE35D942DDC447ULL
	}};
	sign = 0;
	printf("Test Case 254\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 254 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -254;
	} else {
		printf("Test Case 254 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x316C5DD073C5F6A7ULL,
		0x834918AFC25893E6ULL,
		0x703215B9F9925B4EULL,
		0xF315FD099876E632ULL,
		0x13E422427C0172ACULL,
		0x64671E27C7AD6B62ULL,
		0xF78C4049C5A71D0DULL,
		0xB3340F1840F87113ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1ECEC4D2B538338ULL,
		0x81A074E3CE8D3B04ULL,
		0xF3B5AB8E2FDF236CULL,
		0x755C22B49DC8BED3ULL,
		0x93885F41E88A658CULL,
		0xE177911437C6EE38ULL,
		0x3D192054B8DA1C77ULL,
		0xBA67247ED8F4C2F2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3F7F71834872736FULL,
		0x01A8A3CBF3CB58E1ULL,
		0x7C7C6A2BC9B337E2ULL,
		0x7DB9DA54FAAE275EULL,
		0x805BC30093770D20ULL,
		0x82EF8D138FE67D29ULL,
		0xBA731FF50CCD0095ULL,
		0xF8CCEA996803AE21ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 255\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 255 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -255;
	} else {
		printf("Test Case 255 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD16A66EE9230CD6BULL,
		0x53E6D7CE9E93FEA9ULL,
		0x107127E91DE1C2E3ULL,
		0x446DABF665257F83ULL,
		0x758485DB88CC2EFDULL,
		0x100592A8226910F5ULL,
		0xDAFA0A134DC3E233ULL,
		0x8A7D281BF21BCBE3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC738547A22D5A55ULL,
		0x636B211003B9FC83ULL,
		0x8B7923750D987AD7ULL,
		0x4589D9B30207068DULL,
		0x86272BECB2237267ULL,
		0x227E21E691EB511BULL,
		0xEDD983AD65309EDEULL,
		0x43BDB933F4EAF391ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF4F6E1A6F0037316ULL,
		0xF07BB6BE9ADA0225ULL,
		0x84F804741049480BULL,
		0xFEE3D243631E78F5ULL,
		0xEF5D59EED6A8BC95ULL,
		0xED8770C1907DBFD9ULL,
		0xED208665E8934354ULL,
		0x46BF6EE7FD30D851ULL
	}};
	sign = 0;
	printf("Test Case 256\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 256 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -256;
	} else {
		printf("Test Case 256 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7EE1768C3AA6C70DULL,
		0x307927835C8818C4ULL,
		0x11140A825914F9A9ULL,
		0x7AD552CBACA950CEULL,
		0x6F3097996AE32D0DULL,
		0x56E46C0AB248F42CULL,
		0x3683F408BEFA86BCULL,
		0xCA120C5FF43342F9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x960F628AAB479FCEULL,
		0xB339820B72F925C6ULL,
		0xE7688A37DD3B15B0ULL,
		0xA1F169A27D88FA76ULL,
		0xF91DF637E20B7882ULL,
		0x7EE13C56B448B5A1ULL,
		0xA3A5630B0D980755ULL,
		0xFE11C347DA65B11FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE8D214018F5F273FULL,
		0x7D3FA577E98EF2FDULL,
		0x29AB804A7BD9E3F8ULL,
		0xD8E3E9292F205657ULL,
		0x7612A16188D7B48AULL,
		0xD8032FB3FE003E8AULL,
		0x92DE90FDB1627F66ULL,
		0xCC00491819CD91D9ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 257\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 257 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -257;
	} else {
		printf("Test Case 257 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6FAA5E57787DB0F7ULL,
		0xF5FC01E7D2A0F02AULL,
		0x1F251FA740908C40ULL,
		0xFA4F6F426B05038CULL,
		0x021BF0C7CE69EF66ULL,
		0xD2B4097CDEDDA5B1ULL,
		0x831AA186DD115E3DULL,
		0xA4F8384411FEDD6AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x432369CF149173DCULL,
		0x2EC448F11BEF83E8ULL,
		0xCAC79AB4C5F0F0AFULL,
		0xBF8613621E20EBF8ULL,
		0x9BA29E5DB47E9BB1ULL,
		0x054727F1A4514EA8ULL,
		0x8FC05BD1F81AD4FEULL,
		0xB8EA85BF53886D54ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2C86F48863EC3D1BULL,
		0xC737B8F6B6B16C42ULL,
		0x545D84F27A9F9B91ULL,
		0x3AC95BE04CE41793ULL,
		0x6679526A19EB53B5ULL,
		0xCD6CE18B3A8C5708ULL,
		0xF35A45B4E4F6893FULL,
		0xEC0DB284BE767015ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 258\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 258 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -258;
	} else {
		printf("Test Case 258 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x3817F81C1BCF602BULL,
		0x93D165083809F757ULL,
		0x8869E7955D722077ULL,
		0x02FF2133CD4C013EULL,
		0x07061F67C7B7D46BULL,
		0x95CDAE93AAA88CBAULL,
		0x90E7973E1F74906FULL,
		0x83A54B5B65862652ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x88C9E50455EF9545ULL,
		0x702A8F09DC89A210ULL,
		0x69426EBA3A03F2D4ULL,
		0xBBC2B900E0C483B3ULL,
		0x9705EAAE21462CEFULL,
		0xEA061AAC4C20A278ULL,
		0xFBF5F9BFEC2E5190ULL,
		0xA0A808F82AC32260ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAF4E1317C5DFCAE6ULL,
		0x23A6D5FE5B805546ULL,
		0x1F2778DB236E2DA3ULL,
		0x473C6832EC877D8BULL,
		0x700034B9A671A77BULL,
		0xABC793E75E87EA41ULL,
		0x94F19D7E33463EDEULL,
		0xE2FD42633AC303F1ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 259\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 259 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -259;
	} else {
		printf("Test Case 259 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB919FF4CB70327FCULL,
		0x1E2921D8E7FBDA49ULL,
		0xFA1A90E5B8EB7FF4ULL,
		0x953DEC69D34047D0ULL,
		0xD4D5A5AF0682BD47ULL,
		0x04E7F0A62FAB02CEULL,
		0x390C3CF861C71912ULL,
		0xC2A8B9F5A45A2610ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x583BC845147AE9B2ULL,
		0x3D8778692A608B06ULL,
		0x34441DC3E33CEA9AULL,
		0x42013CF584B6416FULL,
		0x2384F6102A84C377ULL,
		0x178DF0B277EC3D60ULL,
		0x07EB396BE1A3007FULL,
		0x559E0A1B90677930ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x60DE3707A2883E4AULL,
		0xE0A1A96FBD9B4F43ULL,
		0xC5D67321D5AE9559ULL,
		0x533CAF744E8A0661ULL,
		0xB150AF9EDBFDF9D0ULL,
		0xED59FFF3B7BEC56EULL,
		0x3121038C80241892ULL,
		0x6D0AAFDA13F2ACE0ULL
	}};
	sign = 0;
	printf("Test Case 260\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 260 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -260;
	} else {
		printf("Test Case 260 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x860C72300291C047ULL,
		0x4A4A8B5B3B59286FULL,
		0xDF8093D2ACD04DDAULL,
		0xBF52EF272512D2AAULL,
		0x1563FC662D54D49AULL,
		0xF9FCD7CD893A1320ULL,
		0xDD5C69CDD403C618ULL,
		0x9B76FCB52B19D378ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x88B8C266076231ADULL,
		0x938F83ACB7492580ULL,
		0xFDA517E0EE24832DULL,
		0xEA7AC26000684214ULL,
		0x1684266C79D2F68FULL,
		0xC4853FB0E4D37CCCULL,
		0x796E4B7A7BC975ADULL,
		0x357C55AA0F6FEB27ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFD53AFC9FB2F8E9AULL,
		0xB6BB07AE841002EEULL,
		0xE1DB7BF1BEABCAACULL,
		0xD4D82CC724AA9095ULL,
		0xFEDFD5F9B381DE0AULL,
		0x3577981CA4669653ULL,
		0x63EE1E53583A506BULL,
		0x65FAA70B1BA9E851ULL
	}};
	sign = 0;
	printf("Test Case 261\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 261 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -261;
	} else {
		printf("Test Case 261 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA11B37AE65DE77AAULL,
		0x3F6DC04C5F94A998ULL,
		0xB11A146BF4F092B7ULL,
		0xFDBED75CE11C3BD0ULL,
		0x395EAD748BA406A7ULL,
		0x12D35B5D1C394DA2ULL,
		0x03C9B89B476B69E7ULL,
		0x684C7E4ED5351A7AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x27BA5E883E10A620ULL,
		0x81A0EFA41462B453ULL,
		0xC5F987A8B3850F99ULL,
		0x23428086584F9ED2ULL,
		0xB262FE59562DBD4DULL,
		0x92A38AF1EB7001F7ULL,
		0x34EE54D6D57587D4ULL,
		0xE439FDE678BE8053ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7960D92627CDD18AULL,
		0xBDCCD0A84B31F545ULL,
		0xEB208CC3416B831DULL,
		0xDA7C56D688CC9CFDULL,
		0x86FBAF1B3576495AULL,
		0x802FD06B30C94BAAULL,
		0xCEDB63C471F5E212ULL,
		0x841280685C769A26ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 262\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 262 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -262;
	} else {
		printf("Test Case 262 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xEC4C5386DC0C7EF9ULL,
		0xE9A3D698ACFA84E2ULL,
		0x8C69241EBB3D7B04ULL,
		0x0E77A2F76146E248ULL,
		0x0C9DF26B671334CFULL,
		0x79ADC5C7242229EBULL,
		0x79472946FFBCE12DULL,
		0x3BC667953F9195C5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x95D13E0D5CE76200ULL,
		0x5D4957639ADD41C8ULL,
		0x6074ADCC04C1E884ULL,
		0xFEDA763BA0A7C757ULL,
		0x17111E0FD379A985ULL,
		0xDDD6BC68A8E9BFFEULL,
		0x8A441AFE7BFDE89CULL,
		0x62BA7BCA05425968ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x567B15797F251CF9ULL,
		0x8C5A7F35121D431AULL,
		0x2BF47652B67B9280ULL,
		0x0F9D2CBBC09F1AF1ULL,
		0xF58CD45B93998B49ULL,
		0x9BD7095E7B3869ECULL,
		0xEF030E4883BEF890ULL,
		0xD90BEBCB3A4F3C5CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 263\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 263 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -263;
	} else {
		printf("Test Case 263 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x93059C400CDC258DULL,
		0x784DE4EA187DE0AAULL,
		0xA4284DCF9AE425A7ULL,
		0x1785C5F0FA0E8549ULL,
		0x54354DFF3464773DULL,
		0x840BF899A876E5D6ULL,
		0x3552F904506EFF4BULL,
		0xE5D80AD4BB4C4976ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA41F07BFF256428ULL,
		0x014A010952198F37ULL,
		0x8FDEFA6C3E0C847EULL,
		0x885434CDD7F90312ULL,
		0x35075B8F430D582FULL,
		0x6BFB0677C0D72D71ULL,
		0x8B86AD18F3584C90ULL,
		0x9ED25B5BEC808DF4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD8C3ABC40DB6C165ULL,
		0x7703E3E0C6645172ULL,
		0x144953635CD7A129ULL,
		0x8F31912322158237ULL,
		0x1F2DF26FF1571F0DULL,
		0x1810F221E79FB865ULL,
		0xA9CC4BEB5D16B2BBULL,
		0x4705AF78CECBBB81ULL
	}};
	sign = 0;
	printf("Test Case 264\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 264 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -264;
	} else {
		printf("Test Case 264 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x3BB2E9D581FF263EULL,
		0x361121F96C077F02ULL,
		0x53585FFEDD094F8CULL,
		0x81619A6AA25C8A01ULL,
		0x7FA396D6D182778EULL,
		0x5920920C12062B7DULL,
		0x543EE9C495DC06B3ULL,
		0xDDD5721A01BA07B1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x17C5446845A75202ULL,
		0xDD0C6409C2E02F98ULL,
		0x326AD79B7CA7E5CFULL,
		0xE8D6660FEBB8A076ULL,
		0x740DB4CE5B841668ULL,
		0xA2BE89C8BD7CA4EBULL,
		0x05B0E6D8712F5C16ULL,
		0x38055E98E81FAB51ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x23EDA56D3C57D43CULL,
		0x5904BDEFA9274F6AULL,
		0x20ED8863606169BCULL,
		0x988B345AB6A3E98BULL,
		0x0B95E20875FE6125ULL,
		0xB662084354898692ULL,
		0x4E8E02EC24ACAA9CULL,
		0xA5D01381199A5C60ULL
	}};
	sign = 0;
	printf("Test Case 265\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 265 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -265;
	} else {
		printf("Test Case 265 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x22666E9970505DBFULL,
		0xDF4CA0AF4DD52E93ULL,
		0x9A4C57FAF94A550AULL,
		0xFEF39615890F8B78ULL,
		0x7B6184DF2F134E4CULL,
		0x16FC5D2E4E42AA19ULL,
		0xEAB02CE184C4BFC4ULL,
		0x03138D62E858F092ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x108F88F084AC8B0FULL,
		0x458583596D5CF3AAULL,
		0xBD87DC696057072EULL,
		0x5E646AF9B9E21A47ULL,
		0x106709EADBF6B670ULL,
		0xA9AE1C7C0755BA1FULL,
		0x0586D432A799BACFULL,
		0x8E8364621C80E3FAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x11D6E5A8EBA3D2B0ULL,
		0x99C71D55E0783AE9ULL,
		0xDCC47B9198F34DDCULL,
		0xA08F2B1BCF2D7130ULL,
		0x6AFA7AF4531C97DCULL,
		0x6D4E40B246ECEFFAULL,
		0xE52958AEDD2B04F4ULL,
		0x74902900CBD80C98ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 266\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 266 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -266;
	} else {
		printf("Test Case 266 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x14EC49AFB758D176ULL,
		0x6DCBCF8991F15580ULL,
		0x727963B2FDF812D5ULL,
		0x11C2D789243A37C8ULL,
		0xF4E22B3A7554D8B2ULL,
		0xA35BD8E5E59D3943ULL,
		0x75552ADD23432603ULL,
		0x4561F7FB6D4EC84DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B67E52589C25A76ULL,
		0x31DF3EE540656834ULL,
		0x86AA6AC756ADCEA7ULL,
		0xB5D80D916862C2BEULL,
		0x6A759B1018680A5EULL,
		0x403463EFC79066FDULL,
		0xD36870F0DD316342ULL,
		0x83414D301D6B7984ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8984648A2D967700ULL,
		0x3BEC90A4518BED4BULL,
		0xEBCEF8EBA74A442EULL,
		0x5BEAC9F7BBD77509ULL,
		0x8A6C902A5CECCE53ULL,
		0x632774F61E0CD246ULL,
		0xA1ECB9EC4611C2C1ULL,
		0xC220AACB4FE34EC8ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 267\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 267 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -267;
	} else {
		printf("Test Case 267 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB09288370B252E15ULL,
		0xC626C4445CE1FDAEULL,
		0xC5ED64216672C243ULL,
		0x69A78B2B2B77974BULL,
		0xE5063362BAD7D524ULL,
		0x04BA8DB2BBC0B3ECULL,
		0xDC63A97F82EE2663ULL,
		0xCDC39D12CE1504F5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x61124F64F286F936ULL,
		0x257FDB6C067E51B0ULL,
		0x9798E109479662F1ULL,
		0xA0773C4568E66CD8ULL,
		0x29F411156662AD31ULL,
		0x7BCBCFD7A4171038ULL,
		0xE8085CB3418AE6DFULL,
		0xAF665B6726764325ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4F8038D2189E34DFULL,
		0xA0A6E8D85663ABFEULL,
		0x2E5483181EDC5F52ULL,
		0xC9304EE5C2912A73ULL,
		0xBB12224D547527F2ULL,
		0x88EEBDDB17A9A3B4ULL,
		0xF45B4CCC41633F83ULL,
		0x1E5D41ABA79EC1CFULL
	}};
	sign = 0;
	printf("Test Case 268\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 268 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -268;
	} else {
		printf("Test Case 268 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x532A428525BC9B87ULL,
		0x8CA9A6D5C91B03FBULL,
		0xAF1816A5ECF3D619ULL,
		0xE09EBC4A07963695ULL,
		0x2B3A352E70BAAFAEULL,
		0x25A4322F3E0AD7DCULL,
		0xE3D73CC092F4BE52ULL,
		0x7F2884C24D6A8621ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2BF8410ADFE625AFULL,
		0xEFAF82F3BD01CAF4ULL,
		0x9CBE967488944427ULL,
		0xB314BF222732D834ULL,
		0xB99CF48C1F6CF5B6ULL,
		0xD009048F8219A76BULL,
		0x9F52DA055DF67B58ULL,
		0x7B7535BEFAB76821ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2732017A45D675D8ULL,
		0x9CFA23E20C193907ULL,
		0x12598031645F91F1ULL,
		0x2D89FD27E0635E61ULL,
		0x719D40A2514DB9F8ULL,
		0x559B2D9FBBF13070ULL,
		0x448462BB34FE42F9ULL,
		0x03B34F0352B31E00ULL
	}};
	sign = 0;
	printf("Test Case 269\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 269 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -269;
	} else {
		printf("Test Case 269 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1C6BBE40C7F41ABCULL,
		0x99982AE79E4DD49CULL,
		0x7C8A76C074EF4006ULL,
		0xDC1F3A021DE99172ULL,
		0xF0BC204B9E148250ULL,
		0xAD15043F53CEB39CULL,
		0x09314684C44CCB7CULL,
		0x9D2BAB6690F5F728ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD600E3F7D50378B2ULL,
		0xFF2D2274CE14D05EULL,
		0xAC9AC8999548A6EBULL,
		0xB9CD9AECE0F8B822ULL,
		0x343EF6031C2245BFULL,
		0xE1C1204686507587ULL,
		0x9D7CCE0DE824617CULL,
		0xC2749C2FF07D51FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x466ADA48F2F0A20AULL,
		0x9A6B0872D039043DULL,
		0xCFEFAE26DFA6991AULL,
		0x22519F153CF0D94FULL,
		0xBC7D2A4881F23C91ULL,
		0xCB53E3F8CD7E3E15ULL,
		0x6BB47876DC2869FFULL,
		0xDAB70F36A078A529ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 270\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 270 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -270;
	} else {
		printf("Test Case 270 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB30AAD5C10A7C852ULL,
		0x66C58762F9C3CAF4ULL,
		0xECA2CFC4AF55898AULL,
		0x4E304504CCFE1699ULL,
		0xB58ADDC5E2C41EA2ULL,
		0x84A3AE48DF3924FFULL,
		0xB3A22274C0D44468ULL,
		0x4B7786A8E715A00DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x389B9C0CE3365B5EULL,
		0x1428C0E610732C84ULL,
		0x32D4F1D3250BAD3AULL,
		0x09E9E64BB2F020DCULL,
		0xE5A07C975B637718ULL,
		0xDB420676A4190B1CULL,
		0x605525A9E864766AULL,
		0x591C8DE684BBDE85ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7A6F114F2D716CF4ULL,
		0x529CC67CE9509E70ULL,
		0xB9CDDDF18A49DC50ULL,
		0x44465EB91A0DF5BDULL,
		0xCFEA612E8760A78AULL,
		0xA961A7D23B2019E2ULL,
		0x534CFCCAD86FCDFDULL,
		0xF25AF8C26259C188ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 271\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 271 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -271;
	} else {
		printf("Test Case 271 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xAC1424D7403B63ACULL,
		0x6293499B57FCF16FULL,
		0x7A1115B3773A2CC5ULL,
		0x7DC1BE222E52A10CULL,
		0x721DB0EBF734C3BAULL,
		0x358D30F577C6B610ULL,
		0x9D555D02BDA726E3ULL,
		0xB67311F12D0B4E20ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9AB36C9E83DD92FBULL,
		0x0008532380AB887FULL,
		0x1FB23ABA4BFF11D1ULL,
		0xC00617F85281F408ULL,
		0x89D29BD0057061D0ULL,
		0x30CB18827A4D6394ULL,
		0x1C3D71ED2038A1A0ULL,
		0x2372DCA8A338562FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1160B838BC5DD0B1ULL,
		0x628AF677D75168F0ULL,
		0x5A5EDAF92B3B1AF4ULL,
		0xBDBBA629DBD0AD04ULL,
		0xE84B151BF1C461E9ULL,
		0x04C21872FD79527BULL,
		0x8117EB159D6E8543ULL,
		0x9300354889D2F7F1ULL
	}};
	sign = 0;
	printf("Test Case 272\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 272 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -272;
	} else {
		printf("Test Case 272 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xCB9E15C9A7AA869DULL,
		0xA5239D8909E2A151ULL,
		0x973556E20260AAA7ULL,
		0xE647996E40B760ECULL,
		0xCD9B3781DD8FA851ULL,
		0xFEE2E503243D58EEULL,
		0x0B8E03422296EC95ULL,
		0x9368097775E5F146ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x76372044F092A85AULL,
		0x80ECCD32152600BDULL,
		0xBFCCF3CCEC5C0AF4ULL,
		0x2543F96BB29F9B4FULL,
		0x2FFF41645C633592ULL,
		0x2DBE2E6D1F8DD397ULL,
		0x6CD6A189D4875A06ULL,
		0x52818EFA1A06641EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5566F584B717DE43ULL,
		0x2436D056F4BCA094ULL,
		0xD768631516049FB3ULL,
		0xC103A0028E17C59CULL,
		0x9D9BF61D812C72BFULL,
		0xD124B69604AF8557ULL,
		0x9EB761B84E0F928FULL,
		0x40E67A7D5BDF8D27ULL
	}};
	sign = 0;
	printf("Test Case 273\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 273 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -273;
	} else {
		printf("Test Case 273 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB126B1A44D744785ULL,
		0xFAE4FF52831B0F8DULL,
		0xB750B7B06D5A6EEEULL,
		0x320B020DB4A05DAAULL,
		0xF1CF899CEEE3BC0EULL,
		0x5EE90CB5CF67F8DAULL,
		0xA7F0F7A62DA400F1ULL,
		0x1CD6C94D9659F1FAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x40D11BDBA70CA307ULL,
		0x8EDB21A5EE4DA907ULL,
		0x4EB722573C46543EULL,
		0x0686057BDACB408FULL,
		0x7411BDEF7DA39ED1ULL,
		0x06AF57948DB918DFULL,
		0x4EED1D743AD1D96CULL,
		0xD89C0A962E8B3CEAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x705595C8A667A47EULL,
		0x6C09DDAC94CD6686ULL,
		0x6899955931141AB0ULL,
		0x2B84FC91D9D51D1BULL,
		0x7DBDCBAD71401D3DULL,
		0x5839B52141AEDFFBULL,
		0x5903DA31F2D22785ULL,
		0x443ABEB767CEB510ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 274\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 274 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -274;
	} else {
		printf("Test Case 274 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD0D912329474D1E5ULL,
		0x512CA81A44E9565FULL,
		0x7507F3475EA7D582ULL,
		0xF4D4A0BD5AE2A444ULL,
		0xBE9B46DD99CCD371ULL,
		0x322ADE7B1239E461ULL,
		0x3F7C2C2DAC532777ULL,
		0x1632FB2ED36224F7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x77F7A74BE47BA323ULL,
		0xF1B58ABE41D5B24CULL,
		0x4A13140777985335ULL,
		0xF21CAD3D80423615ULL,
		0x9D1E3118BE048BB3ULL,
		0xA66315507C75C851ULL,
		0x55247BCF4A221EF6ULL,
		0xEC669402865981B8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x58E16AE6AFF92EC2ULL,
		0x5F771D5C0313A413ULL,
		0x2AF4DF3FE70F824CULL,
		0x02B7F37FDAA06E2FULL,
		0x217D15C4DBC847BEULL,
		0x8BC7C92A95C41C10ULL,
		0xEA57B05E62310880ULL,
		0x29CC672C4D08A33EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 275\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 275 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -275;
	} else {
		printf("Test Case 275 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF589B0AC17CD8EAFULL,
		0xB0D91B0F40BE59BDULL,
		0xCC91809F0D61484BULL,
		0x438E9E3819ECA6E5ULL,
		0x2DE3FEF8229889B7ULL,
		0x4AE9533A3CA036F0ULL,
		0x50ADA3E05B90E1A9ULL,
		0x6D2C8C76356597F1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E5DFC9FB1B8D1C1ULL,
		0x946739B98B33694AULL,
		0x0876235B8586A97FULL,
		0x2DDF6EA61F920543ULL,
		0xD4C6705F2011CA35ULL,
		0x3BFBE8922618EA78ULL,
		0xA5209956CE577DAAULL,
		0x70A8CF40DB79D8B7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x972BB40C6614BCEEULL,
		0x1C71E155B58AF073ULL,
		0xC41B5D4387DA9ECCULL,
		0x15AF2F91FA5AA1A2ULL,
		0x591D8E990286BF82ULL,
		0x0EED6AA816874C77ULL,
		0xAB8D0A898D3963FFULL,
		0xFC83BD3559EBBF39ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 276\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 276 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -276;
	} else {
		printf("Test Case 276 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x33CD9AC3DC4ADC4EULL,
		0x040B53F50F753BD5ULL,
		0x98B4E2A8F6415135ULL,
		0x1372F9E17205C56FULL,
		0x428BC633A0A56CBAULL,
		0xA01B7643C416D477ULL,
		0x9FAD22C74B04D3D4ULL,
		0xC3FFF0AD2FD01F66ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x077245411D592C00ULL,
		0x02F7CF34967446B4ULL,
		0xD0852A1C2A469C18ULL,
		0xD0ECB1B507293594ULL,
		0x606085CE47A0EF7EULL,
		0x06A48BE25A263DF7ULL,
		0x129F8C375F13FC68ULL,
		0x9FDF2EB7706E8559ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2C5B5582BEF1B04EULL,
		0x011384C07900F521ULL,
		0xC82FB88CCBFAB51DULL,
		0x4286482C6ADC8FDAULL,
		0xE22B406559047D3BULL,
		0x9976EA6169F0967FULL,
		0x8D0D968FEBF0D76CULL,
		0x2420C1F5BF619A0DULL
	}};
	sign = 0;
	printf("Test Case 277\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 277 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -277;
	} else {
		printf("Test Case 277 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0876C9B5472625D8ULL,
		0xB29401BEC29138FFULL,
		0x1D7A4CABB0458D84ULL,
		0x7FBBCF6619735347ULL,
		0xA3FBD386806B50A5ULL,
		0x5C4F787C032BED12ULL,
		0xDB92748E85FF10C1ULL,
		0x1D9FF456B35DB735ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C36032F0D9A07FFULL,
		0xF45F2DD13FBA4665ULL,
		0xE4C431DFF169D83EULL,
		0xD18ED611FBE60AD3ULL,
		0xAF88708A61ACC3DEULL,
		0x738D5A7A918AA8EAULL,
		0xF8046F429222D934ULL,
		0x6AE14E1D72F6F542ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBC40C686398C1DD9ULL,
		0xBE34D3ED82D6F299ULL,
		0x38B61ACBBEDBB545ULL,
		0xAE2CF9541D8D4873ULL,
		0xF47362FC1EBE8CC6ULL,
		0xE8C21E0171A14427ULL,
		0xE38E054BF3DC378CULL,
		0xB2BEA6394066C1F2ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 278\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 278 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -278;
	} else {
		printf("Test Case 278 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4E9B6A14FCD379DAULL,
		0xF61A70473F6E6872ULL,
		0xB353204CC9553F72ULL,
		0xEF6C350FD1E652BEULL,
		0x6A66B4B9CEF0A6FCULL,
		0xF64A27213CC4427CULL,
		0xDF8EE9239C08ED06ULL,
		0xD83E62D2CF3AFFF8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AB43A9DF4A1EF7AULL,
		0xE64952F9F92B858EULL,
		0xBD842BFD264C2C50ULL,
		0xA3E2B92C447A3A65ULL,
		0x5E40EFE3758CCCF8ULL,
		0x8A43BA6D40375FB2ULL,
		0xDBA30DECCD309F75ULL,
		0x481931B739E82BA5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF3E72F7708318A60ULL,
		0x0FD11D4D4642E2E3ULL,
		0xF5CEF44FA3091322ULL,
		0x4B897BE38D6C1858ULL,
		0x0C25C4D65963DA04ULL,
		0x6C066CB3FC8CE2CAULL,
		0x03EBDB36CED84D91ULL,
		0x9025311B9552D453ULL
	}};
	sign = 0;
	printf("Test Case 279\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 279 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -279;
	} else {
		printf("Test Case 279 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD55D6EF96CCAB235ULL,
		0x73863AB503212F38ULL,
		0x9A61A510D8C82DF5ULL,
		0x396DB50F413C0FF4ULL,
		0x09B2B3693A76CBC3ULL,
		0xA0890EDB2432F252ULL,
		0xF71B7FBAC5C0AD9FULL,
		0xE98626E0C3356D81ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDFA9114E9F45EC5ULL,
		0xB193B2EDDECF06BAULL,
		0x2B6C1B5811936734ULL,
		0x81A52FAD790E5ABAULL,
		0x91CBD2AD9F8A4AC2ULL,
		0x8FDEBCF1D9640B72ULL,
		0x2E465EBA68A88E35ULL,
		0x45A35B3569BF4A59ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF762DDE482D65370ULL,
		0xC1F287C72452287DULL,
		0x6EF589B8C734C6C0ULL,
		0xB7C88561C82DB53AULL,
		0x77E6E0BB9AEC8100ULL,
		0x10AA51E94ACEE6DFULL,
		0xC8D521005D181F6AULL,
		0xA3E2CBAB59762328ULL
	}};
	sign = 0;
	printf("Test Case 280\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 280 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -280;
	} else {
		printf("Test Case 280 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x98E4D40F3BB2D474ULL,
		0x667D38158320CDBCULL,
		0xBAE1F43D2C41D7B0ULL,
		0x81653D5CA1897D3FULL,
		0xFF6591A78C3BF9CCULL,
		0x09D790E57CF847F0ULL,
		0xE1C8EF46EAF8CD81ULL,
		0x8EF40A0BD8601C2DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7EACA9B9CDC71ADFULL,
		0x353E908EB73F41BCULL,
		0x6FA6CD7656C72B08ULL,
		0xF9DD66FF2AE25072ULL,
		0x50F4EE56AFE02353ULL,
		0x2806CFAFB35DDFB9ULL,
		0xCF74F2375D588680ULL,
		0x5AC2FCBA72844DF0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1A382A556DEBB995ULL,
		0x313EA786CBE18C00ULL,
		0x4B3B26C6D57AACA8ULL,
		0x8787D65D76A72CCDULL,
		0xAE70A350DC5BD678ULL,
		0xE1D0C135C99A6837ULL,
		0x1253FD0F8DA04700ULL,
		0x34310D5165DBCE3DULL
	}};
	sign = 0;
	printf("Test Case 281\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 281 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -281;
	} else {
		printf("Test Case 281 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x934A3BFF27E97506ULL,
		0x69BA232AB4470746ULL,
		0xE644AAD4B470E5F3ULL,
		0x63E23F30DF62DA22ULL,
		0x6D9709858C396161ULL,
		0x07E9F8B57B336028ULL,
		0x595E71CF9B5F3A1AULL,
		0xA93B7E5077A9C026ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B17C14DD56D27A3ULL,
		0x959D457F676D2D01ULL,
		0x02472EADB95D832AULL,
		0xA8C392A63AF9E511ULL,
		0x00B31E98F86C913EULL,
		0x8D90D8B76DC10E1CULL,
		0xE68F0BBF1860EE0CULL,
		0x4ED5C9175D1B463CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF8327AB1527C4D63ULL,
		0xD41CDDAB4CD9DA44ULL,
		0xE3FD7C26FB1362C8ULL,
		0xBB1EAC8AA468F511ULL,
		0x6CE3EAEC93CCD022ULL,
		0x7A591FFE0D72520CULL,
		0x72CF661082FE4C0DULL,
		0x5A65B5391A8E79E9ULL
	}};
	sign = 0;
	printf("Test Case 282\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 282 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -282;
	} else {
		printf("Test Case 282 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6D7A750FDF4D7DE0ULL,
		0x1635C24284C60272ULL,
		0x5F8D21079A2870A5ULL,
		0xE03C1C387D074DFEULL,
		0x2589121E83EC9B2CULL,
		0x180E44E3E045434DULL,
		0xB89737E1870524FFULL,
		0x9382EC70CB251BFBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8D187CF3DB2B1EEULL,
		0x741071ED401C6606ULL,
		0x83E6461A0A78CAB4ULL,
		0x13AFB8E7F61E3026ULL,
		0x727B291C6802ABBFULL,
		0xEC90D8BD739B0473ULL,
		0x781052213044F21EULL,
		0xA768471C23679FE4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x94A8ED40A19ACBF2ULL,
		0xA225505544A99C6BULL,
		0xDBA6DAED8FAFA5F0ULL,
		0xCC8C635086E91DD7ULL,
		0xB30DE9021BE9EF6DULL,
		0x2B7D6C266CAA3ED9ULL,
		0x4086E5C056C032E0ULL,
		0xEC1AA554A7BD7C17ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 283\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 283 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -283;
	} else {
		printf("Test Case 283 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xBDEC95C3E05A7FBDULL,
		0x02DC261CC9D99571ULL,
		0xA3B0B29203FCBEC2ULL,
		0x9EECD668CC1D5E9CULL,
		0xECE53D75F641B6BBULL,
		0x27C7B188E2254BB0ULL,
		0x18D4586440510870ULL,
		0x506B666FFB894710ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA846DBB814FEFEAULL,
		0xF3B69A5C1CE86C16ULL,
		0x8A0F35618ACC0BBAULL,
		0xD7F92E4919211858ULL,
		0x3F9D5147B12C6E20ULL,
		0xEE77A5E9B055FAB9ULL,
		0xA7165494B13A0A74ULL,
		0x7D97F8F5460F40BFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC36828085F0A8FD3ULL,
		0x0F258BC0ACF1295AULL,
		0x19A17D307930B307ULL,
		0xC6F3A81FB2FC4644ULL,
		0xAD47EC2E4515489AULL,
		0x39500B9F31CF50F7ULL,
		0x71BE03CF8F16FDFBULL,
		0xD2D36D7AB57A0650ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 284\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 284 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -284;
	} else {
		printf("Test Case 284 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x641CC7D515DEBC22ULL,
		0x79B6EE8F8D015325ULL,
		0x61537943CE7620BCULL,
		0x09AFA3FAC5213ECEULL,
		0x5F4DBF5B6EE800A0ULL,
		0x5AE62621318220D2ULL,
		0x18C976C177B12D07ULL,
		0x303880EC0471C27FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B53AB0CBDAE8B48ULL,
		0x91A1415D34833DE6ULL,
		0x90CBD5E4E3106812ULL,
		0xB9D7DD9CA1A4A43BULL,
		0xF245143F30983D42ULL,
		0x69C193FF0CCEC949ULL,
		0x88323F8FAF569F92ULL,
		0xE6C04D5741DFF9BDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x58C91CC8583030DAULL,
		0xE815AD32587E153FULL,
		0xD087A35EEB65B8A9ULL,
		0x4FD7C65E237C9A92ULL,
		0x6D08AB1C3E4FC35DULL,
		0xF124922224B35788ULL,
		0x90973731C85A8D74ULL,
		0x49783394C291C8C1ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 285\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 285 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -285;
	} else {
		printf("Test Case 285 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD347B410121A5225ULL,
		0x05B971940A0F933AULL,
		0xF84A6E64EAE0FA8EULL,
		0x9AB8BFC6FD32143DULL,
		0xCB892C09D786E340ULL,
		0x8093C1F9CEF1D6EAULL,
		0x4F5FCD3EAFD64EF5ULL,
		0x66395093E77C2544ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x74E714F13F400713ULL,
		0x223F84C84990654DULL,
		0x3ACD9B94899BF8C0ULL,
		0x9928EDF3EFABB074ULL,
		0xF7BD9F866FAAC1BEULL,
		0xA7C37BC2FEA37AA5ULL,
		0xEEFA8D478ADA2101ULL,
		0x8602B03A8C349528ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5E609F1ED2DA4B12ULL,
		0xE379ECCBC07F2DEDULL,
		0xBD7CD2D0614501CDULL,
		0x018FD1D30D8663C9ULL,
		0xD3CB8C8367DC2182ULL,
		0xD8D04636D04E5C44ULL,
		0x60653FF724FC2DF3ULL,
		0xE036A0595B47901BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 286\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 286 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -286;
	} else {
		printf("Test Case 286 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x2A466F51A2958D5FULL,
		0xCC30E3C49B0AB8BAULL,
		0xDC44887B2E830CF8ULL,
		0x8FFF2F1A179CFF49ULL,
		0xA96FAF6575C5CA36ULL,
		0x03B76E3482880FCEULL,
		0x02F7A445DBC17829ULL,
		0x536D2B5A68942765ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC956BEB5F31F630ULL,
		0x221A5411A80C1D24ULL,
		0x113C4B44ABCFA7FDULL,
		0x306ED6C36AA81C02ULL,
		0xD0C17B479F3D1B9DULL,
		0x12415EDC57677953ULL,
		0xD962CCCBDC9EE242ULL,
		0x323EBF9BBED57F02ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5DB103664363972FULL,
		0xAA168FB2F2FE9B95ULL,
		0xCB083D3682B364FBULL,
		0x5F905856ACF4E347ULL,
		0xD8AE341DD688AE99ULL,
		0xF1760F582B20967AULL,
		0x2994D779FF2295E6ULL,
		0x212E6BBEA9BEA862ULL
	}};
	sign = 0;
	printf("Test Case 287\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 287 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -287;
	} else {
		printf("Test Case 287 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA8497BF36A5F2C2CULL,
		0xA1E48E6B92F8AB3AULL,
		0x18741D101A718F1DULL,
		0x2C6F50E6D45D5FF8ULL,
		0xDC1D9384D711BAF5ULL,
		0x2163A4845A218A5FULL,
		0x84F2A5E7455D8031ULL,
		0x18A1552A8089A76DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8548DEF92F0B1358ULL,
		0xAE8A4897B7E59B70ULL,
		0x17702E174E7AC3FDULL,
		0x6C9DC91737573E2BULL,
		0x158FF34FC989830DULL,
		0xEBD966EAB3DBED14ULL,
		0xEC14FE16748A4813ULL,
		0x11F15C4849270F2AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x23009CFA3B5418D4ULL,
		0xF35A45D3DB130FCAULL,
		0x0103EEF8CBF6CB1FULL,
		0xBFD187CF9D0621CDULL,
		0xC68DA0350D8837E7ULL,
		0x358A3D99A6459D4BULL,
		0x98DDA7D0D0D3381DULL,
		0x06AFF8E237629842ULL
	}};
	sign = 0;
	printf("Test Case 288\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 288 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -288;
	} else {
		printf("Test Case 288 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xBA9635675B385A97ULL,
		0xBAFB61C3F82C99C4ULL,
		0x76CDF651C17ED656ULL,
		0xB9E7A6E04D713A2BULL,
		0x67676E954B4F216AULL,
		0x92DEACC396C79B7FULL,
		0xBA5E0F7C93A01CA0ULL,
		0xB62881EE729EDDD0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x10E641B2E18DD7D6ULL,
		0xF002386FC842B547ULL,
		0x062E2B1C40B8BBD7ULL,
		0x055AAB811D098098ULL,
		0x27E7C821CA8DDEE4ULL,
		0xA7BE1774A5908F86ULL,
		0x849EB8817794447CULL,
		0x1B0F34AEBD39CEC2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA9AFF3B479AA82C1ULL,
		0xCAF929542FE9E47DULL,
		0x709FCB3580C61A7EULL,
		0xB48CFB5F3067B993ULL,
		0x3F7FA67380C14286ULL,
		0xEB20954EF1370BF9ULL,
		0x35BF56FB1C0BD823ULL,
		0x9B194D3FB5650F0EULL
	}};
	sign = 0;
	printf("Test Case 289\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 289 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -289;
	} else {
		printf("Test Case 289 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9C455346A9759BF3ULL,
		0x087290FA7AB3D258ULL,
		0xDB0885C610E25676ULL,
		0x94C45F85BE09E28BULL,
		0x3E6B53ECC2BEEF84ULL,
		0x0DF1E8514393B548ULL,
		0x2C419EFC4F412885ULL,
		0x96B8FA6DCFF5DE8DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2945F821EE50D256ULL,
		0x7C6D4576ACAE3812ULL,
		0x8B9A2FB4D59E12A3ULL,
		0x644EE6F0EEBF894BULL,
		0xC3010DF097FA328EULL,
		0x4865ACC880CBD6C7ULL,
		0xFB039AB17D150889ULL,
		0x2A23818ED2962046ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x72FF5B24BB24C99DULL,
		0x8C054B83CE059A46ULL,
		0x4F6E56113B4443D2ULL,
		0x30757894CF4A5940ULL,
		0x7B6A45FC2AC4BCF6ULL,
		0xC58C3B88C2C7DE80ULL,
		0x313E044AD22C1FFBULL,
		0x6C9578DEFD5FBE46ULL
	}};
	sign = 0;
	printf("Test Case 290\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 290 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -290;
	} else {
		printf("Test Case 290 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5B7FE4E7A7B5A45DULL,
		0xF573B4CB7AE2BEC1ULL,
		0x8FA39ADF40FD8DB4ULL,
		0x5AED68668C0CDBF0ULL,
		0xD75DCDC1FC15DA44ULL,
		0xB4AA69B17BBCDEEFULL,
		0x70350D68096F2280ULL,
		0x743B0172C3DC5857ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD731CE6F0A01110ULL,
		0x299568D02870687FULL,
		0xBBC0E1D9A6D392F5ULL,
		0x2739623C41ADE7BAULL,
		0x004013B088BD2FB2ULL,
		0x1A05A0AFF740DD2CULL,
		0x9A000A1D0BE701FBULL,
		0x12622FED1B4AEA99ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8E0CC800B715934DULL,
		0xCBDE4BFB52725641ULL,
		0xD3E2B9059A29FABFULL,
		0x33B4062A4A5EF435ULL,
		0xD71DBA117358AA92ULL,
		0x9AA4C901847C01C3ULL,
		0xD635034AFD882085ULL,
		0x61D8D185A8916DBDULL
	}};
	sign = 0;
	printf("Test Case 291\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 291 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -291;
	} else {
		printf("Test Case 291 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x07E5B1AF450610C0ULL,
		0x7A77BA96B10C5F4AULL,
		0xD5DE480FF49D7D97ULL,
		0x11EF061C2D19B418ULL,
		0xEEDB3E3AB6B6AC21ULL,
		0xC6A717E4557E1296ULL,
		0xDDBBE9A52CA4F519ULL,
		0x039B1A76FB7DAC34ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF38C57951CF3E97ULL,
		0x5E761E2834294BC8ULL,
		0x9368BC3C861F8D41ULL,
		0x53AE126D98D85BF5ULL,
		0x9C8A5BC02AE760DCULL,
		0xFC6F7067D070A668ULL,
		0x81CCE49F862A41B4ULL,
		0x58FAF5C68C5EF50EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x08ACEC35F336D229ULL,
		0x1C019C6E7CE31381ULL,
		0x42758BD36E7DF056ULL,
		0xBE40F3AE94415823ULL,
		0x5250E27A8BCF4B44ULL,
		0xCA37A77C850D6C2EULL,
		0x5BEF0505A67AB364ULL,
		0xAAA024B06F1EB726ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 292\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 292 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -292;
	} else {
		printf("Test Case 292 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0C664060FA1C38E9ULL,
		0xBDCBECA9F30B8BA8ULL,
		0x5F47F0D5F7512B83ULL,
		0x4D2962B9DCFC9318ULL,
		0x2BC9D6B9FA4BCF69ULL,
		0x07060933E3A7F380ULL,
		0x090FD39A4CEAA8C6ULL,
		0x15407E3CDB2ADBF3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0023FBF650D00822ULL,
		0x7049420D5B8CB282ULL,
		0xA337926C726C4161ULL,
		0xDE374370D346EB58ULL,
		0x166DDE0D5A74D5C4ULL,
		0x0E46B8097898EC91ULL,
		0x84294278E83BE3CAULL,
		0x834F5706E016110BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C42446AA94C30C7ULL,
		0x4D82AA9C977ED926ULL,
		0xBC105E6984E4EA22ULL,
		0x6EF21F4909B5A7BFULL,
		0x155BF8AC9FD6F9A4ULL,
		0xF8BF512A6B0F06EFULL,
		0x84E6912164AEC4FBULL,
		0x91F12735FB14CAE7ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 293\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 293 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -293;
	} else {
		printf("Test Case 293 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xBC0F756C24F963F0ULL,
		0x63EA2C1ED1BB001DULL,
		0xFFEA37DCC17E64ABULL,
		0xA5D6A2B1EB1009A8ULL,
		0xD6F1CBC3F1044B9EULL,
		0x11A94CC126FA56CDULL,
		0x3445E9D9417203C5ULL,
		0x07F709580D40AAD8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x22E9EF08CA0DD130ULL,
		0x9815DB65B9C57B98ULL,
		0x42E043E1907A5F1AULL,
		0xB4CE4F7505F5A667ULL,
		0x62E5F7A67CB7985BULL,
		0x2C595CFC25EFA69BULL,
		0xEB07779C2C0B290CULL,
		0x408BF050949228B9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x992586635AEB92C0ULL,
		0xCBD450B917F58485ULL,
		0xBD09F3FB31040590ULL,
		0xF108533CE51A6341ULL,
		0x740BD41D744CB342ULL,
		0xE54FEFC5010AB032ULL,
		0x493E723D1566DAB8ULL,
		0xC76B190778AE821EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 294\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 294 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -294;
	} else {
		printf("Test Case 294 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x82038D6B92D1FBB5ULL,
		0xA672F9C79FA05B55ULL,
		0x4440B4D659A8C40AULL,
		0x481FC51FD621628EULL,
		0x3EC10AB022B9F805ULL,
		0x445850D14373300CULL,
		0xBAF3BEB5FAEC8CFBULL,
		0x73941D2D92396E56ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0438C608C46502A5ULL,
		0xF46A3180BDD18BAAULL,
		0x7746DE979C4C4DA5ULL,
		0x459D3085EC14DED4ULL,
		0x5D314C5E7F01AECBULL,
		0xE9FF54BFBFC13D00ULL,
		0x16E4F44689995F6FULL,
		0xFC9A884947EDBE70ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7DCAC762CE6CF910ULL,
		0xB208C846E1CECFABULL,
		0xCCF9D63EBD5C7664ULL,
		0x02829499EA0C83B9ULL,
		0xE18FBE51A3B8493AULL,
		0x5A58FC1183B1F30BULL,
		0xA40ECA6F71532D8BULL,
		0x76F994E44A4BAFE6ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 295\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 295 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -295;
	} else {
		printf("Test Case 295 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xAD5DF2776C086B95ULL,
		0xE083E0BFA5EF0256ULL,
		0x6104B71D71F393D4ULL,
		0x3FCDF1EB27377551ULL,
		0xC3AFC0AA08E047A4ULL,
		0x973449E21B3CB129ULL,
		0x45CEB580BC9A05E5ULL,
		0xD9322EAA91F29D3DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA2667FA0C0330BAULL,
		0x019E50C0F8D826E9ULL,
		0x9C03352059A530E0ULL,
		0xD79638952D8BC99AULL,
		0x4EF6BA5EE1F7FDE2ULL,
		0x66B52569C8DC0682ULL,
		0xB604A5AACC303942ULL,
		0x8877BBAF752A0231ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC3378A7D60053ADBULL,
		0xDEE58FFEAD16DB6CULL,
		0xC50181FD184E62F4ULL,
		0x6837B955F9ABABB6ULL,
		0x74B9064B26E849C1ULL,
		0x307F24785260AAA7ULL,
		0x8FCA0FD5F069CCA3ULL,
		0x50BA72FB1CC89B0BULL
	}};
	sign = 0;
	printf("Test Case 296\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 296 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -296;
	} else {
		printf("Test Case 296 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5C03AF586E0D7062ULL,
		0x84490EF1EFEEAE12ULL,
		0xBE626CC3F310EACDULL,
		0xBE752718465DA036ULL,
		0x8842726F7CF84218ULL,
		0x43BC53125EE418E8ULL,
		0xC74E885E23BAB4D0ULL,
		0x1BD9D6A23C9430A8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x24EB54A7616F552AULL,
		0xA3E881FBA0A485A7ULL,
		0xC5DBEC025C479DDBULL,
		0x32C94BA0BCA76849ULL,
		0x4FA423E1FAD1925AULL,
		0xFDF0DD53153DE192ULL,
		0x89A0B4A5B51029C1ULL,
		0x6A7C0B5F4591EF24ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x37185AB10C9E1B38ULL,
		0xE0608CF64F4A286BULL,
		0xF88680C196C94CF1ULL,
		0x8BABDB7789B637ECULL,
		0x389E4E8D8226AFBEULL,
		0x45CB75BF49A63756ULL,
		0x3DADD3B86EAA8B0EULL,
		0xB15DCB42F7024184ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 297\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 297 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -297;
	} else {
		printf("Test Case 297 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5526B0E65CD0B3D4ULL,
		0x25AFBAA059FD249AULL,
		0x21466FF418F91CB8ULL,
		0x2EA363F00E40E7BEULL,
		0xD65BAB2198E23FF2ULL,
		0x9B8BD07D631FC116ULL,
		0xB310C5FB6E886E9CULL,
		0xECEF8117AB7C181FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A4CE0EE7E9EDE9BULL,
		0x5CCE00115E1BA813ULL,
		0x6BE58F70E8FB6281ULL,
		0x411464ED2C8B8EB4ULL,
		0x8C53566A5451852DULL,
		0xAB1D961159FA7C15ULL,
		0x39BD5041E30D7403ULL,
		0x29C3F4DBB8A7B729ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBAD9CFF7DE31D539ULL,
		0xC8E1BA8EFBE17C86ULL,
		0xB560E0832FFDBA36ULL,
		0xED8EFF02E1B55909ULL,
		0x4A0854B74490BAC4ULL,
		0xF06E3A6C09254501ULL,
		0x795375B98B7AFA98ULL,
		0xC32B8C3BF2D460F6ULL
	}};
	sign = 0;
	printf("Test Case 298\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 298 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -298;
	} else {
		printf("Test Case 298 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5644553801CBE3BEULL,
		0xCFD7A51C3F933CADULL,
		0x9F70E8E1F18D7E32ULL,
		0xE80756BCC313A925ULL,
		0x16628590C70FD90BULL,
		0x1C10FCD4DA49E5CBULL,
		0x9670B033D61639C2ULL,
		0xDFAD29D19C87DCF4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFD34AE7FAE9F16FULL,
		0xD0C042F77DDD03CDULL,
		0x1B4ED64553184FB5ULL,
		0x4F465D71B0EFAD24ULL,
		0x04A9818F47976588ULL,
		0x44442CC3D4C6BC8BULL,
		0xF46E85803C9ACFFAULL,
		0x6AF464DF20919C11ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x86710A5006E1F24FULL,
		0xFF176224C1B638DFULL,
		0x8422129C9E752E7CULL,
		0x98C0F94B1223FC01ULL,
		0x11B904017F787383ULL,
		0xD7CCD01105832940ULL,
		0xA2022AB3997B69C7ULL,
		0x74B8C4F27BF640E2ULL
	}};
	sign = 0;
	printf("Test Case 299\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 299 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -299;
	} else {
		printf("Test Case 299 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xDFA91937444E4B03ULL,
		0x4441F2D6AC26D2BCULL,
		0x8530A81A422FCEBAULL,
		0xFB998368C1220571ULL,
		0xB3832BDB3EE0D35AULL,
		0x73FD57827E2D607BULL,
		0xC6A55F5BD82AA814ULL,
		0x11B5F6DD7B58864AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD112278E34977D2EULL,
		0x2D6504568C06A828ULL,
		0xCEDA9D700A48156EULL,
		0xBDB3AF77FC7F5B8BULL,
		0xCBCE25D44DE26366ULL,
		0xC66DE49D5F408E65ULL,
		0x3328136EB823064DULL,
		0x5BBCE7359FDC307DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E96F1A90FB6CDD5ULL,
		0x16DCEE8020202A94ULL,
		0xB6560AAA37E7B94CULL,
		0x3DE5D3F0C4A2A9E5ULL,
		0xE7B50606F0FE6FF4ULL,
		0xAD8F72E51EECD215ULL,
		0x937D4BED2007A1C6ULL,
		0xB5F90FA7DB7C55CDULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 300\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 300 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -300;
	} else {
		printf("Test Case 300 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x694FB9A4F01300FFULL,
		0xC43CC8DD5FC5ABCDULL,
		0x20BFF4F0CF010720ULL,
		0x14E45D58F4B950C7ULL,
		0x2A504C8628659283ULL,
		0x75FD57CBAD8B7EB8ULL,
		0x582BC0D84F0BF5C8ULL,
		0x7C365AA334323022ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB2BE2E0B5E47A2EULL,
		0x0A6E9C9FAC36BB43ULL,
		0x9C2DADD62EF2D4ECULL,
		0xF1B80AD4485C8C93ULL,
		0x79CF3F1B570C22A3ULL,
		0x78BB067E69C62019ULL,
		0xB6381D8836E6B56AULL,
		0x0E8194D2AB11D2A1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6E23D6C43A2E86D1ULL,
		0xB9CE2C3DB38EF089ULL,
		0x8492471AA00E3234ULL,
		0x232C5284AC5CC433ULL,
		0xB0810D6AD1596FDFULL,
		0xFD42514D43C55E9EULL,
		0xA1F3A3501825405DULL,
		0x6DB4C5D089205D80ULL
	}};
	sign = 0;
	printf("Test Case 301\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 301 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -301;
	} else {
		printf("Test Case 301 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA1508B24F49B36F6ULL,
		0x43DFB141165151EAULL,
		0xFA8FFE09DEAF005EULL,
		0xA33A11354153EC8DULL,
		0x675F482ED7A63275ULL,
		0xE5B6B8CCD11E1F3FULL,
		0xD02AE0E7870BB8CCULL,
		0xED9BD5B60DEF5224ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x618233D9775F5BFFULL,
		0xE0A7DC0BD0DF87D8ULL,
		0xC1AF302A4658A1ABULL,
		0xBFF54D6071B6FA65ULL,
		0x3D2902357712DB75ULL,
		0x98C658253AADE370ULL,
		0x8C823C803BC9A802ULL,
		0xCC9A31EEA3B80666ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3FCE574B7D3BDAF7ULL,
		0x6337D5354571CA12ULL,
		0x38E0CDDF98565EB2ULL,
		0xE344C3D4CF9CF228ULL,
		0x2A3645F9609356FFULL,
		0x4CF060A796703BCFULL,
		0x43A8A4674B4210CAULL,
		0x2101A3C76A374BBEULL
	}};
	sign = 0;
	printf("Test Case 302\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 302 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -302;
	} else {
		printf("Test Case 302 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0474609FE75F995CULL,
		0xED462753FA37729FULL,
		0xD4D585C1C5C116A8ULL,
		0x7A3F84385E68C54AULL,
		0x33CA2C2DB0C1792DULL,
		0xE53EF75D2299C332ULL,
		0x3C3A1E36ECACC438ULL,
		0x43D88469AD7494D8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F6728DBE8B13ACAULL,
		0x2E559F386AA3CC92ULL,
		0xC93F0DD44F06CB44ULL,
		0x2A60540D472BB80DULL,
		0x180AC46F48EF4774ULL,
		0x58D446982D5C3312ULL,
		0x5076E0D130056BC3ULL,
		0xBF098E104E05AB3FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x750D37C3FEAE5E92ULL,
		0xBEF0881B8F93A60CULL,
		0x0B9677ED76BA4B64ULL,
		0x4FDF302B173D0D3DULL,
		0x1BBF67BE67D231B9ULL,
		0x8C6AB0C4F53D9020ULL,
		0xEBC33D65BCA75875ULL,
		0x84CEF6595F6EE998ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 303\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 303 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -303;
	} else {
		printf("Test Case 303 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD745563C7F1AFAE0ULL,
		0x2AEEC0D72C20CDA2ULL,
		0xD8E7FD911C6B997AULL,
		0x495108E18AD2CD4CULL,
		0x4E7E6068A78EEDE8ULL,
		0x2FA14953D3E1EE47ULL,
		0xC976D8922F4F1144ULL,
		0xE17578C0AC642A65ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x54827E963F06EDA5ULL,
		0x77CC31525C5D52FBULL,
		0xF74F761E3A878677ULL,
		0x9975E59A1EB33A25ULL,
		0xB99853DF9BF8DA87ULL,
		0x50693841130E7F9DULL,
		0x3D6D72F7ED237AB0ULL,
		0x5CA0BC3578BE82F1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x82C2D7A640140D3BULL,
		0xB3228F84CFC37AA7ULL,
		0xE1988772E1E41302ULL,
		0xAFDB23476C1F9326ULL,
		0x94E60C890B961360ULL,
		0xDF381112C0D36EA9ULL,
		0x8C09659A422B9693ULL,
		0x84D4BC8B33A5A774ULL
	}};
	sign = 0;
	printf("Test Case 304\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 304 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -304;
	} else {
		printf("Test Case 304 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB3BEAE055000F768ULL,
		0x9FA24BAAA43E325CULL,
		0x3DDEBA726B863225ULL,
		0xE6BC629B3743CAE6ULL,
		0xC3D9AD65E9883559ULL,
		0xD8B84407FE08D2DDULL,
		0x4AA59A541F370232ULL,
		0xE1756EF2860D21E6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDAFF80E32DA4E73FULL,
		0xB10C55AD55C8FEEAULL,
		0x8114F62850233287ULL,
		0x02A03B07052FD794ULL,
		0x1311F330EED4ECC0ULL,
		0x10BD33DF66C8C8B4ULL,
		0x69227AAE30668E53ULL,
		0x71C74410E8064719ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD8BF2D22225C1029ULL,
		0xEE95F5FD4E753371ULL,
		0xBCC9C44A1B62FF9DULL,
		0xE41C27943213F351ULL,
		0xB0C7BA34FAB34899ULL,
		0xC7FB102897400A29ULL,
		0xE1831FA5EED073DFULL,
		0x6FAE2AE19E06DACCULL
	}};
	sign = 0;
	printf("Test Case 305\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 305 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -305;
	} else {
		printf("Test Case 305 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xDFF0286150E36BBBULL,
		0x06CD26AC762714C1ULL,
		0xF891AD22BC53CCEEULL,
		0xE770D6EE1FCA6DCEULL,
		0x735493BB9E01D480ULL,
		0xDE18461C47AD0D86ULL,
		0x6FFD6FBD5E0C05FEULL,
		0x4D976416925A2E52ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA73B546E36F3DAF3ULL,
		0x462C09F2082A911DULL,
		0x7D50573910937A02ULL,
		0x4693D0B4DB9CDF12ULL,
		0xAB37302D03838A20ULL,
		0x3041CB5137BC352AULL,
		0xBC113D57C14E5E8AULL,
		0xC898AA4D01D0E226ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x38B4D3F319EF90C8ULL,
		0xC0A11CBA6DFC83A4ULL,
		0x7B4155E9ABC052EBULL,
		0xA0DD0639442D8EBCULL,
		0xC81D638E9A7E4A60ULL,
		0xADD67ACB0FF0D85BULL,
		0xB3EC32659CBDA774ULL,
		0x84FEB9C990894C2BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 306\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 306 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -306;
	} else {
		printf("Test Case 306 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA5591A795947332DULL,
		0x2642D487C291B004ULL,
		0x76DD1A1F207D6187ULL,
		0xF560BC897D6F70B8ULL,
		0xC9E444CC7A8898C6ULL,
		0x11991E3FF8AA3F82ULL,
		0xCCAD3C0942E46E0BULL,
		0x9F7EFB15814F77A4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2BA861FD162E4E80ULL,
		0x98ADD2A024BC795FULL,
		0x73533B4AD4A49F6CULL,
		0x44F6AD1946E5EE08ULL,
		0xF6BF57D93B9C72A0ULL,
		0x6AB22EC8910A927EULL,
		0xCAE2CC2378EC8AF8ULL,
		0xF958BEDEB86D121CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x79B0B87C4318E4ADULL,
		0x8D9501E79DD536A5ULL,
		0x0389DED44BD8C21AULL,
		0xB06A0F70368982B0ULL,
		0xD324ECF33EEC2626ULL,
		0xA6E6EF77679FAD03ULL,
		0x01CA6FE5C9F7E312ULL,
		0xA6263C36C8E26588ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 307\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 307 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -307;
	} else {
		printf("Test Case 307 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x74B904E9CFD61B44ULL,
		0xDDC65B7B0CE37B71ULL,
		0xA69B71E58695C777ULL,
		0xF22B7C54E34E2419ULL,
		0xD59CC0FFF0C932FBULL,
		0xDC3B3C05E31FCBA8ULL,
		0xA5CA8AD911A99178ULL,
		0x3A91FAC2FA12D52AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A6D21923F92A457ULL,
		0xDBFB32EDB15B664FULL,
		0x854E8D2FCA90B6B6ULL,
		0x996EF9DE91137A4CULL,
		0xBE738AB63798B8D4ULL,
		0x6649F79F2670661CULL,
		0x11FBF624BE9F93B3ULL,
		0x92A0F3A81813842FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFA4BE357904376EDULL,
		0x01CB288D5B881521ULL,
		0x214CE4B5BC0510C1ULL,
		0x58BC8276523AA9CDULL,
		0x17293649B9307A27ULL,
		0x75F14466BCAF658CULL,
		0x93CE94B45309FDC5ULL,
		0xA7F1071AE1FF50FBULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 308\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 308 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -308;
	} else {
		printf("Test Case 308 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x71CDD27D302C8B41ULL,
		0x5C5EC03243CE693FULL,
		0x5F16219F843F47BDULL,
		0x2D8AFB7404B5E030ULL,
		0x7B545CB4D3F860B8ULL,
		0xB7C597A89194D35AULL,
		0x9E14487213C3705AULL,
		0x3BE026A1D437C193ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D3185699B4D7DD5ULL,
		0xCA68995CA573B77FULL,
		0xBDF91A5520273B32ULL,
		0x90E593518E7502ACULL,
		0x9579ADC9D34D8729ULL,
		0xDF3ACCDCA9B1016EULL,
		0x7D61583B4618AF0FULL,
		0x4734661500579469ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x349C4D1394DF0D6CULL,
		0x91F626D59E5AB1C0ULL,
		0xA11D074A64180C8AULL,
		0x9CA568227640DD83ULL,
		0xE5DAAEEB00AAD98EULL,
		0xD88ACACBE7E3D1EBULL,
		0x20B2F036CDAAC14AULL,
		0xF4ABC08CD3E02D2AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 309\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 309 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -309;
	} else {
		printf("Test Case 309 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xAFECB5E6618B37B3ULL,
		0xC0BE270F83386339ULL,
		0xA466503016E8E358ULL,
		0x8C2F8622ADB3105FULL,
		0x3407ECA260C4AF14ULL,
		0x0AED7809DA0B671DULL,
		0x9632FCA9346016F6ULL,
		0x8F687611EF5BA48EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x81B1F395E7A60884ULL,
		0x698D94805AA6033DULL,
		0xD66C56512749B38BULL,
		0x3ABB8182901C1A84ULL,
		0xEDCDF2B4A8EEEC2BULL,
		0x762B192175C9656AULL,
		0x6E0FEADF779EFB31ULL,
		0x1ACCEEA454D103EEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2E3AC25079E52F2FULL,
		0x5730928F28925FFCULL,
		0xCDF9F9DEEF9F2FCDULL,
		0x517404A01D96F5DAULL,
		0x4639F9EDB7D5C2E9ULL,
		0x94C25EE8644201B2ULL,
		0x282311C9BCC11BC4ULL,
		0x749B876D9A8AA0A0ULL
	}};
	sign = 0;
	printf("Test Case 310\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 310 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -310;
	} else {
		printf("Test Case 310 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1C75B652A4A6F3F1ULL,
		0xE15EA5D822F61575ULL,
		0xAFEA42F81618BCF6ULL,
		0xD785BD469E1C2492ULL,
		0xE47F9B99BCF78545ULL,
		0x6922CA0BCA3AF2ACULL,
		0xA239619D27C6BC41ULL,
		0xF864640E6990E56CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x327D816E6176EA70ULL,
		0xBCFB944B40BEA277ULL,
		0x92213E025FFB1EF4ULL,
		0x2FDA77AF26E29DEAULL,
		0xE4338268E79B91EDULL,
		0xAD0371684428A5E2ULL,
		0x5A6F693961004F15ULL,
		0x7BE0263B02128597ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE9F834E443300981ULL,
		0x2463118CE23772FDULL,
		0x1DC904F5B61D9E02ULL,
		0xA7AB4597773986A8ULL,
		0x004C1930D55BF358ULL,
		0xBC1F58A386124CCAULL,
		0x47C9F863C6C66D2BULL,
		0x7C843DD3677E5FD5ULL
	}};
	sign = 0;
	printf("Test Case 311\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 311 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -311;
	} else {
		printf("Test Case 311 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x565DCFE1B531F532ULL,
		0x01D404FED73CD748ULL,
		0x592863384FC631A1ULL,
		0x46E960451F1B9C0EULL,
		0x7BC158B53471BEE8ULL,
		0x35403FF4771CBC4DULL,
		0xBA838CB39F3EE12AULL,
		0xAA7035D407417E05ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C68944AA41AFC07ULL,
		0x8E59712BB8D318FFULL,
		0x22C798FA2272D90BULL,
		0xE2456F6AF3E4A12EULL,
		0x4F5658FE660DC442ULL,
		0x16A1276A59DD1521ULL,
		0xB5F3E6A6BD026418ULL,
		0x49499B93FE066CC7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF9F53B971116F92BULL,
		0x737A93D31E69BE48ULL,
		0x3660CA3E2D535895ULL,
		0x64A3F0DA2B36FAE0ULL,
		0x2C6AFFB6CE63FAA5ULL,
		0x1E9F188A1D3FA72CULL,
		0x048FA60CE23C7D12ULL,
		0x61269A40093B113EULL
	}};
	sign = 0;
	printf("Test Case 312\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 312 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -312;
	} else {
		printf("Test Case 312 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x3A67CCB84BF4F264ULL,
		0xEE2CC33CB5332AABULL,
		0xA81E0CCB687E05DBULL,
		0x3F45F9C76F6B9BFBULL,
		0xEBD324533F77C1D9ULL,
		0xC39F5E05375A0E61ULL,
		0xE0FAA41D03146292ULL,
		0x64845AF2169D4FDEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x44C468456E39FB3BULL,
		0xCFE1F3CD7ED34BB5ULL,
		0x18ABD58B0D0D7370ULL,
		0x4C64031086CBD860ULL,
		0x9BB049296ED0446FULL,
		0x78010C05F4A285E4ULL,
		0xA791F0AC211DD0C3ULL,
		0x0F1CD007B1116617ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF5A36472DDBAF729ULL,
		0x1E4ACF6F365FDEF5ULL,
		0x8F7237405B70926BULL,
		0xF2E1F6B6E89FC39BULL,
		0x5022DB29D0A77D69ULL,
		0x4B9E51FF42B7887DULL,
		0x3968B370E1F691CFULL,
		0x55678AEA658BE9C7ULL
	}};
	sign = 0;
	printf("Test Case 313\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 313 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -313;
	} else {
		printf("Test Case 313 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1B9DC3489721A8C2ULL,
		0x78E147C68A37C91FULL,
		0x8490E3C02925648AULL,
		0xF3C3CB53856309A5ULL,
		0xB19D393D565F5539ULL,
		0x27441F321C2C55AFULL,
		0xFED3A8DB83E885A1ULL,
		0xD23110B7A328DE2AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE379E2D85F17522ULL,
		0x24CA3309C1ABB04DULL,
		0xB9F5B40E2DD94302ULL,
		0x4AA04878CA1E6980ULL,
		0x65E042A1A2A418FEULL,
		0x2D5DEB79623C00C1ULL,
		0x1030235CBC7EAD2DULL,
		0xF0EB5C2755DF84BEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5D66251B113033A0ULL,
		0x541714BCC88C18D1ULL,
		0xCA9B2FB1FB4C2188ULL,
		0xA92382DABB44A024ULL,
		0x4BBCF69BB3BB3C3BULL,
		0xF9E633B8B9F054EEULL,
		0xEEA3857EC769D873ULL,
		0xE145B4904D49596CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 314\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 314 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -314;
	} else {
		printf("Test Case 314 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE5D8E29EFA8FE23BULL,
		0xA500CC633D0C784FULL,
		0x9DFD799E5C74EBB0ULL,
		0xACFAA0E030EF5D09ULL,
		0x7692B41603CA64F1ULL,
		0x4C0FC30E6EE1094FULL,
		0xEBA35E8256241067ULL,
		0xA9D882EFFF10C3F1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FE1C9C99556226EULL,
		0x9F6EF6F5B490E584ULL,
		0xAF67FA8E935FCC39ULL,
		0xBDC5ECAD8B2BDDD5ULL,
		0xD14B9D604FAEA2BEULL,
		0x04A864F04DBFD33DULL,
		0x67AC8FC221C736ABULL,
		0xBDFDB37F132BDF34ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB5F718D56539BFCDULL,
		0x0591D56D887B92CBULL,
		0xEE957F0FC9151F77ULL,
		0xEF34B432A5C37F33ULL,
		0xA54716B5B41BC232ULL,
		0x47675E1E21213611ULL,
		0x83F6CEC0345CD9BCULL,
		0xEBDACF70EBE4E4BDULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 315\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 315 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -315;
	} else {
		printf("Test Case 315 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xAE18B002DE2697AAULL,
		0x84D6357B9196D2F6ULL,
		0x641868FFFF4470CFULL,
		0xF8862AD5218C50B7ULL,
		0x976906941EA73DC2ULL,
		0x873CB467CCEB6C4EULL,
		0xC7D7B5B7A724077DULL,
		0x7A6052CBEBBFF5A6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7DF1E948E2C5119ULL,
		0x0F72C6D79CAEC043ULL,
		0xD7C2EE0A49C4CD39ULL,
		0x79084A6AD5711B98ULL,
		0x25868EF1F61D1D53ULL,
		0x70E82916DF0EFC15ULL,
		0x7247BC5C5B5D83C6ULL,
		0xA6BE9897627CCBEEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF639916E4FFA4691ULL,
		0x75636EA3F4E812B2ULL,
		0x8C557AF5B57FA396ULL,
		0x7F7DE06A4C1B351EULL,
		0x71E277A2288A206FULL,
		0x16548B50EDDC7039ULL,
		0x558FF95B4BC683B7ULL,
		0xD3A1BA34894329B8ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 316\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 316 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -316;
	} else {
		printf("Test Case 316 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6D56B86EDDA39B85ULL,
		0x7CE51044136D928AULL,
		0xA6F391FB20B6258AULL,
		0x1744D98D471934A6ULL,
		0xA730F5D149BC7342ULL,
		0x6E65AFBE79B6E393ULL,
		0xD1665FAF6FDEA072ULL,
		0x9C10569AD2EB36E8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE13E5A70660C3AAULL,
		0xD0367CEA6D77C7B3ULL,
		0x2860B1529434592FULL,
		0x7F5D0CA296DDDE31ULL,
		0x75924E06BC8E8E72ULL,
		0x26FFB8B038AB7F89ULL,
		0xA14F792B882AF292ULL,
		0xBA6CE5D35FF7C740ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAF42D2C7D742D7DBULL,
		0xACAE9359A5F5CAD6ULL,
		0x7E92E0A88C81CC5AULL,
		0x97E7CCEAB03B5675ULL,
		0x319EA7CA8D2DE4CFULL,
		0x4765F70E410B640AULL,
		0x3016E683E7B3ADE0ULL,
		0xE1A370C772F36FA8ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 317\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 317 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -317;
	} else {
		printf("Test Case 317 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xBACC77AAE9049563ULL,
		0xC42C4A4CFDFC4130ULL,
		0x3EF96074B510C3C6ULL,
		0x2B0457EDF36B6648ULL,
		0xCCB4E884F4816654ULL,
		0xC35B0CCE545C765BULL,
		0xCE54AA7E156DD403ULL,
		0x50A2217E65113E92ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB56F970A5B49D23ULL,
		0xBA2B9C86E990660EULL,
		0xE222CB2967754BBBULL,
		0x3FF6C293BBD0FBD6ULL,
		0xA0E22186722F934CULL,
		0x8443BEF840DC6586ULL,
		0xD06BFD11F0D5510FULL,
		0xA563CCA77D0C13BFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCF757E3A434FF840ULL,
		0x0A00ADC6146BDB21ULL,
		0x5CD6954B4D9B780BULL,
		0xEB0D955A379A6A71ULL,
		0x2BD2C6FE8251D307ULL,
		0x3F174DD6138010D5ULL,
		0xFDE8AD6C249882F4ULL,
		0xAB3E54D6E8052AD2ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 318\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 318 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -318;
	} else {
		printf("Test Case 318 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x071DF340EADF4815ULL,
		0x65F3907BBB66E9F0ULL,
		0xFBB67925CC37A4B0ULL,
		0x821B54E94A4ACC00ULL,
		0x6E397D528F7D9FBFULL,
		0xDD2E04983A22C057ULL,
		0xDFF6A464CA382C46ULL,
		0x7B87F10C0068150FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x815ABB50BFE7DA8DULL,
		0x11AB12333819912DULL,
		0x0949970C4B0055F2ULL,
		0xDED7659A0FC6EE0BULL,
		0xECD4651A244DA34CULL,
		0x36684F9D4A2B48C6ULL,
		0xDCF9886F2C62CBCAULL,
		0xC71E3713ABE80829ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x85C337F02AF76D88ULL,
		0x54487E48834D58C2ULL,
		0xF26CE21981374EBEULL,
		0xA343EF4F3A83DDF5ULL,
		0x816518386B2FFC72ULL,
		0xA6C5B4FAEFF77790ULL,
		0x02FD1BF59DD5607CULL,
		0xB469B9F854800CE6ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 319\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 319 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -319;
	} else {
		printf("Test Case 319 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5BBF687DD81D51F1ULL,
		0xE3E5AE9E94379FC2ULL,
		0x52A18405E046499AULL,
		0xBDCDD871CD96FA56ULL,
		0x23C4894AFA287A15ULL,
		0x26F562DB079D89BBULL,
		0x58C47EC3417C682AULL,
		0xD364017AF29A8B60ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA650B0F30D07C610ULL,
		0xA316BF4924D4428FULL,
		0x1A2A697629D34DE6ULL,
		0xA2F6650A37060CCDULL,
		0x4175E2ABB1400D31ULL,
		0x92AD88F55E2A5A90ULL,
		0xF8EF04A907FE649AULL,
		0x12AA82451E6C8B80ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB56EB78ACB158BE1ULL,
		0x40CEEF556F635D32ULL,
		0x38771A8FB672FBB4ULL,
		0x1AD773679690ED89ULL,
		0xE24EA69F48E86CE4ULL,
		0x9447D9E5A9732F2AULL,
		0x5FD57A1A397E038FULL,
		0xC0B97F35D42DFFDFULL
	}};
	sign = 0;
	printf("Test Case 320\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 320 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -320;
	} else {
		printf("Test Case 320 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA9E3398CB261C60CULL,
		0x6DE6ADDB5A888B60ULL,
		0x509D44BE321BCC4EULL,
		0x61A3351B27DEB29DULL,
		0x640A34CBB660F281ULL,
		0x49EA1A7DBE879563ULL,
		0x5C8F80F5E6C03569ULL,
		0x401344B74E609242ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDCAA36420C847ACULL,
		0xDB03A4241C039E60ULL,
		0xF19C566C7927B275ULL,
		0x8A28D979BF2E8084ULL,
		0xFF80F8124879A998ULL,
		0xFF5557CCCBF360BCULL,
		0x4A06D7A082640876ULL,
		0xF9DEC2185E1634C3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCC18962891997E60ULL,
		0x92E309B73E84ECFFULL,
		0x5F00EE51B8F419D8ULL,
		0xD77A5BA168B03218ULL,
		0x64893CB96DE748E8ULL,
		0x4A94C2B0F29434A6ULL,
		0x1288A955645C2CF2ULL,
		0x4634829EF04A5D7FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 321\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 321 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -321;
	} else {
		printf("Test Case 321 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA5EEEDCC66C0B235ULL,
		0x849E88E1DF40AD5CULL,
		0x19670251B40093C1ULL,
		0xA369BB6F5E5093F0ULL,
		0xF2701ACAAD3E8ED1ULL,
		0x5C3A9C756C0EAAD7ULL,
		0x25072CF20561CF3AULL,
		0x95DC25554F6527F9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA42B165D0F10017ULL,
		0x1082E4F7CDB99576ULL,
		0x41A085A0C69E16ECULL,
		0xEE321CACCC29F7F6ULL,
		0xBB60510D89F823CFULL,
		0xC3969AF925337C50ULL,
		0x3506D3916EDAF618ULL,
		0x31715E3C5896E939ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBBAC3C6695CFB21EULL,
		0x741BA3EA118717E5ULL,
		0xD7C67CB0ED627CD5ULL,
		0xB5379EC292269BF9ULL,
		0x370FC9BD23466B01ULL,
		0x98A4017C46DB2E87ULL,
		0xF00059609686D921ULL,
		0x646AC718F6CE3EBFULL
	}};
	sign = 0;
	printf("Test Case 322\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 322 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -322;
	} else {
		printf("Test Case 322 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB18E100050DD471FULL,
		0x81A93802D449BF4DULL,
		0xFB57982C4FFE863FULL,
		0x37FA998700D13E70ULL,
		0x1DA6A796CB2BCE0CULL,
		0x5D523B17BA42CE3BULL,
		0xB4B683862DDB635EULL,
		0xE4502CB3927BC016ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC47860CB24DBB08BULL,
		0x9FBB824CA2A418CCULL,
		0xD7D60C28D6B15E52ULL,
		0x327C445BA8F56F2CULL,
		0xEAD6F4EEFB97546DULL,
		0x635DB088EBACC35EULL,
		0xCFA670C850E6F70EULL,
		0xD367C9FA6CF05E57ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xED15AF352C019694ULL,
		0xE1EDB5B631A5A680ULL,
		0x23818C03794D27ECULL,
		0x057E552B57DBCF44ULL,
		0x32CFB2A7CF94799FULL,
		0xF9F48A8ECE960ADCULL,
		0xE51012BDDCF46C4FULL,
		0x10E862B9258B61BEULL
	}};
	sign = 0;
	printf("Test Case 323\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 323 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -323;
	} else {
		printf("Test Case 323 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x747B159971E1E4EEULL,
		0x5A374B8B957A8A76ULL,
		0x18099B9EE94A6DCFULL,
		0x93FB9E6C739176F3ULL,
		0x03D698F3E89625B7ULL,
		0x2816629D15B1AE94ULL,
		0x9A36A09C3C32D18EULL,
		0x74EE8F0AEA0ABE6BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E2A60B16EF6DCF7ULL,
		0xE318DF96BC8CAD55ULL,
		0xACB48C915945E7B0ULL,
		0x46A606D669E8E74EULL,
		0x5DBEEF862ACA3BF1ULL,
		0xCFF04D92B29EFBCFULL,
		0x8C233E90F35063C1ULL,
		0x36186BFCFCA3F9F9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0650B4E802EB07F7ULL,
		0x771E6BF4D8EDDD21ULL,
		0x6B550F0D9004861EULL,
		0x4D55979609A88FA4ULL,
		0xA617A96DBDCBE9C6ULL,
		0x5826150A6312B2C4ULL,
		0x0E13620B48E26DCCULL,
		0x3ED6230DED66C472ULL
	}};
	sign = 0;
	printf("Test Case 324\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 324 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -324;
	} else {
		printf("Test Case 324 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF78229D82402431FULL,
		0x5CF42A9801898E5DULL,
		0x31B68C8D58F0C81AULL,
		0x2957F22D4388EAFBULL,
		0x1AE1A0606BE32681ULL,
		0x8AC5FD296CF974A3ULL,
		0xE35EF45E04530607ULL,
		0x06E62FE0CDA54E48ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC917147E0583D205ULL,
		0x0A593BA5AF91E8FDULL,
		0x68EA7E4E357F46F9ULL,
		0xD24DDF75A0E5A12CULL,
		0x1715679124EBE4ACULL,
		0xEBA354180501452AULL,
		0x3CD59BAF28D37C62ULL,
		0x804DD74E2BD3872CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2E6B155A1E7E711AULL,
		0x529AEEF251F7A560ULL,
		0xC8CC0E3F23718121ULL,
		0x570A12B7A2A349CEULL,
		0x03CC38CF46F741D4ULL,
		0x9F22A91167F82F79ULL,
		0xA68958AEDB7F89A4ULL,
		0x86985892A1D1C71CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 325\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 325 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -325;
	} else {
		printf("Test Case 325 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA173DDA22C5C14CCULL,
		0xC1DA210E4F6BC659ULL,
		0x4A282950492128F0ULL,
		0x946447C47006318EULL,
		0xFB203831B697DF1DULL,
		0xBE64B0D5721BFB09ULL,
		0x82295EB5C2FA3EC2ULL,
		0xA8892E1DF3187BE0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DAF3B67360B6E4CULL,
		0x2C68FBEBB7D61C1AULL,
		0x72546C8F9A0C5651ULL,
		0xFA652399FF88E85AULL,
		0x78B44E4ACC114509ULL,
		0xA5C645BE9805CD42ULL,
		0x0DE67A4790576062ULL,
		0x50BF91B85A8ADF09ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x53C4A23AF650A680ULL,
		0x957125229795AA3FULL,
		0xD7D3BCC0AF14D29FULL,
		0x99FF242A707D4933ULL,
		0x826BE9E6EA869A13ULL,
		0x189E6B16DA162DC7ULL,
		0x7442E46E32A2DE60ULL,
		0x57C99C65988D9CD7ULL
	}};
	sign = 0;
	printf("Test Case 326\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 326 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -326;
	} else {
		printf("Test Case 326 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE8A23CC3F46AD200ULL,
		0x767C1E0B0310FC95ULL,
		0x8D532A0349EB9AA7ULL,
		0x6DC365185D35D638ULL,
		0x08BE9D0245BEFC30ULL,
		0xB189E715C815C635ULL,
		0xFD67DD8F9A63DCAEULL,
		0x6E317BE15D411C72ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8F6DCD6216468C1ULL,
		0xF396EB14F0553F33ULL,
		0x2216A893ACDF2EB1ULL,
		0xDF9DE751E979ED74ULL,
		0x0EF7578F2077AC64ULL,
		0x5BF0B9946E39B37CULL,
		0xCDE8623700CF3E99ULL,
		0xDF669EEC5B9C590AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1FAB5FEDD306693FULL,
		0x82E532F612BBBD62ULL,
		0x6B3C816F9D0C6BF5ULL,
		0x8E257DC673BBE8C4ULL,
		0xF9C7457325474FCBULL,
		0x55992D8159DC12B8ULL,
		0x2F7F7B5899949E15ULL,
		0x8ECADCF501A4C368ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 327\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 327 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -327;
	} else {
		printf("Test Case 327 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x3CD8D728065C1188ULL,
		0x9145884CAB8B0AC4ULL,
		0xFA0CD90C78E346F2ULL,
		0x45BBC7BF91C2BC50ULL,
		0xB35B15350EDB1C73ULL,
		0x591FC71D263B27F2ULL,
		0x8FE1A5A6519C014AULL,
		0x50BE0BD336822E27ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x24B3105963126995ULL,
		0xD7A430E7899D7406ULL,
		0x5EEBCE5D7685861AULL,
		0x661D5B51D333DBA3ULL,
		0x771E719E073E72B4ULL,
		0x98780F4DBE63E84EULL,
		0x93BA7C28EA624218ULL,
		0xAF91EF088A24BFB5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1825C6CEA349A7F3ULL,
		0xB9A1576521ED96BEULL,
		0x9B210AAF025DC0D7ULL,
		0xDF9E6C6DBE8EE0ADULL,
		0x3C3CA397079CA9BEULL,
		0xC0A7B7CF67D73FA4ULL,
		0xFC27297D6739BF31ULL,
		0xA12C1CCAAC5D6E71ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 328\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 328 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -328;
	} else {
		printf("Test Case 328 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE3C2292ED7A51C9AULL,
		0x2698823741261D0CULL,
		0x616E7E0F044A37F0ULL,
		0x3DF214C0825BDFADULL,
		0xDD55B379D29CF124ULL,
		0x6CA734FA499D6D92ULL,
		0x0C17B0A66280E587ULL,
		0xBA9DF624E513289AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x608C50385F518D60ULL,
		0x8FCD5C29960B6630ULL,
		0x30B65B6CEF6431B1ULL,
		0x8FCD366AC4BABE64ULL,
		0x02D92945B47B00C7ULL,
		0xC12C90C4C9BD51DFULL,
		0xA838C4BE01D27A73ULL,
		0x070758D047CD1483ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8335D8F678538F3AULL,
		0x96CB260DAB1AB6DCULL,
		0x30B822A214E6063EULL,
		0xAE24DE55BDA12149ULL,
		0xDA7C8A341E21F05CULL,
		0xAB7AA4357FE01BB3ULL,
		0x63DEEBE860AE6B13ULL,
		0xB3969D549D461416ULL
	}};
	sign = 0;
	printf("Test Case 329\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 329 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -329;
	} else {
		printf("Test Case 329 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xBAE76B265ACA7DDEULL,
		0x2FD064F9236A5042ULL,
		0xBABA6E396CD86630ULL,
		0xA0A20FA906C04207ULL,
		0x702B9A4273EA0F20ULL,
		0x0FBE6C8BD90F28AFULL,
		0x1D565813DC143A54ULL,
		0xF60E0CC7A2C48070ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD22D7BAE0CFD04F3ULL,
		0x746E7157313416EDULL,
		0x32288D6CFC5F1AC3ULL,
		0x1D64A59B58A5AB51ULL,
		0xDD101AC4AA38E390ULL,
		0x47E84DAA629ADDCAULL,
		0x9BC9358A0A8C0CB1ULL,
		0x28FCB95E25B77CB0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE8B9EF784DCD78EBULL,
		0xBB61F3A1F2363954ULL,
		0x8891E0CC70794B6CULL,
		0x833D6A0DAE1A96B6ULL,
		0x931B7F7DC9B12B90ULL,
		0xC7D61EE176744AE4ULL,
		0x818D2289D1882DA2ULL,
		0xCD1153697D0D03BFULL
	}};
	sign = 0;
	printf("Test Case 330\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 330 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -330;
	} else {
		printf("Test Case 330 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x8A0B2AC5BC96F6BCULL,
		0x6CDE27A4423A981EULL,
		0xA0780CD6EF199E84ULL,
		0x907D874775CB9F51ULL,
		0x7C02C22AB524E12EULL,
		0x5E848390AB77E012ULL,
		0x08DB5ACE6E9C81B9ULL,
		0x4242EAE4D68C519AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8EC5D7DBF96748F3ULL,
		0xE40E2E280EFB4643ULL,
		0x8F9B1C74B6E230BAULL,
		0xA1687D414B86C5C7ULL,
		0x12A11C901D5D3289ULL,
		0x68C45140903F0322ULL,
		0x40012DC2B09CF44EULL,
		0x2F6A8B46E0CA19F8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFB4552E9C32FADC9ULL,
		0x88CFF97C333F51DAULL,
		0x10DCF06238376DC9ULL,
		0xEF150A062A44D98AULL,
		0x6961A59A97C7AEA4ULL,
		0xF5C032501B38DCF0ULL,
		0xC8DA2D0BBDFF8D6AULL,
		0x12D85F9DF5C237A1ULL
	}};
	sign = 0;
	printf("Test Case 331\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 331 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -331;
	} else {
		printf("Test Case 331 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x19BD9E5260ACC552ULL,
		0x7B79AC839A963188ULL,
		0x9434B019BC11C3D9ULL,
		0xBD739A93AD35349CULL,
		0x2CBCF0548F483B2EULL,
		0x316394C40CE88FEAULL,
		0xAC233CB60041E2ECULL,
		0x412AB61CC5637A60ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DD5BC67F9CD3BAAULL,
		0x6390602AC338BA45ULL,
		0xC89C196EF53EEC5BULL,
		0x6E7FB63B66190B77ULL,
		0xE33A28895CE8F5DDULL,
		0x88BB1E1A336068CFULL,
		0xD149E9448A05F34DULL,
		0x15DA8E3AF69D267EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xABE7E1EA66DF89A8ULL,
		0x17E94C58D75D7742ULL,
		0xCB9896AAC6D2D77EULL,
		0x4EF3E458471C2924ULL,
		0x4982C7CB325F4551ULL,
		0xA8A876A9D988271AULL,
		0xDAD95371763BEF9EULL,
		0x2B5027E1CEC653E1ULL
	}};
	sign = 0;
	printf("Test Case 332\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 332 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -332;
	} else {
		printf("Test Case 332 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x92322314BCA0DA08ULL,
		0x89017C0BE39802E1ULL,
		0x8157A8F64FBE4781ULL,
		0x42375118B1F01540ULL,
		0x5CC457D85C549F24ULL,
		0x261A367CD4E22AEEULL,
		0x75DD6B11AC4D4407ULL,
		0x539749D5EE7D687AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8C5E05E2BB6DFC5ULL,
		0x187C17399409250BULL,
		0xB1C894A37F71BAEBULL,
		0x25C2F07557C68358ULL,
		0xCC2031ABC0DE9E00ULL,
		0xFC996F461A30DD74ULL,
		0x310E71393E24ED99ULL,
		0x256D27CA7B1D199CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB96C42B690E9FA43ULL,
		0x708564D24F8EDDD5ULL,
		0xCF8F1452D04C8C96ULL,
		0x1C7460A35A2991E7ULL,
		0x90A4262C9B760124ULL,
		0x2980C736BAB14D79ULL,
		0x44CEF9D86E28566DULL,
		0x2E2A220B73604EDEULL
	}};
	sign = 0;
	printf("Test Case 333\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 333 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -333;
	} else {
		printf("Test Case 333 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x8039D53F95FA39D9ULL,
		0x29995C46649B7825ULL,
		0x96DC95A510B12677ULL,
		0xE37B48A1DE022D7CULL,
		0x9FF72E668795511EULL,
		0x72F26933098350D6ULL,
		0xB4ED94E6E2AAE02FULL,
		0x60AA285084797F27ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BDE7F534F1E31ACULL,
		0x164D121D7846B164ULL,
		0xF3610EAE5C324ED7ULL,
		0x27F21EBB33AB3E3DULL,
		0x2EFB9D662089906DULL,
		0x0B8308A717ACC952ULL,
		0xCA96C90DA8F6D4BAULL,
		0x3EB05E5B031AFFA2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x445B55EC46DC082DULL,
		0x134C4A28EC54C6C1ULL,
		0xA37B86F6B47ED7A0ULL,
		0xBB8929E6AA56EF3EULL,
		0x70FB9100670BC0B1ULL,
		0x676F608BF1D68784ULL,
		0xEA56CBD939B40B75ULL,
		0x21F9C9F5815E7F84ULL
	}};
	sign = 0;
	printf("Test Case 334\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 334 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -334;
	} else {
		printf("Test Case 334 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x06D602081A349A98ULL,
		0x20A70088CCBF6E44ULL,
		0x90F99E57828E65D6ULL,
		0x421EB0EE71AA2499ULL,
		0x6AE17631694F65C5ULL,
		0xA15149355C1C52F2ULL,
		0xC7618FDB782A91F4ULL,
		0xCBE88A4FD7C32AAAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x739D40E9ADF681E1ULL,
		0xBBEF3DA5328BDDB0ULL,
		0x137C4BD433837129ULL,
		0x7C0C214D8ECDC48EULL,
		0x58D10BE19881EAA9ULL,
		0x88936B05E90C8F08ULL,
		0x74164D3773827751ULL,
		0x988F96231491EBD7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9338C11E6C3E18B7ULL,
		0x64B7C2E39A339093ULL,
		0x7D7D52834F0AF4ACULL,
		0xC6128FA0E2DC600BULL,
		0x12106A4FD0CD7B1BULL,
		0x18BDDE2F730FC3EAULL,
		0x534B42A404A81AA3ULL,
		0x3358F42CC3313ED3ULL
	}};
	sign = 0;
	printf("Test Case 335\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 335 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -335;
	} else {
		printf("Test Case 335 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF0CB8ABAFB858756ULL,
		0x587500CA4DC0D5D9ULL,
		0xD03A4A600872D7F6ULL,
		0xD0EE72FACD0C9AC6ULL,
		0x451BFE16FEAEAB7EULL,
		0xC80E59488418BC65ULL,
		0x95874F6CDE60A7DBULL,
		0x6045FF49175C3E98ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF791D352C640BF6EULL,
		0x4B7E0231476FE6EFULL,
		0xD18FBD615E996717ULL,
		0x8924A4BE0D5807A2ULL,
		0x1FAE8BDEB70131CFULL,
		0x2B1F3B9C218EEE29ULL,
		0x029323F4E41A8DC7ULL,
		0x7C09DDD598DE0EBEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF939B7683544C7E8ULL,
		0x0CF6FE990650EEE9ULL,
		0xFEAA8CFEA9D970DFULL,
		0x47C9CE3CBFB49323ULL,
		0x256D723847AD79AFULL,
		0x9CEF1DAC6289CE3CULL,
		0x92F42B77FA461A14ULL,
		0xE43C21737E7E2FDAULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 336\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 336 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -336;
	} else {
		printf("Test Case 336 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x52221346A4DB0A57ULL,
		0x721D9433DB708737ULL,
		0xEAD02B26DCBD7F95ULL,
		0x2DB487CA6D6B80ADULL,
		0xB0659FBF38AB3F8CULL,
		0x4EE499664F2C8D0DULL,
		0xDEF61906728FBB1EULL,
		0xBC63E811B9BA74AEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x27EE7A941DA1C5ABULL,
		0xDF3F67C2605B6531ULL,
		0xA1F86E5E05A45C60ULL,
		0xC79F31C06E60C50BULL,
		0x2E050316CFF742C6ULL,
		0x342DADF0E647015FULL,
		0x98F0D07253702D69ULL,
		0x1E374238CF7420A6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2A3398B2873944ACULL,
		0x92DE2C717B152206ULL,
		0x48D7BCC8D7192334ULL,
		0x66155609FF0ABBA2ULL,
		0x82609CA868B3FCC5ULL,
		0x1AB6EB7568E58BAEULL,
		0x460548941F1F8DB5ULL,
		0x9E2CA5D8EA465408ULL
	}};
	sign = 0;
	printf("Test Case 337\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 337 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -337;
	} else {
		printf("Test Case 337 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x37B29BCDA764C77AULL,
		0x78E2A25BF8485575ULL,
		0xC13D4F87938A1D35ULL,
		0x1652E3BC58DE1593ULL,
		0x520635736E618346ULL,
		0x60102E7E0059C1F3ULL,
		0xCECEC2024C4A9F34ULL,
		0x40131BCB4377FE9AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D9F748A420CB0F8ULL,
		0x2DF1FB48FFDFB589ULL,
		0x468FCADEA1215A8FULL,
		0xE37EE3ED4C5D5282ULL,
		0xE2D74875C73D5D7AULL,
		0x207302A6781B0634ULL,
		0xA6166162E349F82FULL,
		0x7645B70B8C0B138CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCA13274365581682ULL,
		0x4AF0A712F8689FEBULL,
		0x7AAD84A8F268C2A6ULL,
		0x32D3FFCF0C80C311ULL,
		0x6F2EECFDA72425CBULL,
		0x3F9D2BD7883EBBBEULL,
		0x28B8609F6900A705ULL,
		0xC9CD64BFB76CEB0EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 338\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 338 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -338;
	} else {
		printf("Test Case 338 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5EBC9130314F3D92ULL,
		0x7178AE3E92BCCE16ULL,
		0x9224EC909CE3F563ULL,
		0xC1DFE90C94DB17BCULL,
		0xEA2C4C35198A40E8ULL,
		0x07B54DF8A4069C0DULL,
		0x27E755C94F699600ULL,
		0xF1BDC5A1B5CE56CCULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x662C4B5D4B129EB3ULL,
		0xC9899AF7EDA96FCFULL,
		0x551D979511846265ULL,
		0x495FE4CC2E911D22ULL,
		0x9267320F87A5D3F4ULL,
		0x42C626655B5E5740ULL,
		0xC463AA2525A1C49FULL,
		0x0DBD910272F6A7D1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF89045D2E63C9EDFULL,
		0xA7EF1346A5135E46ULL,
		0x3D0754FB8B5F92FDULL,
		0x788004406649FA9AULL,
		0x57C51A2591E46CF4ULL,
		0xC4EF279348A844CDULL,
		0x6383ABA429C7D160ULL,
		0xE400349F42D7AEFAULL
	}};
	sign = 0;
	printf("Test Case 339\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 339 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -339;
	} else {
		printf("Test Case 339 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x2B0E8D0E458D2C4FULL,
		0x9EA515C0885756D6ULL,
		0x189A7DA7BD806206ULL,
		0x250E35DDEC8D0E73ULL,
		0xD4ACBB5376A051F0ULL,
		0x3A22CD4B34995A55ULL,
		0x3435A55F10D2285DULL,
		0x54ED7F2C368668ECULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA6B531E0F99817AULL,
		0xC3A4E0EC6CB435CCULL,
		0xF00C393FB6B757CEULL,
		0xFEF8440C0D73F803ULL,
		0x5E576CDD4BF839C2ULL,
		0xB998927DE87B3391ULL,
		0x9654CA00A32D414AULL,
		0xE0B04D3A9A64D060ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x30A339F035F3AAD5ULL,
		0xDB0034D41BA32109ULL,
		0x288E446806C90A37ULL,
		0x2615F1D1DF19166FULL,
		0x76554E762AA8182DULL,
		0x808A3ACD4C1E26C4ULL,
		0x9DE0DB5E6DA4E712ULL,
		0x743D31F19C21988BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 340\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 340 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -340;
	} else {
		printf("Test Case 340 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x66295F287399FB5EULL,
		0x9A5134642AEA0110ULL,
		0x18F74159A7B5C919ULL,
		0x27494283334CAE83ULL,
		0x0FFC756A3BCF74D1ULL,
		0xC5C44C3DA9481F28ULL,
		0xC7412345F7CBEBF0ULL,
		0xF8C1F2377369FBEBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x575DF2E1CF5830D9ULL,
		0x7C8BA72054360014ULL,
		0x77D83CF89D7201B5ULL,
		0x48EFA9E6DD6B7107ULL,
		0x8CAEE95FA28BC936ULL,
		0xE9435DAEA71907FCULL,
		0xD789BE02019448A4ULL,
		0x5DD65B27EABAED31ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0ECB6C46A441CA85ULL,
		0x1DC58D43D6B400FCULL,
		0xA11F04610A43C764ULL,
		0xDE59989C55E13D7BULL,
		0x834D8C0A9943AB9AULL,
		0xDC80EE8F022F172BULL,
		0xEFB76543F637A34BULL,
		0x9AEB970F88AF0EB9ULL
	}};
	sign = 0;
	printf("Test Case 341\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 341 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -341;
	} else {
		printf("Test Case 341 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xECEA13525230F79EULL,
		0x613C3276342C3957ULL,
		0x1B3951922381E4F0ULL,
		0x1AC9DA16F9366D7CULL,
		0x9AAEE1D63C76DFDEULL,
		0xD876839512E52197ULL,
		0x777FB7ED7CEC28DAULL,
		0x8CCB98114B6E17C3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F0F1D3FDD74AFAFULL,
		0x679189987FA1E620ULL,
		0x21E8574A70255A72ULL,
		0x53D5A6DF79AE7B49ULL,
		0x36AB474B496210ECULL,
		0x46FE6122BDE8E29CULL,
		0x7BB979E1E3D7AFFCULL,
		0x0968F8752445D66AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4DDAF61274BC47EFULL,
		0xF9AAA8DDB48A5337ULL,
		0xF950FA47B35C8A7DULL,
		0xC6F433377F87F232ULL,
		0x64039A8AF314CEF1ULL,
		0x9178227254FC3EFBULL,
		0xFBC63E0B991478DEULL,
		0x83629F9C27284158ULL
	}};
	sign = 0;
	printf("Test Case 342\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 342 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -342;
	} else {
		printf("Test Case 342 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xFE4D255B5680ED71ULL,
		0xB4B25CE4951DFA5FULL,
		0xBABE2ECE7A8FE185ULL,
		0x3C134FAAA1F7FE81ULL,
		0x6A5257C2D020CCC2ULL,
		0xBB30A6420EA871CDULL,
		0x1D20C05EEFD7483CULL,
		0xC540AD91F3C014A3ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x65433D8BAC59C498ULL,
		0xFFC70AC8C512EC56ULL,
		0x25E86E85CD8A761AULL,
		0x1A241D71F3C2009EULL,
		0x339EA1EF0287C420ULL,
		0xEED2687A5681831BULL,
		0xCD038F3E6B9E24D3ULL,
		0x850673EC84DC7534ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9909E7CFAA2728D9ULL,
		0xB4EB521BD00B0E09ULL,
		0x94D5C048AD056B6AULL,
		0x21EF3238AE35FDE3ULL,
		0x36B3B5D3CD9908A2ULL,
		0xCC5E3DC7B826EEB2ULL,
		0x501D312084392368ULL,
		0x403A39A56EE39F6EULL
	}};
	sign = 0;
	printf("Test Case 343\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 343 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -343;
	} else {
		printf("Test Case 343 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0DF5774F0948705FULL,
		0x47FE47673DB9EA11ULL,
		0x86B3A3DD82FACCE7ULL,
		0xB9000E9B85040AC3ULL,
		0xCE9C9BE4F90A9EADULL,
		0x5E93B981CA1F9897ULL,
		0x7FE17616C2CA69D8ULL,
		0x3249ABE046BCB4CDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB019EDF22B3200BULL,
		0x70A2B878BA3ABE15ULL,
		0xDBB112875E32C9DAULL,
		0x585C3C2B0822B239ULL,
		0x242B2517AB9C8BABULL,
		0xFF0AA9B00D6C5DF9ULL,
		0x7C9FF139CC385D9DULL,
		0xD78F49ED1E5F5149ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x52F3D86FE6955054ULL,
		0xD75B8EEE837F2BFBULL,
		0xAB02915624C8030CULL,
		0x60A3D2707CE15889ULL,
		0xAA7176CD4D6E1302ULL,
		0x5F890FD1BCB33A9EULL,
		0x034184DCF6920C3AULL,
		0x5ABA61F3285D6384ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 344\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 344 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -344;
	} else {
		printf("Test Case 344 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x910767BF4E308F56ULL,
		0x77AFEA521CDA6793ULL,
		0xE09227C03FC563A3ULL,
		0x82AF5F7E9F10C29DULL,
		0x850E9852DDA2EC8AULL,
		0x004AE32EE22555D9ULL,
		0x41B1B62C8830ED33ULL,
		0xF50AEA494613A910ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A859BAE69BA6CA0ULL,
		0x78A20F0F63ED92C1ULL,
		0xC4A8391ABAF5283DULL,
		0x4E79614C4F61128BULL,
		0x5A81E5326233DCCDULL,
		0xBCCF59B84367D54DULL,
		0xF5C64F503F8CEDFCULL,
		0xA13AFD9D89FD5253ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6681CC10E47622B6ULL,
		0xFF0DDB42B8ECD4D2ULL,
		0x1BE9EEA584D03B65ULL,
		0x3435FE324FAFB012ULL,
		0x2A8CB3207B6F0FBDULL,
		0x437B89769EBD808CULL,
		0x4BEB66DC48A3FF36ULL,
		0x53CFECABBC1656BCULL
	}};
	sign = 0;
	printf("Test Case 345\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 345 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -345;
	} else {
		printf("Test Case 345 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xCD9E979735DD05DFULL,
		0x45BAF90F8AFA3955ULL,
		0x72E3249455557A0EULL,
		0x1F759A897A406270ULL,
		0xA8B39DC7C9A03ECBULL,
		0xDC64EE6806CFFF6FULL,
		0x13064891C7083663ULL,
		0x1DA2B1BF9E2FEC95ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE568088D4C565490ULL,
		0x27605481AFBEB6EBULL,
		0x80813C36E1CD4E87ULL,
		0x86BC44C4FFFA305FULL,
		0x91AFC4F5B6F189B8ULL,
		0x056B03DCAAF4445DULL,
		0x06B48D2BBB11FCB9ULL,
		0x2B37D37698484CF9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE8368F09E986B14FULL,
		0x1E5AA48DDB3B8269ULL,
		0xF261E85D73882B87ULL,
		0x98B955C47A463210ULL,
		0x1703D8D212AEB512ULL,
		0xD6F9EA8B5BDBBB12ULL,
		0x0C51BB660BF639AAULL,
		0xF26ADE4905E79F9CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 346\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 346 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -346;
	} else {
		printf("Test Case 346 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0702A7F6B7C2D978ULL,
		0xB013F26B9BE2832DULL,
		0xA50C2BDCB1E8FE3CULL,
		0xF9079D5B0AB92055ULL,
		0x08C7DF9826A201F9ULL,
		0xC3A21E2C7AD42D9FULL,
		0x0AF3FE301B59D148ULL,
		0x05A100CE13B12BBCULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF8AD73CE82EFBD6ULL,
		0x179DCED7BDEF636BULL,
		0xB1F7468C693C45CCULL,
		0xD87992DFEFE514D4ULL,
		0xA6768DB58E4BE29FULL,
		0xFFB8A24D2C8BCCBDULL,
		0x0BD35B78785D66B9ULL,
		0x18B7F60D6C70D5F9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5777D0B9CF93DDA2ULL,
		0x98762393DDF31FC1ULL,
		0xF314E55048ACB870ULL,
		0x208E0A7B1AD40B80ULL,
		0x625151E298561F5AULL,
		0xC3E97BDF4E4860E1ULL,
		0xFF20A2B7A2FC6A8EULL,
		0xECE90AC0A74055C2ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 347\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 347 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -347;
	} else {
		printf("Test Case 347 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xFB358E0DEF92258BULL,
		0x0502B2AC6F2B2DDBULL,
		0x319089B9B287DF30ULL,
		0x2E717B5C1AA555FBULL,
		0x52B02097F6FE78B7ULL,
		0xAFCB98D9A4BCD75EULL,
		0xF5EADED78FC24886ULL,
		0x3C4F3168E39A4B95ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF61AF0B1B5D692DULL,
		0x8F8D031DE41C21C1ULL,
		0x476242D518E0126DULL,
		0x93642031BA522301ULL,
		0x630D696DB5CC1222ULL,
		0x6EA0ED6FF6CD900EULL,
		0x52F212A0376D56BEULL,
		0x97BC583D8EC07D86ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFBD3DF02D434BC5EULL,
		0x7575AF8E8B0F0C19ULL,
		0xEA2E46E499A7CCC2ULL,
		0x9B0D5B2A605332F9ULL,
		0xEFA2B72A41326694ULL,
		0x412AAB69ADEF474FULL,
		0xA2F8CC375854F1C8ULL,
		0xA492D92B54D9CE0FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 348\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 348 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -348;
	} else {
		printf("Test Case 348 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x79CCD1FCF689B68FULL,
		0xFE88C184D7C96784ULL,
		0xC60CC7B375AEBBAAULL,
		0x191228F8BA691F66ULL,
		0x085B59B6BD3BB02BULL,
		0x8DCB3A3BA41EA424ULL,
		0xB09002FB01BC9C4AULL,
		0xB5127613AF7B569EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6EAF5A7A266B0EDULL,
		0x8243C761C9B70AC1ULL,
		0xF22B7C1042A70FDEULL,
		0x2224339F4B60D124ULL,
		0xCE92E0F0125D8883ULL,
		0xC97642019E062E50ULL,
		0x288883E4D6DB0174ULL,
		0xCF9856099C701E23ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC2E1DC55542305A2ULL,
		0x7C44FA230E125CC2ULL,
		0xD3E14BA33307ABCCULL,
		0xF6EDF5596F084E41ULL,
		0x39C878C6AADE27A7ULL,
		0xC454F83A061875D3ULL,
		0x88077F162AE19AD5ULL,
		0xE57A200A130B387BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 349\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 349 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -349;
	} else {
		printf("Test Case 349 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x28EDF010E2A49174ULL,
		0x89123D7FB0C4F138ULL,
		0xE0F6B0D02197FE97ULL,
		0xA173233CFF502FFDULL,
		0xAD0BC6082D0C7DE2ULL,
		0x6BB734E710F97EB8ULL,
		0xFCCEA2FA202D45A8ULL,
		0xEA95B4A99C7E8E61ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC74379CBD3F64608ULL,
		0xB9BD43C0B9C1A838ULL,
		0x6F0F2F00B6472B2EULL,
		0x897B38D57D4A7A8EULL,
		0x7BA2D621918CB0C0ULL,
		0xC8396B49CCC59BD8ULL,
		0x99547BFB15C2ED4DULL,
		0x4BC5BF10084C31E7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x61AA76450EAE4B6CULL,
		0xCF54F9BEF70348FFULL,
		0x71E781CF6B50D368ULL,
		0x17F7EA678205B56FULL,
		0x3168EFE69B7FCD22ULL,
		0xA37DC99D4433E2E0ULL,
		0x637A26FF0A6A585AULL,
		0x9ECFF59994325C7AULL
	}};
	sign = 0;
	printf("Test Case 350\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 350 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -350;
	} else {
		printf("Test Case 350 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x068B7F56348686A3ULL,
		0xE5F305702F46EF60ULL,
		0x6983DD0CF5CEB208ULL,
		0xEA2139BEF40E25D6ULL,
		0xDF1533D8F772EAF8ULL,
		0xBE66DB021FF3AB96ULL,
		0x1D8ACD175DE6515BULL,
		0x0BB2497ACCBBF845ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5F92783B200A430ULL,
		0x843B3FCE5CC85C2EULL,
		0xAA11B4FED4368A98ULL,
		0xEB3600AC774DE7EDULL,
		0x3DDF1867B8810B36ULL,
		0x7AB9739CFEED2980ULL,
		0x8B4B95EC7B5801DDULL,
		0xE26555EF1B7AD607ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x309257D28285E273ULL,
		0x61B7C5A1D27E9331ULL,
		0xBF72280E21982770ULL,
		0xFEEB39127CC03DE8ULL,
		0xA1361B713EF1DFC1ULL,
		0x43AD676521068216ULL,
		0x923F372AE28E4F7EULL,
		0x294CF38BB141223DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 351\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 351 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -351;
	} else {
		printf("Test Case 351 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1316C2D70F8EAFBDULL,
		0x471AA096A02459E0ULL,
		0xF3F2C9619653038EULL,
		0x3F77DE75D694A887ULL,
		0x0CEDF1A9A749DA9CULL,
		0x483E8542B5EA14FCULL,
		0xD8D257818AD530AFULL,
		0x2E50F63B740CEA99ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A8C8AF4458B05A7ULL,
		0x54BC50562BC8421CULL,
		0xC112EBE0A8E477A7ULL,
		0x3A76B50CFA0CCA2EULL,
		0x3270A2ED0A6DE7D6ULL,
		0x1C0A31C9E98A2BCDULL,
		0xF5FFDD10D9A1B200ULL,
		0xDAEFF630990D6719ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD88A37E2CA03AA16ULL,
		0xF25E5040745C17C3ULL,
		0x32DFDD80ED6E8BE6ULL,
		0x05012968DC87DE59ULL,
		0xDA7D4EBC9CDBF2C6ULL,
		0x2C345378CC5FE92EULL,
		0xE2D27A70B1337EAFULL,
		0x5361000ADAFF837FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 352\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 352 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -352;
	} else {
		printf("Test Case 352 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x3E7E0ABE95C585A7ULL,
		0xB6189A75E0DA79BFULL,
		0xDF06BA77927CC847ULL,
		0x515AD49FC2671073ULL,
		0xDD565A4942932119ULL,
		0x49866BCA3B2123ACULL,
		0xA98AF69A3F750F42ULL,
		0x0E1E03B546FC5BC6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA83DE41911A10BA9ULL,
		0xBDCD1852DB76231AULL,
		0x5A00BBFA8FF59BEAULL,
		0x647BCB57D718ED60ULL,
		0x47414FE3A894F63EULL,
		0xFCA823653EA3C48DULL,
		0xD2590C6328D66305ULL,
		0x26D12775F0F23A07ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x964026A5842479FEULL,
		0xF84B8223056456A4ULL,
		0x8505FE7D02872C5CULL,
		0xECDF0947EB4E2313ULL,
		0x96150A6599FE2ADAULL,
		0x4CDE4864FC7D5F1FULL,
		0xD731EA37169EAC3CULL,
		0xE74CDC3F560A21BEULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 353\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 353 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -353;
	} else {
		printf("Test Case 353 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xAE43BEC8E4F2E468ULL,
		0x8FBA7A02806013E4ULL,
		0x10DA2D48D668C25EULL,
		0x69DF35D6DD339340ULL,
		0xB8EEB3957DEDE288ULL,
		0xEC0A4DD075150ABCULL,
		0xF67DFD4E040EC97EULL,
		0xD6748949F687665EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A2CFBAE13AA61B1ULL,
		0x2C73407279CF468CULL,
		0xAA4BB3724F5BDF35ULL,
		0x19E356F9C8B54420ULL,
		0xAEDE7B209CBDFBDAULL,
		0x4C89E850EED95787ULL,
		0xFBA4225B642397A8ULL,
		0xDBAEEB429743E969ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA416C31AD14882B7ULL,
		0x634739900690CD58ULL,
		0x668E79D6870CE329ULL,
		0x4FFBDEDD147E4F1FULL,
		0x0A103874E12FE6AEULL,
		0x9F80657F863BB335ULL,
		0xFAD9DAF29FEB31D6ULL,
		0xFAC59E075F437CF4ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 354\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 354 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -354;
	} else {
		printf("Test Case 354 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x43C9721E5DD93434ULL,
		0xEE761E1F0112F902ULL,
		0x866089576B563819ULL,
		0x8042E0CCC4D85934ULL,
		0x70CCB04D74DF4340ULL,
		0x5C16FEDCD9B28A7CULL,
		0xD135F4CCBF6F3F79ULL,
		0x76D032906E2C70A0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xACFDE611841739ECULL,
		0x62A46526A38F5D7AULL,
		0x820EF88EFB385DE3ULL,
		0x7C32547302DDC620ULL,
		0x13243F2DAECE0E5FULL,
		0x408C579344A950A7ULL,
		0x36A7193A744DF8FBULL,
		0x6285EC72062185AAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x96CB8C0CD9C1FA48ULL,
		0x8BD1B8F85D839B87ULL,
		0x045190C8701DDA36ULL,
		0x04108C59C1FA9314ULL,
		0x5DA8711FC61134E1ULL,
		0x1B8AA749950939D5ULL,
		0x9A8EDB924B21467EULL,
		0x144A461E680AEAF6ULL
	}};
	sign = 0;
	printf("Test Case 355\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 355 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -355;
	} else {
		printf("Test Case 355 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7E5D2272E475E5DAULL,
		0x55F92A4B7CF25319ULL,
		0xDF505AD809769C9AULL,
		0xAC7D2219E75F994AULL,
		0xF8566C4CCB64AFB3ULL,
		0xDBB6E3A8D0D623ADULL,
		0x67D380D36F9685EDULL,
		0xA3415D057F92F206ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D148F795AEF9F4AULL,
		0xCB5E227EDA0B848FULL,
		0xD2C59C2627FEBDABULL,
		0xDA940DC83845733AULL,
		0xF0AD81344348E01BULL,
		0x559707EF4A19793FULL,
		0x4F71076D680FD2CAULL,
		0x9453E077B6E7DE21ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE14892F989864690ULL,
		0x8A9B07CCA2E6CE89ULL,
		0x0C8ABEB1E177DEEEULL,
		0xD1E91451AF1A2610ULL,
		0x07A8EB18881BCF97ULL,
		0x861FDBB986BCAA6EULL,
		0x186279660786B323ULL,
		0x0EED7C8DC8AB13E5ULL
	}};
	sign = 0;
	printf("Test Case 356\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 356 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -356;
	} else {
		printf("Test Case 356 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB9091567D9BEFFDEULL,
		0x1374E3C48E111A64ULL,
		0xD6A28328029604D7ULL,
		0x2CA82985D19B57C7ULL,
		0xF11F54C05B04CAEEULL,
		0x6F933CDFE921FD95ULL,
		0xC9173DBE58954481ULL,
		0x6DC529434119D1D6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB861EA5DD301C9CULL,
		0xD343DA477D8922D6ULL,
		0xB417C39F06F78642ULL,
		0x37B727F487B3E21EULL,
		0x3BE807DD896FAFA8ULL,
		0x6642C2A03A3713BBULL,
		0x570AAE819FCE0EEBULL,
		0x4C2F42822A4C52BAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFD82F6C1FC8EE342ULL,
		0x4031097D1087F78DULL,
		0x228ABF88FB9E7E94ULL,
		0xF4F1019149E775A9ULL,
		0xB5374CE2D1951B45ULL,
		0x09507A3FAEEAE9DAULL,
		0x720C8F3CB8C73596ULL,
		0x2195E6C116CD7F1CULL
	}};
	sign = 0;
	printf("Test Case 357\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 357 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -357;
	} else {
		printf("Test Case 357 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xAC4CC058B0BF4A7EULL,
		0xA66F0ABA699F97D5ULL,
		0x06CAD5C09C63C912ULL,
		0xE6F8D896F0BA213BULL,
		0xB75A60D30F484CDEULL,
		0x235CF784C4714EBEULL,
		0xFA90FE40B872C2FBULL,
		0x5E764C56B08DFC3CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB46C4A25E699B55CULL,
		0x75954838DBB1E903ULL,
		0xDB55C40C4BC54040ULL,
		0x218C617AB7A5761DULL,
		0x8FE7C241ADFD7693ULL,
		0xB269BFE17AEBA791ULL,
		0x99F54059ECB28E24ULL,
		0x572E713BE724D99CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF7E07632CA259522ULL,
		0x30D9C2818DEDAED1ULL,
		0x2B7511B4509E88D2ULL,
		0xC56C771C3914AB1DULL,
		0x27729E91614AD64BULL,
		0x70F337A34985A72DULL,
		0x609BBDE6CBC034D6ULL,
		0x0747DB1AC96922A0ULL
	}};
	sign = 0;
	printf("Test Case 358\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 358 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -358;
	} else {
		printf("Test Case 358 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6B9F692C09A77CF5ULL,
		0x1A5D98CBE139517BULL,
		0xDB8A3881DE5BD124ULL,
		0x373322D183F6BB69ULL,
		0xF4591076FB34659BULL,
		0x665984AA5FA9E828ULL,
		0x793A237EE6FCBEBAULL,
		0x3D871FA43A4EBCE1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD940BE22B3DC5FE4ULL,
		0xDA8F881C5B8D9F71ULL,
		0xFE82B9E625E425E7ULL,
		0x333DB634D9CC48C5ULL,
		0xE293CE399AF5736CULL,
		0xEE0125F00FB7895DULL,
		0x78DF9937D4938EB5ULL,
		0x35E7B81604AC7262ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x925EAB0955CB1D11ULL,
		0x3FCE10AF85ABB209ULL,
		0xDD077E9BB877AB3CULL,
		0x03F56C9CAA2A72A3ULL,
		0x11C5423D603EF22FULL,
		0x78585EBA4FF25ECBULL,
		0x005A8A4712693004ULL,
		0x079F678E35A24A7FULL
	}};
	sign = 0;
	printf("Test Case 359\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 359 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -359;
	} else {
		printf("Test Case 359 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC3E2ABDB4DF6F199ULL,
		0x9E5C02B0568B4922ULL,
		0x7C1303AB207D42A0ULL,
		0x8D8797278E951046ULL,
		0xD0B1D1C1D3B754FFULL,
		0x43A0009CC7E88BFEULL,
		0x9A90B9B52C63548EULL,
		0x932A6EC0418316C0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x89ECD01E64619B78ULL,
		0xFDE92888C90A8708ULL,
		0xAD6BAEFCB540CCBDULL,
		0x98C02BB6BDF01CFCULL,
		0xCC6F78C93C5C492EULL,
		0xED16D996618AA58DULL,
		0x293B5EB39A5321E4ULL,
		0x7823177F3F3C010AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x39F5DBBCE9955621ULL,
		0xA072DA278D80C21AULL,
		0xCEA754AE6B3C75E2ULL,
		0xF4C76B70D0A4F349ULL,
		0x044258F8975B0BD0ULL,
		0x56892706665DE671ULL,
		0x71555B01921032A9ULL,
		0x1B075741024715B6ULL
	}};
	sign = 0;
	printf("Test Case 360\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 360 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -360;
	} else {
		printf("Test Case 360 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x00E2BD86E81D69A0ULL,
		0x137407F46BE13DF1ULL,
		0x6750BC465071050AULL,
		0xD137830AC842E352ULL,
		0x7E66F541F6ADB9A6ULL,
		0x8F8A3F78A893CBFAULL,
		0x639D21112A302AD2ULL,
		0x9362D9ACC8377676ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA946E74108AC8C7ULL,
		0xA7C36BEAADFCAEF7ULL,
		0x0C47CB7FFCA538A2ULL,
		0x302F6D0008835B55ULL,
		0xC119481523265A9EULL,
		0xFF7C75D31F406D95ULL,
		0x857DDEAB8F87AAEFULL,
		0xBA5805864B81898AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x164E4F12D792A0D9ULL,
		0x6BB09C09BDE48EF9ULL,
		0x5B08F0C653CBCC67ULL,
		0xA108160ABFBF87FDULL,
		0xBD4DAD2CD3875F08ULL,
		0x900DC9A589535E64ULL,
		0xDE1F42659AA87FE2ULL,
		0xD90AD4267CB5ECEBULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 361\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 361 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -361;
	} else {
		printf("Test Case 361 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4A9952FB219CB4ABULL,
		0x03106932A34B2045ULL,
		0x001D8350F62B3CFEULL,
		0x0F5A0D40E16B1904ULL,
		0x59F8B4462A18CA30ULL,
		0xB38CD950831F085CULL,
		0xDA61CCBC0CC6A841ULL,
		0xAFAE86282C566352ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D0B1EACDDBE9FC3ULL,
		0x393C75FC31B6BEE4ULL,
		0x6DF1B89B42A530BEULL,
		0x91620B90C1D31165ULL,
		0xED572878D8F89D18ULL,
		0x550A0C4375F133C4ULL,
		0x5488A10F6FC1061FULL,
		0xE6BD9F49E92E23DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1D8E344E43DE14E8ULL,
		0xC9D3F33671946161ULL,
		0x922BCAB5B3860C3FULL,
		0x7DF801B01F98079EULL,
		0x6CA18BCD51202D17ULL,
		0x5E82CD0D0D2DD497ULL,
		0x85D92BAC9D05A222ULL,
		0xC8F0E6DE43283F77ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 362\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 362 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -362;
	} else {
		printf("Test Case 362 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xABC95190BD75682AULL,
		0xF92C9C30E7F23BF3ULL,
		0x15D04EE6E543BFC3ULL,
		0x8DAD5FACE3D5763CULL,
		0x9B5B41D693A28A29ULL,
		0x0CB3591520F5595CULL,
		0x13F819A7E2A77C06ULL,
		0xA23BAEC09D84D232ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xECBC8CFB14EAFFCDULL,
		0x61A306BC521A6E1FULL,
		0xE4FBFE722C6E8B16ULL,
		0x0EB2FE4F80BA342AULL,
		0xEF7B42B473F9D088ULL,
		0x4CFF97C3BA66EBA6ULL,
		0x0827638143A9B5CBULL,
		0x5C22971BC44879E8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBF0CC495A88A685DULL,
		0x9789957495D7CDD3ULL,
		0x30D45074B8D534ADULL,
		0x7EFA615D631B4211ULL,
		0xABDFFF221FA8B9A1ULL,
		0xBFB3C151668E6DB5ULL,
		0x0BD0B6269EFDC63AULL,
		0x461917A4D93C584AULL
	}};
	sign = 0;
	printf("Test Case 363\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 363 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -363;
	} else {
		printf("Test Case 363 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB83E911AA1131473ULL,
		0x51C77222AAA6A9E2ULL,
		0xBA2BB67B6D1E5FDEULL,
		0x3179098AE45DC610ULL,
		0xFBD08FCD4C2816C4ULL,
		0x0AF138539FC952E4ULL,
		0xBCEB7608E838754FULL,
		0x23D320BDE7107431ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD5A069D53E61234ULL,
		0x808CA95ABA8EAB0DULL,
		0xBFBAC1FF367C4B29ULL,
		0xC1ECA2F54A34C3F9ULL,
		0x7E20EB9B1826D05BULL,
		0xF910B9E8E2B0FB62ULL,
		0x80A1C4549B18ECC1ULL,
		0xD46DC3ADD7B830D2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0AE48A7D4D2D023FULL,
		0xD13AC8C7F017FED5ULL,
		0xFA70F47C36A214B4ULL,
		0x6F8C66959A290216ULL,
		0x7DAFA43234014668ULL,
		0x11E07E6ABD185782ULL,
		0x3C49B1B44D1F888DULL,
		0x4F655D100F58435FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 364\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 364 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -364;
	} else {
		printf("Test Case 364 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC8D4A381DEAEF0E6ULL,
		0xE8FDFF2EEE30DE1FULL,
		0xF07345C737893BF8ULL,
		0x8B4DCBF0533FBA07ULL,
		0xA28CB27C3D519326ULL,
		0xF27CF2155EF09858ULL,
		0xF00127FD44394D5BULL,
		0x5D3182B61D1DC63DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB12B3EE315C7782ULL,
		0xD5E2AFA6AD093CF9ULL,
		0x49241E9F1196F64DULL,
		0x42E899D38600EF77ULL,
		0x19DA42A5BAC45F5DULL,
		0xFA5928EADB079A69ULL,
		0x7E94D3C8A66D2F42ULL,
		0x81B722AE687DC7CFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEDC1EF93AD527964ULL,
		0x131B4F884127A125ULL,
		0xA74F272825F245ABULL,
		0x4865321CCD3ECA90ULL,
		0x88B26FD6828D33C9ULL,
		0xF823C92A83E8FDEFULL,
		0x716C54349DCC1E18ULL,
		0xDB7A6007B49FFE6EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 365\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 365 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -365;
	} else {
		printf("Test Case 365 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6AC7202FB7BBD3A8ULL,
		0x2C6CF3FD9607CED4ULL,
		0x3F6E297E940F080AULL,
		0xA39DC81ED7D43495ULL,
		0x3A394F23250707A4ULL,
		0x070E5BA2737F9301ULL,
		0x03FFD28827504377ULL,
		0x2695D4E4EE8BD3CAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBA55A78325E6F3CULL,
		0x99C6F888FD65F96BULL,
		0x89BD26405BA39A15ULL,
		0x7D2303BE08E82988ULL,
		0xA271D276CB7B120CULL,
		0x2014D39B43578C4CULL,
		0xDBF6AAAC47FEED6DULL,
		0x8811AC3BA4370B67ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7F21C5B7855D646CULL,
		0x92A5FB7498A1D568ULL,
		0xB5B1033E386B6DF4ULL,
		0x267AC460CEEC0B0CULL,
		0x97C77CAC598BF598ULL,
		0xE6F98807302806B4ULL,
		0x280927DBDF515609ULL,
		0x9E8428A94A54C862ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 366\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 366 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -366;
	} else {
		printf("Test Case 366 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5ACDC7F229DDC698ULL,
		0x6385404D3280C51EULL,
		0x20F57F220BAF30F0ULL,
		0xC4F9FA47CAF700F3ULL,
		0x79058BAD0F179037ULL,
		0xCE6513157B8E79FDULL,
		0xEEC3FF86D96CCB39ULL,
		0x13716DBD9243C4F4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x06156D24CA859099ULL,
		0x14BE3AC75AA5A91CULL,
		0x3D0C4720AA21CF43ULL,
		0x963073AC3CF190AEULL,
		0x3B807E1875F87B4CULL,
		0xDE62199AF4D581E6ULL,
		0xDE141A5A7594BB68ULL,
		0x5E040EC55C70837BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x54B85ACD5F5835FFULL,
		0x4EC70585D7DB1C02ULL,
		0xE3E93801618D61ADULL,
		0x2EC9869B8E057044ULL,
		0x3D850D94991F14EBULL,
		0xF002F97A86B8F817ULL,
		0x10AFE52C63D80FD0ULL,
		0xB56D5EF835D34179ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 367\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 367 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -367;
	} else {
		printf("Test Case 367 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD14907746058450BULL,
		0xF87052D1D70F4402ULL,
		0x516770DAC4DAC44EULL,
		0x0216AF3250FE2D62ULL,
		0x5C2B5DD686288006ULL,
		0x7D8F9AD52036D5E9ULL,
		0x68A4D96CBE05161EULL,
		0x754791D9E2326E7FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x111121CD682005F9ULL,
		0x79D591B08DCA7DDCULL,
		0xD1FD540990A607E0ULL,
		0x0D8BB21B73FD64BBULL,
		0x7A7669B90557D9A2ULL,
		0x25CB3C7730CF4495ULL,
		0xAD6FAFBE31A1A3DDULL,
		0x4013C830D83A2469ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC037E5A6F8383F12ULL,
		0x7E9AC1214944C626ULL,
		0x7F6A1CD13434BC6EULL,
		0xF48AFD16DD00C8A6ULL,
		0xE1B4F41D80D0A663ULL,
		0x57C45E5DEF679153ULL,
		0xBB3529AE8C637241ULL,
		0x3533C9A909F84A15ULL
	}};
	sign = 0;
	printf("Test Case 368\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 368 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -368;
	} else {
		printf("Test Case 368 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x72E13284A2384B7DULL,
		0x6E185531F57A6CBFULL,
		0xFBFE2A96C8F723E4ULL,
		0x2F22C9B680D2C480ULL,
		0x2A59AE299FE19805ULL,
		0xC5855B36D5EBC38BULL,
		0x89E7AEF4B6EFBAE0ULL,
		0xB4045296353193C8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D89A8A87FEAE542ULL,
		0x742EA717C9F9FCE0ULL,
		0xDF06A51C16FB4D66ULL,
		0x9F1334C3D20F9280ULL,
		0xEA5B520DF719ED4DULL,
		0xD603A5FED7EC58FFULL,
		0x4829358DBEBA2227ULL,
		0x2B18E65A1BFC0CB1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x055789DC224D663BULL,
		0xF9E9AE1A2B806FDFULL,
		0x1CF7857AB1FBD67DULL,
		0x900F94F2AEC33200ULL,
		0x3FFE5C1BA8C7AAB7ULL,
		0xEF81B537FDFF6A8BULL,
		0x41BE7966F83598B8ULL,
		0x88EB6C3C19358717ULL
	}};
	sign = 0;
	printf("Test Case 369\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 369 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -369;
	} else {
		printf("Test Case 369 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD2792B638F70C275ULL,
		0x182C1AAA698F96DBULL,
		0x28FA4FDF0DA6F2AAULL,
		0x3ECDCBB17D7330A2ULL,
		0x82BDA252DE04DD7EULL,
		0x2B7B280854FAB49AULL,
		0xC5E604E21C05F21FULL,
		0x483673E34F5BC75FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE92C644955128A67ULL,
		0xAB643E1A4E410AD8ULL,
		0xCC2D85F123C40593ULL,
		0xC9F945A874FECFF0ULL,
		0x5DA1CDD9B3FB99B5ULL,
		0xA0451ABF33C25AD7ULL,
		0x60D9407CBA110F94ULL,
		0xCBB7FF94EAC1FE07ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE94CC71A3A5E380EULL,
		0x6CC7DC901B4E8C02ULL,
		0x5CCCC9EDE9E2ED16ULL,
		0x74D48609087460B1ULL,
		0x251BD4792A0943C8ULL,
		0x8B360D49213859C3ULL,
		0x650CC46561F4E28AULL,
		0x7C7E744E6499C958ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 370\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 370 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -370;
	} else {
		printf("Test Case 370 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0E332BF8516934A5ULL,
		0xCD10C0B0078D3E90ULL,
		0x987755C919CFBF92ULL,
		0x1F1B945460C65B12ULL,
		0x8B777A076DDF9947ULL,
		0xFB498110CDEC19FFULL,
		0x7777C1AE7D0FED2CULL,
		0x5087CD86DB94E731ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x933A098F6694271EULL,
		0x7D945B6C66FA3D5FULL,
		0x4F39453853A9D3E6ULL,
		0xFA360555ABB72340ULL,
		0x87AD5895A6881A7AULL,
		0x739F9271B7DD50D6ULL,
		0xCC6D3AD1D06368D8ULL,
		0x257458781263B423ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7AF92268EAD50D87ULL,
		0x4F7C6543A0930130ULL,
		0x493E1090C625EBACULL,
		0x24E58EFEB50F37D2ULL,
		0x03CA2171C7577ECCULL,
		0x87A9EE9F160EC929ULL,
		0xAB0A86DCACAC8454ULL,
		0x2B13750EC931330DULL
	}};
	sign = 0;
	printf("Test Case 371\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 371 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -371;
	} else {
		printf("Test Case 371 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x64A0D4AAEE0D7D5DULL,
		0x052C5800BEA052ABULL,
		0x192790CCC9D6A713ULL,
		0xD09681D9DD48EBCBULL,
		0x1413EADB06EAC650ULL,
		0xDAA970EC94A0C7AEULL,
		0x6A2261419C9A740EULL,
		0xC98E8BDD334CF795ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x245F7DA05EA66684ULL,
		0xD3F3D80C72718E5FULL,
		0xCECA8CFC844E8F62ULL,
		0xCB7A1568DC4008A3ULL,
		0x8604F58D88185D5EULL,
		0x1D84264B714E3466ULL,
		0xC9E852E7419906C9ULL,
		0xE9083E72BA923441ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4041570A8F6716D9ULL,
		0x31387FF44C2EC44CULL,
		0x4A5D03D0458817B0ULL,
		0x051C6C710108E327ULL,
		0x8E0EF54D7ED268F2ULL,
		0xBD254AA123529347ULL,
		0xA03A0E5A5B016D45ULL,
		0xE0864D6A78BAC353ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 372\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 372 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -372;
	} else {
		printf("Test Case 372 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x90B077968062DBB7ULL,
		0x16A9D76E6049E901ULL,
		0xBEC081369D3EC2A5ULL,
		0x5123738C97F1047EULL,
		0x7B2E9379E51F4972ULL,
		0x99FA5003959AFA78ULL,
		0x1ED2A7B7163AC519ULL,
		0xB8965F2C1144D910ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x09868EF753ED8D69ULL,
		0xAD6B4213CBE3BA4FULL,
		0x1E5D12A3910F0DEDULL,
		0x910B0A86858B200BULL,
		0x8C46DF1FC886C410ULL,
		0x92D35D18F75DFB81ULL,
		0x6D7CA2B0BECCF438ULL,
		0x01706FEA31AE69D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8729E89F2C754E4EULL,
		0x693E955A94662EB2ULL,
		0xA0636E930C2FB4B7ULL,
		0xC01869061265E473ULL,
		0xEEE7B45A1C988561ULL,
		0x0726F2EA9E3CFEF6ULL,
		0xB1560506576DD0E1ULL,
		0xB725EF41DF966F39ULL
	}};
	sign = 0;
	printf("Test Case 373\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 373 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -373;
	} else {
		printf("Test Case 373 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x812FB39EE4C3B0B3ULL,
		0xD7AA07B4F0FB4E36ULL,
		0xF64CBB229EED9743ULL,
		0xF77129B4475B3433ULL,
		0x080A7F5D1AF88963ULL,
		0x6E9C67056954A55CULL,
		0xA4B9A42C16A9B29FULL,
		0x3B5FE7DDBEBFFCFEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BAE0EE5DE067BC1ULL,
		0x7F979DBBC9BA294EULL,
		0x779B96D2056E285DULL,
		0xE6169BFC4F1A7940ULL,
		0xA7113917160D065FULL,
		0x69B7DC8EA5328A89ULL,
		0x3E89EE2456028578ULL,
		0x50A2F3581E097712ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2581A4B906BD34F2ULL,
		0x581269F9274124E8ULL,
		0x7EB12450997F6EE6ULL,
		0x115A8DB7F840BAF3ULL,
		0x60F9464604EB8304ULL,
		0x04E48A76C4221AD2ULL,
		0x662FB607C0A72D27ULL,
		0xEABCF485A0B685ECULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 374\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 374 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -374;
	} else {
		printf("Test Case 374 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE303522BED19B98EULL,
		0xDA52E6163EB2BCA6ULL,
		0xB9A36C6B45E56F19ULL,
		0xB704B34FBAAE1A19ULL,
		0xD593EDBF2CCE0B42ULL,
		0x080629797FEB2ADCULL,
		0x614E0F26D294F0F0ULL,
		0x966CE3A74D91787BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA55FA5BFF5A9399DULL,
		0xE65878C4DC339C17ULL,
		0xC87F6CF692AA76A5ULL,
		0xCC7E06E3DDA87DACULL,
		0x3B221940615A654CULL,
		0x4BA15052A16E5789ULL,
		0xA8CC6CE406F30682ULL,
		0x72502B993AC10156ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3DA3AC6BF7707FF1ULL,
		0xF3FA6D51627F208FULL,
		0xF123FF74B33AF873ULL,
		0xEA86AC6BDD059C6CULL,
		0x9A71D47ECB73A5F5ULL,
		0xBC64D926DE7CD353ULL,
		0xB881A242CBA1EA6DULL,
		0x241CB80E12D07724ULL
	}};
	sign = 0;
	printf("Test Case 375\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 375 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -375;
	} else {
		printf("Test Case 375 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x82111FECD4553DA7ULL,
		0x1CFDFEAFDD8B3A0BULL,
		0xBA857C5C51CCEBC4ULL,
		0xC6DC9D03264923D3ULL,
		0xF17FF43EE8D79513ULL,
		0x9EE3B928298EB491ULL,
		0xB61446B8B552DABAULL,
		0x82314A06A544D977ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x830B5AB63A7876C1ULL,
		0xF76DD9DA97924DBFULL,
		0x4D8C246D62D70576ULL,
		0xAE1A2489BB1B8C4DULL,
		0xCD8A23CF57EDE7ECULL,
		0xE4EDBCABFF9906F5ULL,
		0x2DFB37FB0DA16587ULL,
		0xE31C54A64532C1E2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFF05C53699DCC6E6ULL,
		0x259024D545F8EC4BULL,
		0x6CF957EEEEF5E64DULL,
		0x18C278796B2D9786ULL,
		0x23F5D06F90E9AD27ULL,
		0xB9F5FC7C29F5AD9CULL,
		0x88190EBDA7B17532ULL,
		0x9F14F56060121795ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 376\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 376 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -376;
	} else {
		printf("Test Case 376 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5C0FEE97926B0A3FULL,
		0x1E59AD491D6E194CULL,
		0xFC0DFB8B83BCECDFULL,
		0x67D7720F0C61AEF5ULL,
		0xFC3006A0FECAC249ULL,
		0xEC65816A6E52FE0EULL,
		0x7C416FA9C8C29DACULL,
		0xAB418DEFEDDCF125ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x094A7C820E3DE638ULL,
		0x13D96C506291809AULL,
		0x958B57E09C22DAFAULL,
		0xC6735A788BB7DBF3ULL,
		0x5133C49B4E9C37D6ULL,
		0x3C11D5FC40A6B9DFULL,
		0x037E4E7ED4776397ULL,
		0xD70BEE2FF08473AAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x52C57215842D2407ULL,
		0x0A8040F8BADC98B2ULL,
		0x6682A3AAE79A11E5ULL,
		0xA164179680A9D302ULL,
		0xAAFC4205B02E8A72ULL,
		0xB053AB6E2DAC442FULL,
		0x78C3212AF44B3A15ULL,
		0xD4359FBFFD587D7BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 377\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 377 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -377;
	} else {
		printf("Test Case 377 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x95DD82BEAE2DD897ULL,
		0x1D2857E437EFCA25ULL,
		0x7670F215491A0257ULL,
		0xCA8D89FDA4D88A0EULL,
		0xDDDE1548E308D7CAULL,
		0x342695BDFF53193BULL,
		0x53C4AE56320B3B03ULL,
		0xB47B453FEDED5F88ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x14070D0F66482CC4ULL,
		0xD37DD5BD82862328ULL,
		0x3D09D620332D1E7BULL,
		0xECFB51504C92A5E3ULL,
		0xE121BE84801FB841ULL,
		0x22CF19A97935A60BULL,
		0x4181FDB12C21F5A7ULL,
		0x66C9183B36FD1A0BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x81D675AF47E5ABD3ULL,
		0x49AA8226B569A6FDULL,
		0x39671BF515ECE3DBULL,
		0xDD9238AD5845E42BULL,
		0xFCBC56C462E91F88ULL,
		0x11577C14861D732FULL,
		0x1242B0A505E9455CULL,
		0x4DB22D04B6F0457DULL
	}};
	sign = 0;
	printf("Test Case 378\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 378 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -378;
	} else {
		printf("Test Case 378 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xCFF3230EB9A37F1BULL,
		0x4D1FB31FAF637D2BULL,
		0x70BEA6BE53008BE1ULL,
		0x0707BF4633634167ULL,
		0xCA0D074265FB71F5ULL,
		0x6FB290C7520FE70EULL,
		0x18697831A1439146ULL,
		0xADE8302070ABF91BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9AB436C80B6ABFCULL,
		0x9DE7FECB7BF9DC13ULL,
		0xC05363E670223A61ULL,
		0xB241366856D932E5ULL,
		0xA2974B1485833598ULL,
		0x9159440CE4AF0BA7ULL,
		0xF9A86846AA7AD55AULL,
		0xD31E2E11F854EFF3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF647DFA238ECD31FULL,
		0xAF37B4543369A117ULL,
		0xB06B42D7E2DE517FULL,
		0x54C688DDDC8A0E81ULL,
		0x2775BC2DE0783C5CULL,
		0xDE594CBA6D60DB67ULL,
		0x1EC10FEAF6C8BBEBULL,
		0xDACA020E78570927ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 379\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 379 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -379;
	} else {
		printf("Test Case 379 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xBBF73E3D4A373262ULL,
		0xD74432817F80ECA9ULL,
		0x14898DF122D4F05CULL,
		0x011CEAF181254087ULL,
		0xEB60C924DA8E9C05ULL,
		0xEA25404DA07C2A72ULL,
		0xEAB826DBA206120DULL,
		0x814D00D7883CAD09ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x59A438EC4EEB55AFULL,
		0x75079C9143340810ULL,
		0xFFAD5A34147ABFC1ULL,
		0x92F73B1C989E3044ULL,
		0x0C985269887FA30EULL,
		0x9ED3D42A00300405ULL,
		0x311581A789F73F08ULL,
		0xC58D4093F8D56423ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x62530550FB4BDCB3ULL,
		0x623C95F03C4CE499ULL,
		0x14DC33BD0E5A309BULL,
		0x6E25AFD4E8871042ULL,
		0xDEC876BB520EF8F6ULL,
		0x4B516C23A04C266DULL,
		0xB9A2A534180ED305ULL,
		0xBBBFC0438F6748E6ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 380\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 380 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -380;
	} else {
		printf("Test Case 380 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC148772B550A9285ULL,
		0x6AF1503AABDA3584ULL,
		0xCB3D913D88FF4C5DULL,
		0xE82C43518FEA14A8ULL,
		0xF767C91781862E39ULL,
		0x0647DE028FD4139BULL,
		0x1E61F8EDC02C1AE7ULL,
		0x177CDD8C8EB60E87ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6AF548672667C4BCULL,
		0x0B96931F5BB0B69DULL,
		0x365506D3484A6B3EULL,
		0xECB88ABAC3524508ULL,
		0xE9EC1539FED43CD4ULL,
		0xA4C02354D28CA0C3ULL,
		0x4D45603EC71AD507ULL,
		0x214EE5FD36351806ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x56532EC42EA2CDC9ULL,
		0x5F5ABD1B50297EE7ULL,
		0x94E88A6A40B4E11FULL,
		0xFB73B896CC97CFA0ULL,
		0x0D7BB3DD82B1F164ULL,
		0x6187BAADBD4772D8ULL,
		0xD11C98AEF91145DFULL,
		0xF62DF78F5880F680ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 381\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 381 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -381;
	} else {
		printf("Test Case 381 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x98520F80296ACDE2ULL,
		0x7981FC2ADADD7597ULL,
		0xE4C77EF3CD2504D8ULL,
		0xD0FA564D0CCE611CULL,
		0xB6F7771ABF918D31ULL,
		0xF345EB97781BEC48ULL,
		0xB9CA739C4E796D5AULL,
		0xA5633376549E01E5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBB17134D7F8C7BAULL,
		0x3B5B18E112117A0CULL,
		0xB4EB3105264E117BULL,
		0xF466FD7F5E622C20ULL,
		0xE0D2A202D5D54D55ULL,
		0x52F0C2315CA1A388ULL,
		0xA45F8DE5F25784B8ULL,
		0x595971D315559548ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xACA09E4B51720628ULL,
		0x3E26E349C8CBFB8AULL,
		0x2FDC4DEEA6D6F35DULL,
		0xDC9358CDAE6C34FCULL,
		0xD624D517E9BC3FDBULL,
		0xA05529661B7A48BFULL,
		0x156AE5B65C21E8A2ULL,
		0x4C09C1A33F486C9DULL
	}};
	sign = 0;
	printf("Test Case 382\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 382 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -382;
	} else {
		printf("Test Case 382 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA3EDCB581318B9B2ULL,
		0x94DB4CC29F3EAAA8ULL,
		0x1D57013EA14270D7ULL,
		0xE7473DDD00E90AD2ULL,
		0x1B9723FBAFEA9D32ULL,
		0x1FA4C7566E364847ULL,
		0xEF534892E353F538ULL,
		0x2A044EB48C910C34ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x62780C9444BC40D8ULL,
		0x0C435D43AD16C626ULL,
		0x77483E8339077144ULL,
		0xC1258BA483EC3310ULL,
		0xA035A0C48B502106ULL,
		0x9CFB82C9EB01B178ULL,
		0xDFB1A00C3221FC3CULL,
		0x966C841B1B09F27FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4175BEC3CE5C78DAULL,
		0x8897EF7EF227E482ULL,
		0xA60EC2BB683AFF93ULL,
		0x2621B2387CFCD7C1ULL,
		0x7B618337249A7C2CULL,
		0x82A9448C833496CEULL,
		0x0FA1A886B131F8FBULL,
		0x9397CA99718719B5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 383\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 383 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -383;
	} else {
		printf("Test Case 383 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD2331A3C1DB47DCDULL,
		0x5A3836F08C6C7786ULL,
		0x03492B7FDA7C9C43ULL,
		0x965B960FFAF6FCA5ULL,
		0xEEE7537A25E64671ULL,
		0xE0258131D6D1A1D1ULL,
		0xA28B82A6AD55FDC7ULL,
		0x23A360DBDF165B6DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF490C17FFF3E6AACULL,
		0x5ABD6C953A132F73ULL,
		0xDC9C487D818DB69EULL,
		0x19E42932008A219CULL,
		0xB1433EF56515E621ULL,
		0x3787B2FA1298FDCEULL,
		0x305C19DC6983CF40ULL,
		0x7AEE209B134ABD1EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDDA258BC1E761321ULL,
		0xFF7ACA5B52594812ULL,
		0x26ACE30258EEE5A4ULL,
		0x7C776CDDFA6CDB08ULL,
		0x3DA41484C0D06050ULL,
		0xA89DCE37C438A403ULL,
		0x722F68CA43D22E87ULL,
		0xA8B54040CBCB9E4FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 384\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 384 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -384;
	} else {
		printf("Test Case 384 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x576C9D4DC91776F1ULL,
		0x7A5E9C9F0FB275A7ULL,
		0x432778E5EF30AFEEULL,
		0x605149F33AF1B7AFULL,
		0x56C148DC9CFE2B56ULL,
		0x4285BDCCD433CD25ULL,
		0x8FFC4AB13DB77224ULL,
		0xC2B23CC7AD1D2252ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1049E00B51CFC352ULL,
		0x47D5D2678A91DA3FULL,
		0xE8FBB44EBC86E874ULL,
		0x419A49AD00A70D77ULL,
		0xE665E878012C30BFULL,
		0x40CDA5E4B1FE5361ULL,
		0xA45DA82C2933587BULL,
		0xB3697E290BA78D13ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4722BD427747B39FULL,
		0x3288CA3785209B68ULL,
		0x5A2BC49732A9C77AULL,
		0x1EB700463A4AAA37ULL,
		0x705B60649BD1FA97ULL,
		0x01B817E8223579C3ULL,
		0xEB9EA285148419A9ULL,
		0x0F48BE9EA175953EULL
	}};
	sign = 0;
	printf("Test Case 385\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 385 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -385;
	} else {
		printf("Test Case 385 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x77A4308DBB677700ULL,
		0x3662529C75BC6FDAULL,
		0x7EF6E55E71EB7216ULL,
		0x36413658E87129BFULL,
		0x934EA3604F53B9F9ULL,
		0x225DEF9CF2428A58ULL,
		0xC2D44A8D85DFBB97ULL,
		0xECF67D9C2FCD6A07ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DACEF059C2FC1C0ULL,
		0x7522FE1D9909B84EULL,
		0x32DC93B4A594822CULL,
		0xB2E26AE16F2A8ECDULL,
		0x17CB54AE7A5F2BDAULL,
		0x4B472018D9429DEEULL,
		0xD5A03B9F2F945286ULL,
		0x471C331F817C59BCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x69F741881F37B540ULL,
		0xC13F547EDCB2B78CULL,
		0x4C1A51A9CC56EFE9ULL,
		0x835ECB7779469AF2ULL,
		0x7B834EB1D4F48E1EULL,
		0xD716CF8418FFEC6AULL,
		0xED340EEE564B6910ULL,
		0xA5DA4A7CAE51104AULL
	}};
	sign = 0;
	printf("Test Case 386\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 386 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -386;
	} else {
		printf("Test Case 386 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x959EB3520A0F3FF6ULL,
		0x3E7F8D55AAF3579EULL,
		0x3A3183C5BD3B237FULL,
		0x68E30801C84C1653ULL,
		0x3F09A5A574FA44D8ULL,
		0x56EA1813B3EFD1CCULL,
		0x963D5411CD9A56FCULL,
		0x0EBAA7A551B3E643ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x860B462482C2399FULL,
		0xB7AD980BAD4E2CF1ULL,
		0xE24B9CE8D2707DD1ULL,
		0x96E87BEAB25C6215ULL,
		0x24060890991FD3F6ULL,
		0x148D8874A5724CEFULL,
		0xBBD51D453B749A39ULL,
		0xBC56B4915B75D64EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F936D2D874D0657ULL,
		0x86D1F549FDA52AADULL,
		0x57E5E6DCEACAA5ADULL,
		0xD1FA8C1715EFB43DULL,
		0x1B039D14DBDA70E1ULL,
		0x425C8F9F0E7D84DDULL,
		0xDA6836CC9225BCC3ULL,
		0x5263F313F63E0FF4ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 387\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 387 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -387;
	} else {
		printf("Test Case 387 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x924CAD1B84BD7E49ULL,
		0xE9F9FC1DD56CD209ULL,
		0xD63787DD94741A96ULL,
		0x908BBBFB371F36F4ULL,
		0x7DF970B621000C69ULL,
		0x1ACE47384658930EULL,
		0x1787D035D6CECF06ULL,
		0x33444B048B66C919ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB42CA5D8FF165AAEULL,
		0x1027C0C91D9820E7ULL,
		0x8754DEFE899A42C8ULL,
		0xA5BDD2FDC5FADC3BULL,
		0x47A4564456AB143AULL,
		0x5B5FAADB5C352672ULL,
		0xDF0F4DE12894E261ULL,
		0x5AF676696C22BE2EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDE20074285A7239BULL,
		0xD9D23B54B7D4B121ULL,
		0x4EE2A8DF0AD9D7CEULL,
		0xEACDE8FD71245AB9ULL,
		0x36551A71CA54F82EULL,
		0xBF6E9C5CEA236C9CULL,
		0x38788254AE39ECA4ULL,
		0xD84DD49B1F440AEAULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 388\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 388 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -388;
	} else {
		printf("Test Case 388 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xFC193D0BB44E2250ULL,
		0xC02EB296AE614B71ULL,
		0x82BD45072B5C7F6DULL,
		0x33F1D3E86A4EC5D3ULL,
		0xCD2326E5C914C50AULL,
		0xECF90A267016ABC9ULL,
		0x2EA6ED40EC82B384ULL,
		0x084E910A2ACE8EBBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x33C7F26F7CD19064ULL,
		0x72F3C6D985C8E805ULL,
		0x76C05C0E39E3EA59ULL,
		0xB28489BFD9DA1789ULL,
		0x5886144BAFB8EBEFULL,
		0xE7A2FEC7252E6DC6ULL,
		0x140B8EEF10521566ULL,
		0xF924A135EA9D7014ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC8514A9C377C91ECULL,
		0x4D3AEBBD2898636CULL,
		0x0BFCE8F8F1789514ULL,
		0x816D4A289074AE4AULL,
		0x749D129A195BD91AULL,
		0x05560B5F4AE83E03ULL,
		0x1A9B5E51DC309E1EULL,
		0x0F29EFD440311EA7ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 389\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 389 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -389;
	} else {
		printf("Test Case 389 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x88776EA4BE0C71B9ULL,
		0x38B0ED69FD149728ULL,
		0x03072048EF30EADBULL,
		0x0D4FF1B1824A870DULL,
		0x59C11E4B8E0E11B9ULL,
		0x58EE747B3B1CBA1CULL,
		0x3194657D67A18053ULL,
		0xF615A89F83D17AB7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB09E6AB93520BE1ULL,
		0xAAD9FFF1101E9181ULL,
		0x7EBDBB9D5FEECF1BULL,
		0x26DB6EE28F8D05B0ULL,
		0xD1B6C68DD5825B95ULL,
		0x19A11004634CD916ULL,
		0x5159574DEBFFB586ULL,
		0xA0921E446EFCCE12ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDD6D87F92ABA65D8ULL,
		0x8DD6ED78ECF605A6ULL,
		0x844964AB8F421BBFULL,
		0xE67482CEF2BD815CULL,
		0x880A57BDB88BB623ULL,
		0x3F4D6476D7CFE105ULL,
		0xE03B0E2F7BA1CACDULL,
		0x55838A5B14D4ACA4ULL
	}};
	sign = 0;
	printf("Test Case 390\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 390 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -390;
	} else {
		printf("Test Case 390 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x124B2F5635B6FC6DULL,
		0x8359F8F086315701ULL,
		0x948B6960C75D5CD5ULL,
		0xC09B225F169D4C35ULL,
		0x758DDCE28B573D0EULL,
		0xE8E23E19BF437E82ULL,
		0x6EBB8E1F193C4FA0ULL,
		0xACA1BE1C579EED0DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF040D283199A023ULL,
		0xDCABA4335877224BULL,
		0xC2A97B512F8A3DBBULL,
		0x7B3093443EF48730ULL,
		0x780CBA37CADD3A8BULL,
		0xD8C0A8C0AAE9B752ULL,
		0x2F4DDE981C77AD55ULL,
		0x04CE508C6A9794E1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1347222E041D5C4AULL,
		0xA6AE54BD2DBA34B5ULL,
		0xD1E1EE0F97D31F19ULL,
		0x456A8F1AD7A8C504ULL,
		0xFD8122AAC07A0283ULL,
		0x102195591459C72FULL,
		0x3F6DAF86FCC4A24BULL,
		0xA7D36D8FED07582CULL
	}};
	sign = 0;
	printf("Test Case 391\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 391 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -391;
	} else {
		printf("Test Case 391 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5AADA38F0511765DULL,
		0x2711F341780E3F12ULL,
		0x8EFC06ED04EA878BULL,
		0xE3BD12287516E116ULL,
		0xE6566C95D21437AFULL,
		0xAF5BA52800DB09C4ULL,
		0xEE4602C31197B94EULL,
		0x015D4909F0059F74ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF35DA98B5E57EECFULL,
		0xC50F395E3F700E9CULL,
		0x2911029E38E549AAULL,
		0x6D139C02317AD867ULL,
		0x4202E29827B2ADC5ULL,
		0xCEEC66C488EA7D8FULL,
		0xADE99FCDF5FC9C5FULL,
		0x1C0428365C912F7EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x674FFA03A6B9878EULL,
		0x6202B9E3389E3075ULL,
		0x65EB044ECC053DE0ULL,
		0x76A97626439C08AFULL,
		0xA45389FDAA6189EAULL,
		0xE06F3E6377F08C35ULL,
		0x405C62F51B9B1CEEULL,
		0xE55920D393746FF6ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 392\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 392 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -392;
	} else {
		printf("Test Case 392 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xAB916C853641EF60ULL,
		0xCA13960AFDC97C2CULL,
		0x647E461737103273ULL,
		0xB09BC05BED5CC231ULL,
		0xA43D194EB32EA9AFULL,
		0xE167BF71791C2510ULL,
		0x4020D95E02BB822AULL,
		0x167C1B7EA11D405EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x20BF0596FDCED9E1ULL,
		0x134D066440E65A37ULL,
		0x209A88D1CF1945F9ULL,
		0x44E7A8DEE9059E69ULL,
		0x1E2D78018416F569ULL,
		0x67A94F348BC67279ULL,
		0x432EF3D45C6A150EULL,
		0x229AB2AC391A888AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8AD266EE3873157FULL,
		0xB6C68FA6BCE321F5ULL,
		0x43E3BD4567F6EC7AULL,
		0x6BB4177D045723C8ULL,
		0x860FA14D2F17B446ULL,
		0x79BE703CED55B297ULL,
		0xFCF1E589A6516D1CULL,
		0xF3E168D26802B7D3ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 393\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 393 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -393;
	} else {
		printf("Test Case 393 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB8BCC715832BF6F3ULL,
		0x727374EAB63ADBF9ULL,
		0x429D7946F763F63EULL,
		0x709F31B1F357062AULL,
		0xAA5C0E75B1DD3D97ULL,
		0xBAF0D66F57E0FC70ULL,
		0x8C589720F09BD24BULL,
		0x5E9156130E0F2192ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x210AE3681BD90F94ULL,
		0x6022A6173153E09EULL,
		0x977AC1ECF48D0E0DULL,
		0x5F8B62D73F7CD4F8ULL,
		0x0DF74BA5BACBA72CULL,
		0xD5E742EBC9F2F0D9ULL,
		0x79F5AB81A9345D26ULL,
		0x1BCD0DAC63112EC4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x97B1E3AD6752E75FULL,
		0x1250CED384E6FB5BULL,
		0xAB22B75A02D6E831ULL,
		0x1113CEDAB3DA3131ULL,
		0x9C64C2CFF711966BULL,
		0xE50993838DEE0B97ULL,
		0x1262EB9F47677524ULL,
		0x42C44866AAFDF2CEULL
	}};
	sign = 0;
	printf("Test Case 394\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 394 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -394;
	} else {
		printf("Test Case 394 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9F92563A1A7F1E12ULL,
		0xA6B6AB45DDB10D88ULL,
		0x70DBEF87E9C104CCULL,
		0xCA0F77056F73BA41ULL,
		0xAFD98EE582892C7FULL,
		0xED2324378AA0E5E5ULL,
		0x0ADCAB158A75AEB7ULL,
		0x460596A4DCF70C70ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D39367A881AE52FULL,
		0xABAF7D9BBDAB253EULL,
		0x23315F64A3531439ULL,
		0x4712EF7943C17A23ULL,
		0xC1EBBEC6C9D6C467ULL,
		0xFDC33C97D1C5F1E2ULL,
		0x7D798AFB21A1171BULL,
		0x897016BED22D1D42ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x12591FBF926438E3ULL,
		0xFB072DAA2005E84AULL,
		0x4DAA9023466DF092ULL,
		0x82FC878C2BB2401EULL,
		0xEDEDD01EB8B26818ULL,
		0xEF5FE79FB8DAF402ULL,
		0x8D63201A68D4979BULL,
		0xBC957FE60AC9EF2DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 395\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 395 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -395;
	} else {
		printf("Test Case 395 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x712DB980B18A2333ULL,
		0x2BCFDB916A68A80EULL,
		0xA8249B65F69E65ADULL,
		0x4BC7BB80B1F8C8A4ULL,
		0xBAD409BCB3D94848ULL,
		0x88BD7FD7A49B50FAULL,
		0xADD1082612758E32ULL,
		0xAC143DB38D751C35ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C3178862A2E75A8ULL,
		0xD1A604684325437FULL,
		0xE5F37FBD3156E5C6ULL,
		0xB258EA8ACA61F4C9ULL,
		0x513723FFF4E30950ULL,
		0x9BD901706C5F8AB9ULL,
		0x5BB603C9C30553FEULL,
		0xBC19816F4F7F6AAFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x64FC40FA875BAD8BULL,
		0x5A29D7292743648FULL,
		0xC2311BA8C5477FE6ULL,
		0x996ED0F5E796D3DAULL,
		0x699CE5BCBEF63EF7ULL,
		0xECE47E67383BC641ULL,
		0x521B045C4F703A33ULL,
		0xEFFABC443DF5B186ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 396\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 396 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -396;
	} else {
		printf("Test Case 396 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x272D57AEF99F6BABULL,
		0xD3DB68B5573CC229ULL,
		0xBFA7EBC2B0C52C00ULL,
		0x75FD375952B5EE53ULL,
		0x96C6AB55634BC5F0ULL,
		0xF6D5844A5D4134CEULL,
		0x18B300BBC8C4151AULL,
		0x0A8A2797636F1B64ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4EBF51627E5360CULL,
		0xCBDCE4C3C57F70DBULL,
		0x87C17CA3AC23D0E5ULL,
		0xAECF119E12678CB8ULL,
		0x4D526AF90E8F9B4EULL,
		0x3027B97C2A5F0C99ULL,
		0x3C51B521B41F8B74ULL,
		0xD401201B70814355ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x42416298D1BA359FULL,
		0x07FE83F191BD514DULL,
		0x37E66F1F04A15B1BULL,
		0xC72E25BB404E619BULL,
		0x4974405C54BC2AA1ULL,
		0xC6ADCACE32E22835ULL,
		0xDC614B9A14A489A6ULL,
		0x3689077BF2EDD80EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 397\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 397 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -397;
	} else {
		printf("Test Case 397 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1F1F93EEA40E3AD6ULL,
		0x478390F1D2C37FA8ULL,
		0x36B93180C92278F4ULL,
		0x352E68A3B1FF58EEULL,
		0x56FB44C607956A88ULL,
		0x2B8336E519A70D54ULL,
		0x4500A6C80CCCB553ULL,
		0x41B658B286313060ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6444830B07B620A5ULL,
		0x792395DD0A8253B8ULL,
		0x3531D205A3429678ULL,
		0x878DA33F7F7C870CULL,
		0xFF6A0FD1D28FB5F8ULL,
		0xE393A9D36E13BB59ULL,
		0x1287D2D800EDE693ULL,
		0x183D68A6F07AFBC3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBADB10E39C581A31ULL,
		0xCE5FFB14C8412BEFULL,
		0x01875F7B25DFE27BULL,
		0xADA0C5643282D1E2ULL,
		0x579134F43505B48FULL,
		0x47EF8D11AB9351FAULL,
		0x3278D3F00BDECEBFULL,
		0x2978F00B95B6349DULL
	}};
	sign = 0;
	printf("Test Case 398\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 398 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -398;
	} else {
		printf("Test Case 398 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB0E58F02BB410098ULL,
		0xC40FB827026C0434ULL,
		0x233ECEB784604145ULL,
		0xE300DD440A989C16ULL,
		0xE567A805F20BE448ULL,
		0x4C3DCB8E14DA5E15ULL,
		0x81B038EDCD934472ULL,
		0xA2651C05182BB01FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x827A5F46FC05BE33ULL,
		0x9E2FBAE5EB64F166ULL,
		0x451444AB5AC0860CULL,
		0xCD71081C4FC64337ULL,
		0xB95DC2182BAC06CFULL,
		0xAD0AB32D5E221CACULL,
		0x540899FDFA49FFF0ULL,
		0x920C03E9417BF463ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2E6B2FBBBF3B4265ULL,
		0x25DFFD41170712CEULL,
		0xDE2A8A0C299FBB39ULL,
		0x158FD527BAD258DEULL,
		0x2C09E5EDC65FDD79ULL,
		0x9F331860B6B84169ULL,
		0x2DA79EEFD3494481ULL,
		0x1059181BD6AFBBBCULL
	}};
	sign = 0;
	printf("Test Case 399\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 399 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -399;
	} else {
		printf("Test Case 399 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xDEB3C391638F6F1FULL,
		0x7EB3B5F3278C4775ULL,
		0x04C9A4D43032AD42ULL,
		0xC693AADB63C27BEEULL,
		0xD6CB3BD965E4CA5FULL,
		0xF7D59E22423760BFULL,
		0x8521B29406ED8F8BULL,
		0xD6F7A51A5C12819DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D3E286FCB88A448ULL,
		0xF963777B88F86D55ULL,
		0x0B48D2BC0CEA76B3ULL,
		0x7EC3AFEAEE9A8475ULL,
		0x443161DA4DE8586AULL,
		0x713BE454F7122F2AULL,
		0x99C8FDA648A53A10ULL,
		0x976D7D541CEEDC45ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x91759B219806CAD7ULL,
		0x85503E779E93DA20ULL,
		0xF980D2182348368EULL,
		0x47CFFAF07527F778ULL,
		0x9299D9FF17FC71F5ULL,
		0x8699B9CD4B253195ULL,
		0xEB58B4EDBE48557BULL,
		0x3F8A27C63F23A557ULL
	}};
	sign = 0;
	printf("Test Case 400\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 400 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -400;
	} else {
		printf("Test Case 400 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6A612565EA38447CULL,
		0x899581CAA31A73F8ULL,
		0xE2368114DFDD0AEEULL,
		0x7719AFD000A580DCULL,
		0x95314D83C0291ECAULL,
		0x50C867F2BDFC1EDBULL,
		0x3A922D292CBFEFBAULL,
		0x93AAC55BA90B188FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x78E600F1155915E3ULL,
		0x806FF6F17329BCD8ULL,
		0x3FF5FBE06A8922E9ULL,
		0xF948C9568E939042ULL,
		0x1680362018F2469DULL,
		0xF24BEE2777C707AEULL,
		0x00D22D39156ECFBDULL,
		0x7C66D519D79DC6E2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF17B2474D4DF2E99ULL,
		0x09258AD92FF0B71FULL,
		0xA24085347553E805ULL,
		0x7DD0E6797211F09AULL,
		0x7EB11763A736D82CULL,
		0x5E7C79CB4635172DULL,
		0x39BFFFF017511FFCULL,
		0x1743F041D16D51ADULL
	}};
	sign = 0;
	printf("Test Case 401\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 401 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -401;
	} else {
		printf("Test Case 401 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x2033A148A60B4D92ULL,
		0xB87DD7AF56BDB82BULL,
		0x22A996DBEBAF3DA3ULL,
		0xCF31B96069EB3468ULL,
		0x67A49F6D135DB7FDULL,
		0x988E0AE1CAF9C877ULL,
		0x103F2E0CFE227462ULL,
		0xD8416CC9012938FEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF9B3BD818E5C3C3ULL,
		0x8B48C878C550AAC2ULL,
		0x0F7A61B7DD429991ULL,
		0x71364BC432120DBBULL,
		0xA0ADCED4443791AAULL,
		0x7C63A3B54C958007ULL,
		0xC61CF2D5AE049857ULL,
		0xEE8A51EAC353E920ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x209865708D2589CFULL,
		0x2D350F36916D0D68ULL,
		0x132F35240E6CA412ULL,
		0x5DFB6D9C37D926ADULL,
		0xC6F6D098CF262653ULL,
		0x1C2A672C7E64486FULL,
		0x4A223B37501DDC0BULL,
		0xE9B71ADE3DD54FDDULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 402\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 402 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -402;
	} else {
		printf("Test Case 402 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF6441A29E79A738FULL,
		0x1782D47378006442ULL,
		0x3F613930BE9DEF84ULL,
		0x19422B3340C190ADULL,
		0x706E511D5BA3A6E9ULL,
		0x1A5362395DE0E47BULL,
		0x600A96C0178B4452ULL,
		0x548D8ADC6893771CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x67E1DCD759768E57ULL,
		0xB898E422824D3B9AULL,
		0x8675C26E25B6AE71ULL,
		0x063F8F980B987A22ULL,
		0x7D382A6DC27AD2FEULL,
		0x330DF76257FB9637ULL,
		0x8C7EACE571462AA8ULL,
		0xFDCDDB7497C69AAEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8E623D528E23E538ULL,
		0x5EE9F050F5B328A8ULL,
		0xB8EB76C298E74112ULL,
		0x13029B9B3529168AULL,
		0xF33626AF9928D3EBULL,
		0xE7456AD705E54E43ULL,
		0xD38BE9DAA64519A9ULL,
		0x56BFAF67D0CCDC6DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 403\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 403 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -403;
	} else {
		printf("Test Case 403 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE69B8DEDB19073ADULL,
		0xA154ABA7F686F71CULL,
		0x96135A7400A2E029ULL,
		0x08E371F290E4CA56ULL,
		0x13540FD61D30963CULL,
		0x2732767E87C0B09BULL,
		0x0EE0D8899C17268DULL,
		0xD37549E51120AAA7ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DE1DE6B89CD9066ULL,
		0x141D78639F9A969EULL,
		0xDBE61A7DE4749D6EULL,
		0x41590086BD1ADD08ULL,
		0xE0DC644240B2BAC9ULL,
		0x67D64FFC2CBE9EF4ULL,
		0x98CEC1F729F716F7ULL,
		0xFB581B759FACAC6BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD8B9AF8227C2E347ULL,
		0x8D37334456EC607EULL,
		0xBA2D3FF61C2E42BBULL,
		0xC78A716BD3C9ED4DULL,
		0x3277AB93DC7DDB72ULL,
		0xBF5C26825B0211A6ULL,
		0x7612169272200F95ULL,
		0xD81D2E6F7173FE3BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 404\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 404 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -404;
	} else {
		printf("Test Case 404 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x07087373F951522DULL,
		0xBB77FEAB00A7907BULL,
		0xC3C87D8C74C45220ULL,
		0xA21E920875233535ULL,
		0x06D70F2B060C5854ULL,
		0xBF56152ACC9A0CACULL,
		0xE1A2882876A9E08FULL,
		0x68C954FE10D458C0ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x35DA2880264E24E0ULL,
		0xBBD8A18839142818ULL,
		0xA0456D510BEDFD50ULL,
		0xA0CFBF843AA6BD91ULL,
		0xC1CDC3C421CD0D6AULL,
		0xE46D9879B8C33FA9ULL,
		0x0AD06F9315160452ULL,
		0x082A07077CCF705DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD12E4AF3D3032D4DULL,
		0xFF9F5D22C7936862ULL,
		0x2383103B68D654CFULL,
		0x014ED2843A7C77A4ULL,
		0x45094B66E43F4AEAULL,
		0xDAE87CB113D6CD02ULL,
		0xD6D218956193DC3CULL,
		0x609F4DF69404E863ULL
	}};
	sign = 0;
	printf("Test Case 405\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 405 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -405;
	} else {
		printf("Test Case 405 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4642CD02FFBD5368ULL,
		0x8CB92882AA9E95ADULL,
		0xAB9FD042276E50E8ULL,
		0x89D6A9CE16FA9BF6ULL,
		0xF0794FB879D1F0EBULL,
		0x5D8B9BD93E94B64CULL,
		0x221E3795684F44BDULL,
		0xA803BEEC011828E2ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0886826B05D8785ULL,
		0xE106132BB78AE89BULL,
		0xE2DD2461F358F5EAULL,
		0xE5C129F63DCA3740ULL,
		0xC04126C41FEBBEE7ULL,
		0x9A1AA9A602A6757DULL,
		0x95852BDB66B9FDE7ULL,
		0xF16C4D279F38182DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA5BA64DC4F5FCBE3ULL,
		0xABB31556F313AD11ULL,
		0xC8C2ABE034155AFDULL,
		0xA4157FD7D93064B5ULL,
		0x303828F459E63203ULL,
		0xC370F2333BEE40CFULL,
		0x8C990BBA019546D5ULL,
		0xB69771C461E010B4ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 406\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 406 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -406;
	} else {
		printf("Test Case 406 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x362482E58573A2B9ULL,
		0xD82BC159045D51C4ULL,
		0x965FB989C2E5DF70ULL,
		0x5121039E7ED18EC3ULL,
		0xF310F48AA166C937ULL,
		0xF54F9D07E0AA103EULL,
		0x424E5161241DF2B4ULL,
		0x84778C5735FA5722ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x694F7EAAD58A5733ULL,
		0x6AD8D3196A6351CEULL,
		0xFFA981D82789FFEAULL,
		0x61E592ED75371A8BULL,
		0x0CA2D9B77909DC81ULL,
		0xBE18148CFFC33AE6ULL,
		0x3CBCCD68D8E00C4DULL,
		0x7F71A8D9293351B5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCCD5043AAFE94B86ULL,
		0x6D52EE3F99F9FFF5ULL,
		0x96B637B19B5BDF86ULL,
		0xEF3B70B1099A7437ULL,
		0xE66E1AD3285CECB5ULL,
		0x3737887AE0E6D558ULL,
		0x059183F84B3DE667ULL,
		0x0505E37E0CC7056DULL
	}};
	sign = 0;
	printf("Test Case 407\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 407 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -407;
	} else {
		printf("Test Case 407 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xEC02B3FE250F5777ULL,
		0x1D8BB50E286955BCULL,
		0x98D3AFA1BE3ED26EULL,
		0x7AAB1232F10506A7ULL,
		0x727DAC5C63DDCBF8ULL,
		0xBEC7B11A031D6DD7ULL,
		0x610C32F45AFB1EA9ULL,
		0xF6D57B08EE1E4D2DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x97946A557D1049C6ULL,
		0x389348CCA3388D71ULL,
		0xEEBCA41DAF0F3A96ULL,
		0x82FDC7DA78A06248ULL,
		0xBA9662ECE8CD0DB8ULL,
		0x3D2822B90EA7FD68ULL,
		0x0A9F8FB5C3436864ULL,
		0xD0206D4600D0FF4DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x546E49A8A7FF0DB1ULL,
		0xE4F86C418530C84BULL,
		0xAA170B840F2F97D7ULL,
		0xF7AD4A587864A45EULL,
		0xB7E7496F7B10BE3FULL,
		0x819F8E60F475706EULL,
		0x566CA33E97B7B645ULL,
		0x26B50DC2ED4D4DE0ULL
	}};
	sign = 0;
	printf("Test Case 408\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 408 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -408;
	} else {
		printf("Test Case 408 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC4890E15BA610C13ULL,
		0xF05A82563223C7B3ULL,
		0xE7220C3A6E36FF96ULL,
		0x90C4B6700B52EC6BULL,
		0xF5CD2067802AA7CEULL,
		0x1B273493759648D7ULL,
		0xC35EB6CEABBDE594ULL,
		0x0AE5BF8731A4E75CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8986BE445BA9171ULL,
		0xE5872499CEAFBCD9ULL,
		0x57274D19E6B0AD96ULL,
		0xD2818FFC5A273DD2ULL,
		0x39D841E4CD532CA9ULL,
		0x7F36CA3E6446BAF1ULL,
		0x3CA0D4A279E65D43ULL,
		0x60AD046E270D3B63ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCBF0A23174A67AA2ULL,
		0x0AD35DBC63740AD9ULL,
		0x8FFABF2087865200ULL,
		0xBE432673B12BAE99ULL,
		0xBBF4DE82B2D77B24ULL,
		0x9BF06A55114F8DE6ULL,
		0x86BDE22C31D78850ULL,
		0xAA38BB190A97ABF9ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 409\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 409 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -409;
	} else {
		printf("Test Case 409 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC01217FACFBA2EC8ULL,
		0x6C70D04C178FF4C8ULL,
		0x840529E3827ED9BEULL,
		0xEB7C058F9AE5C4C9ULL,
		0xB4E1494E28ADA8FAULL,
		0x6B75C4695893A971ULL,
		0x62181D5A7986962AULL,
		0xF2E045884E927439ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0B2FF127403A269ULL,
		0x148A6B2912527EF8ULL,
		0x2965D11988E184FFULL,
		0xCDF34F4DEFDE91C6ULL,
		0x827A713A9BAB6599ULL,
		0x9D006D5E24DEAD70ULL,
		0x7BFED9C3BEE19C03ULL,
		0x6AB1CB3747706DE7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1F5F18E85BB68C5FULL,
		0x57E66523053D75D0ULL,
		0x5A9F58C9F99D54BFULL,
		0x1D88B641AB073303ULL,
		0x3266D8138D024361ULL,
		0xCE75570B33B4FC01ULL,
		0xE6194396BAA4FA26ULL,
		0x882E7A5107220651ULL
	}};
	sign = 0;
	printf("Test Case 410\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 410 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -410;
	} else {
		printf("Test Case 410 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD4A7D09467D4973BULL,
		0xDF5692398AB3BE2EULL,
		0xA8FFA584972EBDF4ULL,
		0x32CB65ADECDE9E01ULL,
		0x511D9995E53819A4ULL,
		0xC6A965FE5502C0BBULL,
		0x04BF932F289A9B40ULL,
		0x9D0C2C4EEF37F429ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E2410E788976A86ULL,
		0x73AB34AE3179582DULL,
		0xF1F7C7ECC14C7E20ULL,
		0x2F36E6AB8D370FC3ULL,
		0xAC16F47BB5CABE3FULL,
		0x218B14D2E6B406CBULL,
		0x0F16EFADA3393C92ULL,
		0x232ABC6D8A2785AFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5683BFACDF3D2CB5ULL,
		0x6BAB5D8B593A6601ULL,
		0xB707DD97D5E23FD4ULL,
		0x03947F025FA78E3DULL,
		0xA506A51A2F6D5B65ULL,
		0xA51E512B6E4EB9EFULL,
		0xF5A8A38185615EAEULL,
		0x79E16FE165106E79ULL
	}};
	sign = 0;
	printf("Test Case 411\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 411 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -411;
	} else {
		printf("Test Case 411 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC28B3ECBA5D28457ULL,
		0xACC8750BD848B2FFULL,
		0x1DBED16149F6D021ULL,
		0x523AF48261175A10ULL,
		0xC4E17BDFFB750EAFULL,
		0xFF4DABDD292DE7BBULL,
		0x5803746EA2F924F2ULL,
		0xB9851E3CD90376E4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DFA72ED54FDEB46ULL,
		0x7836B42CAE8643E3ULL,
		0xADC9281C627F52EDULL,
		0x3FDBEBEF3132484CULL,
		0xA07FF34C0DD43B1CULL,
		0x489E2235584BDF78ULL,
		0xB143AD85A0353FD8ULL,
		0x76354B53A1719E0EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8490CBDE50D49911ULL,
		0x3491C0DF29C26F1CULL,
		0x6FF5A944E7777D34ULL,
		0x125F08932FE511C3ULL,
		0x24618893EDA0D393ULL,
		0xB6AF89A7D0E20843ULL,
		0xA6BFC6E902C3E51AULL,
		0x434FD2E93791D8D5ULL
	}};
	sign = 0;
	printf("Test Case 412\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 412 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -412;
	} else {
		printf("Test Case 412 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x59675DB093BE561DULL,
		0xFFE310E9FC7663C2ULL,
		0x543C70110CC28219ULL,
		0xF9D414708A01AC1FULL,
		0x05B1976089EB079AULL,
		0xBDFE10A3CBF8F2E3ULL,
		0x471F0F01D39C8647ULL,
		0x46E15D03BABB2AD9ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB477960BBFA9FDACULL,
		0xCEB0D10450ED296CULL,
		0x0DC646B79F635E25ULL,
		0xC48608ED25BED14EULL,
		0x10A7FD96B28B1A85ULL,
		0xB30D5BA829E77256ULL,
		0xB6A2387D609F8C21ULL,
		0x96171DFD952F4770ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA4EFC7A4D4145871ULL,
		0x31323FE5AB893A55ULL,
		0x467629596D5F23F4ULL,
		0x354E0B836442DAD1ULL,
		0xF50999C9D75FED15ULL,
		0x0AF0B4FBA211808CULL,
		0x907CD68472FCFA26ULL,
		0xB0CA3F06258BE368ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 413\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 413 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -413;
	} else {
		printf("Test Case 413 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x69CC363CC365D63FULL,
		0x157456AF098209D3ULL,
		0x8317A10C49FA36C2ULL,
		0xC1C0ABBF31FCF9BFULL,
		0xF22E10A7B19DF55CULL,
		0xBF23589A423ED810ULL,
		0xDB2A85DEE9F755CDULL,
		0xEC894D973B618BAAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA11CCAA56F5CC69ULL,
		0x11C20136372B0CBDULL,
		0x0CC808A3132900E2ULL,
		0x0475B172D2A9EB0FULL,
		0x77D1DD9DD0393C75ULL,
		0x2B510682FDAB4781ULL,
		0x58BC2A965B012547ULL,
		0x57DAF11EC4BC75BEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9FBA69926C7009D6ULL,
		0x03B25578D256FD15ULL,
		0x764F986936D135E0ULL,
		0xBD4AFA4C5F530EB0ULL,
		0x7A5C3309E164B8E7ULL,
		0x93D252174493908FULL,
		0x826E5B488EF63086ULL,
		0x94AE5C7876A515ECULL
	}};
	sign = 0;
	printf("Test Case 414\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 414 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -414;
	} else {
		printf("Test Case 414 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x80F63EA71A2D0356ULL,
		0x300DD501933A6473ULL,
		0x9AF7D8B2262D97E8ULL,
		0x6DBE4C4E8A0237BBULL,
		0xD02C7DAD8026968BULL,
		0x98530662903425EFULL,
		0x63BE64129457C30DULL,
		0x6BA861153E07B3DBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1373EADABD28266ULL,
		0xED12940A765D3E52ULL,
		0x2A88E9F027AF47EDULL,
		0x2D8685EB93511F8DULL,
		0x0842B79ECBCEDE85ULL,
		0xA2BCD3B36B852F78ULL,
		0xFD17063064AD4502ULL,
		0x2C9604C0C6C8EFD3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAFBEFFF96E5A80F0ULL,
		0x42FB40F71CDD2620ULL,
		0x706EEEC1FE7E4FFAULL,
		0x4037C662F6B1182EULL,
		0xC7E9C60EB457B806ULL,
		0xF59632AF24AEF677ULL,
		0x66A75DE22FAA7E0AULL,
		0x3F125C54773EC407ULL
	}};
	sign = 0;
	printf("Test Case 415\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 415 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -415;
	} else {
		printf("Test Case 415 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB8B0C04766ED49ECULL,
		0x5C1C058589F4963AULL,
		0x1D371B1E545F4C49ULL,
		0xBF589CB0D6D438B2ULL,
		0x5FA458010ADA1554ULL,
		0x6372960E37516DD6ULL,
		0x76B7A8A7BD9771E3ULL,
		0xC144F1858111FD6AULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FE43FF64AC302DBULL,
		0x08CC2E745055E283ULL,
		0xA4B266A1CF3C7991ULL,
		0x34EF3F10473A90A5ULL,
		0x9FFAF8EAE848C9F9ULL,
		0x136160708AAC18C8ULL,
		0x498BA8D4E764F0C0ULL,
		0x8C3BA28EEE7144FCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x68CC80511C2A4711ULL,
		0x534FD711399EB3B7ULL,
		0x7884B47C8522D2B8ULL,
		0x8A695DA08F99A80CULL,
		0xBFA95F1622914B5BULL,
		0x5011359DACA5550DULL,
		0x2D2BFFD2D6328123ULL,
		0x35094EF692A0B86EULL
	}};
	sign = 0;
	printf("Test Case 416\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 416 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -416;
	} else {
		printf("Test Case 416 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x721BEFE4CA660605ULL,
		0x47AF7D327AE9B1ACULL,
		0xF291F49614232DD6ULL,
		0xE42DC0555E13BDCBULL,
		0x6794AC5BDE174AF1ULL,
		0xCFC1AB91EE4D7670ULL,
		0x5FD47A5A8F6962BFULL,
		0x5024C0E81ABEE31FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x416D964A51B826AFULL,
		0x1435B23A490A1AF3ULL,
		0xAF863ACCCF3AA62EULL,
		0xFC205539D422C4BEULL,
		0x8292624B911BDEF3ULL,
		0xF07AE914D7A1F69BULL,
		0xA068A8E2A17D9776ULL,
		0xD9BAC57108BBACD6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x30AE599A78ADDF56ULL,
		0x3379CAF831DF96B9ULL,
		0x430BB9C944E887A8ULL,
		0xE80D6B1B89F0F90DULL,
		0xE5024A104CFB6BFDULL,
		0xDF46C27D16AB7FD4ULL,
		0xBF6BD177EDEBCB48ULL,
		0x7669FB7712033648ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 417\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 417 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -417;
	} else {
		printf("Test Case 417 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x33A51C5E5CB2999DULL,
		0x40703CCF9B30A294ULL,
		0x7F4BDBF93015765CULL,
		0x680AE3193A128A4FULL,
		0x485A720ECE9284DAULL,
		0x7D4EE4ED5B600FD5ULL,
		0x6E352D917C6590FEULL,
		0x65300F0EF91A004FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4F7240764B93673ULL,
		0x09AA4FA761374B9BULL,
		0x61232F63F5074D13ULL,
		0xF08BAEB454B5FBE2ULL,
		0x9A079A170576B22BULL,
		0x2FD666B3B3A5F8C6ULL,
		0xDE8B23C7417B1669ULL,
		0xBC57B750FC8C9CDDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5EADF856F7F9632AULL,
		0x36C5ED2839F956F8ULL,
		0x1E28AC953B0E2949ULL,
		0x777F3464E55C8E6DULL,
		0xAE52D7F7C91BD2AEULL,
		0x4D787E39A7BA170EULL,
		0x8FAA09CA3AEA7A95ULL,
		0xA8D857BDFC8D6371ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 418\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 418 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -418;
	} else {
		printf("Test Case 418 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xCECABC8B461A634BULL,
		0x8BAFEA96BD49D98BULL,
		0x6042851E76FF95E8ULL,
		0x26B411AABD72BCC5ULL,
		0x131ADF48BCECEB9BULL,
		0xD4B668270E44966AULL,
		0x823512230A3DC69EULL,
		0x0D0C1CB8D203EBBBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EAA51C5926844E3ULL,
		0x6D0DE41D002BD0B8ULL,
		0xCA2DFB8F5BC7C011ULL,
		0x4B6BADF2B180363EULL,
		0x4FF5E364E0E151EAULL,
		0x1C8CF4529DE39203ULL,
		0x23CE8E95A1659AADULL,
		0x683EBB4658B332E4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x80206AC5B3B21E68ULL,
		0x1EA20679BD1E08D3ULL,
		0x9614898F1B37D5D7ULL,
		0xDB4863B80BF28686ULL,
		0xC324FBE3DC0B99B0ULL,
		0xB82973D470610466ULL,
		0x5E66838D68D82BF1ULL,
		0xA4CD61727950B8D7ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 419\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 419 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -419;
	} else {
		printf("Test Case 419 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB3D0109A87C120FCULL,
		0x56ECC88453D15B32ULL,
		0x826AA225E92DD55CULL,
		0x0B20E2692BF13C09ULL,
		0xD6E65E9848DE2F8BULL,
		0xA0A7B595A5202E89ULL,
		0xEC70CB3E08CD599CULL,
		0xE3EE89A2A333BA97ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA176997C9008F87AULL,
		0x55CEE8B0FC62EBB4ULL,
		0x8DBAC303067D774CULL,
		0x6845C48CBF5111F7ULL,
		0x90718DEF7DBA2A46ULL,
		0x2D49CA7F9CCA571EULL,
		0x28C3FA39F4479428ULL,
		0x1081C075904C6FE0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1259771DF7B82882ULL,
		0x011DDFD3576E6F7EULL,
		0xF4AFDF22E2B05E10ULL,
		0xA2DB1DDC6CA02A11ULL,
		0x4674D0A8CB240544ULL,
		0x735DEB160855D76BULL,
		0xC3ACD1041485C574ULL,
		0xD36CC92D12E74AB7ULL
	}};
	sign = 0;
	printf("Test Case 420\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 420 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -420;
	} else {
		printf("Test Case 420 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x64D7AF873BFCF107ULL,
		0x3273469FC8E0D9B5ULL,
		0x44856FA8FE1BCC87ULL,
		0x29ACD38EBB7692E4ULL,
		0x6D5F83318CF80E7EULL,
		0x1D7657DC92E78E25ULL,
		0xEA46BF85B44BA3B1ULL,
		0x2666D02145AA0338ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE2C193B140FE6FCULL,
		0x8DAA291A722E2FAFULL,
		0x5A10847AD27B39C8ULL,
		0x5A7856EA6441F000ULL,
		0x67CF2B72109CB8BDULL,
		0xC5C2647E5EC0813EULL,
		0x6000D1B1F51448EDULL,
		0xEB3797371F47B2ABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB6AB964C27ED0A0BULL,
		0xA4C91D8556B2AA05ULL,
		0xEA74EB2E2BA092BEULL,
		0xCF347CA45734A2E3ULL,
		0x059057BF7C5B55C0ULL,
		0x57B3F35E34270CE7ULL,
		0x8A45EDD3BF375AC3ULL,
		0x3B2F38EA2662508DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 421\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 421 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -421;
	} else {
		printf("Test Case 421 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xFDDC86E460B4AB0BULL,
		0x710E5EBE34AB615EULL,
		0x9579DDF586CB365CULL,
		0x13F7530D2E2EB90DULL,
		0xC928A66088F4328DULL,
		0x18EE499B9B0CA6F4ULL,
		0xB48568700E5E7F18ULL,
		0xFF10C4A8031BD0DDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBC27E4274A01E09ULL,
		0x9F6B92D004B556DBULL,
		0x2FA7386B8FB78A79ULL,
		0xBA594D9928FE1E49ULL,
		0x97C907EAF464B948ULL,
		0x1838F3E98589C1B7ULL,
		0xDDC52D3D679DDB88ULL,
		0x9FFC37530F22BFA2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x121A08A1EC148D02ULL,
		0xD1A2CBEE2FF60A83ULL,
		0x65D2A589F713ABE2ULL,
		0x599E057405309AC4ULL,
		0x315F9E75948F7944ULL,
		0x00B555B21582E53DULL,
		0xD6C03B32A6C0A390ULL,
		0x5F148D54F3F9113AULL
	}};
	sign = 0;
	printf("Test Case 422\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 422 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -422;
	} else {
		printf("Test Case 422 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x886BC4F62D8EB941ULL,
		0x9A93607D1D7EB9F1ULL,
		0xC91B8B63B449BB09ULL,
		0x8B45C7F61FF4F7B4ULL,
		0x2C3642E73364B792ULL,
		0x8A42E707B25BFF29ULL,
		0xB3DAB3D2C8DA93EAULL,
		0xF5F2C91752F549ACULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x855A412F3A958403ULL,
		0x6CAD8E49F8B2C281ULL,
		0xA5D3445CE74BD625ULL,
		0xAF807506BF55CAF7ULL,
		0xF9AA8F74A7D5D670ULL,
		0xA864EC7F8C904256ULL,
		0x2AE0AB25813B2BCBULL,
		0x78BF2B7C15C59345ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x031183C6F2F9353EULL,
		0x2DE5D23324CBF770ULL,
		0x23484706CCFDE4E4ULL,
		0xDBC552EF609F2CBDULL,
		0x328BB3728B8EE121ULL,
		0xE1DDFA8825CBBCD2ULL,
		0x88FA08AD479F681EULL,
		0x7D339D9B3D2FB667ULL
	}};
	sign = 0;
	printf("Test Case 423\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 423 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -423;
	} else {
		printf("Test Case 423 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC0184BDA1482E096ULL,
		0x6928402F4AB1A1D7ULL,
		0x7195DBD4EDCC2A1AULL,
		0xD96E87FE693FCAFEULL,
		0x7680A9C274671318ULL,
		0x37890B1A1546F74BULL,
		0x57817DC39C729040ULL,
		0x8D503D04649A0E1FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3090DDB94647DAEULL,
		0x774BB99278F5EA2EULL,
		0x730CBD0C8EDEDE99ULL,
		0x1CD43EB762662660ULL,
		0xCE9DBD54558573CAULL,
		0x116C693C24646397ULL,
		0x81FCD03634E307F7ULL,
		0xBA132E9D20AA9E0FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xED0F3DFE801E62E8ULL,
		0xF1DC869CD1BBB7A8ULL,
		0xFE891EC85EED4B80ULL,
		0xBC9A494706D9A49DULL,
		0xA7E2EC6E1EE19F4EULL,
		0x261CA1DDF0E293B3ULL,
		0xD584AD8D678F8849ULL,
		0xD33D0E6743EF700FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 424\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 424 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -424;
	} else {
		printf("Test Case 424 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA8BB77F15C78F89DULL,
		0x221631213E39E6AEULL,
		0xA8CFBBF770082B5CULL,
		0x94EFB9AE4F4D6C52ULL,
		0x7940835E586FB362ULL,
		0x1D53002895CB8111ULL,
		0xC4D4C60F5CEEFD39ULL,
		0x7757F0F8245D4426ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB28CA8F264DA00FULL,
		0xAD5F911AD357CE41ULL,
		0xF2E83048F1340C2CULL,
		0x93B0A631A8876EF1ULL,
		0x00623F2AA776CEA5ULL,
		0x5C2DF7E3721791C7ULL,
		0x2E12E2F9DF510502ULL,
		0xCB9450D218D14D4DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAD92AD62362B588EULL,
		0x74B6A0066AE2186CULL,
		0xB5E78BAE7ED41F2FULL,
		0x013F137CA6C5FD60ULL,
		0x78DE4433B0F8E4BDULL,
		0xC125084523B3EF4AULL,
		0x96C1E3157D9DF836ULL,
		0xABC3A0260B8BF6D9ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 425\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 425 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -425;
	} else {
		printf("Test Case 425 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA27240D718D63352ULL,
		0x5D894C3191812459ULL,
		0x7A6AF8DA8B44C34AULL,
		0x7D22FB987B3E7F71ULL,
		0x631B11FC08572171ULL,
		0x620FCB0E7484DFFFULL,
		0xCC2D348888A6527AULL,
		0xDC9ABECCF68AD05FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x71C6AAAAC893CB75ULL,
		0xC608F65FE96A7F81ULL,
		0x41367584526A9D7AULL,
		0x931A0E58C37FE4A3ULL,
		0x36CDD3AE11496DB8ULL,
		0x242E04899EF688F6ULL,
		0xC981BF35553EB9AFULL,
		0xA1B34AB96B556F81ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x30AB962C504267DDULL,
		0x978055D1A816A4D8ULL,
		0x3934835638DA25CFULL,
		0xEA08ED3FB7BE9ACEULL,
		0x2C4D3E4DF70DB3B8ULL,
		0x3DE1C684D58E5709ULL,
		0x02AB7553336798CBULL,
		0x3AE774138B3560DEULL
	}};
	sign = 0;
	printf("Test Case 426\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 426 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -426;
	} else {
		printf("Test Case 426 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC25DE474BB4AD3C1ULL,
		0x8D3DD9476D09971CULL,
		0x6A2472657BF52443ULL,
		0x9BF1384A1E96EF99ULL,
		0xD84212A73A7B31E7ULL,
		0x092ECAC406F96953ULL,
		0xA1980B52E946D4DAULL,
		0x344221EC65263E37ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7EF39EFD86A6A874ULL,
		0x93120B45EA824BCFULL,
		0x1493757BCE98030DULL,
		0x57F2EB68FC256086ULL,
		0x7C5E06F58F53DE51ULL,
		0x7B8F5F49B2E435B1ULL,
		0x9BBA905E800F4422ULL,
		0xB6385A3F7889A458ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x436A457734A42B4DULL,
		0xFA2BCE0182874B4DULL,
		0x5590FCE9AD5D2135ULL,
		0x43FE4CE122718F13ULL,
		0x5BE40BB1AB275396ULL,
		0x8D9F6B7A541533A2ULL,
		0x05DD7AF4693790B7ULL,
		0x7E09C7ACEC9C99DFULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 427\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 427 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -427;
	} else {
		printf("Test Case 427 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7E9D4B4B0327BB18ULL,
		0x7979C905FDFFB517ULL,
		0x9F3D3F3B23D79D1EULL,
		0xD88ACB6FD624F578ULL,
		0x8420A758844449FCULL,
		0xC46948493EC14925ULL,
		0xCE3E4FA63269C3BCULL,
		0x9A8CECCC35AAF585ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C55901AE1554F1AULL,
		0x076F61A04FE18560ULL,
		0x2F50426F95D6A4F5ULL,
		0x9668CF679EF854AEULL,
		0x87F95BFE12F15DC8ULL,
		0x7A24396E1727C810ULL,
		0xFE35B1D9D6D46078ULL,
		0x2CA3CE067BD7D8E4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5247BB3021D26BFEULL,
		0x720A6765AE1E2FB7ULL,
		0x6FECFCCB8E00F829ULL,
		0x4221FC08372CA0CAULL,
		0xFC274B5A7152EC34ULL,
		0x4A450EDB27998114ULL,
		0xD0089DCC5B956344ULL,
		0x6DE91EC5B9D31CA0ULL
	}};
	sign = 0;
	printf("Test Case 428\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 428 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -428;
	} else {
		printf("Test Case 428 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6C69E0104ABB5437ULL,
		0x5080E19BA6427696ULL,
		0x3A668380DEE91641ULL,
		0x4EC5D6E182FE3FA5ULL,
		0xBB95B593C6645F32ULL,
		0xEA4C927783B84127ULL,
		0xE925DE67B53AB421ULL,
		0xF0D7D2E024A3F9EAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CABB62DDFE6C99EULL,
		0xE1AAFAD2A21EE243ULL,
		0x3664621EB7B2D5AFULL,
		0x8EE54F05D8DBC894ULL,
		0xA10096DC8B156BB5ULL,
		0x4155E0E1A7735DC0ULL,
		0xC97DA404E56FB9E4ULL,
		0x79267BD2CE56B6EAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDFBE29E26AD48A99ULL,
		0x6ED5E6C904239452ULL,
		0x0402216227364091ULL,
		0xBFE087DBAA227711ULL,
		0x1A951EB73B4EF37CULL,
		0xA8F6B195DC44E367ULL,
		0x1FA83A62CFCAFA3DULL,
		0x77B1570D564D4300ULL
	}};
	sign = 0;
	printf("Test Case 429\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 429 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -429;
	} else {
		printf("Test Case 429 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x8698B9FA3E6133CBULL,
		0x97208000CB7B35B7ULL,
		0x8EB03113F2E367F4ULL,
		0x3DC7915A0D730294ULL,
		0xDA6AA5303E87F756ULL,
		0x39C7F56EE9052AA0ULL,
		0x65320D678DE39145ULL,
		0xCCF4314F1E4E6E09ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x807693CD311C2CFDULL,
		0xB4F5C644B8C8F1AFULL,
		0x8BAF1414F6E3D6DCULL,
		0x7A300CC723909980ULL,
		0xBA00FD9F750BC203ULL,
		0xD971D8EA52C9F57EULL,
		0x9180DBE03E5D7789ULL,
		0xB91D5C1A05F1A3DCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0622262D0D4506CEULL,
		0xE22AB9BC12B24408ULL,
		0x03011CFEFBFF9117ULL,
		0xC3978492E9E26914ULL,
		0x2069A790C97C3552ULL,
		0x60561C84963B3522ULL,
		0xD3B131874F8619BBULL,
		0x13D6D535185CCA2CULL
	}};
	sign = 0;
	printf("Test Case 430\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 430 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -430;
	} else {
		printf("Test Case 430 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC13D3082002E2AE8ULL,
		0x40FD3B397C767A25ULL,
		0xD5D131C8407DD24BULL,
		0x8E980A29F6DF9DA8ULL,
		0x04B142E762F6387AULL,
		0xEAF6AB92DC1D24FAULL,
		0x7BB476E418260916ULL,
		0x0FF65FB978D54B5EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB28B78CFE5EE8C0ULL,
		0x44BDE8FFE1A5F02CULL,
		0xE9648F694D2740D7ULL,
		0x9EB78B7381E7F53FULL,
		0x90FE903ECA072FFDULL,
		0x9AF2D7310D84242DULL,
		0xB4DB1BA3F14D1A17ULL,
		0x252415B3772C088BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x061478F501CF4228ULL,
		0xFC3F52399AD089F9ULL,
		0xEC6CA25EF3569173ULL,
		0xEFE07EB674F7A868ULL,
		0x73B2B2A898EF087CULL,
		0x5003D461CE9900CCULL,
		0xC6D95B4026D8EEFFULL,
		0xEAD24A0601A942D2ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 431\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 431 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -431;
	} else {
		printf("Test Case 431 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD9A451A4A4FFA37FULL,
		0x27995FDC08B27F65ULL,
		0x7238D7AEFD896FC3ULL,
		0xDD6FF138F05FD3FFULL,
		0x8F9AE052E889E7C6ULL,
		0x755866853F648FC5ULL,
		0xEF808563F1FBE193ULL,
		0xEA42002214B349F6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8799577817D50F7BULL,
		0xD79CB4AF0DAFC8C7ULL,
		0xBE8FC2F1A96BA910ULL,
		0x9179FECFF7396688ULL,
		0x8856238BB311EA30ULL,
		0xAF3768AC90671963ULL,
		0x9B00C1303B1E8F16ULL,
		0xD8F4FC482F2341BDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x520AFA2C8D2A9404ULL,
		0x4FFCAB2CFB02B69EULL,
		0xB3A914BD541DC6B2ULL,
		0x4BF5F268F9266D76ULL,
		0x0744BCC73577FD96ULL,
		0xC620FDD8AEFD7662ULL,
		0x547FC433B6DD527CULL,
		0x114D03D9E5900839ULL
	}};
	sign = 0;
	printf("Test Case 432\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 432 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -432;
	} else {
		printf("Test Case 432 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF8674B420CC67247ULL,
		0xE5D0EDAD9D53C97EULL,
		0x51F450145D702C74ULL,
		0x624F9E92487924ABULL,
		0x98990706A371AACAULL,
		0xFDF1D79BEC7BC9F2ULL,
		0x1E488DD800EF56ABULL,
		0x3E5DB537901DA2FFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD325EE1510FE16EULL,
		0x67DBDFF9AD4CF7C0ULL,
		0x44945E1E4CC5354EULL,
		0x3BCA074F08A3D9D2ULL,
		0xD92856F0CB3D9D59ULL,
		0xE78B5E99785FDBA0ULL,
		0x45BDF554F1F5FEEAULL,
		0xF8D4DE765E57AC0DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3B34EC60BBB690D9ULL,
		0x7DF50DB3F006D1BEULL,
		0x0D5FF1F610AAF726ULL,
		0x268597433FD54AD9ULL,
		0xBF70B015D8340D71ULL,
		0x16667902741BEE51ULL,
		0xD88A98830EF957C1ULL,
		0x4588D6C131C5F6F1ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 433\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 433 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -433;
	} else {
		printf("Test Case 433 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x60824546CE659D12ULL,
		0xB3D65BF2EB0CDE7CULL,
		0x19D1F9F1E117AD2EULL,
		0x1DBF852C5B7E0D20ULL,
		0x182E9FCB9EEC9723ULL,
		0x299AED1C51169958ULL,
		0xA19B668397A5C60BULL,
		0x1C753E38F343BE2BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF0621A15A8ACB12ULL,
		0x9FCA59DEA6A97C1EULL,
		0xF2C8FEC9C2FCBA70ULL,
		0x6BC484D268D2A32CULL,
		0x31D0FEC3DCEE0A37ULL,
		0x3153D394B5898B04ULL,
		0xD6963349B2A1C33DULL,
		0x20AFC98A90BBD0F2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB17C23A573DAD200ULL,
		0x140C02144463625DULL,
		0x2708FB281E1AF2BEULL,
		0xB1FB0059F2AB69F3ULL,
		0xE65DA107C1FE8CEBULL,
		0xF84719879B8D0E53ULL,
		0xCB053339E50402CDULL,
		0xFBC574AE6287ED38ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 434\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 434 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -434;
	} else {
		printf("Test Case 434 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9E1988172D9300A4ULL,
		0xFCB4F7369ECD836CULL,
		0xBED699789BA5572CULL,
		0x44C7EF617A60AE06ULL,
		0x9BCA388F30C52F82ULL,
		0x2110E6FD08741297ULL,
		0xA818EEAA9C3440A7ULL,
		0x0E525159961ED72FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x26219A84440C22DFULL,
		0xE0ADB64B1B65303EULL,
		0x6E473F032A182B60ULL,
		0x3E4BFD63D03D810EULL,
		0xB39F3A3F2FA01DA7ULL,
		0x8AD1F503D69879FBULL,
		0x9D4B98D5564AF597ULL,
		0xEA6DDFA3E58B0B6FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x77F7ED92E986DDC5ULL,
		0x1C0740EB8368532EULL,
		0x508F5A75718D2BCCULL,
		0x067BF1FDAA232CF8ULL,
		0xE82AFE50012511DBULL,
		0x963EF1F931DB989BULL,
		0x0ACD55D545E94B0FULL,
		0x23E471B5B093CBC0ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 435\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 435 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -435;
	} else {
		printf("Test Case 435 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0EB81B74BE0B4358ULL,
		0xCEED90C484091686ULL,
		0x56B8A794201440C0ULL,
		0x670ACC4590276067ULL,
		0x45FA2B951224A31AULL,
		0xA8679137185D5913ULL,
		0x919AA21FC6875A0CULL,
		0xD8B4900CA056F578ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0B84AE7E6D07CABULL,
		0xC7086E4AAC29B2BAULL,
		0x4DEC3D58DA0A9E55ULL,
		0x54B9DB9EDA5C8849ULL,
		0x938F247045649CC8ULL,
		0xA4A8B9A88EA86E2FULL,
		0xFF3F80423191CDEFULL,
		0xDD9BBEF9A05FAA93ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6DFFD08CD73AC6ADULL,
		0x07E52279D7DF63CBULL,
		0x08CC6A3B4609A26BULL,
		0x1250F0A6B5CAD81EULL,
		0xB26B0724CCC00652ULL,
		0x03BED78E89B4EAE3ULL,
		0x925B21DD94F58C1DULL,
		0xFB18D112FFF74AE4ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 436\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 436 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -436;
	} else {
		printf("Test Case 436 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC7EA69D43CF77E2EULL,
		0x19FBDD94E6DE3F3EULL,
		0x3538CA358F550F16ULL,
		0x49666C46F036809DULL,
		0x245040EC00082A0AULL,
		0x2F94918FDA9D57C0ULL,
		0xFBC6C56CC142DF86ULL,
		0x0CA32F4490601601ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CFA28882F8D9A53ULL,
		0x7818B7D06FA21B33ULL,
		0x7C0192387E3B668BULL,
		0xB24FC1C87A1EEDB3ULL,
		0x86AC0840DC81E09AULL,
		0x2172492E87CFF6AEULL,
		0x22D6D63D05174C54ULL,
		0x681680F561A9ED7DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6AF0414C0D69E3DBULL,
		0xA1E325C4773C240BULL,
		0xB93737FD1119A88AULL,
		0x9716AA7E761792E9ULL,
		0x9DA438AB2386496FULL,
		0x0E22486152CD6111ULL,
		0xD8EFEF2FBC2B9332ULL,
		0xA48CAE4F2EB62884ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 437\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 437 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -437;
	} else {
		printf("Test Case 437 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE2189304F3A8D23EULL,
		0xAF79AD94A9ECFAC9ULL,
		0xEDE86DAC62E33E69ULL,
		0xCFB420CB94FA37BAULL,
		0xC5FB87FF800DDF74ULL,
		0xD49EBB3BBDA061C4ULL,
		0xAE99C16DDFFA120EULL,
		0xBE9A089F14F1BC38ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FF26CF254F083A0ULL,
		0xA341DB25D18EB159ULL,
		0xA00F38837DE28939ULL,
		0x8651385A51BCC07CULL,
		0x561603B70422B87FULL,
		0x64A2175579A909F8ULL,
		0xD26390897702CC5FULL,
		0x7B7D34E7DF854018ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD22626129EB84E9EULL,
		0x0C37D26ED85E4970ULL,
		0x4DD93528E500B530ULL,
		0x4962E871433D773EULL,
		0x6FE584487BEB26F5ULL,
		0x6FFCA3E643F757CCULL,
		0xDC3630E468F745AFULL,
		0x431CD3B7356C7C1FULL
	}};
	sign = 0;
	printf("Test Case 438\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 438 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -438;
	} else {
		printf("Test Case 438 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x09620688B0D8D71DULL,
		0x549C4C179E4A440EULL,
		0x22AAB805741E0A01ULL,
		0x40005581FC86FE8FULL,
		0x89526BC17349FEB7ULL,
		0x7F2626571C9A11F4ULL,
		0xBC12D8353903420EULL,
		0x3985C74319608826ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x7EA75059662BA0BEULL,
		0x1B2C9E0E9ECCCB17ULL,
		0x20ED90E4BBF6C1B5ULL,
		0x9A240354581CEF5FULL,
		0x1D890F8441E975B1ULL,
		0x440C33E032B575E2ULL,
		0x769D08790C81A766ULL,
		0x11BB22CAEC7C5492ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8ABAB62F4AAD365FULL,
		0x396FAE08FF7D78F6ULL,
		0x01BD2720B827484CULL,
		0xA5DC522DA46A0F30ULL,
		0x6BC95C3D31608905ULL,
		0x3B19F276E9E49C12ULL,
		0x4575CFBC2C819AA8ULL,
		0x27CAA4782CE43394ULL
	}};
	sign = 0;
	printf("Test Case 439\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 439 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -439;
	} else {
		printf("Test Case 439 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC49338077603CAA0ULL,
		0xA213231286C1C5E4ULL,
		0x213684FF1584EC05ULL,
		0x082D6BB784ED1FECULL,
		0xB31AFE2C3C82C370ULL,
		0xDA7BD91DD1CA3BA5ULL,
		0xDA2BBD5F0358F9B2ULL,
		0xD688B5875103FE84ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C76A16367F7646EULL,
		0xAC3592A9D831DC24ULL,
		0xD5D64EF3AADD3157ULL,
		0xFDBB5FB167813F14ULL,
		0x30D0F2C968D080BCULL,
		0x94DA45311C5EF3E3ULL,
		0x904EFC0D2531BB35ULL,
		0xD92758E17DA9AD84ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x781C96A40E0C6632ULL,
		0xF5DD9068AE8FE9C0ULL,
		0x4B60360B6AA7BAADULL,
		0x0A720C061D6BE0D7ULL,
		0x824A0B62D3B242B3ULL,
		0x45A193ECB56B47C2ULL,
		0x49DCC151DE273E7DULL,
		0xFD615CA5D35A5100ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 440\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 440 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -440;
	} else {
		printf("Test Case 440 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xCCC1D83A3100086AULL,
		0x9E9F5A07CB181EF4ULL,
		0xB61A79B1AC48D7C2ULL,
		0x360FE2252E6894EEULL,
		0xF74F4CEB9D09948EULL,
		0xF6D90AB36218248BULL,
		0x52C6CAD8F3AF58FAULL,
		0x0A96F154ADD76672ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC416CD8DB53B7BA2ULL,
		0x321623426E4F1E88ULL,
		0x96F0DD82BBE0D00DULL,
		0xC5BA9FF92D9DA2B3ULL,
		0x98BE27A5153485A3ULL,
		0xC23A3205E98E3ED9ULL,
		0x1D7FB8BD2E01FA96ULL,
		0x547E4613807F0E20ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x08AB0AAC7BC48CC8ULL,
		0x6C8936C55CC9006CULL,
		0x1F299C2EF06807B5ULL,
		0x7055422C00CAF23BULL,
		0x5E91254687D50EEAULL,
		0x349ED8AD7889E5B2ULL,
		0x3547121BC5AD5E64ULL,
		0xB618AB412D585852ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 441\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 441 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -441;
	} else {
		printf("Test Case 441 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4313E72A379305D1ULL,
		0xD4DF8F3D6C6D95F6ULL,
		0xE9E05C5548AD91B2ULL,
		0x3EAB08078AD13AE8ULL,
		0xB8B97B9AD6A1C320ULL,
		0xE5F517706A8AC7C1ULL,
		0x31908F126A2398D3ULL,
		0x451B277D2CD7C4DAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xADE57A4F39A400B3ULL,
		0x8954FE44C8AFD7CAULL,
		0xD6B74B2E2D172D9BULL,
		0x7E47C65B4E6E06A8ULL,
		0x8252E4C3D3B64C0AULL,
		0x6A502935B7282D79ULL,
		0x21735B80DDD1273EULL,
		0x5D531B82F5C0A832ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x952E6CDAFDEF051EULL,
		0x4B8A90F8A3BDBE2BULL,
		0x132911271B966417ULL,
		0xC06341AC3C633440ULL,
		0x366696D702EB7715ULL,
		0x7BA4EE3AB3629A48ULL,
		0x101D33918C527195ULL,
		0xE7C80BFA37171CA8ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 442\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 442 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -442;
	} else {
		printf("Test Case 442 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xEBDEAAA5586AA5E1ULL,
		0xBE79E97F735B6BDFULL,
		0x0E445B4D72CBFAFCULL,
		0xCDEDC53C1046B19DULL,
		0xA63B01D90588AE57ULL,
		0xDB8580B9C2DE4ACAULL,
		0xFF0573968118DA6AULL,
		0x9E9C861809738252ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8ED9B6217B1CB7BULL,
		0xAA2E1F60772BAF99ULL,
		0x1D227AE0796ED30AULL,
		0x4A34C8537EA984F9ULL,
		0xA29C3EBD36CC6121ULL,
		0x406F466DAEDE8F32ULL,
		0x67E6E6E967058583ULL,
		0xE9DCDA673F0E8469ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x12F10F4340B8DA66ULL,
		0x144BCA1EFC2FBC46ULL,
		0xF121E06CF95D27F2ULL,
		0x83B8FCE8919D2CA3ULL,
		0x039EC31BCEBC4D36ULL,
		0x9B163A4C13FFBB98ULL,
		0x971E8CAD1A1354E7ULL,
		0xB4BFABB0CA64FDE9ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 443\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 443 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -443;
	} else {
		printf("Test Case 443 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1549591F38AD496AULL,
		0x5463531C8A01BC76ULL,
		0x504311A5882D7B02ULL,
		0x6FE78CAFC37C423DULL,
		0xC1F04D62F2A7F522ULL,
		0x529AAA099B0CC2E6ULL,
		0xB6E6FBC5248608BDULL,
		0x1424DDDECF9ED888ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x88D979F6BFF3FA07ULL,
		0x34C4D2AEE51B60F8ULL,
		0x3436F256210C8E17ULL,
		0x24B0DED5F4E05FE4ULL,
		0x240310C572C29E8FULL,
		0x3C04AD3ABBFCC853ULL,
		0x8978EA92F42DF6B4ULL,
		0x81B909F8CFED3816ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8C6FDF2878B94F63ULL,
		0x1F9E806DA4E65B7DULL,
		0x1C0C1F4F6720ECEBULL,
		0x4B36ADD9CE9BE259ULL,
		0x9DED3C9D7FE55693ULL,
		0x1695FCCEDF0FFA93ULL,
		0x2D6E113230581209ULL,
		0x926BD3E5FFB1A072ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 444\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 444 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -444;
	} else {
		printf("Test Case 444 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x2A12F29075F45DDEULL,
		0x30BD17C2D19597BAULL,
		0x489C81B42E854F93ULL,
		0x2B73D6F8F9ACEC0FULL,
		0xBB847F0DD217314AULL,
		0xAFD8786A5F3519D6ULL,
		0x23594ACF2255B7EAULL,
		0x66485F11128E432DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3BAE8FF41FD2B18ULL,
		0x519163BCAB18D496ULL,
		0xB86323344EE8CADDULL,
		0xF0D7B78F25C369A4ULL,
		0x5B24437C0DDB0EA2ULL,
		0x6F2A7B1D57C7A4B9ULL,
		0xDAE4DFDC8768F4E9ULL,
		0xA6ED70CCB2351E85ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8658099133F732C6ULL,
		0xDF2BB406267CC323ULL,
		0x90395E7FDF9C84B5ULL,
		0x3A9C1F69D3E9826AULL,
		0x60603B91C43C22A7ULL,
		0x40ADFD4D076D751DULL,
		0x48746AF29AECC301ULL,
		0xBF5AEE44605924A7ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 445\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 445 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -445;
	} else {
		printf("Test Case 445 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6C53CF8954DB2BC3ULL,
		0x0AE81028B16C30CDULL,
		0x09DF439C4D497526ULL,
		0xB24F22A985EE4884ULL,
		0xFC900CA60074AFB5ULL,
		0x09448E4420E52BF9ULL,
		0x32B2209DC6A5CBD6ULL,
		0x75D79E3B694A87E6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D1CAFDF78F3CEF5ULL,
		0xEA39E62CDCBED640ULL,
		0xB6A76D5A489650A3ULL,
		0xECC2E2CD2B3CE598ULL,
		0x4B5346BA3EB65DA0ULL,
		0x2898186867FF8CECULL,
		0xA4EB1E4AA3487CAEULL,
		0x4ECA73132405D5D5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCF371FA9DBE75CCEULL,
		0x20AE29FBD4AD5A8CULL,
		0x5337D64204B32482ULL,
		0xC58C3FDC5AB162EBULL,
		0xB13CC5EBC1BE5214ULL,
		0xE0AC75DBB8E59F0DULL,
		0x8DC70253235D4F27ULL,
		0x270D2B284544B210ULL
	}};
	sign = 0;
	printf("Test Case 446\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 446 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -446;
	} else {
		printf("Test Case 446 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x966BDE29755CB869ULL,
		0xCA2FF53E1B07A2ACULL,
		0x613FC755218059E5ULL,
		0x6DBE4D896EF29F29ULL,
		0x6E9D69F40F7C2E55ULL,
		0xDF9AB4AFEF9D4F47ULL,
		0x57770EFE98C456CAULL,
		0x8CD286B1ED5BA34DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6561A65D5D3F89EULL,
		0x244B33FD41500F1CULL,
		0x7A3F889F5BD715F1ULL,
		0x7BCC282570DBAA74ULL,
		0x504B41A55DE23BD6ULL,
		0x909F10BC065E7C68ULL,
		0xFACF7AB9CC4DDBBAULL,
		0x37D275EAC4FF0DCFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE015C3C39F88BFCBULL,
		0xA5E4C140D9B7938FULL,
		0xE7003EB5C5A943F4ULL,
		0xF1F22563FE16F4B4ULL,
		0x1E52284EB199F27EULL,
		0x4EFBA3F3E93ED2DFULL,
		0x5CA79444CC767B10ULL,
		0x550010C7285C957DULL
	}};
	sign = 0;
	printf("Test Case 447\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 447 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -447;
	} else {
		printf("Test Case 447 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x5B4D4B71CB8093F0ULL,
		0xDA7B1274DC5CD542ULL,
		0xD4E7B1CA2F1F88D0ULL,
		0x8E2F2EE187BC3471ULL,
		0x34F2F5AD7CFCF608ULL,
		0xF2C52192F87C9B8AULL,
		0x9C57DC50FCE54962ULL,
		0x5746D6CC137198CEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D25044D4880714CULL,
		0x83B46F758D8AE68EULL,
		0x9CF6692B900C2F0EULL,
		0xC3A0F188C0D77C13ULL,
		0xCB71FBAC1FC2BABCULL,
		0x215ABDCF0A101428ULL,
		0xC78028F2F255C688ULL,
		0xBB8E4C4F2CC6EB90ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBE284724830022A4ULL,
		0x56C6A2FF4ED1EEB3ULL,
		0x37F1489E9F1359C2ULL,
		0xCA8E3D58C6E4B85EULL,
		0x6980FA015D3A3B4BULL,
		0xD16A63C3EE6C8761ULL,
		0xD4D7B35E0A8F82DAULL,
		0x9BB88A7CE6AAAD3DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 448\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 448 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -448;
	} else {
		printf("Test Case 448 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1BF37CA14144D1B9ULL,
		0x3BA84A3E1DB8CC77ULL,
		0xE15DB422A452A8F9ULL,
		0x0FA6AD81F41DC91AULL,
		0x2A6A7881A577353EULL,
		0x1C44E94F810CF2B4ULL,
		0x755CFF4B027BAAC7ULL,
		0xDED2CA4FB79275E4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0F2082782642F88ULL,
		0xEE4EC9EFC50CF0D5ULL,
		0x67A60CECFDD86ADFULL,
		0x0E1411A978DAF0BBULL,
		0x67CC9CF09C5278C2ULL,
		0xCEF2BF05B5DCB9BBULL,
		0x7B7E9B684B8C2128ULL,
		0x21BCF1B1EBF1C1ADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2B017479BEE0A231ULL,
		0x4D59804E58ABDBA1ULL,
		0x79B7A735A67A3E19ULL,
		0x01929BD87B42D85FULL,
		0xC29DDB910924BC7CULL,
		0x4D522A49CB3038F8ULL,
		0xF9DE63E2B6EF899EULL,
		0xBD15D89DCBA0B436ULL
	}};
	sign = 0;
	printf("Test Case 449\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 449 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -449;
	} else {
		printf("Test Case 449 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9BB39920C0D44E01ULL,
		0xC4A02E619C907747ULL,
		0x4EB27517FEEC2956ULL,
		0x75E464D7F2AE16E6ULL,
		0x0E2337E2D8BEB7F5ULL,
		0x15F113C64685E874ULL,
		0xCE3EB0A201F937E9ULL,
		0xAF7A090AAB91C59BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE14B138905BADC1FULL,
		0x402DFFFF04A97496ULL,
		0x94B962B2F3383EC9ULL,
		0x376B1461699EAFC2ULL,
		0xAC8264CD760A910FULL,
		0xD908389FCFB6C864ULL,
		0x3EF4794D464C13CDULL,
		0x37C78FD80D076A15ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBA688597BB1971E2ULL,
		0x84722E6297E702B0ULL,
		0xB9F912650BB3EA8DULL,
		0x3E795076890F6723ULL,
		0x61A0D31562B426E6ULL,
		0x3CE8DB2676CF200FULL,
		0x8F4A3754BBAD241BULL,
		0x77B279329E8A5B86ULL
	}};
	sign = 0;
	printf("Test Case 450\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 450 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -450;
	} else {
		printf("Test Case 450 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x93F77A35A98E1D19ULL,
		0xC04C6E54AD844399ULL,
		0x9B9CD67B2448968EULL,
		0x3C3E50F14CEFB6D0ULL,
		0xE1BF082B41846F94ULL,
		0x279F97076790627DULL,
		0xC99A8CE3AFA71DB4ULL,
		0xA853FEA89F7EAB8DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD459ADABA0D9A59ULL,
		0x8707542A12BC7BE5ULL,
		0x1221078BBA608D81ULL,
		0x3A4B1F34539B1088ULL,
		0x43E8E2612BE92C32ULL,
		0xB0A419A02D62B588ULL,
		0xBF4B5B93B61EBE8AULL,
		0x042BBB3BFC4479BAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x96B1DF5AEF8082C0ULL,
		0x39451A2A9AC7C7B3ULL,
		0x897BCEEF69E8090DULL,
		0x01F331BCF954A648ULL,
		0x9DD625CA159B4362ULL,
		0x76FB7D673A2DACF5ULL,
		0x0A4F314FF9885F29ULL,
		0xA428436CA33A31D3ULL
	}};
	sign = 0;
	printf("Test Case 451\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 451 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -451;
	} else {
		printf("Test Case 451 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xECB9BC15BB46AD9BULL,
		0x603E1CC0445F2825ULL,
		0x2DCD81C67B3C91BBULL,
		0x01974F642F1FF922ULL,
		0xC65121CD2E42FD4CULL,
		0xB2143DE2FDFFEFE2ULL,
		0xD523A32968979178ULL,
		0xB9742150B112F2EBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x12DDBCAC7BAE929FULL,
		0x534F7A20772BF02CULL,
		0x7D9EA2640148DA37ULL,
		0xB3A2E44DF306A859ULL,
		0x407FB0BD9C2FF2B7ULL,
		0x5A00941C5D7C7156ULL,
		0x3F4A94AF8E622388ULL,
		0xAFD1B858048141EEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD9DBFF693F981AFCULL,
		0x0CEEA29FCD3337F9ULL,
		0xB02EDF6279F3B784ULL,
		0x4DF46B163C1950C8ULL,
		0x85D1710F92130A94ULL,
		0x5813A9C6A0837E8CULL,
		0x95D90E79DA356DF0ULL,
		0x09A268F8AC91B0FDULL
	}};
	sign = 0;
	printf("Test Case 452\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 452 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -452;
	} else {
		printf("Test Case 452 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x36C55530E9C4A282ULL,
		0x66E489B3D2E9AF0AULL,
		0x1BFB8B15BB5FB117ULL,
		0xD088E01DF1AA6766ULL,
		0xB48B3E8F90B8AC51ULL,
		0x554C8B39C8D1263AULL,
		0x9CCF6876BABD16B9ULL,
		0xE8DD17CD7446D1E5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD699D78D05BF8F24ULL,
		0x9E17907007F5D8F0ULL,
		0x5CE6A669EAEF0CA1ULL,
		0xC9F40CB7D181CC6AULL,
		0xE000F49942226C9BULL,
		0x68B314198FF3D53CULL,
		0xE905A7A668BA253BULL,
		0x2F835D4460262ADCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x602B7DA3E405135EULL,
		0xC8CCF943CAF3D619ULL,
		0xBF14E4ABD070A475ULL,
		0x0694D36620289AFBULL,
		0xD48A49F64E963FB6ULL,
		0xEC99772038DD50FDULL,
		0xB3C9C0D05202F17DULL,
		0xB959BA891420A708ULL
	}};
	sign = 0;
	printf("Test Case 453\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 453 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -453;
	} else {
		printf("Test Case 453 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x29EBC43D0775FED4ULL,
		0x1F61F6410FB4555AULL,
		0x93C898136463BF56ULL,
		0xB274229E51206165ULL,
		0x705F5231591D688FULL,
		0x03A44AA0B40A314DULL,
		0xDADA5831A5F0B410ULL,
		0x77BF98F42A5D214EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9CE7ADC4DBEA6B18ULL,
		0xFF301B84E1EEDD33ULL,
		0x71357ECA5523BDD7ULL,
		0x94462E450696D062ULL,
		0x3299922191D25553ULL,
		0x0307A27319CD9EF0ULL,
		0xF946C7B3BFD1E45CULL,
		0xE6E968B4B290F550ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8D0416782B8B93BCULL,
		0x2031DABC2DC57826ULL,
		0x229319490F40017EULL,
		0x1E2DF4594A899103ULL,
		0x3DC5C00FC74B133CULL,
		0x009CA82D9A3C925DULL,
		0xE193907DE61ECFB4ULL,
		0x90D6303F77CC2BFDULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 454\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 454 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -454;
	} else {
		printf("Test Case 454 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB6BB46A48EF6EF31ULL,
		0x5462083231397E29ULL,
		0xE3EDB527E39AD38DULL,
		0x0D096FFB6B5D0E4CULL,
		0x70FF1ACFA90BC494ULL,
		0xDD708F2983855ED9ULL,
		0x7DB7D7F7D39C5275ULL,
		0x2706FD7757586320ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x97DB966F4575D2F5ULL,
		0x2A26898E064D6EF1ULL,
		0x1F40798B7B15685CULL,
		0xE252249094E841A1ULL,
		0xECEA999E78E1559BULL,
		0x6DAD8FF8EA786FE9ULL,
		0x4D07C75276977EE0ULL,
		0x6278A5CC38A715A9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1EDFB03549811C3CULL,
		0x2A3B7EA42AEC0F38ULL,
		0xC4AD3B9C68856B31ULL,
		0x2AB74B6AD674CCABULL,
		0x84148131302A6EF8ULL,
		0x6FC2FF30990CEEEFULL,
		0x30B010A55D04D395ULL,
		0xC48E57AB1EB14D77ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 455\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 455 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -455;
	} else {
		printf("Test Case 455 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4FC45388D4E40D0FULL,
		0x431945CCBC200260ULL,
		0x495666EA1BC09635ULL,
		0x20EE8B5E92FAAB32ULL,
		0xAEED6D6DFD7637A1ULL,
		0x98E79A5FF73D2E2FULL,
		0xD6BA071B92E91D6EULL,
		0xB1C45A61FCD9852EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCC2B17DD07AF395ULL,
		0xC1ACB9DB9672985BULL,
		0xE58982BCEF95C5CAULL,
		0x0D4996B6BDA51293ULL,
		0xDA42C427F337A47DULL,
		0xF5A3B59C2E239958ULL,
		0xE0F891BEA3B09561ULL,
		0x13C146AAF4B7EBEBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5301A20B0469197AULL,
		0x816C8BF125AD6A04ULL,
		0x63CCE42D2C2AD06AULL,
		0x13A4F4A7D555989EULL,
		0xD4AAA9460A3E9324ULL,
		0xA343E4C3C91994D6ULL,
		0xF5C1755CEF38880CULL,
		0x9E0313B708219942ULL
	}};
	sign = 0;
	printf("Test Case 456\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 456 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -456;
	} else {
		printf("Test Case 456 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x83CCCF0F0263223DULL,
		0x4642B266A8E7F28CULL,
		0x5C2273F1FF02DFD9ULL,
		0x897F66A682FE68D2ULL,
		0xDFE4835A4619EE41ULL,
		0xACBB683C371EDD19ULL,
		0xF6A38E7F3655A3F2ULL,
		0xB9225BB5FB64591BULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA23812E4468A776ULL,
		0x0CF88C2E1D312374ULL,
		0x0E655E6789D21744ULL,
		0x8751A1A842B6BF4AULL,
		0x3565B6AA045348C1ULL,
		0xFB43DCA562149679ULL,
		0x7AED78B0C7034EC1ULL,
		0x2929665A93468099ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD9A94DE0BDFA7AC7ULL,
		0x394A26388BB6CF17ULL,
		0x4DBD158A7530C895ULL,
		0x022DC4FE4047A988ULL,
		0xAA7ECCB041C6A580ULL,
		0xB1778B96D50A46A0ULL,
		0x7BB615CE6F525530ULL,
		0x8FF8F55B681DD882ULL
	}};
	sign = 0;
	printf("Test Case 457\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 457 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -457;
	} else {
		printf("Test Case 457 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x072C668211D60482ULL,
		0xCDCF7F69EEEDC861ULL,
		0xA8A9D952ECD718F4ULL,
		0x45AEAF8C17807389ULL,
		0x78D081DF3753FAD1ULL,
		0x9BD0740EC2F8553EULL,
		0x6A6686BC5232D280ULL,
		0x233EFE8EC12737B5ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x29F6D2E1C79FB90AULL,
		0x25CBF7AB489C734AULL,
		0xF0A19F7C37D1F9E8ULL,
		0xC7ED5A90433F07A4ULL,
		0xB9B5C0A3253F6BC6ULL,
		0x5524516FB82F46E2ULL,
		0x7DB5FB0299D2167EULL,
		0x923BF350608B54F3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDD3593A04A364B78ULL,
		0xA80387BEA6515516ULL,
		0xB80839D6B5051F0CULL,
		0x7DC154FBD4416BE4ULL,
		0xBF1AC13C12148F0AULL,
		0x46AC229F0AC90E5BULL,
		0xECB08BB9B860BC02ULL,
		0x91030B3E609BE2C1ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 458\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 458 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -458;
	} else {
		printf("Test Case 458 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD5B6F9DD2CBEA496ULL,
		0x0707A52FEF290990ULL,
		0xA5F8EDA937885376ULL,
		0x5627AD91DF0174A1ULL,
		0x01063FC3FA7209DAULL,
		0x2C633E6732F14A0CULL,
		0xF4F29B27F9FD0400ULL,
		0xE7261104D8E74845ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCED8DF7A50B86E1EULL,
		0x7DC86BFD1B8AE9A4ULL,
		0x37326A811690D766ULL,
		0xFE20428CB8769930ULL,
		0x760CDB30D14C0DECULL,
		0xBAB8DEA0214D77F7ULL,
		0x7476BF766E72FEDDULL,
		0x416FEA42CFEA0D7DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x06DE1A62DC063678ULL,
		0x893F3932D39E1FECULL,
		0x6EC6832820F77C0FULL,
		0x58076B05268ADB71ULL,
		0x8AF964932925FBEDULL,
		0x71AA5FC711A3D214ULL,
		0x807BDBB18B8A0522ULL,
		0xA5B626C208FD3AC8ULL
	}};
	sign = 0;
	printf("Test Case 459\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 459 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -459;
	} else {
		printf("Test Case 459 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC8345A9EB10B26C9ULL,
		0xAC0F934905D0270AULL,
		0x8F8BC3619852F79FULL,
		0x33B22B211DCC32D6ULL,
		0x6A0806F45184FBB4ULL,
		0x7B8BA6A8D424F0F5ULL,
		0x9BC30740FF5B45F4ULL,
		0x657D2BDC327D0DA1ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE41B3A2292D5DEF5ULL,
		0x3E021EEA0D30F866ULL,
		0xE9EEF1CC67C62948ULL,
		0xEFED704EE9DB13D0ULL,
		0x6C9EDC6BB142BCD5ULL,
		0x5CEE28294E89D7AAULL,
		0x8344C41BBA566031ULL,
		0x431168EE0E6C2816ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE419207C1E3547D4ULL,
		0x6E0D745EF89F2EA3ULL,
		0xA59CD195308CCE57ULL,
		0x43C4BAD233F11F05ULL,
		0xFD692A88A0423EDEULL,
		0x1E9D7E7F859B194AULL,
		0x187E43254504E5C3ULL,
		0x226BC2EE2410E58BULL
	}};
	sign = 0;
	printf("Test Case 460\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 460 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -460;
	} else {
		printf("Test Case 460 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA7D5FD6DC084F382ULL,
		0xC992AF57FCFCFAF1ULL,
		0xED6DCC062CECB4E3ULL,
		0x4A37187D1AE470E2ULL,
		0x898CACDAD3F03D11ULL,
		0x7268DF59C0893FA4ULL,
		0x91755784E6AD05B5ULL,
		0x3FA63BDFB79DDA61ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1168F1B5640520B8ULL,
		0x8FB8FB80C0326892ULL,
		0xB8895244A71EB96CULL,
		0xCFE4956BD1CCDAADULL,
		0xCC31F4BAB7DB5DE2ULL,
		0x51A045EB41307817ULL,
		0xB47D0BABC634B331ULL,
		0x3875F65892C1E496ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x966D0BB85C7FD2CAULL,
		0x39D9B3D73CCA925FULL,
		0x34E479C185CDFB77ULL,
		0x7A52831149179635ULL,
		0xBD5AB8201C14DF2EULL,
		0x20C8996E7F58C78CULL,
		0xDCF84BD920785284ULL,
		0x0730458724DBF5CAULL
	}};
	sign = 0;
	printf("Test Case 461\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 461 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -461;
	} else {
		printf("Test Case 461 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF7574E91F676F42DULL,
		0xB01F932DD8FAF831ULL,
		0xA7D23DCAED853AA3ULL,
		0xB02D379AAA1C7E81ULL,
		0xA2A530ABEC29E13DULL,
		0x6234BBB76E96F3C5ULL,
		0xB99A9F3659E3CC66ULL,
		0xA4F29FDAC6B9EF79ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3759DEFA9236B32ULL,
		0x8576D51B9EB5FD62ULL,
		0xE0FF6C9B7341636EULL,
		0x16EE49F849B15B88ULL,
		0xCE9F820B898AFDD2ULL,
		0x18C1ECCC8FBCF0C7ULL,
		0x41B751D4092F3304ULL,
		0x408F44A45CAE9EA7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x33E1B0A24D5388FBULL,
		0x2AA8BE123A44FACFULL,
		0xC6D2D12F7A43D735ULL,
		0x993EEDA2606B22F8ULL,
		0xD405AEA0629EE36BULL,
		0x4972CEEADEDA02FDULL,
		0x77E34D6250B49962ULL,
		0x64635B366A0B50D2ULL
	}};
	sign = 0;
	printf("Test Case 462\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 462 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -462;
	} else {
		printf("Test Case 462 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xBF590CF66ED8B800ULL,
		0x3E62F00FC187CF06ULL,
		0x68028E016DFF0DD2ULL,
		0xE65F6ED26F441634ULL,
		0x748314E75A5C6DA5ULL,
		0x7A011D947793FD73ULL,
		0x9D6819EF31A87134ULL,
		0x8B281DB71FAA1ACDULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x628650426E82633AULL,
		0xA56E2214A5F32827ULL,
		0x60A4A41FCAD9A628ULL,
		0x09838D03312DCE99ULL,
		0x939D9706AD2EEB9AULL,
		0x695E32608458372CULL,
		0xB80FB0A431135D84ULL,
		0xF902E0B9C971164AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5CD2BCB4005654C6ULL,
		0x98F4CDFB1B94A6DFULL,
		0x075DE9E1A32567A9ULL,
		0xDCDBE1CF3E16479BULL,
		0xE0E57DE0AD2D820BULL,
		0x10A2EB33F33BC646ULL,
		0xE558694B009513B0ULL,
		0x92253CFD56390482ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 463\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 463 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -463;
	} else {
		printf("Test Case 463 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xE2DD2F2E6729B8E3ULL,
		0x1FC8737D7CFC776AULL,
		0x05B2DDB7EC31DF9DULL,
		0x13968823BB0EBA89ULL,
		0x470103FB8B174ED7ULL,
		0x21C78AE0619EF40AULL,
		0x3DCB031ABBC41A7DULL,
		0xE1406BEF1110B61DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x25EBEA97C08A2FB6ULL,
		0x467E096AE0C84C30ULL,
		0xFADE6ABDFD2999E5ULL,
		0xD838D0195CF27F3EULL,
		0x6E7A17B4C519E807ULL,
		0x189938C5E790F556ULL,
		0xF725243BA5CD17CCULL,
		0xAB3964F564800D9DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBCF14496A69F892DULL,
		0xD94A6A129C342B3AULL,
		0x0AD472F9EF0845B7ULL,
		0x3B5DB80A5E1C3B4AULL,
		0xD886EC46C5FD66CFULL,
		0x092E521A7A0DFEB3ULL,
		0x46A5DEDF15F702B1ULL,
		0x360706F9AC90A87FULL
	}};
	sign = 0;
	printf("Test Case 464\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 464 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -464;
	} else {
		printf("Test Case 464 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x2B6310F1810BD748ULL,
		0xA756E9185E5A6123ULL,
		0xAEA15D18A99682BAULL,
		0xFD1A3A24EEE50BB7ULL,
		0xB4540691220E9C61ULL,
		0x548BE47EB2C6B7FDULL,
		0x15E2F9FC8D1E6417ULL,
		0xF9F87A485A764055ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6571E0227745BBB3ULL,
		0x1DB9F4F0E43EE287ULL,
		0x399C06352B76FF3DULL,
		0x626E061AEB2A4F8EULL,
		0x3275FA164E0E1CDFULL,
		0x5102B6362FEFD693ULL,
		0x978ABB98297ADEC8ULL,
		0xC4A42C4EA9B92B26ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC5F130CF09C61B95ULL,
		0x899CF4277A1B7E9BULL,
		0x750556E37E1F837DULL,
		0x9AAC340A03BABC29ULL,
		0x81DE0C7AD4007F82ULL,
		0x03892E4882D6E16AULL,
		0x7E583E6463A3854FULL,
		0x35544DF9B0BD152EULL
	}};
	sign = 0;
	printf("Test Case 465\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 465 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -465;
	} else {
		printf("Test Case 465 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x80A2B0C7622D9CA8ULL,
		0xF38B46D1A46D3814ULL,
		0x0AD83287C31140CDULL,
		0x04C582AA4FF186ACULL,
		0x1B02EBE8771FBFEEULL,
		0x9C5CF2268F228377ULL,
		0x68F487E7DD601A2BULL,
		0x47A1E1C1ED21E36EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D4A5B1182193784ULL,
		0xA6413A22A1ACAE3CULL,
		0xD0E1493D73268E41ULL,
		0xC0CB41FC3A61BDADULL,
		0x3A0FFEB769AF2586ULL,
		0x31CDC43840C28999ULL,
		0x3B814CC093FAD255ULL,
		0x80C68E4CEEC70D74ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x135855B5E0146524ULL,
		0x4D4A0CAF02C089D8ULL,
		0x39F6E94A4FEAB28CULL,
		0x43FA40AE158FC8FEULL,
		0xE0F2ED310D709A67ULL,
		0x6A8F2DEE4E5FF9DDULL,
		0x2D733B27496547D6ULL,
		0xC6DB5374FE5AD5FAULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 466\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 466 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -466;
	} else {
		printf("Test Case 466 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x11486571CCE9F6A9ULL,
		0x97FE3ABF15A17BC6ULL,
		0xD3C20C66768FBA38ULL,
		0x86CF1AA652948204ULL,
		0x6F144D5FEDCCE9A2ULL,
		0x6EB0086D6519A006ULL,
		0x0C72B1D16F207072ULL,
		0x34BF6385A8BDABEAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x997663093E903D0CULL,
		0xDA38BDCCCDB8AB18ULL,
		0x020C41AF3D3B079AULL,
		0x4940EEFB6A400086ULL,
		0x4677FAF82A09B93DULL,
		0x4B740DB55C4A6FBFULL,
		0x525F1A16BE89B145ULL,
		0x290F2C51D5E80EA6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x77D202688E59B99DULL,
		0xBDC57CF247E8D0ADULL,
		0xD1B5CAB73954B29DULL,
		0x3D8E2BAAE854817EULL,
		0x289C5267C3C33065ULL,
		0x233BFAB808CF3047ULL,
		0xBA1397BAB096BF2DULL,
		0x0BB03733D2D59D43ULL
	}};
	sign = 0;
	printf("Test Case 467\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 467 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -467;
	} else {
		printf("Test Case 467 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x1FB7E2DF60D72C7DULL,
		0x2B91AD8165E5229FULL,
		0x1A446CCC6F71EDCFULL,
		0x15AEB5155672B01FULL,
		0x30428D5465E3569DULL,
		0x5D6213B28F81E2D5ULL,
		0xB3ED8E24F59D2E9EULL,
		0xB80F0AE95D9119B8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD6FC511E294165BULL,
		0xA332DD8A54C0E325ULL,
		0x5A8E443AC56EEA87ULL,
		0x53E8E7E9B1566E46ULL,
		0x5C1F8D62A6704837ULL,
		0x1CC74300C2B9F493ULL,
		0xF7FCACEDC03556FCULL,
		0x0B8736DC8C1F50B9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x52481DCD7E431622ULL,
		0x885ECFF711243F79ULL,
		0xBFB62891AA030347ULL,
		0xC1C5CD2BA51C41D8ULL,
		0xD422FFF1BF730E65ULL,
		0x409AD0B1CCC7EE41ULL,
		0xBBF0E1373567D7A2ULL,
		0xAC87D40CD171C8FEULL
	}};
	sign = 0;
	printf("Test Case 468\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 468 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -468;
	} else {
		printf("Test Case 468 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xEB9D2AC395D83D0FULL,
		0x813D5E223170456EULL,
		0x3E0CB78A1D8ACAADULL,
		0xA4DCA7D7F71C82FBULL,
		0xF8E31158A34C1EACULL,
		0x79878D7357DA447BULL,
		0x00DFB4F64240D2C0ULL,
		0x739EF4E3D1A59E3CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E2E10E482D03F02ULL,
		0xE2EBBEBF68B8D32CULL,
		0x2479F7B72DD899D9ULL,
		0x195D98CDFC784B46ULL,
		0xF47B08192226DE98ULL,
		0x5984C293DF6ADC44ULL,
		0x6A1343D3B3A660DAULL,
		0x725C3F20CFC1FD66ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBD6F19DF1307FE0DULL,
		0x9E519F62C8B77242ULL,
		0x1992BFD2EFB230D3ULL,
		0x8B7F0F09FAA437B5ULL,
		0x0468093F81254014ULL,
		0x2002CADF786F6837ULL,
		0x96CC71228E9A71E6ULL,
		0x0142B5C301E3A0D5ULL
	}};
	sign = 0;
	printf("Test Case 469\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 469 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -469;
	} else {
		printf("Test Case 469 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x8948A94995F4A5E9ULL,
		0xEF8A6DDE029EDEDAULL,
		0x4EC9FF472AB73A0AULL,
		0xFEE6BB5B01313FC6ULL,
		0x9D92C24C2E673467ULL,
		0x9FA89D3E2C6B9B38ULL,
		0xB910FA3078DD1088ULL,
		0x01A33A0B3752E794ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x484E0748B5AE59F3ULL,
		0xE42EBE1659D2E2A3ULL,
		0x5DD349539FDAE712ULL,
		0x72B33FC1129E5D97ULL,
		0x10446A0651F22168ULL,
		0x04F7BACBC4DE4924ULL,
		0x53015053D4440DBBULL,
		0x80DE4A53EEFAD4D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40FAA200E0464BF6ULL,
		0x0B5BAFC7A8CBFC37ULL,
		0xF0F6B5F38ADC52F8ULL,
		0x8C337B99EE92E22EULL,
		0x8D4E5845DC7512FFULL,
		0x9AB0E272678D5214ULL,
		0x660FA9DCA49902CDULL,
		0x80C4EFB7485812BDULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 470\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 470 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -470;
	} else {
		printf("Test Case 470 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4FE28D82947AFCF5ULL,
		0xC125A4AC5A712A50ULL,
		0x18F0F5DEF50A1ED3ULL,
		0xFAFD794AE014ADD9ULL,
		0x56BE3FC40585757EULL,
		0x8A36B310F1ECEA39ULL,
		0x375B1F67982CBE50ULL,
		0x2418F9E6EA644950ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BF940BE167C73E3ULL,
		0xA9ACFA0C4BBE52F7ULL,
		0x34D69905B10207B7ULL,
		0xFF8DD722723FC3BAULL,
		0xCA0762C444EAF95CULL,
		0x9AE54F1656FC5792ULL,
		0xC55D4E3BF2C416A2ULL,
		0x6C22ABC48FAFAE87ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC3E94CC47DFE8912ULL,
		0x1778AAA00EB2D758ULL,
		0xE41A5CD94408171CULL,
		0xFB6FA2286DD4EA1EULL,
		0x8CB6DCFFC09A7C21ULL,
		0xEF5163FA9AF092A6ULL,
		0x71FDD12BA568A7ADULL,
		0xB7F64E225AB49AC8ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 471\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 471 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -471;
	} else {
		printf("Test Case 471 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x7ED6847B9BA2129EULL,
		0xF4134B355460F09AULL,
		0x0DD2CEC4795E3A3FULL,
		0xBD93D52C838B5874ULL,
		0x4A5331DE43469EB0ULL,
		0xC92C77E83D98BB03ULL,
		0x8770FE3EE9D1F447ULL,
		0xF3B22B05227A5914ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x28832879D8BA66AAULL,
		0x78E7D2F2E275E167ULL,
		0x52EF76FCC44E5658ULL,
		0xAD5DA7489A074789ULL,
		0x2294232F5070DCD8ULL,
		0xE3807B7E93A26DDCULL,
		0x33D45FAE6806EF21ULL,
		0x60573B667C858263ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x56535C01C2E7ABF4ULL,
		0x7B2B784271EB0F33ULL,
		0xBAE357C7B50FE3E7ULL,
		0x10362DE3E98410EAULL,
		0x27BF0EAEF2D5C1D8ULL,
		0xE5ABFC69A9F64D27ULL,
		0x539C9E9081CB0525ULL,
		0x935AEF9EA5F4D6B1ULL
	}};
	sign = 0;
	printf("Test Case 472\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 472 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -472;
	} else {
		printf("Test Case 472 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x77F7443A9B31B42AULL,
		0x3709C325FC22A4D5ULL,
		0x684022D3E5E27076ULL,
		0x3BCE6433EA9CBA38ULL,
		0xDA806890065986E2ULL,
		0xECD5E3D6B1030581ULL,
		0xAA948630E95C9505ULL,
		0x0B67652771AB9E40ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D8EF5DE09759C2DULL,
		0x9F5627390B929B08ULL,
		0x4AA2126063A41E9AULL,
		0x9A8A3B4E51BEF555ULL,
		0xACBFA7FD6815C993ULL,
		0x437C38841C1363AEULL,
		0xB4C275354891D493ULL,
		0xBF7A5A4D1079BF51ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4A684E5C91BC17FDULL,
		0x97B39BECF09009CDULL,
		0x1D9E1073823E51DBULL,
		0xA14428E598DDC4E3ULL,
		0x2DC0C0929E43BD4EULL,
		0xA959AB5294EFA1D3ULL,
		0xF5D210FBA0CAC072ULL,
		0x4BED0ADA6131DEEEULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 473\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 473 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -473;
	} else {
		printf("Test Case 473 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x421FD1AF38759403ULL,
		0x4220D1DDFA5E92CEULL,
		0xBD3B68C3E0ABE98AULL,
		0x52AFE263A75A663CULL,
		0x5A384CAEE1521B08ULL,
		0xFAB1B4E024071A84ULL,
		0x175EAD6D1DE280DAULL,
		0xC74FC866C60A1E0DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x98FFF240D76AA75BULL,
		0x7FBF20322E44232EULL,
		0x44E5D28BBF000C33ULL,
		0xE871F023EC15DF12ULL,
		0x8E035FC371CFE227ULL,
		0xB43C5C300A584A0EULL,
		0xA38B56B4FB6A1572ULL,
		0xAA333DBFE9ADA791ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA91FDF6E610AECA8ULL,
		0xC261B1ABCC1A6F9FULL,
		0x7855963821ABDD56ULL,
		0x6A3DF23FBB44872AULL,
		0xCC34ECEB6F8238E0ULL,
		0x467558B019AED075ULL,
		0x73D356B822786B68ULL,
		0x1D1C8AA6DC5C767BULL
	}};
	sign = 0;
	printf("Test Case 474\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 474 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -474;
	} else {
		printf("Test Case 474 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xF69CE94A8CA9656EULL,
		0x55619E1C6772CAC4ULL,
		0x0C72DB3EAAC61127ULL,
		0x607B031C493BBA29ULL,
		0xCF0BC13A20A81A25ULL,
		0x51B64E23F03C42F8ULL,
		0x216024ADBDBAB5AAULL,
		0x41A0120A1B38080DULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B1C83E61C03B9A3ULL,
		0x1BE2A46DACDBE5D9ULL,
		0xC5B134F68DA637F5ULL,
		0x4CFD24D48AFCEF0BULL,
		0x8B6F4471949DE155ULL,
		0x36A450A18B70167CULL,
		0xA2F3358DAFE7A586ULL,
		0x654F89EE33AEA29BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9B80656470A5ABCBULL,
		0x397EF9AEBA96E4EBULL,
		0x46C1A6481D1FD932ULL,
		0x137DDE47BE3ECB1DULL,
		0x439C7CC88C0A38D0ULL,
		0x1B11FD8264CC2C7CULL,
		0x7E6CEF200DD31024ULL,
		0xDC50881BE7896571ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 475\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 475 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -475;
	} else {
		printf("Test Case 475 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA0E554A4EBB108D1ULL,
		0x7B71D072594F0AB6ULL,
		0x98DC8D786B06A28AULL,
		0x368F2034A988E7FDULL,
		0x4206879C73670502ULL,
		0xB608D132839A577CULL,
		0x18D758125D12D9ADULL,
		0x374782DA05A4F29FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x93416F9F48A1795EULL,
		0x186A98A9F06AF865ULL,
		0x5AD3178945832433ULL,
		0x1510EC81027FEDEFULL,
		0x97ADD915BC5C5666ULL,
		0x15E8E8D1BBDC5564ULL,
		0x93B08C137FE7A6D5ULL,
		0x782CC547A6A09AE4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0DA3E505A30F8F73ULL,
		0x630737C868E41251ULL,
		0x3E0975EF25837E57ULL,
		0x217E33B3A708FA0EULL,
		0xAA58AE86B70AAE9CULL,
		0xA01FE860C7BE0217ULL,
		0x8526CBFEDD2B32D8ULL,
		0xBF1ABD925F0457BAULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 476\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 476 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -476;
	} else {
		printf("Test Case 476 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x485D429D84D1C430ULL,
		0x11060704C10E107CULL,
		0xEF913EE3CB82BFCDULL,
		0x5721D4C50B985CADULL,
		0xE9247FBD72357141ULL,
		0xF264DCA707EA4962ULL,
		0x4FFF14B0AEA45D44ULL,
		0x874CE79EE8BDE7BAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6605AB532114E5DULL,
		0x9CFA474F229A9048ULL,
		0xFD851D8B2D2EBBACULL,
		0xEAD26092AEA53F4EULL,
		0x49CA19828DF96A6CULL,
		0x295A5D44A03F1E9FULL,
		0xE66F6A3F8B5BFEDAULL,
		0x949F15F27E5F3A48ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x51FCE7E852C075D3ULL,
		0x740BBFB59E738033ULL,
		0xF20C21589E540420ULL,
		0x6C4F74325CF31D5EULL,
		0x9F5A663AE43C06D4ULL,
		0xC90A7F6267AB2AC3ULL,
		0x698FAA7123485E6AULL,
		0xF2ADD1AC6A5EAD71ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 477\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 477 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -477;
	} else {
		printf("Test Case 477 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xC02A43DCE8EAE2AEULL,
		0xBC30DCA084ADA063ULL,
		0x6BA9001AD1972EB5ULL,
		0x2D2D99DEF90EB29AULL,
		0x872ECD6A4169255FULL,
		0x683BA3DD83364CABULL,
		0x3280BD83809A14F3ULL,
		0x0B6254561271DE27ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AB4E8C91D0E5FAAULL,
		0x8A975E938FD5EDABULL,
		0x20A144893FC7CF53ULL,
		0x4065A4843586D043ULL,
		0x7B6B4EB70AA7E9D8ULL,
		0x13DC99271A690924ULL,
		0xFD10DF57AB820D68ULL,
		0x3D19C10482429950ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x65755B13CBDC8304ULL,
		0x31997E0CF4D7B2B8ULL,
		0x4B07BB9191CF5F62ULL,
		0xECC7F55AC387E257ULL,
		0x0BC37EB336C13B86ULL,
		0x545F0AB668CD4387ULL,
		0x356FDE2BD518078BULL,
		0xCE489351902F44D6ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 478\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 478 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -478;
	} else {
		printf("Test Case 478 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4F066DC7CAA5DFEAULL,
		0xE03580D3B5287348ULL,
		0xF4E2EA6CEE5937F7ULL,
		0xF89F4B508E8FFF59ULL,
		0x57996EEB7180BE49ULL,
		0xD0DFB8B6B9B6ADA2ULL,
		0x178EAF05A2986219ULL,
		0xD929A8B598AA6F8CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B48A8AE17833FC2ULL,
		0xDDDC9ABF9AC828B7ULL,
		0x3D2D506A659ECBBFULL,
		0x340C9DAB50979A48ULL,
		0x268FA21C543BB1BBULL,
		0x600765542AED9F48ULL,
		0x024E51F107C1D6A2ULL,
		0xE35620D562C917E4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC3BDC519B322A028ULL,
		0x0258E6141A604A90ULL,
		0xB7B59A0288BA6C38ULL,
		0xC492ADA53DF86511ULL,
		0x3109CCCF1D450C8EULL,
		0x70D853628EC90E5AULL,
		0x15405D149AD68B77ULL,
		0xF5D387E035E157A8ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 479\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 479 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -479;
	} else {
		printf("Test Case 479 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xFCF842202558929FULL,
		0x1CE1548B569E66E1ULL,
		0x1BA3B52F71DF6DABULL,
		0x455DC41236C82BCFULL,
		0xDEE85521E0B63248ULL,
		0xF34660BE6B7F2B16ULL,
		0x9D1E5A00CB6A2E0FULL,
		0xEE4EBDD0EF9082DBULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x319C9D2AED725985ULL,
		0x028A60770C5046B3ULL,
		0x46AC87AA39157E16ULL,
		0x247F52DAA6FB902AULL,
		0x468116D967F58760ULL,
		0x2E9B96F6E371C158ULL,
		0x140B2EA26EA6AF9EULL,
		0xBB2AEDA813623B18ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCB5BA4F537E6391AULL,
		0x1A56F4144A4E202EULL,
		0xD4F72D8538C9EF95ULL,
		0x20DE71378FCC9BA4ULL,
		0x98673E4878C0AAE8ULL,
		0xC4AAC9C7880D69BEULL,
		0x89132B5E5CC37E71ULL,
		0x3323D028DC2E47C3ULL
	}};
	sign = 0;
	printf("Test Case 480\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 480 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -480;
	} else {
		printf("Test Case 480 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x348FBFA331B0A217ULL,
		0x7D3AC5C51842D37DULL,
		0x796825A5B7979E37ULL,
		0x8F4C9A306A86AC3DULL,
		0x91846B6645F90DE1ULL,
		0x68CA8079180F98CAULL,
		0x91890B3D4B33F6B6ULL,
		0xECC861019E3FB5E8ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9603998131FB992FULL,
		0x6247AF384E3DA866ULL,
		0xAA1B29BA264C0F3AULL,
		0x187BE536EF1018D8ULL,
		0x377B50B069628022ULL,
		0x5DC901A93507DA63ULL,
		0x58CC714970626CF3ULL,
		0x122FD31E229C1B6BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9E8C2621FFB508E8ULL,
		0x1AF3168CCA052B16ULL,
		0xCF4CFBEB914B8EFDULL,
		0x76D0B4F97B769364ULL,
		0x5A091AB5DC968DBFULL,
		0x0B017ECFE307BE67ULL,
		0x38BC99F3DAD189C3ULL,
		0xDA988DE37BA39A7DULL
	}};
	sign = 0;
	printf("Test Case 481\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 481 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -481;
	} else {
		printf("Test Case 481 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x173BB1DAFA57DADAULL,
		0xB5F16C2ED5E69CA0ULL,
		0xA88124CA114253EFULL,
		0xCF8D0BAD6A43527CULL,
		0xFCDDB6C42B33B671ULL,
		0xFE7911BF06830795ULL,
		0xA9F0714D0F6C1DBFULL,
		0xE0839EBFB408DCCFULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF10BB743C532F38ULL,
		0x52CAFD4E634620B8ULL,
		0x71528D09D33A1EE6ULL,
		0x4CD676B045446926ULL,
		0x3FE037C738840BD1ULL,
		0x04897B3617F0F69DULL,
		0xA77E7A2C88F4568DULL,
		0x9440B3A2D3270B3FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x482AF666BE04ABA2ULL,
		0x63266EE072A07BE7ULL,
		0x372E97C03E083509ULL,
		0x82B694FD24FEE956ULL,
		0xBCFD7EFCF2AFAAA0ULL,
		0xF9EF9688EE9210F8ULL,
		0x0271F7208677C732ULL,
		0x4C42EB1CE0E1D190ULL
	}};
	sign = 0;
	printf("Test Case 482\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 482 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -482;
	} else {
		printf("Test Case 482 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9E8B7DBF23D5FC3CULL,
		0x4D88CE90B6B41C3EULL,
		0xB60A31C7204FF25CULL,
		0xF00DF060544A64CDULL,
		0xC0772F562212227BULL,
		0x3FD91B84E660F89DULL,
		0x47F024A436558952ULL,
		0x7D29BC3E7A884467ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x05422685B10268A2ULL,
		0xB4A5B0571B456714ULL,
		0x6105869B67D9FD5DULL,
		0x20495A814972FB0CULL,
		0xE71B9BC04498608FULL,
		0x2F8F49D47CE8E6BEULL,
		0x08F7C18B95CA47B8ULL,
		0xEC15E8E36CAA47D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9949573972D3939AULL,
		0x98E31E399B6EB52AULL,
		0x5504AB2BB875F4FEULL,
		0xCFC495DF0AD769C1ULL,
		0xD95B9395DD79C1ECULL,
		0x1049D1B0697811DEULL,
		0x3EF86318A08B419AULL,
		0x9113D35B0DDDFC90ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 483\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 483 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -483;
	} else {
		printf("Test Case 483 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xA00B74860E43D690ULL,
		0xE304075293BCEE99ULL,
		0x62A50C174F7DBC99ULL,
		0xD02C25C69BE0A63FULL,
		0x791E0AD50C6E0889ULL,
		0x29B4F53E72908F51ULL,
		0x628F57256CC0AEBDULL,
		0xD3D1F91CF5B6568EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x21B236AAB4435A42ULL,
		0xCB82E4DFB6E94F98ULL,
		0xF136E86D5583305CULL,
		0x1D6E1004CEB709EDULL,
		0x486D1A5AF103BF21ULL,
		0xF6EA0300B722DA40ULL,
		0x53AC391F222F8970ULL,
		0x5906D4B5E96C979BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7E593DDB5A007C4EULL,
		0x17812272DCD39F01ULL,
		0x716E23A9F9FA8C3DULL,
		0xB2BE15C1CD299C51ULL,
		0x30B0F07A1B6A4968ULL,
		0x32CAF23DBB6DB511ULL,
		0x0EE31E064A91254CULL,
		0x7ACB24670C49BEF3ULL
	}};
	sign = 0;
	printf("Test Case 484\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 484 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -484;
	} else {
		printf("Test Case 484 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xADC2036B72A8EE31ULL,
		0x48D9C852CB914B37ULL,
		0xC5A9DB802E3DBDB9ULL,
		0x258894550DA5FFC5ULL,
		0x05433B3D925410A9ULL,
		0xC3194A084549CF7CULL,
		0xF8E282FABA9244F1ULL,
		0x0E6308D52232C62CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0161FF96F10FB50ULL,
		0x591903A22F69CC8DULL,
		0x2E9E8E1887CCEBCFULL,
		0xB667C1261426297BULL,
		0xAFDAAB4B6D0DBC3FULL,
		0x2BD65EB4EF67899CULL,
		0x071D3EA318D0B97DULL,
		0xCEC6DF3813B39C21ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFDABE3720397F2E1ULL,
		0xEFC0C4B09C277EA9ULL,
		0x970B4D67A670D1E9ULL,
		0x6F20D32EF97FD64AULL,
		0x55688FF225465469ULL,
		0x9742EB5355E245DFULL,
		0xF1C54457A1C18B74ULL,
		0x3F9C299D0E7F2A0BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 485\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 485 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -485;
	} else {
		printf("Test Case 485 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x6576033F057DF1ADULL,
		0x5F314682CC45180AULL,
		0x9625CF51B2EA5837ULL,
		0xD7BA2A70F5B14CD5ULL,
		0x4A6CCAF574583F58ULL,
		0x193202B9118470BAULL,
		0x73EBC05E9841F40DULL,
		0x8A2F1B74FF9C0C51ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A19F9F7376AFF6DULL,
		0xD000992F6A54DBCAULL,
		0xA28A65B791C9428CULL,
		0xF6FB47079AB3A6E7ULL,
		0xFDA6E8EDB05CA9B2ULL,
		0x8BCDDF1BBD7CE657ULL,
		0x85B2253DD9A000B8ULL,
		0x3B263D8677B2FF6CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCB5C0947CE12F240ULL,
		0x8F30AD5361F03C3FULL,
		0xF39B699A212115AAULL,
		0xE0BEE3695AFDA5EDULL,
		0x4CC5E207C3FB95A5ULL,
		0x8D64239D54078A62ULL,
		0xEE399B20BEA1F354ULL,
		0x4F08DDEE87E90CE4ULL
	}};
	sign = 0;
	printf("Test Case 486\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 486 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -486;
	} else {
		printf("Test Case 486 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x33ED875F1FFFF47EULL,
		0x6272323FDFB7EF85ULL,
		0x36F17671CDE727F1ULL,
		0x5996F3A6A0130D22ULL,
		0x065612FE64ACF357ULL,
		0xDE263E165DE59588ULL,
		0x592B9A24316DE9C0ULL,
		0x571E567FAE0DE065ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x8386A8E46B31D992ULL,
		0x96AE98BBE328C132ULL,
		0x753E9FA0852E6521ULL,
		0xB457A3F44CB03646ULL,
		0x2B89EBE5DCB365C6ULL,
		0x211F4366053E607FULL,
		0xD3867F0BE5A52FF6ULL,
		0x8A93BC6C9CFBC5D2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB066DE7AB4CE1AECULL,
		0xCBC39983FC8F2E52ULL,
		0xC1B2D6D148B8C2CFULL,
		0xA53F4FB25362D6DBULL,
		0xDACC271887F98D90ULL,
		0xBD06FAB058A73508ULL,
		0x85A51B184BC8B9CAULL,
		0xCC8A9A1311121A92ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 487\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 487 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -487;
	} else {
		printf("Test Case 487 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x75277CC3CCD32678ULL,
		0xD21F575B984ACE53ULL,
		0x832DF06F5F748851ULL,
		0xE14826DCFEA2F86AULL,
		0x6660B5135DDCD8FAULL,
		0xA4D79A9280A31793ULL,
		0x8872BDC3A381BEA7ULL,
		0xA35E2998990BDE1EULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7D9D388E346969CULL,
		0x2B7A7DE1FB5DE292ULL,
		0x260B75BC4437D148ULL,
		0xA3B708BB02AC1D3BULL,
		0x8FD3BC27E1E0F4F4ULL,
		0x38E9342181544E74ULL,
		0xDBE201B0CC037107ULL,
		0x68EADDC3402AA69AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCD4DA93AE98C8FDCULL,
		0xA6A4D9799CECEBC0ULL,
		0x5D227AB31B3CB709ULL,
		0x3D911E21FBF6DB2FULL,
		0xD68CF8EB7BFBE406ULL,
		0x6BEE6670FF4EC91EULL,
		0xAC90BC12D77E4DA0ULL,
		0x3A734BD558E13783ULL
	}};
	sign = 0;
	printf("Test Case 488\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 488 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -488;
	} else {
		printf("Test Case 488 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9F2DC54FA0083B0FULL,
		0xD56D44CA75E328AFULL,
		0x9259762A9F1564C5ULL,
		0x2B6AC764C49E4EF1ULL,
		0x07A68C036A65EF30ULL,
		0xE6268FEDD29C8F59ULL,
		0x4CB3029B70134C9CULL,
		0x828B5B8C52A5B3DAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8E0998B23B5A7D8ULL,
		0xB4E19C8782D3A035ULL,
		0x9DACE0477B637D52ULL,
		0x5D610A46A661BA95ULL,
		0x3F0E626C442BBAC3ULL,
		0x47859E8E501D19E8ULL,
		0x4DE385397D5D5052ULL,
		0x6210A731858AFE87ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB64D2BC47C529337ULL,
		0x208BA842F30F8879ULL,
		0xF4AC95E323B1E773ULL,
		0xCE09BD1E1E3C945BULL,
		0xC8982997263A346CULL,
		0x9EA0F15F827F7570ULL,
		0xFECF7D61F2B5FC4AULL,
		0x207AB45ACD1AB552ULL
	}};
	sign = 0;
	printf("Test Case 489\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 489 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -489;
	} else {
		printf("Test Case 489 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xD184B175F98D13FDULL,
		0xB0B98195BC7D4A2AULL,
		0x35FA893C8F3E2A48ULL,
		0x4AA4622529D7EA38ULL,
		0x027CBCC00EF8D879ULL,
		0xFFD5F4966A3EA3DEULL,
		0x8F283872EF8B8220ULL,
		0x82BA905C7F252789ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F142B2FFAEF585EULL,
		0x332B1DA000BA7068ULL,
		0xA9C5A113397A28FAULL,
		0xC7C99FDF88799493ULL,
		0x026B47220B88B1CDULL,
		0x03F809BAD5D76A68ULL,
		0x05754434028DF2F4ULL,
		0xE47EA8A2C51CE649ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA2708645FE9DBB9FULL,
		0x7D8E63F5BBC2D9C2ULL,
		0x8C34E82955C4014EULL,
		0x82DAC245A15E55A4ULL,
		0x0011759E037026ABULL,
		0xFBDDEADB94673976ULL,
		0x89B2F43EECFD8F2CULL,
		0x9E3BE7B9BA084140ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 490\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 490 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -490;
	} else {
		printf("Test Case 490 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x59E16E893184BBBEULL,
		0x9DBA6F1C9D3D7013ULL,
		0x9A0C6E2F1353CB01ULL,
		0x2CFBC9CBE44737EBULL,
		0xB49FA5B662B04039ULL,
		0x15CDEA61A62DC551ULL,
		0xA673F09638A3FC0CULL,
		0x67DCABC1B6A36ED4ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x23C671530CA8A582ULL,
		0x62F3B09349C39D89ULL,
		0x78CBE5DBEC4ADA45ULL,
		0x54059A04B966C00BULL,
		0x6CDD974C1B40C69CULL,
		0xFE1AA2779C885A6CULL,
		0xD7FF8A328C08E97BULL,
		0xF44C60E3369B60A8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x361AFD3624DC163CULL,
		0x3AC6BE895379D28AULL,
		0x214088532708F0BCULL,
		0xD8F62FC72AE077E0ULL,
		0x47C20E6A476F799CULL,
		0x17B347EA09A56AE5ULL,
		0xCE746663AC9B1290ULL,
		0x73904ADE80080E2BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 491\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 491 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -491;
	} else {
		printf("Test Case 491 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x9D8FCF973AE65368ULL,
		0x764FAC6D3CA73B78ULL,
		0xBA02A7D70374A825ULL,
		0x65992F7BB59FC185ULL,
		0x0B7C42A02D9994C9ULL,
		0x9FE72155C9BA3E5FULL,
		0x6BF68FBBF0E55B39ULL,
		0x55CC5A9C46EE860CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA3335CB7DE25E99ULL,
		0x7D329ADF2623293FULL,
		0x0A628040875C1E8AULL,
		0xC452B0DBACCBEEFFULL,
		0x039A3D7DAE57587BULL,
		0xEDC59F24DC5F2F19ULL,
		0x12527F449A00207EULL,
		0x824C4CE25E808D9EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC35C99CBBD03F4CFULL,
		0xF91D118E16841238ULL,
		0xAFA027967C18899AULL,
		0xA1467EA008D3D286ULL,
		0x07E205227F423C4DULL,
		0xB2218230ED5B0F46ULL,
		0x59A4107756E53ABAULL,
		0xD3800DB9E86DF86EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 492\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 492 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -492;
	} else {
		printf("Test Case 492 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xAEE1868326DA9185ULL,
		0xC76C2B990BD4D70AULL,
		0x1E6E109DA308D78DULL,
		0xD9321BC368CF3C8BULL,
		0x0ECF3D9698AC3E1AULL,
		0x5445D9C49DC5CD4BULL,
		0x57541820ED193B23ULL,
		0x151C1FD502E4AF0CULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD9AAFF5625C6CA7ULL,
		0x5F28B0E46B85E3BDULL,
		0x3B8C4580233D3538ULL,
		0x2C7AFC07C34083D2ULL,
		0xBF19670FA61394C8ULL,
		0x9C7589E97D176493ULL,
		0x5A055CC743486AC2ULL,
		0x480AB89B50FD584DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0146D68DC47E24DEULL,
		0x68437AB4A04EF34DULL,
		0xE2E1CB1D7FCBA255ULL,
		0xACB71FBBA58EB8B8ULL,
		0x4FB5D686F298A952ULL,
		0xB7D04FDB20AE68B7ULL,
		0xFD4EBB59A9D0D060ULL,
		0xCD116739B1E756BEULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 493\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 493 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -493;
	} else {
		printf("Test Case 493 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x69F7E1624528C2E4ULL,
		0xF41383BCC9C11ED8ULL,
		0x484FC8F920D30EC9ULL,
		0x33B7F24F28B23D19ULL,
		0x8F86D3C2A23ADDA2ULL,
		0x8B34602C01526581ULL,
		0x906D1497BADB423FULL,
		0x6D284CF397741E52ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x469F2284EC74C445ULL,
		0x283A6452C085E73BULL,
		0xC646259A0445ED85ULL,
		0xAEB49249535964C7ULL,
		0xCE46E109EDA8A9B0ULL,
		0xDFF519753DC0687FULL,
		0xED57988D7A1EF4BAULL,
		0x4CF1077B0F8F5173ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2358BEDD58B3FE9FULL,
		0xCBD91F6A093B379DULL,
		0x8209A35F1C8D2144ULL,
		0x85036005D558D851ULL,
		0xC13FF2B8B49233F1ULL,
		0xAB3F46B6C391FD01ULL,
		0xA3157C0A40BC4D84ULL,
		0x2037457887E4CCDEULL
	}};
	sign = 0;
	printf("Test Case 494\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 494 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -494;
	} else {
		printf("Test Case 494 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x164519CA67AFA598ULL,
		0xA422C643B7703257ULL,
		0x91AC12B95E14450BULL,
		0x8A4E43A6EC9E4E87ULL,
		0xB32AD9585E7A5CEFULL,
		0xE94FDA68379FA8A4ULL,
		0xA14D81997A10859EULL,
		0x23DBFFA6686AB9EAULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F0760AF813F049EULL,
		0xD53FF7E7B632375DULL,
		0x71593655E25333C4ULL,
		0x54620D70F6454CECULL,
		0x12129310992AA1F3ULL,
		0x7F6C792AB1B55E63ULL,
		0xDE548886FDE4F330ULL,
		0xE79346916827521EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD73DB91AE670A0FAULL,
		0xCEE2CE5C013DFAF9ULL,
		0x2052DC637BC11146ULL,
		0x35EC3635F659019BULL,
		0xA1184647C54FBAFCULL,
		0x69E3613D85EA4A41ULL,
		0xC2F8F9127C2B926EULL,
		0x3C48B915004367CBULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 495\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 495 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -495;
	} else {
		printf("Test Case 495 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0xB7FAC49104963743ULL,
		0x188A2E0F25118D24ULL,
		0xD66AAAF507D10EAEULL,
		0x5FAAC15B8069A160ULL,
		0x67061F1E18C89771ULL,
		0xEC355B32DDC4C4DAULL,
		0xA2E59BE1E0AE2937ULL,
		0xE0DD0E64D99C69ECULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6607E7D78FD874DULL,
		0x20C788D25D0EC9C6ULL,
		0x9F5DB8B3C1EEA5C2ULL,
		0xE75A9DBA14CFE003ULL,
		0x0FAD45E37E84523EULL,
		0xD348BD2D96B99066ULL,
		0xB8C35D1C22209740ULL,
		0xAF61D1F18A0AFF8BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF19A46138B98AFF6ULL,
		0xF7C2A53CC802C35DULL,
		0x370CF24145E268EBULL,
		0x785023A16B99C15DULL,
		0x5758D93A9A444532ULL,
		0x18EC9E05470B3474ULL,
		0xEA223EC5BE8D91F7ULL,
		0x317B3C734F916A60ULL
	}};
	sign = 0;
	printf("Test Case 496\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 496 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -496;
	} else {
		printf("Test Case 496 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x4E1CB995DDD2FBE3ULL,
		0xFCDB531BEAE18975ULL,
		0x7246EA1703A1F940ULL,
		0xEC9CD2A9440B982AULL,
		0xD8EBBC76003E28FCULL,
		0x0BE636388642EB5CULL,
		0x8B6B89ED86EA5D37ULL,
		0x32E62978E23F7EC6ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0x1753AD30374F8F49ULL,
		0x4A92CD29CB3447A0ULL,
		0x9B2CD1E887F6B06FULL,
		0x65DFC411B2B0F1CCULL,
		0x25A6451E985F062CULL,
		0x9D609B5DFE8DCCEEULL,
		0x0AB9BC2E0DCCA1D3ULL,
		0x7D2F0C6115A806E9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x36C90C65A6836C9AULL,
		0xB24885F21FAD41D5ULL,
		0xD71A182E7BAB48D1ULL,
		0x86BD0E97915AA65DULL,
		0xB345775767DF22D0ULL,
		0x6E859ADA87B51E6EULL,
		0x80B1CDBF791DBB63ULL,
		0xB5B71D17CC9777DDULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 497\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 497 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -497;
	} else {
		printf("Test Case 497 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x0D8926C34283E6B2ULL,
		0x7DAF60650575F632ULL,
		0x0993A66030140FADULL,
		0x66A65F840B1240F1ULL,
		0xF59B0C8A2C30D2D6ULL,
		0x7456E30DB1940131ULL,
		0x7A010BF36EEC12AAULL,
		0x29937E212AACC751ULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7FA884A65BC2BAFULL,
		0xDC09FA93C6996A7FULL,
		0x874A7CD64F9581A4ULL,
		0x2525440311EEBE66ULL,
		0x9974D8282B0C2DECULL,
		0xB2EC11217EE856BFULL,
		0xB1361C50B7C9CD7AULL,
		0x709C9686305E9610ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x458E9E78DCC7BB03ULL,
		0xA1A565D13EDC8BB2ULL,
		0x82492989E07E8E08ULL,
		0x41811B80F923828AULL,
		0x5C2634620124A4EAULL,
		0xC16AD1EC32ABAA72ULL,
		0xC8CAEFA2B722452FULL,
		0xB8F6E79AFA4E3140ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 498\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 498 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -498;
	} else {
		printf("Test Case 498 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x52738A99CC7CD4ECULL,
		0x7832CBF8C3279E94ULL,
		0x9F57EDF2351B2262ULL,
		0xF3EC4B1984CE25D0ULL,
		0x3732A25EEC15FF04ULL,
		0xF89ACBE9E515C4B2ULL,
		0x4199CE7C9B1CC3C0ULL,
		0x8E435934FCCE359FULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xD870C9887FD5F1BCULL,
		0x37A081E797575A6AULL,
		0xEE52355D2123832CULL,
		0xFD9C3C4832B512DCULL,
		0x0343D8F042FD72A3ULL,
		0x804548D54AAD51DAULL,
		0xC1E01929BDDE5D8FULL,
		0x859AD7FD0112D7F0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7A02C1114CA6E330ULL,
		0x40924A112BD04429ULL,
		0xB105B89513F79F36ULL,
		0xF6500ED1521912F3ULL,
		0x33EEC96EA9188C60ULL,
		0x785583149A6872D8ULL,
		0x7FB9B552DD3E6631ULL,
		0x08A88137FBBB5DAEULL
	}};
	sign = 0;
	printf("Test Case 499\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 499 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -499;
	} else {
		printf("Test Case 499 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_signed_t){.key = {.key64 = {
		0x944601755C3A8071ULL,
		0x958BE4F147BC58B4ULL,
		0x49A9AB1676180EB4ULL,
		0x51F5213CADE0CD98ULL,
		0xDCEB5909AEAD1618ULL,
		0x5E95AD06DB4E54BDULL,
		0x895972C5FD78FCABULL,
		0x71BF77F73128F9AEULL
	}}};
	k2 = (curve25519_key_t){.key64 = {
		0xE76C85986E143A79ULL,
		0xB6DC21A751CCB62DULL,
		0xF8CC6C687541D9FCULL,
		0x47AEA793BACC8DACULL,
		0x6C5AA27947051CE1ULL,
		0x527E476E3A725129ULL,
		0x036E5EB797828F46ULL,
		0x2509CDBA15C87F16ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xACD97BDCEE2645F8ULL,
		0xDEAFC349F5EFA286ULL,
		0x50DD3EAE00D634B7ULL,
		0x0A4679A8F3143FEBULL,
		0x7090B69067A7F937ULL,
		0x0C176598A0DC0394ULL,
		0x85EB140E65F66D65ULL,
		0x4CB5AA3D1B607A98ULL
	}};
	sign = 0;
	printf("Test Case 500\n");
	printf("k1:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&k1.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 500 FAILED\n");
		curve25519_key_printf(&k1.key, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -500;
	} else {
		printf("Test Case 500 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}