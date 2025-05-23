#include "../tests.h"

int32_t curve25519_key_cmp_test(void) {
	printf("Key Comparison Test\n");
	curve25519_key_t k1 = {.key64 = {
		0xD2B7A5667D423CE3ULL,
		0x7AF80444FAF7909BULL,
		0x6D0BA4FD73895AD3ULL,
		0xB28477863F0F4A29ULL,
		0x4787296539CA4CA7ULL,
		0xBE652BB12BA3825EULL,
		0x85A093042BD50022ULL,
		0x16CBC86A1ED5708EULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x832410D013190453ULL,
		0x226D6CF0493695CDULL,
		0xD236509635AD5EB9ULL,
		0xD11A4EE9BAF28526ULL,
		0xD95D34A1371A0823ULL,
		0xDA8F67096D4A36EAULL,
		0xFF9459CAB88CAA48ULL,
		0x29710FA998B40AFFULL
	}};
	int t = -1;
	printf("Test Case 1\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	int32_t res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 1 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x893A3FB2E3B76696ULL,
		0x26C0F0FD492C199DULL,
		0x63FE413850D730B0ULL,
		0xA91FC15E5B91EF0BULL,
		0x58BFC13A35414A78ULL,
		0xBA882F7D4CF9A9CCULL,
		0x552B678F58E7B3CCULL,
		0x518CAD49ADFCDC0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E3FD8E8F22391EFULL,
		0x680B9BFF9AF550B2ULL,
		0x29F63DB900C8ED42ULL,
		0x1924108C1AD97560ULL,
		0x06B909FCECBAF4D0ULL,
		0x82D82C0F9A40D8B6ULL,
		0xD6D0B966C1EC34BEULL,
		0x5B8A10D9863565E9ULL
	}};
	t = -1;
	printf("Test Case 2\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 2 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3B41311331C20698ULL,
		0x38AF48639C9A63E4ULL,
		0xD14258C0EDE9F91EULL,
		0x4AFAE08DCE90EF0EULL,
		0x4C43999D59E8C848ULL,
		0xDA0FCC93DC7F942CULL,
		0xC337BC0B783E6DDCULL,
		0x1D8D8BFADB30D929ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DB9EBC97F09CFBFULL,
		0x6AC741643055143FULL,
		0x0F16A98F424439F7ULL,
		0xB4029CFB4F78124EULL,
		0x10E31CA4A71C1E20ULL,
		0x2EF81B14A793AE36ULL,
		0x342D58AB389F43EEULL,
		0x6B0E95093967E69CULL
	}};
	t = -1;
	printf("Test Case 3\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 3 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0377D22E0636990AULL,
		0x49B078B91174281FULL,
		0x0BBB4908898D76C9ULL,
		0xD87D6A971052B99FULL,
		0x83519E8F819ACEFDULL,
		0xF36BA028872058C0ULL,
		0xF2AE5EF0DC23B26FULL,
		0xCFA74C2D4D50320AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB90E31FB9D6BA34EULL,
		0x4BB398F6EF759972ULL,
		0x48B02AF15CE761EAULL,
		0xAB1125A8F07FB424ULL,
		0xC399379DAD9FA52DULL,
		0x99305D52CF2674AFULL,
		0x65BFB01D3CF4E3EAULL,
		0x96BDB93B2DE65D15ULL
	}};
	t = 1;
	printf("Test Case 4\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 4 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1E37BC783AB8358FULL,
		0x5C59A57352DD6B34ULL,
		0x026FAC345CF60D32ULL,
		0xD726D756E1C1463AULL,
		0x1B12525CE3566262ULL,
		0x2F8368DD1B5BE37FULL,
		0x627E73B607345057ULL,
		0xC66288CAA26432F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E37BC783AB8358FULL,
		0x5C59A57352DD6B34ULL,
		0x026FAC345CF60D32ULL,
		0xD726D756E1C1463AULL,
		0x1B12525CE3566262ULL,
		0x2F8368DD1B5BE37FULL,
		0x627E73B607345057ULL,
		0xC66288CAA26432F3ULL
	}};
	t = 0;
	printf("Test Case 5\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 5 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7B66B8A6043F48DFULL,
		0xA3F4028DF3B2C9C7ULL,
		0xE3034919ADABDB91ULL,
		0x8EE9FAEB163DC894ULL,
		0xCACA471DC145E95AULL,
		0x3F76711B18AC17A5ULL,
		0x20BD8C43817B9044ULL,
		0x4627FB1768C97E08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF09FCFAAE5D1D40AULL,
		0xAF0677E3E2273BA4ULL,
		0xE8EF40938A6918B6ULL,
		0xAF0B74BB4F5EB84DULL,
		0x083F35E38E1D1681ULL,
		0x4176F3097AF0C35AULL,
		0xAE6680A63E79396AULL,
		0xC8B887BC222C0B81ULL
	}};
	t = -1;
	printf("Test Case 6\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 6 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE434B98066590421ULL,
		0xD4EC6E7C86D01C8FULL,
		0x42F76197817287ABULL,
		0x8BD7C580F226B6A2ULL,
		0x8E3D6A7C51D0610CULL,
		0x205AE963891F895AULL,
		0x4A34483C820A6420ULL,
		0x50231E66131D4DE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C5F5F51062C75A2ULL,
		0xF125E44B9DBFA051ULL,
		0x7D3E5E087B2348C9ULL,
		0x450A63808F78F343ULL,
		0xFD23B54D1F00E222ULL,
		0x810E36395C4C50BFULL,
		0x2B776EFAE23DA4B5ULL,
		0x283DE4499F5D8CEDULL
	}};
	t = 1;
	printf("Test Case 7\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 7 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x80C102C8A0A335E7ULL,
		0x83EA9FE0D2ED45B9ULL,
		0x02FBBB6C0A3593A2ULL,
		0x2D49A52E06F75C22ULL,
		0x8EF7BCB73A9595F0ULL,
		0x8C2C27903830433EULL,
		0xC35705F25224AEC3ULL,
		0x07B143EB9E56E3BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F0CBF081FF289A5ULL,
		0x322C9BE6ED6FE8A7ULL,
		0x9F0CC94E09C16625ULL,
		0xE6EF12F4CCF842AFULL,
		0x918CFC63C7942934ULL,
		0x9496057CC8BE7DA3ULL,
		0xDDAC3642261DD411ULL,
		0xA90869079C2EC594ULL
	}};
	t = -1;
	printf("Test Case 8\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 8 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA31617DEF18E79DFULL,
		0x2DD5FA9455A2A798ULL,
		0x8EC29B4A13FFB10BULL,
		0x82D7EFAE59B5E721ULL,
		0xBA656D94AEED3DB8ULL,
		0x16E15C87D9244D05ULL,
		0x1DF87B666B3BB0F5ULL,
		0xA0FF6091A57E4D99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA31617DEF18E79DFULL,
		0x2DD5FA9455A2A798ULL,
		0x8EC29B4A13FFB10BULL,
		0x82D7EFAE59B5E721ULL,
		0xBA656D94AEED3DB8ULL,
		0x16E15C87D9244D05ULL,
		0x1DF87B666B3BB0F5ULL,
		0xA0FF6091A57E4D99ULL
	}};
	t = 0;
	printf("Test Case 9\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 9 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9F4D049CC10429B7ULL,
		0x16AA27BC9F6A6AC1ULL,
		0xAA5D19E4001D235FULL,
		0xA2DFE66F0B6E05EAULL,
		0x1F4CAB4091300632ULL,
		0xE2AD881F84938C6CULL,
		0xE5717556E7E6B494ULL,
		0x0864E50280714DA0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA974F0DE589451CULL,
		0x077951CEA9222228ULL,
		0xA48C09BDC540BC2AULL,
		0xACD691FD4FA74F5BULL,
		0x7D191E682CFD0FAAULL,
		0xB842BF0C145D5206ULL,
		0x30A64C60584CB7C4ULL,
		0xF313DA922B8BB509ULL
	}};
	t = -1;
	printf("Test Case 10\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 10 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x37C881B2F6F2B765ULL,
		0x11FFF2B273C26DB2ULL,
		0x32D47D8E123238DFULL,
		0x31163269DD0277CDULL,
		0xD489121BB25FBCA3ULL,
		0xB2E77DD2C1A053C9ULL,
		0xB690D4EA96FECC48ULL,
		0x70A6A2F1CB7A8CAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B8478DC7E62A140ULL,
		0xBFD2E33945CF3C97ULL,
		0x3C2DA1F79830B229ULL,
		0x9D6BEE833E831FEEULL,
		0x5EAFE488D094BAAAULL,
		0xF8DE3EA767130AF9ULL,
		0x9BD6882FFE093995ULL,
		0x4D68355D9A96EABCULL
	}};
	t = 1;
	printf("Test Case 11\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 11 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2ED8526A781CD963ULL,
		0xAC71EADEFBE3AE8AULL,
		0xC35D240FB54BE704ULL,
		0xD63202A8D4A2BC32ULL,
		0x8774D0E6500D9606ULL,
		0x4D6B87C2697B2659ULL,
		0xB4F2FC8627912E16ULL,
		0x4A40A74B0622BF3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD15A32B4FE107DE7ULL,
		0xEF3F0508C2EDF295ULL,
		0xF4DA9F4121014A12ULL,
		0x3B8697BE029EB5F9ULL,
		0x32140AD5F31B7ACEULL,
		0x92FC50FE807998FEULL,
		0xDC46F1D6D043B9B7ULL,
		0x48C79A067883B9FFULL
	}};
	t = 1;
	printf("Test Case 12\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 12 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBE57889D5A54C624ULL,
		0xE3543E06C28C3518ULL,
		0x508AE084A93CA714ULL,
		0xF86DCCE9808B91ECULL,
		0x247383FD701F1F4AULL,
		0xCED2732FDD27096BULL,
		0x69F832C99613D486ULL,
		0xDA69C946D05E709FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE57889D5A54C624ULL,
		0xE3543E06C28C3518ULL,
		0x508AE084A93CA714ULL,
		0xF86DCCE9808B91ECULL,
		0x247383FD701F1F4AULL,
		0xCED2732FDD27096BULL,
		0x69F832C99613D486ULL,
		0xDA69C946D05E709FULL
	}};
	t = 0;
	printf("Test Case 13\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 13 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x78B42895B0414847ULL,
		0xE644A88E20ACF5EFULL,
		0x5A69A36AD3966179ULL,
		0xE848CE813E9F71B0ULL,
		0xECB33DFC2EDC31A0ULL,
		0xE92C55350EEBF860ULL,
		0xEE889071F04CC80DULL,
		0x890C32EF6281DB1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x543E2FEAC0C958B6ULL,
		0xA5B4F6454540778DULL,
		0x1BDA81E3E59D7CEBULL,
		0xD32E5616052409FEULL,
		0xA45DED06211B9DE5ULL,
		0x597B6B6515956FFDULL,
		0x0F1BB123409ABA33ULL,
		0xB49E49C6776345A2ULL
	}};
	t = -1;
	printf("Test Case 14\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 14 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7A165145B8C4BB53ULL,
		0xB650031300AA3B1BULL,
		0xCB9A8BA37847A0E9ULL,
		0x1E4F7F10C4CDE913ULL,
		0xD1DC2C4DA11A36AEULL,
		0x83610CA2AD7EFA37ULL,
		0x2116923CAB6841BCULL,
		0x2F73EC482126FB54ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2648E92FF1EC70C2ULL,
		0xB70DAD33CED60FDBULL,
		0x87D81C56F77AD253ULL,
		0x447C9B21F449C049ULL,
		0x84F113DA882D785DULL,
		0x5995476882D98C02ULL,
		0x8E93CAEA8D1965D2ULL,
		0x8E86CFEAC209A455ULL
	}};
	t = -1;
	printf("Test Case 15\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 15 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1F65ADBAAA9D5F95ULL,
		0x4EB8B89646CD8734ULL,
		0xEA6F4CE20E4687ECULL,
		0xF0509F2FD42465D9ULL,
		0xE9A53CDA4556C770ULL,
		0xC21E294DF0AAFAABULL,
		0x5300C69AD9B33663ULL,
		0xEF5B7EFD18135309ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6BB300DD02B81AC8ULL,
		0x661F4E98780AEBEEULL,
		0x8004C6E14614ACB2ULL,
		0xD4D83290C033AB6DULL,
		0xF63AF703F2FA5CB0ULL,
		0x920B5B9881A12B39ULL,
		0xA6E942D052208138ULL,
		0xE64C33B45ECA4B85ULL
	}};
	t = 1;
	printf("Test Case 16\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 16 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x62057D1DA593D7F9ULL,
		0x675DA33542758727ULL,
		0x35A7F718F4E3575DULL,
		0x0333E659BAE5A87FULL,
		0x2124B736EA979AD0ULL,
		0x80FBC24CF3204546ULL,
		0x6AE5E0ADAE652795ULL,
		0x3A0031DB30F91D2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62057D1DA593D7F9ULL,
		0x675DA33542758727ULL,
		0x35A7F718F4E3575DULL,
		0x0333E659BAE5A87FULL,
		0x2124B736EA979AD0ULL,
		0x80FBC24CF3204546ULL,
		0x6AE5E0ADAE652795ULL,
		0x3A0031DB30F91D2EULL
	}};
	t = 0;
	printf("Test Case 17\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 17 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5CA29D5B7BB57CAAULL,
		0xFAE9057786488D9AULL,
		0xEED9A61CBF766346ULL,
		0xCA001AB7C7E0D5A5ULL,
		0xC79DD3352D9CC0D1ULL,
		0x45C0B4E8A6C2FE5EULL,
		0x873FE09CF4A4795CULL,
		0x41F77B7B0EDDACDEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63B8D2B2CF3F3DE1ULL,
		0xDBD9551AA75C842FULL,
		0x9639EABE526BE5A0ULL,
		0xA2A0FA95B8BA78BEULL,
		0xA9984749E8E695F3ULL,
		0xAD4866D0394EDE66ULL,
		0xE63391BAA6E8751FULL,
		0x54CE5F06CE93C01BULL
	}};
	t = -1;
	printf("Test Case 18\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 18 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB90FBC32A1035150ULL,
		0x48CBF70086DCE3C7ULL,
		0x0D6F140025C3D91EULL,
		0xF74BEC13A864E466ULL,
		0x5DC4023C6BD0747DULL,
		0xE0987B4258E1D907ULL,
		0xC345C01476406E58ULL,
		0x998B9C7C97DFA362ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFE4EAC6CE360F7AULL,
		0x5DAF42C8CAB1F1F9ULL,
		0xFD59384355E29451ULL,
		0xD0EB561D5C8CAAB4ULL,
		0xA0D3FEB36F3031EAULL,
		0x0962490E96C4598BULL,
		0xC06093A94DC4F7DCULL,
		0xD4DF69EF6F7CBE82ULL
	}};
	t = -1;
	printf("Test Case 19\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 19 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8307F03A43DEA466ULL,
		0x8AF64C4FACF785BCULL,
		0xB72BF928549F8C63ULL,
		0x42D8CECF7A19FD76ULL,
		0x776429941F6127F5ULL,
		0x8D9CC288E707B59AULL,
		0x8DE47EEC2258D0FBULL,
		0xFF5BCCD8A652C3C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0160A5A177E7E3F2ULL,
		0x8B03A860B85FFD24ULL,
		0x8F7C2958CA8AD2FCULL,
		0x17F369C48E556115ULL,
		0x408D4836A9F26398ULL,
		0x2F9298024FC8BE5DULL,
		0xBC01C67FA38AE235ULL,
		0xCBB246E4C3A637D7ULL
	}};
	t = 1;
	printf("Test Case 20\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 20 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFA688D4F12AADC87ULL,
		0x9F9C092806D0C9B7ULL,
		0xB2443A329D32608AULL,
		0xA6BA52FF08954CC1ULL,
		0x98911A237EBFC339ULL,
		0x127ACBCEF70F0A31ULL,
		0x9CC9BE598E714FAFULL,
		0x5A7813F8A4489575ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA688D4F12AADC87ULL,
		0x9F9C092806D0C9B7ULL,
		0xB2443A329D32608AULL,
		0xA6BA52FF08954CC1ULL,
		0x98911A237EBFC339ULL,
		0x127ACBCEF70F0A31ULL,
		0x9CC9BE598E714FAFULL,
		0x5A7813F8A4489575ULL
	}};
	t = 0;
	printf("Test Case 21\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 21 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB050EEA97EE73B2FULL,
		0x5B96A93FFB16C79AULL,
		0x7BA3E9B2CD541677ULL,
		0xA4D58DB2E1E30CDDULL,
		0x0496AF96FB1FC262ULL,
		0x345AD595590564DEULL,
		0x317566074F75AC47ULL,
		0x83ACA3B097E7F317ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F1413701FDC52AFULL,
		0xB5BE4CAD6DBC4FDFULL,
		0xADDC51CCABD00D48ULL,
		0x5EF89BAADA94E38CULL,
		0x258A4960E17AC1F8ULL,
		0x17CE328CCD52952BULL,
		0xB2C57BFEF9B1FB69ULL,
		0x152743EA78C25878ULL
	}};
	t = 1;
	printf("Test Case 22\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 22 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCF61239A5183DFF4ULL,
		0xB9FC167E075A1537ULL,
		0x8145D21EA793136BULL,
		0xAAA1ECE6A77D86DAULL,
		0x83AE121B58361C73ULL,
		0xCC3CC6C724548AFBULL,
		0xF88A1D81EE0C2AA9ULL,
		0xF2F4A47848433CBFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84EB7296F3F8CE54ULL,
		0x7E895258F62B8DC2ULL,
		0x1AE9ED53C38DF6A1ULL,
		0xB09037D7219C0475ULL,
		0x872E13672F45D395ULL,
		0xCC8D3D17DE2C179DULL,
		0xAEDBB081253E1366ULL,
		0x76AF9A58D7738424ULL
	}};
	t = 1;
	printf("Test Case 23\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 23 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDDA66680CBD03A42ULL,
		0x922BDC313BEC1018ULL,
		0x1F5A477D2C211D2CULL,
		0xA196581C58032BB6ULL,
		0x584328CEA9EB8ADBULL,
		0x299AC2C0110AF989ULL,
		0x73E2CDBF8B5550FFULL,
		0xE39BCB1CFC6F743DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD71A0FA32043A073ULL,
		0xD9900E9FA382E8E7ULL,
		0x3F7F8FE17848E975ULL,
		0x96F24D2B050813EEULL,
		0xA347939A2BDB625BULL,
		0x6561A79670433220ULL,
		0xBD18F473D5B25634ULL,
		0x5C236ED44C459871ULL
	}};
	t = 1;
	printf("Test Case 24\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 24 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x70737469AE718430ULL,
		0x583EFC9C8403433EULL,
		0xD92C19FE33852A11ULL,
		0xEB3492FB8D140D08ULL,
		0xBA0AC41C323265E2ULL,
		0xCD209546156F0CCCULL,
		0x38E9B5DBF5E78B60ULL,
		0xF07FCB85019C9D2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70737469AE718430ULL,
		0x583EFC9C8403433EULL,
		0xD92C19FE33852A11ULL,
		0xEB3492FB8D140D08ULL,
		0xBA0AC41C323265E2ULL,
		0xCD209546156F0CCCULL,
		0x38E9B5DBF5E78B60ULL,
		0xF07FCB85019C9D2AULL
	}};
	t = 0;
	printf("Test Case 25\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 25 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA786E7C1B2ED3C0BULL,
		0xBE34C28B6908A3AFULL,
		0x72323AF8AC45F97DULL,
		0x8B84298CE3C80E3CULL,
		0xD2C038F5455631B1ULL,
		0xB4D9E5C54ED23396ULL,
		0xEFBFB5D54D97EB3EULL,
		0xE40389D3C00F9867ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5076359C615EA994ULL,
		0xD4D5D2B0A5291A7EULL,
		0xF058929628D8F255ULL,
		0x20893AFE79E1C521ULL,
		0x31BC0136AEAE01CEULL,
		0x1442F0AEE66B5647ULL,
		0x558E5103F9601C8EULL,
		0xAE4D0823D52F37E3ULL
	}};
	t = 1;
	printf("Test Case 26\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 26 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC34E1B91C701F49BULL,
		0x1650EF0C44A07438ULL,
		0x06C917747CC64BE0ULL,
		0xC3C0768C960C97D9ULL,
		0x601EB1218C0113A0ULL,
		0x958E129A4E9BDA62ULL,
		0x17C710B72D16A4DBULL,
		0x7275CE9E3166DE5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCE3F022CCB0C3C5ULL,
		0xE81BB0134440F913ULL,
		0x8AD31A88995CFF8EULL,
		0xBBFF764B8F80637EULL,
		0xD98CCBB33FED8A79ULL,
		0xBD1DFE4F85894BD7ULL,
		0x820BC7F85CFFBC79ULL,
		0xCC5A5FE4829CE6CBULL
	}};
	t = -1;
	printf("Test Case 27\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 27 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8994B1A5185A6485ULL,
		0x180C40DB8202B337ULL,
		0x29C8D69A01C8113CULL,
		0x708F247E015F5D0EULL,
		0xF95908510BF7A274ULL,
		0x08FB807EC2FACFB5ULL,
		0x5FBA82EE684A760DULL,
		0x77D09E2C506F041BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20928E749A0AE372ULL,
		0xDF8831C01C0C79F3ULL,
		0x6B32B787A909DCBEULL,
		0x91068C4EA012658DULL,
		0x8E7E22D21C43E202ULL,
		0xCFEA7254721BDB26ULL,
		0xF977450D34693B3CULL,
		0xAA8CDC07B729B455ULL
	}};
	t = -1;
	printf("Test Case 28\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 28 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8603606A0C8A891FULL,
		0x3BD69E01403487DDULL,
		0x9F9F1C8F7B6ECF17ULL,
		0x26052282C7C85615ULL,
		0x06E0877CAE3C03BDULL,
		0x57A506F08C248F0EULL,
		0x0FD2AB1CD368D25DULL,
		0x25B5BA9EF9901E56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8603606A0C8A891FULL,
		0x3BD69E01403487DDULL,
		0x9F9F1C8F7B6ECF17ULL,
		0x26052282C7C85615ULL,
		0x06E0877CAE3C03BDULL,
		0x57A506F08C248F0EULL,
		0x0FD2AB1CD368D25DULL,
		0x25B5BA9EF9901E56ULL
	}};
	t = 0;
	printf("Test Case 29\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 29 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5D4698603BB9543CULL,
		0xCF45E2786E102466ULL,
		0xE267AEA1BBCDDE37ULL,
		0x4A577A59929AA48AULL,
		0x0A5F625A5E802CF8ULL,
		0x6BCAC0EE7DBA01E7ULL,
		0x7DC4CEE3BDEAD8A7ULL,
		0xDBFB76F8A7483AB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9E5A9BEB84C5B90ULL,
		0x3B3FD68CD00D93A9ULL,
		0xD91BA70877C51A00ULL,
		0xF190EA75151E8BE2ULL,
		0x6F746E5F252EC837ULL,
		0xD2E5C5C68523EACEULL,
		0x90B8B2091482CFE2ULL,
		0x6406BD0DE5405C08ULL
	}};
	t = 1;
	printf("Test Case 30\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 30 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xABB0A1AF1A1E87EEULL,
		0x3D6EB1F671D5ECA0ULL,
		0xAF6CAC9F90A79FBEULL,
		0xEFB7BE0720004017ULL,
		0x32880083F17238EFULL,
		0xA82DF92858454220ULL,
		0x8FE79C7E28E18242ULL,
		0xCE627B00117FFE3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25E543AFA43674EDULL,
		0x7311440C8DE340E3ULL,
		0x91AA3129B888AA2BULL,
		0x69E0D814DE005DE9ULL,
		0x16F97D98D6A1A1CBULL,
		0xF2F86E23F7DBBB2DULL,
		0x68C5465B4AF2ADAAULL,
		0x8A6D8D7BDB92534EULL
	}};
	t = 1;
	printf("Test Case 31\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 31 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD7D5834B9945C695ULL,
		0x67320382C5C01346ULL,
		0xE5BFE969097580B7ULL,
		0xFA43C87048B6B08BULL,
		0xA21656FE62F40C38ULL,
		0x5381DD5C54547375ULL,
		0x5157B3DA842F0D61ULL,
		0x75ABCABEBAFE409FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAEF66BC46D8985BCULL,
		0x032C6E2FCDB8D624ULL,
		0x36E8B3FB6CDC748AULL,
		0x565A3AEF10B2C955ULL,
		0xE920A9F3C36CD90CULL,
		0xF53E6947AA6ADCCDULL,
		0xA44545B33EF20AFCULL,
		0xF5463A1942BF39EBULL
	}};
	t = -1;
	printf("Test Case 32\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 32 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB0528B92F34E50FCULL,
		0x96A70EEDA35CB54BULL,
		0xA4A180D71D56802CULL,
		0x9F76323C80326C49ULL,
		0xF6C5BACC6222D429ULL,
		0x6262983B99DFABDDULL,
		0x48F124F74921CB71ULL,
		0xBCB84DF338620FB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0528B92F34E50FCULL,
		0x96A70EEDA35CB54BULL,
		0xA4A180D71D56802CULL,
		0x9F76323C80326C49ULL,
		0xF6C5BACC6222D429ULL,
		0x6262983B99DFABDDULL,
		0x48F124F74921CB71ULL,
		0xBCB84DF338620FB9ULL
	}};
	t = 0;
	printf("Test Case 33\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 33 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5A25E746D7ADA0F0ULL,
		0x2D71D888B732FCA1ULL,
		0x2CC2B2F2FE16320DULL,
		0x5A8BC062BB72E06AULL,
		0xD3E017EE91CBF4FCULL,
		0xE5F379963D244E21ULL,
		0x7BFC6786F11A5552ULL,
		0x768B7544CE712E55ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9CAD84F6C666733FULL,
		0x099AC4BAE43EFD8FULL,
		0x201404161C9DEDDFULL,
		0x9763CB75BFC61965ULL,
		0xCD109627B77B157FULL,
		0x4B0AFB73AE01F989ULL,
		0x1728A6F842B99C02ULL,
		0xB737AC97D42172CAULL
	}};
	t = -1;
	printf("Test Case 34\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 34 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF03CFDD474AD5206ULL,
		0x597C424AB65F6854ULL,
		0xA4DFE5A41FDD37AEULL,
		0x211E74EBAD552512ULL,
		0x35B37E26EFC947E9ULL,
		0xF3C9CF7810D320E6ULL,
		0x3DB32FCCB4746B74ULL,
		0x00589A10DA5AF233ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0CDF0CFD7CEDB283ULL,
		0xC5948BEB40355F00ULL,
		0xC5A586B8D1293566ULL,
		0x0E03B72E9ED41CCAULL,
		0x9EDF093E8A840073ULL,
		0x8BD4B369CDF3E716ULL,
		0x770CC4EC7A826240ULL,
		0xC4E1C6E4598F9D98ULL
	}};
	t = -1;
	printf("Test Case 35\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 35 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD2327BAC8B38F8C6ULL,
		0xADE1FA0515D1E8D6ULL,
		0x4EBED6C0DF0FA5ACULL,
		0x434B83151890EF1BULL,
		0x6842022622ECE90DULL,
		0xA30BECCF8236802AULL,
		0xA7484FD173DB7C89ULL,
		0x7C8AAB395D96EB87ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1314D787B8CE5FE7ULL,
		0x26A1BF9F2100B88CULL,
		0x6B0936242CFA0ADEULL,
		0x420E75895D517BEFULL,
		0x66C3E94B9DA8DF2FULL,
		0x1C188A8436336FB9ULL,
		0x6548DF876894DCB9ULL,
		0xB3A1E528AA8E3B6BULL
	}};
	t = -1;
	printf("Test Case 36\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 36 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBA4E6BF4DE639FF3ULL,
		0x30095B0CC2ACBC0BULL,
		0x74D8FDF20244E04AULL,
		0xC3443F7B5768F442ULL,
		0x3BBE923D8106A1AFULL,
		0xB8E625767C64FFC4ULL,
		0x09E0B343EB980E44ULL,
		0xCC41A20C9ECD22CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA4E6BF4DE639FF3ULL,
		0x30095B0CC2ACBC0BULL,
		0x74D8FDF20244E04AULL,
		0xC3443F7B5768F442ULL,
		0x3BBE923D8106A1AFULL,
		0xB8E625767C64FFC4ULL,
		0x09E0B343EB980E44ULL,
		0xCC41A20C9ECD22CFULL
	}};
	t = 0;
	printf("Test Case 37\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 37 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6B6F803643CC23B3ULL,
		0xE448D92F38CB62C8ULL,
		0xD1BB1EBA2D05FED3ULL,
		0x3B99475D858C0ED9ULL,
		0x7902130DC7EBE9E9ULL,
		0x75353EECF0EE2AD9ULL,
		0x94D9C51832E90C49ULL,
		0x7B61BB633A5A00A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27BA5BFAA44BB6A4ULL,
		0x05B178727A6C3D53ULL,
		0x6E29F7A75986A3DAULL,
		0x955A965B8ABB178FULL,
		0x6C882E5D85594FF3ULL,
		0x1EA9DA2DA5BD93B1ULL,
		0x43268551DEDD73FAULL,
		0x819949824A454DCAULL
	}};
	t = -1;
	printf("Test Case 38\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 38 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3E702B955EC79DCDULL,
		0x400CD813C7427C21ULL,
		0x6F5EF7A39D64772DULL,
		0x8F3168FC438E927EULL,
		0x0C8A93199990C9A8ULL,
		0xA49893FC912DA280ULL,
		0xD3D7757B50BDA285ULL,
		0x94D3821FD8D7B0ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE40F80231E0054B2ULL,
		0x91F2F2491EA10ECCULL,
		0xE82F87F0C13C778EULL,
		0x7C75C9F6D4F9DDEFULL,
		0xE8C705A5DB4BA3F5ULL,
		0x62F47155F0C53A7FULL,
		0xFABDA9519FE5DFC8ULL,
		0x307C03D399F51F3BULL
	}};
	t = 1;
	printf("Test Case 39\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 39 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFF7C93C2FB66898EULL,
		0xD545ADD2A35DC2CFULL,
		0xA6249DB35363C30BULL,
		0x6E58DB97CC6AABDBULL,
		0x58E921D214424999ULL,
		0xC90C6CE511CB168BULL,
		0x4090A4929569D833ULL,
		0xB66BB41DCEEE915AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4E9ADF3330057E6ULL,
		0x191A88BE5698B4A4ULL,
		0x5B3E2373BCAAF44CULL,
		0x8555C269B2A6DC33ULL,
		0xAF4C83D8F4FBC9C9ULL,
		0x1C91ABEB83976258ULL,
		0xE6F5C791A4D7FB58ULL,
		0xD6D7A9DA81AD9EB0ULL
	}};
	t = -1;
	printf("Test Case 40\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 40 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x061D15214856D23BULL,
		0xE51BF4B8EE96782EULL,
		0xE2F9BA65508018D0ULL,
		0xD11EFCE4EC2EFB1DULL,
		0x5B399CD5840EA3C0ULL,
		0x4708476718948409ULL,
		0xBD3B2FB0D6F43173ULL,
		0xD9D4113C18370F98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x061D15214856D23BULL,
		0xE51BF4B8EE96782EULL,
		0xE2F9BA65508018D0ULL,
		0xD11EFCE4EC2EFB1DULL,
		0x5B399CD5840EA3C0ULL,
		0x4708476718948409ULL,
		0xBD3B2FB0D6F43173ULL,
		0xD9D4113C18370F98ULL
	}};
	t = 0;
	printf("Test Case 41\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 41 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD94CA280C78F85CBULL,
		0x887013EFB0973857ULL,
		0x11A29636FFA4CFAFULL,
		0xAA34DACEA7273ED6ULL,
		0x1A09663A24CAE520ULL,
		0x5DA73DF95A2C0C58ULL,
		0xDBB5F452C6909889ULL,
		0xFB3AF86DBEAA77B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDC838AE7ED472FDULL,
		0x4B58F6A0FA2B4D85ULL,
		0x1727294FCA1CF5AAULL,
		0x0A6ACE404DBD5B46ULL,
		0x22AF0BA36B515D34ULL,
		0x5BC27437728A77A1ULL,
		0x633152315E726004ULL,
		0xD83E1B3AB8ADE295ULL
	}};
	t = 1;
	printf("Test Case 42\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 42 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x63325B1342D8094FULL,
		0xB58604C8D5C318D1ULL,
		0x7FC625932B5CE843ULL,
		0x86964EE830505919ULL,
		0x7AC3E2046D073B31ULL,
		0xB3E9E818DD9DFBF3ULL,
		0x8A1B26DD344F6037ULL,
		0xEDD3A799639043D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A0AE9D1652B0FFDULL,
		0xAADFD971C3DEA138ULL,
		0xF6F67E2AB3D6026BULL,
		0x4E181F3F1E71609EULL,
		0x8B99B53179404D10ULL,
		0xEEC5A72857083D1BULL,
		0x2CD78513F1DBD5EEULL,
		0x15D0FA50F68EE015ULL
	}};
	t = 1;
	printf("Test Case 43\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 43 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9131A10ECD56D1F2ULL,
		0x3027A415779001D0ULL,
		0x45F467298933BDF5ULL,
		0x586DE54428523876ULL,
		0xA5E695C222F5BD90ULL,
		0x48C7C3DA3BD0FDADULL,
		0x6E49D61E6ACAC703ULL,
		0xC326A63DD60F4033ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02B8360BAB122B8DULL,
		0x0DE5F8E051B67EF7ULL,
		0xAD3685857D0DC7FBULL,
		0x45178E40FD198B01ULL,
		0x30B515654B700291ULL,
		0xE41E3C0EC852B867ULL,
		0x53FABBF28F9C3F91ULL,
		0xEC2C643621E5CC38ULL
	}};
	t = -1;
	printf("Test Case 44\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 44 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4642CF5FEF3F61B8ULL,
		0x80CF9AFA22974F54ULL,
		0x8EF92A911E265BA7ULL,
		0x789C82EE2F600E30ULL,
		0x4985EA9864C51737ULL,
		0x7674BBD594686EAEULL,
		0x7B8EBC4622262322ULL,
		0xF525A46CF86C2F35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4642CF5FEF3F61B8ULL,
		0x80CF9AFA22974F54ULL,
		0x8EF92A911E265BA7ULL,
		0x789C82EE2F600E30ULL,
		0x4985EA9864C51737ULL,
		0x7674BBD594686EAEULL,
		0x7B8EBC4622262322ULL,
		0xF525A46CF86C2F35ULL
	}};
	t = 0;
	printf("Test Case 45\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 45 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF4DCB6F6382A1E5BULL,
		0xB356371168751432ULL,
		0x690B1B1673D19AF4ULL,
		0x4AA06EAE3DE2BE4FULL,
		0x40047032DA9EA83FULL,
		0x275DC2F07ED543DAULL,
		0x9595DFB33BDDA4FCULL,
		0xB6CED83D1C824022ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x409BE03784B22583ULL,
		0x87409983FF6A1CF4ULL,
		0xD3C370396F1A1805ULL,
		0x65933BBCC3900DA6ULL,
		0x1C3F7A3C0A5C7736ULL,
		0x761FBAEF061690D2ULL,
		0xEBD774F966722862ULL,
		0xB8ADB62E98AE8602ULL
	}};
	t = -1;
	printf("Test Case 46\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 46 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4C28ABC40DA7E6D3ULL,
		0x88D6ADCE41CEFFF5ULL,
		0x5D672DC7249A3425ULL,
		0x6BCD6F61A28AE432ULL,
		0xFB0ECB5128ECB4E9ULL,
		0x0CDECB9D40E678BCULL,
		0x88BC4AE0AE10B351ULL,
		0xFF2F226242509182ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D22A9B285D5796AULL,
		0x303ADB46C8D66997ULL,
		0x83268E6E849032D0ULL,
		0x4F4ECDF822C22F26ULL,
		0x85A61BFF7FCB908DULL,
		0xF28E0ED2E51FDE12ULL,
		0x84B73ED92031AA87ULL,
		0xF9C127AC8C6DBA38ULL
	}};
	t = 1;
	printf("Test Case 47\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 47 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0F8DBE40FC189602ULL,
		0x4249EC8DBD53B8AAULL,
		0x10A606D7D19C822BULL,
		0x66B25DFB8A32457AULL,
		0x2EB8CF0B40F52EC4ULL,
		0x9533649715928A70ULL,
		0x6D44A27F57BB00C0ULL,
		0x965E1F2E45FA097BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83EE53E404F9340EULL,
		0x02EA9B50A6FF6FD6ULL,
		0xCC1B71E2B44058C3ULL,
		0x3466AA6E6F648996ULL,
		0xC00FF95419E51287ULL,
		0x38EA1E2F95BB6638ULL,
		0x4C097460CE1E896BULL,
		0x960649111A41FA4CULL
	}};
	t = 1;
	printf("Test Case 48\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 48 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFCD8005C7F3723E3ULL,
		0x7633B9A6961F96F9ULL,
		0x72CF26AAF4C82CBBULL,
		0xFBC56539014FB40AULL,
		0xDD55A5317E264760ULL,
		0x3CA6B32EF9309A98ULL,
		0x9F7E3DAD6D091403ULL,
		0x45BBC9BE0A791493ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCD8005C7F3723E3ULL,
		0x7633B9A6961F96F9ULL,
		0x72CF26AAF4C82CBBULL,
		0xFBC56539014FB40AULL,
		0xDD55A5317E264760ULL,
		0x3CA6B32EF9309A98ULL,
		0x9F7E3DAD6D091403ULL,
		0x45BBC9BE0A791493ULL
	}};
	t = 0;
	printf("Test Case 49\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 49 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD264963B02150712ULL,
		0xAA8939AADD43C684ULL,
		0xF1508AAE665EC36FULL,
		0x477ECEF5E7F58A55ULL,
		0x170AD48C33146CE6ULL,
		0xAA8C5F32CD81D952ULL,
		0xF6BE42DE8E7168B2ULL,
		0xEF6FBB42094395B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34F06E6B76B12C96ULL,
		0xEF28603F38E7C4C2ULL,
		0x449181201C022BB8ULL,
		0x7514E80BD94BAAA8ULL,
		0xF15FDD0DAEA8466DULL,
		0x715697A893F97C5FULL,
		0xE3830102A2A9217EULL,
		0xCF628CB061CD51EFULL
	}};
	t = 1;
	printf("Test Case 50\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 50 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF11CC1B51AD5CD31ULL,
		0xA8BD7F85A2724BDCULL,
		0x8A9233E40FA32982ULL,
		0x548CAD227179193DULL,
		0x20E438BF01D3C3B3ULL,
		0x7E63B0BECCB33934ULL,
		0x07667D9C1CD60D3BULL,
		0xF3692009977C8E8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD23D88ED8FF618AEULL,
		0xE5F0C1C084EB7E20ULL,
		0xD4A3F2282196D743ULL,
		0x35C90B81A04410F8ULL,
		0xEEBC71916BF3B7C9ULL,
		0xB23A673F48D004EFULL,
		0x19B7B30E4E404D96ULL,
		0xA707CF588AD96C1CULL
	}};
	t = 1;
	printf("Test Case 51\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 51 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -51;
	} else {
		printf("Test Case 51 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB441CB744805A171ULL,
		0xC390A7726D994A29ULL,
		0xA6E0069871C01FBAULL,
		0xD6A801BFD281C364ULL,
		0x74F23F387C8E50A2ULL,
		0x5D1FEAB5165F627FULL,
		0x2D2B009D990B836BULL,
		0x3DB930051910A7F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F11F115ADF43FD1ULL,
		0x139FD64DDF081747ULL,
		0xCAD37CFADD935B8AULL,
		0xC64A1457EB2A7E6BULL,
		0x1EAEA21EC8A7048DULL,
		0xDD95C60C80DFBC85ULL,
		0x5960160F5C7DB21CULL,
		0xACD5CA007EB43F74ULL
	}};
	t = -1;
	printf("Test Case 52\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 52 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -52;
	} else {
		printf("Test Case 52 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x442D92B69ED67444ULL,
		0x0A0B60E958737F78ULL,
		0x4983AEDC0FBF0AD6ULL,
		0x763ED78BDC12817EULL,
		0xE71A7C307AE1DB33ULL,
		0xF5D9EC14CC82890DULL,
		0x0F044C327E50F712ULL,
		0x96A81C878CB909B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x442D92B69ED67444ULL,
		0x0A0B60E958737F78ULL,
		0x4983AEDC0FBF0AD6ULL,
		0x763ED78BDC12817EULL,
		0xE71A7C307AE1DB33ULL,
		0xF5D9EC14CC82890DULL,
		0x0F044C327E50F712ULL,
		0x96A81C878CB909B5ULL
	}};
	t = 0;
	printf("Test Case 53\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 53 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -53;
	} else {
		printf("Test Case 53 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x57A622C9158CCFC1ULL,
		0x44E73DFFCB7229FEULL,
		0x5398C52ADE74AD9AULL,
		0x708DB53099F45790ULL,
		0x9C35F7902300CD66ULL,
		0xDDA366ECDB49AE91ULL,
		0x780970AF5EF6FF36ULL,
		0xE54D6F5039A952EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C18A178D8F66ADFULL,
		0x5827E27A949C37C4ULL,
		0x38B836267B935A97ULL,
		0x47AD4D9BEF1EFBD9ULL,
		0x68579B6A2E2F4C09ULL,
		0xEBF1AEF78FE26496ULL,
		0x62344183BF587859ULL,
		0x0BC6CFEF27C97700ULL
	}};
	t = 1;
	printf("Test Case 54\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 54 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -54;
	} else {
		printf("Test Case 54 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9D7478B857BD2837ULL,
		0x318D6CF10458640DULL,
		0x7FF93D36DC53051FULL,
		0xFD3D79A3A606F300ULL,
		0x1FAC47E1D463A0E2ULL,
		0xB81E168E47457848ULL,
		0x3804CD616655D867ULL,
		0x388AA341C64EFEA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0AC751AC4D5810A1ULL,
		0x1B1816486F8BB4A5ULL,
		0x12D05B8266C7A490ULL,
		0xDA7B5E167519CBC6ULL,
		0xF5BEF6B3ABF56982ULL,
		0xA3CDB1F2C8D5834DULL,
		0xFBB23B4BDDEBEDECULL,
		0xA1D4DF73F7CC8662ULL
	}};
	t = -1;
	printf("Test Case 55\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 55 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -55;
	} else {
		printf("Test Case 55 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x674F5920BAFB70FDULL,
		0x95805052B1B4636FULL,
		0xBD74C7F39F516B13ULL,
		0xD061FD549D6EF890ULL,
		0x4A2B9F2B43B78A11ULL,
		0x161376BF2135139AULL,
		0x0C05666A7960DDE7ULL,
		0xDAB45696D962E960ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13A69A250D2E3F76ULL,
		0x0924A903BCF79304ULL,
		0xC4C48C175063ADB2ULL,
		0xE46F96387C2117D0ULL,
		0xE5E1FD7644826805ULL,
		0x40FBC03D4D695674ULL,
		0xABD17F918B60B651ULL,
		0xEE5D0D6A9CA8F7D6ULL
	}};
	t = -1;
	printf("Test Case 56\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 56 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -56;
	} else {
		printf("Test Case 56 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF957F6050882A967ULL,
		0x77E867C05266C95EULL,
		0x815791F34D92D059ULL,
		0x82861199AE0D4D22ULL,
		0xAECC84B8D48BD2C0ULL,
		0xC72F15FC70A630F7ULL,
		0x5D5A44EF88DDEFB3ULL,
		0xAFC45537DF3DF766ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF957F6050882A967ULL,
		0x77E867C05266C95EULL,
		0x815791F34D92D059ULL,
		0x82861199AE0D4D22ULL,
		0xAECC84B8D48BD2C0ULL,
		0xC72F15FC70A630F7ULL,
		0x5D5A44EF88DDEFB3ULL,
		0xAFC45537DF3DF766ULL
	}};
	t = 0;
	printf("Test Case 57\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 57 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -57;
	} else {
		printf("Test Case 57 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFACB16CA26C31C58ULL,
		0x4CD2CEAD8B72B1F2ULL,
		0xB32868131A23242CULL,
		0x10349075DBA95B86ULL,
		0xF0F8D1B2271CAAB1ULL,
		0xE0B4688C0014C24EULL,
		0x7E401BAC0B7CC9DCULL,
		0xEE12E9B49B844435ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D63D2B201464E50ULL,
		0xF4CEE61379C6B7E3ULL,
		0x71A1077CA32DFF93ULL,
		0x0D55DA95E9E9FE17ULL,
		0x369AE6EAAD8D5DF7ULL,
		0x6362937135DB6268ULL,
		0x9CA023B633BE8796ULL,
		0xF31C07D8C7ABC10EULL
	}};
	t = -1;
	printf("Test Case 58\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 58 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -58;
	} else {
		printf("Test Case 58 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x501552547B8DEA59ULL,
		0x83ABE03A2D53AB97ULL,
		0x52F3A5DB4B0FA3D3ULL,
		0x2E9CAB3EDF6D86B1ULL,
		0x083DB225C4AB3189ULL,
		0x47CD5B63AE6F8633ULL,
		0xE8EE90F00F6642EBULL,
		0x914DAF1190857A7CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x858871DC353DA09FULL,
		0xC60E4F4F5151E7BEULL,
		0x34B771883667A1D5ULL,
		0xC3087A28A693BB4EULL,
		0xD0FC30EB4597BCDFULL,
		0xDEA652B0E4AF1A3DULL,
		0x1CB707E69E2C20ACULL,
		0x8A3136D5636B64B0ULL
	}};
	t = 1;
	printf("Test Case 59\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 59 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -59;
	} else {
		printf("Test Case 59 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFF900F3C908B2918ULL,
		0x5047658DBAC6B4F8ULL,
		0x0B6A03905BF75BC3ULL,
		0xF86BDB5F5E3D51F5ULL,
		0x6AA42A8AC3A48828ULL,
		0xB09643F9DB511963ULL,
		0xAAC1D58A1001383DULL,
		0x249A886D442F2DF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05120F5DAE180A64ULL,
		0x9CFF0285DDD9C321ULL,
		0x8692DD9720DC9C8CULL,
		0x4E4FB9EA4EBBF76DULL,
		0xF226A047208FEB5CULL,
		0xE99E83307CD30A76ULL,
		0x8C845A4433284455ULL,
		0xA21D7CDF64DB67B2ULL
	}};
	t = -1;
	printf("Test Case 60\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 60 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -60;
	} else {
		printf("Test Case 60 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6A2ED0B5217CED12ULL,
		0xB45D1856798ED910ULL,
		0x194D2FB65924EC98ULL,
		0x20083EF824CA60E9ULL,
		0xE6F935404407601CULL,
		0x235C7283F7C8D0CAULL,
		0xC6797E3D05D06C94ULL,
		0xA128196152BCEB35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A2ED0B5217CED12ULL,
		0xB45D1856798ED910ULL,
		0x194D2FB65924EC98ULL,
		0x20083EF824CA60E9ULL,
		0xE6F935404407601CULL,
		0x235C7283F7C8D0CAULL,
		0xC6797E3D05D06C94ULL,
		0xA128196152BCEB35ULL
	}};
	t = 0;
	printf("Test Case 61\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 61 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -61;
	} else {
		printf("Test Case 61 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x198A759EFDE51299ULL,
		0x3C0DED441288734EULL,
		0x7784F4AE8A14CAA3ULL,
		0xD7DBDC0D56E1F28EULL,
		0xE081B7E04C2EF047ULL,
		0x42F6DA8BBEB29CAAULL,
		0x185CA4519C940A58ULL,
		0xAF17BA8B7A9E5DF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83053164A2689FD5ULL,
		0x01FB57C3677C3D61ULL,
		0x14A2E1A961EE4ED7ULL,
		0x91C015696DD04D1CULL,
		0x5FD8023CCEA96A8FULL,
		0x1D49BBBF9BC79488ULL,
		0x709D188C87F08984ULL,
		0x7B9B42EB19A7485EULL
	}};
	t = 1;
	printf("Test Case 62\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 62 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -62;
	} else {
		printf("Test Case 62 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x807557E28B51261AULL,
		0x1678BC5B417A6F3BULL,
		0x2843635A555EE4E6ULL,
		0x7776FDF35A3DBCE8ULL,
		0x98532CBA46F56738ULL,
		0x7D43C029E20D3BC3ULL,
		0x3ABD16238AA3619AULL,
		0xFE8551C471C059D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF323EA7ACFDDC75ULL,
		0xC1A65A8173977899ULL,
		0x868949638ED6461AULL,
		0xF9283436C37717F8ULL,
		0x84ED240FDDF1D8C7ULL,
		0xC0796BA3C24BFACDULL,
		0x715D5AE89A59B017ULL,
		0x09EE335FC06A432AULL
	}};
	t = 1;
	printf("Test Case 63\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 63 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -63;
	} else {
		printf("Test Case 63 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3B95CFD470AC5B5CULL,
		0xD010B559D1B1BB1DULL,
		0xEC8C375E783C0136ULL,
		0x04A8DB8CEFC42340ULL,
		0x158600C5863CCD7AULL,
		0x074F0B324893936FULL,
		0x0193AC00E61B2CCFULL,
		0x01D853E1E12EFD2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22331F7D0D28B2F7ULL,
		0x66FCA0AEE4D83609ULL,
		0xBD93085D88CA3F65ULL,
		0x9D7BA8E7E970CAD9ULL,
		0x563233B3ACAFE195ULL,
		0xFEBE81734C9A9138ULL,
		0xD049AAF35559BA96ULL,
		0x278D549C6DB2E5CEULL
	}};
	t = -1;
	printf("Test Case 64\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 64 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -64;
	} else {
		printf("Test Case 64 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x027219D62A241B15ULL,
		0xD6196DCEE39D437CULL,
		0x5DC28BB9156B011AULL,
		0x5DF4AB69F4520CFEULL,
		0xE557BF86F670EF18ULL,
		0x91867279840FA1D9ULL,
		0x4F421FCFBC1F0CA0ULL,
		0xE606B96F44C481DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x027219D62A241B15ULL,
		0xD6196DCEE39D437CULL,
		0x5DC28BB9156B011AULL,
		0x5DF4AB69F4520CFEULL,
		0xE557BF86F670EF18ULL,
		0x91867279840FA1D9ULL,
		0x4F421FCFBC1F0CA0ULL,
		0xE606B96F44C481DFULL
	}};
	t = 0;
	printf("Test Case 65\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 65 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -65;
	} else {
		printf("Test Case 65 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBF485268DCDE3AA8ULL,
		0x72E8B921DB5DB068ULL,
		0xD1460FFA1ADB278AULL,
		0x8F8E352A9C4997E7ULL,
		0x8B047B8920226B36ULL,
		0x146760C5F5331661ULL,
		0xD01734B07C45093DULL,
		0xDBEE3CDD9FA0803AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB036B15A1EA1C084ULL,
		0x4EAAC03BBCE8BF45ULL,
		0x859A90C45C532A2CULL,
		0x5AD00458888482A4ULL,
		0xDA53917C1C6BB0BFULL,
		0xF1071D98AA3AF9F8ULL,
		0x0D7DF00BA94EDE69ULL,
		0xA3167364AC0C5DC7ULL
	}};
	t = 1;
	printf("Test Case 66\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 66 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -66;
	} else {
		printf("Test Case 66 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4D75FF2FED658126ULL,
		0xD6699913EF941418ULL,
		0xC15ADC545E5FAC95ULL,
		0xA4720B144E95F0A5ULL,
		0x27801C3951462DD0ULL,
		0xCEFC5AFB3E2F1AFFULL,
		0x118A5ACD9240E649ULL,
		0x7BB1E21A9AD665CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB553A7D12DDAB714ULL,
		0x86FF4A7B3146839CULL,
		0x46B27EC9EB2BDD65ULL,
		0xC78826654BF4F5E5ULL,
		0x5D4A245211D79354ULL,
		0x6C933B4CAF22759CULL,
		0xB522C00179EF97A2ULL,
		0x73CF57BDAF1F838CULL
	}};
	t = 1;
	printf("Test Case 67\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 67 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -67;
	} else {
		printf("Test Case 67 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFF2CDA3B67BE3CC5ULL,
		0x752F9F42732DA8AFULL,
		0x6721C37D4B311469ULL,
		0x578695DA0B3CDC6EULL,
		0x2425683CB078C3DCULL,
		0x4EE647CE0953E4B8ULL,
		0xF288A98485CBF3B8ULL,
		0x8481BA2345AEF562ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEADFD847BB089ED8ULL,
		0x265AA74C409E8DDFULL,
		0xBCC173D3B751A727ULL,
		0x476BC35CEB082181ULL,
		0x8DA84A1B1D472BDAULL,
		0x86E2FD271EF260AAULL,
		0xAF418C35DCE52862ULL,
		0x89170D7BE567BF26ULL
	}};
	t = -1;
	printf("Test Case 68\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 68 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -68;
	} else {
		printf("Test Case 68 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x20BAC697FA3EE518ULL,
		0x365E3EED1B535E1EULL,
		0xFC96AA4F38F97866ULL,
		0x59BB8D5A81BE50C7ULL,
		0xACF15184E6D6E413ULL,
		0xEBCA8FC0ABB2657DULL,
		0x33F70C76D4016332ULL,
		0x57EC699ED0E59991ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20BAC697FA3EE518ULL,
		0x365E3EED1B535E1EULL,
		0xFC96AA4F38F97866ULL,
		0x59BB8D5A81BE50C7ULL,
		0xACF15184E6D6E413ULL,
		0xEBCA8FC0ABB2657DULL,
		0x33F70C76D4016332ULL,
		0x57EC699ED0E59991ULL
	}};
	t = 0;
	printf("Test Case 69\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 69 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -69;
	} else {
		printf("Test Case 69 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDC0A80888CA063E8ULL,
		0x9DE619EBDBA7CF17ULL,
		0xDF9E6F362414B7F8ULL,
		0x1FE644221E8B9540ULL,
		0x80FB2E490E871B8FULL,
		0x2A9E8DC82652F104ULL,
		0xD95321939860C8C7ULL,
		0x0D5511ECAA50F259ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBAFEDFFFE2752268ULL,
		0x1371AB6AB62454F0ULL,
		0xB77BB3D3F0FB6DF5ULL,
		0x0C7103D9E3DA2E5EULL,
		0x9D37542D5D824662ULL,
		0xC651DAA8B9F2BA13ULL,
		0x399BC5103B42D1CFULL,
		0x17E32F59F2ABFDBEULL
	}};
	t = -1;
	printf("Test Case 70\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 70 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -70;
	} else {
		printf("Test Case 70 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA0C9B00FE0BE6D68ULL,
		0x6E0BAFAF5F86A2D2ULL,
		0xC0B1BB6961747AECULL,
		0x8AE55313BA07E52CULL,
		0xFC5FED42361AFC2DULL,
		0x6647DBE784944752ULL,
		0xA70AF215863A5312ULL,
		0xE13DA8BE9E50DA79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD43CFC44A31DBBD8ULL,
		0x1CB8C7F62ADAA223ULL,
		0xD10664D50E494BF3ULL,
		0x6AA8B53439225D5AULL,
		0x56F72ECC65FCFB0DULL,
		0x770DB8E0973A280EULL,
		0xC2D95BB8C3DF13AAULL,
		0x07928D7246384827ULL
	}};
	t = 1;
	printf("Test Case 71\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 71 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -71;
	} else {
		printf("Test Case 71 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x181FE9A7B8488C92ULL,
		0x8C8A81CBD21D7D64ULL,
		0xDB04AF334E789A28ULL,
		0x34067A7C7D8F6EBEULL,
		0xED275A2D8720D788ULL,
		0xFF2DFC26987FD785ULL,
		0x28C70C086EC8DEA6ULL,
		0xBED0EBD94C35A5FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A64734454437C91ULL,
		0xB5CCCFBD03C4290CULL,
		0x5A58DB1ADD810685ULL,
		0xF38CDABF64727EF1ULL,
		0x4778255B321308D1ULL,
		0xB4C9A0508A7855E1ULL,
		0x473386D24CFF18B7ULL,
		0x765F9EC116935AFBULL
	}};
	t = 1;
	printf("Test Case 72\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 72 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -72;
	} else {
		printf("Test Case 72 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCBD3D037524447B4ULL,
		0x9D7F59F9C3F94872ULL,
		0xFEB41B2D0A645361ULL,
		0x510DF7615E92747CULL,
		0xC2C5B99C4F9D4F4BULL,
		0x6ACAD992A837246AULL,
		0x490ABBFE14FBC989ULL,
		0x67402E5246E9BBA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBD3D037524447B4ULL,
		0x9D7F59F9C3F94872ULL,
		0xFEB41B2D0A645361ULL,
		0x510DF7615E92747CULL,
		0xC2C5B99C4F9D4F4BULL,
		0x6ACAD992A837246AULL,
		0x490ABBFE14FBC989ULL,
		0x67402E5246E9BBA2ULL
	}};
	t = 0;
	printf("Test Case 73\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 73 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -73;
	} else {
		printf("Test Case 73 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB922493D041CBCECULL,
		0xF6F7CC72267E418EULL,
		0x48EE5849E3BC1DD0ULL,
		0x5037B907573EDE37ULL,
		0xD8227A76C984631CULL,
		0x4504978E82FAE873ULL,
		0xC6327248DF569A42ULL,
		0x8EA80B9FA8E86071ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31B6195B230320DDULL,
		0xD82B33ADD48C8855ULL,
		0x9E4010144D9F3886ULL,
		0xEECE6A614AD7364EULL,
		0xD760224C9B34692DULL,
		0xDBB13DB4BCBAF1E4ULL,
		0x103D85C83E78052EULL,
		0x4FB1134751241A50ULL
	}};
	t = 1;
	printf("Test Case 74\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 74 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -74;
	} else {
		printf("Test Case 74 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFF2931E214CC24B4ULL,
		0x56F0530FD5AD82ABULL,
		0x733EB6A2511393AFULL,
		0x728EC679BC2FEC0FULL,
		0xE3E5B7AD3479C745ULL,
		0x77D5EFB54CCDEA81ULL,
		0x9CB3D8482F1D21E1ULL,
		0xAFE3B39ACFEA88C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53B142AD6444E5C7ULL,
		0x6DD31CCD7415F01FULL,
		0x33F3AE2191B14E02ULL,
		0x091D78CAE25123E8ULL,
		0xFD622979D6C93288ULL,
		0x2A35DF50C931E0DEULL,
		0x50FD50B5C3754690ULL,
		0x17ED29FECD6B2651ULL
	}};
	t = 1;
	printf("Test Case 75\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 75 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -75;
	} else {
		printf("Test Case 75 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5E3DB6E5F909E7C1ULL,
		0x742374821670FACEULL,
		0x71FF47ADA75F4561ULL,
		0xDA2E7CA0E86CE02EULL,
		0xF928EAFE8D858C2FULL,
		0xC2BF43D6E6BFF835ULL,
		0x7ABD08A03F1A8921ULL,
		0xCCAB38DA982461D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60A0D394060E91ADULL,
		0xD9A5B95768759692ULL,
		0xEE9372E43464A065ULL,
		0xFC245ED1AF71670CULL,
		0xA28DE609B2C2BCB4ULL,
		0x31E212DE9E6433B0ULL,
		0x106DDDE842455E42ULL,
		0xB1BB5E3FD793BAF5ULL
	}};
	t = 1;
	printf("Test Case 76\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 76 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -76;
	} else {
		printf("Test Case 76 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA49F24B4B6B0B257ULL,
		0x8B42553E5BAA2EDFULL,
		0x917C67D9AA5EEDFBULL,
		0xC0106DF4954FDCD9ULL,
		0x012F924F0F935F66ULL,
		0x40C1913A791B3E93ULL,
		0x0D82462CCD8D9A54ULL,
		0x85F42C6BE3E4B6DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA49F24B4B6B0B257ULL,
		0x8B42553E5BAA2EDFULL,
		0x917C67D9AA5EEDFBULL,
		0xC0106DF4954FDCD9ULL,
		0x012F924F0F935F66ULL,
		0x40C1913A791B3E93ULL,
		0x0D82462CCD8D9A54ULL,
		0x85F42C6BE3E4B6DDULL
	}};
	t = 0;
	printf("Test Case 77\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 77 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -77;
	} else {
		printf("Test Case 77 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDE09139682EA7BB9ULL,
		0xCF14D92E8F3E2CFEULL,
		0x265367D18789A41CULL,
		0xC6001832EC34C689ULL,
		0x08353BAFD7D04F5EULL,
		0x4073D84BDDD64B4BULL,
		0x9B5754995BE5362AULL,
		0x09277341309EB61EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2AEC4AEAA93B352ULL,
		0xE93E35D812F3956CULL,
		0x4D93EE8D49BC7A57ULL,
		0xFCF4FFCDD7F2A128ULL,
		0x7D1827C9DB70B6DDULL,
		0xFD04646327FFF260ULL,
		0x8277B733E5424784ULL,
		0x295F8BE205C93170ULL
	}};
	t = -1;
	printf("Test Case 78\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 78 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -78;
	} else {
		printf("Test Case 78 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5BD8CE2ABFE79461ULL,
		0xF6D8581061369ABDULL,
		0x261B64D9706891E1ULL,
		0x516D27B02564B645ULL,
		0x221DAD51BE478109ULL,
		0xD7F87CA41B46F229ULL,
		0x6B184DE97F94EE24ULL,
		0xFAD4E4F509BEAAA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB07B32C33CACF037ULL,
		0x58679487AE5E3234ULL,
		0x728E8AE35A86C610ULL,
		0x90CE8CBF6B507BF8ULL,
		0xA0BD95D91CC52F25ULL,
		0x740CAA080C60A7AAULL,
		0xB999FBE4386E8983ULL,
		0x511CA2F7F7EB55B4ULL
	}};
	t = 1;
	printf("Test Case 79\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 79 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -79;
	} else {
		printf("Test Case 79 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3E1A9F32072CB599ULL,
		0xF5E42E2C12D479BEULL,
		0xEDD90585D3C11B75ULL,
		0xDD2BE0987691C4D2ULL,
		0x9BE53D41D0788AFBULL,
		0x91C5612EFE5C408CULL,
		0x34DC358D04FA806FULL,
		0xC51C77C2F3CC616BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD822B6E2BEFC0019ULL,
		0xF46A5194D174234DULL,
		0x0A8AF521AF362B53ULL,
		0x6BCD734B7D6DEDAEULL,
		0x173843D6580E27F7ULL,
		0xBE11D2B49B3BDBC5ULL,
		0x06085B9CB0711638ULL,
		0x6264D7C8B7FAA318ULL
	}};
	t = 1;
	printf("Test Case 80\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 80 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -80;
	} else {
		printf("Test Case 80 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF812E3F055C5C702ULL,
		0x82EDA07CB95813C9ULL,
		0xE91EEC633B1F1E96ULL,
		0x5D391C09C1109DDEULL,
		0xBB6F1223171285A0ULL,
		0xF46919044F4A2A9BULL,
		0x46A64F43B6B0AFD2ULL,
		0xDE35175A22D39ACBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF812E3F055C5C702ULL,
		0x82EDA07CB95813C9ULL,
		0xE91EEC633B1F1E96ULL,
		0x5D391C09C1109DDEULL,
		0xBB6F1223171285A0ULL,
		0xF46919044F4A2A9BULL,
		0x46A64F43B6B0AFD2ULL,
		0xDE35175A22D39ACBULL
	}};
	t = 0;
	printf("Test Case 81\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 81 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -81;
	} else {
		printf("Test Case 81 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xECE70AFF20964870ULL,
		0xF6921E7540662365ULL,
		0xD4CA648FF9E84252ULL,
		0x054C436A670C23BCULL,
		0xA7700FA435A2DD60ULL,
		0xE7A7BB8E7A210364ULL,
		0xD4D9465F0BC30731ULL,
		0xE3C4A1305E936AA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB64B05141463C90AULL,
		0x49E80F7D81DCB5B7ULL,
		0x197807B7A74A9BB6ULL,
		0xD76530FC6606B2E6ULL,
		0x7857D4C9C7BEEAACULL,
		0xA74CC3F0E38504D9ULL,
		0xBC7E4250B10F9724ULL,
		0xCFEC3BDA87747A72ULL
	}};
	t = 1;
	printf("Test Case 82\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 82 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -82;
	} else {
		printf("Test Case 82 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE435833811B63C92ULL,
		0x3A04795CB0940D54ULL,
		0x4852179424DCD934ULL,
		0x75F9CAD53827AAF4ULL,
		0xBF39F05DFE137E85ULL,
		0x3A36BF8A4A2DB83EULL,
		0x908945692D6CA439ULL,
		0x82962D704756E677ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DCAEB516CC454AFULL,
		0x9B0ED531B101C717ULL,
		0xD9B1BAFB1DF9F7BCULL,
		0x4FF200F35CB2DCC1ULL,
		0xD8571FE9A97EDD84ULL,
		0x92C09B19B321D020ULL,
		0xEDC5E1E3DF70E30DULL,
		0xBDD4743879E4B99DULL
	}};
	t = -1;
	printf("Test Case 83\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 83 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -83;
	} else {
		printf("Test Case 83 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6D3F2B48FBD830BDULL,
		0xC4CF6FB28264BF49ULL,
		0xF070DDAF0EC7BBAFULL,
		0xA4E0E73E49600093ULL,
		0x91890AE359CABF0AULL,
		0x3E3CC7FBFCC6B59AULL,
		0xF2204210120162BDULL,
		0x01FD389B68FC83E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E5F3B6ABB3490C8ULL,
		0xEB53E1D5FE8E1D93ULL,
		0x06907AA25537CDFAULL,
		0x64CA0F88C729E8BEULL,
		0xEB15B24C1933A075ULL,
		0x6182AEE4A16F28BEULL,
		0xEBE2491D3A5092DAULL,
		0x563D043FD32F7919ULL
	}};
	t = -1;
	printf("Test Case 84\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 84 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -84;
	} else {
		printf("Test Case 84 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x21EAA9950202F5D8ULL,
		0xA2ECB99AA3809AACULL,
		0x2245893273EFA1EBULL,
		0x60780C3932511827ULL,
		0x83F048FE499C4663ULL,
		0x0FC4D4AF00620706ULL,
		0xE0EC318444BEA4BAULL,
		0x5D23C30A043056BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21EAA9950202F5D8ULL,
		0xA2ECB99AA3809AACULL,
		0x2245893273EFA1EBULL,
		0x60780C3932511827ULL,
		0x83F048FE499C4663ULL,
		0x0FC4D4AF00620706ULL,
		0xE0EC318444BEA4BAULL,
		0x5D23C30A043056BDULL
	}};
	t = 0;
	printf("Test Case 85\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 85 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -85;
	} else {
		printf("Test Case 85 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC2C0754D729BB063ULL,
		0xEF4052D42C9EA71AULL,
		0xB875FDEF1D523A90ULL,
		0x6E43D1B0D6816070ULL,
		0x8C8CA804ECAAFD81ULL,
		0x5C831A6C9B42D197ULL,
		0xF6F6166E7D01C375ULL,
		0x64C6DD46585EEF94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75CC2A4CCDD48EE3ULL,
		0x6F6179C59BEA2ABEULL,
		0x3424A52ADB2C5E97ULL,
		0x9C87AB1029494C81ULL,
		0x59C2A0E65C62DFF4ULL,
		0x70669468D1A3F946ULL,
		0x29C7F3BED01C7A2FULL,
		0x7D61DE71CE9B4756ULL
	}};
	t = -1;
	printf("Test Case 86\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 86 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -86;
	} else {
		printf("Test Case 86 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x46CB6F5AE2B3292CULL,
		0x1B68089F5A57B18EULL,
		0xA78DB62D2EC0D5F6ULL,
		0xAE9AA7F3664140C6ULL,
		0xC6000795816B9260ULL,
		0x01012E0968E245DEULL,
		0xEE21A076F1DE212BULL,
		0xDFE5ECBD47F9A086ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x097B9CF4D2D1D7BFULL,
		0x4D45B6E587A45361ULL,
		0x2C6FAE525232A135ULL,
		0xFAD7EC0325CADC68ULL,
		0xAA4512121B02F9D0ULL,
		0x8723C9D907737F9FULL,
		0x5DD36D72CC15760EULL,
		0x62917E0DDB2B66BBULL
	}};
	t = 1;
	printf("Test Case 87\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 87 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -87;
	} else {
		printf("Test Case 87 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAE2B979064EB8E5CULL,
		0xC79BFC354B086B37ULL,
		0x50A0B42B384FD88AULL,
		0x52EE28F96573D015ULL,
		0x1223A4B1B1374C89ULL,
		0x62C1125054035337ULL,
		0xEDC040AF49D2BCEBULL,
		0xD32BE327D502F0D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E6F4D5EA0FA8F2CULL,
		0xDC19B6C9033032FDULL,
		0xF12C99684FC162C4ULL,
		0x07FBBFFC8F26D363ULL,
		0xE99E85A8EEEA2254ULL,
		0xAC4B0D43B84FD34BULL,
		0x34D1A8D25C39221FULL,
		0xD7EF4AC740E39C1DULL
	}};
	t = -1;
	printf("Test Case 88\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 88 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -88;
	} else {
		printf("Test Case 88 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD48FC95A7D938201ULL,
		0xEFF160995F566094ULL,
		0x6EDEAACF69ADDF8CULL,
		0xDB5DD46DC2788DFDULL,
		0xD23612EB7845704AULL,
		0x99D19F98504CFE08ULL,
		0xECBE7A310480C496ULL,
		0x8A1A09DB1D5DBD21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD48FC95A7D938201ULL,
		0xEFF160995F566094ULL,
		0x6EDEAACF69ADDF8CULL,
		0xDB5DD46DC2788DFDULL,
		0xD23612EB7845704AULL,
		0x99D19F98504CFE08ULL,
		0xECBE7A310480C496ULL,
		0x8A1A09DB1D5DBD21ULL
	}};
	t = 0;
	printf("Test Case 89\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 89 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -89;
	} else {
		printf("Test Case 89 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2F60108B7E2E8F2DULL,
		0x2AA41F3A91944356ULL,
		0x06C9039715A48453ULL,
		0xB8CD96310A8A3114ULL,
		0xFD27E843B759C9E6ULL,
		0x3DC291773AEE618EULL,
		0xC7C53ECE269CBB46ULL,
		0x5E6D36D37E6D338CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DF60BCFEA4D6FCFULL,
		0xFBDD993800B52BE7ULL,
		0xB10EBECB94A16DE9ULL,
		0x2D24CB9E261C2A20ULL,
		0xF5222D17EC3B6BF3ULL,
		0xDF59090A0BBB3813ULL,
		0x4C1AC8589A9AE238ULL,
		0x121CA950FB525545ULL
	}};
	t = 1;
	printf("Test Case 90\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 90 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -90;
	} else {
		printf("Test Case 90 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA10EDEADBCB9E1D9ULL,
		0xCB6175AA441BCB6EULL,
		0x2A29F853FE86D7A5ULL,
		0xC5D2319A0DCC6FBDULL,
		0xB94F4A78570AC0C0ULL,
		0x88B86FB84881B33EULL,
		0x877F1AA9DABEEC29ULL,
		0x403507702A2AA135ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x171FB56596ADC4E3ULL,
		0x05C843659638545EULL,
		0xA2F4E72399833EE4ULL,
		0x049FB2B0BD4267E6ULL,
		0x71DA594F079A9352ULL,
		0x30F558C7774DB3DFULL,
		0xEAF60869EBE21D2DULL,
		0xE9CB52BCF1CBD180ULL
	}};
	t = -1;
	printf("Test Case 91\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 91 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -91;
	} else {
		printf("Test Case 91 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF7E23994A072F11EULL,
		0xAC90F3FFDE9266F3ULL,
		0xB36AF75EE67B4971ULL,
		0x17611DCBC5B34B28ULL,
		0x5DB8E0F001E5A176ULL,
		0xDEF96B9609B651E0ULL,
		0xADD9F7A78A0C70ACULL,
		0x94E3FF558C63C0C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9966381975C97B15ULL,
		0xDA16BDAF21513CA0ULL,
		0x99DD2A53AECAAA5CULL,
		0xB5B30CF0A1515B04ULL,
		0x0FABE2C1BFCC44C1ULL,
		0x5288227305960998ULL,
		0x79B211F73012DEFBULL,
		0x0C95F662089325C4ULL
	}};
	t = 1;
	printf("Test Case 92\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 92 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -92;
	} else {
		printf("Test Case 92 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF57011DEA475997DULL,
		0xA8C83DB217FBBDE7ULL,
		0x9BFB33469B65285FULL,
		0xBB74C636940F0452ULL,
		0xF2A70F5C3A754848ULL,
		0x1D0EDCA4E644E707ULL,
		0x310201C22CED3806ULL,
		0x0B02FDA6782DAF20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF57011DEA475997DULL,
		0xA8C83DB217FBBDE7ULL,
		0x9BFB33469B65285FULL,
		0xBB74C636940F0452ULL,
		0xF2A70F5C3A754848ULL,
		0x1D0EDCA4E644E707ULL,
		0x310201C22CED3806ULL,
		0x0B02FDA6782DAF20ULL
	}};
	t = 0;
	printf("Test Case 93\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 93 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -93;
	} else {
		printf("Test Case 93 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7A2DBC0992D19A60ULL,
		0xCE413AE9A595235FULL,
		0x014FFCBCE7DA3DDCULL,
		0x097083EA17EB57D6ULL,
		0x74D61B866800EB04ULL,
		0xE3FE76D4D3DBBC46ULL,
		0xC3664C737157BB63ULL,
		0xAA4EB385F1B99AB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62A0D7792F28CA69ULL,
		0xC190485A1A762709ULL,
		0xEE0AE988B55FDF8BULL,
		0xFEFF8EA23BCCF2AAULL,
		0xC175A057E3B20F0FULL,
		0xFA58885CBC92C1FBULL,
		0x22AE937FAB3861B6ULL,
		0x14E7DE9089381EEEULL
	}};
	t = 1;
	printf("Test Case 94\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 94 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -94;
	} else {
		printf("Test Case 94 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA4C81E07909C1008ULL,
		0x40F7FEA58B435EACULL,
		0x402FB940CAC89FCFULL,
		0x9EF0EB71F4B999B2ULL,
		0xFF38EE073E898CF1ULL,
		0x568CFF01AFE1A814ULL,
		0x476EBDA9A83D08F3ULL,
		0xAA93FD7349B37A87ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF44C16A66B6EA47ULL,
		0x1725EC4945D812DEULL,
		0x49BEB54DF6E95F5FULL,
		0x96FF07E5A4CCA529ULL,
		0x622AB924772A2AFAULL,
		0xEDA67834E8B7949AULL,
		0x5A219CFDEE0EFBC2ULL,
		0xD9DF42F175A8C2C3ULL
	}};
	t = -1;
	printf("Test Case 95\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 95 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -95;
	} else {
		printf("Test Case 95 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x359A46C4A0868519ULL,
		0xC1E7DB7864C5395BULL,
		0xB940D9D27F4BE5E8ULL,
		0xCB1B8D7EA3C88367ULL,
		0x5A5D42C1208A3196ULL,
		0x595FB056674A447AULL,
		0xFEA51D081B943A62ULL,
		0x6242CEFCFD3010FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47DFCE1EB01C93F3ULL,
		0x16905AA44AE1BE72ULL,
		0x8682372F87B5902AULL,
		0x04B7D9ADE26702DEULL,
		0x6273411BE46BE4EDULL,
		0x58325ACFAC5065BCULL,
		0xE9243A3951E11B5CULL,
		0x9B012502EAD3258DULL
	}};
	t = -1;
	printf("Test Case 96\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 96 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -96;
	} else {
		printf("Test Case 96 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9B6C611460CC8006ULL,
		0xAC43147A042298BCULL,
		0x1CA43321D1C373E9ULL,
		0x9DB4AF3061ABC7FCULL,
		0xC32020F0896E4482ULL,
		0xB83A2F13BC65EB6CULL,
		0x9E4A6C33C4875C11ULL,
		0x340C78E6255ACF0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B6C611460CC8006ULL,
		0xAC43147A042298BCULL,
		0x1CA43321D1C373E9ULL,
		0x9DB4AF3061ABC7FCULL,
		0xC32020F0896E4482ULL,
		0xB83A2F13BC65EB6CULL,
		0x9E4A6C33C4875C11ULL,
		0x340C78E6255ACF0EULL
	}};
	t = 0;
	printf("Test Case 97\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 97 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -97;
	} else {
		printf("Test Case 97 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDEB7E0D4CBEEBCE7ULL,
		0x39EE2DD96CFB21ABULL,
		0x237FADDD5DCA9261ULL,
		0x07068985EC17200FULL,
		0xE1E4ECB872592681ULL,
		0x4A9318857195ACD3ULL,
		0xA8B2C6FA9CA5E155ULL,
		0x564CA39005051404ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DBA1CE00A0BB5D3ULL,
		0x00DFFB4283386CE0ULL,
		0xFDA5543770D56FF8ULL,
		0xF7A10369F5816B0BULL,
		0x266D0751BC3092B0ULL,
		0x9F409DC48735E277ULL,
		0xA400E3684D80C147ULL,
		0x301CC41587AD0831ULL
	}};
	t = 1;
	printf("Test Case 98\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 98 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -98;
	} else {
		printf("Test Case 98 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x840E88E03C64A7E3ULL,
		0x8EAD9EB1872DADCAULL,
		0x3AB4F325030D5F8FULL,
		0x761EFC6255F36DA8ULL,
		0x0BD70668D3634C27ULL,
		0x794E98907F80E9FFULL,
		0xB098DA0C5BABBE7CULL,
		0x8EFE3F39D1F4CA44ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50D47CE29CDE4BF5ULL,
		0xB10A9CA71704A346ULL,
		0x9BF976782EEC9642ULL,
		0xC1FDF7A364D8D83CULL,
		0x4BA6EFBDC9860AD0ULL,
		0x010D5F99D714C336ULL,
		0xF1C1AB08A2242C36ULL,
		0x798867877337081EULL
	}};
	t = 1;
	printf("Test Case 99\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 99 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -99;
	} else {
		printf("Test Case 99 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6BB2A7CD70ECBE1CULL,
		0x50B3D9FD12DC337EULL,
		0x66DCBF1C6AE53E06ULL,
		0xF9102C03FDD2CAD8ULL,
		0x4BC15CA0806C3B8FULL,
		0x95801A1F231ED584ULL,
		0x29B8972DA38D3E06ULL,
		0xB8F3DB39908BCFB3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B9E42DB2F3940D8ULL,
		0x60FAB9B497BE1FAAULL,
		0xA0B438004A0DA71FULL,
		0x9A6D0B7F922CC9D7ULL,
		0x56603E590123E10BULL,
		0x2D3265EE3D88E6A2ULL,
		0x9F1CE931225232A1ULL,
		0x096BE49E62E701C9ULL
	}};
	t = 1;
	printf("Test Case 100\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 100 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -100;
	} else {
		printf("Test Case 100 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1D98304D96ECB072ULL,
		0xD9CEC1C4E3ABE454ULL,
		0x6CAF1A4087EF5EFDULL,
		0x3C3E95D7813A552CULL,
		0xBEE7241612210CF7ULL,
		0xF46C0D11FC4AA3B5ULL,
		0x5697D130CC1162FAULL,
		0xE2FF914E25B0A306ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D98304D96ECB072ULL,
		0xD9CEC1C4E3ABE454ULL,
		0x6CAF1A4087EF5EFDULL,
		0x3C3E95D7813A552CULL,
		0xBEE7241612210CF7ULL,
		0xF46C0D11FC4AA3B5ULL,
		0x5697D130CC1162FAULL,
		0xE2FF914E25B0A306ULL
	}};
	t = 0;
	printf("Test Case 101\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 101 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -101;
	} else {
		printf("Test Case 101 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x20C60E710CE7F867ULL,
		0xEF0F9A97FFD75E56ULL,
		0x5EBB47A13BC3B438ULL,
		0xD1F58461D85C335DULL,
		0x70EAFFF3D9149A29ULL,
		0x04FD261FBFAB6BBFULL,
		0xDD20D0B3B8536DF3ULL,
		0x4D96E56F1BFF1544ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E7AF2C4FF4363F8ULL,
		0x75B8A64553A4AD90ULL,
		0xCD46FFC7BFD5A38EULL,
		0x07F77691641E86DBULL,
		0x254A881B8FEBFA98ULL,
		0xD5F60D7C9A82E8F0ULL,
		0x72DCA151E7B18D6EULL,
		0x5194432268DDDF89ULL
	}};
	t = -1;
	printf("Test Case 102\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 102 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -102;
	} else {
		printf("Test Case 102 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9A4F795185B92883ULL,
		0xFE325A554B0BB674ULL,
		0x9E90EE31B4927044ULL,
		0xA7BF29B111C78737ULL,
		0xFA5A53770E43C8A5ULL,
		0xE9B1A8B9AA7982B2ULL,
		0x78A96970C26E784DULL,
		0xC6B5EF8656293A24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A83CBB13B7C40F4ULL,
		0x6A987CDD10977D49ULL,
		0xDFAE57CDFD2C09F2ULL,
		0x59F6AF06019B39E5ULL,
		0x5FCE6021ABFB7E38ULL,
		0x8EF1B55CBB095A31ULL,
		0x4DEFB0F71745471AULL,
		0x824851F4646825E2ULL
	}};
	t = 1;
	printf("Test Case 103\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 103 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -103;
	} else {
		printf("Test Case 103 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9A1824A70DAC8A25ULL,
		0xA25B4A1A739D47ACULL,
		0x5A661B403B932C82ULL,
		0x2B0D7BC6CABE6A2BULL,
		0x42031B9082791FECULL,
		0x84BCB4AF814880A2ULL,
		0x962B1AAD1D7D0438ULL,
		0x3DC68A601F5D6B2DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F0D703232ED31E5ULL,
		0x746BB43730DE306BULL,
		0xA655E5D83588AC0FULL,
		0xD632184E5B102270ULL,
		0x6A716BD5DDAE6573ULL,
		0x6ABF52E45B27C388ULL,
		0x1346EA90B3F0EA60ULL,
		0x70325F904221D57BULL
	}};
	t = -1;
	printf("Test Case 104\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 104 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -104;
	} else {
		printf("Test Case 104 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9CF549268E7865BFULL,
		0x198E0B994CFFD0BEULL,
		0x7AC3593F5EC48146ULL,
		0x0350188C74440B74ULL,
		0x9AC97ABA1F9040E9ULL,
		0x95975B838FF41F93ULL,
		0x53C0EB4B7FF8501DULL,
		0xB9AA124F64CEFCDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9CF549268E7865BFULL,
		0x198E0B994CFFD0BEULL,
		0x7AC3593F5EC48146ULL,
		0x0350188C74440B74ULL,
		0x9AC97ABA1F9040E9ULL,
		0x95975B838FF41F93ULL,
		0x53C0EB4B7FF8501DULL,
		0xB9AA124F64CEFCDCULL
	}};
	t = 0;
	printf("Test Case 105\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 105 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -105;
	} else {
		printf("Test Case 105 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD5D30B8CE2BB8499ULL,
		0xFA7262014CA14F74ULL,
		0xB162C2B9D46EE029ULL,
		0x8920F53B84587654ULL,
		0x714E1ED99E88A4E1ULL,
		0xD4E0B79A6C0C57D7ULL,
		0x66FEBC916CEFB281ULL,
		0xE2DDADA864D61722ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x462358FCFBC09AE7ULL,
		0x44C50350A6CED61EULL,
		0x097B5DF2BE49F922ULL,
		0x4D228E65ABF8E971ULL,
		0x53DD56C78E739819ULL,
		0x0EE660A6416770E1ULL,
		0xFF5398D202E14D93ULL,
		0x22249D7340C4F349ULL
	}};
	t = 1;
	printf("Test Case 106\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 106 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -106;
	} else {
		printf("Test Case 106 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0052D8CA0931A7A8ULL,
		0xA6799D257237DAB2ULL,
		0xDD5AFBDB4B350D08ULL,
		0x604DD26DBE15268FULL,
		0xC3369FC9FD9C054DULL,
		0xA8B126B4A12FEA44ULL,
		0xE890A6562AFBF86DULL,
		0x918E75FCEBF0BE97ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2AAF55C90EDC9130ULL,
		0x9B1557968C7FB17AULL,
		0xB73A56269129C1FEULL,
		0xADA8CADD9947897AULL,
		0x927F92515E862E99ULL,
		0xAF05980D9AA86377ULL,
		0xCF520914D0FF77D1ULL,
		0xF05CC4622F3ED7DBULL
	}};
	t = -1;
	printf("Test Case 107\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 107 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -107;
	} else {
		printf("Test Case 107 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x57FCEC9E8A904A70ULL,
		0x15E63BD2D82E41E8ULL,
		0x0E667D89219F0D5BULL,
		0xFA0A5E2CE4423164ULL,
		0x34175AB340D8F32FULL,
		0x5D46B70A644BE362ULL,
		0x9DCBDE19C67A716CULL,
		0xEC5082843C5D5032ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCAF2FCE4CC85230EULL,
		0xB43920B79BB0D0E1ULL,
		0x545BA760EEE09AAAULL,
		0xDBC57E6AA143047EULL,
		0x83EF6D6D2091B7D9ULL,
		0x8F727F79BBE61EE0ULL,
		0x92AED06B3E880375ULL,
		0x1F6BE1D6FD65826EULL
	}};
	t = 1;
	printf("Test Case 108\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 108 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -108;
	} else {
		printf("Test Case 108 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x54E68C928D51688FULL,
		0xD5FD654A2DA8B369ULL,
		0x548B0D49990F5F4BULL,
		0x10DAA31C75BC7AC5ULL,
		0xE9712A13C12557DAULL,
		0x0FA59BBB307AC0F8ULL,
		0xC774990F4D68AD05ULL,
		0x8615BFE0F2571179ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54E68C928D51688FULL,
		0xD5FD654A2DA8B369ULL,
		0x548B0D49990F5F4BULL,
		0x10DAA31C75BC7AC5ULL,
		0xE9712A13C12557DAULL,
		0x0FA59BBB307AC0F8ULL,
		0xC774990F4D68AD05ULL,
		0x8615BFE0F2571179ULL
	}};
	t = 0;
	printf("Test Case 109\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 109 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -109;
	} else {
		printf("Test Case 109 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x19FD26A40FDB98C9ULL,
		0x7C44779574AC1D02ULL,
		0x656CE5FEECCFD8FCULL,
		0xCF3ADB9063F5088FULL,
		0x3A2AD8BB534335E3ULL,
		0xBC5C76A4F4BB4257ULL,
		0xE866E3BD5837968AULL,
		0x29FA6D5AAA6F6E2CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14010AD31478E5FAULL,
		0x661BF7E635CEF928ULL,
		0xFB8D9521B883021DULL,
		0x6659052E47804E6CULL,
		0xCEB69F218FC1D903ULL,
		0x0667199C7CCDE503ULL,
		0xEA4C8336A8BE9DC6ULL,
		0xAA23C8E77E69AACDULL
	}};
	t = -1;
	printf("Test Case 110\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 110 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -110;
	} else {
		printf("Test Case 110 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x73CFB9AAE327BEDDULL,
		0x12DE20BB40E96597ULL,
		0xC244B74886B2F48BULL,
		0x525C87E2DBD9C871ULL,
		0x2A33840E450F5246ULL,
		0x2BB2A67DE91BDDBEULL,
		0x30F4F3FDB2CD0BC9ULL,
		0xEABE15C9182DC325ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x724EF84B4CCCE26BULL,
		0x6CB6528D9D4F0FA6ULL,
		0xFB037BF7DDA4BD13ULL,
		0xC90B2268501AC0ABULL,
		0x3972526E1D53001FULL,
		0x34768A9BBF5CA401ULL,
		0x1455A030E78BB283ULL,
		0x89556E3AD6F27CC8ULL
	}};
	t = 1;
	printf("Test Case 111\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 111 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -111;
	} else {
		printf("Test Case 111 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x10BC66A60577F03CULL,
		0xEF55957DC44CAAD3ULL,
		0x18616BCC6F5E1ABBULL,
		0x67FAEAC6D34C00C0ULL,
		0xFE78F398498A363BULL,
		0xFC01DA3C5775B4E4ULL,
		0xDA606B0315D41B7DULL,
		0x8A140179603F63B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E16D4E9ECE55B01ULL,
		0x68EC65293514090EULL,
		0x7C9644A7262E8895ULL,
		0x542E2F0A9D8FD350ULL,
		0x83ECB1A2CF1A3C51ULL,
		0x62571AA44C458498ULL,
		0x24D0AF1CB70E8767ULL,
		0xC67D6B058CF3FF77ULL
	}};
	t = -1;
	printf("Test Case 112\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 112 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -112;
	} else {
		printf("Test Case 112 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCDCD61B07E279E2FULL,
		0xA7725217C77C8975ULL,
		0x9035AEFFD5579B96ULL,
		0x3478E22CA0201732ULL,
		0x3B14F05B8C6BA666ULL,
		0xB1AADCBD07884653ULL,
		0x96317613511395E8ULL,
		0xF1255973E926505DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCDCD61B07E279E2FULL,
		0xA7725217C77C8975ULL,
		0x9035AEFFD5579B96ULL,
		0x3478E22CA0201732ULL,
		0x3B14F05B8C6BA666ULL,
		0xB1AADCBD07884653ULL,
		0x96317613511395E8ULL,
		0xF1255973E926505DULL
	}};
	t = 0;
	printf("Test Case 113\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 113 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -113;
	} else {
		printf("Test Case 113 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA24ABE205B825707ULL,
		0x051B68CC662C68A7ULL,
		0xD2686D8022AFB9F0ULL,
		0xCE046F7527B30099ULL,
		0x981C98EB551FC406ULL,
		0xAC89BDFD5C39B695ULL,
		0x7E81EBFF28F69DD3ULL,
		0x967331D15358BDDAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8CE1D66C2E1DA10ULL,
		0x271865F654EC42A1ULL,
		0x15A1B50AE942C157ULL,
		0x988EA3B748761468ULL,
		0xE5AE2EB621B64B21ULL,
		0x263A49814AA4AECFULL,
		0x82141CA42726F5BEULL,
		0x7DF388AE92992941ULL
	}};
	t = 1;
	printf("Test Case 114\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 114 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -114;
	} else {
		printf("Test Case 114 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6CEAAEFAC9A67334ULL,
		0x1B4A137D13C46844ULL,
		0x1B2E33A55AC3F4C0ULL,
		0xB28E7E07F4CA537DULL,
		0xF6493A3438359C03ULL,
		0xD6E0538848CBF33BULL,
		0x421218295038BBC2ULL,
		0x41089F65AC48108AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6E03B6126ECBD81ULL,
		0xFBD6DF479A9EDFBEULL,
		0xE753DF536812CF1DULL,
		0x8712F10C6922A42DULL,
		0xDAD389074CB7CBB9ULL,
		0x49A7675EACD290EFULL,
		0x784055D1679DCD61ULL,
		0x52993A8B0D75F887ULL
	}};
	t = -1;
	printf("Test Case 115\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 115 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -115;
	} else {
		printf("Test Case 115 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x62D0962F0ADB41C2ULL,
		0x19ED89B199A67AACULL,
		0x1FE4D619F933D541ULL,
		0x5270701291B1A841ULL,
		0x6270BE0891C45BE9ULL,
		0x6B928ECAE54C36D7ULL,
		0xBEF1D98A3A1D9371ULL,
		0x1771BDB50EE951ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB29C177C86DDFC86ULL,
		0xCF0744DBA7131555ULL,
		0xFC3E09303B9978DBULL,
		0xE08458B358434851ULL,
		0x1CEE47B6E2D08BD8ULL,
		0xEE83A7659DFB0368ULL,
		0x937A47BE14A4397CULL,
		0x13A60EA5F8467E3EULL
	}};
	t = 1;
	printf("Test Case 116\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 116 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -116;
	} else {
		printf("Test Case 116 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD7BDE9528306BBD0ULL,
		0x4E61D5359CFD394AULL,
		0x5A98FAB104C949A9ULL,
		0x646758A617A46BE2ULL,
		0x5A8869BCEAF03E17ULL,
		0x99AE22A64482A0C8ULL,
		0xABC9FE695D28F82DULL,
		0xF190F12C74397ECAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7BDE9528306BBD0ULL,
		0x4E61D5359CFD394AULL,
		0x5A98FAB104C949A9ULL,
		0x646758A617A46BE2ULL,
		0x5A8869BCEAF03E17ULL,
		0x99AE22A64482A0C8ULL,
		0xABC9FE695D28F82DULL,
		0xF190F12C74397ECAULL
	}};
	t = 0;
	printf("Test Case 117\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 117 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -117;
	} else {
		printf("Test Case 117 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x11394BC75DFF1BD4ULL,
		0xD3EB8F01747CAAC3ULL,
		0x1DF6346C00D5900AULL,
		0xA6B5CF548CB34D69ULL,
		0xC29096376497FC50ULL,
		0x0D31D5D344D3DA4BULL,
		0x1FBB007B9C9E01D8ULL,
		0x57368F0399553F04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D81340E78AE3893ULL,
		0x4ACEC8043C196F24ULL,
		0x188E72F5441EEB1BULL,
		0x26E2227DF2205C9AULL,
		0x0C285C2106D216C4ULL,
		0xAD51DDD440FB86FCULL,
		0xE2173546BE460036ULL,
		0x419148AD8D6D5E57ULL
	}};
	t = 1;
	printf("Test Case 118\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 118 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -118;
	} else {
		printf("Test Case 118 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x04391AF9AA48AE1CULL,
		0x3F07EC1CC3513D89ULL,
		0x2BC7647D4D21F802ULL,
		0x6BA4DED4B3A614AFULL,
		0xBF9A7C4CB39ABFD1ULL,
		0x88F509FBCC1A1B53ULL,
		0xB3021350C72BBF39ULL,
		0xB0DB4AEDDD61629FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3E6C9A342037BCBULL,
		0xEB6D1035734458CCULL,
		0xF27C2B02ABAF6B5BULL,
		0x7EB0233120A29A90ULL,
		0x70EAF6685260FC32ULL,
		0x05F59CD878B14652ULL,
		0x1701F6887E42B0A8ULL,
		0x2F5294329487BCD2ULL
	}};
	t = 1;
	printf("Test Case 119\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 119 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -119;
	} else {
		printf("Test Case 119 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x47B7E1C4B382A7D6ULL,
		0x7B1168701DD86DA9ULL,
		0x0F48A2D0A5CE1586ULL,
		0x377C80D3C677C49BULL,
		0x4954269D97BF0DB2ULL,
		0x0FBDCCA7B18D85E3ULL,
		0x5C1EF1B65C6B8521ULL,
		0x9AEA8404A2DF9D48ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B5F4FC94B394714ULL,
		0x0AB5920A24A3FC42ULL,
		0x87D2761ADB2010B9ULL,
		0xB27AE67932911DE3ULL,
		0x11D706F792861BD3ULL,
		0xC002B916EABF9AC9ULL,
		0xEB4AF8A308EBA60AULL,
		0x88FA6C7FD4B34678ULL
	}};
	t = 1;
	printf("Test Case 120\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 120 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -120;
	} else {
		printf("Test Case 120 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEDDCBF2389F5104BULL,
		0x2705DB44445180F3ULL,
		0x7C15CFF3ECCD40E8ULL,
		0x387C6F676D507F23ULL,
		0xF5B9793824D34DBBULL,
		0xB9F1404ADD67BC14ULL,
		0x99208A7A2E623378ULL,
		0x981D7C641E013C0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDDCBF2389F5104BULL,
		0x2705DB44445180F3ULL,
		0x7C15CFF3ECCD40E8ULL,
		0x387C6F676D507F23ULL,
		0xF5B9793824D34DBBULL,
		0xB9F1404ADD67BC14ULL,
		0x99208A7A2E623378ULL,
		0x981D7C641E013C0AULL
	}};
	t = 0;
	printf("Test Case 121\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 121 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -121;
	} else {
		printf("Test Case 121 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x187D2B04504AC157ULL,
		0x71A572802D5DA9D0ULL,
		0x9E5471CE62113BC6ULL,
		0x76CC4BF2C2BF12FFULL,
		0x98A2EE06B23B2904ULL,
		0xEF22864EBC7894B3ULL,
		0x4EE87DECD7EBC066ULL,
		0x1458A2253FF4E6E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29871B6B494010D5ULL,
		0xFFA0282BDDADDEE0ULL,
		0x1103B8333428FB10ULL,
		0x300B848860CC6C2EULL,
		0x243D6A7C6FC493C6ULL,
		0x4BF00ECA2BCF0611ULL,
		0x7FB55A6151D344EAULL,
		0xC5FE3F657F9FAD05ULL
	}};
	t = -1;
	printf("Test Case 122\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 122 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -122;
	} else {
		printf("Test Case 122 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8A3AE9ABE132220CULL,
		0xE8616E70CE0EC71AULL,
		0x9A1E730A94D6923DULL,
		0xB0275CE7387774E3ULL,
		0x88490886C3EFAE72ULL,
		0xFC812454591881B8ULL,
		0xE9D9C2C76E1E0DD5ULL,
		0x693F47D7B2780CCAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA6DBDA8C97A3871ULL,
		0x1DDD52F59DF50F52ULL,
		0x42EF216874097475ULL,
		0x0FEBB6FE1D1F7CD6ULL,
		0x1AF33485002E22F5ULL,
		0x55375E52A955B54EULL,
		0x7FA4644B7C28A9D4ULL,
		0xFE9DC8DDC3D48AF8ULL
	}};
	t = -1;
	printf("Test Case 123\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 123 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -123;
	} else {
		printf("Test Case 123 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x73A657E879C888AAULL,
		0xCF4EC0D0AFB7493EULL,
		0xEDD48036E74737C8ULL,
		0x65EC0EA834F2C2A7ULL,
		0xD10D6200718E5EE5ULL,
		0x4905ACB668CE9F7CULL,
		0x4161F6B8477C4CFEULL,
		0x9997D6A216229AEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACC756EADC90E5CEULL,
		0x21022B48671EA14DULL,
		0x413F670B20269156ULL,
		0x0AF8176DD45900F3ULL,
		0x67770EC793059DF0ULL,
		0x82424A1D0C039531ULL,
		0x2173E1F40329DDC3ULL,
		0x1A1CE2B0FCB1742AULL
	}};
	t = 1;
	printf("Test Case 124\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 124 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -124;
	} else {
		printf("Test Case 124 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5D8D6055897353FCULL,
		0xCDF2E6947EB0AE6CULL,
		0x68F2D47652AA58F4ULL,
		0x5BB508D90AA51A2EULL,
		0x8C015078A6D17CA7ULL,
		0x21EC721F4ECA51A6ULL,
		0x1AD867F6FD29AE3FULL,
		0x59DB4E1A2E4A525DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D8D6055897353FCULL,
		0xCDF2E6947EB0AE6CULL,
		0x68F2D47652AA58F4ULL,
		0x5BB508D90AA51A2EULL,
		0x8C015078A6D17CA7ULL,
		0x21EC721F4ECA51A6ULL,
		0x1AD867F6FD29AE3FULL,
		0x59DB4E1A2E4A525DULL
	}};
	t = 0;
	printf("Test Case 125\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 125 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -125;
	} else {
		printf("Test Case 125 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE59972FC820601B1ULL,
		0xE5607A8E3EE3E601ULL,
		0x5F63EFCB48B01A44ULL,
		0xE1934FACB92DEA40ULL,
		0x0FB9A7F47BAA0837ULL,
		0x6A3F92A4861AB1F4ULL,
		0x32DBDC1642450471ULL,
		0x4F35E3851D2CCFB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E085DD31173B76AULL,
		0x632D786B103C6100ULL,
		0x739B49B70FD881AAULL,
		0x24BC88431034D65CULL,
		0xD84BB12445DBC520ULL,
		0xEF5EEB9DB8DEB0E6ULL,
		0x16312707755370F6ULL,
		0x86FA134C2FC7FB5BULL
	}};
	t = -1;
	printf("Test Case 126\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 126 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -126;
	} else {
		printf("Test Case 126 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8D094AC3061BD0B6ULL,
		0x6F84DA446D039D86ULL,
		0x941E25C47A80AB7DULL,
		0x1B94BFC583986B49ULL,
		0x261E8B2F06AE4A4EULL,
		0x8321D0E2A878DABDULL,
		0x4E3A044DD7D8F917ULL,
		0x5A0C85D209235933ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE930EC822B553DDDULL,
		0xF97BA41ADDF38257ULL,
		0x0F0DEF9304F2572AULL,
		0x9260172504CE5D0AULL,
		0xC102C03FC0A374D4ULL,
		0xAF5F085C4A2DBC81ULL,
		0x680DA9FE074F526DULL,
		0x546FC5B561A37CFFULL
	}};
	t = 1;
	printf("Test Case 127\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 127 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -127;
	} else {
		printf("Test Case 127 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF8DDC26C0485B07CULL,
		0xFAB90A6D9A577701ULL,
		0x14EA1CC55C63AF21ULL,
		0x5E8AFBDBCA322DE5ULL,
		0x81F50CD79BE623E6ULL,
		0x524C477C31EA23CCULL,
		0xECB7CC07EC15EACAULL,
		0x164E92089C76D125ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42441F1A958A5909ULL,
		0x25A11DC48EC30507ULL,
		0xF3191325969BEC7FULL,
		0xBE49015E10B56CD7ULL,
		0xACC4A7D73C9EBBFFULL,
		0xB7B21B80EA6E7D5CULL,
		0x733945E46ED12415ULL,
		0x52BCDD6247CAAC73ULL
	}};
	t = -1;
	printf("Test Case 128\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 128 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -128;
	} else {
		printf("Test Case 128 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFF252BCEB8E5118BULL,
		0xB3695B3148CE750BULL,
		0xCD849B1A41227650ULL,
		0x655D1314B6558EB0ULL,
		0x2E1FBC66222D26E9ULL,
		0x521E5D331E5BEF05ULL,
		0xD39242D49A1A956EULL,
		0xCBEE2B170D03B0ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF252BCEB8E5118BULL,
		0xB3695B3148CE750BULL,
		0xCD849B1A41227650ULL,
		0x655D1314B6558EB0ULL,
		0x2E1FBC66222D26E9ULL,
		0x521E5D331E5BEF05ULL,
		0xD39242D49A1A956EULL,
		0xCBEE2B170D03B0ADULL
	}};
	t = 0;
	printf("Test Case 129\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 129 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -129;
	} else {
		printf("Test Case 129 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6794E5EA344C4EFFULL,
		0x75E4BC67D9D60216ULL,
		0x4BE5A8A645A67F2DULL,
		0x006056A921EC2B06ULL,
		0x0E27886FA0D60AFEULL,
		0xA138B5739B182E23ULL,
		0x94511D81D76C0ADDULL,
		0x5820C650C4E637F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57AA1361248A577FULL,
		0x045DDD22844EBAC4ULL,
		0x6D4ACDFE7BD45323ULL,
		0xDF904B184DCE720BULL,
		0xF0891D06C624E79BULL,
		0x959B1DEC3B233C8DULL,
		0x953A11420E14EB15ULL,
		0x86E56E82BA34FEE8ULL
	}};
	t = -1;
	printf("Test Case 130\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 130 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -130;
	} else {
		printf("Test Case 130 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCBDC01C0D207094FULL,
		0xE4EB23162E64B033ULL,
		0x442310CD8475700EULL,
		0x903ED9732C0B7894ULL,
		0xFD9C15DEF6BBA474ULL,
		0x6FF9E488DA0E0313ULL,
		0xEA28C67FE016D594ULL,
		0xA467F4C8B873DA55ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6895E6E0307D725ULL,
		0xAD21755D1FB0DD36ULL,
		0x55E4933A69477129ULL,
		0xBFE04582C5DCF2AAULL,
		0x03DF89CEFD702F9BULL,
		0x4EE5A58C4DCDB93EULL,
		0xEA7C89FC7E396299ULL,
		0xC3D884AA49EAC140ULL
	}};
	t = -1;
	printf("Test Case 131\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 131 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -131;
	} else {
		printf("Test Case 131 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD0FC9895D3543682ULL,
		0x63988FF6C434AE33ULL,
		0x2B15BE6083E87AB6ULL,
		0x4FCBFC77A1C29A69ULL,
		0x74F8E024AC859263ULL,
		0xD394D5A2603CB2E7ULL,
		0xDE915C0229DDEDD8ULL,
		0xDC32005B28D6CCF5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDAA695C55B17C98ULL,
		0x1E9EC65CBBD1514EULL,
		0xAB758B09A8F763FCULL,
		0x88324FBFAA31900CULL,
		0x9EC08473EBADA0C1ULL,
		0x6CBBEC9866EA2C49ULL,
		0x7B7B456F77DA5F23ULL,
		0x8B7CCFB09E6F92F3ULL
	}};
	t = 1;
	printf("Test Case 132\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 132 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -132;
	} else {
		printf("Test Case 132 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5023AD6CE72A8EB3ULL,
		0xD847FC03E7521DD9ULL,
		0xAA7AB66BC1621604ULL,
		0x2668C66FCA084158ULL,
		0x07644785288E3904ULL,
		0xF979D87F2DB554AEULL,
		0xAB59A1818CF9BEAEULL,
		0x70B67992BFF644D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5023AD6CE72A8EB3ULL,
		0xD847FC03E7521DD9ULL,
		0xAA7AB66BC1621604ULL,
		0x2668C66FCA084158ULL,
		0x07644785288E3904ULL,
		0xF979D87F2DB554AEULL,
		0xAB59A1818CF9BEAEULL,
		0x70B67992BFF644D1ULL
	}};
	t = 0;
	printf("Test Case 133\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 133 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -133;
	} else {
		printf("Test Case 133 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB3DD9310D7C37191ULL,
		0xA7C631CB34FFD09CULL,
		0xD0A58C9587B988DEULL,
		0x16C2C0CB6CC12816ULL,
		0x9C36FE5818645874ULL,
		0x07DA09E821D765DBULL,
		0xE2C0C2696B0EAE3BULL,
		0x3719418091046B02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8F6565C5CDF2A14ULL,
		0xFC1F307E8AD727BAULL,
		0xDFC25175826EB562ULL,
		0xDE81A931990A691DULL,
		0xCB03FE3D94502317ULL,
		0xDAA454B34B9BCB0AULL,
		0x88A020A7883F0A2FULL,
		0xB2CAFCD8AEA02670ULL
	}};
	t = -1;
	printf("Test Case 134\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 134 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -134;
	} else {
		printf("Test Case 134 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5742698B2ECE782BULL,
		0xBFBF45375040D8E7ULL,
		0x2B7D3D392932D1DDULL,
		0x7ABF6FDC082FBBE5ULL,
		0x789D08639245AE77ULL,
		0x93F63F683F0BE1A9ULL,
		0xF8894DB0C4E76833ULL,
		0xBD72D760F71BD07FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0893471DB918243ULL,
		0x95B0CDC10B75F76AULL,
		0x8420E8E9F4BE2254ULL,
		0x99C0612C91F82315ULL,
		0xFEB7E4DC0C345AA4ULL,
		0x99CF21D08A694FC1ULL,
		0x5DD0395183568FE1ULL,
		0xF70E55F3D2AF33FAULL
	}};
	t = -1;
	printf("Test Case 135\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 135 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -135;
	} else {
		printf("Test Case 135 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x737AEE1E278ECCADULL,
		0x68C7F10189EB14BAULL,
		0xAED2BEA40DFAA7A3ULL,
		0x463C5D9EDE790A96ULL,
		0x9618C7F1E325E01DULL,
		0x7FF8DB287FA2C1C8ULL,
		0x79054C372E6C1F88ULL,
		0x15F0122C46A06AEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8F21D60AED8213FULL,
		0x394A6C063D3827B9ULL,
		0x2E6098D51E8B9B5DULL,
		0xFCC02934B1BCBBD1ULL,
		0x23EEC6BBF543B2AFULL,
		0x82EE4E0065A3ACDAULL,
		0x5BE796638D2DEA6DULL,
		0xFF27A5E92A2A7773ULL
	}};
	t = -1;
	printf("Test Case 136\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 136 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -136;
	} else {
		printf("Test Case 136 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x98CD0E17C0683A42ULL,
		0xB69D962511135521ULL,
		0x139C1952E4C54272ULL,
		0x02A517CC131B37CFULL,
		0xFDD7133B124685B4ULL,
		0x5E86CF0C985DB464ULL,
		0xF10823A68BF9C550ULL,
		0xD268361F61DB5C1BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98CD0E17C0683A42ULL,
		0xB69D962511135521ULL,
		0x139C1952E4C54272ULL,
		0x02A517CC131B37CFULL,
		0xFDD7133B124685B4ULL,
		0x5E86CF0C985DB464ULL,
		0xF10823A68BF9C550ULL,
		0xD268361F61DB5C1BULL
	}};
	t = 0;
	printf("Test Case 137\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 137 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -137;
	} else {
		printf("Test Case 137 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFC6857EE5CB3EB17ULL,
		0x552085C177553275ULL,
		0x8920AD6BFEE9D62FULL,
		0x8307F32316315B02ULL,
		0x04A6895EF07D7A8FULL,
		0xC773F61518962019ULL,
		0xF1ABF67CCEEA1A6BULL,
		0x766393CEFB94A8FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD953E4BAEFCCC274ULL,
		0xEB7A9D565D716E23ULL,
		0x3E370DBD545621D6ULL,
		0x2EE091D2F241F892ULL,
		0xE646DB26D756278AULL,
		0xFBBC20D8E17E630FULL,
		0xE79BBDC1E7E8CB0BULL,
		0x2BFAB28CF9E3FAA9ULL
	}};
	t = 1;
	printf("Test Case 138\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 138 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -138;
	} else {
		printf("Test Case 138 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB645F9E5EFE47BFEULL,
		0x1BB81D28498ADF80ULL,
		0xF96E1170B1781B33ULL,
		0x8E0DF0533E7056CBULL,
		0xBD5AF9B9929EF1ABULL,
		0x6B02B81E2D3A6359ULL,
		0x2A2EE513884876ACULL,
		0x6F642124537116A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF645DBFE1F756966ULL,
		0xC3F95A3095085106ULL,
		0x498C0393FAF9BDC0ULL,
		0x66BFF100B603EBFDULL,
		0x88ED2C7B4DE798C9ULL,
		0x506C6BEC4A491DCCULL,
		0xEDDF5CF2FB5BE20DULL,
		0xC7B5781CEE13B0EDULL
	}};
	t = -1;
	printf("Test Case 139\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 139 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -139;
	} else {
		printf("Test Case 139 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBDCE382E1303AC7EULL,
		0x0CC2F4A9DB671A25ULL,
		0xB11E35240231AAA8ULL,
		0xA4C70D2268818002ULL,
		0xA49C985BB731E3E0ULL,
		0x2FE8A277F2C6AA6CULL,
		0xA557DF9CE3D4CE1EULL,
		0x0B9170F06B4DB2B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x889D0F25D34A908FULL,
		0xF64363E70BB549CCULL,
		0x6579D9E98F0E7669ULL,
		0x612315D2541F270EULL,
		0xEDC5197EE1ACEF24ULL,
		0xF7938EF91C775D93ULL,
		0x71C9A00B5E3D34A0ULL,
		0xE9D9E6345B62BF59ULL
	}};
	t = -1;
	printf("Test Case 140\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 140 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -140;
	} else {
		printf("Test Case 140 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF67C7716ED3FE692ULL,
		0xC997CE67326E3AA0ULL,
		0xEA04BAA6DF98486AULL,
		0xD6149770CA712685ULL,
		0x693D41867BF7C0A6ULL,
		0xC020A9C596C38462ULL,
		0xFB17D7242920E41EULL,
		0x9229D9E12EF456FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF67C7716ED3FE692ULL,
		0xC997CE67326E3AA0ULL,
		0xEA04BAA6DF98486AULL,
		0xD6149770CA712685ULL,
		0x693D41867BF7C0A6ULL,
		0xC020A9C596C38462ULL,
		0xFB17D7242920E41EULL,
		0x9229D9E12EF456FEULL
	}};
	t = 0;
	printf("Test Case 141\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 141 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -141;
	} else {
		printf("Test Case 141 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x55BB79FA3EA3C522ULL,
		0xEFA637FCF77AB695ULL,
		0x2A2BD933583D88ADULL,
		0xF4305A0F31608245ULL,
		0x2BA5D8BFB0B803F8ULL,
		0xEB493DFB8C0851EAULL,
		0xED83E1B35DF917B5ULL,
		0x816BB139A0CF302BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A80851548376D4DULL,
		0x11CD7E19BAC5B1F0ULL,
		0xFA3E9E8ECD374498ULL,
		0x10C3D44F37DDB1E4ULL,
		0x7ABEFAF2F3A4900BULL,
		0xB0FF6A3FF2187E29ULL,
		0x39C7B349934D0FBAULL,
		0x0DAF55C1CAFEFFD0ULL
	}};
	t = 1;
	printf("Test Case 142\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 142 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -142;
	} else {
		printf("Test Case 142 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB99141ABB0077C34ULL,
		0xEAC536840880A051ULL,
		0x934D3ED2CF76D87DULL,
		0xE18F6508E90C9FB8ULL,
		0x813A6342BC370F41ULL,
		0x74F37E4E1B688A84ULL,
		0xBBE459D605A0B64EULL,
		0xDD945C1A30C26FDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5287CA4B745C0AA1ULL,
		0xB47251905FB719FCULL,
		0x519F1F9D02F5CBC9ULL,
		0xDB3A7FBB5E4FFFA7ULL,
		0x3F2AAB132131D5A9ULL,
		0x0A601EFE709A1DD0ULL,
		0x0301838095562065ULL,
		0x14BA48B48DFCA467ULL
	}};
	t = 1;
	printf("Test Case 143\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 143 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -143;
	} else {
		printf("Test Case 143 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x44771021387264ABULL,
		0xBE2056804226DB2DULL,
		0x33C23CB874F32340ULL,
		0x7003031CB3D944F7ULL,
		0x7397B7BCF6A6044BULL,
		0x17D79E2814BB80B0ULL,
		0xA78A5D3F5806895CULL,
		0xA9CCF69ED7DD93DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8AA33FEB010BF7CAULL,
		0xAF9BD954BEFFF889ULL,
		0xADE72B7ED5BBB61DULL,
		0x8DB673E47EFB9EADULL,
		0x1F0D844F79774B91ULL,
		0x329F738CC61D2F89ULL,
		0xDF64D145DF3A6140ULL,
		0x73E82B8459A9ED55ULL
	}};
	t = 1;
	printf("Test Case 144\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 144 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -144;
	} else {
		printf("Test Case 144 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x987B0899A301239BULL,
		0x3B013E3AFEB6E590ULL,
		0x2D1065B74593CE0AULL,
		0x362E2766068CB886ULL,
		0xFDA8AFD17087C89CULL,
		0xBF4C8FFC5E0D613CULL,
		0xE5A63AC0EDA3198FULL,
		0x6B23A96B4A16E496ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x987B0899A301239BULL,
		0x3B013E3AFEB6E590ULL,
		0x2D1065B74593CE0AULL,
		0x362E2766068CB886ULL,
		0xFDA8AFD17087C89CULL,
		0xBF4C8FFC5E0D613CULL,
		0xE5A63AC0EDA3198FULL,
		0x6B23A96B4A16E496ULL
	}};
	t = 0;
	printf("Test Case 145\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 145 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -145;
	} else {
		printf("Test Case 145 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x75235F979999B129ULL,
		0x0BB2C38C6DDBEE1DULL,
		0xE6237C4BCB9BED33ULL,
		0xE3FF2570E5C73B01ULL,
		0x68991859D9314235ULL,
		0x694AC4460FC57DCDULL,
		0x6219A0442B224DA2ULL,
		0xBBF9DED82C838C07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03B6253ABD0FE112ULL,
		0x973044D93BBF1D80ULL,
		0x4E20DE9223A2FE26ULL,
		0xEB8A106798868D36ULL,
		0x46F8721BF48C90CEULL,
		0x3F11FA44FA5726AFULL,
		0xB01EF224171050A5ULL,
		0x2A6ED88D2CC19C66ULL
	}};
	t = 1;
	printf("Test Case 146\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 146 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -146;
	} else {
		printf("Test Case 146 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBD1216786899F20DULL,
		0x6B3049B0A2ABBD79ULL,
		0x2619F26F50E93406ULL,
		0x555AF5459448535CULL,
		0xF86AA6F478E597ECULL,
		0x00730A6F231F2898ULL,
		0x4CE2326E24973CE7ULL,
		0xBB34A08157167D9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97C34051A4C0C05DULL,
		0xDD52B61C66A5E11CULL,
		0x86361D58AE0F57BEULL,
		0xF4200FED0FA817E1ULL,
		0x598A8B795066BF32ULL,
		0x39FF601788E38ADCULL,
		0xE66FC140E36EA9C1ULL,
		0x463A3454E4EF5062ULL
	}};
	t = 1;
	printf("Test Case 147\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 147 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -147;
	} else {
		printf("Test Case 147 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAE79C9CD3189F71EULL,
		0xE749550310AFAE76ULL,
		0x69191F063D793A70ULL,
		0x0E4107E0F153E237ULL,
		0x9322226DA4B451CFULL,
		0xE86EE29CA4E6F4F1ULL,
		0xC9025320F40F5ED6ULL,
		0xA768828C4CAA5C91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17504EAE702D8ACCULL,
		0x430E2D2026FF2DA8ULL,
		0xB6B0C68D1DAC5F6FULL,
		0x8849C74095880385ULL,
		0xDB3CC7468BAA1B71ULL,
		0x7CE7CB6CB7885B01ULL,
		0xE969437268711095ULL,
		0x21B3C02AEDC7C279ULL
	}};
	t = 1;
	printf("Test Case 148\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 148 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -148;
	} else {
		printf("Test Case 148 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9DF41D944522945CULL,
		0x04E88D11BB6B7FFFULL,
		0x1826F5B6D09A9A35ULL,
		0xE3239BF1395E866CULL,
		0xDDED431347F60D8FULL,
		0x2451FBF56468EABBULL,
		0x989B576CBDB1523BULL,
		0x1F8736E6C1D30A58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DF41D944522945CULL,
		0x04E88D11BB6B7FFFULL,
		0x1826F5B6D09A9A35ULL,
		0xE3239BF1395E866CULL,
		0xDDED431347F60D8FULL,
		0x2451FBF56468EABBULL,
		0x989B576CBDB1523BULL,
		0x1F8736E6C1D30A58ULL
	}};
	t = 0;
	printf("Test Case 149\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 149 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -149;
	} else {
		printf("Test Case 149 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA616FCC1C1F28EC1ULL,
		0xC91DE450B5316DF5ULL,
		0x766C061F18B52BB4ULL,
		0xB918AA6F472A1E81ULL,
		0x8893FAF44308D351ULL,
		0x31337C4877B0FC42ULL,
		0xE5C43114022E5881ULL,
		0x1B505E95E8584770ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70359FFAA3572BA1ULL,
		0x532ACF35F962D131ULL,
		0x99C021630C3F0C47ULL,
		0x037E73C6F34DB6A8ULL,
		0x726B5F2FCEE8F415ULL,
		0xC5330B6809B9E920ULL,
		0x2B03C15271B60EC7ULL,
		0x47C3537B20C5AEFFULL
	}};
	t = -1;
	printf("Test Case 150\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 150 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -150;
	} else {
		printf("Test Case 150 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0A62DC6D4BF38E13ULL,
		0xAD47A85A5725D219ULL,
		0x264A23D1F7F54F20ULL,
		0x7EBDED39218658D4ULL,
		0xFC9B6608FB0C731EULL,
		0x76FDFF168C44CA57ULL,
		0x6F256E03F1D1B65CULL,
		0x2EF1A00A1B81075AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C376A71F831E14DULL,
		0x08ECC995FE2CECEEULL,
		0x73AAB6904628DFDBULL,
		0x1B0CDCD8F7ED79CBULL,
		0x5FF7FB9A3DE53573ULL,
		0xAB5F10452B828E43ULL,
		0xCBF67F935F2E4814ULL,
		0x14C59A4542CCD4BAULL
	}};
	t = 1;
	printf("Test Case 151\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 151 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -151;
	} else {
		printf("Test Case 151 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x80B0DD071764CDDEULL,
		0x0E5A1EC9567B1EDDULL,
		0x0713ECF520A31406ULL,
		0xCCC03CBD44D6A4B8ULL,
		0x2D6C5FF18F4C80D1ULL,
		0xA1FBA382EDCA5FBCULL,
		0x56EAB597475D5F82ULL,
		0xA2082E818601DD9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82C6EDE39A32B57EULL,
		0xCE93D90E73594BDEULL,
		0x6EC73962594E832BULL,
		0x4C4E7D5AFA23AAFDULL,
		0x349301F02B34F537ULL,
		0x7AF51E0375F14779ULL,
		0x1DB71200527F87B5ULL,
		0xC115E01749805066ULL
	}};
	t = -1;
	printf("Test Case 152\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 152 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -152;
	} else {
		printf("Test Case 152 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0426203F99B4189CULL,
		0xEF6AB85ABBD4DE4EULL,
		0x4F0105F5B4FBF9B7ULL,
		0x980C13F271B56305ULL,
		0xCD19924F7C94CBD5ULL,
		0xEF08251A7CA83420ULL,
		0x4E9F5CFCE7863368ULL,
		0xFD3A49374159873CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0426203F99B4189CULL,
		0xEF6AB85ABBD4DE4EULL,
		0x4F0105F5B4FBF9B7ULL,
		0x980C13F271B56305ULL,
		0xCD19924F7C94CBD5ULL,
		0xEF08251A7CA83420ULL,
		0x4E9F5CFCE7863368ULL,
		0xFD3A49374159873CULL
	}};
	t = 0;
	printf("Test Case 153\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 153 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -153;
	} else {
		printf("Test Case 153 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x597B624F1BEDD0A8ULL,
		0x3BBD25317BF73717ULL,
		0x56E9D20670D5C242ULL,
		0x8E99205BABE167C5ULL,
		0x1B0EE57BB590F8FAULL,
		0x4AEFD237E254ED0BULL,
		0x4E79412D2D5B933FULL,
		0x095C6A59AC798491ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66690A7B191AF8B4ULL,
		0xAF583E7AA5452671ULL,
		0x1161599A210C8F91ULL,
		0x17E9507D2F5E9BAFULL,
		0x80CFFBCDF7719B2BULL,
		0xD1C7735F59746C32ULL,
		0xE76FFEEAB135B956ULL,
		0x12EF463229F91508ULL
	}};
	t = -1;
	printf("Test Case 154\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 154 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -154;
	} else {
		printf("Test Case 154 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE497322E3D7D4D6DULL,
		0x660091817C6E929EULL,
		0xE503E8683DEC04D1ULL,
		0xE0C6BCC27A23D1BEULL,
		0x6ABED3E828E49E81ULL,
		0xD9B054149DD93D5EULL,
		0xDEBAC8C71C46EAAFULL,
		0x9D3977BC37E8382CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48E7F6E2A037000DULL,
		0x49CA16D23FB51D23ULL,
		0x71C9E6E10A02923BULL,
		0x64399860701623AEULL,
		0x817CB4E1514E66C0ULL,
		0x8FC834A06BF8A847ULL,
		0x239A336438EB4B08ULL,
		0xFD3F30C274844395ULL
	}};
	t = -1;
	printf("Test Case 155\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 155 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -155;
	} else {
		printf("Test Case 155 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9AA303523A0AEE4DULL,
		0x14569488C31C09E2ULL,
		0xD06E0C1AB291E3D4ULL,
		0xA061B64ED758171BULL,
		0x8F5F2C7A0C2447B0ULL,
		0x86DE09E46977E59AULL,
		0x74A4840548B48874ULL,
		0xB45FD1AAB514E677ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DC94E34F5BB10DFULL,
		0x3C622CEE89717391ULL,
		0x48000AC831A64ED3ULL,
		0xD2BE7470E5F7DCD3ULL,
		0x35ACE25B8C6C5E8DULL,
		0xB09E60C4E08D2146ULL,
		0xC57F9CDFF16CC25DULL,
		0x85834D1BACB6908CULL
	}};
	t = 1;
	printf("Test Case 156\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 156 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -156;
	} else {
		printf("Test Case 156 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4757462AB248F8C4ULL,
		0xA53C9BB162C008F5ULL,
		0x70197DA893D78853ULL,
		0xA525A14981FEBFB8ULL,
		0x77838985D36C4A33ULL,
		0x8C3BA40967C00C04ULL,
		0xCE98626CE5DE4F00ULL,
		0x7A033129E1EDD0F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4757462AB248F8C4ULL,
		0xA53C9BB162C008F5ULL,
		0x70197DA893D78853ULL,
		0xA525A14981FEBFB8ULL,
		0x77838985D36C4A33ULL,
		0x8C3BA40967C00C04ULL,
		0xCE98626CE5DE4F00ULL,
		0x7A033129E1EDD0F4ULL
	}};
	t = 0;
	printf("Test Case 157\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 157 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -157;
	} else {
		printf("Test Case 157 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x12ADB6531E631CFDULL,
		0x98AF652C9DEE5634ULL,
		0x94EAD52210FD57D2ULL,
		0x048B4F10225DDE29ULL,
		0xBBAF07F6322B8F1BULL,
		0xA67BD432C734E180ULL,
		0x50BEDE0835306AF8ULL,
		0xC36ABB3176EEBFABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x568E0A6805A556D0ULL,
		0x939C99501E56D040ULL,
		0x32CC53F493CDFF93ULL,
		0x3FD6EA225A799591ULL,
		0xB8BF7BD44C411E94ULL,
		0x2CA436FC07CF6A4EULL,
		0x5F2F2F16E36EC770ULL,
		0x4DEAF7389FCA1D5EULL
	}};
	t = 1;
	printf("Test Case 158\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 158 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -158;
	} else {
		printf("Test Case 158 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5C59F83D72B59B34ULL,
		0xEFE2BA89D9C5F8ABULL,
		0xAE482BE663DD446DULL,
		0x585976A94E492613ULL,
		0xD9B551CFDD6F4D4AULL,
		0x683743A294814896ULL,
		0xB471F4261EAD74CAULL,
		0xD60B82089488832FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x509A960CF690E367ULL,
		0x2E9E910E276AE51CULL,
		0xB8E469E9749BA405ULL,
		0x2A72A4BB83247CAAULL,
		0x355212469CAC0046ULL,
		0xF419740071B167A3ULL,
		0x2FB26855CA370034ULL,
		0x6A67EEDD2720B57CULL
	}};
	t = 1;
	printf("Test Case 159\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 159 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -159;
	} else {
		printf("Test Case 159 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBE50A0420D24156CULL,
		0x4D73D7120B649539ULL,
		0xD9F6085A7E50E213ULL,
		0x9FB1F927D25D92F2ULL,
		0x40D6B261BB9FF36FULL,
		0x68CB918826791AD6ULL,
		0x5358C689F1BD2342ULL,
		0x3D4774DF3B5AFB8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2266F74587FDB437ULL,
		0xC78DA5F8B58177DCULL,
		0x953381991C9F5B3DULL,
		0x29B6BCAFDDF2A683ULL,
		0xDCB65AFC4585FB19ULL,
		0x86118A3FF31F0B9CULL,
		0x113BED3AB90F5FFFULL,
		0xC011546AE8B8E2B2ULL
	}};
	t = -1;
	printf("Test Case 160\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 160 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -160;
	} else {
		printf("Test Case 160 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x53A15B4BE903FBB9ULL,
		0xE35621F63C184442ULL,
		0x1155BC7212E0B2C5ULL,
		0x0C27E6B09797B641ULL,
		0xD0E5707C19CEA71AULL,
		0x6C7AF805575DAB84ULL,
		0xDA95C4C68547D64FULL,
		0x1D2BA8B86B8AEDBDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53A15B4BE903FBB9ULL,
		0xE35621F63C184442ULL,
		0x1155BC7212E0B2C5ULL,
		0x0C27E6B09797B641ULL,
		0xD0E5707C19CEA71AULL,
		0x6C7AF805575DAB84ULL,
		0xDA95C4C68547D64FULL,
		0x1D2BA8B86B8AEDBDULL
	}};
	t = 0;
	printf("Test Case 161\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 161 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -161;
	} else {
		printf("Test Case 161 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB43658D2B822EDA3ULL,
		0xBE53830C1D53E068ULL,
		0xC36992DF2CA7A52BULL,
		0x566C70C0258C549DULL,
		0x4256F73436664E96ULL,
		0x2ACFA6B601B6F2D7ULL,
		0x2BD2DAE20DFB58A5ULL,
		0xAD5796F823183C22ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8903AFA75896DA22ULL,
		0x0399E07FC2DB1E57ULL,
		0xBD7F33AC6FC48723ULL,
		0x549004B906CFD366ULL,
		0xA1CD447746CD8BA6ULL,
		0x3FF76F7D4003A91EULL,
		0x3AF6007874CFDBDAULL,
		0x27B02A85144D5A3EULL
	}};
	t = 1;
	printf("Test Case 162\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 162 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -162;
	} else {
		printf("Test Case 162 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDDC1CA8CC313DCB3ULL,
		0x17475DA48732E44EULL,
		0x268CC99C0992DEE3ULL,
		0x3585A0EAC244F8F6ULL,
		0x2F7781221A7F78B2ULL,
		0x8D9CFC0F3C1A86E3ULL,
		0x613A354C26FF97B2ULL,
		0x0972A09EEC655107ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7284DB419C8DA6D8ULL,
		0x5D45B8DEAFC27E80ULL,
		0xA10838867937AE66ULL,
		0x3E0F29485E7B2BAFULL,
		0xE4E0AE901275BDB9ULL,
		0x49D8550E70D2C445ULL,
		0x699C0DDE61DCD869ULL,
		0x22FEB834BF63140DULL
	}};
	t = -1;
	printf("Test Case 163\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 163 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -163;
	} else {
		printf("Test Case 163 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x68ABD2D92FF4581CULL,
		0x364089F8601574EEULL,
		0xF31A14C908669D4DULL,
		0x237290ADAF2EA55AULL,
		0xC31B9AA4A8B33397ULL,
		0x0DAF40C600A2D336ULL,
		0x79ECBA52A7C7850DULL,
		0x8425F35DC993F8D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34B6C953B7C97AC8ULL,
		0x5130EEBB387649ADULL,
		0x7B3119E473617D5BULL,
		0x98256F69C5EB656AULL,
		0x9D8FB74C12316384ULL,
		0x6A2E4A65B3D41F24ULL,
		0xF13B8D0572F214DDULL,
		0x1E0880989B096B21ULL
	}};
	t = 1;
	printf("Test Case 164\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 164 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -164;
	} else {
		printf("Test Case 164 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x67EB399F61DA66FEULL,
		0xB5681500BC0B9C59ULL,
		0x4FA68C4D8967CFB3ULL,
		0xD6CEBDE683805250ULL,
		0xD68C04B277422B21ULL,
		0xE2084E3388C4ADECULL,
		0x4DE007DF18E9BF20ULL,
		0xA147049281B63962ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67EB399F61DA66FEULL,
		0xB5681500BC0B9C59ULL,
		0x4FA68C4D8967CFB3ULL,
		0xD6CEBDE683805250ULL,
		0xD68C04B277422B21ULL,
		0xE2084E3388C4ADECULL,
		0x4DE007DF18E9BF20ULL,
		0xA147049281B63962ULL
	}};
	t = 0;
	printf("Test Case 165\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 165 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -165;
	} else {
		printf("Test Case 165 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD2532B062D1974B0ULL,
		0xDA322EBBC2E8547BULL,
		0xFF79C14FB7A83585ULL,
		0xD60FB3E6BB136EFEULL,
		0x20ACBD374F9ABE49ULL,
		0x1078F9B697460AE7ULL,
		0x441337D0975805A5ULL,
		0x368BA2164062F075ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B1126E03EE85257ULL,
		0xBB76B8499C86E415ULL,
		0xD688268A5B1BE411ULL,
		0xA2EE0032C8D7FC55ULL,
		0xE8E916FF709DFB49ULL,
		0x478009A50D02C1D7ULL,
		0xB773A3F7DF79B8AEULL,
		0x80EBCA3C9E37EDE4ULL
	}};
	t = -1;
	printf("Test Case 166\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 166 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -166;
	} else {
		printf("Test Case 166 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA4FAB1D9247C457FULL,
		0x03A4859207F13055ULL,
		0xB37744B1577B446BULL,
		0x5306015AA34AECAEULL,
		0x6F208596D7C5219BULL,
		0x42531458C6D4404AULL,
		0x4B171428603F52F6ULL,
		0xA7D9432C44BD29B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36BA1899800037B6ULL,
		0x589F85B15BD5CF53ULL,
		0x3A555691B8E20344ULL,
		0x4AAF4A40223ED7E5ULL,
		0x4E9C49F5CA039C47ULL,
		0x5E3F195D095AD917ULL,
		0x49239B470EAF06CAULL,
		0xDC509C0BA4CA82A2ULL
	}};
	t = -1;
	printf("Test Case 167\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 167 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -167;
	} else {
		printf("Test Case 167 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA61246D3F2CDACFAULL,
		0xC2C9A2A6EDE3CC6EULL,
		0x63314FCE60C0A557ULL,
		0x503B51C186C5DA44ULL,
		0x18064254CE558CB7ULL,
		0xC1C85A2789812DD9ULL,
		0x37447A47DCFA2AFEULL,
		0x9FDD0EC3FF5D7D41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29D8998D186D93AFULL,
		0x860B8F469CD865D9ULL,
		0x5BCDE6A94FAE548DULL,
		0x19256D39CECA8975ULL,
		0x00EA45FB0B3720A0ULL,
		0xE85C6D10889CD2EBULL,
		0xBAD673E4FE1C176DULL,
		0x017BF0CA6E9D2CABULL
	}};
	t = 1;
	printf("Test Case 168\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 168 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -168;
	} else {
		printf("Test Case 168 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3CB497D54368FB6EULL,
		0x1175CF9F642BBF25ULL,
		0x4F944A6128993E4AULL,
		0xEE14825E20BA57AAULL,
		0xA8C134FB74B8D9B5ULL,
		0xAC9748FC1690AD3BULL,
		0x177CDBF2B3ABA8D5ULL,
		0x227EC78543C2B959ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CB497D54368FB6EULL,
		0x1175CF9F642BBF25ULL,
		0x4F944A6128993E4AULL,
		0xEE14825E20BA57AAULL,
		0xA8C134FB74B8D9B5ULL,
		0xAC9748FC1690AD3BULL,
		0x177CDBF2B3ABA8D5ULL,
		0x227EC78543C2B959ULL
	}};
	t = 0;
	printf("Test Case 169\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 169 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -169;
	} else {
		printf("Test Case 169 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB4C9A8A2FBA1AC16ULL,
		0x5411FB9E5C65D106ULL,
		0xDB7DDFE923759268ULL,
		0x25202A91387C0BA6ULL,
		0xCA748B945393ED08ULL,
		0x4CCB9983A400C5D0ULL,
		0x682971081D380CF8ULL,
		0x4FC55A4B4512BAE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12642C267F9440DDULL,
		0x49DDEAEBAF21284FULL,
		0xBCBC5F45C8E40571ULL,
		0x5311020897C183FDULL,
		0xF822271A53093458ULL,
		0x7CBF6B1F27FE0369ULL,
		0x76F1FCD94F8D9B67ULL,
		0xE6E66647C9601832ULL
	}};
	t = -1;
	printf("Test Case 170\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 170 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -170;
	} else {
		printf("Test Case 170 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x01C3FE1E691AE841ULL,
		0x11CE04FA295463C0ULL,
		0xA2603F22E9076E46ULL,
		0x49D610A4ECA8F68FULL,
		0x2C2FCF0B20953A90ULL,
		0x164CB34E86BCD55EULL,
		0x23E499A3C933E719ULL,
		0x168939D47DE2CE6FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27EBE360C1D68209ULL,
		0x99C4239503407CA2ULL,
		0x0A0B8BFD8A917C02ULL,
		0x7138B985537BA8AFULL,
		0x24EF5ECCBBE72B04ULL,
		0x070F21E818D822E1ULL,
		0x6CF3F3A32B43E3A9ULL,
		0xBBA0C6B9C3E5969FULL
	}};
	t = -1;
	printf("Test Case 171\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 171 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -171;
	} else {
		printf("Test Case 171 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x392A7D641EA684CBULL,
		0xE3D23C483383562FULL,
		0x87535DFA8309D8F3ULL,
		0x09104D31E1FC9249ULL,
		0xEBE0F98B716DEBACULL,
		0x5E32F755D7242CE5ULL,
		0xF7CD2A959DFB61E0ULL,
		0x2E4996322FE5FC72ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x979EBD869469BD74ULL,
		0x8D3F8C75979F0769ULL,
		0x4F8D29D5383E690DULL,
		0xC5E8F38BCA41F324ULL,
		0x097B5308C454BEBDULL,
		0xA821DA17E2011C60ULL,
		0xAC4E948BC1B97DE3ULL,
		0x3C8A604921D7D4C9ULL
	}};
	t = -1;
	printf("Test Case 172\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 172 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -172;
	} else {
		printf("Test Case 172 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA4F4F06C6222A014ULL,
		0xB27A76C11E224853ULL,
		0xD7EEE858E7608F22ULL,
		0x9A090E53C31F7AEDULL,
		0x0DB0C2434B14C978ULL,
		0x0615C7D65110FD8BULL,
		0x717548CDA13E745AULL,
		0xD232F805C8751FDFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4F4F06C6222A014ULL,
		0xB27A76C11E224853ULL,
		0xD7EEE858E7608F22ULL,
		0x9A090E53C31F7AEDULL,
		0x0DB0C2434B14C978ULL,
		0x0615C7D65110FD8BULL,
		0x717548CDA13E745AULL,
		0xD232F805C8751FDFULL
	}};
	t = 0;
	printf("Test Case 173\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 173 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -173;
	} else {
		printf("Test Case 173 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7A971B5CD0F8BEECULL,
		0x3731A38C347E84CFULL,
		0xF26D8C47A9BFB9A0ULL,
		0x16194FC102BEBB9EULL,
		0xB42C38C97040314AULL,
		0xD5B45A0327AB232FULL,
		0xEB67991DFB332F4AULL,
		0x874213F9E30B4843ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD809091EDC86D489ULL,
		0x4513BEEE15EB0BE0ULL,
		0xEDA49D9DF18B89C1ULL,
		0x2A8441819BAF3E8DULL,
		0x7AD044CAB5E9601DULL,
		0xC370500D7763680FULL,
		0xF4DB891CD363697EULL,
		0x68A95E02E65876F4ULL
	}};
	t = 1;
	printf("Test Case 174\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 174 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -174;
	} else {
		printf("Test Case 174 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1FF6C1C385139BAFULL,
		0xE400EDD4FC05BE4EULL,
		0x529D61ED85A8B7B4ULL,
		0x29045FE61DB40C4EULL,
		0x84AA5A8A27DA392BULL,
		0x0E6B87E89704EA6EULL,
		0xF1EC31983439341AULL,
		0x42266CEEF2634502ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0C81B76357641FFULL,
		0x868CDAE60FECF208ULL,
		0x4ACA853223EA7208ULL,
		0xCD885A18CF5C47B8ULL,
		0x0CA217CC39C130BCULL,
		0x22535395B00BB2D2ULL,
		0x18F70AA1210C9D5DULL,
		0x45F836456BE4BEE0ULL
	}};
	t = -1;
	printf("Test Case 175\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 175 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -175;
	} else {
		printf("Test Case 175 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6F830003DF698DA8ULL,
		0xB3E5033A3FBF9300ULL,
		0xF988B15BAA842048ULL,
		0x503EDBCD7C339AC1ULL,
		0xC2BC015076EAA9C3ULL,
		0xE1D5938E7BB049AFULL,
		0xFA8DAF582185D2CFULL,
		0x98024BA84BF61064ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D739DB9F61141A3ULL,
		0x1F3A5D3887B92B68ULL,
		0x36C23A498A65D432ULL,
		0x08D685C1102DA865ULL,
		0x5D4B1A24017DDD4BULL,
		0xA7DB67B5DFE553C0ULL,
		0xBF2AF17B841EE3E9ULL,
		0x9A650844520F72B8ULL
	}};
	t = -1;
	printf("Test Case 176\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 176 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -176;
	} else {
		printf("Test Case 176 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6B2CF8084BF449CAULL,
		0x374C7714CACC6E03ULL,
		0x6E42DEC829328BB6ULL,
		0xE1758A9DA2D9AEFAULL,
		0x10ED2E1908F48399ULL,
		0x9F238CC18438755DULL,
		0xBFBAA539849E74E6ULL,
		0xAF6344C071C87577ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B2CF8084BF449CAULL,
		0x374C7714CACC6E03ULL,
		0x6E42DEC829328BB6ULL,
		0xE1758A9DA2D9AEFAULL,
		0x10ED2E1908F48399ULL,
		0x9F238CC18438755DULL,
		0xBFBAA539849E74E6ULL,
		0xAF6344C071C87577ULL
	}};
	t = 0;
	printf("Test Case 177\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 177 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -177;
	} else {
		printf("Test Case 177 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0541C0D95ECB7CBBULL,
		0xCAC67506EDF0A2D0ULL,
		0x7311D5164E7166D8ULL,
		0x148B63AE836FD230ULL,
		0x50F02107D6C3D437ULL,
		0xEAF03F1CD13CA87DULL,
		0xFD7D2AB12E8093C7ULL,
		0x826D724288DE2302ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74D1CA871F35DC8BULL,
		0x19C1EB8819C406FFULL,
		0xB6D35E0FD05D16FEULL,
		0x943737AAD00A5930ULL,
		0x305C6B3D73269BAEULL,
		0xF9262F0D9E47B204ULL,
		0xE33ABB1658A1E1C2ULL,
		0xE5CE7AE26F4D55F4ULL
	}};
	t = -1;
	printf("Test Case 178\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 178 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -178;
	} else {
		printf("Test Case 178 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x39043A8DC15E915DULL,
		0xCB1105F701F27870ULL,
		0x2E5347AA9E7C0359ULL,
		0x17D1427A138FABC5ULL,
		0x81C0B328EC3C0C28ULL,
		0x4ED2715F3AD0718BULL,
		0x1FA36D9ED58D8B8CULL,
		0x20EFB9BED227EA3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x434FD4A8FD25CF0DULL,
		0x1412A2693F96B4ABULL,
		0x2F80C31C99295DB1ULL,
		0xC473D8DA3622885EULL,
		0x9AE2EBE186D48AE0ULL,
		0xDB995F98EDC48594ULL,
		0x18082C0E6BB21755ULL,
		0xEA57CDFC37F6F4ECULL
	}};
	t = -1;
	printf("Test Case 179\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 179 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -179;
	} else {
		printf("Test Case 179 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBD3073AE32656CA6ULL,
		0xC1300634E3AF6C04ULL,
		0x0FC1CE85208B77D3ULL,
		0x403240F861F7E66EULL,
		0x02D4641E43CDF12EULL,
		0x86EFBA30FDA8E860ULL,
		0x0DE6F73ED427898CULL,
		0x7BAFF875A43DFF5AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA599B12A888916F3ULL,
		0x11A08D3874D776ECULL,
		0x02CDD0D3C3C043F2ULL,
		0x00B460760A12713BULL,
		0xDCFC0955F6FFC1B6ULL,
		0xFD66998481FBF1D8ULL,
		0xC6EC674832359A30ULL,
		0x3C23EFA137C1593CULL
	}};
	t = 1;
	printf("Test Case 180\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 180 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -180;
	} else {
		printf("Test Case 180 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBE8834F41181C88BULL,
		0x3CA8EE4AEC622E34ULL,
		0x6E424675E384F7BFULL,
		0x4E71E6784E69FA5DULL,
		0xEF27A33BC9887A4FULL,
		0x0DEAB730DBCF5FD8ULL,
		0x4A49917E1553E7E8ULL,
		0x2BC310953C58F851ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE8834F41181C88BULL,
		0x3CA8EE4AEC622E34ULL,
		0x6E424675E384F7BFULL,
		0x4E71E6784E69FA5DULL,
		0xEF27A33BC9887A4FULL,
		0x0DEAB730DBCF5FD8ULL,
		0x4A49917E1553E7E8ULL,
		0x2BC310953C58F851ULL
	}};
	t = 0;
	printf("Test Case 181\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 181 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -181;
	} else {
		printf("Test Case 181 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4697D1F7F506C311ULL,
		0x40380545A079983AULL,
		0xDA609EB409A756EEULL,
		0x4A6EB9467B658783ULL,
		0xAFC56C944C68D152ULL,
		0xFFBA214E2F57CE32ULL,
		0x44B6CD1DD17259DEULL,
		0x4457E3FA003438C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xABA5847B139C5FB3ULL,
		0x48F3E4543D9D3733ULL,
		0x9A325FC50B7CAD0DULL,
		0x9FC91E1F9B939EEDULL,
		0x564DA90794BE6A10ULL,
		0xC19235A78EEBA83DULL,
		0x4D663D06E962ADF4ULL,
		0x15060C62A23A126EULL
	}};
	t = 1;
	printf("Test Case 182\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 182 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -182;
	} else {
		printf("Test Case 182 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6C061CE9F42AFF2FULL,
		0xD595AA8B4619A0BAULL,
		0x7783E61E59A1E1A0ULL,
		0x9B9DB99C7A02B2E6ULL,
		0x31630CA46EE8B757ULL,
		0x38E60A8661597D61ULL,
		0x85AEBE82425666F6ULL,
		0x31D0722302FD2688ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x461968E3FF9983EDULL,
		0x4E8D752E269DEB72ULL,
		0xFE3FA3488A2D95A9ULL,
		0x9245C76EEFA2C42FULL,
		0x61899803EC32140DULL,
		0xE996D9462AB065CEULL,
		0x7EEAB25ABD855843ULL,
		0x0439F1B438F4BC54ULL
	}};
	t = 1;
	printf("Test Case 183\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 183 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -183;
	} else {
		printf("Test Case 183 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7B9037073984AF6FULL,
		0xCBEAEAE9CF3DA8E0ULL,
		0xC4DC34DA762346D7ULL,
		0xAB3350C6CA99A33BULL,
		0xBE6748AB42F8FC1CULL,
		0xCAE6148DA217A4B3ULL,
		0xA13A57E5C6533EFBULL,
		0x94CC02F2CAD1CAAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E5B54FDE6B83598ULL,
		0x170478F2BB37C944ULL,
		0x2F3FD30AF4DC78FAULL,
		0xA49D2696F09D8059ULL,
		0x9ACD37042BC202B1ULL,
		0x33B56804312DA6D3ULL,
		0x4181AA64CD742559ULL,
		0x56468A5D98DCADF3ULL
	}};
	t = 1;
	printf("Test Case 184\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 184 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -184;
	} else {
		printf("Test Case 184 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x410DE61FCB351923ULL,
		0x4AB2FC1D68A3692AULL,
		0x5199B875547B39A5ULL,
		0x75CCF5C485E8E3B9ULL,
		0xA7661EF0CCA85F1FULL,
		0xEED6902B989EF71DULL,
		0xB9DFF2943E7F1B96ULL,
		0xFDEEBF279DFC8CE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x410DE61FCB351923ULL,
		0x4AB2FC1D68A3692AULL,
		0x5199B875547B39A5ULL,
		0x75CCF5C485E8E3B9ULL,
		0xA7661EF0CCA85F1FULL,
		0xEED6902B989EF71DULL,
		0xB9DFF2943E7F1B96ULL,
		0xFDEEBF279DFC8CE1ULL
	}};
	t = 0;
	printf("Test Case 185\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 185 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -185;
	} else {
		printf("Test Case 185 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x10B366912D2EC8C8ULL,
		0x6E0E5622FDE812A1ULL,
		0x6B2B9DF6F148490AULL,
		0xD643BB61D1CC1744ULL,
		0x53D3DF59190CCD5FULL,
		0xBCA683B63F02752CULL,
		0x2E61A9D3B6148441ULL,
		0x0FA983350154963DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8668FAF506153E40ULL,
		0x98B2E6BBF7D66744ULL,
		0x9B1937FF99674F14ULL,
		0x141439028D75CA3DULL,
		0x99AA13CA2EE04CA2ULL,
		0xC7EAF6DAA8E37098ULL,
		0x50ED1311A1C87F1DULL,
		0xA758977DE68C0479ULL
	}};
	t = -1;
	printf("Test Case 186\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 186 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -186;
	} else {
		printf("Test Case 186 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x94C08C3B9D1FBF59ULL,
		0x9E930C250F528DBFULL,
		0xB3D59A66A601D860ULL,
		0xAEDE47AC550242C4ULL,
		0x726F2A210C4E2286ULL,
		0x1395CA81F7DBDEEBULL,
		0xBCCC1CB846B6D041ULL,
		0x717958BFAC2F5586ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84A69C3E2D20BD64ULL,
		0x770DDB28F679C243ULL,
		0x45A2DA0BA6515AD9ULL,
		0xD880D233D6444FE6ULL,
		0x04636C722FD419B6ULL,
		0x0FA754495FC8A28AULL,
		0xAF307EA17A3B7EAFULL,
		0x5B1627A2C88F4D64ULL
	}};
	t = 1;
	printf("Test Case 187\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 187 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -187;
	} else {
		printf("Test Case 187 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5E43AEA201D396F3ULL,
		0x9B46322A2CBD0DE4ULL,
		0x8B7A13ECC6F88473ULL,
		0x294C520F88AEF276ULL,
		0x6366942AF4E96698ULL,
		0x7D6210130087F159ULL,
		0x168F802FCA8B3892ULL,
		0xDB56B9C47AB185FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DEFD8DB6FE2F01DULL,
		0xC0DDAC3C4C5EEB35ULL,
		0xA133FE26A9E8B478ULL,
		0x3234F56FF2305A38ULL,
		0x814FFCCC8D2ACBFCULL,
		0x0D4178F6FDAA17BCULL,
		0x96172D69EBE8B85EULL,
		0xF1771372989C9286ULL
	}};
	t = -1;
	printf("Test Case 188\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 188 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -188;
	} else {
		printf("Test Case 188 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x686BE41AFACE444BULL,
		0x44218A46E0191924ULL,
		0x7910BDC5E8642D90ULL,
		0xC63E1BAB694FA997ULL,
		0x4A9DE8C6FEADAF6FULL,
		0x6D553C313E2AFF7FULL,
		0x93F993ABA39CB43BULL,
		0x1F2926B3ED8123B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x686BE41AFACE444BULL,
		0x44218A46E0191924ULL,
		0x7910BDC5E8642D90ULL,
		0xC63E1BAB694FA997ULL,
		0x4A9DE8C6FEADAF6FULL,
		0x6D553C313E2AFF7FULL,
		0x93F993ABA39CB43BULL,
		0x1F2926B3ED8123B7ULL
	}};
	t = 0;
	printf("Test Case 189\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 189 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -189;
	} else {
		printf("Test Case 189 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x85CBDB914D33248CULL,
		0xD8CF6AFB54701038ULL,
		0xD4C0764A60083F5FULL,
		0x57CE83BF9DB3D7ADULL,
		0x179D5C0314C3638EULL,
		0x1F354E62F85E1774ULL,
		0x57AB7D68283A8300ULL,
		0x90A5DFC08EEDA032ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8606DA545BC6831ULL,
		0xE244DA104500BA5AULL,
		0xCB4D2ADD3455132DULL,
		0x054A226A1B5DA03BULL,
		0xEDE8A285FF904123ULL,
		0xCA915706A1F150E4ULL,
		0x74A47F00768854A7ULL,
		0x715CFA029D029291ULL
	}};
	t = 1;
	printf("Test Case 190\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 190 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -190;
	} else {
		printf("Test Case 190 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3A029E508F4E8AB7ULL,
		0xBDA708B467EA92B2ULL,
		0x8DA98F74946AB586ULL,
		0xB9E27FD0003EDA39ULL,
		0x3C074C7E91C102EFULL,
		0x8D60924F5AFB0128ULL,
		0xEA1BA94A92C1B20DULL,
		0xE6E02FE600106658ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE37CA92B82762F21ULL,
		0x3E1AD3E8E49831B9ULL,
		0x51AEAB792129E0B6ULL,
		0x03A836552A832D69ULL,
		0x409B3C87B2A3E914ULL,
		0xB0D2A2BAC818599BULL,
		0xE210FC50A4F53FF0ULL,
		0x5923D5FBFD142835ULL
	}};
	t = 1;
	printf("Test Case 191\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 191 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -191;
	} else {
		printf("Test Case 191 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF375D29704FCCF4BULL,
		0x7F114F60C5A8E0F2ULL,
		0xF2B4D6C2E7B86D1DULL,
		0x29A617AF51528C10ULL,
		0x5E2E8B26087C73C0ULL,
		0xB5AC7FF77A09B131ULL,
		0x104843912B2C040BULL,
		0x7E42B5AF8E5E1568ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2BC53AF8E72ED55AULL,
		0x54A388C67E3D3C47ULL,
		0x03C3883CE94B6A10ULL,
		0x44FD350AEAE14C26ULL,
		0xB10C504407A1D040ULL,
		0x5C2D210FD08B4FADULL,
		0x37C28E44D5AD332EULL,
		0x97F148BB46667403ULL
	}};
	t = -1;
	printf("Test Case 192\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 192 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -192;
	} else {
		printf("Test Case 192 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x49626191EF8E4714ULL,
		0x2E03AC62EB8CA855ULL,
		0x9E3F4CE6F94B0853ULL,
		0x57013EA0CCF56749ULL,
		0xF39C84ECC2E08EA9ULL,
		0x1B177DD5B30AABBBULL,
		0xD1DED6D709889720ULL,
		0xDB9CAD15D9D3C000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49626191EF8E4714ULL,
		0x2E03AC62EB8CA855ULL,
		0x9E3F4CE6F94B0853ULL,
		0x57013EA0CCF56749ULL,
		0xF39C84ECC2E08EA9ULL,
		0x1B177DD5B30AABBBULL,
		0xD1DED6D709889720ULL,
		0xDB9CAD15D9D3C000ULL
	}};
	t = 0;
	printf("Test Case 193\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 193 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -193;
	} else {
		printf("Test Case 193 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x52185FD8AC7923F3ULL,
		0xDB123CCBFB0B3F3CULL,
		0x36D9C3274998005EULL,
		0x6B29E1108354B38DULL,
		0xE0D955D080EAA616ULL,
		0xAA83192FE3CDA589ULL,
		0xADADB747A97D1B39ULL,
		0x2E62DA88F6D959C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80C33A930D5D8B0AULL,
		0xCA362F07F1E3F2BAULL,
		0x9AF9B432D9B8615CULL,
		0xCC8E980946FEB447ULL,
		0xC00AB12BA85DB4A4ULL,
		0x20501694FFC6D012ULL,
		0xE488815E90F71766ULL,
		0x88F599847E774FCEULL
	}};
	t = -1;
	printf("Test Case 194\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 194 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -194;
	} else {
		printf("Test Case 194 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC4B2BF1B7DC2D5F6ULL,
		0xBB5F6CE0287B379BULL,
		0x895227689FBEB51DULL,
		0x66B4D74F3143A5DFULL,
		0xCB3D19FAEF0DECCAULL,
		0x8202742DA178688BULL,
		0x6F499CE65635EF79ULL,
		0x3051C79DA4CA5924ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC43AA8A6A23BAD7AULL,
		0x1B15255DA2CE6083ULL,
		0xCBC65975A315D4B9ULL,
		0x0329F8B48608AAE8ULL,
		0x0B3FEA53F008AF57ULL,
		0x58AB3A4B6790693BULL,
		0x206AF089404D58B1ULL,
		0x09A3171F6BE23F8AULL
	}};
	t = 1;
	printf("Test Case 195\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 195 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -195;
	} else {
		printf("Test Case 195 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8833326E58B813B9ULL,
		0xACF8FE7237053215ULL,
		0x124E44203B7144F0ULL,
		0x61F73E674FBD5073ULL,
		0x1F1D51B480E505E4ULL,
		0xB43B9739901F54A5ULL,
		0xF7C53914B06187D5ULL,
		0x76FF43A862C26240ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48C139CBABAD2B3DULL,
		0x238CD75C565BC9D9ULL,
		0x624BC7D0D6742A83ULL,
		0x938E35ACF8AB7469ULL,
		0x568DCD878113DF6DULL,
		0x9C530482E9018A2FULL,
		0xE2EBC43023100BCEULL,
		0x5ABE1F618ECCB091ULL
	}};
	t = 1;
	printf("Test Case 196\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 196 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -196;
	} else {
		printf("Test Case 196 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE6994AB09E843AEEULL,
		0x7E0A58373AAC4E10ULL,
		0xE8F0A5DA3AAEC97FULL,
		0x197A7C2C993783C3ULL,
		0x493223705C697949ULL,
		0xA5A3225C120A4D6AULL,
		0x960330C2F92F54C3ULL,
		0xB9FE0E10AF042606ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6994AB09E843AEEULL,
		0x7E0A58373AAC4E10ULL,
		0xE8F0A5DA3AAEC97FULL,
		0x197A7C2C993783C3ULL,
		0x493223705C697949ULL,
		0xA5A3225C120A4D6AULL,
		0x960330C2F92F54C3ULL,
		0xB9FE0E10AF042606ULL
	}};
	t = 0;
	printf("Test Case 197\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 197 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -197;
	} else {
		printf("Test Case 197 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x11919072460F01FAULL,
		0x19D7F36C7725A429ULL,
		0x8EA607B1E4088986ULL,
		0x38977183E6559EDBULL,
		0xD407B5F4C3403292ULL,
		0xA64E5930AEF023B6ULL,
		0x578959EECA99917CULL,
		0xF2196F77F0A43DFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E7A58C45E3F7A6CULL,
		0x0E312FD317AB31A4ULL,
		0x3F234C0DB48A1749ULL,
		0xC2F17F5A809B3E0FULL,
		0x233BA811D6FD4248ULL,
		0x35B1DB2ECDAEF928ULL,
		0x63C5B0B524025853ULL,
		0x0D56FCBA33B3CEA9ULL
	}};
	t = 1;
	printf("Test Case 198\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 198 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -198;
	} else {
		printf("Test Case 198 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFBABF0F4095B187FULL,
		0xD689CFA20E0C3F8FULL,
		0x1AFB3504E8B28D18ULL,
		0x2C72AA4CD2743413ULL,
		0x63BBC698EFFC1635ULL,
		0x7794F3EF8CA20298ULL,
		0xB7CB4FC026B6544FULL,
		0x7E538C8B642FC863ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF570B81483B2719EULL,
		0x2C42D17099D68B76ULL,
		0xBCB702657F95615FULL,
		0x422F302E84887CFFULL,
		0x614D45C8A64E4E83ULL,
		0x09AED9886240B1A0ULL,
		0x232F7867301E3BE3ULL,
		0x47CD999ED3A80168ULL
	}};
	t = 1;
	printf("Test Case 199\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 199 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -199;
	} else {
		printf("Test Case 199 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8BBBA6D813BA8F35ULL,
		0x4C33AE060A90AA02ULL,
		0x7A772778F2451412ULL,
		0xC5DC7ED6B543588AULL,
		0x7A8F8730CA1E6035ULL,
		0xEF12A6F80BE31110ULL,
		0xB4733A2B2315396CULL,
		0xF05CABDF0E953BE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x056E6401C78A433BULL,
		0x35B29BEAE5F4EB4FULL,
		0x257973CF65DDA45BULL,
		0xB4A2B23FA2126B72ULL,
		0x08473960E250003CULL,
		0x70E47E157450907AULL,
		0x64905996594A8E68ULL,
		0x7585A3DFB68C4E3AULL
	}};
	t = 1;
	printf("Test Case 200\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 200 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -200;
	} else {
		printf("Test Case 200 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC25350BFD5125DC1ULL,
		0xCA7F11411DB17950ULL,
		0x35375BA2B3D86B43ULL,
		0x4A2BE1D54A860F85ULL,
		0x941BEE84221A40F8ULL,
		0x43910D5F64E19542ULL,
		0xD22003854A7024E4ULL,
		0x59B188D4EC3D1071ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC25350BFD5125DC1ULL,
		0xCA7F11411DB17950ULL,
		0x35375BA2B3D86B43ULL,
		0x4A2BE1D54A860F85ULL,
		0x941BEE84221A40F8ULL,
		0x43910D5F64E19542ULL,
		0xD22003854A7024E4ULL,
		0x59B188D4EC3D1071ULL
	}};
	t = 0;
	printf("Test Case 201\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 201 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -201;
	} else {
		printf("Test Case 201 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x58291A3AEF0C7076ULL,
		0xE2BD040957A3982CULL,
		0x6F08DA03FB21FC1BULL,
		0x2226D024D290B325ULL,
		0xD1FD19F396FC0E80ULL,
		0x3E2DFA543E9D9364ULL,
		0xA3D74D50C4CEEDA0ULL,
		0x8616466A6A5B226AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEAEBDF32996D0FD2ULL,
		0xD374EF8463C0650EULL,
		0x22BBDA6459340F9AULL,
		0x1462B6527BAD8E0EULL,
		0xDCE16309DACAE048ULL,
		0x54EB859E21202AE0ULL,
		0xBDBBE16AC8FD185EULL,
		0x77FBAB99FF9BCC25ULL
	}};
	t = 1;
	printf("Test Case 202\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 202 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -202;
	} else {
		printf("Test Case 202 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3DB9CE3630653178ULL,
		0x72C68A37A4DC8E46ULL,
		0xD990F2DA55700FD4ULL,
		0x20FA35D26B18B6FCULL,
		0x9720DC2CD4255883ULL,
		0x637FCE13504BFE10ULL,
		0xD85D27C17F6DB211ULL,
		0x40C2AAFA45FCAADCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x622FC62C87F8BC63ULL,
		0x2C73D2A5EE7BF809ULL,
		0x041A50C7B8198B02ULL,
		0x50DD80B1D25883E5ULL,
		0x53D040656E33EE9EULL,
		0x2676DD8A55E7CF65ULL,
		0x041749E7D2754EE5ULL,
		0x699CC7BFCB8A879DULL
	}};
	t = -1;
	printf("Test Case 203\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 203 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -203;
	} else {
		printf("Test Case 203 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3BCF2E55E19BC6D0ULL,
		0xDBFF46E42F72504BULL,
		0xD34A2FFE07C5E65CULL,
		0x552DED64041EC122ULL,
		0xAAE56E5DB63E3F96ULL,
		0x0FD80256DC81939BULL,
		0x2C07C922EA0808A8ULL,
		0xF6496C4FC513C6F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BE35241737A00AFULL,
		0x187F49740F52EA44ULL,
		0x89FE234772F85B7FULL,
		0x5D0CD47EE642C0FFULL,
		0x77D0A0F972CB177FULL,
		0x37119F6E8FEF5085ULL,
		0x17F9389FFD9ADEE9ULL,
		0xEBCEBC0C8B8581DBULL
	}};
	t = 1;
	printf("Test Case 204\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 204 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -204;
	} else {
		printf("Test Case 204 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6E3E58745665E58BULL,
		0x7F18C9C09B33CEE4ULL,
		0xC41879135842C3D4ULL,
		0xF3A4F345E896CD42ULL,
		0x5FB90DB1A059C745ULL,
		0xB9E47C6CBDF2E65CULL,
		0xAFB367D2E5737866ULL,
		0x6BB450556F281827ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E3E58745665E58BULL,
		0x7F18C9C09B33CEE4ULL,
		0xC41879135842C3D4ULL,
		0xF3A4F345E896CD42ULL,
		0x5FB90DB1A059C745ULL,
		0xB9E47C6CBDF2E65CULL,
		0xAFB367D2E5737866ULL,
		0x6BB450556F281827ULL
	}};
	t = 0;
	printf("Test Case 205\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 205 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -205;
	} else {
		printf("Test Case 205 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5AE6F5E4F005557BULL,
		0xDAF43C3B07D29B90ULL,
		0x2E8C9B1FADA4D4E2ULL,
		0x62011DF096D8E075ULL,
		0xA9387AD99601B1A3ULL,
		0xD0594BAB55A04AE1ULL,
		0x889269F9411AD06CULL,
		0xD54974762A72B303ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43E36B2C3B468DEFULL,
		0x8A2D2640B22FBF5DULL,
		0xEF6109505B419958ULL,
		0xAE88D5DB4C740EF9ULL,
		0x12C0CDA34D7489C8ULL,
		0xD5039EEF6B41110EULL,
		0x4773D3A3A9D4FBA2ULL,
		0x2FAF6E1957BDA175ULL
	}};
	t = 1;
	printf("Test Case 206\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 206 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -206;
	} else {
		printf("Test Case 206 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5E83888CC9837987ULL,
		0x27934AD934137EDCULL,
		0x996A5B4E12809DE7ULL,
		0x3AF71FDF44882FA8ULL,
		0x5514B36A1E9CD077ULL,
		0x551C0AEC9D307E74ULL,
		0x9F6FFA502A89158EULL,
		0x5FAA3989D9D71F73ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2AB9B4DA0B4AF03ULL,
		0xFF6093EE8984765DULL,
		0x45914B71C680D5AAULL,
		0xD25499A1EE0B942AULL,
		0x54EDF271DC041729ULL,
		0x3A0C6A7A485E2F2CULL,
		0x9EF8E7B28B0E6F3DULL,
		0xD92082C0556681F4ULL
	}};
	t = -1;
	printf("Test Case 207\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 207 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -207;
	} else {
		printf("Test Case 207 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1A51119C0DE7C01BULL,
		0x9EDC07F43E068AB3ULL,
		0xBE5A57C7E99DA979ULL,
		0x51D071432103E3BAULL,
		0x6301B0D6781C5155ULL,
		0x2A715CA6F80B2076ULL,
		0x15ED335DE9561D67ULL,
		0xFEF9A22FAE395AE2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57B75B3FF1108638ULL,
		0xAAACB5AF6F2173FCULL,
		0xDBB0504E0A57A44DULL,
		0x64D2D04CFFEC85A0ULL,
		0x6AC89CEE84E54951ULL,
		0x9E9E4C2D9510CABDULL,
		0x2FF350109867FDE2ULL,
		0x9826C44460322EADULL
	}};
	t = 1;
	printf("Test Case 208\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 208 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -208;
	} else {
		printf("Test Case 208 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC8F5941A72E09CACULL,
		0x32EB96944D443F93ULL,
		0xAF81BE3E1348492EULL,
		0x8EB8A4A61EA5539FULL,
		0x49C73BAC435E17EFULL,
		0x56AB131E8614AA91ULL,
		0x7AC168D5B8D6EEC5ULL,
		0xE3E3AEFF8734C194ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8F5941A72E09CACULL,
		0x32EB96944D443F93ULL,
		0xAF81BE3E1348492EULL,
		0x8EB8A4A61EA5539FULL,
		0x49C73BAC435E17EFULL,
		0x56AB131E8614AA91ULL,
		0x7AC168D5B8D6EEC5ULL,
		0xE3E3AEFF8734C194ULL
	}};
	t = 0;
	printf("Test Case 209\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 209 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -209;
	} else {
		printf("Test Case 209 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4DEA24FD44216CDBULL,
		0xFD49812F21561A7BULL,
		0x6D6B565D495C5E88ULL,
		0x535CF5B53570130FULL,
		0x9D59C669472BC44BULL,
		0xD86A1E52D14506A5ULL,
		0x2E46EF3B0DED3682ULL,
		0x886982621AFC9619ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0CABAD2D2757B122ULL,
		0x8A50D247E8B44649ULL,
		0x000C7646960BFDE3ULL,
		0x4503F782C522A825ULL,
		0x9DD07E4CDC436FE7ULL,
		0x1AC9E0F7EA18934BULL,
		0x02FAFC8C65D3204AULL,
		0x4C66D6F676DC0246ULL
	}};
	t = 1;
	printf("Test Case 210\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 210 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -210;
	} else {
		printf("Test Case 210 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD33E55761CB47A35ULL,
		0x33083B0A96F55A9BULL,
		0x8B9BBAD58761CF3EULL,
		0xC18E8D5907466755ULL,
		0x72B2794E503A447BULL,
		0x10F2594A77085663ULL,
		0x4907E142EF7FFD18ULL,
		0xE641718083958C5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A5420A154C730B7ULL,
		0x08DA28FE777F1819ULL,
		0x7C58ABA471DA1438ULL,
		0x7A2CE12CF65F0D9FULL,
		0x5A9FA1980BF5919AULL,
		0x7D6F23F63B6814E0ULL,
		0x36B2AD24371B0683ULL,
		0xF80478CF6E5024A8ULL
	}};
	t = -1;
	printf("Test Case 211\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 211 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -211;
	} else {
		printf("Test Case 211 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB834B99A9C0BA227ULL,
		0xE65AAF1239443FD9ULL,
		0x47BB011F5260C071ULL,
		0xE864095B5FBF2251ULL,
		0x074FA41F91DB26BDULL,
		0xFEDD0F50FA4C0F4FULL,
		0xC763FD35A59286EDULL,
		0x87FC0F9A5CC3AD1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A2C3C328BF2B58DULL,
		0x4C903D295C490F3FULL,
		0x02D454FDBDF1F28DULL,
		0xA489CCBE82E36270ULL,
		0x997DA3509667A529ULL,
		0xFED9FE1EA55B9351ULL,
		0x77D1AFBD1BE71C0DULL,
		0x6CD4ACFD1AAC5E45ULL
	}};
	t = 1;
	printf("Test Case 212\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 212 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -212;
	} else {
		printf("Test Case 212 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x129D950E2356E66EULL,
		0x5E86918338136BE7ULL,
		0xF13E677C09999ABAULL,
		0x740A0DD51DF78ADBULL,
		0x40F49FE450F93C8CULL,
		0x141C8BE800202676ULL,
		0xE8A64A86BDA2F424ULL,
		0xC8DAC7C618195468ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x129D950E2356E66EULL,
		0x5E86918338136BE7ULL,
		0xF13E677C09999ABAULL,
		0x740A0DD51DF78ADBULL,
		0x40F49FE450F93C8CULL,
		0x141C8BE800202676ULL,
		0xE8A64A86BDA2F424ULL,
		0xC8DAC7C618195468ULL
	}};
	t = 0;
	printf("Test Case 213\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 213 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -213;
	} else {
		printf("Test Case 213 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCC118536C6F87650ULL,
		0x550339BEFD4E34E4ULL,
		0xB5F8705A56E662D3ULL,
		0x82E87A6412A98FCBULL,
		0xCDB122D7A640A919ULL,
		0xA23312315372FFB7ULL,
		0xEBCFFF221DE83522ULL,
		0xBF34A16B3A6080AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2049FE9638C1B960ULL,
		0x4C283494C1C892CAULL,
		0xF9EEFF408D101274ULL,
		0x3BB9B469C670C25BULL,
		0xD81579CE0A18A049ULL,
		0xF111DC1696E4AB9BULL,
		0xAA79FF672FF3B765ULL,
		0x1A1121C9163EC4F2ULL
	}};
	t = 1;
	printf("Test Case 214\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 214 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -214;
	} else {
		printf("Test Case 214 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4297AC100A77E645ULL,
		0x71CDE966D409A10FULL,
		0x2BFF47B17D8689E2ULL,
		0xC53B4BF331A818DFULL,
		0x13B6C2B83642A48FULL,
		0xF6C72B7B381FC540ULL,
		0xC3A9B5EEA8EAFAA5ULL,
		0xF1675C603EE27BB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x018C9BE59D3481DAULL,
		0xAABB3CC43F237CB6ULL,
		0x92455D22B3FB9BFCULL,
		0x9297909A3E0CD243ULL,
		0x869CDE6437ED29E9ULL,
		0x38D6E2FB7330256FULL,
		0x4D48289A609CD000ULL,
		0x0A53F94D19B13264ULL
	}};
	t = 1;
	printf("Test Case 215\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 215 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -215;
	} else {
		printf("Test Case 215 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF96302576FFD892EULL,
		0x35D28F7692203193ULL,
		0xC8C270076CA65767ULL,
		0x248283449C005E56ULL,
		0xF8D8FF75C17F2522ULL,
		0x2CA44E9D07251B7AULL,
		0x978B36EC5A38FFB9ULL,
		0x6DB99B3B8E810696ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13A16FA6FCDE2C3CULL,
		0x744B50056490FC2DULL,
		0x32E292AEADE369F3ULL,
		0xAC60115117B51944ULL,
		0x0AE7A74BDEBE12C8ULL,
		0x1936BBBFCCF26AF2ULL,
		0xF8E7C0FCD0C23119ULL,
		0x58CFA9A41EC80507ULL
	}};
	t = 1;
	printf("Test Case 216\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 216 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -216;
	} else {
		printf("Test Case 216 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x917C100962E33399ULL,
		0x37D51909E82604BDULL,
		0xD5601E5281749856ULL,
		0xD57429D47AF0383CULL,
		0x46108C6C3382A79FULL,
		0xF2CC1460F3433FCAULL,
		0xD3A03D07DA901DD3ULL,
		0x14A9076CCBF92103ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x917C100962E33399ULL,
		0x37D51909E82604BDULL,
		0xD5601E5281749856ULL,
		0xD57429D47AF0383CULL,
		0x46108C6C3382A79FULL,
		0xF2CC1460F3433FCAULL,
		0xD3A03D07DA901DD3ULL,
		0x14A9076CCBF92103ULL
	}};
	t = 0;
	printf("Test Case 217\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 217 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -217;
	} else {
		printf("Test Case 217 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3CC09B662F118EDBULL,
		0x842379E589214448ULL,
		0x9422FD7A641E881CULL,
		0xA7F5F46913843813ULL,
		0xBB731DB94BCB4F6EULL,
		0x4468C84F052E47D0ULL,
		0x08E74CB3537BB41EULL,
		0xC3D7862FE78A42A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7075B37DAB2F269ULL,
		0x8A3B1192AAA84AF3ULL,
		0x1A3C228E5EDDCCDEULL,
		0xDFC18C9256D0EE9DULL,
		0xF62DA412EAEDA9FBULL,
		0xB044E907A60B74E9ULL,
		0xB3C7867FB131F3A3ULL,
		0x0C1E7C7BB3B3BC0EULL
	}};
	t = 1;
	printf("Test Case 218\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 218 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -218;
	} else {
		printf("Test Case 218 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA0DEF4030FB56488ULL,
		0xE8A72CD1279F3A19ULL,
		0xABA8B58579729A26ULL,
		0x564C63BB1EEC082DULL,
		0xD3B119CAC063CAE4ULL,
		0x80FA954EB8FEFD05ULL,
		0x15779B8962EEF968ULL,
		0x2A1E616A7A97067DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06D0C64BC45B3260ULL,
		0x7ABA1D5E7190794DULL,
		0x730CCA8387B4CEE6ULL,
		0x238D0582DE44760CULL,
		0xEAA28994F7CA34FAULL,
		0x7BC54ED54B302187ULL,
		0xDECCD45C71997F32ULL,
		0x3B9E393F2AEFF0F7ULL
	}};
	t = -1;
	printf("Test Case 219\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 219 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -219;
	} else {
		printf("Test Case 219 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD5BDDD51AB2D2BE6ULL,
		0x8BE845BF5E431FD2ULL,
		0x7781A052FCA6345EULL,
		0x23F6C7496F9EE396ULL,
		0xECA23660D808FAA4ULL,
		0x267BA57A2381B435ULL,
		0x5AF94A8316C5F357ULL,
		0x1C839CCF5B306A11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1CAA6DED3F6B5DBULL,
		0x99A8EFA7C9FAD867ULL,
		0xFE1216907DBD1CA1ULL,
		0xFFCE7552D9E6666CULL,
		0x407B2223F76A3ACBULL,
		0x3D24DC3A533F35A1ULL,
		0x5DBA354A539761B9ULL,
		0x240F3204009FFDC2ULL
	}};
	t = -1;
	printf("Test Case 220\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 220 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -220;
	} else {
		printf("Test Case 220 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2C2A32DFFA42A410ULL,
		0x8B0D603A54192C73ULL,
		0x9C88861AB9D5E851ULL,
		0x43AE8CCD263F9E4EULL,
		0x7BE3E6D700B4E399ULL,
		0x3AA9C6EC82FA3516ULL,
		0xD9E1CC6D4CD87226ULL,
		0x4C677B0490EBAE5FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C2A32DFFA42A410ULL,
		0x8B0D603A54192C73ULL,
		0x9C88861AB9D5E851ULL,
		0x43AE8CCD263F9E4EULL,
		0x7BE3E6D700B4E399ULL,
		0x3AA9C6EC82FA3516ULL,
		0xD9E1CC6D4CD87226ULL,
		0x4C677B0490EBAE5FULL
	}};
	t = 0;
	printf("Test Case 221\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 221 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -221;
	} else {
		printf("Test Case 221 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2B2E5D8024844E1CULL,
		0x241561BF6012F3ECULL,
		0xF6DE7888E095883CULL,
		0xC92FF335728B35DBULL,
		0xC097C88D8783EAF6ULL,
		0xF8B1EF0AADD7B09AULL,
		0x63027AA66447EC0FULL,
		0xFA55DDB3DBC3C2C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BB07D1CE04909BAULL,
		0x0F215D52CFDD390DULL,
		0xBA56D23FD29E35B7ULL,
		0x70837D67A6E28D6DULL,
		0x9DD30F35B8D65274ULL,
		0xD19E6359BBA940B3ULL,
		0x3B8C225145CF13DBULL,
		0xC56FF2F264FA4D5CULL
	}};
	t = 1;
	printf("Test Case 222\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 222 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -222;
	} else {
		printf("Test Case 222 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x24C64C7B80132816ULL,
		0x1DD00627AEF470F8ULL,
		0xCB7800BC13DE4058ULL,
		0xA343DA975CED7EFAULL,
		0xB744BC890B81BB96ULL,
		0x2B53BE957254D93AULL,
		0xF98AD6E7703941BCULL,
		0xE3320320B7647281ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28CF470E4795BB38ULL,
		0xFFB243380A8A1E3AULL,
		0xC9A14B7A888F0DFBULL,
		0x0AFFB83185BEB9AFULL,
		0xA0B1EA18B8B12B48ULL,
		0x20FA3CCC0BB45074ULL,
		0xC0E7DE6F319BB50CULL,
		0xCE76D185E7B0ACF9ULL
	}};
	t = 1;
	printf("Test Case 223\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 223 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -223;
	} else {
		printf("Test Case 223 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9870E128FA3DBB1FULL,
		0x8E0B0F05C3AD8540ULL,
		0xD7061D6210FA512FULL,
		0x7D981F7DE8505DF3ULL,
		0x2997A4D714C79B9EULL,
		0x336B254428FE24DCULL,
		0x773B7C62D2A645B7ULL,
		0x266CC37A75A3D65BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AE790D00F2FADFFULL,
		0x9D07AACF3B0BF335ULL,
		0x6AD0978804E6AEA2ULL,
		0x0704B665C13C5195ULL,
		0xC7B0723CC3E32E9BULL,
		0x6C0E9A5EC9E8FB70ULL,
		0xF61022B55448BF7CULL,
		0x864923257B74B6EAULL
	}};
	t = -1;
	printf("Test Case 224\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 224 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -224;
	} else {
		printf("Test Case 224 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3DC8200183316AA8ULL,
		0xD9AD18E214414240ULL,
		0x25038E714AC3C451ULL,
		0xAB32C63D973FC86BULL,
		0x64AD58CF88DD2BBDULL,
		0x5F90EC318BD26B08ULL,
		0x1BFD429B264435EFULL,
		0xE6E03F018066D9D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DC8200183316AA8ULL,
		0xD9AD18E214414240ULL,
		0x25038E714AC3C451ULL,
		0xAB32C63D973FC86BULL,
		0x64AD58CF88DD2BBDULL,
		0x5F90EC318BD26B08ULL,
		0x1BFD429B264435EFULL,
		0xE6E03F018066D9D4ULL
	}};
	t = 0;
	printf("Test Case 225\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 225 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -225;
	} else {
		printf("Test Case 225 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEFE6C2399906916CULL,
		0xB8983BCE1760E801ULL,
		0xD709A487185E6367ULL,
		0xDBC7FA81AFC57E75ULL,
		0xBFAC055BBB3164A3ULL,
		0x9743374EFC910052ULL,
		0x73E3E4467DEDEEA2ULL,
		0x9343EC798A5E8CD7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7BAD1E96A002E50BULL,
		0xA668178F72C56ECBULL,
		0xCFA66905E5F28509ULL,
		0x596133F2A09E2EAFULL,
		0x5C55E35DE9684384ULL,
		0xFE12255340F68F00ULL,
		0x1B18E08E50CF090AULL,
		0x07A268AB91CA5BA7ULL
	}};
	t = 1;
	printf("Test Case 226\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 226 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -226;
	} else {
		printf("Test Case 226 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7838C35CB4C597A4ULL,
		0xD11547EDD9415A13ULL,
		0x95DC92E1627A78EAULL,
		0xD8A4254A1EED7B64ULL,
		0x8CF07C590510CA9AULL,
		0xF268AB437CC4FEB9ULL,
		0x772C37411E78BE99ULL,
		0x01519ACA2B6C0932ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5DF4BB3DA467461ULL,
		0x455D1C7EC0B58B23ULL,
		0x3DB56C0977F65270ULL,
		0x037AA5709D0DB1D5ULL,
		0x96F332DA3A6A234CULL,
		0x009A8D67173D3DBAULL,
		0x3732CD14EB534F33ULL,
		0x13A7E4C2255650AEULL
	}};
	t = -1;
	printf("Test Case 227\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 227 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -227;
	} else {
		printf("Test Case 227 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x908FB595BC879EECULL,
		0x05F80E682FEDEB37ULL,
		0x1B0FABF86F66E078ULL,
		0x1F13AF750D61C7D9ULL,
		0x2965817414C71F3AULL,
		0xEBDA53AE430EDE1AULL,
		0x07605F42E9726A3FULL,
		0x11537F268CC6E4E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x921E630DA3E55E93ULL,
		0x61206010EC3A0239ULL,
		0x495F0C9C8421C3CEULL,
		0xAE5436E0146059D4ULL,
		0x964B8478F350E071ULL,
		0x5CC3ECB7AA2BFF8DULL,
		0x728EA2F76586F457ULL,
		0xD91AC7153C7E6F8DULL
	}};
	t = -1;
	printf("Test Case 228\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 228 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -228;
	} else {
		printf("Test Case 228 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x213E29A85781F8CCULL,
		0x999824616A51CE85ULL,
		0xB2A4C8F3B05165EEULL,
		0x519BBFF67968BDB8ULL,
		0x4D7513F21F9F6612ULL,
		0xA49B46928A3447EEULL,
		0xF18633EB10307698ULL,
		0x90ABE7393819404DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x213E29A85781F8CCULL,
		0x999824616A51CE85ULL,
		0xB2A4C8F3B05165EEULL,
		0x519BBFF67968BDB8ULL,
		0x4D7513F21F9F6612ULL,
		0xA49B46928A3447EEULL,
		0xF18633EB10307698ULL,
		0x90ABE7393819404DULL
	}};
	t = 0;
	printf("Test Case 229\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 229 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -229;
	} else {
		printf("Test Case 229 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBA2C8892F622E7F9ULL,
		0x94B4F94FAA8450E8ULL,
		0xA0D646868F56B9B4ULL,
		0x6208ED96810E37B8ULL,
		0xA57D9071E3866A1FULL,
		0x03AF688268062A24ULL,
		0x251C9F503FCFEC32ULL,
		0x39EAFC0D092E5874ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x144DAC58FAA1AAB1ULL,
		0x69F1AB1B35198807ULL,
		0x10800AFA2CFCA6DBULL,
		0x0688EE490804B981ULL,
		0xA197087CAC8FCD09ULL,
		0x2A48281CAD51E2E1ULL,
		0xADEF76B7814DAE6FULL,
		0xF60977AB94C4B1CBULL
	}};
	t = -1;
	printf("Test Case 230\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 230 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -230;
	} else {
		printf("Test Case 230 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB7FE4B8905CAF53EULL,
		0xDC1BA731B6363FB8ULL,
		0x5A95EE436E08AA6FULL,
		0x6871FF7EA7D9E62BULL,
		0x61A27E12682351BDULL,
		0xE0D152798C84B42CULL,
		0xE5D1450995C12ECFULL,
		0x828D2F26FD97D155ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0339B3395E6C783CULL,
		0xC598382F51D8B4D5ULL,
		0xD2B6EB4C41961A34ULL,
		0x3D74E42A64EA08DCULL,
		0xDE273BBD4FE63D23ULL,
		0x533FC861859CC239ULL,
		0xFF2A22D6BE9A9340ULL,
		0xEF05A657057C7B39ULL
	}};
	t = -1;
	printf("Test Case 231\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 231 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -231;
	} else {
		printf("Test Case 231 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x39DCD65FBEB7FCC9ULL,
		0x6BA5DC83A81A1EF7ULL,
		0xE78DC042D7A8E027ULL,
		0x816C591F7C6FC361ULL,
		0xAF33547DCCD32149ULL,
		0x8C7A26B0A5AF6684ULL,
		0x3C3FCB260617F883ULL,
		0xA6A488B3B64362BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8655CBDC0DE3ACE3ULL,
		0xF9AEEB1B9BD0DEDDULL,
		0x9968D5F56E366D35ULL,
		0x57F989633C77E9D1ULL,
		0xA0C7C84478FBD334ULL,
		0xC81DEEAE0891FC1DULL,
		0x488A18F5AE6535C9ULL,
		0xAE396C6D7D92DA76ULL
	}};
	t = -1;
	printf("Test Case 232\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 232 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -232;
	} else {
		printf("Test Case 232 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD21ED2DCDB8719C6ULL,
		0xD13E4F382935691BULL,
		0xD2ABFB20424A777DULL,
		0xC9451B6947E4E24AULL,
		0x115ADAE2DE1AA977ULL,
		0x4E0FB23828406AEDULL,
		0x36262D266EB18C05ULL,
		0x4214575D77DB69F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD21ED2DCDB8719C6ULL,
		0xD13E4F382935691BULL,
		0xD2ABFB20424A777DULL,
		0xC9451B6947E4E24AULL,
		0x115ADAE2DE1AA977ULL,
		0x4E0FB23828406AEDULL,
		0x36262D266EB18C05ULL,
		0x4214575D77DB69F2ULL
	}};
	t = 0;
	printf("Test Case 233\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 233 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -233;
	} else {
		printf("Test Case 233 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFE323D05573D29C5ULL,
		0x9C41C91DA254E2D0ULL,
		0x76B78C84E623E887ULL,
		0x743F3DDC2F1D71A5ULL,
		0x47F522B3AA3BBF74ULL,
		0x9A67374BB658DA5CULL,
		0x37E924C55E472B01ULL,
		0x8DC75C1AE4E6994FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFECE0255F2771044ULL,
		0xB74524A0129A01F2ULL,
		0xCC448F05DFFBB21DULL,
		0x28BFA1A4D5E85D04ULL,
		0xFBE13C0DD15CD410ULL,
		0xC755A4C5F2E922F1ULL,
		0x794BC96A110E90A7ULL,
		0xFE841CCDB0AD3D36ULL
	}};
	t = -1;
	printf("Test Case 234\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 234 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -234;
	} else {
		printf("Test Case 234 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8D1A9E8283AFCC70ULL,
		0xA70DD6468D3250D2ULL,
		0x18E9F81623DB6959ULL,
		0xD34B8CB3BCD902B6ULL,
		0x730C591AC68C66F0ULL,
		0xB4E27AE0282C3014ULL,
		0x84DE75EA956416D9ULL,
		0xAB1F72C59A65E66DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A157A525F9D23F3ULL,
		0xB6FAB93A25CDE6C9ULL,
		0xADF2AE29B2BA67FFULL,
		0x180B133A865DD0B4ULL,
		0x7F0317DC1F53097EULL,
		0xA123EDB623B48F0BULL,
		0x452E1B57384767FCULL,
		0xAB39AEBD1CBDDC8BULL
	}};
	t = -1;
	printf("Test Case 235\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 235 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -235;
	} else {
		printf("Test Case 235 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4989B57DB19AA35CULL,
		0x9F7C53D5F867D948ULL,
		0x239EF730843A1248ULL,
		0xCB35B19A972D146CULL,
		0xE66CDA8B1CB2E526ULL,
		0xEA6BD4DFF36C346EULL,
		0xBD8E4C5D43D9026EULL,
		0x3E7529F0C0C43D54ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E03DD6B447E4CB7ULL,
		0x8EA07CD36CAA926CULL,
		0x89D7C8868867B1EEULL,
		0x84C4E0C71B93B41CULL,
		0xC6ABB51933A9956AULL,
		0x1103E8F3442D8BB9ULL,
		0xDAE4CB8CCA261AA0ULL,
		0xE04C621EF7C6C923ULL
	}};
	t = -1;
	printf("Test Case 236\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 236 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -236;
	} else {
		printf("Test Case 236 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x91AECD549D8E3B96ULL,
		0x90C5492C89DFB07FULL,
		0x2EADAC133B350276ULL,
		0x852992293093E3C0ULL,
		0x0E6F9F96F9A0D040ULL,
		0x87AA27A0310C2F0BULL,
		0xEB16BE904A916031ULL,
		0xE485C43FCF77FEBEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91AECD549D8E3B96ULL,
		0x90C5492C89DFB07FULL,
		0x2EADAC133B350276ULL,
		0x852992293093E3C0ULL,
		0x0E6F9F96F9A0D040ULL,
		0x87AA27A0310C2F0BULL,
		0xEB16BE904A916031ULL,
		0xE485C43FCF77FEBEULL
	}};
	t = 0;
	printf("Test Case 237\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 237 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -237;
	} else {
		printf("Test Case 237 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEA037F5F691E1C39ULL,
		0x7F19AB3758998081ULL,
		0xCBEBE0524F6F92A4ULL,
		0x58C1EB34429905A0ULL,
		0x4E160A2D281AAF25ULL,
		0xE6771156E9B92D4EULL,
		0x371ABF730B054535ULL,
		0xDF8D23E7A9DEF7CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA432F60A75010227ULL,
		0x81A6C43A52F5790DULL,
		0x004E17B2B89EABA7ULL,
		0x89BF3D091A39E99AULL,
		0x26FEE80DAEBAFE15ULL,
		0xB5D2F2CEB33A1448ULL,
		0xA5697268A29C0BB0ULL,
		0x5CE5A2AD19146314ULL
	}};
	t = 1;
	printf("Test Case 238\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 238 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -238;
	} else {
		printf("Test Case 238 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7823EBF3FB88C888ULL,
		0x800FE422567320BBULL,
		0x4B9A96D05D62B450ULL,
		0xDAC7A7F816713D06ULL,
		0x043861583979E361ULL,
		0x400AE6D503000DDFULL,
		0x356BAE934E93916BULL,
		0xCD0FF6DAD996896EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0A0EBA53709E53DULL,
		0x1F67D0390159E3AEULL,
		0xB8B1967DC2CB68A2ULL,
		0x477128B722450272ULL,
		0x0627F926792C6E09ULL,
		0xE6D0364DBFC88954ULL,
		0x5BA116B6F3238AAAULL,
		0xCEE8F1B044088CD5ULL
	}};
	t = -1;
	printf("Test Case 239\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 239 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -239;
	} else {
		printf("Test Case 239 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6B5E5BC063F6727CULL,
		0xDA83D77EF2619B94ULL,
		0x273D49ADD086A31EULL,
		0xAC96F47468807973ULL,
		0x552ED43F7C7F3C82ULL,
		0x45237C0F5AA2DE78ULL,
		0x2E563EE0CCC47018ULL,
		0x85D7D2EF5B184905ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x764744F86DF86263ULL,
		0x6E8062CCD388CC12ULL,
		0xA1A705D327AAAF4EULL,
		0x70F2AEA1707CCFA6ULL,
		0xFCFDDF803CCAC81FULL,
		0xD4B5AC8F2395B5A3ULL,
		0x7E20CBC5E9BE6FDCULL,
		0xEE951405B4AE8B95ULL
	}};
	t = -1;
	printf("Test Case 240\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 240 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -240;
	} else {
		printf("Test Case 240 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x366DA0196021BF1BULL,
		0x309E09FBD6ABD21CULL,
		0x0949EFFAE76C4B62ULL,
		0x9552D5F5E92F8E05ULL,
		0xEAC8C6FB258D6123ULL,
		0xB515A744E49E33BFULL,
		0x10A4CC3E18B12C6AULL,
		0x4E1277B46B91E2AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x366DA0196021BF1BULL,
		0x309E09FBD6ABD21CULL,
		0x0949EFFAE76C4B62ULL,
		0x9552D5F5E92F8E05ULL,
		0xEAC8C6FB258D6123ULL,
		0xB515A744E49E33BFULL,
		0x10A4CC3E18B12C6AULL,
		0x4E1277B46B91E2AEULL
	}};
	t = 0;
	printf("Test Case 241\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 241 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -241;
	} else {
		printf("Test Case 241 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE2AA4503DFBDB12FULL,
		0xCF6C9BC8BD7A87FFULL,
		0x6651F869F36C0283ULL,
		0x87A59B6F5112FFEBULL,
		0xF10392AC390D8146ULL,
		0x64D3E7334B59CCA8ULL,
		0xAA16F76274BC622FULL,
		0xE83C5C4FDC521C11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x198B4F3D00FAF38FULL,
		0xFC14F5CFDFA31B83ULL,
		0x3981057A1776ADF2ULL,
		0x2A8A158121BA5409ULL,
		0xF3B93393B4EB618AULL,
		0x8229EC799F1AD89EULL,
		0x1518F90CF2C294E7ULL,
		0xF21D400D6401B808ULL
	}};
	t = -1;
	printf("Test Case 242\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 242 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -242;
	} else {
		printf("Test Case 242 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCB4EC33B4C51079FULL,
		0xC4635DCED147BB48ULL,
		0x222A93BBEE98B1F9ULL,
		0xF26BD46EE94767D5ULL,
		0x12C3181BA3FB3B33ULL,
		0x5C02A476DBBC9341ULL,
		0xDE16C5B344E01083ULL,
		0xB54C4C4A797B505EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF5AA8A66F1C832AULL,
		0x6A8F09C3D80452A6ULL,
		0xD06C0227F5FD364CULL,
		0x03CF55930FAFAD14ULL,
		0x0B06BF88C1C2215AULL,
		0xA62FCD048B19C736ULL,
		0x8B1A312DAA00A2ACULL,
		0x3D8928189A2FB708ULL
	}};
	t = 1;
	printf("Test Case 243\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 243 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -243;
	} else {
		printf("Test Case 243 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x35038FE0A4B2F624ULL,
		0x3957C8301B14FB8FULL,
		0xFB11DB8D53FA6371ULL,
		0xEE6AAA3E137990B8ULL,
		0x3BAAF889E8AFF383ULL,
		0x01831490D24D662AULL,
		0x4452483B2DEA6F1DULL,
		0xDF9C885E10476746ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A27FF61D9CB67B9ULL,
		0x575953E4A9E9BCCAULL,
		0x476A840F44C8EC10ULL,
		0xEAD8830342C0F2F0ULL,
		0x1ECC20719E91C5E4ULL,
		0x0D2787780F86E7AFULL,
		0x87F59FB82F313197ULL,
		0xEE85204FC4ED14ABULL
	}};
	t = -1;
	printf("Test Case 244\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 244 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -244;
	} else {
		printf("Test Case 244 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD070CB0A8CF44821ULL,
		0xE0259C9FC2668320ULL,
		0xB6368BFF5D18A4EBULL,
		0xFF4D26A460F30657ULL,
		0xF9A1C60EC1A61E90ULL,
		0x1CC7AB6F43EBA353ULL,
		0x20B7778B3F57EAF1ULL,
		0x827F05CDAEE91814ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD070CB0A8CF44821ULL,
		0xE0259C9FC2668320ULL,
		0xB6368BFF5D18A4EBULL,
		0xFF4D26A460F30657ULL,
		0xF9A1C60EC1A61E90ULL,
		0x1CC7AB6F43EBA353ULL,
		0x20B7778B3F57EAF1ULL,
		0x827F05CDAEE91814ULL
	}};
	t = 0;
	printf("Test Case 245\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 245 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -245;
	} else {
		printf("Test Case 245 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5CB502882C353808ULL,
		0xE451794D2E515103ULL,
		0xEA1BF9ACD65BD41BULL,
		0x2126376707CF3F87ULL,
		0x3F2AC0C7191FBD1CULL,
		0x9A1FFC2DC6B66D06ULL,
		0xBC5248A11A8C05D1ULL,
		0x9CFE7DFA3619BF30ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCEE3DF1B4C965F8CULL,
		0x7E3E0F033332CDC8ULL,
		0xDD507F03E113DD82ULL,
		0x6E0C53FCE0F24BE4ULL,
		0x6027022E2D5D30BDULL,
		0xB5F4B535ABD6D97BULL,
		0xF8C91469E2C3F5DAULL,
		0xC7AC9AF1D8B80451ULL
	}};
	t = -1;
	printf("Test Case 246\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 246 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -246;
	} else {
		printf("Test Case 246 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x71AEC8F27CEF9707ULL,
		0x69BE1668E7C3C067ULL,
		0x552D89C5829D8902ULL,
		0x56D334A9B6E7F730ULL,
		0x6701DBE9AA1A6D9EULL,
		0x83B83509C769D86BULL,
		0xF7FF8512FFAC7FBAULL,
		0xE406F38EE8875AFAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AEF981EAD536E33ULL,
		0x26D14539F66C8C0AULL,
		0xBFB7E054D43ED63BULL,
		0x408CCE0BC61845BBULL,
		0x22F27D60F8B96A0BULL,
		0xC4B3E6F02581DB51ULL,
		0xE4BD660955B42B56ULL,
		0x428333EF7FCA6769ULL
	}};
	t = 1;
	printf("Test Case 247\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 247 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -247;
	} else {
		printf("Test Case 247 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEF6CEC3E2F504995ULL,
		0xD1C59D97708CCEE6ULL,
		0x632A2801D5853F3AULL,
		0x37E974FDE5DB9C94ULL,
		0xDA89147F2636F01DULL,
		0x0D997C83A4518D8BULL,
		0x0B5C16270CAF84FEULL,
		0xA13127E27A2AF391ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA7540C460FB7E20ULL,
		0x9EA4E74C94158647ULL,
		0x3CC8109BF6210AF3ULL,
		0x8D2517F8A6358837ULL,
		0x40A31559919B1B13ULL,
		0x5007A0E5D692027BULL,
		0x22FA13DD5CD20BD1ULL,
		0x37D54D6C3CA628DEULL
	}};
	t = 1;
	printf("Test Case 248\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 248 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -248;
	} else {
		printf("Test Case 248 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5A1A30E705A37E8AULL,
		0xA17C7BD7848BE49AULL,
		0xA7C852A411167683ULL,
		0x16C76C287325E989ULL,
		0xE6B781D1905CBA1AULL,
		0x620B20DB7ADF8DE0ULL,
		0xCA42CD1718DDB2C8ULL,
		0x70318F5E9A31AE84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A1A30E705A37E8AULL,
		0xA17C7BD7848BE49AULL,
		0xA7C852A411167683ULL,
		0x16C76C287325E989ULL,
		0xE6B781D1905CBA1AULL,
		0x620B20DB7ADF8DE0ULL,
		0xCA42CD1718DDB2C8ULL,
		0x70318F5E9A31AE84ULL
	}};
	t = 0;
	printf("Test Case 249\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 249 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -249;
	} else {
		printf("Test Case 249 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2E22CD2996DBA8D0ULL,
		0xC0A3DE183694D05CULL,
		0xAF5F990E1978C45BULL,
		0xE02F49C15DEA81D0ULL,
		0x0AF8F6A006EAFB8EULL,
		0xF072E5CFEC36E33EULL,
		0x1F8AD4B1430006C4ULL,
		0x792BA19EF30402E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F6AA8C97CA316ECULL,
		0x6B19839D212359C3ULL,
		0x37F7DBF4F2536617ULL,
		0x1EC4315106586D8EULL,
		0x954B7422F16925DBULL,
		0x2B4DD3E649331603ULL,
		0x13F3CF5DC57EDA21ULL,
		0x394DF86CEFD5CCB1ULL
	}};
	t = 1;
	printf("Test Case 250\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 250 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -250;
	} else {
		printf("Test Case 250 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x44140D5EFECBA862ULL,
		0x0AE7ECD9715F4FC9ULL,
		0x43989CDF0E5D63CEULL,
		0x49609373791D0510ULL,
		0xA1CA983B2A1AB19CULL,
		0xE43197578036767EULL,
		0x52A062A29C274FADULL,
		0xCB08E617825E9F2CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54EE70541F8E3AD8ULL,
		0x1B0E6CAEB0366801ULL,
		0x9E204385E96C866AULL,
		0x7D345611F3FC176FULL,
		0x077BC8E001DAB372ULL,
		0xD9F6BC774D1CC1A5ULL,
		0x763C1757EEEC0364ULL,
		0x0706A897F419AD3AULL
	}};
	t = 1;
	printf("Test Case 251\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 251 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -251;
	} else {
		printf("Test Case 251 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFFB09B61BF6A81B2ULL,
		0xFB1BC6B6EBEE17ADULL,
		0x235C75E29CAE2DF7ULL,
		0x3C2E96408783CAE9ULL,
		0x8BEFFA276E4BDF9DULL,
		0xA1376D768F67A0F7ULL,
		0xE4BC1FC186757DCEULL,
		0xD02448EB93137969ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF0727CBC77C2AEEULL,
		0x78367854C297D266ULL,
		0x2F9759F403C0B18EULL,
		0xE3B5873D97E9E855ULL,
		0x610311253738EAE1ULL,
		0x42FE5A15A2BB0019ULL,
		0x6CFFBB25A04DC7D5ULL,
		0x7C4F0464FDF77A3DULL
	}};
	t = 1;
	printf("Test Case 252\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 252 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -252;
	} else {
		printf("Test Case 252 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x918717FC96E34309ULL,
		0x72F10C1B606A41D0ULL,
		0x0879B3E26F9F82D9ULL,
		0xF345BA23D1C5A054ULL,
		0xCA964A18367C58A6ULL,
		0x705F48FC0EC3B7A6ULL,
		0x32DF67CBFF1309F5ULL,
		0x58565953684A9066ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x918717FC96E34309ULL,
		0x72F10C1B606A41D0ULL,
		0x0879B3E26F9F82D9ULL,
		0xF345BA23D1C5A054ULL,
		0xCA964A18367C58A6ULL,
		0x705F48FC0EC3B7A6ULL,
		0x32DF67CBFF1309F5ULL,
		0x58565953684A9066ULL
	}};
	t = 0;
	printf("Test Case 253\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 253 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -253;
	} else {
		printf("Test Case 253 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBD784A8B5FC28F91ULL,
		0x054DC617DA87B00AULL,
		0x4F60C3F04FA39C7BULL,
		0x695AF21038BC4264ULL,
		0x6956AA709A6FF366ULL,
		0x839BC1C5BACA546EULL,
		0xC7B5E0DB848F91DFULL,
		0x8D3A44DBDAF36BEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D6CE68640E98735ULL,
		0xFBD857CFA10C8907ULL,
		0xB9A5BC715CA87F99ULL,
		0x32AB65BEA6595422ULL,
		0x1D594BA4AA0D9396ULL,
		0x99330BA967519810ULL,
		0x35B6022604BF9E94ULL,
		0xB57F8C6E3B71A0C8ULL
	}};
	t = -1;
	printf("Test Case 254\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 254 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -254;
	} else {
		printf("Test Case 254 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x68FD2CB093570511ULL,
		0x4F8B004B196F4E56ULL,
		0x9CCA65A60728E1C5ULL,
		0xE2494855B844416BULL,
		0xB1CF66AB60BB7CA2ULL,
		0x0DAE174D742A2E3BULL,
		0x4804324C4306E75BULL,
		0x881B7B87E8E66E6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25B5639EB87259EAULL,
		0x422F3EB65840F672ULL,
		0xE0EA4A6B17F28CC7ULL,
		0x25884F9C2AD4AB72ULL,
		0x9DAC8FCB5855E97DULL,
		0x33439EE9452C36D1ULL,
		0x727C81FB20B97140ULL,
		0xF7D8B28E9D2C39D9ULL
	}};
	t = -1;
	printf("Test Case 255\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 255 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -255;
	} else {
		printf("Test Case 255 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9B8FC17E122BE65CULL,
		0xE4BBF9780EC31054ULL,
		0x9ADA8739CEA8EC11ULL,
		0x054AB696FA43A81FULL,
		0x2C77F31F10074B48ULL,
		0x129485D2A4DED505ULL,
		0x94600BADA01D9A03ULL,
		0x41643E0D0C159C0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4442BC61B84FFDC0ULL,
		0xC7E6A7DCF51722CAULL,
		0x2160BD532A6DBD77ULL,
		0xFC2C856719BADC20ULL,
		0x91B8E6B025C0E970ULL,
		0x5AEB9156E6B3197EULL,
		0x3BC8D1400BEFD6EEULL,
		0x30227E84E398999CULL
	}};
	t = 1;
	printf("Test Case 256\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 256 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -256;
	} else {
		printf("Test Case 256 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8D01DFF1417E3423ULL,
		0xA5E19DC356A36C44ULL,
		0xA426B38129177402ULL,
		0x3039B9952C422DC9ULL,
		0x908C8BAB654EAB8EULL,
		0xA3513AE6681DA842ULL,
		0x9285F7FA124B01F8ULL,
		0x92AD39A681827257ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D01DFF1417E3423ULL,
		0xA5E19DC356A36C44ULL,
		0xA426B38129177402ULL,
		0x3039B9952C422DC9ULL,
		0x908C8BAB654EAB8EULL,
		0xA3513AE6681DA842ULL,
		0x9285F7FA124B01F8ULL,
		0x92AD39A681827257ULL
	}};
	t = 0;
	printf("Test Case 257\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 257 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -257;
	} else {
		printf("Test Case 257 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x401EE8D24C8E23C8ULL,
		0x6B8B7ABB94E540A6ULL,
		0x7FE32BA59D04ADC3ULL,
		0xBCD469715A64FB83ULL,
		0xBD7309C86B238AA8ULL,
		0xE896203D9BD871C9ULL,
		0xC52FF499922075D8ULL,
		0xB29327B5E7562844ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1B678854D65C36EULL,
		0x3600F4762038C3C2ULL,
		0xCDE71AF137C62705ULL,
		0x2528FB6D0CDDD1BEULL,
		0x14234DD74C6152BEULL,
		0xBB5A4D75DBE4110EULL,
		0x4A2DFF2C00D19DE7ULL,
		0x49A816439FE50B7FULL
	}};
	t = 1;
	printf("Test Case 258\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 258 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -258;
	} else {
		printf("Test Case 258 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC3B92D2E4AE8E1ADULL,
		0xD9913004B13D16E9ULL,
		0x34AEBDCCE6DE7552ULL,
		0xB5680F27D26EFDD7ULL,
		0x503685D75303492BULL,
		0x973A22702360CA2FULL,
		0x28B34760AD7A662DULL,
		0xAB3C439CBFACDE1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE995200730D66F90ULL,
		0xB75DC5F0E03F14CBULL,
		0x3E047D6221C9ACC9ULL,
		0xEFCD8B4A16DB7807ULL,
		0xF13EA1883EBD6004ULL,
		0x375AA32D74E7658AULL,
		0x58D294EB41B57EF2ULL,
		0x862142C9BCD1F8D3ULL
	}};
	t = 1;
	printf("Test Case 259\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 259 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -259;
	} else {
		printf("Test Case 259 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x513D1177C4C99095ULL,
		0xD618779F858B8AEAULL,
		0x6C928ED8600B35DAULL,
		0x28EE920D091D077BULL,
		0xF4C3FF9F12DC96A6ULL,
		0xD88D0403C047F3BCULL,
		0x02F0081966EB5196ULL,
		0xD26DF86E163FC290ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6FFE07823E6C0A04ULL,
		0x344E94A141EFAD2DULL,
		0xB3645EB855C40217ULL,
		0x27C795D4B6244129ULL,
		0x8F81CED035714832ULL,
		0x5D35EC12867F91B0ULL,
		0xABCF340697937B28ULL,
		0x9FE073C9C07603FCULL
	}};
	t = 1;
	printf("Test Case 260\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 260 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -260;
	} else {
		printf("Test Case 260 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4DCC1232A6CD5B58ULL,
		0x6E5987B5886DE00EULL,
		0x59C95E68C1C6A15BULL,
		0x6615D7F4A659BC6CULL,
		0x4F829CEB57BF6981ULL,
		0xD2D6276935BE6FF1ULL,
		0xCA7C12D09A16880DULL,
		0x46C96ED83E350148ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DCC1232A6CD5B58ULL,
		0x6E5987B5886DE00EULL,
		0x59C95E68C1C6A15BULL,
		0x6615D7F4A659BC6CULL,
		0x4F829CEB57BF6981ULL,
		0xD2D6276935BE6FF1ULL,
		0xCA7C12D09A16880DULL,
		0x46C96ED83E350148ULL
	}};
	t = 0;
	printf("Test Case 261\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 261 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -261;
	} else {
		printf("Test Case 261 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD27A347F41B4CE49ULL,
		0xFD88B6388237D459ULL,
		0xD6716A62A8EC08F0ULL,
		0xB0649307B9145ABDULL,
		0xBFE8BE650B01BAAAULL,
		0x30BADC00529C4B90ULL,
		0x6F02B87595AED45FULL,
		0x5CD1BF6239C28493ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D6421891B2B2673ULL,
		0x834127C9C35A3FF5ULL,
		0x64DFE3DE551E5E6CULL,
		0x1139809A160A378CULL,
		0x41CC5FAA2D69FF9EULL,
		0xE5DE5F4B6D64599CULL,
		0x3A038E1A2D5AD76DULL,
		0xF6A3C4B901E9C68FULL
	}};
	t = -1;
	printf("Test Case 262\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 262 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -262;
	} else {
		printf("Test Case 262 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBE570A94E077B6C1ULL,
		0xE41CE7C1A917748DULL,
		0xE04C3401552B3180ULL,
		0xE51E73A0B45BCAB9ULL,
		0x635CD5E978EB9151ULL,
		0xFDB3E87A188C4260ULL,
		0xDC014333161AACB1ULL,
		0x3E614751AB1C648DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC87A567BE2EE2A17ULL,
		0x12D47828D26EC0BDULL,
		0x9C5D3E62F27DC643ULL,
		0xBBB815D61642B267ULL,
		0x5A3FBC9414CA2681ULL,
		0xF7FCD60C1CCEDE6EULL,
		0x8D5DC7EE2DCD59B3ULL,
		0x6465E060B2B46D94ULL
	}};
	t = -1;
	printf("Test Case 263\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 263 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -263;
	} else {
		printf("Test Case 263 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x77705BFED7517C92ULL,
		0x346CDDD2A745218DULL,
		0xB2040D3D474E4F75ULL,
		0x628755B538D3CD1CULL,
		0x0DE2FAD7A5481938ULL,
		0xD08A1519BCBD7C66ULL,
		0xE778AD794C3AFF2BULL,
		0xF3D3CEBB25A6BB20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF467664F5CF6C70ULL,
		0x0CF63C2F942B1C72ULL,
		0x4D558F79BCD42A7EULL,
		0x8BFC977179EBCE38ULL,
		0xA66796F38588BB72ULL,
		0xF41A35BB8C9F60F2ULL,
		0xA99911A5C6FF22F4ULL,
		0xFF2E4A2F7666B217ULL
	}};
	t = -1;
	printf("Test Case 264\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 264 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -264;
	} else {
		printf("Test Case 264 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA501905ADA5C30D7ULL,
		0x6346AC298FB7BC90ULL,
		0x73585520914BC1AFULL,
		0xD8B7B5B431C776D9ULL,
		0x54E3346DE0D1177AULL,
		0xEA6B26056FE52C0BULL,
		0x662A1FEF0C28E006ULL,
		0xDBB75063E99E65E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA501905ADA5C30D7ULL,
		0x6346AC298FB7BC90ULL,
		0x73585520914BC1AFULL,
		0xD8B7B5B431C776D9ULL,
		0x54E3346DE0D1177AULL,
		0xEA6B26056FE52C0BULL,
		0x662A1FEF0C28E006ULL,
		0xDBB75063E99E65E6ULL
	}};
	t = 0;
	printf("Test Case 265\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 265 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -265;
	} else {
		printf("Test Case 265 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x76CD10B7F2862F97ULL,
		0x6037BD305C99EF00ULL,
		0x70E86B70D8C1EF52ULL,
		0x299D76BEB1D033EBULL,
		0x7944CF5A0466152DULL,
		0x8898C1F8F0B84277ULL,
		0x34F63E7C829BC5D8ULL,
		0x84AAA547A315EB3FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x719A549A56F836FEULL,
		0xF30417BF5D3059DCULL,
		0xECD6FAF5D250C131ULL,
		0xC550F26363A10501ULL,
		0x8A71E7B5643377F2ULL,
		0x22F0A6361070E796ULL,
		0xC258EC8809425AA1ULL,
		0xBDD59A99BE1530B0ULL
	}};
	t = -1;
	printf("Test Case 266\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 266 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -266;
	} else {
		printf("Test Case 266 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD6742BBB572E5106ULL,
		0xD16BA9670172C41BULL,
		0x811549DA51EF6F96ULL,
		0xB4C156F39BF3D6B8ULL,
		0xB76638F4084ED801ULL,
		0xF3509D185DA5C4F8ULL,
		0xE55CC2774E59E263ULL,
		0xF943671CE6823EAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA76896E774C0F26EULL,
		0x5FF8A38CE2438C5FULL,
		0x17DA12D14F830738ULL,
		0x2E51043ABC6EBEA3ULL,
		0x15DE6B118B05D48EULL,
		0xCAA3E16CFCAF90F5ULL,
		0x4384B2838313FB8CULL,
		0xD4AC08217BDE0BFFULL
	}};
	t = 1;
	printf("Test Case 267\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 267 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -267;
	} else {
		printf("Test Case 267 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEB148805C2F1A125ULL,
		0x1FFF3DBFDBAB1BE9ULL,
		0x17EA810F6B039C32ULL,
		0x5613D936D761DBF4ULL,
		0x374F21E198A34095ULL,
		0x677345EBB2E5E478ULL,
		0xD85C752A0B7DCFE0ULL,
		0x45B43C58DEA2C2FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48CD3C1CC5E9E9CBULL,
		0x8A97C9853EE474DFULL,
		0x460BDEF33E08EF62ULL,
		0x53B63396B68975B9ULL,
		0xC770D441104826CAULL,
		0x77AB985976177177ULL,
		0x2620489C5468AF55ULL,
		0xB92547B002CE4D1AULL
	}};
	t = -1;
	printf("Test Case 268\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 268 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -268;
	} else {
		printf("Test Case 268 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF30951D4FE83F705ULL,
		0x91BE4494DFA9B1EDULL,
		0xAA7F4669E6D00301ULL,
		0x9BD41DC4ED29217FULL,
		0xF2FF4E685449453DULL,
		0x8AE0DC7E90D698C8ULL,
		0xE63BB993CA7AB567ULL,
		0x2AB823776AD4D663ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF30951D4FE83F705ULL,
		0x91BE4494DFA9B1EDULL,
		0xAA7F4669E6D00301ULL,
		0x9BD41DC4ED29217FULL,
		0xF2FF4E685449453DULL,
		0x8AE0DC7E90D698C8ULL,
		0xE63BB993CA7AB567ULL,
		0x2AB823776AD4D663ULL
	}};
	t = 0;
	printf("Test Case 269\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 269 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -269;
	} else {
		printf("Test Case 269 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB288025210DF6AADULL,
		0x8AAC01F66D515A28ULL,
		0xA225444D670CF786ULL,
		0x4CBDFB65EA4EC725ULL,
		0xA784A8E0BCE202DBULL,
		0x3DABA83E6E0005F4ULL,
		0x36C03618593F76E1ULL,
		0xC3EB2625E9703B95ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE55EBB52775D5309ULL,
		0x65CC8FB3BDA88893ULL,
		0x40BF1C62AF8025D9ULL,
		0x77012B58051C558FULL,
		0xB70A588519087753ULL,
		0x107ABAFF0BDEDA22ULL,
		0xF02FF64B6C3F8A91ULL,
		0xCBDC126A186D92C2ULL
	}};
	t = -1;
	printf("Test Case 270\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 270 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -270;
	} else {
		printf("Test Case 270 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3E366DB203E3AF36ULL,
		0x814ECE04B861DB17ULL,
		0xCC1A9FDB1FFE87D2ULL,
		0x819DB30A0B7E76F1ULL,
		0xEF8A7C72574E9D70ULL,
		0x91511D91DF9E3F76ULL,
		0x039496B2ABC2E233ULL,
		0x832D83DACF71C685ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6496E84745A1D6C9ULL,
		0xE22F59E66577DE63ULL,
		0xEB48966EBC70E03AULL,
		0x8810E488FB133DB3ULL,
		0x322681952DB29B67ULL,
		0x3063D9A81134AAD7ULL,
		0x5F3266C67ADF5E63ULL,
		0xEFC09C2A18620854ULL
	}};
	t = -1;
	printf("Test Case 271\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 271 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -271;
	} else {
		printf("Test Case 271 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x16F54B92E74759DEULL,
		0x1BD83FD02F2EAC0AULL,
		0xB8D2BEAC8872E8FFULL,
		0xC28348D2DCCFBCA6ULL,
		0xA2C020095DC3EDA1ULL,
		0xF4256A849CE4AB52ULL,
		0xCCAC9129FA8A96A1ULL,
		0x9FD461331DC9DCFBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBFE3C1A02DF8D5DULL,
		0x13CEA68AF7E2EE97ULL,
		0x594E540C027EF526ULL,
		0x1D8F318B3EC075B6ULL,
		0x52C9D343CA16B8B2ULL,
		0xECFD5BBC36FF0381ULL,
		0x8BF118C9B079AC3BULL,
		0x25728001A4706915ULL
	}};
	t = 1;
	printf("Test Case 272\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 272 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -272;
	} else {
		printf("Test Case 272 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1C9E0F48E0E8B998ULL,
		0x7C786A1E13AAE76CULL,
		0x9E247FFC2985F7C0ULL,
		0x196D9109C05A7ECBULL,
		0x56F4D573C1CC80E1ULL,
		0xCC7E6DD646E29F97ULL,
		0x2E10E7AFDEDE5785ULL,
		0x1847F4A7CCD0EB34ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C9E0F48E0E8B998ULL,
		0x7C786A1E13AAE76CULL,
		0x9E247FFC2985F7C0ULL,
		0x196D9109C05A7ECBULL,
		0x56F4D573C1CC80E1ULL,
		0xCC7E6DD646E29F97ULL,
		0x2E10E7AFDEDE5785ULL,
		0x1847F4A7CCD0EB34ULL
	}};
	t = 0;
	printf("Test Case 273\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 273 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -273;
	} else {
		printf("Test Case 273 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x09B21CFB29F9F7CEULL,
		0x88938B3994A81D53ULL,
		0x15EEC7AF8A82F18AULL,
		0x6ED6D9928F369A33ULL,
		0xC44270B6EA401CBFULL,
		0xC140BC16F1645D61ULL,
		0xDF3A3655C46F5353ULL,
		0xA243388716531880ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x132953CB27DCBD19ULL,
		0x92AA4F7AA926B291ULL,
		0x5B3FC93DB9A8951DULL,
		0x0AE0506FC43AF996ULL,
		0x90781537680C4901ULL,
		0xBCDD137CAB4F26EEULL,
		0x0159B0E20F52999DULL,
		0x6DCF8640918BCE6FULL
	}};
	t = 1;
	printf("Test Case 274\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 274 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -274;
	} else {
		printf("Test Case 274 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEB199236EFBFE57DULL,
		0x03696C57BA24A9DDULL,
		0x511FED2E5DE5A8D1ULL,
		0xE61B18C0BCC9DEC4ULL,
		0xB31C60EF0526F9ECULL,
		0x803376CF18062FEFULL,
		0x6E05F889B45A1696ULL,
		0x783AC29322B94F25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x357208FCBD06DAF2ULL,
		0x387C20FA2F1CD359ULL,
		0xFE935B0C14F6EF5CULL,
		0x4B8125E46CA3DAEAULL,
		0xA8180084DEC20440ULL,
		0x8D67D9838D16EC0CULL,
		0xD727F6FFC467CE9EULL,
		0x0904D06E411E97DEULL
	}};
	t = 1;
	printf("Test Case 275\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 275 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -275;
	} else {
		printf("Test Case 275 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x71394AA9CB208C6DULL,
		0x2E5177148B6F2970ULL,
		0x88E6BD794AA37DBDULL,
		0x468EDC20B3EBBE0BULL,
		0x166F0DEDF39BE334ULL,
		0xDE48B3514F8230D2ULL,
		0x555F0E18A9BB34EDULL,
		0xCA2BDA7A549272B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22310F682578BC46ULL,
		0x7CD30C8B6BAFE47CULL,
		0x66EFD2B8316A2809ULL,
		0x33B692FA5AB90330ULL,
		0x726ADB11E127ABF1ULL,
		0xD268E2EBB8CABB9CULL,
		0x26A47E976A7B410CULL,
		0xC2DF6D3950A7E272ULL
	}};
	t = 1;
	printf("Test Case 276\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 276 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -276;
	} else {
		printf("Test Case 276 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x63E03B77AECFAC78ULL,
		0x298D217C193541B7ULL,
		0xBBE4BB0DCF3A1EA5ULL,
		0x96B1FBA5882853A1ULL,
		0xADB539FAD0B38E2BULL,
		0xE80C37BA3853E4C9ULL,
		0xE34E79C746C627D6ULL,
		0x89E0763D2EAD5482ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63E03B77AECFAC78ULL,
		0x298D217C193541B7ULL,
		0xBBE4BB0DCF3A1EA5ULL,
		0x96B1FBA5882853A1ULL,
		0xADB539FAD0B38E2BULL,
		0xE80C37BA3853E4C9ULL,
		0xE34E79C746C627D6ULL,
		0x89E0763D2EAD5482ULL
	}};
	t = 0;
	printf("Test Case 277\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 277 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -277;
	} else {
		printf("Test Case 277 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE67AB9A19756F1E1ULL,
		0x26205B75F39B1D00ULL,
		0x1088CD600FE84048ULL,
		0x8BA76B97F72C5606ULL,
		0x397EE1037663D5A3ULL,
		0xBA683C105E5F28A2ULL,
		0xE68053BB9C580ADCULL,
		0xE0D3ECBCCA0AF45AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x499453EF5F727F6BULL,
		0x6E75E30E25ED315AULL,
		0xE3FBCA662D00BB91ULL,
		0x839CCCBD2B8E47F0ULL,
		0x4861B89DC51074DCULL,
		0xAA5E35AC0AEF7F21ULL,
		0x6BBF914E607BB7EDULL,
		0xA792C4EBD1BBA1B7ULL
	}};
	t = 1;
	printf("Test Case 278\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 278 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -278;
	} else {
		printf("Test Case 278 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFAC6979F9D2516BBULL,
		0xC6785A454692BEE4ULL,
		0x9DF5722488874DBFULL,
		0x40C9F08D1AAD3ED8ULL,
		0x3842351CC6196B74ULL,
		0x8CF9BE295BE82535ULL,
		0x4442FA017FF396A3ULL,
		0x8A30C6D5FDA27C4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE19E562A463E7D11ULL,
		0x42647F9F9F43B113ULL,
		0x916138A99CB5C37FULL,
		0x9C2CBFFA5756F637ULL,
		0xD6E532608A695D1BULL,
		0x7DF0385D3EC1A848ULL,
		0xF79A60DE1492CFC7ULL,
		0xB1BD3E0C1FD49C4CULL
	}};
	t = -1;
	printf("Test Case 279\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 279 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -279;
	} else {
		printf("Test Case 279 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3260C7BA1F0EDBC1ULL,
		0xBF70724D611C640AULL,
		0x49093E46476CC606ULL,
		0x189A80A223F67D86ULL,
		0x8D0F8850E5234DEDULL,
		0x61E91501380E19D2ULL,
		0x8AD1AD68098B8505ULL,
		0xABB2DF2A421060F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7474F319037E4AC6ULL,
		0xC94E34D5C5ABC437ULL,
		0x48DA65FEE9F5D594ULL,
		0x9CD61E564E51F020ULL,
		0xCC643AC7A55A7329ULL,
		0x6DB42A889D6957C3ULL,
		0x2B0F87B1BE04D79EULL,
		0xA5573D9B180BD3A8ULL
	}};
	t = 1;
	printf("Test Case 280\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 280 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -280;
	} else {
		printf("Test Case 280 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA8522D234038DCECULL,
		0xCF5553D74A76C7EEULL,
		0xCD1778A838E15E0FULL,
		0xC2DD9A3CB7FF5C20ULL,
		0x1D3B8D8D9D1120F0ULL,
		0x5F667141054C3213ULL,
		0x3C645E951B742B6EULL,
		0x5963100D05D2FC94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8522D234038DCECULL,
		0xCF5553D74A76C7EEULL,
		0xCD1778A838E15E0FULL,
		0xC2DD9A3CB7FF5C20ULL,
		0x1D3B8D8D9D1120F0ULL,
		0x5F667141054C3213ULL,
		0x3C645E951B742B6EULL,
		0x5963100D05D2FC94ULL
	}};
	t = 0;
	printf("Test Case 281\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 281 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -281;
	} else {
		printf("Test Case 281 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFB636ECD40DF85EBULL,
		0x74FA8EF91F7B7D21ULL,
		0x78E881E94EEC5E7FULL,
		0x5B58621CED7775F3ULL,
		0xE9D52EE88CC7A9F4ULL,
		0xADF2444DE4FEF32EULL,
		0xB8702C81035E7D7BULL,
		0xF16120FFC6C4FFBAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D90D78BC8B623E5ULL,
		0x7AFC9CA0027782E3ULL,
		0x767FAA5FD512326DULL,
		0xEAE6BAE4B897E93AULL,
		0x053207262C4244A7ULL,
		0x7A30142785ADB864ULL,
		0x795533F0A6C340A2ULL,
		0x37A9D23B0A654C67ULL
	}};
	t = 1;
	printf("Test Case 282\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 282 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -282;
	} else {
		printf("Test Case 282 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD9471712739BD4A2ULL,
		0x1B8EA561D951DF75ULL,
		0x1814DEDC799F6C33ULL,
		0x54B5F2682114F010ULL,
		0x2CB4557BE80F548EULL,
		0xFC5D79A5CF26D773ULL,
		0x5C4BADB5704A3F31ULL,
		0xAF48C07235C3DC06ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C37F1B09620C01FULL,
		0xEEAB5D28369A483BULL,
		0x6AE998F0F9999115ULL,
		0x8E19D22981900518ULL,
		0x827039AF58CDE827ULL,
		0x5A91DA4E0EB034AFULL,
		0x96360C0E3D085E13ULL,
		0xB15CBF846C60058EULL
	}};
	t = -1;
	printf("Test Case 283\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 283 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -283;
	} else {
		printf("Test Case 283 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x44A3F286ADB035C8ULL,
		0x3300D9E9B862289FULL,
		0x03010725D6A7FB9FULL,
		0xCC7CECEA7B38C5F0ULL,
		0x0606487B60920C08ULL,
		0x0EDEA1D27F84B494ULL,
		0xD9B96DFA7ED7C740ULL,
		0xA26AC1171431B128ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D3F81DAFA8955FCULL,
		0xEC0DEB371A171EA9ULL,
		0x5E07CA8E34DCC5E9ULL,
		0xC42B42BBE198F18BULL,
		0xAB57940282FF6521ULL,
		0x5C1C91EA31277494ULL,
		0x37A8BF8B14E04952ULL,
		0x8E7FD391BF3FDD92ULL
	}};
	t = 1;
	printf("Test Case 284\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 284 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -284;
	} else {
		printf("Test Case 284 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC5AAD7682FE5A660ULL,
		0x5A68CA1CC6EA8FA5ULL,
		0x596A64742A27F56FULL,
		0x4621730A47129632ULL,
		0xC5D4770AF931C491ULL,
		0xF7A8D74DDC020A7CULL,
		0x09B637C3E182FB05ULL,
		0x47982AFCDF2586CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5AAD7682FE5A660ULL,
		0x5A68CA1CC6EA8FA5ULL,
		0x596A64742A27F56FULL,
		0x4621730A47129632ULL,
		0xC5D4770AF931C491ULL,
		0xF7A8D74DDC020A7CULL,
		0x09B637C3E182FB05ULL,
		0x47982AFCDF2586CDULL
	}};
	t = 0;
	printf("Test Case 285\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 285 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -285;
	} else {
		printf("Test Case 285 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x380D98921DD595AAULL,
		0xF683EA8945C8610BULL,
		0xF5F791C0752DA485ULL,
		0x7E71FAFD40B577ADULL,
		0x2FD522C3FFEDE076ULL,
		0x19066C8BE77C7BECULL,
		0xA2F5F9A89B197645ULL,
		0x5ADDACCEF60A0363ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35FA1DB9BB3BC34CULL,
		0x59729E74E8A5A8E7ULL,
		0xAA9C800FB0F46636ULL,
		0x5E6C9A406B7E98F8ULL,
		0x1C98494CBE4350B7ULL,
		0x63C71783C49D8830ULL,
		0x6849FFEDCE7901D7ULL,
		0x4885FAED2FCAD175ULL
	}};
	t = 1;
	printf("Test Case 286\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 286 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -286;
	} else {
		printf("Test Case 286 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x93ABA1BDA686930EULL,
		0x5FECA0DC70B29DBFULL,
		0xDBBF6E7E4B54BBA4ULL,
		0x2E10C3F7B4B44BA2ULL,
		0xE876ED098335227AULL,
		0x208F146B69DDD158ULL,
		0x4BF69AE16FADF949ULL,
		0x7368C278186A802DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC017B639D6DC0642ULL,
		0x14BC6586F4C745D7ULL,
		0x602013438B9B4691ULL,
		0x2C115AF36389D4BDULL,
		0xCB39255ACDB3DE3DULL,
		0xBD1C2B2E163F6A7EULL,
		0x46CC4F03064F4493ULL,
		0xCDEE2B7C637152E3ULL
	}};
	t = -1;
	printf("Test Case 287\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 287 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -287;
	} else {
		printf("Test Case 287 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x672AA853ECA5DDC5ULL,
		0x167D046D2031741BULL,
		0x0F8C4A009560A2EAULL,
		0x6810817274F58FE5ULL,
		0x5C52EF88CCE25FFBULL,
		0x960579BEC1081F8FULL,
		0x1BDDD6AA02961D57ULL,
		0x75650FA3BDE243E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FA4FE4D0C7C0AADULL,
		0x5FA58AA7D14C0507ULL,
		0x4224D9D82E9C6BE3ULL,
		0x28C9EAC8B8EEA692ULL,
		0x915B57F94899EC0BULL,
		0x770728BB47184B03ULL,
		0x2F73AA964F62F7EFULL,
		0x1D3112A4F7BD4DB4ULL
	}};
	t = 1;
	printf("Test Case 288\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 288 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -288;
	} else {
		printf("Test Case 288 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE7E6DF05F2021565ULL,
		0x291B5DEC6ABDB7AFULL,
		0xB508692EACA974A7ULL,
		0xA8816338B14F9FA0ULL,
		0xFE073FED3A1A4CCFULL,
		0xF6AB3E83109602D2ULL,
		0x22AA144848F7B4CAULL,
		0xBA9D0013EEB77AE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7E6DF05F2021565ULL,
		0x291B5DEC6ABDB7AFULL,
		0xB508692EACA974A7ULL,
		0xA8816338B14F9FA0ULL,
		0xFE073FED3A1A4CCFULL,
		0xF6AB3E83109602D2ULL,
		0x22AA144848F7B4CAULL,
		0xBA9D0013EEB77AE0ULL
	}};
	t = 0;
	printf("Test Case 289\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 289 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -289;
	} else {
		printf("Test Case 289 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE3BD79AD5C435AF7ULL,
		0x6445FA09C85796A4ULL,
		0xED681D56728B8A87ULL,
		0xF180C7B5C7A5F86EULL,
		0xBA64AFE689C76482ULL,
		0x565A031D1F0AA7B7ULL,
		0xF38BD33D748E631CULL,
		0xAFF77BF06F099D37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x029A4A97610A6B73ULL,
		0x4D6E9F9A91975867ULL,
		0x836B8399142265D2ULL,
		0x92F4C75FBEC32C8DULL,
		0x4466E124031F100CULL,
		0x50F69E8821923469ULL,
		0x0824BBE6B4589F87ULL,
		0xFDC0C5B108A4AE42ULL
	}};
	t = -1;
	printf("Test Case 290\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 290 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -290;
	} else {
		printf("Test Case 290 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x04B964EE51851DD3ULL,
		0x90F3148BCE5DBCFBULL,
		0xD3A11B5D418F5DDAULL,
		0xF9114DFECC967103ULL,
		0xE8FC92CCC722E0EAULL,
		0x8050A152A2C9719FULL,
		0xEF3E869C564F246CULL,
		0xC5BD785D5A629390ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF02E8B8FAB172ACFULL,
		0x656A0FB5D4C589AFULL,
		0x50FF8C9984CADBEBULL,
		0x8FAB021C2405ACC5ULL,
		0xCE0F51D2CF49E6C1ULL,
		0xB4401C4FD800AF37ULL,
		0x4BD9C7AF8669CECCULL,
		0x06CA26E48E9FB7A9ULL
	}};
	t = 1;
	printf("Test Case 291\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 291 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -291;
	} else {
		printf("Test Case 291 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x692FF861F5694040ULL,
		0x600BF787D124A93BULL,
		0x2AE4040362A3E190ULL,
		0xFBD25A223419D5F8ULL,
		0xB44770FF61A21362ULL,
		0x8469E4E0DC5AD74BULL,
		0xEB45F86403D2E953ULL,
		0x2A157F575DD70B6FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFD8F2D857502777ULL,
		0x19D2165911D29615ULL,
		0xED36CC79E8888C9AULL,
		0xA544AF30B7DD8667ULL,
		0x3578BB338E92AE64ULL,
		0x5A57689B8EDE5367ULL,
		0x2FA8F461D60A8D45ULL,
		0xB5A6C65DFB424794ULL
	}};
	t = -1;
	printf("Test Case 292\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 292 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -292;
	} else {
		printf("Test Case 292 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFC48218FC95C3C80ULL,
		0x8F82EF77702317BFULL,
		0x58E1A58962805C0DULL,
		0x5A8D667FEDF0FB87ULL,
		0xC54F1AA1FE5CDC6CULL,
		0xE473325663A7C291ULL,
		0xFE334D1106E90BDDULL,
		0x5BCE474DE63B9B37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC48218FC95C3C80ULL,
		0x8F82EF77702317BFULL,
		0x58E1A58962805C0DULL,
		0x5A8D667FEDF0FB87ULL,
		0xC54F1AA1FE5CDC6CULL,
		0xE473325663A7C291ULL,
		0xFE334D1106E90BDDULL,
		0x5BCE474DE63B9B37ULL
	}};
	t = 0;
	printf("Test Case 293\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 293 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -293;
	} else {
		printf("Test Case 293 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE2CF9A58EB42C1A6ULL,
		0x5B258C1D207EA13BULL,
		0xD229F55552F20292ULL,
		0x4A0AD2F2BC7E71DAULL,
		0x48130A9CAC9B0363ULL,
		0x64B1B3B65BBBA531ULL,
		0x7FBB008764C73B7FULL,
		0xDAB41FC698014D58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE5DAB0AE9645A3DULL,
		0xABA37B80E8E7539DULL,
		0x5EEEEA265F321504ULL,
		0x7F0CDBEF817081D6ULL,
		0x5871B734D623C59EULL,
		0x84BB64F666F8F3E8ULL,
		0x641395F0400BB612ULL,
		0x33187FDFFD01856EULL
	}};
	t = 1;
	printf("Test Case 294\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 294 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -294;
	} else {
		printf("Test Case 294 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x77B81E1E3ECD3BD3ULL,
		0x9EE3596DD5FB234BULL,
		0x443F28306D54E5D1ULL,
		0x98B5C467D9B4ED1DULL,
		0x4BDC97CB44F26D1EULL,
		0x540AC7C245F296AEULL,
		0xD50B1D03C63C6508ULL,
		0x00929E8DB871E7BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9BF97E46D3079A2ULL,
		0x16AADED287F0780FULL,
		0x3AAA3F8FA57DEF5BULL,
		0xBC97D40860A7762FULL,
		0xF3E3E948D7D4651FULL,
		0xB3318829B33A4BDCULL,
		0x03A52D257CB045ADULL,
		0x586539EB1194F967ULL
	}};
	t = -1;
	printf("Test Case 295\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 295 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -295;
	} else {
		printf("Test Case 295 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x362252117ECD9142ULL,
		0x0A4153B7FE223B36ULL,
		0xF3F62C13B9E2B41AULL,
		0x3EB4719F25B4E660ULL,
		0xC6252588D88A1ACBULL,
		0xD4B1CF1D8699BACDULL,
		0xF1D4C9B1CB94496AULL,
		0x0CDA250A52FA4E80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E4D690199CEF319ULL,
		0x173C35B94B3430D0ULL,
		0xE8619DB0B77366ECULL,
		0xC10F824EA5978DDEULL,
		0xDCE1294F2FF1FFD7ULL,
		0x9827E992ACAC76BCULL,
		0x3410DE73F28DA2BCULL,
		0x4BC7F26A43B0D241ULL
	}};
	t = -1;
	printf("Test Case 296\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 296 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -296;
	} else {
		printf("Test Case 296 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1CAABDE5534B96D2ULL,
		0xD09A0A4EF7DA59C5ULL,
		0x77ADD006CF3B9897ULL,
		0xD16A49144FF5B34AULL,
		0x13E420573E6B8E77ULL,
		0x55D6B6920EB0C98BULL,
		0x778CA3CBA960CBA8ULL,
		0x461E9A8D731F5C36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CAABDE5534B96D2ULL,
		0xD09A0A4EF7DA59C5ULL,
		0x77ADD006CF3B9897ULL,
		0xD16A49144FF5B34AULL,
		0x13E420573E6B8E77ULL,
		0x55D6B6920EB0C98BULL,
		0x778CA3CBA960CBA8ULL,
		0x461E9A8D731F5C36ULL
	}};
	t = 0;
	printf("Test Case 297\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 297 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -297;
	} else {
		printf("Test Case 297 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFED7F2C7B2190065ULL,
		0x1709405816AC07E3ULL,
		0x2F54C6F02EC8B33EULL,
		0x3EB4D1917ED498E6ULL,
		0x88906F063A92F513ULL,
		0xD0D16E2FA377ED73ULL,
		0xF190FBE5133EF4E5ULL,
		0xD53E3580AB72BCDDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x621E4F662DB6AB29ULL,
		0x40B3C26956FF3DA0ULL,
		0x5DCD0B1456D07CDCULL,
		0x6EA8708A20CC360AULL,
		0x960F1D293655C9B5ULL,
		0xB0D89D0344374EF9ULL,
		0xD448C4B7B9178895ULL,
		0xE891C6BD1CE3A542ULL
	}};
	t = -1;
	printf("Test Case 298\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 298 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -298;
	} else {
		printf("Test Case 298 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF569A7BCEC95E81AULL,
		0x284F91A0CBAB63BFULL,
		0x8D47B752AAB15ABEULL,
		0x5EAD1113CC8C59D7ULL,
		0x0A6D7599D5253916ULL,
		0x1AAEA5597B3201CAULL,
		0x30BEEDEEC183DA5BULL,
		0x62304AE32D70AA1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x385A1D6A510FFBE7ULL,
		0x346CD45F049B1E7CULL,
		0xE2EDECA77EC084D5ULL,
		0x56A010027D91B842ULL,
		0xD476C125434F56AEULL,
		0x9C39C5F495718C09ULL,
		0x4244B0766098C9ECULL,
		0x2CAC67E9D7D895D2ULL
	}};
	t = 1;
	printf("Test Case 299\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 299 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -299;
	} else {
		printf("Test Case 299 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD0A517CA59A19FE1ULL,
		0xC9CA959F52F0DD4BULL,
		0x70061408976B1A30ULL,
		0xCDED71261BB446D3ULL,
		0x54D9E13ACA88D4D3ULL,
		0xC4A995BFDD64B3ECULL,
		0xD0A6B970CA5EA1F9ULL,
		0xD08E1D65B993A3DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF952A952BC019F96ULL,
		0xE929BA59766672B4ULL,
		0x2EEA55365C0B4F9DULL,
		0xEC611C7487009DF4ULL,
		0x74E947ACE52DFF8FULL,
		0x885594C7C8A19281ULL,
		0x59C5503931F20267ULL,
		0xEFBF6F79AD8C7929ULL
	}};
	t = -1;
	printf("Test Case 300\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 300 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -300;
	} else {
		printf("Test Case 300 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0343CB37C28FA280ULL,
		0xCAA6D066769FF9A6ULL,
		0xB3201EF2396F85EFULL,
		0x51D2C29E936F7F56ULL,
		0xC93607C690BE83F5ULL,
		0x12B87627FEE47504ULL,
		0xFE67474379FB6E11ULL,
		0x207703A0F968FC11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0343CB37C28FA280ULL,
		0xCAA6D066769FF9A6ULL,
		0xB3201EF2396F85EFULL,
		0x51D2C29E936F7F56ULL,
		0xC93607C690BE83F5ULL,
		0x12B87627FEE47504ULL,
		0xFE67474379FB6E11ULL,
		0x207703A0F968FC11ULL
	}};
	t = 0;
	printf("Test Case 301\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 301 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -301;
	} else {
		printf("Test Case 301 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDE48844A081F2E0DULL,
		0xCD43B9AD1E131052ULL,
		0x85C26443A9178255ULL,
		0x8E82B73F712517F2ULL,
		0x7E1969B1096620D3ULL,
		0x7C4D9338C95008C2ULL,
		0x2330C0A8595D4CF9ULL,
		0x9EDD535B9A5F9AB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x016C80630870CA3CULL,
		0x4262DE5C881A58A7ULL,
		0x0755114C663C1561ULL,
		0xE4569C5EB746A102ULL,
		0x3167E9CB8E38FD49ULL,
		0x17212C7315DD7183ULL,
		0x39B9090E920D25A0ULL,
		0x99F54BF7E30054BCULL
	}};
	t = 1;
	printf("Test Case 302\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 302 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -302;
	} else {
		printf("Test Case 302 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2B6C9057C323EB1AULL,
		0xA57F0CD75B4F7FA9ULL,
		0xDFEF7CFB26A152DDULL,
		0x9FBB47862214E8B5ULL,
		0xB6236C8DFB0F9B3DULL,
		0x429DB5EF1DBEA7A8ULL,
		0x4F49773B4F4B869BULL,
		0x8C777EC01DC43520ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30BD81DB42DBA86CULL,
		0x58FDFC87DAE5C718ULL,
		0xB840F95B25E49D59ULL,
		0x46B3598A4D151189ULL,
		0xFE6AB3DBC28CCF76ULL,
		0x8E0D269213D9DE89ULL,
		0xAE95A520531AC27BULL,
		0x0509AA3B3781F7FDULL
	}};
	t = 1;
	printf("Test Case 303\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 303 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -303;
	} else {
		printf("Test Case 303 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x35AF9F99CD022E3DULL,
		0xFD12224EE8F43FBCULL,
		0x21443E55AC3EEF31ULL,
		0x60C0A9C751ADC261ULL,
		0xDA84669AF65F2398ULL,
		0xEEF5AF8F63262819ULL,
		0xBB9A53C1AE60B608ULL,
		0x934F520ECE2C7B45ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B58BE63CB6DF651ULL,
		0x39C7AB37CA3D3942ULL,
		0xA601DA4BB263AF23ULL,
		0x9AA066EC696D76F0ULL,
		0xF640B55651EBB2CDULL,
		0xDB000EDE2D5A0706ULL,
		0xC1D0C498EB3874D7ULL,
		0x919457192407CA4EULL
	}};
	t = 1;
	printf("Test Case 304\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 304 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -304;
	} else {
		printf("Test Case 304 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8892B0593E92072DULL,
		0xE27335BFA1407E02ULL,
		0x251227D2D56AB9A5ULL,
		0xD835F1E31DAB5FDFULL,
		0xD43606ED7668D8E6ULL,
		0xBBA9424BA3C14635ULL,
		0x560F980EA6509CF4ULL,
		0x4F402341F217B985ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8892B0593E92072DULL,
		0xE27335BFA1407E02ULL,
		0x251227D2D56AB9A5ULL,
		0xD835F1E31DAB5FDFULL,
		0xD43606ED7668D8E6ULL,
		0xBBA9424BA3C14635ULL,
		0x560F980EA6509CF4ULL,
		0x4F402341F217B985ULL
	}};
	t = 0;
	printf("Test Case 305\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 305 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -305;
	} else {
		printf("Test Case 305 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x487F9DCB3CCB327DULL,
		0x0B3A017D528AA42FULL,
		0x6BE5237F7D3DF8FDULL,
		0x22C47BB92E3F8211ULL,
		0x44BDC290A1CE568CULL,
		0x2709ACF9D780E861ULL,
		0xFD044CC4F38B3196ULL,
		0xB19C4782FFE7596DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7ED9CB0AB01A923ULL,
		0x7E0C0D96B2BF4C93ULL,
		0x12B02971EDAC5556ULL,
		0x2E371C73FA0ABF3FULL,
		0x528BEA9ACDFC1CA0ULL,
		0x434E5A36F1F272BBULL,
		0x4FB1D462222ABDBCULL,
		0x9444652808507276ULL
	}};
	t = 1;
	printf("Test Case 306\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 306 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -306;
	} else {
		printf("Test Case 306 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x03CFF06DE6EA5743ULL,
		0xF03EEF342ACA5E64ULL,
		0xFB5324CC88E774BFULL,
		0xC21C8D8575BF4FB9ULL,
		0x48826CEF5D3024C6ULL,
		0xD4A8E492E5EC941BULL,
		0x1204DDA29906045CULL,
		0x44929D750C1A5F19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0C42A40D8BFA7FAULL,
		0x52E58B7630CCD90CULL,
		0x40008241EC710562ULL,
		0x6B8064DE8CD16655ULL,
		0x6B383515E6DBEB3DULL,
		0x1A90B219342CA9B8ULL,
		0xF6205BA773229B30ULL,
		0xAB2599C2F89B3D09ULL
	}};
	t = -1;
	printf("Test Case 307\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 307 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -307;
	} else {
		printf("Test Case 307 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x88B0E885761C5E1DULL,
		0x1A983B4295993B9EULL,
		0x925E5CF5B7D089DCULL,
		0x6F074683325FBEC7ULL,
		0x2121AE72FE288B96ULL,
		0xD6B5AB410B97E965ULL,
		0xAC18A59EA981BD20ULL,
		0xFAEAF0CA847874FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA590CDA957490801ULL,
		0xED6572A074B766A7ULL,
		0x6C16312FA620867DULL,
		0x843175E0AE080B84ULL,
		0x8CAF571651DFC485ULL,
		0x8FBBB2F9F52592F2ULL,
		0x216C8A8C03EE1FE9ULL,
		0x0DCEEBE77E9A38BBULL
	}};
	t = 1;
	printf("Test Case 308\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 308 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -308;
	} else {
		printf("Test Case 308 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4D6FA42BA9BE122AULL,
		0x8913DD7F7C5C0B3EULL,
		0x350C07A8D24673E6ULL,
		0xC5B45773252A3A6DULL,
		0xC4E105D8621A3560ULL,
		0x2DB8C776F4044686ULL,
		0xFC5C95D9D2E2A64CULL,
		0xA093A996C6539169ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D6FA42BA9BE122AULL,
		0x8913DD7F7C5C0B3EULL,
		0x350C07A8D24673E6ULL,
		0xC5B45773252A3A6DULL,
		0xC4E105D8621A3560ULL,
		0x2DB8C776F4044686ULL,
		0xFC5C95D9D2E2A64CULL,
		0xA093A996C6539169ULL
	}};
	t = 0;
	printf("Test Case 309\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 309 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -309;
	} else {
		printf("Test Case 309 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4F8614556B7A14E6ULL,
		0xB0412666B5C016DAULL,
		0xF1BBB9CA18213DE5ULL,
		0x7BC6DD215F453B28ULL,
		0xBC4EF065B7793380ULL,
		0x51B039D3F34714A3ULL,
		0xDA9EF895FDE5AE02ULL,
		0x57F768ED6B6FD2B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83C18C1755A26628ULL,
		0xFF35B8C234741012ULL,
		0xAF77F2EF5AD59492ULL,
		0x368DB992F58ED7CFULL,
		0x84E5336ACA70AD6EULL,
		0xF7D9D25544659D55ULL,
		0x31DF01C52B0BACEAULL,
		0x425946AE64122145ULL
	}};
	t = 1;
	printf("Test Case 310\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 310 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -310;
	} else {
		printf("Test Case 310 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAE23FF13D18C556DULL,
		0x59F1622D02C26C37ULL,
		0x31707F76E5949B0DULL,
		0xA9FE6008F6A51891ULL,
		0xDADAC1E7ED505D71ULL,
		0x1414B921CBBDEE77ULL,
		0x2488F275944CEBC4ULL,
		0x3E8A683F27C20EA0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB64FA22D17FD814DULL,
		0x7A15BFDAB6463887ULL,
		0x587ECC2DF1C37A51ULL,
		0xD8EF25CC16C3A71DULL,
		0x42E5397CFB5ECF22ULL,
		0xEBD1A15023D8D6CFULL,
		0x127782402860BB8DULL,
		0xF667B75811F12742ULL
	}};
	t = -1;
	printf("Test Case 311\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 311 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -311;
	} else {
		printf("Test Case 311 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF05E8E28F447ECEAULL,
		0x5C6678A5C8EC6011ULL,
		0x49996767392CD7A6ULL,
		0xD9FF28330E53D274ULL,
		0x522D19F1FEEAB4B6ULL,
		0x05A24A584E2028E4ULL,
		0x2C9E116389D4D99DULL,
		0xE3A2E3B8129EDF78ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A950253FA4A5939ULL,
		0xD3562769DE32F743ULL,
		0x9B829B1FB8F6A8ABULL,
		0x9576838F224A53BBULL,
		0x2BE1DB662E229BD8ULL,
		0x84C3077DFFC05670ULL,
		0x0318C00239FF0646ULL,
		0x8A99856DB44CDBF2ULL
	}};
	t = 1;
	printf("Test Case 312\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 312 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -312;
	} else {
		printf("Test Case 312 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD3734FDA323463F4ULL,
		0x6D264F74C419A289ULL,
		0x703B4210E7AC298FULL,
		0xFC72F44341B57E40ULL,
		0x20120596E60FBC12ULL,
		0x51C16E410239E6BDULL,
		0x7573677E83C4293DULL,
		0x2F164288894E04C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3734FDA323463F4ULL,
		0x6D264F74C419A289ULL,
		0x703B4210E7AC298FULL,
		0xFC72F44341B57E40ULL,
		0x20120596E60FBC12ULL,
		0x51C16E410239E6BDULL,
		0x7573677E83C4293DULL,
		0x2F164288894E04C3ULL
	}};
	t = 0;
	printf("Test Case 313\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 313 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -313;
	} else {
		printf("Test Case 313 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF81746FC840DFECAULL,
		0x2A5C8043FC058F8CULL,
		0x032A6459532FDFDBULL,
		0x7B0BB5CF5B89AECFULL,
		0x03B4329052DC4372ULL,
		0x7599F9E4537AAA79ULL,
		0xA99086DAE71CBC72ULL,
		0x2BF77F99CCB76A10ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF272C6D92D737ACEULL,
		0x4A89087C1E5421EEULL,
		0x9CB716E3FF04D8EFULL,
		0x83D2281B4EC76DDBULL,
		0x80F45235695452C3ULL,
		0x44B4E825739AEEF1ULL,
		0x5F061FE28227AB32ULL,
		0x384C5455F0CC1AD3ULL
	}};
	t = -1;
	printf("Test Case 314\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 314 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -314;
	} else {
		printf("Test Case 314 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x44156213643FEF25ULL,
		0xDD0C439262514F6AULL,
		0x83865DD381E34E4AULL,
		0x4452A5C97D70B66EULL,
		0x931EE19E5D2BE9F0ULL,
		0x39DD4222A096BE55ULL,
		0x07B0012491C865AEULL,
		0xD8E17A40A46689C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5403BA77E9280A17ULL,
		0xD65A7DF4DF8338C3ULL,
		0x5B4E7B9F109AD11CULL,
		0x24507D9C52F6BB94ULL,
		0x473E84BCF2836983ULL,
		0xE5F140C0B147A9E5ULL,
		0x188F890783445F0EULL,
		0x9F6EDFB5A8CC7073ULL
	}};
	t = 1;
	printf("Test Case 315\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 315 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -315;
	} else {
		printf("Test Case 315 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEF8AFDF8C0BBE479ULL,
		0xE33EE7F34715FCEAULL,
		0xE38AFBDE83A31ABEULL,
		0x87457BEA16463F5BULL,
		0xDB3C37B5D25F1483ULL,
		0x8E711556C05F2A6EULL,
		0x4819D212BA79FAACULL,
		0x27FB6CEED7EF2D47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x097392D9F1638ED4ULL,
		0xFCBF1036E2E23D25ULL,
		0x39D34C3AA4E48852ULL,
		0x2FE6980D64EC6AF3ULL,
		0x7EA59E8E11BC0759ULL,
		0xC743E9E80F8502B6ULL,
		0x1E6877E0F861A421ULL,
		0x57709361AF9BCD81ULL
	}};
	t = -1;
	printf("Test Case 316\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 316 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -316;
	} else {
		printf("Test Case 316 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAA39F3C20D0B7749ULL,
		0xB042F75F87884FF6ULL,
		0x3462277E88D75449ULL,
		0x12DC63C2CDC70329ULL,
		0xD2F45546A2FA4AD4ULL,
		0x991FC920E034D0B8ULL,
		0x8764C6D5183537DEULL,
		0x3871E916C7A7CFEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA39F3C20D0B7749ULL,
		0xB042F75F87884FF6ULL,
		0x3462277E88D75449ULL,
		0x12DC63C2CDC70329ULL,
		0xD2F45546A2FA4AD4ULL,
		0x991FC920E034D0B8ULL,
		0x8764C6D5183537DEULL,
		0x3871E916C7A7CFEDULL
	}};
	t = 0;
	printf("Test Case 317\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 317 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -317;
	} else {
		printf("Test Case 317 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6C2D47CCEB6844D8ULL,
		0x5CFE1A85823E7B9CULL,
		0x312D86D92409BF23ULL,
		0x07199CF76D28C7C2ULL,
		0x7E11E846258DCE9CULL,
		0x58D842320DAF7CC6ULL,
		0xEABFFEC3F4782E94ULL,
		0xAAF4B57C52DD87D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46051E722BF0D011ULL,
		0x9EF11F878E6BC51EULL,
		0x122719E5E31C5DB8ULL,
		0x9006D1CFB9E8F530ULL,
		0xF60E0464CA87C6DBULL,
		0x037928F61CF3ECFBULL,
		0xBB9F25B6B922272DULL,
		0xE864155E7D17415FULL
	}};
	t = -1;
	printf("Test Case 318\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 318 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -318;
	} else {
		printf("Test Case 318 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC7ED1CA18D482478ULL,
		0x4C8B23620462B67BULL,
		0xDC45FF28F982B618ULL,
		0x52065312BED1FF14ULL,
		0x0943A713D781E3B4ULL,
		0x5D79517E6A301C74ULL,
		0xC77286EB8ED9B236ULL,
		0x2B91A0C1D59678B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46B1F34877ACCE9EULL,
		0xA9927FF3DC5933B9ULL,
		0x83B5CDBDD3041873ULL,
		0x310110E739AD89B9ULL,
		0xF362FDA206409220ULL,
		0x0F7356F2AF2F5A13ULL,
		0x97DFE62A2804E973ULL,
		0x413530F674D0AB13ULL
	}};
	t = -1;
	printf("Test Case 319\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 319 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -319;
	} else {
		printf("Test Case 319 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1E637AE633C7137FULL,
		0xBC61D45D40EE8670ULL,
		0x87F921FEBC3F6C52ULL,
		0x3394C4CB751414E3ULL,
		0xA596AAE5D03570F6ULL,
		0xE19BCB54CBA6C2C6ULL,
		0xA6A9B622A0A0E3AEULL,
		0x2B1A0FDDCFDB7E31ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB1B59190E7F6962ULL,
		0xEBA3551BC0D9AB6FULL,
		0x439750820EF535D3ULL,
		0x1F3D9AF0C8653DBAULL,
		0xC80EFAB0F4B65E6CULL,
		0x4D5AEBE822D7BA8DULL,
		0x5541411B327F7DF7ULL,
		0x1BE43BAD10CDD8D2ULL
	}};
	t = 1;
	printf("Test Case 320\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 320 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -320;
	} else {
		printf("Test Case 320 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x45DC636825A88838ULL,
		0x0DC177A341D1BD2EULL,
		0xED370162D05F800BULL,
		0x334FDA381C0D5252ULL,
		0x598F858BC1614204ULL,
		0x28061309921917F5ULL,
		0x5A90C7AA70C8C641ULL,
		0xC525D6E2DDF34D02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45DC636825A88838ULL,
		0x0DC177A341D1BD2EULL,
		0xED370162D05F800BULL,
		0x334FDA381C0D5252ULL,
		0x598F858BC1614204ULL,
		0x28061309921917F5ULL,
		0x5A90C7AA70C8C641ULL,
		0xC525D6E2DDF34D02ULL
	}};
	t = 0;
	printf("Test Case 321\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 321 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -321;
	} else {
		printf("Test Case 321 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC5ECF7C2B30BBDB4ULL,
		0x8A52EB49BE69F6F7ULL,
		0xF73C38983D042512ULL,
		0xF533F8949BD77041ULL,
		0x62B336E4A0F9C345ULL,
		0x4FEAD0580933BBC5ULL,
		0xBB9E46E067CA071BULL,
		0x999FFED272DA53EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE1F6366AD8292A7ULL,
		0x8177C0FAE4EE8787ULL,
		0x17BD76D459665CAEULL,
		0xA15F875B8C1FC351ULL,
		0x4BE8FC700A417B57ULL,
		0x6C96F4E22736FFE1ULL,
		0xAEB983728F3DC9C1ULL,
		0x1E6045E31A7D848DULL
	}};
	t = 1;
	printf("Test Case 322\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 322 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -322;
	} else {
		printf("Test Case 322 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x86311E157EC62B6FULL,
		0xBDF66C731289F0D9ULL,
		0x473999CE1CC2DA4FULL,
		0xBE6DEA2EED2B9CACULL,
		0xAD5A142AFD925F71ULL,
		0xFE47799B1FC06E4AULL,
		0x83B0E2DBE2E22A89ULL,
		0x7667BA55EEC3A486ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB82AA17F718DFCC7ULL,
		0x3189D1718527DF15ULL,
		0x5A44F889BC4F70DDULL,
		0x708FC6C6D405CA6AULL,
		0xFE5CB57E3C429CCAULL,
		0xDD05CBF6B16FAC7FULL,
		0x23F01C4C18ABD05EULL,
		0x8B9F7A1B62CEBBECULL
	}};
	t = -1;
	printf("Test Case 323\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 323 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -323;
	} else {
		printf("Test Case 323 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0F31E4445AC337D0ULL,
		0x9A3F4DFB44EDC1ECULL,
		0x9D07CA1BC72226C9ULL,
		0x3B736845791880B0ULL,
		0x730C6BBAE90CA991ULL,
		0x57A2A8D7CF5A8802ULL,
		0x580E4D873A9F2DFBULL,
		0xC96014AE29127C5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C0186332E9A9597ULL,
		0x01A649343F71E15EULL,
		0x4FA0ECBCF4744C6CULL,
		0x53EAFFEBB1F5384EULL,
		0x8B6385BAD731FE78ULL,
		0x2640062D577C3DE5ULL,
		0x3FBBB9B4420D566EULL,
		0xA949CACC2B1FE846ULL
	}};
	t = 1;
	printf("Test Case 324\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 324 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -324;
	} else {
		printf("Test Case 324 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE211F2E39C8884EDULL,
		0x44B581D09D85F5B9ULL,
		0x28A34DE3A71B0E3FULL,
		0x26044E419B1CB231ULL,
		0x0BA5226A942C9C78ULL,
		0x665AE31F12699A40ULL,
		0x78AD63A627BD488AULL,
		0x52E284EC411B8195ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE211F2E39C8884EDULL,
		0x44B581D09D85F5B9ULL,
		0x28A34DE3A71B0E3FULL,
		0x26044E419B1CB231ULL,
		0x0BA5226A942C9C78ULL,
		0x665AE31F12699A40ULL,
		0x78AD63A627BD488AULL,
		0x52E284EC411B8195ULL
	}};
	t = 0;
	printf("Test Case 325\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 325 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -325;
	} else {
		printf("Test Case 325 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFEDDDCB3FE1996B2ULL,
		0xA49134502AE0DCFCULL,
		0xCEE2894586059A3CULL,
		0xFE13F5D39FFA3488ULL,
		0x5FDBF1F5D321DAA4ULL,
		0xEA79FBD1AB1A5167ULL,
		0x94D7D635314DFE1EULL,
		0x6B12A07857575FA9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA1664BF58507CECULL,
		0xE03E61B95DF56D4CULL,
		0x13F449F06B9E710FULL,
		0x7C7B9FA01E619947ULL,
		0xFB79B7BCDF90215AULL,
		0xBEC95D05C4CEFC01ULL,
		0x3BE574EE0A0AC7A9ULL,
		0x3BD6702D22842FE7ULL
	}};
	t = 1;
	printf("Test Case 326\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 326 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -326;
	} else {
		printf("Test Case 326 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4CDBA24E30A9F88FULL,
		0x17B898DFC3048E5DULL,
		0xEC8E7798CECCE2E4ULL,
		0x641D6696ED6127CBULL,
		0xF04E6B2C7C9C8943ULL,
		0xEAA794E7A5D9B646ULL,
		0x2CADC61ABF5863C8ULL,
		0xC1556BD7A4EEB605ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1921F8F31E7C204AULL,
		0xB020C9A8956547B0ULL,
		0x70C59F09F4EE7E55ULL,
		0xFEC456D198656282ULL,
		0xE12CA2289A63B962ULL,
		0x0A56FA74E9745114ULL,
		0x64440CD04E14B87AULL,
		0x36B5A6ECBF99AC60ULL
	}};
	t = 1;
	printf("Test Case 327\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 327 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -327;
	} else {
		printf("Test Case 327 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x817C21FB429827CBULL,
		0x97813C021060C1F0ULL,
		0x97D11D9DD068DD5FULL,
		0x9BE09F65B114C820ULL,
		0x22369FF8204C160FULL,
		0xAE685E05CA8C7395ULL,
		0x1328354416A8147BULL,
		0x7BD41637CD1F6176ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E72205960A48263ULL,
		0x7E8EB64F010FC9D1ULL,
		0xDB2D5D449AC29EFCULL,
		0x57CB3BE53A48E11FULL,
		0xF6033C50FFF6CF52ULL,
		0x0844B4E74FE205AFULL,
		0x360CCCC1C89B1292ULL,
		0x648CEE3290C0AAB6ULL
	}};
	t = 1;
	printf("Test Case 328\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 328 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -328;
	} else {
		printf("Test Case 328 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBEDFC0F21377D749ULL,
		0xAF2683F118F04632ULL,
		0xCA6A061ADCC4014BULL,
		0xD89DE67F8318D589ULL,
		0xE17250B3E1657959ULL,
		0x4ECFDE094B7F3385ULL,
		0x1F330DD44EC643EBULL,
		0x57749673EFF32EB3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBEDFC0F21377D749ULL,
		0xAF2683F118F04632ULL,
		0xCA6A061ADCC4014BULL,
		0xD89DE67F8318D589ULL,
		0xE17250B3E1657959ULL,
		0x4ECFDE094B7F3385ULL,
		0x1F330DD44EC643EBULL,
		0x57749673EFF32EB3ULL
	}};
	t = 0;
	printf("Test Case 329\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 329 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -329;
	} else {
		printf("Test Case 329 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC98B0A7E2C1A6C69ULL,
		0x44DDCD3A7F1C2AB2ULL,
		0x21CDA05EB374B35DULL,
		0xAC331043551B7559ULL,
		0xD232444C181733ECULL,
		0x25BFB26EF8DB4492ULL,
		0xEE537E4E29DC0A1BULL,
		0x74757E2B20E03C67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2518421157529E7ULL,
		0x4167B9C99A930F00ULL,
		0xD279145E375526FCULL,
		0xC0E675A5D12E24EAULL,
		0xF2DD0990D18DD593ULL,
		0x6E33FAFDC8396AB0ULL,
		0xE2953A601B7F845DULL,
		0x10093CAFABFDA0C6ULL
	}};
	t = 1;
	printf("Test Case 330\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 330 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -330;
	} else {
		printf("Test Case 330 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF6BF04B2A59F42C1ULL,
		0x20AAA21A6E773347ULL,
		0x7E92C22CE3F0BEEDULL,
		0xF58FDA912132624AULL,
		0x92452C72DC5E1FEFULL,
		0xEBA661F891173347ULL,
		0xC478839C8A2D5695ULL,
		0x04F743152413611BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5A3BFAC38D4216EULL,
		0x2780772EA0638179ULL,
		0x44D86F446E52812EULL,
		0x79A26B9FF4DAEA4DULL,
		0x087187D0F36FCCFBULL,
		0x58460D181E32504CULL,
		0x4B73D7802B3864C7ULL,
		0x384FE6A294B8C672ULL
	}};
	t = -1;
	printf("Test Case 331\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 331 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -331;
	} else {
		printf("Test Case 331 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x89DFB151328E0302ULL,
		0xEDA11B9866579DD5ULL,
		0x893D6EC06055DA87ULL,
		0xFEE60D9D027542C9ULL,
		0xDC67F414137EA6D0ULL,
		0x65E75A479D67D9E9ULL,
		0x9AC966A35CE1E9B9ULL,
		0xDE40919CCE16A0A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x895748F94955B7D1ULL,
		0xF6E598B4D003F781ULL,
		0x9ADE69EC4FDF296CULL,
		0x87E83C11163D3E58ULL,
		0x99259DA0728BD55CULL,
		0x38819982DB260BEBULL,
		0xD9D1419C2104ADCCULL,
		0x4BA91873FD74F7FAULL
	}};
	t = 1;
	printf("Test Case 332\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 332 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -332;
	} else {
		printf("Test Case 332 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF35CAFADD1F5B208ULL,
		0xFFE621C0CCB42CB2ULL,
		0x3A0281E7537F706CULL,
		0x415ED4547700F0B0ULL,
		0x7C1FD74BEEAC8791ULL,
		0x5F130EE072689BACULL,
		0xD11A38AAB3EEDE46ULL,
		0xE0572177303C4843ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF35CAFADD1F5B208ULL,
		0xFFE621C0CCB42CB2ULL,
		0x3A0281E7537F706CULL,
		0x415ED4547700F0B0ULL,
		0x7C1FD74BEEAC8791ULL,
		0x5F130EE072689BACULL,
		0xD11A38AAB3EEDE46ULL,
		0xE0572177303C4843ULL
	}};
	t = 0;
	printf("Test Case 333\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 333 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -333;
	} else {
		printf("Test Case 333 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3DFA07C53BE8EDC6ULL,
		0xF55AF3E404E5C70EULL,
		0x25B51044CEEEBEEDULL,
		0x96962070DCBAB7A8ULL,
		0xB0D6B924187BA6E8ULL,
		0xF6DEF78783EAB6A6ULL,
		0x1887B261D91F4DA9ULL,
		0xD7B78A667ED28D59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2AA343E9B7FA1CC4ULL,
		0x575B899A28E77F93ULL,
		0xD6B34F5C18AB5FC1ULL,
		0x96B5B51EA91B5581ULL,
		0xC78A22413B714E41ULL,
		0x6BA2D0FC14BA2A6DULL,
		0xB9DA2051C5534E1AULL,
		0x03025318AE386953ULL
	}};
	t = 1;
	printf("Test Case 334\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 334 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -334;
	} else {
		printf("Test Case 334 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x73827037EFB28456ULL,
		0x7B290FBA544282E0ULL,
		0x3C3E207ACF4055D2ULL,
		0xE776C7801E810406ULL,
		0x482A59B5A325F390ULL,
		0x90915017EDA88660ULL,
		0xD6F849A83445C1BFULL,
		0x12871FD2262419A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15F6C81BB5197B45ULL,
		0x1A25C121C16BCF4FULL,
		0xB3491DECFC0A2C59ULL,
		0x94F7DD3244FDEC47ULL,
		0x396685E158F7218FULL,
		0x1C21C47717838012ULL,
		0x5B3D748F023AE454ULL,
		0xFFBBE71C4DB2865BULL
	}};
	t = -1;
	printf("Test Case 335\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 335 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -335;
	} else {
		printf("Test Case 335 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x788B02638EA3FEA1ULL,
		0xD71E9E4D7745190CULL,
		0xF91403579E621A5CULL,
		0x970C679D0F8BF815ULL,
		0x24DDD6479E0E27EEULL,
		0x81EDB34918EDA307ULL,
		0x70FD7118C1C63E7BULL,
		0xECE0A0071737019BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCEFA4E7511AE3AAULL,
		0x9F406768295D6801ULL,
		0xABF8795103BC7F5FULL,
		0xC4AE64A89DFFF04EULL,
		0x3D4488825B92CFB8ULL,
		0xEF3DBC9A9206540AULL,
		0xCD483031C137D74EULL,
		0xEB14251353886990ULL
	}};
	t = 1;
	printf("Test Case 336\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 336 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -336;
	} else {
		printf("Test Case 336 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x173178DA2AA9259AULL,
		0x73D61656C36BECF8ULL,
		0x6C057CE1FE9976DAULL,
		0x4BC687E763D513BDULL,
		0xC2DD03C971AE6283ULL,
		0x8EC9AB07520CAF54ULL,
		0x1E67EED79B33E8DDULL,
		0x169CF313514BEA83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x173178DA2AA9259AULL,
		0x73D61656C36BECF8ULL,
		0x6C057CE1FE9976DAULL,
		0x4BC687E763D513BDULL,
		0xC2DD03C971AE6283ULL,
		0x8EC9AB07520CAF54ULL,
		0x1E67EED79B33E8DDULL,
		0x169CF313514BEA83ULL
	}};
	t = 0;
	printf("Test Case 337\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 337 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -337;
	} else {
		printf("Test Case 337 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF24964E9076E0D6EULL,
		0xD8C3C7A07BB043D5ULL,
		0x1AF113432CB830CCULL,
		0x504F74BF34F77923ULL,
		0x1A98C8834DE95E88ULL,
		0xEF5C6EDD283971E8ULL,
		0x44D578F3E314C1CEULL,
		0x875ECB951550ED6FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56D25EDAD6C0451FULL,
		0x722CBEA5E23AF286ULL,
		0x6B0B73F3243896DFULL,
		0x99AF42FBAD77329AULL,
		0x626125D67081C033ULL,
		0x501B4CE62D9900C8ULL,
		0xA0D8D817113DB7D8ULL,
		0xD7549A6F46BDF6F4ULL
	}};
	t = -1;
	printf("Test Case 338\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 338 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -338;
	} else {
		printf("Test Case 338 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4162ADDA90B5FC4AULL,
		0x077234A4C87BB5A4ULL,
		0x3D42E93000A4E4EEULL,
		0x8561C6121ED5759FULL,
		0xCDD1688523EFAD00ULL,
		0x360882B462191CFCULL,
		0xBB76A2BE9582878AULL,
		0xDC6EF2941911D9E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB299C460B3278FE7ULL,
		0xD5509177DDCCC8D4ULL,
		0x18F2A8EEE63C066AULL,
		0xABB1AECA06CB1C61ULL,
		0x5190AB2DC7128A16ULL,
		0x8398ED5B4FD1BB06ULL,
		0xC738FBCFBA633AB5ULL,
		0xF18431D236472937ULL
	}};
	t = -1;
	printf("Test Case 339\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 339 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -339;
	} else {
		printf("Test Case 339 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5DB1B36E85A1B0AFULL,
		0x9363F2A825113DADULL,
		0xCE33BEDED6C360DEULL,
		0x9BCC2E9828271150ULL,
		0xFB80E6E74D7FE69DULL,
		0x6825F740C47B88BDULL,
		0xB11E54319BF5A5FEULL,
		0x458750F2BC922A4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB04DD4CFB13E342AULL,
		0xA7034007A173F551ULL,
		0x9DB7696B431A0D79ULL,
		0x8C33283D426B0A70ULL,
		0x7A071AB53398E758ULL,
		0x56E9CA2C4B456402ULL,
		0xE7F6F88CA22512ADULL,
		0x8D56C5C1FA9078FCULL
	}};
	t = -1;
	printf("Test Case 340\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 340 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -340;
	} else {
		printf("Test Case 340 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB152FE0612F20AA9ULL,
		0xEF2E2B1828098427ULL,
		0x36A1FE5842F7FBDEULL,
		0x942620D6F8D1E1DDULL,
		0xE99F0C6D99F70EE0ULL,
		0xC6366624C580A882ULL,
		0x7BC6B71704860741ULL,
		0x5AC6B195D965C81EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB152FE0612F20AA9ULL,
		0xEF2E2B1828098427ULL,
		0x36A1FE5842F7FBDEULL,
		0x942620D6F8D1E1DDULL,
		0xE99F0C6D99F70EE0ULL,
		0xC6366624C580A882ULL,
		0x7BC6B71704860741ULL,
		0x5AC6B195D965C81EULL
	}};
	t = 0;
	printf("Test Case 341\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 341 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -341;
	} else {
		printf("Test Case 341 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAB4FCF1918F86160ULL,
		0x9BFEA1FEA6FF56BDULL,
		0x47B863B57E8F7360ULL,
		0xB91BA567902DA3FDULL,
		0x11A375D8FD1792BCULL,
		0x4157EAC28B792FE9ULL,
		0x8B6D8F114F69B90BULL,
		0x4FD3F0B516ED6C75ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC49B32BA57516707ULL,
		0xAF00BBF5923A8AB3ULL,
		0xFDB0BF430BDFDED8ULL,
		0x62D1CBEC0899BF5DULL,
		0x49E46215156376D8ULL,
		0x7B1A0C2CD19BBAA5ULL,
		0x530D132A964437BBULL,
		0x0D6AEB9B03836179ULL
	}};
	t = 1;
	printf("Test Case 342\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 342 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -342;
	} else {
		printf("Test Case 342 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6009B252AC97739FULL,
		0x93F8F2D9141957BDULL,
		0xE82DB9A31E9768E8ULL,
		0x29970ACC1B558C24ULL,
		0xB802C9AC4B3872E8ULL,
		0x4EEEE5EC4D4E77DFULL,
		0xD977B70E3719F4EEULL,
		0x20B01BDF0985002DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x548B3996E4F21296ULL,
		0x6A8453C4EDFF9DB3ULL,
		0x0C8E138E4F05F379ULL,
		0xF6F1AA2CE3DA1A0BULL,
		0xE35212461CEDC621ULL,
		0xE2582564818046BCULL,
		0xDF13784335E8C66BULL,
		0x53CC90A88BF88B50ULL
	}};
	t = -1;
	printf("Test Case 343\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 343 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -343;
	} else {
		printf("Test Case 343 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xABED5501F7A34D9BULL,
		0x91BD026090406A28ULL,
		0x148FE97AE7CF341CULL,
		0x8AEE9ECEAABFFA36ULL,
		0x1E4E8DF97E222DE0ULL,
		0xEB6391B7AE410272ULL,
		0x0A4046ACCBB8310FULL,
		0xF67EF004AC80072FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x628FFA2E22F36A21ULL,
		0x9697BC93691E7A34ULL,
		0x0D440A78FF5E8561ULL,
		0x7CC7E1981A7297D4ULL,
		0x6CCAA6077C89385EULL,
		0x6A8182C7150A99D7ULL,
		0x37C1DC8CB57409F5ULL,
		0x663ED7B98945827FULL
	}};
	t = 1;
	printf("Test Case 344\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 344 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -344;
	} else {
		printf("Test Case 344 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x74865A71AA1D268AULL,
		0x1052316C008EEC92ULL,
		0xAB9D619DF72C369BULL,
		0x6504BDEFD6C24775ULL,
		0x69D7A36BCA068871ULL,
		0xEC062F74C3FAC509ULL,
		0xCFAD807B7D254ECEULL,
		0xD3A45B4BBF05077FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74865A71AA1D268AULL,
		0x1052316C008EEC92ULL,
		0xAB9D619DF72C369BULL,
		0x6504BDEFD6C24775ULL,
		0x69D7A36BCA068871ULL,
		0xEC062F74C3FAC509ULL,
		0xCFAD807B7D254ECEULL,
		0xD3A45B4BBF05077FULL
	}};
	t = 0;
	printf("Test Case 345\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 345 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -345;
	} else {
		printf("Test Case 345 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x98DE857DDB07E37DULL,
		0xC0D0A5A783ACCE0AULL,
		0x0B045FD453043BCCULL,
		0x028617F03E9AD701ULL,
		0x5E4C4FA0F9944434ULL,
		0x6995608238EF88A3ULL,
		0xD21272DD22F31ECFULL,
		0x87C7700940D24127ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA18C8D8E9620F81EULL,
		0xFB2C808EF68CDAF4ULL,
		0x2E127EAA7DBF087DULL,
		0xD7535803B7FFA71DULL,
		0xE101A60B8410C989ULL,
		0x18E99E6725969EADULL,
		0xAC4981FFF1E009E9ULL,
		0xEAE7BD772FC7DE44ULL
	}};
	t = -1;
	printf("Test Case 346\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 346 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -346;
	} else {
		printf("Test Case 346 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD0526CCFFF69D30FULL,
		0x299836DFBD03ED6AULL,
		0x05C0465DEF60C70FULL,
		0x8FBB10B40E13B944ULL,
		0x8300AB34F4DFC594ULL,
		0xE5A511DDCA7D5EC4ULL,
		0x5379D8779C1570EBULL,
		0xE3370C71D74D7D7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FAA0C7710991582ULL,
		0x80BEE8E1B73D982DULL,
		0x104747279520ACA9ULL,
		0x043316BDC2FC40F6ULL,
		0x147072ED5986BBD4ULL,
		0x82E897ACDEED96CCULL,
		0x42D13676B47D8525ULL,
		0x2782BB285DE62947ULL
	}};
	t = 1;
	printf("Test Case 347\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 347 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -347;
	} else {
		printf("Test Case 347 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5AD1D0A5BB64A10AULL,
		0xA27B759B4382DB82ULL,
		0x2B6B5EDE5EC8F09DULL,
		0x5F070F73BF58A12FULL,
		0xF39EEA42B052C023ULL,
		0xC91A27C1D6A3A762ULL,
		0x6C2C34996B039A57ULL,
		0xAF2C8BE2A413C7C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x335C7A09D270A6EAULL,
		0x822698FE0A39BFD4ULL,
		0x5515304918C4D798ULL,
		0x713CCD7F6FD8B4FCULL,
		0x7A5C283928767B92ULL,
		0x5E975C02979E8FF8ULL,
		0x1EBD3ADD8AD1EC88ULL,
		0xBCB8A58450F44167ULL
	}};
	t = -1;
	printf("Test Case 348\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 348 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -348;
	} else {
		printf("Test Case 348 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x36E1D6C55BB0F761ULL,
		0x9666ADC3D209CDCCULL,
		0x5BE5F842B7D10677ULL,
		0x37741346DFCA4BA0ULL,
		0x91C0D81028965723ULL,
		0x631BA739DCBC59B7ULL,
		0x90B6850181218649ULL,
		0xEB1F477912EA3F02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36E1D6C55BB0F761ULL,
		0x9666ADC3D209CDCCULL,
		0x5BE5F842B7D10677ULL,
		0x37741346DFCA4BA0ULL,
		0x91C0D81028965723ULL,
		0x631BA739DCBC59B7ULL,
		0x90B6850181218649ULL,
		0xEB1F477912EA3F02ULL
	}};
	t = 0;
	printf("Test Case 349\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 349 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -349;
	} else {
		printf("Test Case 349 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB579B1150322DE3BULL,
		0xF6B04D8B3DD88236ULL,
		0xAF267962CF0539F1ULL,
		0xEFCA0D0E412E81A2ULL,
		0xBB2E25E56E1A6B7DULL,
		0x055780B2D0BD6D37ULL,
		0x711144DDD0694394ULL,
		0x493D37346656AF9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83D7571D09B77AF0ULL,
		0xC3367C2F41DC8FD5ULL,
		0x5E22508E89400020ULL,
		0x5C0B0A8FCD102011ULL,
		0x8C99CADACBCEBEEFULL,
		0xC7AE4F7EB7ACF3B3ULL,
		0xCD4EC4408D3E701CULL,
		0x244B7427982447A6ULL
	}};
	t = 1;
	printf("Test Case 350\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 350 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -350;
	} else {
		printf("Test Case 350 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x96ECF5AC07CC6B5FULL,
		0x7CC3DBD78267AA25ULL,
		0xC7C968B708D75E76ULL,
		0x2B5F22614B9153D0ULL,
		0xF191625479A641D6ULL,
		0x71B43941EBC83E0AULL,
		0x11280906AED5C338ULL,
		0x98CABF0A6DD24803ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB89C054187D93090ULL,
		0x0595A6316E0DAF29ULL,
		0xD9AE377BDBF5A6BEULL,
		0x6C18D1778EF27FD1ULL,
		0xF4D8AA6F47DE9818ULL,
		0xCDEBEB069476E2E2ULL,
		0xED6E53D6A1AA1117ULL,
		0xB8C7B95B621F07AFULL
	}};
	t = -1;
	printf("Test Case 351\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 351 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -351;
	} else {
		printf("Test Case 351 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x41D411DBD65EADF4ULL,
		0x1C0DAB33A17D55AFULL,
		0x2D2535A1B72C5D1BULL,
		0x1C6235398ED9B68AULL,
		0x27B0FD8D96FB8AC8ULL,
		0xAAC8BC4A105F6994ULL,
		0xD71945FD50C28D7EULL,
		0x6ED05E1992CC31BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6AE25630AD7B6032ULL,
		0xE40B4BEE9024CC52ULL,
		0xAC94BF3DB7D71F65ULL,
		0x25A5C3639C8A6180ULL,
		0xFE901BC2EAE484B0ULL,
		0x22AD2A5B1F4514DEULL,
		0xDE59D53CCA72E0FFULL,
		0x48EABDC7E6649CF5ULL
	}};
	t = 1;
	printf("Test Case 352\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 352 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -352;
	} else {
		printf("Test Case 352 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x03CD9F3B0E014D44ULL,
		0x8DB8EDD31033CB64ULL,
		0x309F5FFA924C65AAULL,
		0x775FE73E8BC2CB1FULL,
		0x5730144943C54B17ULL,
		0x8B7C0E25AA8A2E6DULL,
		0x6DE109CFAEEA7FD1ULL,
		0x6946AE94766FCF8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03CD9F3B0E014D44ULL,
		0x8DB8EDD31033CB64ULL,
		0x309F5FFA924C65AAULL,
		0x775FE73E8BC2CB1FULL,
		0x5730144943C54B17ULL,
		0x8B7C0E25AA8A2E6DULL,
		0x6DE109CFAEEA7FD1ULL,
		0x6946AE94766FCF8AULL
	}};
	t = 0;
	printf("Test Case 353\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 353 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -353;
	} else {
		printf("Test Case 353 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x475C163784925F29ULL,
		0xE359F57F99E97E92ULL,
		0xB6E2D4F8BCA5F68AULL,
		0x5B729A4CF586C541ULL,
		0x2794D44454ED1307ULL,
		0x34AD1BAFD74AB3CBULL,
		0x94547D60F0A14C46ULL,
		0x511A70F57317BCD4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97F05AAD93D81EBDULL,
		0xC5FEC61332A7ECADULL,
		0x709B94DEB72A58ADULL,
		0x399C1E6A0C3D54E6ULL,
		0xE6DD82B2E83AC46EULL,
		0xEA708DB72CA05F09ULL,
		0x49FFB31CB453616EULL,
		0xC42EC7B9E1757E32ULL
	}};
	t = -1;
	printf("Test Case 354\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 354 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -354;
	} else {
		printf("Test Case 354 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2C637AA5E2D12145ULL,
		0xD42A12FDB207C0D4ULL,
		0x80CA49EC84A7E76EULL,
		0x19471627597443D6ULL,
		0xF6DAD87F2CD9A3A7ULL,
		0x8E145C1612E5553DULL,
		0xE8185ADE4D1864C3ULL,
		0x9AF828EDFF09FABCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF0B87625DF3868EULL,
		0x046529C4FB71ABB0ULL,
		0x12BCCC871D07FEDFULL,
		0x61CD25E5D5FDB9A7ULL,
		0xE314DD18EF45AD65ULL,
		0x1957705FFA39BFEEULL,
		0xD7C00844D0FE088BULL,
		0xBF4A3651240FB7B2ULL
	}};
	t = -1;
	printf("Test Case 355\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 355 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -355;
	} else {
		printf("Test Case 355 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3F982B5ED657B609ULL,
		0x95658CCC263C8F79ULL,
		0x913F89E636C1B267ULL,
		0x692329255DE6C8D2ULL,
		0xAA776935E3FC5BB3ULL,
		0xC2162961F18606C8ULL,
		0x71287F0F6535F6AEULL,
		0x8293A9EAE1CA0604ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC00E67837A3310DAULL,
		0xEE7E9CCCF710536EULL,
		0x3E9BA2536709F0B7ULL,
		0x0CEB545560CB299FULL,
		0xB5DB13F35089D8F6ULL,
		0xD16B9652CC557427ULL,
		0x9934827AC62BBCDDULL,
		0x05ECA9AB67B235ECULL
	}};
	t = 1;
	printf("Test Case 356\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 356 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -356;
	} else {
		printf("Test Case 356 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6980EEB43EEC1296ULL,
		0x689107C8DDD08EC7ULL,
		0x69E5EF1DDB55434BULL,
		0xEA4D17D3F7B8E85AULL,
		0x3A6FD9BDC64D38C7ULL,
		0x412E8012F16A9E9BULL,
		0x4BF54131A00FD1D5ULL,
		0x45B0A6E182F33B88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6980EEB43EEC1296ULL,
		0x689107C8DDD08EC7ULL,
		0x69E5EF1DDB55434BULL,
		0xEA4D17D3F7B8E85AULL,
		0x3A6FD9BDC64D38C7ULL,
		0x412E8012F16A9E9BULL,
		0x4BF54131A00FD1D5ULL,
		0x45B0A6E182F33B88ULL
	}};
	t = 0;
	printf("Test Case 357\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 357 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -357;
	} else {
		printf("Test Case 357 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x051CD0A54CFC981BULL,
		0x5449B15F553C30EDULL,
		0xBE3F78109CE72FF6ULL,
		0xE5F9AFF48327A72FULL,
		0xA92E872840BA864CULL,
		0x8A75E129CCF08FFAULL,
		0x02655645EBDD3497ULL,
		0x3AEC33C58DDFE84FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E3BF7A4A0DCCE73ULL,
		0x82DA5273D2683E57ULL,
		0x17A0D59E1E12929BULL,
		0xD651FEA318CAD70AULL,
		0xF4B2FFFCC478C1B6ULL,
		0x24503C476AE40F9AULL,
		0xC33B85698D0E1FA2ULL,
		0x12D8A5DCEF9A15D4ULL
	}};
	t = 1;
	printf("Test Case 358\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 358 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -358;
	} else {
		printf("Test Case 358 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x36AA2491B36181B6ULL,
		0xA9F421E50C17EEBEULL,
		0x49FEB5A6F4EC8A35ULL,
		0xA57B70E7CFB4544EULL,
		0x92F88C32A7D738F9ULL,
		0x9A532AB44126DCBFULL,
		0x0485D771930695E0ULL,
		0xA8532A799CF32E94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x556C826331A9AED0ULL,
		0x51547947534A730EULL,
		0x2DA11ADF5C821CC8ULL,
		0xE4A881DBCE20A8D8ULL,
		0x117DD6ECC237E956ULL,
		0x52660BD1A09D64C9ULL,
		0xD00B88B00C57D381ULL,
		0x9876C10CE792FF1DULL
	}};
	t = 1;
	printf("Test Case 359\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 359 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -359;
	} else {
		printf("Test Case 359 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAAE9D559EFEFC576ULL,
		0x5F0DF27104079E96ULL,
		0x5406EC0A7238D8BCULL,
		0xD9A7B30F705C4BA3ULL,
		0x6DDEB6C50B039CCAULL,
		0x37A931CBF507CA9AULL,
		0x544F25B511031B4DULL,
		0x4E6901471F4F8A9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E32989B498E29E4ULL,
		0xD560E9E3ACAA89BAULL,
		0xFE0E400549A15BA2ULL,
		0x344242AA6E728379ULL,
		0x7AB368061E70A19AULL,
		0x2E5D8BFA93F608FEULL,
		0x341E8D53BF25F8B4ULL,
		0x4E9BB0CE09D0CCA4ULL
	}};
	t = -1;
	printf("Test Case 360\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 360 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -360;
	} else {
		printf("Test Case 360 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x88B27D3C733BC6DEULL,
		0x90F26D9FEF557CA6ULL,
		0xBB73A5EAD9F79188ULL,
		0x46B03B3E38C9548EULL,
		0x444978E96C799277ULL,
		0x4E802CE845E0F9FEULL,
		0xEE227F873EA6C780ULL,
		0xB51819DCAD311D87ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88B27D3C733BC6DEULL,
		0x90F26D9FEF557CA6ULL,
		0xBB73A5EAD9F79188ULL,
		0x46B03B3E38C9548EULL,
		0x444978E96C799277ULL,
		0x4E802CE845E0F9FEULL,
		0xEE227F873EA6C780ULL,
		0xB51819DCAD311D87ULL
	}};
	t = 0;
	printf("Test Case 361\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 361 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -361;
	} else {
		printf("Test Case 361 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA2DF1486A490B9C0ULL,
		0x1A420DFF2F044D60ULL,
		0x12354AA56F55D6F6ULL,
		0x74BE02A8B6E962A8ULL,
		0xD0E4635ADEB6AA0CULL,
		0x09247E0485ADD5A1ULL,
		0x3898AB2EA77417A0ULL,
		0x98BDD1775F330C7FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0714CFF23AD7C52ULL,
		0x23335FD8156549D9ULL,
		0x7ADD52E31592D559ULL,
		0x60CAD83F860E814AULL,
		0x6DFB84E05FA3105FULL,
		0xB06CDB7205577228ULL,
		0x36FA1CF8345B5CA2ULL,
		0xF2EAA81233632FEBULL
	}};
	t = -1;
	printf("Test Case 362\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 362 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -362;
	} else {
		printf("Test Case 362 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x946179CF623A9E60ULL,
		0x8746AB58B0036871ULL,
		0x6AE345392F7E2E71ULL,
		0xE654F7068E0925DFULL,
		0xA09C24AB11F74D54ULL,
		0x62B1AF618FE6B7A4ULL,
		0x22BEDA181A9A7644ULL,
		0xB2B792FEB38443E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DFC0E15EF274EB8ULL,
		0x6437C86C3A8BE062ULL,
		0xA4D3AB92DFEFA217ULL,
		0x1998EE2741210128ULL,
		0x6E0613142C5EFB57ULL,
		0xCD7DA63B3136221CULL,
		0x964655648B79E60CULL,
		0xF278D08E5B8296E5ULL
	}};
	t = -1;
	printf("Test Case 363\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 363 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -363;
	} else {
		printf("Test Case 363 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3A66FB2962EA4C8BULL,
		0xD1011EBC16D7F937ULL,
		0x5810ABC63F826B54ULL,
		0xC7857DADDF1732D5ULL,
		0x3FBC3BC9C07D8E68ULL,
		0xD4184C8F8C43DBA7ULL,
		0xCBF5C1C52ABA26D2ULL,
		0x71C9E5E52F5207B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6512EAF5E1191945ULL,
		0x6D7F065D867ADCCEULL,
		0xDD67D936FA24F558ULL,
		0x1D0E38ABED976F84ULL,
		0x16E96393EB82CE59ULL,
		0xA93069ED030E282EULL,
		0xFEC30B850C9D236FULL,
		0x36125314687171E0ULL
	}};
	t = 1;
	printf("Test Case 364\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 364 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -364;
	} else {
		printf("Test Case 364 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x36847CE00275822DULL,
		0x604588930457E72BULL,
		0xB461970FDFB6800DULL,
		0x36DE91C0D49AED42ULL,
		0x4021267C065F0471ULL,
		0x0FDD44A69C7F9DD2ULL,
		0xAA4973F8F8A83EDFULL,
		0x27593E7C1D1FE6E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36847CE00275822DULL,
		0x604588930457E72BULL,
		0xB461970FDFB6800DULL,
		0x36DE91C0D49AED42ULL,
		0x4021267C065F0471ULL,
		0x0FDD44A69C7F9DD2ULL,
		0xAA4973F8F8A83EDFULL,
		0x27593E7C1D1FE6E8ULL
	}};
	t = 0;
	printf("Test Case 365\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 365 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -365;
	} else {
		printf("Test Case 365 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDB26CBD9E3FC86EEULL,
		0xEE7A59F9EB7DF5D7ULL,
		0xA1A5ED6A1C7A5D32ULL,
		0xC4602659B1A2C4DBULL,
		0x1D708E52B30C74FFULL,
		0xC99CA8AAC9A747F7ULL,
		0xDFC789D440D7748FULL,
		0x39A55C62C3F98EB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x518AF45FB45AC3EBULL,
		0xD746FCC09E26E0B1ULL,
		0x47D99B4A308DD1CDULL,
		0xF837C1747545BD6EULL,
		0x54C7D9C5553E3C02ULL,
		0x5ECBC9570A45033AULL,
		0x5A01F67A6CD32793ULL,
		0x48B5F62283D75DAAULL
	}};
	t = -1;
	printf("Test Case 366\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 366 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -366;
	} else {
		printf("Test Case 366 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x71CBADB33BEE2D8EULL,
		0x60E22F4CD3EA860CULL,
		0xA179BFAD3988C8D3ULL,
		0x5CE31DD96BB038C6ULL,
		0x6857E0DA56955E5FULL,
		0x0A5B4401DC29792EULL,
		0x443BF44A0CCE0D60ULL,
		0x66F71599CD6FB357ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBE35BCC7F0BE82CULL,
		0xCB83133084482944ULL,
		0xB908D7EE3581CC3CULL,
		0x62F0DFE4EC154767ULL,
		0xA46C9D5280503D80ULL,
		0xF9345DC0A02E2CB2ULL,
		0xFEB32045F0D339D7ULL,
		0x72E74A360F6C2EABULL
	}};
	t = -1;
	printf("Test Case 367\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 367 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -367;
	} else {
		printf("Test Case 367 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD035A5B9FFDDB14CULL,
		0xC5CE7EF98977E0CEULL,
		0x4CBBAC4765DBF6B3ULL,
		0x94C2DE2F74361FA0ULL,
		0x9597CF2CEECCE638ULL,
		0x4BBA9A35C8D643C2ULL,
		0xE2607CF83F93D4C5ULL,
		0x8952CBA917287513ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF4F16BD70CB0485ULL,
		0x78071E1D016B7107ULL,
		0x0090138154D1D3B2ULL,
		0xCD321706F266CC76ULL,
		0x7CE15797E0CF5CCCULL,
		0x6FCD5D2078B566B8ULL,
		0xB02148A7D94E65C9ULL,
		0x3A67F736147C7960ULL
	}};
	t = 1;
	printf("Test Case 368\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 368 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -368;
	} else {
		printf("Test Case 368 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBAFD23AC44C19F94ULL,
		0x3EBE27470533328EULL,
		0x8B727EE8A31269B2ULL,
		0x6763ED5815637432ULL,
		0x67D984FA7C1ECA0DULL,
		0x0EFEDE4FF337B0BAULL,
		0x5243E9A0EBD2D82FULL,
		0x87A81C198C39EF53ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBAFD23AC44C19F94ULL,
		0x3EBE27470533328EULL,
		0x8B727EE8A31269B2ULL,
		0x6763ED5815637432ULL,
		0x67D984FA7C1ECA0DULL,
		0x0EFEDE4FF337B0BAULL,
		0x5243E9A0EBD2D82FULL,
		0x87A81C198C39EF53ULL
	}};
	t = 0;
	printf("Test Case 369\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 369 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -369;
	} else {
		printf("Test Case 369 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0F40D2FBC7B1E35EULL,
		0xCC016D9F599B9C3FULL,
		0x8401CCD2CBA10C3CULL,
		0x5F36716DA37FB899ULL,
		0x307EA4278EA8F5D5ULL,
		0x1633C48571AB3DBAULL,
		0x2D8DE629ADD738B0ULL,
		0xBAC0974D6784A8BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DBF71716EA584D5ULL,
		0x1B11381DEC90AB8DULL,
		0x6F5E188DD98C2BA2ULL,
		0xBA5C0C2D05F8BC8DULL,
		0x7BF131E0B59AD991ULL,
		0x66271CCF0F4BB005ULL,
		0x291A706CF60EB7F9ULL,
		0x0843C2B875BE8897ULL
	}};
	t = 1;
	printf("Test Case 370\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 370 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -370;
	} else {
		printf("Test Case 370 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C4B848BD4DCDCB8ULL,
		0x906888CAD7975F5FULL,
		0xA3BA1653F7358CF5ULL,
		0xF1AE45E8B82B5D8EULL,
		0x976ECBBD9D40A57EULL,
		0xB03FF386A9CF9701ULL,
		0xA051C27E12B0058CULL,
		0xE1F0B5B80E043C74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x315D17874D6E8934ULL,
		0xC33CC8ED0F76F51BULL,
		0xCAA49D2EA2B27C69ULL,
		0x82BE6145BBDE02A5ULL,
		0xDB4A943264006056ULL,
		0xF900D7DE057E49CBULL,
		0x00F6B61F1AB62110ULL,
		0x32BBD050D3F6C983ULL
	}};
	t = 1;
	printf("Test Case 371\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 371 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -371;
	} else {
		printf("Test Case 371 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x330D27D2A18FCF5BULL,
		0x1C7D9E33FD2934E5ULL,
		0x70B0E6CCA0DBD25FULL,
		0xC1CC67E89CCC183AULL,
		0xFBF6DC69AB72F9A6ULL,
		0x9AE2B9D9938F3565ULL,
		0x99748C1BDAF49AFCULL,
		0x012A855A5BAB6335ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9A5AF97CF514478ULL,
		0x165DA5FB630A8203ULL,
		0xEA60638F8A4A9F5BULL,
		0x78E09EAC8185A586ULL,
		0x82F0CED422793B7AULL,
		0x33EB4BFE129534D1ULL,
		0x1401086FF6003CABULL,
		0x32839A37F680EC23ULL
	}};
	t = -1;
	printf("Test Case 372\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 372 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -372;
	} else {
		printf("Test Case 372 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6BB0E596D159F183ULL,
		0x74C582943C1BF399ULL,
		0xC2C056D16941D6CDULL,
		0xB661AB21C3F64EEDULL,
		0x8B5CE5A4CE964AC0ULL,
		0xF837B6F749CF9201ULL,
		0x82ED00116A75125AULL,
		0x0FFAC7F53CB2EF50ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6BB0E596D159F183ULL,
		0x74C582943C1BF399ULL,
		0xC2C056D16941D6CDULL,
		0xB661AB21C3F64EEDULL,
		0x8B5CE5A4CE964AC0ULL,
		0xF837B6F749CF9201ULL,
		0x82ED00116A75125AULL,
		0x0FFAC7F53CB2EF50ULL
	}};
	t = 0;
	printf("Test Case 373\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 373 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -373;
	} else {
		printf("Test Case 373 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x033D8C92CE604DC3ULL,
		0xAC2D9E4472640F69ULL,
		0x3BC44FB397106C79ULL,
		0xE0B04CE402AACBD1ULL,
		0x1777F0EE50B3EA54ULL,
		0x0462F05F54A32C9CULL,
		0xE2D2EC67F9506CEAULL,
		0x9688FB499B17E2C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2CB73D4D728F059ULL,
		0x5E26E7CDFA0F7C9CULL,
		0xA4159E1F75FEEC6DULL,
		0x6EEB0AEE227A69BCULL,
		0x964690318B622C99ULL,
		0x8AED45ADB31345DCULL,
		0x24D7B2B32FDB6E9AULL,
		0x34F6BCA7138981CFULL
	}};
	t = 1;
	printf("Test Case 374\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 374 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -374;
	} else {
		printf("Test Case 374 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x316267D770A4FD90ULL,
		0x989131D0B3FAFB5FULL,
		0x9000C1B6B2CE045AULL,
		0xD56C3CC421C069F8ULL,
		0xE102A25D9F2CBF0CULL,
		0xB09317BC2C269EDAULL,
		0x38C87994AFDF672DULL,
		0xB62D526435FDC9A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21FCD3145C07B874ULL,
		0x8EECB12769EF620CULL,
		0x1E4251D800C56E82ULL,
		0xFDA94C0397981045ULL,
		0xA9981AD4630BC2B3ULL,
		0x8A983C2154824498ULL,
		0x9D9F5D4948EBCF3EULL,
		0x510700393CF80983ULL
	}};
	t = 1;
	printf("Test Case 375\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 375 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -375;
	} else {
		printf("Test Case 375 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x619E7BCD4B19E8E0ULL,
		0x65419112FCA4E1EFULL,
		0x009E60CF9C8C3775ULL,
		0xB7383908FBAEA979ULL,
		0x7D7725EF1079F614ULL,
		0x9105BF327AD06D90ULL,
		0xCBAFB953EAE1CC74ULL,
		0x0782512254F61BB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99154DC9F789EB69ULL,
		0xE4F3CA611AF5337BULL,
		0xAC18F4B6094A1A33ULL,
		0xAEE21E6059896928ULL,
		0xA5F8DE67497868EFULL,
		0xD1C04377603D7996ULL,
		0x6BDCFFB319BACE7AULL,
		0xB9287E0EC5F6A28EULL
	}};
	t = -1;
	printf("Test Case 376\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 376 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -376;
	} else {
		printf("Test Case 376 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4EF50DFBFADC16C5ULL,
		0x2935009687D57B6EULL,
		0x284DF580F45D8106ULL,
		0xF73173BCE8BDEF33ULL,
		0x9A4421C85B3B3BE5ULL,
		0xDC765CDACA639CF8ULL,
		0xAE1231CFA6EE98C9ULL,
		0x5BCE2BE28E1E65FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EF50DFBFADC16C5ULL,
		0x2935009687D57B6EULL,
		0x284DF580F45D8106ULL,
		0xF73173BCE8BDEF33ULL,
		0x9A4421C85B3B3BE5ULL,
		0xDC765CDACA639CF8ULL,
		0xAE1231CFA6EE98C9ULL,
		0x5BCE2BE28E1E65FEULL
	}};
	t = 0;
	printf("Test Case 377\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 377 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -377;
	} else {
		printf("Test Case 377 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x52A195765A624F6EULL,
		0x04B712A423083501ULL,
		0x84D9BA5999EEF459ULL,
		0xCE09D2EE64B8E8ECULL,
		0xFC012ED5ADF095E0ULL,
		0x77F24CAB53DA031CULL,
		0xAB535976883A5F7BULL,
		0xFD6BB14DF2AC3E5EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF4E677291D2B643ULL,
		0xF1E669582CA33269ULL,
		0x47D49C228BB9EBDBULL,
		0xB947665B613F00F1ULL,
		0x13827349735C135FULL,
		0xFEACA3641815C9FFULL,
		0x172A74C344344CC5ULL,
		0xA7A126C1F6B06D44ULL
	}};
	t = 1;
	printf("Test Case 378\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 378 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -378;
	} else {
		printf("Test Case 378 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCBFE896F24FB6DC9ULL,
		0x75748791B44783E6ULL,
		0xC980F52ED7B0DBE6ULL,
		0x568182ADC1B83C33ULL,
		0x81E1808693CDEEC3ULL,
		0xF8D4200517750DE2ULL,
		0x69DA74CCCE2D23C6ULL,
		0xF0906E63B97DA6F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13F02E61FF5232A3ULL,
		0xE039213BBF77E1DDULL,
		0x2A09D6995C4496AAULL,
		0xF7B69AE8D1670F06ULL,
		0xDFD21D3E0CC6B536ULL,
		0xCC63EE3A68262CCDULL,
		0x2299AF74A72E7670ULL,
		0x50B39C4DA565273AULL
	}};
	t = 1;
	printf("Test Case 379\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 379 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -379;
	} else {
		printf("Test Case 379 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x82D6513732E73B9DULL,
		0x3098EB84CA6DC691ULL,
		0x27B7D422C2CFE5A2ULL,
		0x8412A77098864AF8ULL,
		0xADF94FA55269B039ULL,
		0xA134EF7BB07B8E7EULL,
		0x1D466985ECAC9515ULL,
		0xB11C1C706D54D828ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB07321809594128ULL,
		0x1405CA75115D95B8ULL,
		0xA51F391B0B558A48ULL,
		0xC39D89117B062C72ULL,
		0xC2ADF839C9E00671ULL,
		0x526BBBF2E1EE240DULL,
		0x574F598744070122ULL,
		0xFEC90B34B908073CULL
	}};
	t = -1;
	printf("Test Case 380\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 380 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -380;
	} else {
		printf("Test Case 380 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCFADDCFCD5BC86ADULL,
		0x3C7F9194DFE5402CULL,
		0x8425801F625421AEULL,
		0x54B837E56A0D718DULL,
		0x1A7B78102127EC22ULL,
		0xF150C5223D7A116CULL,
		0x15FB78362122AF6CULL,
		0x3639DEFE7087D49BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFADDCFCD5BC86ADULL,
		0x3C7F9194DFE5402CULL,
		0x8425801F625421AEULL,
		0x54B837E56A0D718DULL,
		0x1A7B78102127EC22ULL,
		0xF150C5223D7A116CULL,
		0x15FB78362122AF6CULL,
		0x3639DEFE7087D49BULL
	}};
	t = 0;
	printf("Test Case 381\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 381 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -381;
	} else {
		printf("Test Case 381 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x378EDBC79400E37EULL,
		0xD35F457951F24B6CULL,
		0xA275BF188013F8A1ULL,
		0xEDF2DD8EAB557C67ULL,
		0x05E6A40FFABDA41FULL,
		0xF5AC60762F7A01B5ULL,
		0x494B7AD8F821287FULL,
		0x798CFD070E765A51ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFEFBC102B8FC6EEULL,
		0x6349CCF0F00406EAULL,
		0x1D611C08A73F1D24ULL,
		0x15237266AF90DAF1ULL,
		0x88DE68FA59376743ULL,
		0xD6393A473BF0F733ULL,
		0x344A0B6E7D124B6DULL,
		0x7663D32D1735F0A3ULL
	}};
	t = 1;
	printf("Test Case 382\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 382 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -382;
	} else {
		printf("Test Case 382 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA237E950EFBEC6BDULL,
		0x0E774A4D242358C9ULL,
		0xF43C337975269630ULL,
		0xB58C805C7EAFD389ULL,
		0xE5A38D921FA5B342ULL,
		0x4989368154384733ULL,
		0x6937DD625F7EDD1EULL,
		0x1F10F750E107D13AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FC80AF329109724ULL,
		0x5A720A04FF35C771ULL,
		0xD6FAC6F0424F557EULL,
		0x839C0F34E0B5A91FULL,
		0x00778ECC3C8FC300ULL,
		0xE0359CCB564B8987ULL,
		0x16918F0490A9B3E6ULL,
		0xFDF9D2621673CB90ULL
	}};
	t = -1;
	printf("Test Case 383\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 383 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -383;
	} else {
		printf("Test Case 383 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x217DB104B7C9FD2EULL,
		0xF18ABF90FB5DA092ULL,
		0xB4A8551F9A50E16EULL,
		0x5E49C65E2F4361D9ULL,
		0xA19668257AA1DD36ULL,
		0x401E0AABE620BF66ULL,
		0x310ADE70C22183FDULL,
		0x6C3960E222C75CEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x682FCFB883A9F79BULL,
		0x7F96ACDCA4D4E0C0ULL,
		0xA42E37701D5EE535ULL,
		0x284A754BC57B429EULL,
		0x5A6E20D28ABF57BFULL,
		0x8046974B84087DCBULL,
		0x828259F203C1342CULL,
		0x26C855984B2F4AB7ULL
	}};
	t = 1;
	printf("Test Case 384\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 384 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -384;
	} else {
		printf("Test Case 384 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE0289D7B80E9BC59ULL,
		0x9D74917C4E9F9543ULL,
		0x073B955F806B27B3ULL,
		0x7DB7220F2DCE25B2ULL,
		0x579E075FBD07A791ULL,
		0x0FDB92A3BE15EEE0ULL,
		0x120DF0D39E4D7321ULL,
		0x8C8E14D50EA9C3E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0289D7B80E9BC59ULL,
		0x9D74917C4E9F9543ULL,
		0x073B955F806B27B3ULL,
		0x7DB7220F2DCE25B2ULL,
		0x579E075FBD07A791ULL,
		0x0FDB92A3BE15EEE0ULL,
		0x120DF0D39E4D7321ULL,
		0x8C8E14D50EA9C3E9ULL
	}};
	t = 0;
	printf("Test Case 385\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 385 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -385;
	} else {
		printf("Test Case 385 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0D177C31DADDCFA9ULL,
		0x17F6F67D1033DEA4ULL,
		0x5690468C509292A3ULL,
		0xDABCBD437AC90782ULL,
		0x9C6D361A81F3E901ULL,
		0x6C4746B2627F79A0ULL,
		0xC9C62468D73A8C84ULL,
		0x644765A63E781720ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5455F9474B282199ULL,
		0x218A6A0DC8FBF38AULL,
		0x05E7D6EC119F6C8AULL,
		0xDE606F5E05E2857DULL,
		0x54F755394DF923C2ULL,
		0xECE06B9F5CF9C3F9ULL,
		0xA2A70A220B7E8BB7ULL,
		0x41F518F8E99B6856ULL
	}};
	t = 1;
	printf("Test Case 386\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 386 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -386;
	} else {
		printf("Test Case 386 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7A0E014BCD62BE59ULL,
		0xD71AB74CF9598796ULL,
		0x92A2A35A70597842ULL,
		0x594F7DC1D04B3155ULL,
		0xDA3D544AA1B19FC7ULL,
		0xFE7F944410B1F2DEULL,
		0x85CBC9AAD49D5301ULL,
		0x940440A27029A4F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04ACF29638D61072ULL,
		0xCC27D6D51A86A49AULL,
		0x7DE78680BBE095D5ULL,
		0x0969A4C28C142177ULL,
		0xD607B7403E7EDAA7ULL,
		0xA38B993B44192D14ULL,
		0x29463A0B0712262FULL,
		0x3D8D9EDB26558F43ULL
	}};
	t = 1;
	printf("Test Case 387\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 387 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -387;
	} else {
		printf("Test Case 387 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9E38C31EBAB67C87ULL,
		0x7794414D84479099ULL,
		0xE7042525D2354B1AULL,
		0xB76653699ED000B9ULL,
		0x5EF9FF7BA8BBC15EULL,
		0xF5D5D947F7847F01ULL,
		0xAE83133350EFE45DULL,
		0x5C79587FB8AA2911ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42A295B0210C1440ULL,
		0x8F081AD68C26AE3EULL,
		0x98C1BC5D8F37AF97ULL,
		0x7025B53EC05AED69ULL,
		0x5602C6B62C21C4F8ULL,
		0xAC0020183AEA99A5ULL,
		0xAFB226D75C42F471ULL,
		0xFAC6A28E131E65FEULL
	}};
	t = -1;
	printf("Test Case 388\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 388 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -388;
	} else {
		printf("Test Case 388 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAE058321EF83533FULL,
		0xDB6850BDE16CA4F9ULL,
		0xC2C506B06AA91728ULL,
		0x839997BB7DED0540ULL,
		0xD96EF6EFDAF075F0ULL,
		0xDAEA4A5FD50517E2ULL,
		0x285FFEF793F51D5CULL,
		0x5FF80420ED563522ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE058321EF83533FULL,
		0xDB6850BDE16CA4F9ULL,
		0xC2C506B06AA91728ULL,
		0x839997BB7DED0540ULL,
		0xD96EF6EFDAF075F0ULL,
		0xDAEA4A5FD50517E2ULL,
		0x285FFEF793F51D5CULL,
		0x5FF80420ED563522ULL
	}};
	t = 0;
	printf("Test Case 389\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 389 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -389;
	} else {
		printf("Test Case 389 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3075B9672448A3E1ULL,
		0xC1C546CA9552B584ULL,
		0xC391631C57C35449ULL,
		0xEB36D60FD92D4246ULL,
		0x61588D1633CBD00AULL,
		0x95D31D2BAF5E55CBULL,
		0xE8EC8BB3D163607EULL,
		0xCE4BCC549A28CA3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x832A506CF809BBE8ULL,
		0xBCA626D528AD4D9EULL,
		0x351EF8708C2DE15DULL,
		0x6111C07774C8A8E2ULL,
		0xC4B42226DDBEAA92ULL,
		0x93D7A0460486543FULL,
		0x5DF91C98522D77EFULL,
		0x137232AE034146BDULL
	}};
	t = 1;
	printf("Test Case 390\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 390 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -390;
	} else {
		printf("Test Case 390 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4609956D9E9681A4ULL,
		0xA829C1F4BC8A63E6ULL,
		0x367C917302F37AADULL,
		0xE390437C66AA1764ULL,
		0xC7C48FFBD99D2722ULL,
		0x0B579FD58886E2A2ULL,
		0xE8249FD8069AC73EULL,
		0xEC5A37FF118CCD30ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56A758AB809203DEULL,
		0xABF9EDB2D12CCA31ULL,
		0xA93749355175849EULL,
		0x9D8C2575179B0C9BULL,
		0x83DA6F3C06504BA5ULL,
		0x0968C463261E9467ULL,
		0xCA20816E82B75247ULL,
		0xDD48D158A07799CFULL
	}};
	t = 1;
	printf("Test Case 391\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 391 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -391;
	} else {
		printf("Test Case 391 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x99B7F6789D0FED6EULL,
		0x5D609E1EC3507081ULL,
		0x53375A2E54BFE482ULL,
		0x587C5AB1C0D3FA31ULL,
		0xF7F70DFCAF23D944ULL,
		0x8003804972C3022AULL,
		0x7DFB01FB4B57D046ULL,
		0x0D83AEA346057CACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6430B7794E6CF906ULL,
		0x5276E5A1D1005A5BULL,
		0xB64C1C1EC4EE4895ULL,
		0x8A6D6732A095F60FULL,
		0xEBD928441E947EF7ULL,
		0x92AE205C1CCE5A3CULL,
		0x76E3A2479F5F5C84ULL,
		0x30633A4980F23117ULL
	}};
	t = -1;
	printf("Test Case 392\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 392 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -392;
	} else {
		printf("Test Case 392 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE87E57590567E42EULL,
		0xDA00B904ACBF29B6ULL,
		0xB340F4195E705EA6ULL,
		0xD1EF6AE36865A75BULL,
		0x100C71DCA1B069A0ULL,
		0xE6340DEEBAB07F09ULL,
		0xFA0CFCCE03DDEB13ULL,
		0x00BEAF4E5369E681ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE87E57590567E42EULL,
		0xDA00B904ACBF29B6ULL,
		0xB340F4195E705EA6ULL,
		0xD1EF6AE36865A75BULL,
		0x100C71DCA1B069A0ULL,
		0xE6340DEEBAB07F09ULL,
		0xFA0CFCCE03DDEB13ULL,
		0x00BEAF4E5369E681ULL
	}};
	t = 0;
	printf("Test Case 393\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 393 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -393;
	} else {
		printf("Test Case 393 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBACE2D05958C2A92ULL,
		0xA2F64CFCB9574FF2ULL,
		0x7A2B0A128460A1DDULL,
		0x56E593C4A47DA376ULL,
		0x4DCB33F03419B824ULL,
		0x2D5282004BF35A2CULL,
		0x06DB89DB5C1A1CC9ULL,
		0x84DB7B8C0CD894A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21D34655A581B5BFULL,
		0x241B1B7518EE402BULL,
		0x3746FF2EDE760E32ULL,
		0x12A2376F07F6A52EULL,
		0xE3C324AB0DD1F2C3ULL,
		0x0EE09124AD967431ULL,
		0x86A3CB57F40AED90ULL,
		0xCDAEBE7AA171AAFBULL
	}};
	t = -1;
	printf("Test Case 394\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 394 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -394;
	} else {
		printf("Test Case 394 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA8FAF85AE84DCA75ULL,
		0x22A2E11B3CE6F2CFULL,
		0xB1E3CFE1E41E33FAULL,
		0xBE16816AC0DF7822ULL,
		0xE9AA8CF21123F93CULL,
		0x2D7D4FAD9DDE820DULL,
		0x104A9DA5B572A447ULL,
		0x9087F59D97DA57F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCBB6AF6C83B8681ULL,
		0xA40F28AB73B3872CULL,
		0xB8BA59193CDA5713ULL,
		0x74ECBDADF67AEA20ULL,
		0x2FBC734B9613DB79ULL,
		0xCA58370016D11DFAULL,
		0x553B8555004B7AF8ULL,
		0x26D601515BB6D05DULL
	}};
	t = 1;
	printf("Test Case 395\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 395 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -395;
	} else {
		printf("Test Case 395 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB915A41F4E1BCA7BULL,
		0xE3E49388AD1A3B97ULL,
		0x1ED5C2DDCD7BC414ULL,
		0x0C22C72E8F91F64DULL,
		0x624447F3F9DC4BD7ULL,
		0xC64F9DD3884D8AF0ULL,
		0x9B34C7FEB271773EULL,
		0xA9AA3F84E69A2AD0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x255CD23115A2F606ULL,
		0xB002B67EC7B66CB4ULL,
		0xC5814C1D3392EDE8ULL,
		0xF600880F1DCC9E62ULL,
		0xA728C03A6376850BULL,
		0x13D81F1C98B6FBFAULL,
		0x042F0FAF842F94D3ULL,
		0x3CDD3E2FCEFC3531ULL
	}};
	t = 1;
	printf("Test Case 396\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 396 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -396;
	} else {
		printf("Test Case 396 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x405967C9447EC0B1ULL,
		0xC99103567EB029EEULL,
		0xC42EAB9681A231F0ULL,
		0x28556744EA939AEEULL,
		0xB2D5EA10F7331551ULL,
		0x2C2CD50CB22DA9D3ULL,
		0x62F55199EDF5F927ULL,
		0x483915B1C60A82B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x405967C9447EC0B1ULL,
		0xC99103567EB029EEULL,
		0xC42EAB9681A231F0ULL,
		0x28556744EA939AEEULL,
		0xB2D5EA10F7331551ULL,
		0x2C2CD50CB22DA9D3ULL,
		0x62F55199EDF5F927ULL,
		0x483915B1C60A82B3ULL
	}};
	t = 0;
	printf("Test Case 397\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 397 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -397;
	} else {
		printf("Test Case 397 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB282862DDB79C861ULL,
		0xA86505C20A097620ULL,
		0xD9E2DB63CFA4A42DULL,
		0xE6F8F1227558522DULL,
		0xC3EEA548960DCAFBULL,
		0x50A55B88BB12DFB2ULL,
		0xC46134A60B4E3154ULL,
		0x3885B24B3A9D7C73ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB6831325DDA5E26ULL,
		0x0DA7825FE3649D1FULL,
		0xFDEFF26F0F1E7CE2ULL,
		0xDAAD4F70DD1F8F84ULL,
		0xB3E959116C9A95A1ULL,
		0x93C802EC73E81DF4ULL,
		0x3FA25E1C174E848DULL,
		0x3A56D24D15F60EEEULL
	}};
	t = -1;
	printf("Test Case 398\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 398 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -398;
	} else {
		printf("Test Case 398 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3F7E590DCDFF9097ULL,
		0x2DF61804484315C0ULL,
		0x20A3755BDADD2C6FULL,
		0x8925A927B59D43AAULL,
		0x9DE61257C6BB8FE1ULL,
		0xA3DD6C2F5BBFFC50ULL,
		0x40B4640F6870583DULL,
		0xD13AF10667E845C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5DC77964778571AULL,
		0xCCAF577E4318731DULL,
		0x206A9164A6A7EDB2ULL,
		0x5B0D60B5DCDA9830ULL,
		0xD69FF7F4CF5B71BFULL,
		0xDD32C1C8AF824052ULL,
		0x82496163CD4AF6C3ULL,
		0xCE3961ABB9EACA1FULL
	}};
	t = 1;
	printf("Test Case 399\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 399 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -399;
	} else {
		printf("Test Case 399 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9C8272754C51E38EULL,
		0xE991F94EF8C16792ULL,
		0xF08098DD38EE7D90ULL,
		0xD19F7A27EDF38017ULL,
		0x1F6DFDB558463778ULL,
		0x6116218C5AC55A70ULL,
		0x3B25E1AE5C6DB4F1ULL,
		0xF8CF60120FBFE4F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA0CE5687835B987ULL,
		0xD680963D37B4459EULL,
		0xAEF41FAE805B77E3ULL,
		0xEA485AD765C406F5ULL,
		0x1363B28122A67C91ULL,
		0xDF0D2A913AF8D579ULL,
		0xE3C721BCE415B192ULL,
		0xA6CC3E7F2B6244B9ULL
	}};
	t = 1;
	printf("Test Case 400\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 400 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -400;
	} else {
		printf("Test Case 400 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x01BFFC714EA5F9D6ULL,
		0x5A84BA25139D8F0AULL,
		0x5A20D7412D7F1AB5ULL,
		0x3336D43A062E5C01ULL,
		0xB20E60EC3ECF273EULL,
		0xC50BA3475B736ED5ULL,
		0xAB91FD1FE7136413ULL,
		0xF6662A4D83179AEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01BFFC714EA5F9D6ULL,
		0x5A84BA25139D8F0AULL,
		0x5A20D7412D7F1AB5ULL,
		0x3336D43A062E5C01ULL,
		0xB20E60EC3ECF273EULL,
		0xC50BA3475B736ED5ULL,
		0xAB91FD1FE7136413ULL,
		0xF6662A4D83179AEBULL
	}};
	t = 0;
	printf("Test Case 401\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 401 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -401;
	} else {
		printf("Test Case 401 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x36865FFA489E67EDULL,
		0x2D3A799D44EDABF2ULL,
		0xAD941E10DB443D1DULL,
		0xF654CE6F95EA3EDEULL,
		0xEF7C5EEDAE3FFC30ULL,
		0x80B50A4415B7A96FULL,
		0x223D0EC29695584AULL,
		0xCACC44C807D3AF1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F7B9170AFCC07EAULL,
		0x5B169BB6138DD0FEULL,
		0x2289A8BA467587B7ULL,
		0x2B48806295BE1F98ULL,
		0xB7F42B5423204C4BULL,
		0xA736A21084400B37ULL,
		0x97B4B5DE5351336EULL,
		0x437EA9CC334A8147ULL
	}};
	t = 1;
	printf("Test Case 402\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 402 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -402;
	} else {
		printf("Test Case 402 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6F2B0C2438CFFCE8ULL,
		0xAD1ADC4471C6EB90ULL,
		0xFA24AA41890E5577ULL,
		0xC3D6096E28DB3727ULL,
		0x4994F9CF50600258ULL,
		0x3206168ED3F6C671ULL,
		0xC3C77E14BE1E9DB5ULL,
		0xF290BA68908C3BEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF998063B06639D8FULL,
		0x25CEE5609524D897ULL,
		0x660A04D6A207E2BDULL,
		0x971895CCE6273A11ULL,
		0x0F1A35690CDA4E6BULL,
		0x9EC4CBD481BCB1B6ULL,
		0x7FD7A8452F5187BDULL,
		0x4340E7B983EFFFE7ULL
	}};
	t = 1;
	printf("Test Case 403\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 403 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -403;
	} else {
		printf("Test Case 403 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6081271455ECBDC6ULL,
		0xA0A6FE92D735E440ULL,
		0x788E80F924039D07ULL,
		0x24C6F9CAF2F327EBULL,
		0x6D7DE8F82E961F9FULL,
		0x307287661CD462BDULL,
		0xF361D04EA1B62E30ULL,
		0x293C199BFEF114A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9FC6200EA96719BULL,
		0xE3ED2A7BA78EDF90ULL,
		0x3383D9B628E40A73ULL,
		0xD6408AAB5113459EULL,
		0x14531F1C4793EC8BULL,
		0x0708A3AFCB57329EULL,
		0xFE52EB4D038B5930ULL,
		0xCC64D2FB7530A2B8ULL
	}};
	t = -1;
	printf("Test Case 404\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 404 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -404;
	} else {
		printf("Test Case 404 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB6069A018AE210F5ULL,
		0xA552228748F6B797ULL,
		0x6B067F9F15306730ULL,
		0xDDD704E75DEAAABAULL,
		0x06E56425C6C11464ULL,
		0x9D7270B7DC74A8D7ULL,
		0x923CD117C3966A42ULL,
		0x2A1933F83F149A40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6069A018AE210F5ULL,
		0xA552228748F6B797ULL,
		0x6B067F9F15306730ULL,
		0xDDD704E75DEAAABAULL,
		0x06E56425C6C11464ULL,
		0x9D7270B7DC74A8D7ULL,
		0x923CD117C3966A42ULL,
		0x2A1933F83F149A40ULL
	}};
	t = 0;
	printf("Test Case 405\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 405 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -405;
	} else {
		printf("Test Case 405 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x03068688D3FE87A2ULL,
		0x7E1CC410C1CD3115ULL,
		0x9A034212368720B0ULL,
		0x3514A2C3A33AF31DULL,
		0x792F5E6CF5DE344FULL,
		0xFEA69D52D5B34AD8ULL,
		0xBFEE605CD45D91BCULL,
		0xC1E481D10304C11BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0C115A080092BC4ULL,
		0xC1DE04D053F8653AULL,
		0xD5E4A5C19AC68E60ULL,
		0x4B3745C3E67159C9ULL,
		0xEC5986A04E4D2ACFULL,
		0xB84CD6E905FCF624ULL,
		0xC780BA2EFA63E9EEULL,
		0xF565136238488287ULL
	}};
	t = -1;
	printf("Test Case 406\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 406 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -406;
	} else {
		printf("Test Case 406 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x46C25D41680A6F6DULL,
		0x930D35C6F4303D8EULL,
		0xB78769FA49FFD796ULL,
		0x3DF28F0220313C6AULL,
		0xFE2ECB20C60B445FULL,
		0xE82F5057F7DEFF1BULL,
		0x86B29B86219D2BEDULL,
		0x51EE9604B15B640AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA704761882A24CCEULL,
		0x03CF883B862779FCULL,
		0xC1C50AC401B5F8F4ULL,
		0x9D2F0C4FE9025FCCULL,
		0x2BB9D953D293E595ULL,
		0xF3BF7C2DA3496347ULL,
		0xBFEE4E28E35BC34FULL,
		0x70C9BA64A6AC3E40ULL
	}};
	t = -1;
	printf("Test Case 407\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 407 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -407;
	} else {
		printf("Test Case 407 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC986575B2132178DULL,
		0x1357533734D0963BULL,
		0x6916BC971DF5EFFAULL,
		0xACAF266E31021FFEULL,
		0xB54266FBD06150EAULL,
		0x1DEB519CF2153739ULL,
		0x04AE2FF81C09E4AFULL,
		0xCD98C8641E221EAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8232C6691027A84ULL,
		0x2F00D6A039698281ULL,
		0x73EA6E294A3117EDULL,
		0xBC701237A6F2D468ULL,
		0xEBA7D24B37066AECULL,
		0xF40AE7F8782D939FULL,
		0xFF9C9B98D71E2123ULL,
		0xACBA021FEC77B3ABULL
	}};
	t = 1;
	printf("Test Case 408\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 408 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -408;
	} else {
		printf("Test Case 408 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC5EEE3FB72FC4986ULL,
		0x0B06170D8ECD371CULL,
		0x9985BC731B088CD9ULL,
		0x3D819E7FEA4FF101ULL,
		0xC98E329A14926AD5ULL,
		0x71D72E2CCFE9C5ECULL,
		0xBC94ABD0EB9A048BULL,
		0x289A42A00B47D226ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5EEE3FB72FC4986ULL,
		0x0B06170D8ECD371CULL,
		0x9985BC731B088CD9ULL,
		0x3D819E7FEA4FF101ULL,
		0xC98E329A14926AD5ULL,
		0x71D72E2CCFE9C5ECULL,
		0xBC94ABD0EB9A048BULL,
		0x289A42A00B47D226ULL
	}};
	t = 0;
	printf("Test Case 409\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 409 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -409;
	} else {
		printf("Test Case 409 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x44217207E65F6D3EULL,
		0xA3A42E99209AC8CBULL,
		0xADB6F26432D6D949ULL,
		0xE4C188F3CAF40566ULL,
		0x9A4D748D04B929EAULL,
		0x0867FCEBF16E1E10ULL,
		0x1D576FAF3084CEB1ULL,
		0x867A35A557ECDD04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x016208F4798A8B30ULL,
		0xB40BFD1444C31F83ULL,
		0xFC82F419D322AEAAULL,
		0xDD47D1C6FC288AD5ULL,
		0x27BC6AF65A8A5473ULL,
		0x348CD27B6419278CULL,
		0xF11CBDF78C0C1304ULL,
		0x607B2C43E043CA41ULL
	}};
	t = 1;
	printf("Test Case 410\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 410 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -410;
	} else {
		printf("Test Case 410 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC49858CE1EC9834AULL,
		0x8C898677031A9040ULL,
		0x766735EA848EF3ABULL,
		0x58B25E3A2F25D9F9ULL,
		0x5B663B7E791E02B1ULL,
		0x95B265EAE35E8770ULL,
		0xAD33E2AD86AB2737ULL,
		0xBE9AE5AD2B392778ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x955C1B205480E1B5ULL,
		0xAA58D03EFAE7384EULL,
		0x3CDBE84EA40A1F85ULL,
		0x4E631EDD6427D117ULL,
		0x521B3BD853E079EEULL,
		0x8B73EF73A96EA04DULL,
		0x5356CB48EF05AFCBULL,
		0x79AA37B68A9CD3A2ULL
	}};
	t = 1;
	printf("Test Case 411\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 411 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -411;
	} else {
		printf("Test Case 411 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC3F69CC4C9758CFEULL,
		0xE94108DBF17D3D6AULL,
		0xE0147E368FDB3333ULL,
		0x2610D061CFEAEC45ULL,
		0x1DD0A1D9AFDCFDACULL,
		0xCFF032D25D036F57ULL,
		0xEA012FA3B252AD6BULL,
		0xEB4B495B80EAE6F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59C9BE1AD0D8B6EAULL,
		0x48D74E33E0ECBBBBULL,
		0x654F1D535525BA19ULL,
		0xBC0C8A5E0C56143CULL,
		0x8C56431DF990E35AULL,
		0x37705CAB09612A25ULL,
		0x1392CD1D75B2DEB0ULL,
		0x24C8DCEEEDF2A6E0ULL
	}};
	t = 1;
	printf("Test Case 412\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 412 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -412;
	} else {
		printf("Test Case 412 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9AC9CB32417433A1ULL,
		0xF4AFB286151FB68FULL,
		0xE66B6063D0F76AA8ULL,
		0x2EA231687699D77FULL,
		0x26B92CDA79F93E07ULL,
		0xE434813F26394F2AULL,
		0x65CDC0638D10B6CDULL,
		0x4E73CA0C9050887AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9AC9CB32417433A1ULL,
		0xF4AFB286151FB68FULL,
		0xE66B6063D0F76AA8ULL,
		0x2EA231687699D77FULL,
		0x26B92CDA79F93E07ULL,
		0xE434813F26394F2AULL,
		0x65CDC0638D10B6CDULL,
		0x4E73CA0C9050887AULL
	}};
	t = 0;
	printf("Test Case 413\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 413 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -413;
	} else {
		printf("Test Case 413 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCB3C4C1B6E7CCA48ULL,
		0xAADA0ACED1237AC3ULL,
		0x8A90B1C67123E14FULL,
		0x0FDDA64C2CBD5209ULL,
		0x74F286B9E42F12B4ULL,
		0x805DCC4A7F9FF3D7ULL,
		0x9FB0F8DAC33FF992ULL,
		0x6C550C65AE4E6307ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE770A7B226E116E9ULL,
		0x1595A47497FE4AD0ULL,
		0x5C501B62BEF610A1ULL,
		0x000C8E69F5982E50ULL,
		0x2B9EB41F101B94B6ULL,
		0x8043042510FDB1C2ULL,
		0xDBE290A34253C232ULL,
		0x1E8F27BD27E619ACULL
	}};
	t = 1;
	printf("Test Case 414\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 414 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -414;
	} else {
		printf("Test Case 414 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA0EF8230771DA4F8ULL,
		0x8243EF4A6CE180F3ULL,
		0x3A2893DA9781C3C8ULL,
		0xEEF4E44DA4740B34ULL,
		0x6029961334EBBEBAULL,
		0xFC310B4229F66073ULL,
		0xE4DDA89AE2BC4A80ULL,
		0x2D0C8C193AACB076ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9603208EE9DD1040ULL,
		0x68D03A9CF6C33A03ULL,
		0x1BB128A367EE7468ULL,
		0xC9F765CCFBE88809ULL,
		0xA29619C06A921F46ULL,
		0x65CB6E4749F5E976ULL,
		0xE7A5E046E1CE19C1ULL,
		0xE8360EDEA1B954AAULL
	}};
	t = -1;
	printf("Test Case 415\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 415 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -415;
	} else {
		printf("Test Case 415 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x362ADFD04749819EULL,
		0x82F93A9300C3ACF7ULL,
		0x99D4C6D3DBA3FCA0ULL,
		0xEF0F3CFACEF1BB30ULL,
		0x2F4FECC56148DEF7ULL,
		0x58BA15A47CBB1131ULL,
		0x6995EC6A72AC30CCULL,
		0xD83541E7D11A3EACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40ADA130D9615A95ULL,
		0x17A4EB2911488E7DULL,
		0x35C2F073B0AEE1CDULL,
		0x8EDA3EA7F55B0E6CULL,
		0x5A3E812D23E1A234ULL,
		0x8FC3445A534FB641ULL,
		0x5531887C941F57AAULL,
		0xFF6400E37FF340AFULL
	}};
	t = -1;
	printf("Test Case 416\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 416 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -416;
	} else {
		printf("Test Case 416 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE61FB6E02602E035ULL,
		0x5FD66D0C3126DB5FULL,
		0x6AB69A2AFDE2F0D0ULL,
		0x5585F1F669E75E68ULL,
		0x13549431C62629E0ULL,
		0x0853CD8FEDB0E722ULL,
		0x84ED469264F1957AULL,
		0x4F7F53705333D868ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE61FB6E02602E035ULL,
		0x5FD66D0C3126DB5FULL,
		0x6AB69A2AFDE2F0D0ULL,
		0x5585F1F669E75E68ULL,
		0x13549431C62629E0ULL,
		0x0853CD8FEDB0E722ULL,
		0x84ED469264F1957AULL,
		0x4F7F53705333D868ULL
	}};
	t = 0;
	printf("Test Case 417\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 417 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -417;
	} else {
		printf("Test Case 417 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x30A8DD187D90E720ULL,
		0x27CDDBD94745A897ULL,
		0x47C0989E1ED0CDD6ULL,
		0xDB9F77A5BC36B73CULL,
		0x9F0F61BDA67C3690ULL,
		0x30C3D0A0368C8673ULL,
		0x0B43FC7E5485B835ULL,
		0x04CCAE5AAF88E441ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25ACD3356968CC52ULL,
		0x0C4F9BA356F5AA4AULL,
		0x598D63FBB6CBD1BCULL,
		0x87ACF98BFF3E8C19ULL,
		0x7CB8FAE6347E6C39ULL,
		0x21D86C3047A98AC3ULL,
		0x64034403AB11370BULL,
		0x169883CED85EC91CULL
	}};
	t = -1;
	printf("Test Case 418\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 418 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -418;
	} else {
		printf("Test Case 418 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4E6487B1DA1F0563ULL,
		0xF25D91B070E767C6ULL,
		0x64FB0E08AB2C97CDULL,
		0xE1FEB1CE119A9056ULL,
		0xF5C5BB9728204C9BULL,
		0x077A2444789F48C9ULL,
		0xC55F0232585F994BULL,
		0xC93E6F7D407A442BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7377CB0CE252A714ULL,
		0x8CC005B0A8F3F0A0ULL,
		0xD870C5A07484FA77ULL,
		0x8F9EE443841D1F68ULL,
		0x7D0EBE4A698AFAD5ULL,
		0xB3FE58B485B21DDCULL,
		0x8C8C48D967AFF790ULL,
		0x4F67B609F70A3EACULL
	}};
	t = 1;
	printf("Test Case 419\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 419 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -419;
	} else {
		printf("Test Case 419 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6E669EFCD55116D1ULL,
		0x42DFA1FF7485DC73ULL,
		0x1C44A326F3C112B0ULL,
		0x0B73CEAD6FBDC1CDULL,
		0x9FF59E4C9F9847CDULL,
		0xAEA234D78EB68573ULL,
		0xDD6DA55CAABCB841ULL,
		0x051C6DCCC1F31A19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x474315A9C6FD0B3AULL,
		0xBFADCA09CC1AD56EULL,
		0x0E57FBAFF2376939ULL,
		0x3B913A7A63D7A4A4ULL,
		0x92E9EC408D7A425FULL,
		0x40CF8B9036A88CB2ULL,
		0xBB289A51CD37777FULL,
		0xBF2D72BD9A8CAD60ULL
	}};
	t = -1;
	printf("Test Case 420\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 420 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -420;
	} else {
		printf("Test Case 420 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCD32B6FC26A81E38ULL,
		0x98EF98C5FC3C05D6ULL,
		0x042FDFBF2C3827D3ULL,
		0xC934AB4EDCFB9352ULL,
		0x4D3603B3FE2D98ADULL,
		0x40BDB2E1074C22CDULL,
		0x6F1194044E06CA56ULL,
		0xB23C192CA1690B92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD32B6FC26A81E38ULL,
		0x98EF98C5FC3C05D6ULL,
		0x042FDFBF2C3827D3ULL,
		0xC934AB4EDCFB9352ULL,
		0x4D3603B3FE2D98ADULL,
		0x40BDB2E1074C22CDULL,
		0x6F1194044E06CA56ULL,
		0xB23C192CA1690B92ULL
	}};
	t = 0;
	printf("Test Case 421\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 421 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -421;
	} else {
		printf("Test Case 421 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x42921AF6D213AB41ULL,
		0xFED09057DBFA2C99ULL,
		0xCC467D287C8F6124ULL,
		0x8269E433AA6E5950ULL,
		0x8798EA5599656554ULL,
		0x303F40D2F87F2408ULL,
		0x15DC6CF356182A0FULL,
		0xD6987F6D5DEFCE35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89406A74122EB218ULL,
		0x54CF499E4771AD87ULL,
		0x23AF20D90F96A9C6ULL,
		0x6B49B92864DD6192ULL,
		0x4C92FD9154392614ULL,
		0x38715E6713277FBFULL,
		0x7CC89A5E99CEA924ULL,
		0x0D9F1C577B05CEDBULL
	}};
	t = 1;
	printf("Test Case 422\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 422 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -422;
	} else {
		printf("Test Case 422 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCA6445321976F69CULL,
		0x7962B34348A0A17BULL,
		0xBFF3B3BE943779B4ULL,
		0x8BDE6E18001D42AFULL,
		0xF42BA92A81B0D25DULL,
		0xD645D80998D1BB36ULL,
		0x1EFBA32FFF386F00ULL,
		0xD75540AC5C321772ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC99944ACC45C2CDULL,
		0xB7067F86CABA22D9ULL,
		0x2B79ADD32334C23BULL,
		0x6121D3332D8C5457ULL,
		0x4319713846BA89F7ULL,
		0x433059272A050EADULL,
		0xE8BFBD3A025E91B7ULL,
		0xAE1CE47CDAF7F8B4ULL
	}};
	t = 1;
	printf("Test Case 423\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 423 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -423;
	} else {
		printf("Test Case 423 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4347DD329E177C03ULL,
		0xE7FF43800FA29592ULL,
		0x19EC93C0176361A5ULL,
		0x980C5F3C466C1AA3ULL,
		0xD26495AD8C90AE68ULL,
		0xF37102E7915508D1ULL,
		0xEB3BE734A7E423EBULL,
		0xFC1F09C8D7DA35A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75368E17938728BEULL,
		0x5D724DEBFF393239ULL,
		0x1EB5462A765DCBB1ULL,
		0xAEB57E4B6BB46F8BULL,
		0xB6660EB3D27CC5F8ULL,
		0xB3B64D898B103AC3ULL,
		0xF6B94E20C0D6BA77ULL,
		0xF21998A657F5EA6BULL
	}};
	t = 1;
	printf("Test Case 424\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 424 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -424;
	} else {
		printf("Test Case 424 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC8B0F1F53CE757BAULL,
		0x98B502EDE7026BEBULL,
		0xD621661F18DE9FE9ULL,
		0x7BA2AA7A2A96A456ULL,
		0x3A486F9E8A440B93ULL,
		0x688774DBA83BBFD3ULL,
		0x52F84EB353B49F36ULL,
		0x5066FDB5693A4EDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8B0F1F53CE757BAULL,
		0x98B502EDE7026BEBULL,
		0xD621661F18DE9FE9ULL,
		0x7BA2AA7A2A96A456ULL,
		0x3A486F9E8A440B93ULL,
		0x688774DBA83BBFD3ULL,
		0x52F84EB353B49F36ULL,
		0x5066FDB5693A4EDCULL
	}};
	t = 0;
	printf("Test Case 425\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 425 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -425;
	} else {
		printf("Test Case 425 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC18B868BAE5F805CULL,
		0xD5F246B047095170ULL,
		0x05DAFFE36282E8D4ULL,
		0xBB0D5A6BE5177E65ULL,
		0xF500A61DC5174061ULL,
		0xC57314BD12091887ULL,
		0x61B40D89AA5E9816ULL,
		0x250410235A095D8CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD485949C7F8016BDULL,
		0x40A2E0551B366774ULL,
		0xFCA2660700EF846EULL,
		0x703414F57543B326ULL,
		0x277B6FC769BF9B46ULL,
		0xBDABEBD15481A7E3ULL,
		0x9588A8FCCC2A12DFULL,
		0x8BBA366FC1F438C9ULL
	}};
	t = -1;
	printf("Test Case 426\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 426 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -426;
	} else {
		printf("Test Case 426 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6E9689B108AFC734ULL,
		0x260A0742FF8DBB1EULL,
		0x5332531184A33457ULL,
		0x56B36A7DD8548696ULL,
		0x0B26386128850A88ULL,
		0xD0A3ED8FC3D3B92DULL,
		0xE788CC090F690B0BULL,
		0x3F1017C33C340390ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD377E7B68572CD46ULL,
		0x1454CA13F15783AFULL,
		0x59F14102DE838179ULL,
		0x0E6BD8D7436902DAULL,
		0x2FEA5F75A204BDAEULL,
		0x2E67D20EEF8D9D8EULL,
		0x62ED09F93ACF10A9ULL,
		0x0E1559D5A5E65A92ULL
	}};
	t = 1;
	printf("Test Case 427\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 427 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -427;
	} else {
		printf("Test Case 427 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0A765BF3A8F80612ULL,
		0xF1EDE4146F00A54FULL,
		0x634368A18F943E94ULL,
		0x94A1E4C7CAC6B00FULL,
		0xCF0014800CC7DF2EULL,
		0x40F57A9357242C35ULL,
		0x1F05A3E3B6358710ULL,
		0x59DB3292FD0D4246ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9ECD5257B6327C70ULL,
		0xB327FE5F8F177CB1ULL,
		0x3E9D6CC4B7E72F6EULL,
		0xDAA40FA3A1C0E95FULL,
		0x49AD392A0E8D6404ULL,
		0x0033F1423C1A7E52ULL,
		0x300B059F5AB84B88ULL,
		0x17749AD68C18DB2AULL
	}};
	t = 1;
	printf("Test Case 428\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 428 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -428;
	} else {
		printf("Test Case 428 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x043BA1767012708EULL,
		0x71C8BD1FCE466662ULL,
		0xF8F8180128314EECULL,
		0xDEF138FDFA703F59ULL,
		0xCEB26AEC924B7566ULL,
		0xF1E89F61C32B8580ULL,
		0x638E1A2A2940B951ULL,
		0x8FEFB285AE985D00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x043BA1767012708EULL,
		0x71C8BD1FCE466662ULL,
		0xF8F8180128314EECULL,
		0xDEF138FDFA703F59ULL,
		0xCEB26AEC924B7566ULL,
		0xF1E89F61C32B8580ULL,
		0x638E1A2A2940B951ULL,
		0x8FEFB285AE985D00ULL
	}};
	t = 0;
	printf("Test Case 429\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 429 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -429;
	} else {
		printf("Test Case 429 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5C824CA380555D66ULL,
		0xC39240DD0167F2E2ULL,
		0x01F1BC00448B6F55ULL,
		0xB1C645E0728B927BULL,
		0xEA6BC7F7EAB6266AULL,
		0xB47033A7D0319606ULL,
		0x685C4A7D05266CF8ULL,
		0xFF48916031ED4E8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73F9A00A589DFE42ULL,
		0xF01551D40FBB0434ULL,
		0x0E14F6EA09EBDCA6ULL,
		0x8744D8DC3217AA00ULL,
		0x72E8559D6821E216ULL,
		0x10421A47D1862B90ULL,
		0xC4EECE4C008D0824ULL,
		0x6003F62A0E9F0F89ULL
	}};
	t = 1;
	printf("Test Case 430\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 430 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -430;
	} else {
		printf("Test Case 430 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x50FE91C44CD16393ULL,
		0x14FB443B9FA5680FULL,
		0xD0D19688C0098714ULL,
		0xD1C4230707CA5926ULL,
		0x46345A3EAEB9A973ULL,
		0xB9726995AB66FCF1ULL,
		0x53A5F4E68E50A82EULL,
		0x0B1CDF44FB136111ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C79FA95ADE15997ULL,
		0xA65469A17D406553ULL,
		0xE81315EC6AE75373ULL,
		0x2BD7833EDDFE8D33ULL,
		0x58F2FA91A1C3E6A8ULL,
		0xD8070F104493D89CULL,
		0x6A6AA4F05DA90358ULL,
		0x21AFF647413C5DE6ULL
	}};
	t = -1;
	printf("Test Case 431\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 431 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -431;
	} else {
		printf("Test Case 431 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4493CF72CA7F8D25ULL,
		0xA8C2F5F110A90F89ULL,
		0xC48B4370C6209030ULL,
		0x87D661BE26B12F71ULL,
		0xCEE260ECC6999604ULL,
		0x155C9A50EE78436DULL,
		0x7EB806171C0198E8ULL,
		0xBB3133E3D4B2C417ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90A18E10B8C3F32FULL,
		0xE9962690062E6898ULL,
		0x5E3363EE67056C7BULL,
		0xC6C5E0F1D0897CF4ULL,
		0xD2253BE512296F34ULL,
		0xECB7B0ABE580A573ULL,
		0xAF73CD0D124988F2ULL,
		0x9733C2E9D9CF8C6DULL
	}};
	t = 1;
	printf("Test Case 432\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 432 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -432;
	} else {
		printf("Test Case 432 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC8F50BFF820D3F0DULL,
		0xBCFAB9209D7AE749ULL,
		0x05AC50887DADAFE7ULL,
		0xB788A4E1D7978ECCULL,
		0x2AA58B8EA5587CFBULL,
		0xF1872CA68FA23D37ULL,
		0x299E6CA7254B9819ULL,
		0x58DB1942CE1AF5CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8F50BFF820D3F0DULL,
		0xBCFAB9209D7AE749ULL,
		0x05AC50887DADAFE7ULL,
		0xB788A4E1D7978ECCULL,
		0x2AA58B8EA5587CFBULL,
		0xF1872CA68FA23D37ULL,
		0x299E6CA7254B9819ULL,
		0x58DB1942CE1AF5CCULL
	}};
	t = 0;
	printf("Test Case 433\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 433 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -433;
	} else {
		printf("Test Case 433 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1D5F84FD3A53D5BDULL,
		0x2E5B940750D36134ULL,
		0x250CC9A559F19FD3ULL,
		0xE2A51CC751F19040ULL,
		0x0EB8E1DAD76B117BULL,
		0xDD6DF7218A0FE208ULL,
		0x4DBDA7DCB52B700FULL,
		0x1998BFE8572959E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x600689B9969AF0C1ULL,
		0xD18A236C3A6050BBULL,
		0xFD75B9F31BD21A7EULL,
		0x28660500E3BF3158ULL,
		0x5E493115EDDB8F44ULL,
		0x33845C5077324D26ULL,
		0xDB4B0FD845121114ULL,
		0x2AE179309085EA9BULL
	}};
	t = -1;
	printf("Test Case 434\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 434 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -434;
	} else {
		printf("Test Case 434 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x84F448864C25C14CULL,
		0x23F156D935456F55ULL,
		0xAC270776C7F5CE74ULL,
		0xBABA9CE71C35EDB3ULL,
		0x3BC1C4426906DE8BULL,
		0xD3DC94B10AC91587ULL,
		0x06D3B72A231E5FD9ULL,
		0x362FAB7965027D47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38AFB48D5BECCF74ULL,
		0x39CE7FE2B42B78F1ULL,
		0x56EB7AC14D6E3F6CULL,
		0x2DC5B6BDDCA3DF2BULL,
		0x1B426530FE503FB5ULL,
		0xB78865B6BB9EA3E1ULL,
		0x88656EB89D9103ABULL,
		0x623BE28E32DEEBC5ULL
	}};
	t = -1;
	printf("Test Case 435\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 435 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -435;
	} else {
		printf("Test Case 435 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAE586A2480BE40B6ULL,
		0x6CFAC2CD58A4CE42ULL,
		0x0E6798C11165BA47ULL,
		0x5FDD304A158D44EAULL,
		0x9B8104CC04D4B94AULL,
		0x769BFFB515E61EDAULL,
		0x06BE664A8E512C4CULL,
		0xA1BCA7EFAACF1CD5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDBCEE12B4B4A901CULL,
		0x38A8D8CDFE621D93ULL,
		0x8269A9C1E5A20934ULL,
		0xBCFBD93E5B28E6F3ULL,
		0x0F87E8ED50E61F7DULL,
		0xCBCA5DC0A03CFE17ULL,
		0x180DB27FD1DA38DBULL,
		0x2D415482EB82203CULL
	}};
	t = 1;
	printf("Test Case 436\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 436 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -436;
	} else {
		printf("Test Case 436 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x642CD6DE447C656CULL,
		0x9887B3F59449BF7CULL,
		0x971642472A72AB5FULL,
		0x51197194A60AB472ULL,
		0x954FB23E1B4E4D03ULL,
		0xD6DB8B6B743CFB03ULL,
		0x5D87F2C8D11D7EFEULL,
		0x0F96B5AF1989E288ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x642CD6DE447C656CULL,
		0x9887B3F59449BF7CULL,
		0x971642472A72AB5FULL,
		0x51197194A60AB472ULL,
		0x954FB23E1B4E4D03ULL,
		0xD6DB8B6B743CFB03ULL,
		0x5D87F2C8D11D7EFEULL,
		0x0F96B5AF1989E288ULL
	}};
	t = 0;
	printf("Test Case 437\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 437 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -437;
	} else {
		printf("Test Case 437 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x83AAAEFFB7D07F65ULL,
		0x1F4F88F3182DDD30ULL,
		0xE9788C9A6883945EULL,
		0x097819123380EC9CULL,
		0xC624CC89B31259D5ULL,
		0xBFC5A74279EEFFE7ULL,
		0x543C092B07F7840FULL,
		0xEA71849DFF1E233AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB49F92CDDA2841D8ULL,
		0xAE8B930734D6BAACULL,
		0x71292051205EF6CEULL,
		0xBC834163342545A5ULL,
		0x95CFD881DDA0E273ULL,
		0x744B41648196DFE3ULL,
		0xE02BF6E80DC40F2EULL,
		0x7185F2DA32D182F5ULL
	}};
	t = 1;
	printf("Test Case 438\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 438 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -438;
	} else {
		printf("Test Case 438 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFF5D6F7910DAD0BDULL,
		0xC340A941EBFFF793ULL,
		0x11F4A929D3AEFE63ULL,
		0xBC38F32D70131C5EULL,
		0x3FDE1B72EA2BAD55ULL,
		0x66A875F55EE15D16ULL,
		0x7C343FC9EFCA21DBULL,
		0x6017822691731DB3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x918C617132322EC7ULL,
		0xD0296E35506954D8ULL,
		0x59154F8E87F6F41EULL,
		0x4F1EABE19F1E3403ULL,
		0x7F90E494BBCFCA09ULL,
		0xE3B9F6EEFF439CEFULL,
		0x287DEF376DE2FCD7ULL,
		0x3D141F279FDC4FBDULL
	}};
	t = 1;
	printf("Test Case 439\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 439 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -439;
	} else {
		printf("Test Case 439 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAA7AFBB4554E4DFEULL,
		0x7A28159D533AACD3ULL,
		0x7EE792EB256FD1F9ULL,
		0x223D1E1A6CB1706BULL,
		0x6B6940FA636171BBULL,
		0xC7CCAE45CBCFEBEAULL,
		0x707D2D0FCE6D752DULL,
		0x132C397529C157A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x851C3ACEE9D35F4EULL,
		0x211EF9B8F3D44B0EULL,
		0x733DEB547DE3175DULL,
		0xD880C5A6FE18E891ULL,
		0x442D1F3382EF04C4ULL,
		0xF74A876A87D52A11ULL,
		0xB895212882C57BA8ULL,
		0xFEF414F60A1F5071ULL
	}};
	t = -1;
	printf("Test Case 440\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 440 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -440;
	} else {
		printf("Test Case 440 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1F98AA74DDAD4738ULL,
		0x701657A145B2A7D3ULL,
		0xA138CA01B93C61E2ULL,
		0xF369E0963F31279FULL,
		0x33C078C5E7784320ULL,
		0x406A2EE5475978A8ULL,
		0x3036E1C05413B308ULL,
		0xD7C96A2B6C2DAB56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F98AA74DDAD4738ULL,
		0x701657A145B2A7D3ULL,
		0xA138CA01B93C61E2ULL,
		0xF369E0963F31279FULL,
		0x33C078C5E7784320ULL,
		0x406A2EE5475978A8ULL,
		0x3036E1C05413B308ULL,
		0xD7C96A2B6C2DAB56ULL
	}};
	t = 0;
	printf("Test Case 441\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 441 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -441;
	} else {
		printf("Test Case 441 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x59DCE7695CF00324ULL,
		0x0514AED1D33DE051ULL,
		0x9D18F050657A3D35ULL,
		0xC2AD122FF501CE18ULL,
		0x5DEEC8B7FD6EBC77ULL,
		0x63813B08A9C60CC5ULL,
		0xA337D375861325C9ULL,
		0x42AAFADD4F02A557ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BB1BACBE10E2881ULL,
		0xECDE95ED8AFF6349ULL,
		0x0E920A42B8BC4A28ULL,
		0xA905866721D24652ULL,
		0x67A17FEA6A5EB7FCULL,
		0x3232C003837EDA96ULL,
		0x9842B6A9662C792AULL,
		0x0BBEABCEFE26B121ULL
	}};
	t = 1;
	printf("Test Case 442\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 442 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -442;
	} else {
		printf("Test Case 442 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x61C91FB20708C5D5ULL,
		0xDD630F3A5CEE2091ULL,
		0x80EA4F8204D5F241ULL,
		0x788ED851600C588DULL,
		0x8286EA3EF611BEEAULL,
		0x8CCC4E952AA8846BULL,
		0x43A01946F0FC6D90ULL,
		0x67B1DA77B0542072ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62FA796599CFFFA7ULL,
		0x05760CEDED13E172ULL,
		0x2A52610389E326F4ULL,
		0x355EFFE4CDE9B4C2ULL,
		0xE52EAB7968E15BB0ULL,
		0xD55A3F9B258A99F6ULL,
		0x974DC7A392D45DC4ULL,
		0xD3CE8BB1652CFCDEULL
	}};
	t = -1;
	printf("Test Case 443\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 443 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -443;
	} else {
		printf("Test Case 443 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x91E630D7CA729BCDULL,
		0x3EBA84CE140F7A4AULL,
		0x3331DFBD69D5A3DBULL,
		0xB24737E2321DAD53ULL,
		0xA4D68344AD7CD3F0ULL,
		0xB9CBB6DDC44812A3ULL,
		0xAA1BAF184C153A3CULL,
		0x34EC521BB0813D54ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E53C5FB70F7165DULL,
		0x673A13F339382D29ULL,
		0x6B653A8F130773A3ULL,
		0x97930377AC7B480EULL,
		0xFEC0C916FBF7C531ULL,
		0x5E529330F863B9E0ULL,
		0xE57402A2B3AC6F2FULL,
		0x1D9CE15FD9E034D8ULL
	}};
	t = 1;
	printf("Test Case 444\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 444 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -444;
	} else {
		printf("Test Case 444 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA0616D752779D6CEULL,
		0x39DC1C1FF729CB2DULL,
		0x75C541782DEDCE9BULL,
		0x3F4C009843B2EF54ULL,
		0xFC32D8E2A7962D10ULL,
		0x3B9857B40605703BULL,
		0x245EC7DF22BB53E7ULL,
		0x5C1B6AB7F41CE009ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0616D752779D6CEULL,
		0x39DC1C1FF729CB2DULL,
		0x75C541782DEDCE9BULL,
		0x3F4C009843B2EF54ULL,
		0xFC32D8E2A7962D10ULL,
		0x3B9857B40605703BULL,
		0x245EC7DF22BB53E7ULL,
		0x5C1B6AB7F41CE009ULL
	}};
	t = 0;
	printf("Test Case 445\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 445 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -445;
	} else {
		printf("Test Case 445 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x57FEE722326C5FE7ULL,
		0xCD1010A5B8EE50B7ULL,
		0x44B116FBB5CF388AULL,
		0xF95E8942A2648974ULL,
		0x081BCBFD8FCD19EBULL,
		0xF89BEC53E5390BF0ULL,
		0x44BBA793454D2699ULL,
		0xA5EF6154B3D54AAAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34B8EBFF8ADA4E78ULL,
		0x21210835E8A0976BULL,
		0x8D94EE6F93A01754ULL,
		0x85947C92A4594DC8ULL,
		0x9079A776013C6CD0ULL,
		0x755D6985FC0BF77EULL,
		0x08E177406B0CC386ULL,
		0x61AD8D49BB6ACD19ULL
	}};
	t = 1;
	printf("Test Case 446\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 446 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -446;
	} else {
		printf("Test Case 446 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7E3E01F12D267F14ULL,
		0xAB83BD61534522B0ULL,
		0x5811F2501740F78CULL,
		0x6E8B351E2F214970ULL,
		0x21D95C0E827C5303ULL,
		0xEDC0D99E85D99EE8ULL,
		0xD75B58B31DC8503AULL,
		0xC61A6826E647CA46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E95C9B9D8957202ULL,
		0xC00F27C15E262A89ULL,
		0x166A1EBEF639A27FULL,
		0x04F0179FC01778CDULL,
		0xA6BD9F4634B5B916ULL,
		0x78653F21DD0E8D5BULL,
		0xC158E47004C7D598ULL,
		0xCCE6E8971F1E160DULL
	}};
	t = -1;
	printf("Test Case 447\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 447 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -447;
	} else {
		printf("Test Case 447 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC99C476200DACCC9ULL,
		0xA385E472D83504C4ULL,
		0xD865078C4D24155EULL,
		0x35F8B69DBA78AA9CULL,
		0x402BCE70535C9A48ULL,
		0xC365A2D3FC668582ULL,
		0x8C9D92B802B81113ULL,
		0x7F910930247F3BD0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C63C4BCE63932A3ULL,
		0x8B1E281418F0EF96ULL,
		0xBC417E547795AE84ULL,
		0x6FBC094959208017ULL,
		0x7616853D251D3205ULL,
		0x39006BF3E927FD31ULL,
		0xDC596A2EB1BB8920ULL,
		0x60F8A8F7A9C905E7ULL
	}};
	t = 1;
	printf("Test Case 448\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 448 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -448;
	} else {
		printf("Test Case 448 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6FFA8DBDD01377F4ULL,
		0x528C869A86700AFEULL,
		0xD5AB72F9C96E6D42ULL,
		0x2993A4890E83DDF2ULL,
		0x44AA8E89E79362BDULL,
		0xBAE42C037153B3EFULL,
		0x44ED7789A348AB2CULL,
		0xDA419B43F8575C0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6FFA8DBDD01377F4ULL,
		0x528C869A86700AFEULL,
		0xD5AB72F9C96E6D42ULL,
		0x2993A4890E83DDF2ULL,
		0x44AA8E89E79362BDULL,
		0xBAE42C037153B3EFULL,
		0x44ED7789A348AB2CULL,
		0xDA419B43F8575C0AULL
	}};
	t = 0;
	printf("Test Case 449\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 449 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -449;
	} else {
		printf("Test Case 449 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBA9082289E3E8105ULL,
		0x23E5C3C92F1D9507ULL,
		0x5864F3B16C3DCAF1ULL,
		0x5225CB3B0F75F330ULL,
		0xCCF6F5426642EE32ULL,
		0x700C3AAE13E72D29ULL,
		0x92BBF0B1FA89230FULL,
		0xB07219695CA05052ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11E5D66DBF84ED3BULL,
		0x97AE62344F4D118AULL,
		0x8FCE35E6878FBC66ULL,
		0xC7BAE14CA84EA4D1ULL,
		0xE675087857A1C22FULL,
		0x3508B0DEEEC06FEEULL,
		0xCB2B8DBD6E0A8D3EULL,
		0xEFCA377D0A19F303ULL
	}};
	t = -1;
	printf("Test Case 450\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 450 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -450;
	} else {
		printf("Test Case 450 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEA59178B032B54BFULL,
		0x7874B6603B6649C8ULL,
		0x2F5338BBD355CF8FULL,
		0x9D2598C202931FE1ULL,
		0xF4D2143CC5DB9D11ULL,
		0x03E47ECF72D2FF0FULL,
		0xBB7BB6B20709EC06ULL,
		0x3E6B40B7C83089FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x332005E4AF3281B0ULL,
		0x506CF7EE1F176745ULL,
		0xFD459A18DAC24576ULL,
		0xF28425DB2C1111DCULL,
		0x0A3141255E1E9E32ULL,
		0x4DED5F4313D9D96FULL,
		0x9341623C8B2D41B8ULL,
		0xB1BD31ADA7994A15ULL
	}};
	t = -1;
	printf("Test Case 451\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 451 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -451;
	} else {
		printf("Test Case 451 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA2397A675B95214FULL,
		0xF1B2EF7D0D6F2310ULL,
		0xC94862DA3A9E9C60ULL,
		0xABBC90AE1C32D452ULL,
		0xF76373B11BB148D8ULL,
		0x75D4D14E93635AE4ULL,
		0x4FDD5BC9E3A2755BULL,
		0x6BF3D33110B6FAC3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F975779C9023183ULL,
		0x62E7048A44F3C14BULL,
		0xD98646D088ED95B4ULL,
		0x84E6C0C77BF72291ULL,
		0x056E0F1616C9F966ULL,
		0xAFCCB6E5CDA5E9F2ULL,
		0xF33AE9444EF3B10BULL,
		0xD2CE81BD20A0B182ULL
	}};
	t = -1;
	printf("Test Case 452\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 452 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -452;
	} else {
		printf("Test Case 452 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0FB34A7AEACC255BULL,
		0x0061E1C1554CD6F4ULL,
		0x6FE2ACEC11E06E13ULL,
		0xCE224F6D963AAE44ULL,
		0xE786BDBA9CF5860DULL,
		0xA22A9BF75BC162F3ULL,
		0x7D1AAC672FE35E09ULL,
		0xA43F3670C1CA79E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FB34A7AEACC255BULL,
		0x0061E1C1554CD6F4ULL,
		0x6FE2ACEC11E06E13ULL,
		0xCE224F6D963AAE44ULL,
		0xE786BDBA9CF5860DULL,
		0xA22A9BF75BC162F3ULL,
		0x7D1AAC672FE35E09ULL,
		0xA43F3670C1CA79E7ULL
	}};
	t = 0;
	printf("Test Case 453\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 453 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -453;
	} else {
		printf("Test Case 453 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1D8F363830E188D5ULL,
		0x18A289F9A8A9F50FULL,
		0x2AEA208902DDF41EULL,
		0x83D6D17936B92CAAULL,
		0xA3C7AFF547C3B26EULL,
		0x6E797C2AF47537B9ULL,
		0x4CD5677674B69550ULL,
		0x1A645CFA47902ACEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F63B544A85F3F6FULL,
		0x8075DBBEEC7631A6ULL,
		0x997BC381AD5956B5ULL,
		0x70E50464627DB370ULL,
		0x7166B24B24530EA0ULL,
		0x53E7CECD80E0A271ULL,
		0x8DD95FE4EC097324ULL,
		0x5C6AEEB40A391906ULL
	}};
	t = -1;
	printf("Test Case 454\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 454 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -454;
	} else {
		printf("Test Case 454 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6CF7FCCA83D40000ULL,
		0x422D32E6D1224627ULL,
		0x6F8EFDEBBAB0459DULL,
		0xA41C074068EBAC06ULL,
		0x3FCB59BAA36C50BEULL,
		0x48F51F05CDB46CEDULL,
		0xBC626FF3922B54E0ULL,
		0xCE531625515DAE14ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5147726B29DDF7B1ULL,
		0xF3ECED59F0321AE1ULL,
		0x340E042D46FE43B7ULL,
		0x181F01D0B44A2C16ULL,
		0xB731FE82BE88E6F0ULL,
		0xF6942042B28A3E84ULL,
		0x151E95C510F0F636ULL,
		0x5BC7C358DBCC7480ULL
	}};
	t = 1;
	printf("Test Case 455\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 455 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -455;
	} else {
		printf("Test Case 455 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8B283C9A4B3A501AULL,
		0x82D30C6B36F5CFC7ULL,
		0x1033F3360DB87567ULL,
		0x2E0590E2900D516BULL,
		0x6FC3F9C13C543EAFULL,
		0xD30A452B5EC99D3AULL,
		0x6E5334337D57A116ULL,
		0xDCF55E41C6AF8567ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D3534727A3CDAB7ULL,
		0x57828E59887A4E5DULL,
		0x3ABD5FDD528AA458ULL,
		0x6D306352104793E9ULL,
		0x49100C58B2B601ACULL,
		0x4ADD997F4BE5D5EFULL,
		0x0719F34635B2A52AULL,
		0x4032950B680106D7ULL
	}};
	t = 1;
	printf("Test Case 456\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 456 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -456;
	} else {
		printf("Test Case 456 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x61D8DE51D2D982E3ULL,
		0xB9B5E3414B77A838ULL,
		0x43B07F8B2540B126ULL,
		0x981D30032F1910BFULL,
		0xEC34A0012871F7C0ULL,
		0xF98E57DD5C1E0F3CULL,
		0x76778FB474FFFE81ULL,
		0x354AF4C7A195BFF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61D8DE51D2D982E3ULL,
		0xB9B5E3414B77A838ULL,
		0x43B07F8B2540B126ULL,
		0x981D30032F1910BFULL,
		0xEC34A0012871F7C0ULL,
		0xF98E57DD5C1E0F3CULL,
		0x76778FB474FFFE81ULL,
		0x354AF4C7A195BFF0ULL
	}};
	t = 0;
	printf("Test Case 457\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 457 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -457;
	} else {
		printf("Test Case 457 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC6690ADAA6BE31ADULL,
		0x009A3F7FD9933AB0ULL,
		0xE657F3D2189391F4ULL,
		0xB2760CC337FF2263ULL,
		0xAC9B2A20AFED4FA4ULL,
		0x62F1527D2AD70685ULL,
		0xCC1FF2958905D4B8ULL,
		0xA0237A000CE753DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9474215B96BC3C14ULL,
		0x8567CE61FAC57914ULL,
		0xECDACF1B09F508FBULL,
		0xD412D8EDDD1A9262ULL,
		0xEB9579A35D9C6C65ULL,
		0xC5F648D5119F1EF2ULL,
		0x3F8B174C5F8DA061ULL,
		0x29739D83F91497ACULL
	}};
	t = 1;
	printf("Test Case 458\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 458 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -458;
	} else {
		printf("Test Case 458 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD1C5C7632AD32A51ULL,
		0x1F21D71A09E69F64ULL,
		0x41CE9D935F5E6C52ULL,
		0xB5BD7155E6416A5BULL,
		0xDE6E589ABF298BB3ULL,
		0x6C0EBA6937C585F9ULL,
		0x5BDF4C6EF5FA1CCAULL,
		0x9EB64F086216C40FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB79CAA47C78F8C81ULL,
		0xF7E82FA133B8A568ULL,
		0x87E835EE1E0AE537ULL,
		0xE4889795E0DCAA0EULL,
		0x872940232F28DE6BULL,
		0xE69A4BA9FDC0299CULL,
		0x9ABCF314BCC328BCULL,
		0xE951B3B71B25E880ULL
	}};
	t = -1;
	printf("Test Case 459\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 459 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -459;
	} else {
		printf("Test Case 459 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x91A12FB63A0943C5ULL,
		0x4F349C36A69CB996ULL,
		0x1CEA3A4FAD8E0CABULL,
		0x29FA276D16A2B7D1ULL,
		0xA6E807A1A518BC4BULL,
		0x96F642F5E7693EE9ULL,
		0xEC0154047E9C976AULL,
		0x0B5F27ED542F275AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x206AF97DF04DD9DFULL,
		0x988BE532FAE98ECAULL,
		0x0F1EB8C1953C24A6ULL,
		0x4D85286B0F8453AFULL,
		0x84878742EFE852D3ULL,
		0xA6DA12058CFFFE32ULL,
		0x972F75746605A1E4ULL,
		0xA8E62668A0DF6CD4ULL
	}};
	t = -1;
	printf("Test Case 460\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 460 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -460;
	} else {
		printf("Test Case 460 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x52DC351B34D19131ULL,
		0xCB320D4126F96117ULL,
		0xA7CA8EE5B39A9471ULL,
		0x5DD0B748048D9F8BULL,
		0xFF2BAA7FB4900354ULL,
		0xD454548E088A26C2ULL,
		0xFBA4E22B0B7B3D10ULL,
		0xFBE99B74E155AA9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52DC351B34D19131ULL,
		0xCB320D4126F96117ULL,
		0xA7CA8EE5B39A9471ULL,
		0x5DD0B748048D9F8BULL,
		0xFF2BAA7FB4900354ULL,
		0xD454548E088A26C2ULL,
		0xFBA4E22B0B7B3D10ULL,
		0xFBE99B74E155AA9AULL
	}};
	t = 0;
	printf("Test Case 461\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 461 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -461;
	} else {
		printf("Test Case 461 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF0A3FADB017A9B1FULL,
		0x3E5CE9E891446B5BULL,
		0x46184D7AD44DAF97ULL,
		0xC0FAA033E6531123ULL,
		0xD2611A8944064488ULL,
		0x1D42472543418C59ULL,
		0x613D289B4AF9D5A3ULL,
		0xFF5DDD3F2598388EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15DACC6062BEABA4ULL,
		0x361581B03528AC4AULL,
		0xFCC2CD53D10BDCEDULL,
		0x1297CE9A94578B0EULL,
		0x4083934D480DAEEBULL,
		0xCE104E88988DABEEULL,
		0x4A64EA05A092963DULL,
		0xD80788A82210B06EULL
	}};
	t = 1;
	printf("Test Case 462\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 462 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -462;
	} else {
		printf("Test Case 462 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x002D77AAAB080B24ULL,
		0x8A72C30E835D4AEFULL,
		0xB31D416165FE7724ULL,
		0x08E8B4F7FF3FB3C0ULL,
		0x6AC2D7DBE3488A71ULL,
		0x2DA7AF624E0B9CC7ULL,
		0x4542AC5219C6DC31ULL,
		0x95476EB34A076C49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB92A5562E25134E4ULL,
		0x5912B2625495B4A0ULL,
		0x5AF60A5D241E6289ULL,
		0xDF67F2B4CEE08C31ULL,
		0xA6D0369D02FFEDFCULL,
		0xB9A2FBB5331EB14EULL,
		0xB9A83CC6975749CFULL,
		0x934B11A4B6B9C1F6ULL
	}};
	t = 1;
	printf("Test Case 463\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 463 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -463;
	} else {
		printf("Test Case 463 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2A5BAB7BC64CC0ADULL,
		0x5C207568B1308115ULL,
		0x953EC2FEB070CA56ULL,
		0xD683468B847DC574ULL,
		0x003F67E326AFF740ULL,
		0x241ADBF38A1B1C8BULL,
		0x1107388DBA87EC75ULL,
		0x6569ACF3679FED0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DFEE606AB014C5EULL,
		0x44FCC6ACB4721A6BULL,
		0xE625393CF8B70A2FULL,
		0x8271B12F653CD1D5ULL,
		0xAEEC2193AADE0EB9ULL,
		0x3ACEC0A8493774FAULL,
		0x0C6DE77F822C76C0ULL,
		0x4475592B5EEA6BAFULL
	}};
	t = 1;
	printf("Test Case 464\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 464 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -464;
	} else {
		printf("Test Case 464 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x77AC86068BEA5A0FULL,
		0x5A600CD6B48B369AULL,
		0x77618682C841E07DULL,
		0x9115B7CF067DD06DULL,
		0xC864F6ABF896A77CULL,
		0xDF42A7B70A6DEE41ULL,
		0xCE30AFF6504D814BULL,
		0xF69C588B2C552A23ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77AC86068BEA5A0FULL,
		0x5A600CD6B48B369AULL,
		0x77618682C841E07DULL,
		0x9115B7CF067DD06DULL,
		0xC864F6ABF896A77CULL,
		0xDF42A7B70A6DEE41ULL,
		0xCE30AFF6504D814BULL,
		0xF69C588B2C552A23ULL
	}};
	t = 0;
	printf("Test Case 465\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 465 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -465;
	} else {
		printf("Test Case 465 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2C3E8487E5CB46F4ULL,
		0xA6A1A8DA4A61ED70ULL,
		0x4EAF095998EA2664ULL,
		0xEC20A64B8D0B55E2ULL,
		0x3C6C70A7CE4DF28EULL,
		0xB28C95385C7FC5CCULL,
		0xA23754EDC79D6D13ULL,
		0x897BD9CDBBB80D95ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EAC6851D790A88BULL,
		0x738518E439F7ED58ULL,
		0x1B93F7778DA143E2ULL,
		0x2111B63FDA1A9E83ULL,
		0x72F0E183E08F4F42ULL,
		0x764B66DE0129E60AULL,
		0x81A94FE4339077B6ULL,
		0x3D575643A63D1F50ULL
	}};
	t = 1;
	printf("Test Case 466\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 466 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -466;
	} else {
		printf("Test Case 466 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x202B6D8A35C336C5ULL,
		0x868C2A150A39A545ULL,
		0x0F3507986D175409ULL,
		0xC73F359377BB44CDULL,
		0x09143C7919BCF82EULL,
		0x4974B00D935B0010ULL,
		0x6A89B0BD7AAA866BULL,
		0xE026CB7B7BD1A8A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A1DA1F20B59E359ULL,
		0x6B1D0C89E65C2B6DULL,
		0x4B2235705BE2EF5CULL,
		0x39DD4D11E135FE6CULL,
		0xF87937DDCD6AAEA8ULL,
		0xDF991B5104C826F4ULL,
		0x64B699CE3884354DULL,
		0x310A58F1BFB07F7CULL
	}};
	t = 1;
	printf("Test Case 467\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 467 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -467;
	} else {
		printf("Test Case 467 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6C7A96E1000A0926ULL,
		0x2FE5FE284B18DA77ULL,
		0x25EDF17072702F7DULL,
		0xACBE97B22DEBC1D2ULL,
		0xE102F70B18F219ACULL,
		0x0633BFC22B6555DFULL,
		0x1ECF260AF97014FBULL,
		0x0BBBBBBD6B80F615ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3477569B89E6F02CULL,
		0x17B52E48156B46FBULL,
		0xFCA12916CA9B5339ULL,
		0x1F4F9DFBA740FF9CULL,
		0x5F3B52C2A2E41B19ULL,
		0x87DAD0F22B2B1BC9ULL,
		0xCF72963A28FF73D4ULL,
		0x75492A2DC03D256AULL
	}};
	t = -1;
	printf("Test Case 468\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 468 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -468;
	} else {
		printf("Test Case 468 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6E0CD50BA0666F8BULL,
		0x027AF3A34A9959D6ULL,
		0x9C14B27A87E0F23AULL,
		0x5EE2EC463D49003EULL,
		0x05859ADB565CB90BULL,
		0x79F5B04A72B0CC85ULL,
		0x0F81F110A0A4B1C2ULL,
		0x8B831C5D20B412DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E0CD50BA0666F8BULL,
		0x027AF3A34A9959D6ULL,
		0x9C14B27A87E0F23AULL,
		0x5EE2EC463D49003EULL,
		0x05859ADB565CB90BULL,
		0x79F5B04A72B0CC85ULL,
		0x0F81F110A0A4B1C2ULL,
		0x8B831C5D20B412DBULL
	}};
	t = 0;
	printf("Test Case 469\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 469 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -469;
	} else {
		printf("Test Case 469 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD9AA3BEC393CCF90ULL,
		0x66DB629BBB25E64FULL,
		0x233FC05F545F4CFCULL,
		0xE077EC6511F87074ULL,
		0xFB95580C1F917EB9ULL,
		0x3B470F652873871FULL,
		0x231E3E006EA074B8ULL,
		0xBA41B6E318A1A5A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB430140C72EE873EULL,
		0x6E8DBEFE82D5D760ULL,
		0x7A4741F65F528C8BULL,
		0x29975B51525DFAFDULL,
		0x34C25AED9C1D6F63ULL,
		0xA270423D54C2E2C6ULL,
		0x6410857525CEC36CULL,
		0xFEFECED23C83C162ULL
	}};
	t = -1;
	printf("Test Case 470\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 470 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -470;
	} else {
		printf("Test Case 470 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0A05ABD03CA4855AULL,
		0x59C4AF2CB6FFE13AULL,
		0xBB063AF4E0C93B3BULL,
		0x93671E4030BBEB3AULL,
		0xFF877106771613E0ULL,
		0x2AE2EC633763D4EFULL,
		0x3BA3DDDCD2B6C937ULL,
		0x55A2F1A0C0BE1CBBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3F068F28F2BAE32ULL,
		0x2B8734DC578B78CAULL,
		0x87962ABD3C72F221ULL,
		0x9AE76DE891189EB5ULL,
		0x661A6302E98970EAULL,
		0x806EBB45C7623FFFULL,
		0x84A701698E558022ULL,
		0x1E4D00F9B3AC5756ULL
	}};
	t = 1;
	printf("Test Case 471\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 471 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -471;
	} else {
		printf("Test Case 471 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7276B5733194A006ULL,
		0xDBEE306A194F39F5ULL,
		0xA143928EBB2F6FF5ULL,
		0xA3EA56947FFE9072ULL,
		0x07E2A049357FF178ULL,
		0xD03B28A5B774AE3CULL,
		0xC27989F542CCE137ULL,
		0xA7C5292A6D236CBDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7ADDF49AC148059ULL,
		0xDFDF377421E11C0FULL,
		0x6373BDFDEFC2C4F8ULL,
		0x95E3CEFAACF87C2AULL,
		0x1BAB388AE552E082ULL,
		0x790AA93BB6F31701ULL,
		0x37B27491A6C2A94FULL,
		0xB48E1AC6582B4006ULL
	}};
	t = -1;
	printf("Test Case 472\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 472 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -472;
	} else {
		printf("Test Case 472 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9CC78298B4B36868ULL,
		0x7279A6AC403B2D7CULL,
		0x48A2208FEE98A8CCULL,
		0x4195C4A0C8E72FFAULL,
		0xD884E73FC14E960BULL,
		0x936B2AC5EC085BA3ULL,
		0x34346B1193DA5328ULL,
		0xE5AC41CC0DA4B89DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9CC78298B4B36868ULL,
		0x7279A6AC403B2D7CULL,
		0x48A2208FEE98A8CCULL,
		0x4195C4A0C8E72FFAULL,
		0xD884E73FC14E960BULL,
		0x936B2AC5EC085BA3ULL,
		0x34346B1193DA5328ULL,
		0xE5AC41CC0DA4B89DULL
	}};
	t = 0;
	printf("Test Case 473\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 473 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -473;
	} else {
		printf("Test Case 473 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x11E83B388385A121ULL,
		0x9415F8810137EC4AULL,
		0x1E4C2C6F63DC0F11ULL,
		0x9B8B8774DD7650CCULL,
		0x2AF322FB29605D84ULL,
		0x447C97842C73EF5AULL,
		0x227DC19D6A016B3CULL,
		0x84F2618EA71D4B89ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC164CED13B0D581ULL,
		0xEF0783963BBE80A2ULL,
		0xB51B3CEBC36AF8ABULL,
		0xF2C8152D7F402F7DULL,
		0x61C5919027C84027ULL,
		0xD3A709AEA8A1A3D2ULL,
		0x86833ECEC327D4F6ULL,
		0xE2B659EBAA8B0DC4ULL
	}};
	t = -1;
	printf("Test Case 474\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 474 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -474;
	} else {
		printf("Test Case 474 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x10005EA6BA56C4A2ULL,
		0xDD72C235BFBC7B0DULL,
		0x99237A32AD293EEBULL,
		0x2EDDDD369E07047BULL,
		0xF667F7A20504416DULL,
		0xE16D8B07D5000BA7ULL,
		0x8DCF618CC0C242F3ULL,
		0xEED7D03161D7D1E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0611C585EAC2D568ULL,
		0xE8A52671483D28F3ULL,
		0xAF7D8ACA479AFD7DULL,
		0xFACD2B71ECC5A5E5ULL,
		0xB4A1CB6987ECEA9DULL,
		0x742A1402157AFFC2ULL,
		0xA67206B007F99AE1ULL,
		0x47DD060048B70A97ULL
	}};
	t = 1;
	printf("Test Case 475\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 475 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -475;
	} else {
		printf("Test Case 475 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x395DC89A1CB75A94ULL,
		0xD2AF223C9291C70EULL,
		0x8AB380CBB125078EULL,
		0x0F4B54E8A88CC321ULL,
		0x3E9181E62F74B570ULL,
		0x08BD1C61EFE9183FULL,
		0x8E04D0B3C7278E6AULL,
		0xC3FA35DE04889EDEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC390CD000428AF51ULL,
		0x41F4B6E47D693FBAULL,
		0x6B79ECEFDFF27621ULL,
		0xA297500190F1DD27ULL,
		0x0413E1A67EE2063BULL,
		0x2DEBD41A2F1F6802ULL,
		0xCD2EC0AFDF617B1DULL,
		0x5BF5617C699DBFA6ULL
	}};
	t = 1;
	printf("Test Case 476\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 476 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -476;
	} else {
		printf("Test Case 476 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAFDF3B11F528C62DULL,
		0xFCACCE0FDC9AC4B9ULL,
		0x4E02C3D2F16F04F1ULL,
		0xCCE12F885BEC6340ULL,
		0x93B0409E0ECB9DD6ULL,
		0x5E83B8F8C1DDD463ULL,
		0xCB5955D1099604B8ULL,
		0x6169471161F1DBD9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFDF3B11F528C62DULL,
		0xFCACCE0FDC9AC4B9ULL,
		0x4E02C3D2F16F04F1ULL,
		0xCCE12F885BEC6340ULL,
		0x93B0409E0ECB9DD6ULL,
		0x5E83B8F8C1DDD463ULL,
		0xCB5955D1099604B8ULL,
		0x6169471161F1DBD9ULL
	}};
	t = 0;
	printf("Test Case 477\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 477 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -477;
	} else {
		printf("Test Case 477 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0847F388CDF469E6ULL,
		0x42B2EB5595FB6F8FULL,
		0x70D3CB23B7C9D7F5ULL,
		0x08CAA973ABC06850ULL,
		0xD4448F46F395D8F3ULL,
		0x9F1F47EAB2A197ACULL,
		0xC274305772B9F79EULL,
		0xBFE18E192D01A6FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F65F1CAC0A28B5CULL,
		0x183FF77528E9E752ULL,
		0x654458150112BFF3ULL,
		0xDA4DF09B5A985F4FULL,
		0x1FD07903BCBCA6FEULL,
		0xB9C119220C004064ULL,
		0x71A35C8A1843D598ULL,
		0xF1E7CCB6BF195CC3ULL
	}};
	t = -1;
	printf("Test Case 478\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 478 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -478;
	} else {
		printf("Test Case 478 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD5237BB650E6CAE0ULL,
		0xF00CEC7ABAE5143EULL,
		0x791D44BD5D1064E9ULL,
		0xCAAB51040C7A8A5DULL,
		0x0827BFF207EF5391ULL,
		0xCEA72D48F7F98E1EULL,
		0xABCC6E766EE89C16ULL,
		0xE0831EC7CBD1B26EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45CED79734D64431ULL,
		0x76FC004E0786CF4EULL,
		0xD39B90A4E2D078A5ULL,
		0x26E0083F0C6BA499ULL,
		0xE918820BD2C67714ULL,
		0x7F88465BC49F6C48ULL,
		0xA5E76BE5EE2F2620ULL,
		0xACED28223CFEB312ULL
	}};
	t = 1;
	printf("Test Case 479\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 479 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -479;
	} else {
		printf("Test Case 479 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4FE4548445666957ULL,
		0x1CB002A9487F8072ULL,
		0x26B424C318CE1315ULL,
		0xFC94F2F3E6F996C8ULL,
		0x23D72173C48AC517ULL,
		0x3E3653A96BA8027CULL,
		0x5517164965C1508EULL,
		0xBE22AC1969ED1FB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4BA865C6284E4FDULL,
		0x795741628C54A287ULL,
		0xB3D4B43CA9CC9475ULL,
		0x958150FEC87FA82BULL,
		0xB89AF3F589728D6FULL,
		0xF8C92F168E042B88ULL,
		0x8FEC5C1F911FB991ULL,
		0x601E55D253462A1BULL
	}};
	t = 1;
	printf("Test Case 480\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 480 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -480;
	} else {
		printf("Test Case 480 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0AE507F212F03207ULL,
		0x0712E9A259B91823ULL,
		0x8170378A1735755BULL,
		0x83D98203DAC3E7A1ULL,
		0x58EAE89379A269C4ULL,
		0xA391E7FFF4E409DCULL,
		0x33C230B73CF1FEFEULL,
		0x241701367C09EB31ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0AE507F212F03207ULL,
		0x0712E9A259B91823ULL,
		0x8170378A1735755BULL,
		0x83D98203DAC3E7A1ULL,
		0x58EAE89379A269C4ULL,
		0xA391E7FFF4E409DCULL,
		0x33C230B73CF1FEFEULL,
		0x241701367C09EB31ULL
	}};
	t = 0;
	printf("Test Case 481\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 481 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -481;
	} else {
		printf("Test Case 481 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDA37016BA9911401ULL,
		0x2497CBCC7983947CULL,
		0x54F6675BEA8921F5ULL,
		0x5A3DE55A01DE3DC1ULL,
		0x13DD65E26C4C2AD6ULL,
		0x19FB3D1E09517E1AULL,
		0x145A5F0474CD5B0FULL,
		0x1BA0C8116E73AA9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF675B5626E9B8D5ULL,
		0x236C31A7D122CB85ULL,
		0x3059D12DB7FC36ADULL,
		0x02E968F9574796E6ULL,
		0xE47B11288A6948B3ULL,
		0x41BDA6295E7925D0ULL,
		0xF7DB480EE9E2C238ULL,
		0x2FDF0AD03EFC0E8FULL
	}};
	t = -1;
	printf("Test Case 482\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 482 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -482;
	} else {
		printf("Test Case 482 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9BF4AFC5FAEAB14BULL,
		0x655310AAE1B57409ULL,
		0xDBE3CAD626032C74ULL,
		0xE82F42E497B5A88CULL,
		0xF61E1F48535E042DULL,
		0xEF0137E0BA0F4617ULL,
		0x5A1C02274BE369A5ULL,
		0x72E3434D8F4A2FEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA268399843F8EC2ULL,
		0x27F7114AFFFA13EEULL,
		0xBB3FC4DAE693FBD8ULL,
		0xF1E04F59E9EA98FFULL,
		0xD96F71063550E4DAULL,
		0x16B31D0CFC0F339DULL,
		0xDE00B6F09B23690CULL,
		0xFB1331874AC88A0FULL
	}};
	t = -1;
	printf("Test Case 483\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 483 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -483;
	} else {
		printf("Test Case 483 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC579F2E48B75D7C5ULL,
		0x08972087304081D1ULL,
		0x292D0EE4A7B37A32ULL,
		0xBE08AAB9E110E970ULL,
		0x82B26F18C6C305DEULL,
		0xAB58F525E8E1ABF0ULL,
		0x6D3A586A47B97B42ULL,
		0x8B4AD440BD4E63CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E52C55E975E8004ULL,
		0x39B92126EF52F0F5ULL,
		0x9242B1BCB3B3738EULL,
		0xE46CA2048417F99DULL,
		0x3836F0A945BFF679ULL,
		0x1EF0E5C40FA1DA0CULL,
		0xC4292796285388D9ULL,
		0xDDD41092CC8A767DULL
	}};
	t = -1;
	printf("Test Case 484\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 484 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -484;
	} else {
		printf("Test Case 484 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x82ACDFABE7F91EF0ULL,
		0x2F8D707140D52DEDULL,
		0xDE539CE5B4C44EDBULL,
		0x06113BFDC55DFE4CULL,
		0x55EC7472FCC2F9E3ULL,
		0x175D1F7CC6D23AF8ULL,
		0x0817F95520CE05BDULL,
		0xDFF8D30106A28FF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82ACDFABE7F91EF0ULL,
		0x2F8D707140D52DEDULL,
		0xDE539CE5B4C44EDBULL,
		0x06113BFDC55DFE4CULL,
		0x55EC7472FCC2F9E3ULL,
		0x175D1F7CC6D23AF8ULL,
		0x0817F95520CE05BDULL,
		0xDFF8D30106A28FF3ULL
	}};
	t = 0;
	printf("Test Case 485\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 485 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -485;
	} else {
		printf("Test Case 485 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C4BC8C53B9B0D79ULL,
		0xA1C9B327B7A3AB2CULL,
		0x5C5358D1F036CEFAULL,
		0xA0404D0466FA2A3AULL,
		0x9ED64DD6149599C9ULL,
		0x51EEFA71551D9A4FULL,
		0x728221EF66907218ULL,
		0x1FAE50DDB0DBDBDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD852CDE6BEE59F7ULL,
		0x45597BBDD1BA7AD2ULL,
		0x0B99081837D6A932ULL,
		0x3A2C01FA5DE69DA6ULL,
		0x073F05AF22816BB5ULL,
		0x0C8EC9EFABE9BB1CULL,
		0x9385626CD4237D8AULL,
		0x2E4D7276FC6F439BULL
	}};
	t = -1;
	printf("Test Case 486\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 486 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -486;
	} else {
		printf("Test Case 486 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC7ACB83BB4D6CF53ULL,
		0x2F83B37551228DF6ULL,
		0x155A8922695EF7BFULL,
		0xE932C85A13982C19ULL,
		0xC6E4FCAC35E2F437ULL,
		0x8354451FF2A0BFACULL,
		0x4ECBD2258A4453A6ULL,
		0xBED0FE912247722CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31E8B4E6CDED2B48ULL,
		0x050B69E76253E0E4ULL,
		0xB0B4B5A255B9B790ULL,
		0x3E9C0F200E18D2F6ULL,
		0x3F9E7BD0BBB7A141ULL,
		0x3AA1BD082AE464C9ULL,
		0xC04C866927C6DDF7ULL,
		0xDC49F6AE9AE29FF5ULL
	}};
	t = -1;
	printf("Test Case 487\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 487 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -487;
	} else {
		printf("Test Case 487 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x53D416E65DAB7184ULL,
		0xF9DBD4B3EB787ED0ULL,
		0x220F5484FBF7BF82ULL,
		0x82B25875E31DF0D1ULL,
		0x569D7D7CCC67DBCCULL,
		0xB2D164E713C621ADULL,
		0x80DA065F727CAF44ULL,
		0x61D400CBF940B4DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30BF77FECD5F4880ULL,
		0xC4DEBEB85AC2FC47ULL,
		0xFB585B52043F4C31ULL,
		0x34AE13EF530B8510ULL,
		0xAEBC051FDAA5C563ULL,
		0x4F87CCA9F4DA83F1ULL,
		0xE14B7899B061925BULL,
		0x1B2EB0409F751C4EULL
	}};
	t = 1;
	printf("Test Case 488\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 488 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -488;
	} else {
		printf("Test Case 488 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x33A2782A8B7C1F8EULL,
		0xF334799738D1C152ULL,
		0xEE112B85FA768E5AULL,
		0x883BF0B2E37422D4ULL,
		0xCC1BC3390FA375E7ULL,
		0x7CB8D3C6FAFFBB26ULL,
		0x51AF43AAA0150A90ULL,
		0x741EE9C539749DABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33A2782A8B7C1F8EULL,
		0xF334799738D1C152ULL,
		0xEE112B85FA768E5AULL,
		0x883BF0B2E37422D4ULL,
		0xCC1BC3390FA375E7ULL,
		0x7CB8D3C6FAFFBB26ULL,
		0x51AF43AAA0150A90ULL,
		0x741EE9C539749DABULL
	}};
	t = 0;
	printf("Test Case 489\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 489 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -489;
	} else {
		printf("Test Case 489 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x741467D6785EE226ULL,
		0x9323461F0633720CULL,
		0x8DE180A934838722ULL,
		0x0E814E2F060DEDE7ULL,
		0x4B1999DCC6A06661ULL,
		0xBEC9AACE22254D76ULL,
		0x07234BB44B20427FULL,
		0x19C704D536D70063ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82AECB95FD208B00ULL,
		0xC3437ED911A9A738ULL,
		0x1F1A9D5C5AAF59A8ULL,
		0x9F83CBCE63E29943ULL,
		0xEB2BCC5D34988CC9ULL,
		0xB5C5DEB289DAE3B3ULL,
		0x04EF3EEF3603EE47ULL,
		0x6220EDB08775AE50ULL
	}};
	t = -1;
	printf("Test Case 490\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 490 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -490;
	} else {
		printf("Test Case 490 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2300BBA09E365833ULL,
		0x817C13D0E14F854EULL,
		0xD71D2CF613A343B7ULL,
		0xD155E2CFD5FD137CULL,
		0x6BE5305797833D0DULL,
		0x523369B0C1D0AD60ULL,
		0x66972DBA4561DECCULL,
		0xDD01331D26A9D825ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA58D46E04945A94BULL,
		0x781456C99D8603B2ULL,
		0xF32EF16C84B3C240ULL,
		0xDD786AA62A9F0358ULL,
		0xCA3226ED43A84C17ULL,
		0x1DD0F9A02404C1C2ULL,
		0xDB8509BF55EF9AE3ULL,
		0x23E15FD279E1BDE4ULL
	}};
	t = 1;
	printf("Test Case 491\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 491 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -491;
	} else {
		printf("Test Case 491 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8627D32D2228188EULL,
		0xA848B36E0B4470FEULL,
		0xDCE4CF16000398A9ULL,
		0x7E68BB0C6959D0B3ULL,
		0x532903211F498B23ULL,
		0xE59E285F859A1138ULL,
		0x461E6133AC793FE4ULL,
		0xE62446F276E6F0F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F7BA641266398B1ULL,
		0x4143A5BBEFAC1185ULL,
		0x1F0CB69686736FD3ULL,
		0x2C3F3487DD707C80ULL,
		0xD4F5715C18A46328ULL,
		0xB989192A90C40377ULL,
		0xE0C0BAC78FD53A59ULL,
		0x860EDFAFEF035DA7ULL
	}};
	t = 1;
	printf("Test Case 492\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 492 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -492;
	} else {
		printf("Test Case 492 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x68AB3A038F3451A3ULL,
		0xB5711C2373AFC41FULL,
		0x3A2AE2F72F03B5C8ULL,
		0x5A43ECB94ADE185EULL,
		0x35B1B15971AC663FULL,
		0xC233530E26C19405ULL,
		0xAA3E1BCEF07B9C7FULL,
		0x1E4D8BAEDE1BF193ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68AB3A038F3451A3ULL,
		0xB5711C2373AFC41FULL,
		0x3A2AE2F72F03B5C8ULL,
		0x5A43ECB94ADE185EULL,
		0x35B1B15971AC663FULL,
		0xC233530E26C19405ULL,
		0xAA3E1BCEF07B9C7FULL,
		0x1E4D8BAEDE1BF193ULL
	}};
	t = 0;
	printf("Test Case 493\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 493 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -493;
	} else {
		printf("Test Case 493 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAE0B2164D1B9EE5EULL,
		0x24526643DD39A740ULL,
		0xD9346BACEA8072E6ULL,
		0x438D8CA13E88E638ULL,
		0x7B9E8E654BBA022AULL,
		0xF60BCE5BA63234F9ULL,
		0xC32C79FC17F1CB97ULL,
		0xA11FD4E243D6141CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC6E8E1EC3A8F5AEULL,
		0x6D59C1F5B1C9FFA3ULL,
		0xE73BF98AD930E924ULL,
		0xC12ABBA2BDE27994ULL,
		0xCF64315330F68926ULL,
		0xB7B95EAA069858C6ULL,
		0xECD1F54DDD132A85ULL,
		0x1EBE050C4BD6E0DEULL
	}};
	t = 1;
	printf("Test Case 494\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 494 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -494;
	} else {
		printf("Test Case 494 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2BC313C32DF3AA0FULL,
		0x082FC3219B82A839ULL,
		0x6B9A71CB3D57B88CULL,
		0xD4728850ADCD3BD7ULL,
		0x49B0577D12E84E94ULL,
		0x0773940FE0BAD13AULL,
		0xE06BBD9B7B2F2886ULL,
		0xE506BD4F82CD6B92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5DFFFE638F20F3AULL,
		0x9B314C715B6680ECULL,
		0xCA6939254D885509ULL,
		0x9A863D899C309AD7ULL,
		0xFC49BB2B17ED6297ULL,
		0xBB6B9F48C72464E3ULL,
		0xCA89BE9B52CA0F1BULL,
		0x720BC12C20654888ULL
	}};
	t = 1;
	printf("Test Case 495\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 495 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -495;
	} else {
		printf("Test Case 495 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA1F1BB9F25884E5BULL,
		0x2D1DD0A34F4F271DULL,
		0x56064468615417CFULL,
		0x584C8FC28DC19126ULL,
		0xB788DA9F6D7A426CULL,
		0x97E141E1CB603838ULL,
		0x47E14F1FECB8463EULL,
		0xBF7E2A2A179EDB97ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24B71AE28DBD31B8ULL,
		0xC2D1F15F3A4171F8ULL,
		0x2156D66428A46B9FULL,
		0x8DF0BB9D545557A0ULL,
		0x30BB6C3D1F7CA875ULL,
		0xF72545581D5267E9ULL,
		0x8A8E36A5FAE58F02ULL,
		0x2DEA2D9C30627AD5ULL
	}};
	t = 1;
	printf("Test Case 496\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 496 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -496;
	} else {
		printf("Test Case 496 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE7948D0B410333F9ULL,
		0x5530A88EA49FDF76ULL,
		0x96618F9A1E2A62FFULL,
		0xB818968ECE038D20ULL,
		0xAB06E2B15FD830CEULL,
		0x4865FF27B61A8DB7ULL,
		0x5DC298624669D7E8ULL,
		0x8B6214ECF2AA9290ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7948D0B410333F9ULL,
		0x5530A88EA49FDF76ULL,
		0x96618F9A1E2A62FFULL,
		0xB818968ECE038D20ULL,
		0xAB06E2B15FD830CEULL,
		0x4865FF27B61A8DB7ULL,
		0x5DC298624669D7E8ULL,
		0x8B6214ECF2AA9290ULL
	}};
	t = 0;
	printf("Test Case 497\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 497 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -497;
	} else {
		printf("Test Case 497 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x73333DF5C239C293ULL,
		0xDFE78F15DECB66B7ULL,
		0x9EA6334946240602ULL,
		0x8B6CA06514F500FFULL,
		0x29E454C80F8A3868ULL,
		0x6C2A8A23C36EFC21ULL,
		0x18C296AF23436FC6ULL,
		0x308CB89B868E6071ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71B0516080E18ED8ULL,
		0x8AF4E93103BC8587ULL,
		0x9EDEE24C9465DB67ULL,
		0x730B9B520E3F465DULL,
		0xF77B95D17E64854AULL,
		0xD1CD4258D81E2986ULL,
		0x82B80CA0B67ACFB4ULL,
		0x2B1FE0DDBB785AB9ULL
	}};
	t = 1;
	printf("Test Case 498\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 498 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -498;
	} else {
		printf("Test Case 498 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8366389B64E37C14ULL,
		0x954C311F34B908BCULL,
		0x9D26132E290A3A47ULL,
		0x244E2C6125CE0445ULL,
		0xF0DD21A56C5B8E5FULL,
		0x612B87E71F051682ULL,
		0xFAC9ACF357778678ULL,
		0xC511183987F4D509ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48600F2F8DE90D30ULL,
		0x275A0EA5DC550BECULL,
		0x6FB7BBB8D1F52F9CULL,
		0xC204FCDD554EB3D3ULL,
		0xFBD35CE35C83867FULL,
		0x2CBC6218D920FB9BULL,
		0x70843D88DEFFB358ULL,
		0x913F8384D41C07C7ULL
	}};
	t = 1;
	printf("Test Case 499\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 499 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -499;
	} else {
		printf("Test Case 499 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8A7D60B1E3E4667EULL,
		0xDAE6DCB7E2F5D183ULL,
		0x4F3AE6B26B06DFCEULL,
		0x772B089E7A85060DULL,
		0x080A4631703EAB8AULL,
		0x723CC52E0E5077DDULL,
		0x137BECE0538C8CCCULL,
		0x560963C308BA764EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42E0BFDC4A11C686ULL,
		0xDCCDF4D0E08CA57EULL,
		0xD86FC58F67DF1DFEULL,
		0x11C2F5CB2AB74F90ULL,
		0x9C87192190BEAC06ULL,
		0x87F8C9792675794DULL,
		0xEA9848FD883002EDULL,
		0x48F8708B77CCD7BBULL
	}};
	t = 1;
	printf("Test Case 500\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
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